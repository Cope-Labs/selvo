// Copyright (c) 2026 Cope Labs LLC
// SPDX-License-Identifier: MIT
/**
 * selvo VS Code Extension — main entry point.
 *
 * Architecture:
 *   Scanner  — runs `selvo scan --format json` as a subprocess (or calls
 *              remote API) and caches results per workspace folder.
 *   Decorator — applies editor decorations (underlines + status-bar icons)
 *               to lines in supported files that reference a vulnerable package.
 *   HoverProvider — returns a rich MDString hover card showing CVSS, EPSS,
 *                   KEV status, blast radius, and a `selvo fix` button.
 *   StatusBar — shows "⚡ selvo: N CVEs · K KEV" summary at the bottom.
 *   Commands  — scan, scanWorkspace, fix, clearCache, openDashboard.
 *
 * Supported file patterns:
 *   requirements.txt, Pipfile, pyproject.toml
 *   package.json, package-lock.json, yarn.lock
 *   Cargo.toml, Cargo.lock
 *   go.mod, go.sum
 *   Gemfile, Gemfile.lock
 *   pom.xml, build.gradle
 *   composer.json, composer.lock
 *   *.csproj, packages.config
 */

import * as vscode from 'vscode';
import * as cp from 'child_process';
import * as path from 'path';
import * as https from 'https';

// --------------------------------------------------------------------------
// Types
// --------------------------------------------------------------------------

interface PackageRisk {
  name: string;
  version: string;
  cve_ids: string[];
  max_cvss: number;
  max_epss: number;
  in_cisa_kev: boolean;
  exploit_maturity: 'none' | 'poc' | 'weaponized';
  transitive_rdep_count: number;
  score: number;
  upstream_version: string | null;
}

interface ScanResult {
  packages: PackageRisk[];
  scanned_at: number;
}

// Map from workspace-relative file path → last scan result
const _cache = new Map<string, ScanResult>();

// Decoration types
let _cveDecoration: vscode.TextEditorDecorationType;
let _kevDecoration: vscode.TextEditorDecorationType;

let _statusBar: vscode.StatusBarItem;

// Secret storage for the selvo API key (not stored in plaintext settings.json)
let _secrets: vscode.SecretStorage;

// --------------------------------------------------------------------------
// Extension lifecycle
// --------------------------------------------------------------------------

export function activate(context: vscode.ExtensionContext): void {
  _secrets = context.secrets;
  _cveDecoration = vscode.window.createTextEditorDecorationType({
    borderWidth: '0 0 1px 0',
    borderStyle: 'solid',
    borderColor: new vscode.ThemeColor('editorWarning.foreground'),
    after: {
      color: new vscode.ThemeColor('editorWarning.foreground'),
      margin: '0 0 0 12px',
      fontStyle: 'italic',
    },
  });

  _kevDecoration = vscode.window.createTextEditorDecorationType({
    borderWidth: '0 0 2px 0',
    borderStyle: 'solid',
    borderColor: new vscode.ThemeColor('editorError.foreground'),
    after: {
      color: new vscode.ThemeColor('editorError.foreground'),
      margin: '0 0 0 12px',
      fontStyle: 'italic',
      fontWeight: 'bold',
    },
  });

  _statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 90);
  _statusBar.command = 'selvo.scanWorkspace';
  _statusBar.text = '⚡ selvo';
  _statusBar.tooltip = 'selvo security scan — click to run';
  _statusBar.show();

  // Commands
  context.subscriptions.push(
    vscode.commands.registerCommand('selvo.scan', () => scanActiveFile()),
    vscode.commands.registerCommand('selvo.scanWorkspace', () => scanWorkspace()),
    vscode.commands.registerCommand('selvo.fix', fixPackage),
    vscode.commands.registerCommand('selvo.clearCache', clearCache),
    vscode.commands.registerCommand('selvo.openDashboard', openDashboard),
    vscode.commands.registerCommand('selvo.setApiKey', setApiKey),
  );

  // Auto-scan on file open / save
  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument(doc => maybeScan(doc)),
    vscode.workspace.onDidSaveTextDocument(doc => maybeScan(doc, true)),
    vscode.window.onDidChangeActiveTextEditor(editor => {
      if (editor) { applyDecorations(editor); }
    }),
  );

  // Hover provider for all supported files
  const selector = _supportedPatterns.map(p => ({ pattern: p } as vscode.DocumentFilter));
  context.subscriptions.push(
    vscode.languages.registerHoverProvider(selector, { provideHover }),
  );

  // Scan already-open editors on startup
  if (cfg().autoScan) {
    for (const doc of vscode.workspace.textDocuments) {
      maybeScan(doc);
    }
  }
}

export function deactivate(): void {
  _cveDecoration?.dispose();
  _kevDecoration?.dispose();
  _statusBar?.dispose();
}

// --------------------------------------------------------------------------
// Configuration helpers
// --------------------------------------------------------------------------

const _supportedPatterns = [
  '**/requirements*.txt',
  '**/Pipfile',
  '**/pyproject.toml',
  '**/package.json',
  '**/package-lock.json',
  '**/yarn.lock',
  '**/pnpm-lock.yaml',
  '**/Cargo.toml',
  '**/Cargo.lock',
  '**/go.mod',
  '**/go.sum',
  '**/Gemfile',
  '**/Gemfile.lock',
  '**/pom.xml',
  '**/build.gradle',
  '**/build.gradle.kts',
  '**/composer.json',
  '**/composer.lock',
  '**/*.csproj',
  '**/packages.config',
];

function cfg(): vscode.WorkspaceConfiguration & {
  path: string; autoScan: boolean; minCvssDecorate: number;
  showEpss: boolean; apiUrl: string; apiKey: string;
  policy: string; ecosystem: string;
} {
  return vscode.workspace.getConfiguration('selvo') as any;
}

function isSupportedFile(doc: vscode.TextDocument): boolean {
  const base = path.basename(doc.uri.fsPath);
  const supported = [
    'requirements.txt', 'requirements-dev.txt', 'requirements-test.txt',
    'Pipfile', 'pyproject.toml',
    'package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
    'Cargo.toml', 'Cargo.lock',
    'go.mod', 'go.sum',
    'Gemfile', 'Gemfile.lock',
    'pom.xml', 'build.gradle', 'build.gradle.kts',
    'composer.json', 'composer.lock',
    'packages.config',
  ];
  return supported.includes(base) || base.endsWith('.csproj');
}

// --------------------------------------------------------------------------
// Scanning
// --------------------------------------------------------------------------

async function maybeScan(doc: vscode.TextDocument, force = false): Promise<void> {
  if (!isSupportedFile(doc)) { return; }
  const key = doc.uri.fsPath;
  if (!force && _cache.has(key)) {
    const editor = vscode.window.visibleTextEditors.find(e => e.document === doc);
    if (editor) { applyDecorations(editor); }
    return;
  }
  if (cfg().autoScan || force) {
    await runScan(doc);
  }
}

async function runScan(doc: vscode.TextDocument): Promise<ScanResult | undefined> {
  const filePath = doc.uri.fsPath;
  _statusBar.text = '⚡ selvo: scanning…';

  let result: ScanResult | undefined;
  const apiUrl = cfg().apiUrl;
  if (apiUrl) {
    // Read API key from Secret Storage (never from plaintext settings.json)
    const apiKey = await _secrets.get('selvo.apiKey') ?? '';
    result = await scanViaApi(filePath, apiUrl, apiKey);
  } else {
    result = await scanViaLocalCli(filePath);
  }

  if (result) {
    _cache.set(filePath, result);
    const editors = vscode.window.visibleTextEditors.filter(e => e.document === doc);
    for (const ed of editors) { applyDecorations(ed); }
    updateStatusBar();
  }
  return result;
}

async function scanViaLocalCli(filePath: string): Promise<ScanResult | undefined> {
  const selvoPath = cfg().path || 'selvo';
  return new Promise(resolve => {
    cp.execFile(
      selvoPath,
      ['scan', '--lockfile', filePath, '--output', 'json', '--no-cve'],
      { timeout: 60_000, maxBuffer: 4 * 1024 * 1024 },
      (err, stdout) => {
        if (err && !stdout) {
          // selvo not installed or errored — silently skip
          resolve(undefined);
          return;
        }
        try {
          const data = JSON.parse(stdout);
          const pkgs: PackageRisk[] = (data.packages || data).map((p: any) => ({
            name: p.name ?? '',
            version: p.version ?? 'unknown',
            cve_ids: p.cve_ids ?? [],
            max_cvss: p.max_cvss ?? 0,
            max_epss: p.max_epss ?? 0,
            in_cisa_kev: Boolean(p.in_cisa_kev),
            exploit_maturity: p.exploit_maturity ?? 'none',
            transitive_rdep_count: p.transitive_rdep_count ?? 0,
            score: p.score ?? 0,
            upstream_version: p.upstream_version ?? null,
          }));
          resolve({ packages: pkgs, scanned_at: Date.now() });
        } catch {
          resolve(undefined);
        }
      },
    );
  });
}

async function scanViaApi(filePath: string, apiUrl: string, apiKey: string): Promise<ScanResult | undefined> {
  // POST the lockfile path to the remote API
  return new Promise(resolve => {
    const body = JSON.stringify({ lockfile: filePath, run_cve: true });
    const url = new URL('/api/v1/scan', apiUrl);
    const opts: https.RequestOptions = {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
        ...(apiKey ? { 'X-API-Key': apiKey } : {}),
      },
    };
    const mod = url.protocol === 'https:' ? https : require('http');
    const req = mod.request(url, opts, (res: any) => {
      let raw = '';
      res.on('data', (chunk: string) => { raw += chunk; });
      res.on('end', () => {
        try {
          const data = JSON.parse(raw);
          const pkgs = (data.packages || []).map((p: any) => ({
            name: p.name, version: p.version, cve_ids: p.cve_ids ?? [],
            max_cvss: p.max_cvss ?? 0, max_epss: p.max_epss ?? 0,
            in_cisa_kev: Boolean(p.in_cisa_kev), exploit_maturity: p.exploit_maturity ?? 'none',
            transitive_rdep_count: p.transitive_rdep_count ?? 0, score: p.score ?? 0,
            upstream_version: p.upstream_version ?? null,
          }));
          resolve({ packages: pkgs, scanned_at: Date.now() });
        } catch { resolve(undefined); }
      });
    });
    req.on('error', () => resolve(undefined));
    req.write(body);
    req.end();
  });
}

async function scanActiveFile(): Promise<void> {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showWarningMessage('selvo: No active editor.');
    return;
  }
  if (!isSupportedFile(editor.document)) {
    vscode.window.showWarningMessage('selvo: This file type is not supported for scanning.');
    return;
  }
  await runScan(editor.document);
}

async function scanWorkspace(): Promise<void> {
  const docs = vscode.workspace.textDocuments.filter(isSupportedFile);
  if (!docs.length) {
    vscode.window.showInformationMessage('selvo: No supported manifest/lock files found in workspace.');
    return;
  }
  await Promise.all(docs.map(d => runScan(d)));
  vscode.window.showInformationMessage(`selvo: Scanned ${docs.length} file(s).`);
}

function clearCache(): void {
  _cache.clear();
  for (const ed of vscode.window.visibleTextEditors) {
    ed.setDecorations(_cveDecoration, []);
    ed.setDecorations(_kevDecoration, []);
  }
  _statusBar.text = '⚡ selvo';
  vscode.window.showInformationMessage('selvo: Cache cleared.');
}

function openDashboard(): void {
  const apiUrl = cfg().apiUrl || 'http://localhost:8765';
  vscode.env.openExternal(vscode.Uri.parse(`${apiUrl}/dash/overview`));
}

// --------------------------------------------------------------------------
// Decorations
// --------------------------------------------------------------------------

/**
 * Walk the document lines looking for package name mentions that match
 * a package in the cached scan result, then apply underline decorations.
 */
function applyDecorations(editor: vscode.TextEditor): void {
  const filePath = editor.document.uri.fsPath;
  const result = _cache.get(filePath);
  if (!result) { return; }

  const minCvss = cfg().minCvssDecorate;
  const cveDecorations: vscode.DecorationOptions[] = [];
  const kevDecorations: vscode.DecorationOptions[] = [];

  const doc = editor.document;
  for (let i = 0; i < doc.lineCount; i++) {
    const line = doc.lineAt(i);
    const lineText = line.text;

    for (const pkg of result.packages) {
      if (pkg.max_cvss < minCvss && !pkg.in_cisa_kev) { continue; }

      // Match the package name anywhere on the line (case-insensitive)
      const idx = lineText.toLowerCase().indexOf(pkg.name.toLowerCase());
      if (idx === -1) { continue; }

      const range = new vscode.Range(i, idx, i, idx + pkg.name.length);
      const label = _makeLabel(pkg);

      const opts: vscode.DecorationOptions = {
        range,
        renderOptions: { after: { contentText: label } },
        hoverMessage: _makeHoverMessage(pkg),
      };

      if (pkg.in_cisa_kev) {
        kevDecorations.push(opts);
      } else {
        cveDecorations.push(opts);
      }
    }
  }

  editor.setDecorations(_cveDecoration, cveDecorations);
  editor.setDecorations(_kevDecoration, kevDecorations);
}

function _makeLabel(pkg: PackageRisk): string {
  const parts: string[] = [];
  if (pkg.cve_ids.length) { parts.push(`${pkg.cve_ids.length} CVE${pkg.cve_ids.length > 1 ? 's' : ''}`); }
  if (pkg.in_cisa_kev) { parts.push('⚠ KEV'); }
  if (pkg.max_cvss > 0) { parts.push(`CVSS ${pkg.max_cvss.toFixed(1)}`); }
  if (cfg().showEpss && pkg.max_epss > 0.01) {
    parts.push(`EPSS ${(pkg.max_epss * 100).toFixed(1)}%`);
  }
  return parts.length ? `  ← ${parts.join(' · ')}` : '';
}

function _makeHoverMessage(pkg: PackageRisk): vscode.MarkdownString {
  const md = new vscode.MarkdownString('', true);
  md.isTrusted = true;
  md.supportHtml = true;

  const kevBadge = pkg.in_cisa_kev ? '🔴 **CISA KEV**  ' : '';
  const matBadge =
    pkg.exploit_maturity === 'weaponized' ? '☢ **Weaponized exploit**  ' :
    pkg.exploit_maturity === 'poc' ? '⚠ **PoC exploit**  ' : '';

  md.appendMarkdown(`### ⚡ selvo — \`${pkg.name}\`\n\n`);
  md.appendMarkdown(`${kevBadge}${matBadge}\n\n`);
  md.appendMarkdown(`| | |\n|---|---|\n`);
  md.appendMarkdown(`| **Version** | \`${pkg.version}\` |\n`);
  if (pkg.upstream_version) {
    md.appendMarkdown(`| **Fix version** | \`${pkg.upstream_version}\` |\n`);
  }
  if (pkg.max_cvss > 0) {
    md.appendMarkdown(`| **CVSS** | ${pkg.max_cvss.toFixed(1)} |\n`);
  }
  if (pkg.max_epss > 0) {
    md.appendMarkdown(`| **EPSS** | ${(pkg.max_epss * 100).toFixed(2)}% exploited within 30d |\n`);
  }
  if (pkg.transitive_rdep_count > 0) {
    md.appendMarkdown(`| **Blast radius** | ${pkg.transitive_rdep_count.toLocaleString()} transitive rdeps |\n`);
  }
  md.appendMarkdown(`| **Score** | ${pkg.score.toFixed(1)} |\n`);

  if (pkg.cve_ids.length) {
    md.appendMarkdown(`\n**CVEs:** `);
    const shown = pkg.cve_ids.slice(0, 5);
    md.appendMarkdown(shown.map(c =>
      `[\`${c}\`](https://nvd.nist.gov/vuln/detail/${c})`
    ).join('  '));
    if (pkg.cve_ids.length > 5) {
      md.appendMarkdown(` _+${pkg.cve_ids.length - 5} more_`);
    }
  }

  md.appendMarkdown('\n\n---\n');
  const fixCmd = vscode.Uri.parse(
    `command:selvo.fix?${encodeURIComponent(JSON.stringify({ packageName: pkg.name }))}`
  );
  md.appendMarkdown(`[🔧 selvo fix](${fixCmd})  ·  `);
  md.appendMarkdown(`[📊 Dashboard](command:selvo.openDashboard)`);

  return md;
}

// --------------------------------------------------------------------------
// Status bar
// --------------------------------------------------------------------------

function updateStatusBar(): void {
  let totalCves = 0;
  let kevCount = 0;
  for (const result of _cache.values()) {
    for (const pkg of result.packages) {
      totalCves += pkg.cve_ids.length;
      if (pkg.in_cisa_kev) { kevCount += 1; }
    }
  }
  if (totalCves === 0) {
    _statusBar.text = '⚡ selvo: ✓ clean';
    _statusBar.backgroundColor = undefined;
  } else {
    const kev = kevCount > 0 ? ` · ${kevCount} KEV` : '';
    _statusBar.text = `⚡ selvo: ${totalCves} CVE${totalCves !== 1 ? 's' : ''}${kev}`;
    _statusBar.backgroundColor = kevCount > 0
      ? new vscode.ThemeColor('statusBarItem.errorBackground')
      : new vscode.ThemeColor('statusBarItem.warningBackground');
  }
}

// --------------------------------------------------------------------------
// Hover provider
// --------------------------------------------------------------------------

function provideHover(
  doc: vscode.TextDocument,
  position: vscode.Position,
): vscode.Hover | undefined {
  const result = _cache.get(doc.uri.fsPath);
  if (!result) { return undefined; }

  const line = doc.lineAt(position.line).text;
  for (const pkg of result.packages) {
    const idx = line.toLowerCase().indexOf(pkg.name.toLowerCase());
    if (idx === -1) { continue; }
    const range = new vscode.Range(position.line, idx, position.line, idx + pkg.name.length);
    if (range.contains(position)) {
      return new vscode.Hover(_makeHoverMessage(pkg), range);
    }
  }
  return undefined;
}

// --------------------------------------------------------------------------
// Commands
// --------------------------------------------------------------------------

async function fixPackage(args?: { packageName?: string }): Promise<void> {
  const pkgName = args?.packageName
    || await vscode.window.showInputBox({ prompt: 'Package name to fix' });
  if (!pkgName) { return; }

  const selvoPath = cfg().path || 'selvo';
  const terminal = vscode.window.createTerminal('selvo fix');
  terminal.sendText(`${selvoPath} fix --package "${pkgName}" --dry-run`);
  terminal.show();
}

async function setApiKey(): Promise<void> {
  const key = await vscode.window.showInputBox({
    prompt: 'Enter your selvo API key',
    password: true,
    placeHolder: 'sk-...',
    ignoreFocusOut: true,
  });
  if (key === undefined) { return; }
  if (key === '') {
    await _secrets.delete('selvo.apiKey');
    vscode.window.showInformationMessage('selvo: API key cleared.');
  } else {
    await _secrets.store('selvo.apiKey', key);
    vscode.window.showInformationMessage('selvo: API key saved to Secret Storage.');
  }
}
