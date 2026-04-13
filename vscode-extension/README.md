# selvo VS Code Extension

Inline CVE annotations, EPSS scores, CISA KEV badges, and `selvo fix` integration for Linux package files and lock files directly in VS Code.

## Features

- **Inline decorations** — underlines on any line containing a vulnerable package name, with a trailing label showing CVE count, CVSS, and EPSS
- **Hover cards** — rich hover panels with full CVE list (NVD links), CVSS, EPSS, KEV status, blast radius (transitive rdep count), and a one-click `selvo fix` button
- **Status bar** — persistent `⚡ selvo: N CVEs · K KEV` counter at the bottom right; red background when KEV packages are detected
- **Auto-scan** — triggered on file open and save for all supported manifest/lock file types
- **`selvo fix`** — opens an integrated terminal running `selvo fix --package <name> --dry-run`
- **Dashboard** — opens the selvo web dashboard (`/dash/overview`) in the browser
- **Remote API mode** — optionally routes scans through the selvo SaaS REST API instead of the local CLI

## Supported File Types

| File | Ecosystem |
|---|---|
| `requirements*.txt`, `Pipfile`, `pyproject.toml` | Python / PyPI |
| `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` | Node.js / npm |
| `Cargo.toml`, `Cargo.lock` | Rust / crates.io |
| `go.mod`, `go.sum` | Go modules |
| `Gemfile`, `Gemfile.lock` | Ruby / RubyGems |
| `pom.xml`, `build.gradle`, `build.gradle.kts` | Java / Maven / Gradle |
| `composer.json`, `composer.lock` | PHP / Packagist |
| `*.csproj`, `packages.config` | .NET / NuGet |

## Requirements

**Local mode (default):** `selvo` must be on your `PATH` or configured via `selvo.path`.

```sh
pip install selvo
```

**Remote mode:** Set `selvo.apiUrl` and `selvo.apiKey` in settings to route scans through the selvo SaaS API.

## Extension Settings

| Setting | Default | Description |
|---|---|---|
| `selvo.path` | `"selvo"` | Path to the selvo CLI executable |
| `selvo.autoScan` | `true` | Auto-scan supported files on open/save |
| `selvo.minCvssDecorate` | `4.0` | Minimum CVSS to show inline decoration |
| `selvo.showEpss` | `true` | Show EPSS score in hover cards |
| `selvo.apiUrl` | `""` | Remote API URL (optional) |
| `selvo.apiKey` | `""` | API key for remote scans |
| `selvo.policy` | `""` | Path to `selvo.policy.yml` |
| `selvo.ecosystem` | `"all"` | Default ecosystem for workspace scans |

## Commands

| Command | Description |
|---|---|
| `selvo: Scan Current File` | Scan the active editor's file |
| `selvo: Scan Workspace` | Scan all supported files in the workspace |
| `selvo: Fix Package` | Run `selvo fix` for the selected package |
| `selvo: Clear Cached Results` | Remove all cached scan results |
| `selvo: Open Web Dashboard` | Open the selvo dashboard in the browser |

## Building from Source

```sh
cd vscode-extension
npm install
npm run compile
npm run package   # produces selvo-security-0.1.0.vsix
code --install-extension selvo-security-0.1.0.vsix
```

## Publishing to Marketplace

```sh
npm run package
vsce publish
```

Requires a Personal Access Token from [marketplace.visualstudio.com](https://marketplace.visualstudio.com/manage).
