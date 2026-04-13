# Changelog

All notable changes to **selvo** are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions correspond to PyPI releases of the `selvo` package.

---

## [0.1.9] — 2026-03-10

### Added
- `PackageRecord` fields `runtime_loaded`, `runtime_pids`, `runtime_procs` for
  live process correlation across the entire analysis pipeline
- `fleet --runtime` flag: SSH into each host, run runtime scan, merge results
  into worst-case fleet risk view
- MCP tool `check_runtime_risk` (tool #16): LLM-addressable runtime scan for a
  named package
- eBPF tracer improvements: `merge_ebpf_events`, `android_dlopen_ext` intercept,
  digit-strip in CVE index, bare file-descriptor leak fix
- CI security audit: pinned all `@master` GitHub Action refs to SHA digests,
  added explicit `permissions:`, gated deploy on CI pass, added job timeouts
- NIST CWE import script (`scripts/convert.py`)
- Fleet SSH: `StrictHostKeyChecking=accept-new` clarification in docs

### Fixed
- `_dpkg_map` symlink resolution for multi-arch `.so` paths
- Branch collision guard in `selvo fix` when a PR branch already exists
- `shell=True` removed from fleet subprocess calls (security hardening)
- Timing attack in API key comparison replaced with `hmac.compare_digest`
- Arch Linux and NixOS CVE warning thresholds corrected
- Slack webhook URL now accepts `SELVO_SLACK_WEBHOOK` environment variable as
  alternative to the policy YAML field
- Repology and Scorecard HTTP errors now logged at `WARNING` level instead of
  silently swallowed

### Changed
- `selvo fix` E2E test suite added (covers branch creation, PR open, dry-run)

---

## [0.1.8] — 2026-02-20

### Added
- **Elastic License 2.0 (ELv2)** — replaced MIT; prohibits offering selvo as a
  competing managed service
- VS Code extension published to **Open VSX Registry** (`selvo-security`)
- SPDX and ELv2 copyright headers added to all source files
- Extension bumped to 0.1.1 with correct ELv2 metadata

### Changed
- PyPI trusted publishing via OIDC — no stored secrets in CI

---

## [0.1.7] — 2026-02-05

### Added
- **Stripe billing integration** (`api/billing.py`): Pro ($49/mo) and Enterprise
  ($299/mo) products; checkout session + thin-event webhook handler
- Dashboard pricing page with checkout redirect (`api/dashboard.py`)
- Persistent Fly.io volume for SQLite data between deploys
- Daily analysis cron workflow (GitHub Actions)
- Root URL redirect to dashboard; authenticated daily cron re-analysis
- API auth gate: `SELVO_API_AUTH=1` env var enables HMAC key enforcement

### Fixed
- Duplicate `Request` import removed (ruff F401); unused `price_id` removed
  (ruff F841)
- Volume creation step simplified in deploy workflow
- Silent failure in CI deploy corrected

---

## [0.1.6] — 2026-01-18

### Added
- **Runtime scanning** (`analysis/runtime.py`): reads `/proc/<pid>/maps` to
  confirm which `.so` files are live in running processes
- **eBPF tracer** (`analysis/ebpf_tracer.py`): kprobe-based `dlopen` intercept,
  collects CVE-correlated package list from kernel events
- `selvo runtime` CLI command: scan all PIDs (`--all`), watch mode
  (`--watch --watch-duration`)
- Runtime boost in scorer: 1.5× multiplier when a package's `.so` is confirmed
  loaded and has open CVEs
- Source-binary path expansion, parallel per-PID scanning, `pacman`/`apk` binary
  path resolution

---

## [0.1.5] — 2026-01-04

### Added
- **SLSA attestation verification** (`analysis/slsa.py`): queries Sigstore Rekor
  to assign SLSA provenance level 0–3 per package
- `selvo attest` CLI command: `--min-level`, `--fail-below` gates
- **OSV local mirror** (`analysis/osv_local.py`): downloads and indexes the full
  OSV advisory database into SQLite (~400 MB)
- `selvo sync` CLI command: `selvo sync osv`, `selvo sync epss`, `--check` flag
  for offline validation

---

## [0.1.4] — 2025-12-14

### Added
- **SaaS REST API** (`api/server.py`, `api/auth.py`, `api/tenancy.py`): FastAPI
  server with 34 routes, per-org isolation, HMAC API key auth
- `selvo api` CLI command to start the server
- `selvo api-key create/list/revoke` CLI subcommands
- Multi-tenant tenancy model: per-org data isolation
- Docker Compose + Caddyfile reverse-proxy configuration
- Helm chart for Kubernetes deployment

---

## [0.1.3] — 2025-11-28

### Added
- **Reachability analysis** (`analysis/reachability.py`): Go (`govulncheck`
  integration) and Python (AST call-graph walk) support
- **Auto-remediation** (`analysis/fix.py`): opens upstream GitHub PRs via GitHub
  API without cloning; `selvo fix --dry-run`, `--top N`, `--package`
- **VS Code extension** (`vscode-extension/`): inline CVE severity annotations,
  one-click `selvo fix` button, package hover cards
- `selvo watch add/start/status` continuous monitoring daemon
- Slack Block Kit and PagerDuty Events v2 alerts with 3-attempt exponential
  backoff (2 s / 4 s)

---

## [0.1.2] — 2025-11-09

### Added
- **Compliance mapping** (`analysis/compliance.py`, `data/compliance_map.json`):
  33 CWEs mapped to NIST 800-53, FedRAMP High, SOC 2 Type II, PCI-DSS v4.0,
  DoD IL4
- `selvo compliance` CLI command with JSON and Markdown output
- **SLA breach reporting** (`analysis/sla.py`): ok / warn / breach / critical
  bands; `selvo sla` with configurable day thresholds
- **Dependency confusion detection** (`analysis/dep_confusion.py`): namespace
  hijacking, Levenshtein-1 typosquatting, version confusion via PyPI / npm
  cross-check
- `selvo deps` CLI command
- SARIF 2.1.0 reporter (`reporters/sarif.py`) — GitHub Code Scanning compatible
- VEX reporter (`reporters/vex.py`), CycloneDX SBOM reporter (`reporters/sbom.py`)
- `selvo test` CI regression gate: baseline diff + policy gate in one step
- GitHub Actions composite action (`.github/actions/selvo-scan`): SARIF upload,
  KEV / score gate

---

## [0.1.1] — 2025-10-22

### Added
- **Fleet scanning** (`analysis/fleet.py`): SSH-based multi-host package
  collection, worst-case merged risk view, `--dry-run` validation mode
- WinGet, Homebrew, Chocolatey discovery backends for mixed-fleet enterprise
  support
- NixOS and Alpine Linux discovery backends
- `selvo distro-compare`: cross-distro version comparison and supply-chain lag
  table
- `selvo scan`: SBOM (CycloneDX / SPDX), Grype JSON, Trivy JSON, Docker image,
  tarball, and 11-format lockfile ingestion
- Time-series trend store with sparklines (`analysis/trend.py`): SQLite-backed,
  SVG output in HTML reports
- HTML reporter with embedded sparklines (`reporters/html.py`)
- Policy-as-code engine (`analysis/policy.py`): YAML gates on KEV, CVSS, EPSS,
  SLA; CVE allow-list with expiry dates; `selvo policy check`
- `selvo.policy.yml` default configuration shipped with the package

### Fixed
- Arch Linux package discovery off-by-one in API pagination
- Alpine `apk` version string normalisation for packaging.version compatibility

---

## [0.1.0] — 2025-10-01

### Added
- Core CVE/CVSS/EPSS/KEV enrichment pipeline
- Package discovery for Debian, Ubuntu, Fedora, Arch Linux
- Blast-radius scoring engine (`prioritizer/scorer.py`) — 9-factor composite
  score with reverse-dependency graph weighting
- Dependency graph via NetworkX (`graph/builder.py`)
- `selvo analyze`, `selvo graph`, `selvo discover`, `selvo patch`, `selvo cache`,
  `selvo diff` CLI commands
- JSON, Markdown, terminal (Rich) reporters
- OSV, NVD, EPSS, Repology, Scorecard, OSS-Fuzz enrichment sources
- Upstream version tracking via `analysis/upstream.py`
