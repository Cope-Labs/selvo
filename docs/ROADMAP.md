# selvo — Roadmap & High-Value Additions

> Updated March 10, 2026. ~18,700 lines of Python across 22 CLI commands, 16 MCP tools,
> 8 output formats, 37 analysis modules, native Slack/PagerDuty, policy-as-code,
> dependency confusion detection, time-series trends, eBPF runtime scanning, SLSA attestation,
> auto-remediation PRs, offline/air-gap mode, multi-tenant SaaS API.

---

## Tier 1 — Shipped

| Feature | Module | Notes |
|---|---|---|
| CVE/CVSS v4.0/EPSS/KEV enrichment | `analysis/cve`, `cvss`, `epss`, `exploit` | Full pipeline |
| SARIF 2.1.0 output | `reporters/sarif` | GitHub Code Scanning compatible |
| 11-format lockfile input | `discovery/lockfile` | requirements → Cargo → go.sum |
| Policy-as-code engine | `analysis/policy` | YAML gates, CVE allow-list, SLA enforcement |
| Time-series trend store + sparklines | `analysis/trend` | SQLite-backed, SVG in HTML |
| Slack Block Kit + PagerDuty Events v2 | `analysis/watcher` | URL-scheme dispatch |
| Dependency confusion + typosquatting | `analysis/dep_confusion` | Lev-1, version confusion, namespace |
| `selvo test` CI regression gate | `cli` | Baseline diff + policy check in one step |
| GHA composite action | `.github/actions/selvo-scan` | SARIF upload, KEV/score gate |
| Reachability analysis | `analysis/reachability` | Go (`govulncheck`), Python (AST walk) |
| `selvo fix` — auto-remediation PR | `analysis/fix` | GitHub API branch/commit/PR, no clone |
| Compliance mapping | `analysis/compliance`, `data/compliance_map.json` | 33 CWEs, NIST/FedRAMP/SOC2/PCI/DoD |
| SLSA attestation verification | `analysis/slsa` | Sigstore Rekor, SLSA level 0–3 |
| OSV local mirror / air-gap mode | `analysis/osv_local`, `selvo sync` | SQLite, ~400 MB, zero outbound |
| Runtime loaded-library scanning | `analysis/runtime`, `analysis/ebpf_tracer` | `/proc/<pid>/maps` + eBPF kprobes |
| SaaS API + multi-tenant auth | `api/server`, `api/auth`, `api/tenancy` | HMAC API keys, per-org isolation |
| Stripe billing integration | `api/billing` | Stripe v2 thin-event webhooks |
| VS Code extension | `vscode-extension/` | Inline CVE annotations, `selvo fix` button |
| WinGet / Homebrew / Chocolatey | `discovery/winget`, `homebrew`, `chocolatey` | Mixed-fleet enterprise support |
| SLA breach reporting | `analysis/sla` | ok / warn / breach / critical bands |

---

## Tier 2 — Highest remaining value

### 1. Real Reachability for Java / Rust

Current reachability covers Go (`govulncheck`) and Python (AST). Java and Rust are the
other major ecosystems with significant CVE surface.

- **Java:** integrate `dependency-check` call-graph mode or `diff-jars`
- **Rust:** `cargo-geiger` for unsafe reachability; `cargo-vet` for CVE-level graphs

### 2. PDF Compliance Reports

The `reporters/compliance.py` module outputs JSON and Markdown. Auditors often require PDF.
Add `reportlab` or `weasyprint` rendering as an optional dependency.

### 3. GitHub Marketplace Submission

The composite action (`selvo-scan`) has full `branding` metadata. Requires clicking through
`marketplace.github.com` with a `v*` tag push — no code changes needed.

### 4. VS Code Marketplace Publish

The extension is live on Open VSX (`selvo-security`). Azure DevOps PAT is required for
the VS Code Marketplace listing. Unblocked once PAT is issued.

### 5. Data Moat — Anonymised EPSS Velocity Aggregation

Every `selvo analyze` run produces per-package EPSS deltas. An opt-in telemetry layer
across deployed instances would generate a real-time early-warning signal: packages whose
EPSS is spiking across many orgs before CISA formally KEV-lists them. This is the
Cloudflare threat intelligence model applied to Linux package risk.

---

## Strategic Considerations

### Positioning vs. competitors

| Tool | CVE depth | Blast radius | Policy-as-code | SLSA | Reachability | Runtime | Linux-native |
|---|---|---|---|---|---|---|---|
| **selvo** | EPSS+KEV+CVSS v4 | ✅ transitive rdeps | ✅ | ✅ | ✅ Go+Py | ✅ eBPF | ✅ |
| Grype | Basic | ❌ | ❌ | ❌ | ❌ | ❌ | Partial |
| Snyk | Good | ❌ | Paid tier | ❌ | Basic | ❌ | ❌ |
| Endor Labs | Good | ❌ | Paid | ❌ | ✅ | ❌ | ❌ |
| Chainguard | Minimal | ❌ | ❌ | ✅ | ❌ | ❌ | ✅ container |

### Build order recommendation (remaining)

```
Q2 2026   Java/Rust reachability     → complete reachability coverage
Q2 2026   PDF compliance reports     → auditor-ready artifacts
Q2 2026   GH Marketplace submission  → distribution (no code needed)
Q3 2026   Telemetry / data moat      → early-warning signal layer
```
