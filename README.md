# selvo

<!-- mcp-name: io.github.Cope-Labs/selvo -->

**Know what's actually dangerous on your Linux servers.**

[![PyPI](https://img.shields.io/pypi/v/selvo?label=PyPI)](https://pypi.org/project/selvo/)
[![Container](https://img.shields.io/badge/ghcr.io-cope--labs%2Fselvo-2496ED?logo=docker)](https://github.com/Cope-Labs/selvo/pkgs/container/selvo)
[![GitHub Action](https://img.shields.io/badge/Marketplace-selvo--security--scan-181717?logo=github)](https://github.com/marketplace/actions/selvo-security-scan)
[![License: ELv2](https://img.shields.io/badge/License-ELv2-orange.svg)](LICENSE)
[![CodeQL](https://github.com/Cope-Labs/selvo/actions/workflows/codeql.yml/badge.svg)](https://github.com/Cope-Labs/selvo/actions/workflows/codeql.yml)
[![Live Report](https://github.com/Cope-Labs/selvo/actions/workflows/pages.yml/badge.svg)](https://copelabs.dev/selvo-report/)

selvo scans your installed packages, checks every CVE against 8 data sources, filters out what your distro already patched, and ranks the rest by blast radius and exploit probability. Not just a list --- a prioritized action plan.

**Live at [selvo.dev](https://selvo.dev)** | [Public Report](https://copelabs.dev/selvo-report/) | [GitHub Action](https://github.com/Cope-Labs/selvo-action)

---

## Quick Start

### Scan your server (60 seconds)

```bash
curl -s https://selvo.dev/install.sh | SELVO_API_KEY=sk_xxx bash
```

Collects your real installed packages, sends to the API for analysis, sets up daily monitoring via cron. Supports dpkg, rpm, pacman, apk.

Get a free API key at [selvo.dev](https://selvo.dev).

### GitHub Actions

```yaml
- uses: Cope-Labs/selvo-action@v1
  with:
    api-key: ${{ secrets.SELVO_API_KEY }}
```

Auto-detects runner packages. Posts results as a PR comment. Fails on CISA KEV or weaponized exploits.

### curl

```bash
# Scan your actual packages
dpkg-query -W -f='${db:Status-Abbrev}  ${Package}  ${Version}\n' > packages.txt

curl -X POST https://selvo.dev/api/v1/scan/packages \
  -H "X-API-Key: $SELVO_API_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"packages\": \"$(cat packages.txt)\", \"ecosystem\": \"debian\"}"
```

### Container image scan

```bash
curl -X POST https://selvo.dev/api/v1/scan/image \
  -H "X-API-Key: $SELVO_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"image": "nginx:1.24"}'
```

### Pipe existing scanner output

```bash
# Already running Grype or Trivy? Send the JSON for prioritized results:
curl -X POST https://selvo.dev/api/v1/scan \
  -H "X-API-Key: $SELVO_API_KEY" \
  -d "{\"grype\": \"$(cat grype-results.json)\"}"
```

---

## What Makes It Different

**Distro-aware CVE filtering.** If Debian backported a fix into zlib 1.2.11, we don't flag it. We cross-reference the Debian Security Tracker to remove CVEs your distro already patched. Other scanners miss this and massively over-report.

**Blast radius scoring.** A CVE in a library that 200 packages depend on ranks higher than one in a leaf package. We build real dependency graphs from Debian Packages.gz, Alpine APKINDEX, and Arch repo DBs.

**Exploit intelligence.** CISA KEV status, public exploit availability, EPSS exploitation probability --- not just CVSS severity.

**Your actual packages.** We scan what's really installed on your system, not a generic reference list. The dashboard shows "Your system" vs "Reference scan" so you know exactly what you're looking at.

---

## Scoring (0--100)

| Signal | Weight | Source |
| --- | --- | --- |
| Dependency blast radius | 22% | Transitive reverse deps from package index |
| EPSS exploit probability | 20% | FIRST.org |
| Chokepoint centrality | 15% | Betweenness centrality via NetworkX |
| Version lag | 14% | Repology upstream vs installed |
| CVSS severity | 10% | NVD |
| Exploit maturity | 8% | CISA KEV + PoC/weaponized detection |
| Ecosystem popularity | 7% | Repology repo count |
| Download count | 2% | popcon / Homebrew |
| Days exposed | 2% | CVE disclosure date age |

Packages with no security signal are capped at 20. Runtime-loaded packages with CVEs get a 1.5x multiplier.

---

## API Endpoints

Base URL: `https://selvo.dev/api/v1`

### Scanning

| Endpoint | Description |
| --- | --- |
| `POST /scan/packages` | Scan real installed packages (most accurate) |
| `POST /scan/image` | Scan a container image |
| `POST /scan` | Scan SBOM / Grype / Trivy / lockfile |
| `POST /analyze` | Reference scan (common packages) |
| `POST /fleet/scan` | SSH fleet scan |

### Data

| Endpoint | Description |
| --- | --- |
| `GET /status/data` | Data source freshness (cache age per source, no auth) |
| `GET /jobs/{id}` | Poll job status |
| `GET /packages` | List packages with scores (filtered to issues by default) |
| `GET /packages/{name}` | Full detail for one package |
| `GET /cves` | List CVEs with EPSS/CVSS |
| `GET /exploits` | Packages with exploit data |
| `GET /advisories` | USN, Bodhi, RHSA advisory IDs |
| `GET /sla` | SLA breach report |
| `GET /patch-plan` | Ordered patch recommendations |
| `GET /diff` | Diff vs previous snapshot |

### Exports

| Endpoint | Description |
| --- | --- |
| `GET /report.sarif` | SARIF for GitHub Code Scanning |
| `GET /report.vex` | VEX for compliance |
| `GET /report.nist` | NIST 800-53 Rev 5 OSCAL |
| `GET /report.fedramp` | FedRAMP High OSCAL |
| `GET /report.pdf` | PDF compliance report |

### Policy and Fix

| Endpoint | Description |
| --- | --- |
| `POST /policy/check` | Evaluate policy-as-code against snapshot |
| `POST /fix` | Open upstream PRs for top-risk packages |

### Webhooks

| Endpoint | Description |
| --- | --- |
| `POST /orgs/{id}/webhooks` | Register Slack or generic webhook |
| `GET /orgs/{id}/webhooks` | List webhooks |
| `DELETE /orgs/{id}/webhooks/{wid}` | Remove webhook |

All endpoints require `X-API-Key` header. Get a free key at [selvo.dev](https://selvo.dev).

---

## Policy-as-Code

Define security gates in YAML and evaluate via API or dashboard:

```yaml
version: 1
block:
  on_kev: true
  on_weaponized: true
  min_cvss: 9.0
  min_score: 80
warn:
  on_poc: true
  min_cvss: 7.0
sla:
  critical: 7
  high: 30
  medium: 90
  low: 365
allow:
  cves:
    - id: CVE-2023-12345
      reason: "Not reachable in our deployment"
      expires: 2025-12-31
```

```bash
curl -X POST https://selvo.dev/api/v1/policy/check \
  -H "X-API-Key: $KEY" \
  -d '{"ecosystem":"debian","policy":{"version":1,"block":{"on_kev":true,"min_cvss":9.0}}}'
```

Or use the dashboard at [selvo.dev/dash/policy](https://selvo.dev/dash/policy).

---

## Webhook / Slack Alerts

Get notified when scans complete:

```bash
curl -X POST https://selvo.dev/api/v1/orgs/myorg/webhooks \
  -H "X-API-Key: $KEY" \
  -d '{"url":"https://hooks.slack.com/services/T.../B.../xxx","kind":"slack"}'
```

Fires on every scan completion with package count, CVE count, and KEV status.

---

## Data Sources

| Source | What it provides |
| --- | --- |
| OSV.dev | CVE-to-package mapping with version ranges |
| FIRST.org EPSS | Daily exploitation probability scores |
| NVD | CVSS v3 base scores |
| Debian Security Tracker | Which CVEs are already patched by your distro |
| CISA KEV | Known Exploited Vulnerabilities catalog |
| Repology | Upstream versions, cross-distro comparison |
| Ubuntu USN | Ubuntu advisory IDs |
| Fedora Bodhi | Fedora advisory IDs |

---

## Supported Ecosystems

**Native OSV coverage (11):** Debian, Ubuntu, Fedora, Alpine, Rocky Linux, AlmaLinux, SUSE, openSUSE, Wolfi, Chainguard, Mageia.

**Via Debian namespace (5):** Arch, NixOS, Homebrew, Chocolatey, Winget.

Plus: CycloneDX/SPDX SBOM, Grype/Trivy JSON, 11 lockfile formats (requirements.txt, package-lock.json, Cargo.lock, go.sum, Gemfile.lock, composer.json, pom.xml, and more).

---

## CLI (Self-Hosted)

The full CLI runs locally with no API dependency:

```bash
pip install -e ".[dev,api]"

selvo analyze --ecosystem debian --limit 50
selvo scan requirements.txt --output sarif --file results.sarif
selvo policy check
selvo fix --dry-run --top 5
selvo fleet scan hosts.txt
sudo selvo runtime          # scan loaded .so files in live processes
selvo compliance --framework fedramp
selvo sla
selvo trend
selvo diff
```

---

## Self-Hosting (Server)

Run the same SaaS stack that powers selvo.dev on your own infrastructure.
Five-minute install via Docker Compose:

```bash
git clone https://github.com/Cope-Labs/selvo.git
cd selvo/deploy/selfhost
cp .env.example .env             # set SELVO_API_SECRET, NVD_API_KEY, etc.
cp Caddyfile.example Caddyfile   # set your domain
docker compose up -d
```

Caddy handles automatic Let's Encrypt TLS. The `selvo` image is multi-arch
(amd64 + arm64) and is rebuilt on every push to `main`. See
[deploy/selfhost/README.md](deploy/selfhost/README.md) for sizing,
backups, Cloudflare-in-front guidance, and what isn't included.

The ELv2 license lets you self-host for your own organization, modify
the source, and redistribute. It does **not** let you offer selvo as a
managed service to third parties — for that contact <licensing@cope-labs.dev>.

---

## MCP Server (AI Assistant Integration)

16 tools for Claude Desktop, Cursor, and other MCP-compatible agents:

```json
{
  "mcpServers": {
    "selvo": { "command": "selvo-mcp" }
  }
}
```

Tools: `analyze_packages`, `check_local_risk`, `describe_package`, `list_cves`, `patch_plan`, `fleet_scan`, `get_sla_report`, and more.

---

## Pricing

| Plan | Requests/day | Price |
| --- | --- | --- |
| Free | 5 | $0 |
| Pro | 10,000 | $49/mo |
| Enterprise | 1,000,000 | $299/mo |

Self-serve at [selvo.dev](https://selvo.dev). No credit card required for free tier.

---

## License

[Elastic License 2.0 (ELv2)](LICENSE) --- free to use, modify, and self-host. You may not offer selvo as a managed service to third parties.

---

Built by [Cope Labs LLC](https://selvo.dev) | [Privacy](https://selvo.dev/privacy) | [Terms](https://selvo.dev/terms) | [Status](https://stats.uptimerobot.com/xHk9U5qBJK)
