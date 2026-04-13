# How selvo Works

selvo scans your Linux packages for vulnerabilities and tells you which ones to patch first. Not just a CVE list — a prioritized risk score that factors in exploit probability, blast radius, and whether your distro has already backported the fix.

## What Makes It Different

Most scanners dump a list of CVEs and call it a day. selvo goes further:

- **Distro-aware filtering**: If Debian backported a fix for CVE-2018-25032 into zlib 1.2.11, we don't flag it. Other scanners do.
- **Blast radius scoring**: A CVE in a library that 200 packages depend on ranks higher than one in an isolated tool.
- **Exploit intelligence**: CISA KEV status, public exploit availability, and EPSS exploitation probability — not just CVSS severity.
- **Your actual packages**: We scan what's really installed on your system, not a generic reference list.

## The Pipeline

When you scan your system, here's what happens:

### 1. Collect Your Packages

You send your installed package list (via the agent, CI action, or API). We parse output from dpkg, rpm, pacman, or apk.

### 2. Look Up CVEs

Each package + version is checked against OSV.dev for known vulnerabilities. We resolve Debian binary package names to source names so CVE matching is accurate.

### 3. Filter Already-Patched CVEs

We cross-reference the Debian Security Tracker to remove CVEs that your distro has already resolved via backported patches. This is critical — without it, every scanner over-reports.

### 4. Enrich With Exploit Intelligence

For each remaining CVE:

- **EPSS** (FIRST.org): The probability this CVE gets exploited in the next 30 days (0-100%)
- **CVSS** (NVD): Severity score (0-10)
- **CISA KEV**: Is this being actively exploited in the wild right now?
- **Exploit maturity**: Weaponized, proof-of-concept, or theoretical?

### 5. Compute Blast Radius

We build a dependency graph from your ecosystem's package index:

- **Transitive reverse dependencies**: How many packages break if this one is vulnerable?
- **Betweenness centrality**: Is this package a chokepoint that sits on many dependency paths?

### 6. Score and Rank

Each package gets a composite risk score (0-100):

| Signal | Weight | Why it matters |
| --- | --- | --- |
| Dependency blast radius | 22% | A vuln in a core lib affects everything downstream |
| EPSS exploit probability | 20% | What's actually being exploited, not just theoretically bad |
| Chokepoint centrality | 15% | Packages that are dependency bottlenecks |
| Version lag | 14% | How far behind upstream you are |
| CVSS severity | 10% | Traditional severity score |
| Exploit maturity | 8% | Weaponized > PoC > theoretical |
| Ecosystem popularity | 7% | Widely-used packages have more attacker interest |
| Download count | 2% | Usage signal |
| Days exposed | 2% | Older unpatched CVEs are more urgent |

Packages with no security signal (no CVEs, not outdated, no exploits) are capped at 20 to prevent popular-but-safe packages from ranking high.

## Data Sources

| Source | What we get |
| --- | --- |
| OSV.dev | CVE-to-package mapping with version ranges |
| FIRST.org EPSS | Daily exploitation probability scores |
| NVD | CVSS v3 base scores |
| Debian Security Tracker | Which CVEs are already patched in your distro |
| CISA KEV | Known Exploited Vulnerabilities catalog |
| Repology | Upstream versions, cross-distro comparison |
| Ubuntu/RHEL trackers | Distro-specific patch dates |

## Supported Ecosystems

**16 ecosystems.** 11 with native OSV CVE coverage: Debian, Ubuntu, Fedora, Alpine, Rocky Linux, AlmaLinux, SUSE, openSUSE, Wolfi, Chainguard, Mageia. Plus 5 via Debian namespace: Arch, NixOS, Homebrew, Chocolatey, Winget.

## Export Formats

- **SARIF** — GitHub Code Scanning integration
- **VEX** — Vulnerability Exploitability eXchange for compliance
- **NIST 800-53 OSCAL** — Federal security control mapping
- **FedRAMP OSCAL** — FedRAMP High baseline assessment
- **CycloneDX SBOM** — Software Bill of Materials
- **JSON / HTML / Markdown** — For reports and dashboards

## Connect In 60 Seconds

### Server agent (most accurate)

```bash
curl -s https://selvo.dev/install.sh | SELVO_API_KEY=sk_xxx bash
```

Scans your real packages, sets up daily monitoring via cron.

### GitHub Actions

```yaml
- uses: Cope-Labs/selvo-action@v1
  with:
    api-key: ${{ secrets.SELVO_API_KEY }}
```

Auto-detects runner packages. Writes summary to PR. Fails on KEV/weaponized gates.

### Container image

```bash
curl -X POST https://selvo.dev/api/v1/scan/image \
  -H "X-API-Key: $KEY" \
  -d '{"image":"nginx:1.24"}'
```

### Pipe existing scanner output

Already running Grype or Trivy? Send the JSON to selvo for prioritized results:

```bash
curl -X POST https://selvo.dev/api/v1/scan \
  -H "X-API-Key: $KEY" \
  -d "{\"grype\": \"$(cat grype-results.json)\"}"
```

### Slack alerts

```bash
curl -X POST https://selvo.dev/api/v1/orgs/myorg/webhooks \
  -H "X-API-Key: $KEY" \
  -d '{"url":"https://hooks.slack.com/services/...","kind":"slack"}'
```

Get notified when new CVEs hit your packages.

## API Reference

Full REST API at `https://selvo.dev/api/v1/`. Key endpoints:

| Endpoint | Description |
| --- | --- |
| `POST /scan/packages` | Scan your installed packages (dpkg/rpm/pacman/apk output) |
| `POST /scan/image` | Scan a container image |
| `POST /scan` | Scan SBOM, Grype, or Trivy JSON |
| `GET /packages` | List packages with scores |
| `GET /cves` | List CVEs with EPSS/CVSS |
| `GET /report.sarif` | SARIF export |
| `GET /report.vex` | VEX export |
| `GET /patch-plan` | Ordered patch recommendations |

All endpoints require an `X-API-Key` header. Get a free key at [selvo.dev](https://selvo.dev).

## Methodology Notes

- CVE matching uses version range analysis, not CPE. This is more accurate for distro packages but may miss edge cases where OSV coverage is incomplete.
- EPSS scores update daily. A CVE with 0.01% EPSS today could jump to 90% tomorrow if an exploit drops.
- The Debian Security Tracker filter only applies to Debian/Ubuntu packages. RHEL/Fedora filtering uses Bodhi advisory status.
- Scores are relative within a scan — a score of 50 means "more urgent than most packages in this scan," not an absolute risk level.
- We do not store your package lists beyond the analysis session. Results are cached per-org for dashboard viewing.
