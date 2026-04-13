# selvo as a Cross-Distro Package Health Standard — Thread Summary

> Conversation: March 6–7, 2026  
> Context: Exploring whether selvo could anchor a proposed standard grammar for Linux package metadata across major ecosystems.

---

## The Core Idea

selvo already normalizes five Linux ecosystems (Debian/apt, Fedora/rpm, Arch/pacman, Alpine/apk, NixOS/nixpkgs) into one canonical `PackageRecord` model. The question raised: could that normalization work be contributed upstream as a proposed standard — making similar fields across distros explicitly interoperable, rather than each ecosystem defining them in isolation?

---

## What selvo Already Does (Verified Against Codebase)

### Canonical data model — `selvo/discovery/base.py`

`PackageRecord` is the de-facto cross-distro schema:

```
name, ecosystem, version, upstream_version,
description, homepage, upstream_repo,
dependencies, dependents, download_count, reverse_dep_count,
cve_ids, fix_refs, max_cvss, max_epss, score
```

`FixRef` — links a CVE to a specific upstream commit, PR, or issue URL (type: FIX | REPORT | WEB).

`PrOpportunity` — an actionable upstream patch candidate, scored and ranked.

### Discovery adapters — `selvo/discovery/`

Each adapter fetches from an ecosystem-specific API or curated fallback list and normalizes into `PackageRecord`:

| Adapter | Source |
|---|---|
| `debian.py` | popcon.debian.org (by_inst ranking) |
| `ubuntu.py` | Debian popcon (shared source packages) |
| `fedora.py` | mdapi.fedoraproject.org + curated fallback |
| `arch.py` | archlinux.org packages JSON API (Core repo) |
| `alpine.py` | Curated `_ALPINE_CORE` list (no public ranking API) |
| `nixos.py` | Curated `_NIX_CORE` list (no public ranking API) |

The naming divergence problem is visible here: `libc6` (Debian binary) → `glibc` (Arch, Fedora, NixOS) → `musl` (Alpine) — same function, three different names, zero standard cross-reference.

### Analysis pipeline — `selvo/analysis/`

| Module | Source | What it adds to `PackageRecord` |
|---|---|---|
| `versions.py` | Repology API | `upstream_version`, distro `version` fallback, `download_count` (repo-count proxy) |
| `cve.py` | OSV.dev (with Debian binary→source name translation) | `cve_ids` |
| `epss.py` | FIRST.org EPSS API (batched, 100 CVEs/req) | `max_epss` (0–1 exploitation probability) |
| `cvss.py` | NVD API v2 (with smart budget/rate-limit management) | `max_cvss` (CVSS v3 base score 0–10) |
| `patch.py` | OSV advisory full fetch + regex pattern matching | `fix_refs` (GitHub commits, PRs, GitLab MRs, kernel.org patches) |
| `upstream.py` | Repology + homepage heuristic | `upstream_repo` (VCS URL) |
| `scorecard.py` | OpenSSF Scorecard API | `pkg.scorecard` (0–10) |
| `github.py` | GitHub Search API | `existing_pr_urls` on `PrOpportunity` |
| `distro_status.py` | Various | Distro-specific patch tracking |
| `rdeps.py` | Repology | `reverse_dep_count` refinement |

### Priority scorer — `selvo/prioritizer/scorer.py`

Weighted composite score (sums to 100):

| Signal | Weight | Source |
|---|---|---|
| EPSS exploitation probability | 20 | FIRST.org |
| CVSS v3 severity | 15 | NVD |
| Version gap vs upstream | 25 | Repology |
| Reverse dependency count (blast radius) | 25 | Repology |
| Download popularity | 15 | Repology |

Packages with no security signal (no CVEs, no EPSS, not outdated) are capped at 20 points regardless of popularity — prevents high-install but unvulnerable packages (bash) from topping the list over genuinely exploitable ones.

### Output formats — `selvo/reporters/`

- `terminal.py` — Rich table (color-coded)
- `json_reporter.py` — JSON
- `markdown.py` — Markdown
- `html.py` — HTML report (auto-published to GitHub Pages weekly)
- `sbom.py` — **CycloneDX 1.4 JSON SBOM**

### PURL support — already present

`reporters/sbom.py` has a full PURL type map and generates PURLs for every component in CycloneDX output:

```python
_PURL_TYPES = {
    "debian": "deb",   # pkg:deb/libc6@2.37
    "ubuntu": "deb",
    "fedora": "rpm",   # pkg:rpm/glibc@2.39
    "arch":   "alpm",  # pkg:alpm/glibc@2.39
    "alpine": "apk",   # pkg:apk/musl@1.2.5
    "nixos":  "nix",   # pkg:nix/glibc@2.39
}
```

**Gap:** PURLs are generated in SBOM output but are not a stored field on `PackageRecord` itself — they're absent from JSON, Markdown, and terminal output, and not available as a canonical key during analysis.

### CycloneDX custom properties already in use

The SBOM reporter already emits selvo-specific security fields as CycloneDX custom properties:

```
selvo:ecosystem
selvo:epss
selvo:cvss_max
selvo:priority_score
selvo:reverse_dep_count
selvo:upstream_version
```

These work under a vendor namespace. The standards proposal path is clearly defined: take these to the CycloneDX working group and propose them as a formal `linux-package-health` extension.

---

## What Does NOT Exist as a Standard (The Gap)

Across Debian, Fedora, Arch, Alpine, and NixOS:

- No standard machine-readable `upstream_version` field in distro package APIs
- No standard `epss` or `cvss` field in distro metadata
- No standard `reverse_dep_count` (blast radius) exposed by any distro API
- No standard `fix_refs` format linking a CVE to an upstream commit in distro metadata
- No agreed canonical cross-distro package identity (PURL exists as a spec but most distros don't embed PURLs in their own API responses)

The identity-layer problem (`libc6` ↔ `glibc`) is partially solved by PURL (the spec handles it via ecosystem-specific namespaces) and practically by Repology (which aggregates all names under one project), but neither is formally embedded in distro APIs.

**The existing partial standards:**

| Layer | Standard | Status |
|---|---|---|
| Package identity | PURL (OSI) | Spec exists; patchy distro adoption |
| Vulnerability data | OSV.dev schema | Adopted by Debian, Alpine; Arch/NixOS incomplete |
| SBOM envelope | CycloneDX (OWASP) + SPDX (LF) | Both mandated by US EO 14028; competing, neither won |
| Maintainer health | OpenSSF Scorecard | Exists; no distro embeds it in package metadata |
| Version currency | Repology | De-facto aggregator; no formal standards status |

---

## The Benefits of Compliance (By Stakeholder)

### Distro maintainers (Debian, Fedora, Arch, Alpine, NixOS)
- **Reduced duplicate security triage** — CVE-to-fix mappings discovered by one distro become immediately consumable by others without re-parsing
- **Automated upstream patch pressure** — `fix_refs` + standard envelope = tooling can open "has this fix landed" issues across all distros simultaneously from one upstream fix
- **Own the version-delta signal** — currently outsourced to Repology; a standard `upstream_version` field means distros own this data themselves

### Upstream projects (OpenSSL, systemd, curl, etc.)
- **Know blast radius before shipping** — `reverse_dep_count` exposed in a standard field means upstream maintainers can triage their own CVE queue with real impact data
- **Single structured disclosure** — one `fix_refs`-shaped disclosure reaches all five ecosystems in a parseable format instead of manual coordination with each distro's security team

### Enterprise / downstream consumers
- **SBOM compliance** — US EO 14028, EU Cyber Resilience Act, NIST SP 800-218 all require SBOMs; a standard schema makes a compliant SBOM trivially generated (`selvo analyze --output sbom` already produces CycloneDX)
- **FedRAMP/DISA STIG** — standard `upstream_version` + `max_epss` fields = programmatic proof of patch currency for federal procurement
- **Cyber insurance** — machine-readable `score` field showing ranked update priority is exactly the artifact insurers increasingly require for SOC 2 / cyber policy

### OSS security ecosystem (Sigstore, OpenSSF, CISA, Grype, Trivy, Syft)
- **Correlation without fingerprinting** — a canonical `purl` + `canonical_name` field eliminates the fragile lookup tables all security scanners maintain today to map `libc6` ↔ `glibc` ↔ `glibc` ↔ `musl`
- **Scorecard adoption flywheel** — if `scorecard_score` becomes a standard distro field, low scores visibly deprioritize packages in update queues, creating genuine maintainer incentive to improve

---

## Feasibility Assessment

**High.** Three reasons:

1. **The normalization is already proven.** selvo does it today across five ecosystems. The hardest engineering argument ("this is intractable across distros") is defeated by a working implementation.

2. **Regulatory tailwind is real.** EU Cyber Resilience Act (2025), US EO 14028, NIST SP 800-218. Distros want a defensible compliance artifact they can hand to auditors. The political environment hasn't been this favorable before.

3. **Low per-distro cost.** These fields already exist internally in every distro's tooling — they're just not published in a standard shape. Adding a JSON endpoint is not a packaging-system rewrite.

**Hard part:** canonical naming across distros. Solved practically by Repology; PURL solves the namespace problem but distros don't embed PURLs in their own API responses yet.

---

## Recommended Implementation Path

### Step 1 — Fix the one gap in selvo (1–2 weeks)

Add `purl` as a first-class field on `PackageRecord` in `selvo/discovery/base.py`. Generation logic already exists in `reporters/sbom.py` — it just needs to be moved upstream into the model so every output format and analysis step can use it as the canonical cross-distro key.

```python
@dataclass
class PackageRecord:
    name: str
    ecosystem: str
    purl: str = ""          # pkg:deb/libc6@2.37, pkg:rpm/glibc@2.39, etc.
    canonical_name: str = ""  # Repology project name (cross-distro canonical)
    ...
```

### Step 2 — Write a spec, not a README

One-pager: **"Linux Package Health Metadata — a minimal extension to CycloneDX."**

Define exactly these fields as a proposed extension:

| Field | Type | Description |
|---|---|---|
| `upstream_version` | string | Latest version at upstream VCS |
| `upstream_repo` | string (URL) | Canonical VCS repository |
| `epss_max` | float 0–1 | Max EPSS exploitation probability across CVEs |
| `cvss_max` | float 0–10 | Max CVSS v3 base score across CVEs |
| `fix_refs` | array | CVE → upstream commit/PR mappings |
| `reverse_dep_count` | integer | Packages that depend on this one (blast radius) |
| `scorecard` | float 0–10 | OpenSSF Scorecard maintainer health score |

Point to selvo as the reference implementation. Host it as a GitHub repo (not a Google Doc).

### Step 3 — Engage venues in order

| Venue | Why | How |
|---|---|---|
| **OpenSSF Supply Chain Integrity WG** | Coordinates across distros on exactly this. Meets bi-weekly. Alpha-Omega project funds real security work. | File issue / mailing list post with spec doc |
| **CycloneDX working group** | Extending existing standard is 10x easier than creating one. Formal extension/component-type RFC process exists. | Open discussion on `CycloneDX/cyclonedx-specification` GitHub |
| **Repology maintainer (Dmitry Marakasov)** | De-facto cross-distro identity layer. His buy-in on a formal API schema makes every other conversation easier. | Direct GitHub issue or email |
| **Debian Security Team / Fedora Product Security** | First adopters validate in practice. Debian historically most receptive. | debian-devel mailing list or DEP (Debian Enhancement Proposal) |
| **FOSDEM / Linux Plumbers Conference** | Public credibility, distro maintainers and tooling authors in one room. LPC has a distro/packaging track. | CFP for LPC 2026 opens ~May |

### Step 4 — Frame correctly

The proposal should be: *"here is a minimal schema, here is a CycloneDX extension, and here is a reference implementation anyone can run."*

**selvo is the proof, not the product.** Distros are allergic to adopting another project's roadmap but receptive to adopting a well-scoped schema with a working example.

---

## Realistic Timeline

| Milestone | Target |
|---|---|
| `purl` field in `PackageRecord`, spec doc drafted | 2–3 weeks |
| OpenSSF WG initial feedback | 6–8 weeks |
| CycloneDX extension PR open | 3 months |
| Alpine experimental endpoint (smallest bureaucracy) | 6–9 months |
| Fedora or Debian pilot | 12–18 months |
| Broad adoption | 24–36 months |

Slow by software standards, fast by standards-body standards. Regulatory pressure from CRA and NIST is compressing timelines compared to past efforts.

---

## Strongest Assets selvo Brings to This Conversation

1. Working cross-distro normalization across five ecosystems — the "this is intractable" objection is already closed
2. CycloneDX 1.4 SBOM output with PURL-typed components in every published report
3. The custom property namespace (`selvo:epss`, `selvo:upstream_version`, etc.) is the exact scaffold for a CycloneDX extension PR
4. OSV.dev + FIRST.org EPSS + NVD CVSS + OpenSSF Scorecard + Repology all already integrated — the external data dependencies of the proposed standard are all live
5. GitHub Pages auto-refresh means there's a public live report to point to: [copelabs.dev/selvo-report](https://copelabs.dev/selvo-report/)
6. The CVSS budget-management logic (distributing the NVD rate-limit across packages by EPSS-ranked CVE representatives) is production-grade thinking that demonstrates this isn't a toy

---

*Generated from conversation thread, March 6–7, 2026.*
