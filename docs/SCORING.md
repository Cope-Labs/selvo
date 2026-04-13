# selvo Risk Score — How It Works

selvo assigns every package a **composite risk score between 0 and 100**. The
score is designed to answer one question: *"If I can only fix one package today,
which one has the highest expected security value?"*

The score is computed by `selvo/prioritizer/scorer.py` every time you run
`selvo analyze`, `selvo scan`, `selvo fleet`, or any pipeline command.

---

## The Nine Factors

Weights sum to **100 points**. Each factor produces a normalised 0–1 sub-score
that is multiplied by its weight, then the weighted values are summed.

| # | Factor | Weight | Signal |
|---|---|---|---|
| 1 | Transitive reverse-dep count | **22** | True blast radius: how many packages in the full dep graph ultimately depend on this one |
| 2 | EPSS exploitation probability | **20** | FIRST.org probability that this CVE will be exploited in the wild within 30 days |
| 3 | Betweenness centrality | **15** | Chokepoint score — how often this package sits on the shortest path between others in the dep graph |
| 4 | Version gap | **14** | How far behind the installed version is vs. current upstream (major × 10 + minor versions) |
| 5 | CVSS base score | **10** | NVD CVSS v3 severity of the worst open CVE |
| 6 | Exploit maturity | **8** | Known exploit availability (weaponized / PoC / none), with CISA KEV and OSS-Fuzz adjustments |
| 7 | Direct reverse-dep count | **7** | Fallback blast-radius via Repology repo count (used before full graph traversal) |
| 8 | Download count | **2** | Usage popularity proxy |
| 9 | Exposure days | **2** | Urgency from CVE age — capped at 730 days (2 years) for full score |

---

## Factor Detail

### 1. Transitive reverse-dep count (weight 22)

The most important factor. If `zlib` is patched, every package that transitively
depends on it benefits. This count comes from a full depth-first traversal of the
dependency graph built by NetworkX.

Score = `min(pkg.transitive_rdep_count / max_in_cohort, 1.0)`

### 2. EPSS (weight 20)

The [Exploit Prediction Scoring System](https://www.first.org/epss/) is a
machine-learning model trained on real-world exploit data. A score of `0.95`
means 95% of CVEs with similar characteristics are exploited within 30 days.

If EPSS data is not yet fetched for a package, a discounted fallback is used:
`min(cve_count / 10, 1.0) × 0.5`

### 3. Betweenness centrality (weight 15)

Packages that sit at the intersection of many dependency paths are high-leverage
targets — a vulnerability in them is reachable from many more call sites. This is
the graph-theoretic complement to the simpler reverse-dep count.

The value is pre-normalised to `[0, 1]` by NetworkX.

### 4. Version gap (weight 14)

Being many versions behind is a proxy for accumulated unpatched CVEs and indicates
that the package maintainer has work ready to ship.

```
gap = (upstream_major - installed_major) × 10 + (upstream_minor - installed_minor)
score = min(gap / 20, 1.0)
```

A package 2 major versions behind scores `~1.0`. A package on the current minor but
one patch behind scores `~0`.

### 5. CVSS (weight 10)

NVD CVSS v3 base score (`0–10`) normalised to `[0, 1]`. Uses the worst CVE
across all open vulnerabilities for the package.

### 6. Exploit maturity (weight 8)

| State | Base sub-score | Notes |
|---|---|---|
| `weaponized` | 1.0 | Active in-the-wild exploitation |
| `poc` | 0.5 | Public proof-of-concept exists |
| `none` | 0.0 | No known public exploit |

**CISA KEV bonus:** `+0.2` on top of `weaponized`, capped at 1.0. These are
definitively being exploited by threat actors right now.

**OSS-Fuzz discount:** If the package is actively fuzz-tested by Google OSS-Fuzz,
and an exploit exists, the maturity sub-score is reduced by 20%. The attack
surface is actively shrinking.

### 7. Direct reverse-dep count (weight 7)

Fallback blast-radius signal from Repology's repo count. Used when the full
transitive graph is not yet built. Normalised against the maximum in the current
cohort.

### 8. Download count (weight 2)

Usage popularity from the package ecosystem's download stats. Low weight — a
widely-downloaded package should not rank above one with a weaponized CVE just
because it is popular.

### 9. Exposure days (weight 2)

Days since the oldest open CVE was published. Urgency increases with age, capped
at 730 days (2 years) for a full score. A 23-year-old CVE (like some zlib issues)
scores 1.0 here.

---

## Special Cases

### No security signal — cap at 20

If a package has no CVEs, no EPSS > 0, no CVSS > 0, is not outdated, has no known
exploit, is not in the CISA KEV, and has fewer than 10,000 transitive reverse deps,
its score is capped at 20 regardless of download count or betweenness. This prevents
popular-but-clean packages like `bash` from outranking packages with real
exploitable vulnerabilities.

### Runtime loaded — 1.5× boost

If `selvo runtime` or `selvo fleet --runtime` has confirmed that a package's `.so`
files are currently mapped into a live process on the scanned host, **and** the
package has at least one open CVE, the final score is multiplied by `1.5`.

Rationale: the attack surface is confirmed reachable right now. This is the
difference between "installed on disk" and "an attacker can reach this code
through a network request this second."

---

## Reading the Output

```
Rank  Package     Score   CVEs  EPSS   CVSS  Exploit   Rdeps    Runtime
 1    openssl     87.40     14  0.971   9.8  weaponized  8,241   ✓ loaded
 2    zlib         74.12      5  0.312   7.5  poc        37,000
 3    libcurl      61.88      3  0.180   8.1  none        2,100
```

- **Score** — composite 0–100 (or up to 150 if runtime boost applies)
- **EPSS** — 30-day exploitation probability from FIRST.org
- **Rdeps** — transitive reverse-dep count from the dependency graph
- **Runtime** — `✓ loaded` means confirmed in `/proc/<pid>/maps` on this host

---

## Updating the weights

All weights are defined as module-level constants in
`selvo/prioritizer/scorer.py`:

```python
_W_EPSS             = 20.0
_W_EXPLOIT_MATURITY =  8.0
_W_CVSS             = 10.0
_W_VERSION_GAP      = 14.0
_W_TRANSITIVE_RDEPS = 22.0
_W_BETWEENNESS      = 15.0
_W_REVERSE_DEPS     =  7.0
_W_DOWNLOADS        =  2.0
_W_EXPOSURE_DAYS    =  2.0
```

They must sum to 100. For automated use-cases where you want to weight differently
(e.g. a compliance-focused environment where CVSS is paramount), the recommended
approach is to run the full pipeline and re-rank with a custom script — the raw
sub-scores for each factor are not currently exposed in the JSON reporter, but a
`--raw-scores` flag is on the roadmap.
