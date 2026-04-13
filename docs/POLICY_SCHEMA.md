# Policy Schema Reference — `selvo.policy.yml`

selvo's policy-as-code engine lets you define security gates in a YAML file that
is automatically discovered by `selvo policy check` and `selvo test`. Place the
file in the root of your repository.

```
selvo policy check                        # uses selvo.policy.yml in CWD
selvo policy check --policy custom.yml   # explicit path
selvo test                                # runs policy check + baseline diff
```

Exit codes:
- `0` — all checks passed
- `1` — one or more **block** gates triggered
- `2` — one or more **warn** gates triggered (no block)

---

## Full Schema

```yaml
version: 1   # required; only supported value is 1

sla:
  critical: 7      # integer, days
  high: 30
  medium: 90
  low: 365

allow:
  cves:
    - id: CVE-2023-XXXXX          # string, required
      reason: "..."               # string, required
      expires: 2025-12-31         # date (YYYY-MM-DD), optional

block:
  on_kev: true                    # boolean
  on_weaponized: true             # boolean
  min_cvss: 9.0                   # float, 0.0–10.0; 0.0 disables
  min_score: 0.0                  # float, 0.0–100.0; 0.0 disables
  min_epss: 0.0                   # float, 0.0–1.0; 0.0 disables

warn:
  on_poc: true                    # boolean
  min_cvss: 7.0                   # float, 0.0–10.0; 0.0 disables
  min_epss: 0.0                   # float, 0.0–1.0; 0.0 disables

notifications:
  slack: "https://hooks.slack.com/services/..."   # string, webhook URL
  pagerduty_routing_key: "your_routing_key"        # string
```

---

## Field Reference

### `version`

| Field | Type | Required | Allowed values |
|---|---|---|---|
| `version` | integer | yes | `1` |

The schema version. Always set to `1`.

---

### `sla`

Defines how many days your organisation has to remediate a CVE after it is
published, based on CVSS severity band.

| Field | Type | Default | Notes |
|---|---|---|---|
| `critical` | integer | 7 | CVSS ≥ 9.0 **or** CISA KEV-listed |
| `high` | integer | 30 | CVSS 7.0–8.9 |
| `medium` | integer | 90 | CVSS 4.0–6.9 |
| `low` | integer | 365 | CVSS < 4.0 |

`selvo sla` reads these thresholds and classifies each package as
`ok` / `warn` / `breach` / `critical` based on how many days a CVE has been open
vs. the threshold for its severity band.

---

### `allow.cves`

A list of CVE-level suppressions. Matching CVEs are excluded from all block and
warn gates.

| Field | Type | Required | Notes |
|---|---|---|---|
| `id` | string | yes | Full CVE identifier, e.g. `CVE-2023-44487` |
| `reason` | string | yes | Justification — becomes an audit record |
| `expires` | date (YYYY-MM-DD) | no | After this date the entry is treated as not present; omitting it triggers a warning in strict mode |

**Example:**
```yaml
allow:
  cves:
    - id: CVE-2023-44487
      reason: "HTTP/2 rapid-reset; our deployment does not serve HTTP/2"
      expires: 2026-01-01
    - id: CVE-2021-44228
      reason: "Log4j; Java runtime not present in this environment"
      expires: 2026-06-30
```

Entries without an `expires` date are flagged in the policy report as an audit
finding — indefinite suppressions are a compliance risk.

---

### `block`

Gates that cause `selvo test` and `selvo policy check` to exit `1` (hard failure).
Use these in CI to prevent a pull request from merging if a critical risk is
introduced.

| Field | Type | Default | Triggers on |
|---|---|---|---|
| `on_kev` | boolean | `true` | Any package in the CISA Known Exploited Vulnerabilities catalog |
| `on_weaponized` | boolean | `true` | Any package with a confirmed weaponized exploit (CISA KEV or NVD exploit-code-maturity: HIGH) |
| `min_cvss` | float | `9.0` | Any CVE whose CVSS v3 base score ≥ this value |
| `min_score` | float | `0.0` | Any package whose selvo composite risk score ≥ this value; `0.0` disables |
| `min_epss` | float | `0.0` | Any CVE whose EPSS probability ≥ this value; `0.0` disables |

**Setting `min_score` for environment-specific gates:**

```yaml
block:
  on_kev: true
  on_weaponized: true
  min_cvss: 9.0
  min_score: 75.0   # block if any package scores in the top quartile
  min_epss: 0.9     # block if near-certain exploitation probability
```

**Disabling a gate entirely:**

Set the numeric field to `0.0` (zero). Do not delete the key — an absent key
assumes the default, not "disabled".

```yaml
block:
  on_kev: true
  on_weaponized: false   # permit weaponized exploits (not recommended)
  min_cvss: 0.0          # no CVSS gate
  min_score: 0.0         # no composite score gate
  min_epss: 0.0          # no EPSS gate
```

---

### `warn`

Gates that cause exit `2` (informational failure — does not block CI merge by
default). Use `warn` for signals worth attention that do not meet the bar for a
hard block.

| Field | Type | Default | Triggers on |
|---|---|---|---|
| `on_poc` | boolean | `true` | Any package with a public proof-of-concept exploit |
| `min_cvss` | float | `7.0` | Any CVE whose CVSS base score ≥ this value (and below `block.min_cvss`) |
| `min_epss` | float | `0.0` | Any CVE whose EPSS probability ≥ this value; `0.0` disables |

---

### `notifications`

Push alert destinations for `selvo watch`. Both fields are optional; omit a
field to disable that channel.

| Field | Type | Notes |
|---|---|---|
| `slack` | string | Incoming webhook URL (Slack Block Kit format). Can also be set via `SELVO_SLACK_WEBHOOK` env var — the env var takes precedence |
| `pagerduty_routing_key` | string | PagerDuty Events v2 integration routing key |

`selvo watch` sends alerts with 3-attempt exponential backoff (initial 2 s,
then 4 s) to each configured channel when a block or warn gate is triggered.

---

## Minimal CI configuration

The smallest useful policy for a CI gate:

```yaml
version: 1

block:
  on_kev: true
  on_weaponized: true
  min_cvss: 9.0

warn:
  on_poc: true
  min_cvss: 7.0
```

---

## FedRAMP / Strict configuration

For environments subject to FedRAMP High or DoD IL4, a more aggressive policy:

```yaml
version: 1

sla:
  critical: 3    # FedRAMP High: 3 days for critical
  high: 14
  medium: 30
  low: 90

block:
  on_kev: true
  on_weaponized: true
  min_cvss: 7.0    # block on high, not just critical
  min_epss: 0.5    # block if >50% exploitation probability

warn:
  on_poc: true
  min_cvss: 4.0
  min_epss: 0.1
```

---

## Auto-discovery rules

`selvo policy check` and `selvo test` search for the policy file in this order:

1. Path supplied via `--policy <path>` CLI flag
2. `selvo.policy.yml` in the current working directory
3. `selvo.policy.yml` in the repository root (resolved via `.git` parent walk)

If no file is found, only the default block gates (`on_kev: true`,
`on_weaponized: true`, `min_cvss: 9.0`) are applied.
