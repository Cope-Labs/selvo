#!/bin/bash
# selvo-scan GitHub Actions entrypoint
# Inputs via environment variables (INPUT_* from action.yml)
set -euo pipefail

ECOSYSTEM="${INPUT_ECOSYSTEM:-debian}"
LIMIT="${INPUT_LIMIT:-50}"
FAIL_ON_KEV="${INPUT_FAIL_ON_KEV:-true}"
FAIL_ON_WEAPONIZED="${INPUT_FAIL_ON_WEAPONIZED:-true}"
MIN_SCORE="${INPUT_MIN_SCORE:-0}"
FORMAT="${INPUT_FORMAT:-table}"
SBOM="${INPUT_SBOM:-}"
GRYPE_REPORT="${INPUT_GRYPE_REPORT:-}"
TRIVY_REPORT="${INPUT_TRIVY_REPORT:-}"
SARIF_OUTPUT="${INPUT_SARIF_OUTPUT:-}"

REPORT_PATH="${RUNNER_TEMP:-/tmp}/selvo-report.json"
SARIF_PATH="${RUNNER_TEMP:-/tmp}/selvo.sarif"

# ── Build selvo args ──────────────────────────────────────────────────────────
SCAN_ARGS=""
if [[ -n "$SBOM" ]]; then
    SCAN_ARGS="scan --sbom $SBOM"
elif [[ -n "$GRYPE_REPORT" ]]; then
    SCAN_ARGS="scan --grype $GRYPE_REPORT"
elif [[ -n "$TRIVY_REPORT" ]]; then
    SCAN_ARGS="scan --trivy $TRIVY_REPORT"
else
    SCAN_ARGS="analyze --ecosystem $ECOSYSTEM --limit $LIMIT"
fi

# ── Run analysis → JSON ───────────────────────────────────────────────────────
echo "::group::selvo scan"
selvo $SCAN_ARGS --output json --file "$REPORT_PATH" || true
echo "::endgroup::"

# ── Display table ─────────────────────────────────────────────────────────────
echo "::group::Risk summary"
selvo $SCAN_ARGS --output "$FORMAT" || true
echo "::endgroup::"

# ── Extract counts & set outputs ──────────────────────────────────────────────
KEV_COUNT=$(python3 -c "
import json, sys
try:
    data = json.load(open('$REPORT_PATH'))
    pkgs = data.get('packages', data) if isinstance(data, dict) else data
    print(sum(1 for p in pkgs if p.get('in_cisa_kev')))
except Exception:
    print(0)
")

WPZN_COUNT=$(python3 -c "
import json, sys
try:
    data = json.load(open('$REPORT_PATH'))
    pkgs = data.get('packages', data) if isinstance(data, dict) else data
    print(sum(1 for p in pkgs if p.get('exploit_maturity') == 'weaponized'))
except Exception:
    print(0)
")

echo "kev-count=${KEV_COUNT}" >> "${GITHUB_OUTPUT:-/dev/null}"
echo "weaponized-count=${WPZN_COUNT}" >> "${GITHUB_OUTPUT:-/dev/null}"
echo "report-path=${REPORT_PATH}" >> "${GITHUB_OUTPUT:-/dev/null}"

# ── SARIF output (for GitHub Code Scanning) ────────────────────────────────────
if [[ -n "$SARIF_OUTPUT" ]]; then
    selvo $SCAN_ARGS --output sarif --file "$SARIF_PATH" || true
    echo "sarif-path=${SARIF_PATH}" >> "${GITHUB_OUTPUT:-/dev/null}"
    echo "::notice::SARIF written to $SARIF_PATH — upload with github/codeql-action/upload-sarif"
fi

# ── Gate checks ───────────────────────────────────────────────────────────────
EXIT=0

if [[ "$FAIL_ON_KEV" == "true" && "${KEV_COUNT:-0}" -gt 0 ]]; then
    echo "::error::selvo: ${KEV_COUNT} package(s) in CISA KEV — failing build."
    EXIT=1
fi

if [[ "$FAIL_ON_WEAPONIZED" == "true" && "${WPZN_COUNT:-0}" -gt 0 ]]; then
    echo "::error::selvo: ${WPZN_COUNT} package(s) have weaponized exploits — failing build."
    EXIT=1
fi

if [[ "${MIN_SCORE}" -gt 0 ]]; then
    SCORE_BREACH=$(python3 -c "
import json
try:
    data = json.load(open('$REPORT_PATH'))
    pkgs = data.get('packages', data) if isinstance(data, dict) else data
    print(sum(1 for p in pkgs if p.get('score', 0) >= $MIN_SCORE))
except Exception:
    print(0)
")
    if [[ "${SCORE_BREACH:-0}" -gt 0 ]]; then
        echo "::error::selvo: ${SCORE_BREACH} package(s) exceed min-score=$MIN_SCORE — failing build."
        EXIT=1
    fi
fi

exit $EXIT
