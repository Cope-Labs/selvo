#!/usr/bin/env bash
# selvo agent installer — one command to continuous vulnerability monitoring.
#
# Usage:
#   curl -s https://selvo.dev/install.sh | SELVO_API_KEY=sk_xxx bash
#   curl -s https://selvo.dev/install.sh | SELVO_API_KEY=sk_xxx SELVO_ECOSYSTEM=ubuntu bash
#
# What it does:
#   1. Detects your package manager (dpkg/rpm/pacman/apk)
#   2. Collects installed packages
#   3. Sends them to selvo for CVE analysis
#   4. Sets up a daily cron job to repeat automatically
#
# Requirements: curl, a supported package manager, cron (optional)

set -euo pipefail

SELVO_API="${SELVO_API:-https://selvo.dev}"
SELVO_API_KEY="${SELVO_API_KEY:-}"
SELVO_ECOSYSTEM="${SELVO_ECOSYSTEM:-auto}"
SELVO_CRON="${SELVO_CRON:-1}"  # set to 0 to skip cron setup
SELVO_HOSTNAME="${SELVO_HOSTNAME:-$(hostname -f 2>/dev/null || hostname)}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${CYAN}[selvo]${NC} $*"; }
ok()   { echo -e "${GREEN}[selvo]${NC} $*"; }
warn() { echo -e "${YELLOW}[selvo]${NC} $*"; }
err()  { echo -e "${RED}[selvo]${NC} $*" >&2; }

# ── Preflight checks ────────────────────────────────────────────────────────

if [ -z "$SELVO_API_KEY" ]; then
    err "SELVO_API_KEY is required."
    err "Get one at ${SELVO_API}/dash/keys or run:"
    err "  curl -X POST ${SELVO_API}/api/v1/orgs -H 'Content-Type: application/json' -d '{\"org_id\":\"myorg\"}'"
    exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
    err "curl is required but not installed."
    exit 1
fi

# ── Detect package manager ───────────────────────────────────────────────────

detect_pm() {
    if command -v dpkg-query >/dev/null 2>&1; then echo "dpkg"
    elif command -v rpm >/dev/null 2>&1; then echo "rpm"
    elif command -v pacman >/dev/null 2>&1; then echo "pacman"
    elif command -v apk >/dev/null 2>&1; then echo "apk"
    else echo "unknown"; fi
}

PM=$(detect_pm)
if [ "$PM" = "unknown" ]; then
    err "No supported package manager found (dpkg/rpm/pacman/apk)."
    exit 1
fi

# Auto-detect ecosystem from package manager
if [ "$SELVO_ECOSYSTEM" = "auto" ]; then
    case "$PM" in
        dpkg)
            if grep -qi ubuntu /etc/os-release 2>/dev/null; then
                SELVO_ECOSYSTEM="ubuntu"
            else
                SELVO_ECOSYSTEM="debian"
            fi
            ;;
        rpm)
            if grep -qi "rocky" /etc/os-release 2>/dev/null; then
                SELVO_ECOSYSTEM="rocky"
            elif grep -qi "alma" /etc/os-release 2>/dev/null; then
                SELVO_ECOSYSTEM="almalinux"
            elif grep -qi "suse" /etc/os-release 2>/dev/null; then
                SELVO_ECOSYSTEM="suse"
            else
                SELVO_ECOSYSTEM="fedora"
            fi
            ;;
        pacman) SELVO_ECOSYSTEM="arch" ;;
        apk)    SELVO_ECOSYSTEM="alpine" ;;
    esac
fi

log "Detected: ${PM} (${SELVO_ECOSYSTEM}) on ${SELVO_HOSTNAME}"

# ── Collect packages ─────────────────────────────────────────────────────────

collect_packages() {
    case "$PM" in
        dpkg)   dpkg-query -W -f='${db:Status-Abbrev}  ${Package}  ${Version}\n' 2>/dev/null ;;
        rpm)    rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' 2>/dev/null ;;
        pacman) pacman -Q 2>/dev/null ;;
        apk)    apk info -v 2>/dev/null ;;
    esac
}

log "Collecting installed packages..."
PACKAGES=$(collect_packages)
PKG_COUNT=$(echo "$PACKAGES" | wc -l)
log "Found ${PKG_COUNT} packages"

# ── Send to selvo API ────────────────────────────────────────────────────────

log "Sending to ${SELVO_API}/api/v1/scan/packages..."

PAYLOAD=$(python3 -c "
import json, sys
data = sys.stdin.read()
print(json.dumps({'packages': data, 'ecosystem': '${SELVO_ECOSYSTEM}'}))
" <<< "$PACKAGES" 2>/dev/null || {
    # Fallback if python3 not available: use simple escaping
    ESCAPED=$(echo "$PACKAGES" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr '\n' '\\' | sed 's/\\/\\n/g')
    echo "{\"packages\":\"${ESCAPED}\",\"ecosystem\":\"${SELVO_ECOSYSTEM}\"}"
})

RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "${SELVO_API}/api/v1/scan/packages" \
    -H "X-API-Key: ${SELVO_API_KEY}" \
    -H "Content-Type: application/json" \
    -d "$PAYLOAD")

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | head -n -1)

if [ "$HTTP_CODE" -ge 200 ] && [ "$HTTP_CODE" -lt 300 ]; then
    JOB_ID=$(echo "$BODY" | python3 -c "import json,sys; print(json.load(sys.stdin).get('job_id',''))" 2>/dev/null || echo "")
    PARSED=$(echo "$BODY" | python3 -c "import json,sys; print(json.load(sys.stdin).get('packages_parsed',0))" 2>/dev/null || echo "?")
    ok "Scan queued: ${PARSED} packages (job ${JOB_ID})"
    ok "View results: ${SELVO_API}/dash/overview"

    # Poll for completion (up to 3 minutes)
    if [ -n "$JOB_ID" ]; then
        log "Waiting for analysis to complete..."
        for i in $(seq 1 18); do
            sleep 10
            STATUS=$(curl -s -H "X-API-Key: ${SELVO_API_KEY}" \
                "${SELVO_API}/api/v1/jobs/${JOB_ID}" | \
                python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('status',''))" 2>/dev/null || echo "")
            if [ "$STATUS" = "done" ]; then
                RESULT=$(curl -s -H "X-API-Key: ${SELVO_API_KEY}" "${SELVO_API}/api/v1/jobs/${JOB_ID}")
                TOTAL=$(echo "$RESULT" | python3 -c "import json,sys; print(json.load(sys.stdin)['result']['total_packages'])" 2>/dev/null || echo "?")
                WITH_CVE=$(echo "$RESULT" | python3 -c "import json,sys; print(json.load(sys.stdin)['result']['with_cves'])" 2>/dev/null || echo "?")
                KEV=$(echo "$RESULT" | python3 -c "import json,sys; print(json.load(sys.stdin)['result']['kev_count'])" 2>/dev/null || echo "?")
                echo ""
                ok "=== Scan Complete ==="
                ok "  Packages scanned: ${TOTAL}"
                ok "  With open CVEs:   ${WITH_CVE}"
                ok "  In CISA KEV:      ${KEV}"
                ok "  Dashboard:        ${SELVO_API}/dash/overview"
                break
            elif [ "$STATUS" = "error" ]; then
                err "Scan failed. Check ${SELVO_API}/api/v1/jobs/${JOB_ID}"
                break
            fi
            printf "."
        done
    fi
else
    err "API returned ${HTTP_CODE}: ${BODY}"
    exit 1
fi

# ── Set up daily cron ────────────────────────────────────────────────────────

if [ "$SELVO_CRON" = "1" ] && command -v crontab >/dev/null 2>&1; then
    SCRIPT_DIR="${HOME}/.local/bin"
    SCRIPT_PATH="${SCRIPT_DIR}/selvo-scan"
    mkdir -p "$SCRIPT_DIR"

    cat > "$SCRIPT_PATH" << 'SCAN_SCRIPT'
#!/usr/bin/env bash
# Auto-generated by selvo installer. Runs daily to check for new CVEs.
set -euo pipefail
SCAN_SCRIPT

    cat >> "$SCRIPT_PATH" << SCAN_VARS
SELVO_API="${SELVO_API}"
SELVO_API_KEY="${SELVO_API_KEY}"
SELVO_ECOSYSTEM="${SELVO_ECOSYSTEM}"
SCAN_VARS

    cat >> "$SCRIPT_PATH" << 'SCAN_BODY'

collect() {
    if command -v dpkg-query >/dev/null 2>&1; then
        dpkg-query -W -f='${db:Status-Abbrev}  ${Package}  ${Version}\n' 2>/dev/null
    elif command -v rpm >/dev/null 2>&1; then
        rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' 2>/dev/null
    elif command -v pacman >/dev/null 2>&1; then
        pacman -Q 2>/dev/null
    elif command -v apk >/dev/null 2>&1; then
        apk info -v 2>/dev/null
    fi
}

PKGS=$(collect)
PAYLOAD=$(python3 -c "import json,sys; print(json.dumps({'packages': sys.stdin.read(), 'ecosystem': '${SELVO_ECOSYSTEM}'}))" <<< "$PKGS")
curl -sf -X POST "${SELVO_API}/api/v1/scan/packages" \
    -H "X-API-Key: ${SELVO_API_KEY}" \
    -H "Content-Type: application/json" \
    -d "$PAYLOAD" >/dev/null
SCAN_BODY

    chmod +x "$SCRIPT_PATH"

    # Add cron entry (daily at 6 AM, avoid duplicates)
    CRON_LINE="0 6 * * * ${SCRIPT_PATH} 2>/dev/null"
    (crontab -l 2>/dev/null | grep -v "selvo-scan" ; echo "$CRON_LINE") | crontab -
    ok "Daily scan cron installed (6 AM). Script: ${SCRIPT_PATH}"
else
    if [ "$SELVO_CRON" = "0" ]; then
        log "Cron setup skipped (SELVO_CRON=0)"
    else
        warn "crontab not available — skipping daily scan setup"
        warn "Run this script manually or add to your scheduler."
    fi
fi

echo ""
ok "Done. Your system is now monitored by selvo."
ok "Dashboard: ${SELVO_API}/dash/overview"
