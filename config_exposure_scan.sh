#!/bin/bash
#
# config_exposure_scan.sh
#
# Checks a list of hosts for common publicly-exposed sensitive files
# (config.json, .env, .git/config, etc.) -- httpx/nuclei style CLI.
#
# Runs in the FOREGROUND: you see output live in your terminal (verbose
# or quiet), the script blocks until the scan finishes, then prints a
# summary report -- just like other bug bounty scanners. No tail -f
# needed, nothing hidden in a log file.
#
# USAGE:
#   ./config_exposure_scan.sh -l urls.txt [-c concurrency] [-v] [-q]
#
# FLAGS:
#   -l <file>       Input file, one base URL per line (required)
#   -c <n>          Concurrency (default: 6)
#   -v              Verbose: print every request's result live as it happens
#   -q              Quiet (default): only progress ticks + final summary
#   -h              Show this help
#
# OUTPUT FILES (still written for later reference):
#   found.txt        -> ONLY confirmed HTTP 200 hits with real content
#   all_results.log  -> full log of every path checked and its status
#
# Termux-safe: single curl call per check (low process count) so Android
# doesn't kill the session, and auto-holds a wake-lock (if available)
# for the duration of the scan so the screen can lock without it dying.

set -uo pipefail

SCRIPT_NAME="$(basename "$0")"

usage() {
    cat <<EOF
Usage: $SCRIPT_NAME -l urls.txt [-c concurrency] [-v] [-q]

  -l <file>   Input file, one base URL per line (required)
  -c <n>      Concurrency (default: 6)
  -v          Verbose: print every request's result live as it happens
  -q          Quiet (default): only progress ticks + final summary
  -h          Show this help
EOF
    exit 1
}

for cmd in curl; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "[!] Required command '$cmd' not found."
        echo "    On Termux, install with: pkg install curl"
        exit 1
    fi
done

# ---- Argument parsing ----
URLS_FILE=""
CONCURRENCY=6
VERBOSE=0

while getopts ":l:c:vqh" opt; do
    case "$opt" in
        l) URLS_FILE="$OPTARG" ;;
        c) CONCURRENCY="$OPTARG" ;;
        v) VERBOSE=1 ;;
        q) VERBOSE=0 ;;
        h) usage ;;
        \?) echo "[!] Unknown option: -$OPTARG"; usage ;;
        :) echo "[!] Option -$OPTARG requires an argument"; usage ;;
    esac
done

if [ -z "$URLS_FILE" ]; then
    echo "[!] -l <urls_file> is required."
    usage
fi

if [ ! -f "$URLS_FILE" ]; then
    echo "[!] File not found: $URLS_FILE"
    exit 1
fi

OUT_FOUND="found.txt"
OUT_LOG="all_results.log"
COMBINED="./.combined_urls_$$.txt"

# Hold a wake-lock for the duration of the scan (if on Termux), so the
# screen can lock without Android killing the process. Released
# automatically on exit, whether the scan finishes or is interrupted.
WAKE_LOCK_HELD=0
cleanup() {
    rm -f "$COMBINED"
    if [ "$WAKE_LOCK_HELD" -eq 1 ]; then
        termux-wake-lock -d 2>/dev/null
    fi
}
trap cleanup EXIT

if command -v termux-wake-lock >/dev/null 2>&1; then
    termux-wake-lock
    WAKE_LOCK_HELD=1
fi

PATHS=(
    "config.json"
    "config.js"
    "configuration.json"
    "settings.json"
    "app.config.json"
    "env.json"
    ".env"
    ".env.local"
    ".env.production"
    ".git/config"
    ".git/HEAD"
    "wp-config.php.bak"
    "package.json"
    "composer.json"
    "web.config"
    "appsettings.json"
    "firebase.json"
    "credentials.json"
    "secrets.json"
    "swagger.json"
    "api-docs"
    ".well-known/security.txt"
    "phpinfo.php"
    "server-status"
    "debug.log"
    "error.log"
)

> "$OUT_FOUND"
> "$OUT_LOG"
> "$COMBINED"

while IFS= read -r base_url; do
    [ -z "$base_url" ] && continue
    base_url="${base_url%/}"
    for path in "${PATHS[@]}"; do
        echo "${base_url}/${path}" >> "$COMBINED"
    done
done < "$URLS_FILE"

TOTAL=$(wc -l < "$COMBINED")
START_TIME=$(date +%s)

echo "=================================================="
echo " Config Exposure Scanner"
echo "=================================================="
echo " Targets file : $URLS_FILE"
echo " Paths/host   : ${#PATHS[@]}"
echo " Total checks : $TOTAL"
echo " Concurrency  : $CONCURRENCY"
echo " Mode         : $([ "$VERBOSE" -eq 1 ] && echo verbose || echo quiet)"
[ "$WAKE_LOCK_HELD" -eq 1 ] && echo " Wake-lock    : held for this scan"
echo "=================================================="
echo

# ---- Single-process check: one curl call reports status + size ----
check_url() {
    local full_url="$1"
    local result
    result=$(curl -s -o /dev/null -w "%{http_code} %{size_download}" -m 8 --max-redirs 0 "$full_url" 2>/dev/null)

    local status size
    status=$(echo "$result" | awk '{print $1}')
    size=$(echo "$result" | awk '{print $2}')
    status="${status:-000}"
    size="${size:-0}"

    echo "[$status] [$size bytes] $full_url" >> "$OUT_LOG"

    # STRICT: only exact HTTP 200 with a real body counts as a hit --
    # goes into found.txt AND is the only thing shown live on screen,
    # in both verbose and quiet mode. 301/302/403/404/etc. are logged
    # to all_results.log only, never printed live.
    if [ "$status" = "200" ] && [ "$size" -gt 10 ] 2>/dev/null; then
        echo "$full_url" >> "$OUT_FOUND"
        echo "[+] FOUND (200): $full_url ($size bytes)"
    fi
}

running=0
count=0
while IFS= read -r full_url; do
    [ -z "$full_url" ] && continue
    check_url "$full_url" &
    running=$((running + 1))
    count=$((count + 1))

    if [ "$running" -ge "$CONCURRENCY" ]; then
        wait -n 2>/dev/null || wait
        running=$((running - 1))
    fi

    # Both modes only ever print live 200 hits (see check_url above).
    # Verbose shows progress more often; quiet shows it less often.
    TICK_EVERY=200
    [ "$VERBOSE" -eq 1 ] && TICK_EVERY=20
    if [ $((count % TICK_EVERY)) -eq 0 ]; then
        echo "[*] ...$count / $TOTAL checked"
    fi
done < "$COMBINED"

wait

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

TOTAL_CHECKED=$(wc -l < "$OUT_LOG" | tr -d ' ')
TOTAL_200=$(wc -l < "$OUT_FOUND" | tr -d ' ')

echo
echo "=================================================="
echo " SCAN COMPLETE"
echo "=================================================="
echo " Duration        : ${ELAPSED}s"
echo " Total checked    : $TOTAL_CHECKED"
echo " Confirmed 200s   : $TOTAL_200"
echo
echo " Status code breakdown:"
grep -oE '^\[[0-9]{3}\]' "$OUT_LOG" | tr -d '[]' | sort | uniq -c | sort -rn | \
    awk '{printf "   %-5s : %s\n", $2, $1}'
echo "=================================================="

if [ "$TOTAL_200" -gt 0 ]; then
    echo
    echo " Confirmed 200 findings:"
    echo "--------------------------------------------------"
    cat "$OUT_FOUND" | sed 's/^/   /'
    echo "--------------------------------------------------"
else
    echo
    echo " No 200 findings this run."
fi

echo
echo " Full log : $OUT_LOG"
echo " 200 hits : $OUT_FOUND"
