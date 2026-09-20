#!/bin/bash
#
# validate.sh (Fixed & Smarter)
# Verifies items in found.txt for genuine valuable secrets/configurations
# and filters out empty stubs / false positives.

set -uo pipefail

FOUND_FILE="found.txt"
REPORT_FILE="bounty_report_ready.txt"

if [ ! -f "$FOUND_FILE" ]; then
    echo "[!] $FOUND_FILE not found. Run your scan script first."
    exit 1
fi

echo "=================================================="
echo " Bug Bounty Content Value Verifier (validate.sh)"
echo "=================================================="
echo " Reading targets from: $FOUND_FILE"
echo " Report output       : $REPORT_FILE"
echo "=================================================="
echo

> "$REPORT_FILE"
cat <<EOF >> "$REPORT_FILE"
==================================================
 BUG BOUNTY VULNERABILITY VALIDATION REPORT
==================================================

EOF

VALUABLE_COUNT=0
TOTAL_CHECKED=0

while IFS= read -r url; do
    [ -z "$url" ] && continue
    TOTAL_CHECKED=$((TOTAL_CHECKED + 1))
    echo "[-] Checking: $url"

    response_file=$(mktemp)
    headers_file=$(mktemp)

    # Fetch headers and body safely
    curl -s -D "$headers_file" -o "$response_file" -m 10 --max-redirs 0 "$url" 2>/dev/null
    
    content_type=$(grep -i "^Content-Type:" "$headers_file" 2>/dev/null | tr -d '\r')
    body_content=$(cat "$response_file")

    is_valuable=0
    reason=""

    # Rule 1: Reject HTML responses (Soft 404s) unless specific exception paths
    if echo "$content_type" | grep -qi "text/html"; then
        if [[ "$url" != *"api-docs"* ]] && [[ "$url" != *"security.txt"* ]] && [[ "$url" != *"server-status"* ]]; then
            echo "    [-] Rejected: Returned text/html (likely error page)"
            rm -f "$response_file" "$headers_file"
            continue
        fi
    fi

    # Rule 2: File-specific & Content-Substance Analysis
    if [[ "$url" == *".env"* ]]; then
        if echo "$body_content" | grep -qE "(DB_|API_|SECRET_|PASSWORD|APP_)"; then
            is_valuable=1
            reason="Valid .env Exposure with environment variables"
        else
            reason="Rejected: .env file lacks environment variables"
        fi
    elif [[ "$url" == *"config.json"* ]] || [[ "$url" == *"settings.json"* ]] || [[ "$url" == *"appsettings.json"* ]] || [[ "$url" == *"app.config.json"* ]]; then
        # Clean whitespace/newlines to check if it's just an empty stub
        body_trimmed=$(echo "$body_content" | tr -d ' \t\n\r')
        
        if [[ "$body_trimmed" != '{"data":""}' ]] && [[ "$body_trimmed" != '{}' ]] && [[ "$body_trimmed" != '[]' ]] && [ ${#body_trimmed} -gt 25 ]; then
            is_valuable=1
            reason="Valid Configuration JSON Exposure with substantive content"
        else
            reason="Rejected: JSON is an empty stub or too small (e.g., {\"data\":\"\"})"
        fi
    elif [[ "$url" == *".git/config"* ]]; then
        if echo "$body_content" | grep -q "\[core\]"; then
            is_valuable=1
            reason="Valid .git/config Repository Exposure"
        else
            reason="Rejected: .git/config missing [core] section"
        fi
    else
        # General secret regex patterns with escaped braces for compatibility
        if echo "$body_content" | grep -qE "(sk_live_[a-zA-Z0-9]\{24,\}|AIza[a-zA-Z0-9_-]\{35\}|postgres://|mysql://|mongodb://|aws_access_key_id)"; then
            is_valuable=1
            reason="High-value secrets or database URIs detected"
        else
            reason="No high-value secrets identified"
        fi
    fi

    if [ "$is_valuable" -eq 1 ]; then
        echo "    [+] HIGH VALUE: $reason"
        VALUABLE_COUNT=$((VALUABLE_COUNT + 1))
        
        # Append to report
        {
            echo "Target URL : $url"
            echo "Finding    : $reason"
            echo "Evidence Snippet:"
            echo "--------------------------------------------------"
            head -n 12 "$response_file" | sed 's/^/  /'
            echo "--------------------------------------------------"
            echo ""
        } >> "$REPORT_FILE"
    else
        echo "    [$reason]"
    fi

    rm -f "$response_file" "$headers_file"
done < "$FOUND_FILE"

# Finalize report summary
{
    echo "Summary:"
    echo " Total checked    : $TOTAL_CHECKED"
    echo " Valuable findings: $VALUABLE_COUNT"
    echo "=================================================="
} >> "$REPORT_FILE"

echo
echo "=================================================="
echo " VALIDATION COMPLETE"
echo "=================================================="
echo " Checked          : $TOTAL_CHECKED"
echo " Valuable findings: $VALUABLE_COUNT"
echo " Report saved to  : $REPORT_FILE"
echo "=================================================="
