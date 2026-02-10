#!/bin/bash
# Script to test network segmentation within the lab environment
# Run from the host machine to execute commands within the pentest-kali container

KALI_CONTAINER="pentest-kali"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="/root/pentest-results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="${OUTPUT_DIR}/segmentation_test_${TIMESTAMP}.log"
SEGMENTATION_FINDINGS_JSON="${OUTPUT_DIR}/segmentation_findings_${TIMESTAMP}.json"

echo "Starting network segmentation test..."
echo "Timestamp: $TIMESTAMP"

# Create output directory in Kali container
docker exec "$KALI_CONTAINER" mkdir -p "$OUTPUT_DIR"
docker exec "$KALI_CONTAINER" bash -c "echo '[]' > ${SEGMENTATION_FINDINGS_JSON}" # Initialize JSON array

echo "Results will be logged in Kali container at: $LOG_FILE"
echo "JSON findings will be written to Kali container at: $SEGMENTATION_FINDINGS_JSON"
docker exec "$KALI_CONTAINER" bash -c "echo 'Network Segmentation Test Report - ${TIMESTAMP}' > ${LOG_FILE}"

# Define targets and expected reachability
# Format: "IP_ADDRESS PORT EXPECTED_STATUS SERVICE_DESCRIPTION"
# EXPECTED_STATUS: 0 for reachable, 1 for unreachable
declare -a TESTS=(
    # DMZ Network Services (172.21.0.0/24) - Expected to be reachable from attacker-net
    "172.21.0.2 80 0 Web Server (DMZ) HTTP" # pentest-web HTTP
    # Assuming RADIUS is fixed, it would go here: "172.21.0.X 1812 0 Radius Server (DMZ) UDP"

    # Internal Network Services (172.22.0.0/24) - Expected to be UNREACHABLE from attacker-net
    "172.22.0.2 3306 1 DB Server (Internal) MySQL"      # pentest-db MySQL
    "172.22.0.3 21 1 File Server (Internal) FTP"        # pentest-fileserver FTP
    "172.22.0.3 445 1 File Server (Internal) SMB"       # pentest-fileserver SMB
    "172.22.0.4 22 1 Vulnerable Linux (Internal) SSH"   # pentest-vuln-linux SSH
    "172.22.0.5 80 1 Web Server (Internal) HTTP"        # pentest-web HTTP on internal-net interface
)

# Function to test port reachability using nmap
test_port_reachability() {
    local target_ip=$1
    local target_port=$2
    local expected_status=$3 # 0 for reachable, 1 for unreachable
    local service_description=$4
    local current_timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    echo "Testing $service_description ($target_ip:$target_port)... Expected: $([ "$expected_status" -eq 0 ] && echo 'Reachable' || echo 'Unreachable')" | docker exec "$KALI_CONTAINER" tee -a "${LOG_FILE}"

    # Use nmap to check if the port is open/filtered/closed
    # -Pn: Treat all hosts as online -- skip host discovery
    # -p: specify port
    # --max-retries 1: Speed up by reducing retries
    # --host-timeout 5s: Time out quickly if host is unresponsive
    # -oG: Grepable output to easily parse
    # --open: Only show open ports. If nothing is open, it implies unreachable
    NMAP_RAW_OUTPUT=$(docker exec "$KALI_CONTAINER" nmap -Pn -p "$target_port" --max-retries 1 --host-timeout 5s --open "$target_ip" -oG -)
    NMAP_RESULT_LINE=$(echo "$NMAP_RAW_OUTPUT" | grep "Ports:")
    
    ACTUAL_STATUS=1 # Assume unreachable by default
    if [[ "$NMAP_RESULT_LINE" == *"$target_port/open"* ]]; then
        ACTUAL_STATUS=0 # Considered reachable if open
    fi

    local status_text=""
    local severity=""
    local finding_description=""

    if [ "$ACTUAL_STATUS" -eq "$expected_status" ]; then
        status_text="[PASS]"
        if [ "$ACTUAL_STATUS" -eq 0 ]; then
            # Reachable as expected
            finding_description="Port $target_port on $target_ip ($service_description) is reachable as expected."
            severity="low"
        else
            # Unreachable as expected
            finding_description="Port $target_port on $target_ip ($service_description) is unreachable as expected, indicating proper segmentation."
            severity="low"
        fi
        echo "  ${status_text} $service_description ($target_ip:$target_port) is $([ "$ACTUAL_STATUS" -eq 0 ] && echo 'reachable' || echo 'unreachable') as expected." | docker exec "$KALI_CONTAINER" tee -a "${LOG_FILE}"
    else
        status_text="[FAIL]"
        if [ "$ACTUAL_STATUS" -eq 0 ]; then
            # Reachable but expected unreachable (SEGMENTATION BREACH)
            finding_description="Port $target_port on $target_ip ($service_description) is reachable, but was expected to be unreachable (SEGMENTATION BREACH)."
            severity="critical"
        else
            # Unreachable but expected reachable (SERVICE UNAVAILABLE)
            finding_description="Port $target_port on $target_ip ($service_description) is unreachable, but was expected to be reachable (SERVICE UNAVAILABLE / UNEXPECTED BLOCK)."
            severity="medium"
        fi
        echo "  ${status_text} $service_description ($target_ip:$target_port) is $([ "$ACTUAL_STATUS" -eq 0 ] && echo 'reachable' || echo 'unreachable'), but was expected to be $([ "$expected_status" -eq 0 ] && echo 'reachable' || echo 'unreachable')." | docker exec "$KALI_CONTAINER" tee -a "${LOG_FILE}"
        echo "  NMAP Output: $NMAP_RESULT_LINE" | docker exec "$KALI_CONTAINER" tee -a "${LOG_FILE}"
    fi

    # Append finding to JSON array
    local json_finding=$(cat <<JSON_EOF
{
  "id": "$(uuidgen | tr -d '-')",
  "timestamp": "$current_timestamp",
  "finding_type": "network_segmentation",
  "severity": "$severity",
  "target": "$target_ip",
  "target_ip": "$target_ip",
  "port": "$target_port",
  "protocol": "$(echo "$service_description" | sed -E 's/.*\((\S+)\)$/\1/' | tr -d '\n')",
  "service": "$(echo "$service_description" | sed -E 's/\s*\(.*//' | tr -d '\n')",
  "description": "$finding_description",
  "evidence": "$(echo "$NMAP_RAW_OUTPUT" | sed 's/"/\\"/g' | tr -d '\n')"
}
JSON_EOF
)
    # Use python to append to JSON array to handle commas correctly
    docker exec "$KALI_CONTAINER" python3 -c "
import json
with open('${SEGMENTATION_FINDINGS_JSON}', 'r+') as f:
    data = json.load(f)
    data.append($json_finding)
    f.seek(0)
    json.dump(data, f, indent=2)
    f.truncate()
"
}

echo "" | docker exec "$KALI_CONTAINER" tee -a "${LOG_FILE}"
echo "--- Testing Direct Service Reachability from Attacker Network ---" | docker exec "$KALI_CONTAINER" tee -a "${LOG_FILE}"

# Perform tests
for test_case in "${TESTS[@]}"; do
    read -r ip port expected description <<< "$test_case"
    test_port_reachability "$ip" "$port" "$expected" "$description"
done

echo "" | docker exec "$KALI_CONTAINER" tee -a "${LOG_FILE}"
echo "Network Segmentation Test Complete!" | docker exec "$KALI_CONTAINER" tee -a "${LOG_FILE}"
echo "Review logs in Kali container at: $LOG_FILE"
echo "Review JSON findings in Kali container at: $SEGMENTATION_FINDINGS_JSON"

# Copy JSON findings from Kali container to host findings directory
docker cp "$KALI_CONTAINER":"$SEGMENTATION_FINDINGS_JSON" "$LAB_DIR/findings/"
echo "JSON findings copied to host: $LAB_DIR/findings/$(basename "$SEGMENTATION_FINDINGS_JSON")"
