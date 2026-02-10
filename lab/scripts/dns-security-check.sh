#!/bin/bash
# DNS Security Check Script
# Performs DNS enumeration and zone transfer attempts
# Generates JSON findings for integration with reporting tools

KALI_CONTAINER="pentest-kali"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="/root/pentest-results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="${OUTPUT_DIR}/dns_security_check_${TIMESTAMP}.log"
DNS_FINDINGS_JSON="${OUTPUT_DIR}/dns_findings_${TARGET_DOMAIN_OR_IP//\./_}_${TIMESTAMP}.json"

TARGET_DOMAIN_OR_IP=$1

echo "=========================================="
echo "DNS Security Check"
echo "Timestamp: $TIMESTAMP"
echo "Target: $TARGET_DOMAIN_OR_IP"
echo "=========================================="
echo ""

if [ -z "$TARGET_DOMAIN_OR_IP" ]; then
    echo "Usage: $0 <target_domain_or_ip>"
    echo "  Example: $0 example.com"
    echo "  Example: $0 8.8.8.8"
    exit 1
fi

# Ensure output directory exists in Kali container
docker exec "$KALI_CONTAINER" mkdir -p "$OUTPUT_DIR"
docker exec "$KALI_CONTAINER" bash -c "echo '[]' > ${DNS_FINDINGS_JSON}" # Initialize JSON array
docker exec "$KALI_CONTAINER" bash -c "echo 'DNS Security Check Report - ${TIMESTAMP}' > ${LOG_FILE}"

echo "Results will be logged in Kali container at: $LOG_FILE"
echo "JSON findings will be written to Kali container at: $DNS_FINDINGS_JSON"
echo "" | docker exec "$KALI_CONTAINER" tee -a "${LOG_FILE}"

# Install required tools if not present
docker exec "$KALI_CONTAINER" bash -c "
    if ! command -v dnsrecon &> /dev/null; then
        echo 'dnsrecon not found. Installing dnsrecon...' | tee -a \"${LOG_FILE}\"
        apt-get update -qq && apt-get install -y -qq dnsrecon 2>&1 | tee -a \"${LOG_FILE}\" || true
    fi
    if ! command -v fierce &> /dev/null; then
        echo 'fierce not found. Installing fierce...' | tee -a \"${LOG_FILE}\"
        apt-get update -qq && apt-get install -y -qq fierce 2>&1 | tee -a \"${LOG_FILE}\" || true
    fi
    if ! command -v dig &> /dev/null; then
        echo 'dig not found. Installing dnsutils...' | tee -a \"${LOG_FILE}\"
        apt-get update -qq && apt-get install -y -qq dnsutils 2>&1 | tee -a \"${LOG_FILE}\" || true
    fi
    if ! command -v python3 &> /dev/null; then
        echo 'python3 not found. Installing python3...' | tee -a \"${LOG_FILE}\"
        apt-get update -qq && apt-get install -y -qq python3 2>&1 | tee -a \"${LOG_FILE}\" || true
    fi
"

# Function to add findings to JSON file
add_finding_to_json() {
    local json_content=$1
    docker exec "$KALI_CONTAINER" python3 -c "
import json
import sys
import os

LOG_FILE = '${LOG_FILE}'

def log_debug(message):
    with open(LOG_FILE, 'a') as f:
        f.write(f'[PYTHON_DEBUG] {message}\\n')

try:
    with open('${DNS_FINDINGS_JSON}', 'r+') as f:
        data = json.load(f)
        new_finding = json.loads(sys.argv[1])
        data.append(new_finding)
        f.seek(0)
        json.dump(data, f, indent=2)
        f.truncate()
    log_debug(f'Successfully added finding: {new_finding.get(\"finding_type\", \"\")}')
except json.JSONDecodeError as e:
    log_debug(f'JSONDecodeError in add_finding_to_json: {e}. Content: {sys.argv[1]}')
except Exception as e:
    log_debug(f'Error in add_finding_to_json: {e}')
" "$json_content"
}

echo "--- Performing DNS Enumeration (dnsrecon) ---" | docker exec "$KALI_CONTAINER" tee -a "${LOG_FILE}"
DNSRECON_JSON_OUTPUT_FILE="${OUTPUT_DIR}/dnsrecon_${TARGET_DOMAIN_OR_IP//\./_}_${TIMESTAMP}.json"
# Run dnsrecon and capture JSON output
echo "DEBUG: Running dnsrecon -d \"$TARGET_DOMAIN_OR_IP\" -t std,brt,srv,axfr -a -j \"$DNSRECON_JSON_OUTPUT_FILE\"" | docker exec "$KALI_CONTAINER" tee -a "${LOG_FILE}"
docker exec "$KALI_CONTAINER" dnsrecon -d "$TARGET_DOMAIN_OR_IP" -t std,brt,srv,axfr -a -j "$DNSRECON_JSON_OUTPUT_FILE" 2>&1 | docker exec "$KALI_CONTAINER" tee -a "${LOG_FILE}"
echo "" | docker exec "$KALI_CONTAINER" tee -a "${LOG_FILE}"

# Parse dnsrecon JSON output and create findings
docker exec "$KALI_CONTAINER" python3 -c "
import json
import uuid
from datetime import datetime
import os
import sys

LOG_FILE = '${LOG_FILE}'

def log_debug(message):
    with open(LOG_FILE, 'a') as f:
        f.write(f'[PYTHON_DEBUG] {message}\\n')

dnsrecon_findings_file = '$DNSRECON_JSON_OUTPUT_FILE'
log_debug(f'Checking dnsrecon output file: {dnsrecon_findings_file}')
if os.path.exists(dnsrecon_findings_file):
    log_debug(f'dnsrecon output file exists, attempting to read.')
    try:
        with open(dnsrecon_findings_file, 'r') as f:
            dnsrecon_data = json.load(f)
        log_debug(f'dnsrecon_data loaded: {len(dnsrecon_data.items())} record types found.')
        
        for record_type, records in dnsrecon_data.items():
            if record_type in ['host', 'srv', 'txt', 'mx', 'ns']:
                log_debug(f'Processing {record_type} records: {len(records)} found.')
                for record in records:
                    description = f\"Discovered {record_type.upper()} record: {record.get('name', 'N/A')} -> {record.get('address', record.get('target', 'N/A'))}\"
                    finding = {
                        \"id\": f\"finding-{uuid.uuid4().hex[:8]}\",
                        \"timestamp\": datetime.utcnow().isoformat() + \"Z\",
                        \"finding_type\": f\"dns_{record_type}_record\",
                        \"severity\": \"low\",
                        \"target\": \"$TARGET_DOMAIN_OR_IP\",
                        \"target_ip\": record.get('address', 'N/A') if record_type == 'host' else 'N/A',
                        \"description\": description,
                        \"evidence\": json.dumps(record)
                    }
                    log_debug(f'Adding dnsrecon finding: {finding[\"finding_type\"]} for {finding[\"target\"]}')
                    os.system(f\"/bin/bash -c 'add_finding_to_json \\\''\" + json.dumps(finding) + \"\\''\")
    except json.JSONDecodeError as e:
        log_debug(f'JSONDecodeError reading dnsrecon output: {e}. File: {dnsrecon_findings_file}')
    except Exception as e:
        log_debug(f'Error processing dnsrecon output: {e}')
else:
    log_debug(f'dnsrecon output file {dnsrecon_findings_file} does not exist.')
"
echo "--- Performing DNS Enumeration (fierce) ---" | docker exec "$KALI_CONTAINER" tee -a "${LOG_FILE}"
FIERCE_TEMP_OUTPUT="${OUTPUT_DIR}/fierce_${TARGET_DOMAIN_OR_IP//\./_}_${TIMESTAMP}.txt"
# Run fierce and capture output
echo "DEBUG: Running fierce -dns \"$TARGET_DOMAIN_OR_IP\" -full" | docker exec "$KALI_CONTAINER" tee -a "${LOG_FILE}"
docker exec "$KALI_CONTAINER" fierce -dns "$TARGET_DOMAIN_OR_IP" -full 2>&1 | docker exec "$KALI_CONTAINER" tee "$FIERCE_TEMP_OUTPUT" | docker exec "$KALI_CONTAINER" tee -a "${LOG_FILE}"
echo "" | docker exec "$KALI_CONTAINER" tee -a "${LOG_FILE}"

# Parse fierce output and create findings
docker exec "$KALI_CONTAINER" python3 -c "
import json
import uuid
from datetime import datetime
import os
import re
import sys

LOG_FILE = '${LOG_FILE}'

def log_debug(message):
    with open(LOG_FILE, 'a') as f:
        f.write(f'[PYTHON_DEBUG] {message}\\n')

fierce_output_file = '$FIERCE_TEMP_OUTPUT'
log_debug(f'Checking fierce output file: {fierce_output_file}')
if os.path.exists(fierce_output_file):
    log_debug(f'fierce output file exists, attempting to read.')
    with open(fierce_output_file, 'r') as f:
        fierce_output = f.read()
    log_debug(f'fierce_output length: {len(fierce_output)} bytes')

    # Regex to find subdomains/hosts
    subdomain_pattern = re.compile(r'(\S+)\.\s+IN\s+A\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    
    matches = list(subdomain_pattern.finditer(fierce_output))
    log_debug(f'Found {len(matches)} subdomain matches in fierce output.')
    for match in matches:
        subdomain = match.group(1).strip()
        ip_address = match.group(2)
        description = f\"Discovered subdomain: {subdomain} with IP: {ip_address}\"
        finding = {
            \"id\": f\"finding-{uuid.uuid4().hex[:8]}\",
            \"timestamp\": datetime.utcnow().isoformat() + \"Z\",
            \"finding_type\": \"dns_subdomain_discovery\",
            \"severity\": \"low\",
            \"target\": subdomain,
            \"target_ip\": ip_address,
            \"description\": description,
            \"evidence\": f\"Fierce output: {subdomain} IN A {ip_address}\"
        }
        log_debug(f'Adding fierce finding: {finding[\"finding_type\"]} for {finding[\"target\"]}')
        os.system(f\"/bin/bash -c 'add_finding_to_json \\\''\" + json.dumps(finding) + \"\\''\")
else:
    log_debug(f'fierce output file {fierce_output_file} does not exist.')
"
echo "--- Attempting Zone Transfer (dig axfr) ---" | docker exec "$KALI_CONTAINER" tee -a "${LOG_FILE}"
echo "DEBUG: Running dig ns \"$TARGET_DOMAIN_OR_IP\" +short" | docker exec "$KALI_CONTAINER" tee -a "${LOG_FILE}"
NS_SERVERS_OUTPUT=$(docker exec "$KALI_CONTAINER" dig ns "$TARGET_DOMAIN_OR_IP" +short 2>&1)
echo "DEBUG: NS_SERVERS_OUTPUT: $NS_SERVERS_OUTPUT" | docker exec "$KALI_CONTAINER" tee -a "${LOG_FILE}"

if [ -n "$NS_SERVERS_OUTPUT" ]; then
    for ns in $NS_SERVERS_OUTPUT; do
        echo "  Attempting zone transfer from $ns for $TARGET_DOMAIN_OR_IP..." | docker exec "$KALI_CONTAINER" tee -a "${LOG_FILE}"
        echo "DEBUG: Running dig axfr \"$TARGET_DOMAIN_OR_IP\" @\"$ns\" +short" | docker exec "$KALI_CONTAINER" tee -a "${LOG_FILE}"
        ZONE_TRANSFER_RESULT=$(docker exec "$KALI_CONTAINER" dig axfr "$TARGET_DOMAIN_OR_IP" @"$ns" +short 2>&1)
        
        if [ -n "$ZONE_TRANSFER_RESULT" ]; then
            echo "  [SUCCESS] Zone Transfer Found from $ns:" | docker exec "$KALI_CONTAINER" tee -a "${LOG_FILE}"
            echo "$ZONE_TRANSFER_RESULT" | docker exec "$KALI_CONTAINER" tee -a "${LOG_FILE}"

            # Create JSON finding for successful zone transfer
            ZONE_TRANSFER_EVIDENCE=$(echo "$ZONE_TRANSFER_RESULT" | head -n 10) # Limit evidence to first 10 lines
            
            json_finding_content="$(cat <<JSON_EOF
{
  "id": "finding-$(uuidgen | tr -d '-' | cut -c1-8)",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "finding_type": "dns_zone_transfer_vulnerability",
  "severity": "high",
  "target": "$TARGET_DOMAIN_OR_IP",
  "target_ip": "$ns",
  "description": "Successful DNS Zone Transfer from name server $ns. This exposes internal network structure and hostnames.",
  "evidence": "$(echo "$ZONE_TRANSFER_EVIDENCE" | sed 's/"/\\"/g' | tr -d '\n')"
}
JSON_EOF
)"
            echo "DEBUG: Adding dig axfr finding: dns_zone_transfer_vulnerability for $TARGET_DOMAIN_OR_IP" | docker exec "$KALI_CONTAINER" tee -a "${LOG_FILE}"
            add_finding_to_json "$json_finding_content"
        else
            echo "  [FAIL] No Zone Transfer from $ns." | docker exec "$KALI_CONTAINER" tee -a "${LOG_FILE}"
        fi
    done
else
    echo "  No Name Servers found for $TARGET_DOMAIN_OR_IP, skipping zone transfer attempts." | docker exec "$KALI_CONTAINER" tee -a "${LOG_FILE}"
fi
echo "" | docker exec "$KALI_CONTAINER" tee -a "${LOG_FILE}"

echo "--- DNS Security Check Complete! ---" | docker exec "$KALI_CONTAINER" tee -a "${LOG_FILE}"
echo "Review full report in Kali container at: $LOG_FILE"
echo "Review JSON findings in Kali container at: $DNS_FINDINGS_JSON"

# Copy JSON findings from Kali container to host findings directory
docker cp "$KALI_CONTAINER":"$DNS_FINDINGS_JSON" "$LAB_DIR/findings/"
echo "JSON findings copied to host: $LAB_DIR/findings/$(basename "$DNS_FINDINGS_JSON")"
