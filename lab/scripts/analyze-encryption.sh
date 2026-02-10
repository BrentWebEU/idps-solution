#!/bin/bash
# Script to analyze .pcap files for unencrypted traffic
# Run from the host machine to execute commands within the pentest-kali container

KALI_CONTAINER="pentest-kali"
OUTPUT_DIR="/root/pentest-results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="${OUTPUT_DIR}/encryption_analysis_${TIMESTAMP}.log"
ENCRYPTION_FINDINGS_JSON="${OUTPUT_DIR}/encryption_findings_${TIMESTAMP}.json"

PCAP_FILE=$1

echo "=========================================="
echo "Encryption Analysis from PCAP File"
echo "Timestamp: $TIMESTAMP"
echo "PCAP File to Analyze: $PCAP_FILE"
echo "=========================================="
echo ""

if [ -z "$PCAP_FILE" ]; then
    echo "Usage: $0 <path_to_pcap_file>"
    echo "  Example: $0 captures/capture_20231027_100000.pcap"
    exit 1
fi

# Ensure output directory exists in Kali container
docker exec "$KALI_CONTAINER" mkdir -p "$OUTPUT_DIR"
docker exec "$KALI_CONTAINER" bash -c "echo '[]' > ${ENCRYPTION_FINDINGS_JSON}" # Initialize JSON array
docker exec "$KALI_CONTAINER" bash -c "echo 'Encryption Analysis Report - ${TIMESTAMP}' > ${LOG_FILE}"

echo "Results will be logged in Kali container at: $LOG_FILE"
echo "JSON findings will be written to Kali container at: $ENCRYPTION_FINDINGS_JSON"
echo "" | docker exec "$KALI_CONTAINER" tee -a "${LOG_FILE}"

# Install tshark if not present
docker exec "$KALI_CONTAINER" bash -c "
    if ! command -v tshark &> /dev/null; then
        echo 'tshark not found. Installing tshark...' | tee -a \"${LOG_FILE}\"
        apt-get update -qq && apt-get install -y -qq tshark 2>&1 | tee -a \"${LOG_FILE}\" || true
    fi
"

# Check if the PCAP file exists in the Kali container
if ! docker exec "$KALI_CONTAINER" test -f "$PCAP_FILE"; then
    echo "Error: PCAP file '$PCAP_FILE' not found in the Kali container." | docker exec "$KALI_CONTAINER" tee -a "${LOG_FILE}"
    echo "Please ensure the PCAP file is mounted or copied into the container." | docker exec "$KALI_CONTAINER" tee -a "${LOG_FILE}"
    exit 1
fi

echo "--- Analyzing for Unencrypted Traffic ---" | docker exec "$KALI_CONTAINER" tee -a "${LOG_FILE}"

# Function to run tshark filter and report
analyze_protocol() {
    local protocol_name=$1
    local tshark_filter=$2
    local threshold=$3 # Number of packets to display as an example
    local current_timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    echo "  Searching for $protocol_name traffic..." | docker exec "$KALI_CONTAINER" tee -a "${LOG_FILE}"
    
    # Use tshark to count packets matching the filter
    PACKET_COUNT=$(docker exec "$KALI_CONTAINER" tshark -r "$PCAP_FILE" -Y "$tshark_filter" -q 2>/dev/null | grep "packets" | awk '{print $1}')
    
    if [ -n "$PACKET_COUNT" ] && [ "$PACKET_COUNT" -gt 0 ]; then
        echo "    [FOUND] $PACKET_COUNT packets of $protocol_name traffic detected." | docker exec "$KALI_CONTAINER" tee -a "${LOG_FILE}"
        echo "    First $threshold packets of $protocol_name traffic (summary):" | docker exec "$KALI_CONTAINER" tee -a "${LOG_FILE}"
        
        # Capture summary of packets for evidence
        PACKET_SUMMARY=$(docker exec "$KALI_CONTAINER" tshark -r "$PCAP_FILE" -Y "$tshark_filter" -T fields -e frame.number -e ip.src -e ip.dst -e _ws.col.Protocol -e _ws.col.Info -c "$threshold" 2>/dev/null)
        echo "$PACKET_SUMMARY" | docker exec "$KALI_CONTAINER" tee -a "${LOG_FILE}"
        echo "" | docker exec "$KALI_CONTAINER" tee -a "${LOG_FILE}"

        # Construct JSON finding
        local json_finding=$(cat <<JSON_EOF
{
  "id": "$(uuidgen | tr -d '-')",
  "timestamp": "$current_timestamp",
  "finding_type": "unencrypted_traffic",
  "severity": "high",
  "target": "$PCAP_FILE",
  "description": "Unencrypted $protocol_name traffic detected in PCAP file. $PACKET_COUNT packets identified.",
  "protocol_detected": "$protocol_name",
  "packet_count": $PACKET_COUNT,
  "evidence": "$(echo "$PACKET_SUMMARY" | head -n "$threshold" | sed 's/"/\\"/g' | tr -d '\n')"
}
JSON_EOF
)
        docker exec "$KALI_CONTAINER" python3 -c "
import json
with open('${ENCRYPTION_FINDINGS_JSON}', 'r+') as f:
    data = json.load(f)
    data.append($json_finding)
    f.seek(0)
    json.dump(data, f, indent=2)
    f.truncate()
"
    else:
        echo "    [NOT FOUND] No significant $protocol_name traffic detected." | docker exec "$KALI_CONTAINER" tee -a "${LOG_FILE}"
    fi
}

# Define protocols and their tshark filters
# Note: Filters for identifying sensitive data might need to be more specific or involve regex
# For now, focus on cleartext protocols
analyze_protocol "HTTP (cleartext)" "http and not ssl" 5
analyze_protocol "FTP (cleartext)" "ftp || ftp-data" 5
analyze_protocol "Telnet (cleartext)" "telnet" 5
analyze_protocol "SMB (cleartext)" "smb and not smb2.signature.security_blob" 5 # Basic check, can be more refined
analyze_protocol "MySQL (cleartext)" "mysql.auth_response and not tls.handshake" 5 # MySQL login without TLS
analyze_protocol "SMTP (cleartext)" "smtp and not ssl" 5
analyze_protocol "POP3 (cleartext)" "pop and not ssl" 5
analyze_protocol "IMAP (cleartext)" "imap and not ssl" 5
analyze_protocol "Kerberos (cleartext)" "kerberos and not (kerberos.etype == 23 || kerberos.etype == 18 || kerberos.etype == 17)" 5 # Unencrypted Kerberos traffic

echo "" | docker exec "$KALI_CONTAINER" tee -a "${LOG_FILE}"
echo "Encryption Analysis Complete!" | docker exec "$KALI_CONTAINER" tee -a "${LOG_FILE}"
echo "Review full report in Kali container at: $LOG_FILE"
echo "Review JSON findings in Kali container at: $ENCRYPTION_FINDINGS_JSON"

# Copy JSON findings from Kali container to host findings directory
docker cp "$KALI_CONTAINER":"$ENCRYPTION_FINDINGS_JSON" "$LAB_DIR/findings/"
echo "JSON findings copied to host: $LAB_DIR/findings/$(basename "$ENCRYPTION_FINDINGS_JSON")"