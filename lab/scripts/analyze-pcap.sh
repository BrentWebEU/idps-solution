#!/bin/bash
# PCAP analysis script using tshark
# Extracts protocol-specific data and attack patterns

PCAP_FILE=${1:-""}
OUTPUT_DIR=${2:-"./findings"}

if [ -z "$PCAP_FILE" ]; then
    echo "Usage: $0 <pcap-file> [output-directory]"
    echo "Example: $0 ./captures/capture_20240101_120000.pcap"
    exit 1
fi

if [ ! -f "$PCAP_FILE" ]; then
    echo "Error: PCAP file not found: $PCAP_FILE"
    exit 1
fi

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_FILE="${OUTPUT_DIR}/pcap_analysis_${TIMESTAMP}.json"

mkdir -p "$OUTPUT_DIR"

echo "Analyzing PCAP file: $PCAP_FILE"
echo "Output directory: $OUTPUT_DIR"

# Check if tshark is available
if ! command -v tshark &> /dev/null; then
    echo "tshark not found. Installing..."
    if command -v apt-get &> /dev/null; then
        sudo apt-get update && sudo apt-get install -y tshark
    elif command -v brew &> /dev/null; then
        brew install wireshark
    else
        echo "Please install tshark/wireshark manually"
        exit 1
    fi
fi

# Extract HTTP requests
echo "Extracting HTTP requests..."
HTTP_REQUESTS=$(tshark -r "$PCAP_FILE" -Y "http.request" -T fields -e http.request.method -e http.request.uri -e ip.src -e ip.dst 2>/dev/null | head -100)

# Extract SQL queries (if any)
echo "Extracting potential SQL queries..."
SQL_QUERIES=$(tshark -r "$PCAP_FILE" -Y "mysql.query" -T fields -e mysql.query -e ip.src -e ip.dst 2>/dev/null | head -50)

# Extract RADIUS packets
echo "Extracting RADIUS packets..."
RADIUS_PACKETS=$(tshark -r "$PCAP_FILE" -Y "radius" -T fields -e radius.code -e radius.username -e ip.src -e ip.dst 2>/dev/null | head -50)

# Extract SSH connection attempts
echo "Extracting SSH connection attempts..."
SSH_CONNECTIONS=$(tshark -r "$PCAP_FILE" -Y "ssh" -T fields -e ip.src -e ip.dst -e tcp.port 2>/dev/null | head -50)

# Extract FTP connections
echo "Extracting FTP connections..."
FTP_CONNECTIONS=$(tshark -r "$PCAP_FILE" -Y "ftp" -T fields -e ftp.request.command -e ftp.request.arg -e ip.src -e ip.dst 2>/dev/null | head -50)

# Extract SMB connections
echo "Extracting SMB connections..."
SMB_CONNECTIONS=$(tshark -r "$PCAP_FILE" -Y "smb2" -T fields -e smb2.cmd -e ip.src -e ip.dst 2>/dev/null | head -50)

# Extract port scan patterns
echo "Detecting port scan patterns..."
PORT_SCANS=$(tshark -r "$PCAP_FILE" -Y "tcp.flags.syn==1 and tcp.flags.ack==0" -T fields -e ip.src -e tcp.dstport 2>/dev/null | sort | uniq -c | sort -rn | head -20)

# Extract brute force patterns (multiple failed connections)
echo "Detecting brute force patterns..."
BRUTE_FORCE=$(tshark -r "$PCAP_FILE" -Y "tcp.flags.reset==1" -T fields -e ip.src -e ip.dst -e tcp.dstport 2>/dev/null | sort | uniq -c | sort -rn | head -20)

# Generate JSON report
cat > "$OUTPUT_FILE" <<EOF
{
  "pcap_file": "$PCAP_FILE",
  "analysis_timestamp": "$TIMESTAMP",
  "http_requests": [
$(echo "$HTTP_REQUESTS" | while IFS=$'\t' read -r method uri src dst; do
    echo "    {\"method\": \"$method\", \"uri\": \"$uri\", \"src\": \"$src\", \"dst\": \"$dst\"},"
done | sed '$ s/,$//')
  ],
  "sql_queries": [
$(echo "$SQL_QUERIES" | while IFS=$'\t' read -r query src dst; do
    echo "    {\"query\": \"$query\", \"src\": \"$src\", \"dst\": \"$dst\"},"
done | sed '$ s/,$//')
  ],
  "radius_packets": [
$(echo "$RADIUS_PACKETS" | while IFS=$'\t' read -r code username src dst; do
    echo "    {\"code\": \"$code\", \"username\": \"$username\", \"src\": \"$src\", \"dst\": \"$dst\"},"
done | sed '$ s/,$//')
  ],
  "ssh_connections": [
$(echo "$SSH_CONNECTIONS" | while IFS=$'\t' read -r src dst port; do
    echo "    {\"src\": \"$src\", \"dst\": \"$dst\", \"port\": \"$port\"},"
done | sed '$ s/,$//')
  ],
  "ftp_connections": [
$(echo "$FTP_CONNECTIONS" | while IFS=$'\t' read -r cmd arg src dst; do
    echo "    {\"command\": \"$cmd\", \"argument\": \"$arg\", \"src\": \"$src\", \"dst\": \"$dst\"},"
done | sed '$ s/,$//')
  ],
  "smb_connections": [
$(echo "$SMB_CONNECTIONS" | while IFS=$'\t' read -r cmd src dst; do
    echo "    {\"command\": \"$cmd\", \"src\": \"$src\", \"dst\": \"$dst\"},"
done | sed '$ s/,$//')
  ],
  "port_scan_patterns": [
$(echo "$PORT_SCANS" | while read -r count src port; do
    echo "    {\"count\": \"$count\", \"src\": \"$src\", \"port\": \"$port\"},"
done | sed '$ s/,$//')
  ],
  "brute_force_patterns": [
$(echo "$BRUTE_FORCE" | while read -r count src dst port; do
    echo "    {\"count\": \"$count\", \"src\": \"$src\", \"dst\": \"$dst\", \"port\": \"$port\"},"
done | sed '$ s/,$//')
  ]
}
EOF

echo ""
echo "PCAP analysis complete!"
echo "Results saved to: $OUTPUT_FILE"
