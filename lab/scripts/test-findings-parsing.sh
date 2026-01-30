#!/bin/bash
# Test script to verify findings parsing works
# Creates a test findings JSON and parses it

TARGET_IP=${1:-"94.130.75.252"}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
FINDINGS_DIR="$LAB_DIR/findings"
TEST_JSON="${FINDINGS_DIR}/test_findings_${TARGET_IP//\./_}_$(date +%Y%m%d_%H%M%S).json"

mkdir -p "$FINDINGS_DIR"

# Create a test findings JSON file
cat > "$TEST_JSON" <<EOF
{
  "target_ip": "$TARGET_IP",
  "analysis_timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "findings": [
    {
      "id": "test-001",
      "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
      "finding_type": "open_port",
      "severity": "medium",
      "target": "$TARGET_IP",
      "target_ip": "$TARGET_IP",
      "description": "Open port 80 (HTTP) detected",
      "port": 80,
      "service": "http"
    },
    {
      "id": "test-002",
      "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
      "finding_type": "open_port",
      "severity": "high",
      "target": "$TARGET_IP",
      "target_ip": "$TARGET_IP",
      "description": "Open port 22 (SSH) detected with version disclosure",
      "port": 22,
      "service": "ssh",
      "service_version": "OpenSSH 7.4"
    },
    {
      "id": "test-003",
      "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
      "finding_type": "vulnerability",
      "severity": "high",
      "target": "$TARGET_IP",
      "target_ip": "$TARGET_IP",
      "description": "CVE-2021-12345 detected on port 80",
      "port": 80,
      "evidence": "Nmap vulnerability scan",
      "vulnerability_id": "CVE-2021-12345"
    }
  ],
  "summary": {
    "total_findings": 3,
    "open_ports": 2,
    "vulnerabilities": 1
  }
}
EOF

echo "Created test findings file: $TEST_JSON"
echo ""
echo "Testing report generation..."
bash "$SCRIPT_DIR/generate-external-report.sh" "$TARGET_IP"

echo ""
echo "Test findings file created. You can delete it with:"
echo "  rm $TEST_JSON"
