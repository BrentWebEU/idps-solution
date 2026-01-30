#!/bin/bash
# Parse Nmap XML results and convert to findings JSON format
# Usage: ./parse-nmap-results.sh <nmap-xml-file> <target-ip> <output-json>

XML_FILE=$1
TARGET_IP=$2
OUTPUT_JSON=$3

if [ -z "$XML_FILE" ] || [ -z "$TARGET_IP" ] || [ -z "$OUTPUT_JSON" ]; then
    echo "Usage: $0 <nmap-xml-file> <target-ip> <output-json>"
    exit 1
fi

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Check if xmlstarlet or python is available
if command -v xmlstarlet &> /dev/null; then
    # Use xmlstarlet to parse XML
    OPEN_PORTS=$(xmlstarlet sel -t -m "//port[@state='open']" -v "@portid" -o "," -v "service/@name" -n "$XML_FILE" 2>/dev/null | head -20)
    VULNS=$(xmlstarlet sel -t -m "//script[@id='vuln']" -v "../@portid" -o ":" -v "table/elem[@key='id']" -n "$XML_FILE" 2>/dev/null | head -10)
elif command -v python3 &> /dev/null; then
    # Use Python to parse XML
    OPEN_PORTS=$(python3 <<PYTHON_SCRIPT
import xml.etree.ElementTree as ET
import sys

try:
    tree = ET.parse('$XML_FILE')
    root = tree.getroot()
    
    ports = []
    for host in root.findall('host'):
        for port in host.findall('.//port[@state="open"]'):
            portid = port.get('portid')
            service = port.find('service')
            svc_name = service.get('name') if service is not None else 'unknown'
            ports.append(f"{portid},{svc_name}")
    
    print('\n'.join(ports[:20]))
except Exception as e:
    print('', file=sys.stderr)
PYTHON_SCRIPT
)
else
    OPEN_PORTS=""
fi

# Create findings JSON
cat > "$OUTPUT_JSON" <<EOF
{
  "target_ip": "$TARGET_IP",
  "analysis_timestamp": "$TIMESTAMP",
  "findings": [
EOF

FINDING_COUNT=0

# Add open ports as findings using Python for proper JSON handling
if command -v python3 &> /dev/null && [ -f "$XML_FILE" ]; then
    python3 <<PYTHON_SCRIPT > "$OUTPUT_JSON"
import json
import xml.etree.ElementTree as ET
import sys
from datetime import datetime
import uuid

try:
    tree = ET.parse('$XML_FILE')
    root = tree.getroot()
    
    findings = []
    open_ports = []
    
    for host in root.findall('host'):
        for port in host.findall('.//port[@state="open"]'):
            portid = port.get('portid')
            service = port.find('service')
            svc_name = service.get('name') if service is not None else 'unknown'
            svc_product = service.get('product', '') if service is not None else ''
            svc_version = service.get('version', '') if service is not None else ''
            
            open_ports.append(int(portid))
            
            finding = {
                "id": f"finding-{uuid.uuid4().hex[:8]}",
                "timestamp": "$TIMESTAMP",
                "finding_type": "open_port",
                "severity": "medium",
                "target": "$TARGET_IP",
                "target_ip": "$TARGET_IP",
                "description": f"Open port {portid} ({svc_name}) detected",
                "port": int(portid),
                "service": svc_name
            }
            
            if svc_product:
                finding["service_product"] = svc_product
            if svc_version:
                finding["service_version"] = svc_version
                finding["severity"] = "high"  # Version disclosure increases severity
            
            findings.append(finding)
        
        # Check for vulnerabilities
        for script in host.findall('.//script[@id="vuln"]'):
            port_elem = script.getparent()
            portid = port_elem.get('portid') if port_elem is not None else None
            
            for table in script.findall('table'):
                vuln_id = None
                for elem in table.findall('elem'):
                    if elem.get('key') == 'id':
                        vuln_id = elem.text
                        break
                
                if vuln_id:
                    findings.append({
                        "id": f"finding-{uuid.uuid4().hex[:8]}",
                        "timestamp": "$TIMESTAMP",
                        "finding_type": "vulnerability",
                        "severity": "high",
                        "target": "$TARGET_IP",
                        "target_ip": "$TARGET_IP",
                        "description": f"Vulnerability {vuln_id} detected on port {portid}",
                        "port": int(portid) if portid else None,
                        "evidence": "Nmap vulnerability scan",
                        "vulnerability_id": vuln_id
                    })
    
    result = {
        "target_ip": "$TARGET_IP",
        "analysis_timestamp": "$TIMESTAMP",
        "findings": findings,
        "summary": {
            "total_findings": len(findings),
            "open_ports": len(open_ports),
            "vulnerabilities": len([f for f in findings if f.get('finding_type') == 'vulnerability'])
        }
    }
    
    print(json.dumps(result, indent=2))
except Exception as e:
    # Fallback: create basic structure
    result = {
        "target_ip": "$TARGET_IP",
        "analysis_timestamp": "$TIMESTAMP",
        "findings": [],
        "summary": {
            "total_findings": 0,
            "open_ports": 0,
            "vulnerabilities": 0
        },
        "error": str(e)
    }
    print(json.dumps(result, indent=2))
PYTHON_SCRIPT
else
    # Fallback JSON structure if Python not available
    cat > "$OUTPUT_JSON" <<EOF
{
  "target_ip": "$TARGET_IP",
  "analysis_timestamp": "$TIMESTAMP",
  "findings": [],
  "summary": {
    "total_findings": 0,
    "open_ports": 0,
    "vulnerabilities": 0
  },
  "note": "Python3 required for XML parsing. Install python3 to parse Nmap XML results."
}
EOF
fi

# Add vulnerabilities if found
if [ -n "$VULNS" ]; then
    echo "$VULNS" | while IFS=':' read -r port vuln_id; do
        if [ -n "$vuln_id" ]; then
            if [ $FINDING_COUNT -gt 0 ]; then
                echo "," >> "$OUTPUT_JSON"
            fi
            cat >> "$OUTPUT_JSON" <<VULN_EOF
    {
      "id": "finding-$(uuidgen 2>/dev/null || echo $RANDOM)",
      "timestamp": "$TIMESTAMP",
      "finding_type": "vulnerability",
      "severity": "high",
      "target": "$TARGET_IP",
      "target_ip": "$TARGET_IP",
      "description": "Vulnerability $vuln_id detected on port $port",
      "port": $port,
      "evidence": "Nmap vulnerability scan"
    }VULN_EOF
            FINDING_COUNT=$((FINDING_COUNT + 1))
        fi
    done
fi

cat >> "$OUTPUT_JSON" <<EOF

  ],
  "summary": {
    "total_findings": $FINDING_COUNT,
    "open_ports": $(echo "$OPEN_PORTS" | grep -c "," || echo "0"),
    "vulnerabilities": $(echo "$VULNS" | grep -c ":" || echo "0")
  }
}
EOF

echo "Parsed $FINDING_COUNT findings from Nmap XML"
echo "Output: $OUTPUT_JSON"
