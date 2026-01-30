#!/bin/bash
# Extract findings from Kali container and convert to JSON format
# Usage: ./extract-findings-from-kali.sh <target-ip>

TARGET_IP=${1:-""}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -z "$TARGET_IP" ]; then
    echo "Usage: $0 <target-ip>"
    echo "Example: $0 94.130.75.252"
    exit 1
fi

echo "Extracting findings for $TARGET_IP from Kali container..."

# Use the improved parsing script
bash "$SCRIPT_DIR/parse-nmap-to-findings.sh" "$TARGET_IP"
    python3 <<PYTHON_SCRIPT
import json
import xml.etree.ElementTree as ET
import sys
import os
from datetime import datetime
import uuid
from pathlib import Path

findings = []
all_open_ports = set()
vulnerabilities = []

# Parse all XML files
for xml_file in Path('$TEMP_DIR').glob('*.xml'):
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        
        for host in root.findall('host'):
            host_ip = None
            for address in host.findall('address'):
                if address.get('addrtype') == 'ipv4':
                    host_ip = address.get('addr')
                    break
            
            if not host_ip:
                host_ip = '$TARGET_IP'
            
            for port in host.findall('.//port[@state="open"]'):
                portid = port.get('portid')
                service = port.find('service')
                svc_name = service.get('name') if service is not None else 'unknown'
                svc_product = service.get('product', '') if service is not None else ''
                svc_version = service.get('version', '') if service is not None else ''
                
                all_open_ports.add(int(portid))
                
                finding = {
                    "id": f"finding-{uuid.uuid4().hex[:8]}",
                    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
                    "finding_type": "open_port",
                    "severity": "medium",
                    "target": host_ip,
                    "target_ip": host_ip,
                    "description": f"Open port {portid} ({svc_name}) detected on target",
                    "port": int(portid),
                    "service": svc_name
                }
                
                if svc_product:
                    finding["service_product"] = svc_product
                if svc_version:
                    finding["service_version"] = svc_version
                    finding["severity"] = "high"
                    finding["description"] += f" - Version: {svc_version}"
                
                findings.append(finding)
            
            # Check for vulnerabilities
            for script in host.findall('.//script'):
                script_id = script.get('id', '')
                if 'vuln' in script_id.lower():
                    port_elem = script.getparent()
                    portid = port_elem.get('portid') if port_elem is not None else None
                    
                    for table in script.findall('table'):
                        vuln_id = None
                        for elem in table.findall('elem'):
                            if elem.get('key') == 'id':
                                vuln_id = elem.text
                                break
                        
                        if vuln_id:
                            vulnerabilities.append(vuln_id)
                            findings.append({
                                "id": f"finding-{uuid.uuid4().hex[:8]}",
                                "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
                                "finding_type": "vulnerability",
                                "severity": "high",
                                "target": host_ip,
                                "target_ip": host_ip,
                                "description": f"Vulnerability {vuln_id} detected on port {portid}",
                                "port": int(portid) if portid else None,
                                "evidence": "Nmap vulnerability scan",
                                "vulnerability_id": vuln_id
                            })
    except Exception as e:
        print(f"Error parsing {xml_file}: {e}", file=sys.stderr)

result = {
    "target_ip": "$TARGET_IP",
    "analysis_timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "findings": findings,
    "summary": {
        "total_findings": len(findings),
        "open_ports": len(all_open_ports),
        "vulnerabilities": len(vulnerabilities),
        "unique_vulnerabilities": len(set(vulnerabilities))
    }
}

with open('$FINDINGS_JSON', 'w') as f:
    json.dump(result, f, indent=2)

print(f"Extracted {len(findings)} findings")
print(f"Output: $FINDINGS_JSON")
PYTHON_SCRIPT
else
    echo "Python3 is required to parse XML files. Please install python3."
    exit 1
fi

# Cleanup
rm -rf "$TEMP_DIR"

echo ""
echo "Findings extracted successfully!"
echo "Findings file: $FINDINGS_JSON"
echo ""
echo "Now generate the report:"
echo "  ./scripts/generate-external-report.sh $TARGET_IP"
