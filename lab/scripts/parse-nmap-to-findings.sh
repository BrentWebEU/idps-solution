#!/bin/bash
# Parse Nmap XML files directly and create findings JSON
# This script can parse XML files from Kali container or local filesystem
# Usage: ./parse-nmap-to-findings.sh <target-ip> [xml-file-path]

TARGET_IP=$1
XML_FILE=$2
KALI_CONTAINER="pentest-kali"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
FINDINGS_DIR="$LAB_DIR/findings"
OUTPUT_DIR="/root/pentest-results"

if [ -z "$TARGET_IP" ]; then
    echo "Usage: $0 <target-ip> [xml-file-path]"
    echo "Example: $0 94.130.75.252"
    echo "Or: $0 94.130.75.252 /path/to/nmap-results.xml"
    exit 1
fi

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
FINDINGS_JSON="${FINDINGS_DIR}/findings_${TARGET_IP//\./_}_${TIMESTAMP}.json"
mkdir -p "$FINDINGS_DIR"

# If XML file provided, use it; otherwise find in Kali container
if [ -n "$XML_FILE" ] && [ -f "$XML_FILE" ]; then
    XML_FILES="$XML_FILE"
elif [ -n "$XML_FILE" ] && docker exec $KALI_CONTAINER test -f "$XML_FILE" 2>/dev/null; then
    # Copy from container
    TEMP_XML="/tmp/nmap_${TARGET_IP//\./_}_${TIMESTAMP}.xml"
    docker cp "${KALI_CONTAINER}:${XML_FILE}" "$TEMP_XML" 2>/dev/null
    XML_FILES="$TEMP_XML"
else
    # Find XML files in Kali container
    echo "Searching for Nmap XML files in Kali container..."
    XML_FILES_IN_CONTAINER=$(docker exec $KALI_CONTAINER sh -c "find $OUTPUT_DIR -name '*${TARGET_IP}*.xml' -type f 2>/dev/null" 2>/dev/null)
    
    if [ -z "$XML_FILES_IN_CONTAINER" ]; then
        echo "No XML files found for $TARGET_IP in Kali container"
        echo "Run the pentest first: ./scripts/external-pentest.sh $TARGET_IP"
        exit 1
    fi
    
    # Copy files from container
    TEMP_DIR="/tmp/nmap_parse_$$"
    mkdir -p "$TEMP_DIR"
    for xml_file in $XML_FILES_IN_CONTAINER; do
        filename=$(basename "$xml_file")
        docker cp "${KALI_CONTAINER}:${xml_file}" "$TEMP_DIR/$filename" 2>/dev/null
    done
    XML_FILES="$TEMP_DIR/*.xml"
fi

# Parse XML files using Python
if ! command -v python3 &> /dev/null; then
    echo "Error: python3 is required to parse XML files"
    exit 1
fi

python3 <<PYTHON_SCRIPT
import json
import xml.etree.ElementTree as ET
import sys
import glob
from datetime import datetime
import uuid

findings = []
all_open_ports = set()
vulnerabilities = []
services_found = {}

# Parse all XML files
xml_files = []
if isinstance('$XML_FILES', str) and '*' in '$XML_FILES':
    import os
    xml_files = glob.glob('$XML_FILES')
else:
    xml_files = ['$XML_FILES'] if '$XML_FILES' else []

if not xml_files:
    # Try to find files in temp directory
    xml_files = glob.glob('/tmp/nmap_parse_*/*.xml') + glob.glob('/tmp/nmap_*.xml')

for xml_file in xml_files:
    if not os.path.exists(xml_file):
        continue
        
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        
        for host in root.findall('host'):
            host_ip = None
            hostname = None
            
            # Get host IP
            for address in host.findall('address'):
                if address.get('addrtype') == 'ipv4':
                    host_ip = address.get('addr')
                    break
            
            # Get hostname
            for hostname_elem in host.findall('hostnames/hostname'):
                hostname = hostname_elem.get('name')
                break
            
            if not host_ip:
                host_ip = '$TARGET_IP'
            
            # Parse ports
            for port in host.findall('.//port[@state="open"]'):
                portid = int(port.get('portid'))
                protocol = port.get('protocol', 'tcp')
                
                service = port.find('service')
                svc_name = service.get('name') if service is not None else 'unknown'
                svc_product = service.get('product', '') if service is not None else ''
                svc_version = service.get('version', '') if service is not None else ''
                svc_extrainfo = service.get('extrainfo', '') if service is not None else ''
                
                all_open_ports.add(portid)
                
                # Build service description
                service_desc = f"{svc_name}"
                if svc_product:
                    service_desc += f" ({svc_product})"
                if svc_version:
                    service_desc += f" {svc_version}"
                
                services_found[portid] = {
                    'name': svc_name,
                    'product': svc_product,
                    'version': svc_version
                }
                
                # Determine severity based on service
                severity = "medium"
                if portid in [22, 3389, 5900]:  # SSH, RDP, VNC
                    severity = "high"
                elif portid in [21, 23, 1433, 3306, 5432]:  # FTP, Telnet, SQL
                    severity = "high"
                elif svc_version:
                    severity = "high"  # Version disclosure
                
                finding = {
                    "id": f"finding-{uuid.uuid4().hex[:8]}",
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "finding_type": "open_port",
                    "severity": severity,
                    "target": hostname or host_ip,
                    "target_ip": host_ip,
                    "description": f"Open port {portid}/{protocol} ({service_desc}) detected",
                    "port": portid,
                    "protocol": protocol,
                    "service": svc_name,
                    "service_product": svc_product,
                    "service_version": svc_version
                }
                
                findings.append(finding)
            
            # Parse vulnerabilities
            for script in host.findall('.//script'):
                script_id = script.get('id', '')
                script_output = script.get('output', '')
                
                port_elem = script.getparent()
                portid = None
                if port_elem is not None and port_elem.tag == 'port':
                    portid = int(port_elem.get('portid'))
                
                # Check for vulnerability scripts
                if 'vuln' in script_id.lower() or 'vulns' in script_id.lower():
                    for table in script.findall('table'):
                        vuln_id = None
                        vuln_title = None
                        vuln_state = None
                        
                        for elem in table.findall('elem'):
                            key = elem.get('key')
                            if key == 'id':
                                vuln_id = elem.text
                            elif key == 'title':
                                vuln_title = elem.text
                            elif key == 'state':
                                vuln_state = elem.text
                        
                        if vuln_id or vuln_title:
                            vulnerabilities.append(vuln_id or vuln_title)
                            findings.append({
                                "id": f"finding-{uuid.uuid4().hex[:8]}",
                                "timestamp": datetime.utcnow().isoformat() + "Z",
                                "finding_type": "vulnerability",
                                "severity": "high",
                                "target": hostname or host_ip,
                                "target_ip": host_ip,
                                "description": f"Vulnerability detected: {vuln_title or vuln_id}",
                                "port": portid,
                                "evidence": "Nmap vulnerability scan",
                                "vulnerability_id": vuln_id or vuln_title,
                                "vulnerability_state": vuln_state
                            })
                
                # Check for other security-relevant scripts
                elif script_id in ['http-title', 'http-server-header', 'ssl-cert', 'ssh-hostkey']:
                    if portid:
                        finding_type = script_id.replace('-', '_')
                        severity = "low" if script_id == 'http-title' else "medium"
                        
                        findings.append({
                            "id": f"finding-{uuid.uuid4().hex[:8]}",
                            "timestamp": datetime.utcnow().isoformat() + "Z",
                            "finding_type": finding_type,
                            "severity": severity,
                            "target": hostname or host_ip,
                            "target_ip": host_ip,
                            "description": f"{script_id} information: {script_output[:200]}",
                            "port": portid,
                            "evidence": script_output
                        })
    
    except Exception as e:
        print(f"Error parsing {xml_file}: {e}", file=sys.stderr)
        continue

# Create summary
result = {
    "target_ip": "$TARGET_IP",
    "analysis_timestamp": datetime.utcnow().isoformat() + "Z",
    "findings": findings,
    "summary": {
        "total_findings": len(findings),
        "open_ports": len(all_open_ports),
        "vulnerabilities": len([f for f in findings if f.get('finding_type') == 'vulnerability']),
        "unique_vulnerabilities": len(set(vulnerabilities)),
        "ports": sorted(list(all_open_ports)),
        "services": services_found
    }
}

# Write JSON file
with open('$FINDINGS_JSON', 'w') as f:
    json.dump(result, f, indent=2)

print(f"✓ Extracted {len(findings)} findings")
print(f"✓ Open ports: {len(all_open_ports)}")
print(f"✓ Vulnerabilities: {len([f for f in findings if f.get('finding_type') == 'vulnerability'])}")
print(f"✓ Output: $FINDINGS_JSON")

# Cleanup temp files
import shutil
if os.path.exists('/tmp/nmap_parse_'):
    for temp_dir in glob.glob('/tmp/nmap_parse_*'):
        shutil.rmtree(temp_dir, ignore_errors=True)
for temp_file in glob.glob('/tmp/nmap_*.xml'):
    os.remove(temp_file)
PYTHON_SCRIPT

if [ -f "$FINDINGS_JSON" ]; then
    echo ""
    echo "Findings successfully extracted!"
    echo "File: $FINDINGS_JSON"
else
    echo ""
    echo "Error: Failed to create findings JSON file"
    exit 1
fi
