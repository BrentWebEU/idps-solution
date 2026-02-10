#!/bin/bash
# Generate external pentest report for specific IP
# Usage: ./generate-external-report.sh <ip-address>

TARGET_IP=${1:-"144.178.248.26"}
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
FINDINGS_DIR="$LAB_DIR/findings"
REPORTS_DIR="$LAB_DIR/reports"
REPORT_FILE="$REPORTS_DIR/external_pentest_${TARGET_IP//\./_}_${TIMESTAMP}.html"

mkdir -p "$REPORTS_DIR"

echo "Generating external pentest report for $TARGET_IP..."
echo "Output: $REPORT_FILE"

# Collect findings for this IP
FINDINGS_COUNT=0
FINDINGS_FILES=()
FINDINGS_HTML=""

# Check for findings files - try multiple patterns
if [ -d "$FINDINGS_DIR" ]; then
    # Try different IP formats (dots, underscores, with/without prefix)
    for json_file in \
        "$FINDINGS_DIR"/findings_${TARGET_IP//\./_}_*.json \
        "$FINDINGS_DIR"/*${TARGET_IP//\./_}*.json \
        "$FINDINGS_DIR"/*${TARGET_IP}*.json \
        "$FINDINGS_DIR"/dns_findings_${TARGET_IP//\./_}_*.json \
        "$FINDINGS_DIR"/pcap_analysis_*.json; do
        if [ -f "$json_file" ]; then
            filename=$(basename "$json_file")
            # Check if this file is relevant to our target
            if echo "$filename" | grep -qE "${TARGET_IP//\./_}|${TARGET_IP}|pcap_analysis"; then
                FINDINGS_COUNT=$((FINDINGS_COUNT + 1))
                FINDINGS_FILES+=("$json_file")
                echo "  Found findings file: $filename"
            fi
        fi
    done
fi

# Parse findings from JSON files
PARSING_SUCCEEDED=false
FINDINGS_HTML=""

if [ ${#FINDINGS_FILES[@]} -gt 0 ] && command -v python3 &> /dev/null; then
    echo "  Parsing findings from ${#FINDINGS_FILES[@]} file(s)..."
    
    # Create temp file with file list
    TEMP_FILE_LIST="/tmp/findings_files_$$.txt"
    printf '%s\n' "${FINDINGS_FILES[@]}" > "$TEMP_FILE_LIST"
    
    # Parse with Python and capture both HTML and success status
    PARSING_RESULT=$(python3 <<PYTHON_SCRIPT
import json
import sys
import html
import os

findings_html = ""

# Read file list from temp file
file_list_path = "$TEMP_FILE_LIST"
if os.path.exists(file_list_path):
    with open(file_list_path, 'r') as f:
        json_files = [line.strip() for line in f if line.strip()]
else:
    json_files = []

for json_file in json_files:
    json_file = json_file.strip("'\"")
    if not os.path.exists(json_file):
        continue
        
    try:
        with open(json_file, 'r') as f:
            data = json.load(f)
        
        # Check for findings array (direct list)
        if isinstance(data, list):
            for finding in data:
                # Assuming findings are directly in the list and conform to the expected finding structure
                severity = finding.get('severity', 'medium')
                finding_type = finding.get('finding_type', finding.get('type', 'Unknown Finding'))
                target = finding.get('target', '')
                target_ip = finding.get('target_ip', '')
                description = finding.get('description', '')
                payload = finding.get('payload', '')
                evidence = finding.get('evidence', '')
                source_ip = finding.get('source_ip', '')
                port = finding.get('port', '')
                service = finding.get('service', '')
                username = finding.get('username', '') # For brute_force_success
                password = finding.get('password', '') # For brute_force_success
                
                findings_html += f'<div class="finding {severity}">'
                findings_html += f'<h3>{html.escape(str(finding_type).replace("_", " ").title())}</h3>'
                if target:
                    findings_html += f'<p><strong>Target:</strong> {html.escape(str(target))}</p>'
                if target_ip and target_ip != 'N/A': # Check for 'N/A' from dnsrecon parsing
                    findings_html += f'<p><strong>IP:</strong> {html.escape(str(target_ip))}</p>'
                if severity:
                    findings_html += f'<p><strong>Severity:</strong> <span class="severity severity-{severity}">{severity.upper()}</span></p>'
                if description:
                    findings_html += f'<p><strong>Description:</strong> {html.escape(str(description))}</p>'
                if service:
                    findings_html += f'<p><strong>Service:</strong> {html.escape(str(service))}</p>'
                if port:
                    findings_html += f'<p><strong>Port:</strong> {port}</p>'
                if username:
                    findings_html += f'<p><strong>Username:</strong> {html.escape(str(username))}</p>'
                if password:
                    findings_html += f'<p><strong>Password:</strong> {html.escape(str(password))}</p>'
                if payload:
                    findings_html += f'<p><strong>Payload:</strong> <code>{html.escape(str(payload))}</code></p>'
                if evidence:
                    findings_html += f'<p><strong>Evidence:</strong> <code class="code-block">{html.escape(str(evidence))}</code></p>' # Use code-block for multiline
                findings_html += '</div>'

        # Check for findings array (nested under 'findings' key)
        elif 'findings' in data and isinstance(data['findings'], list) and len(data['findings']) > 0:
            for finding in data['findings']:
                severity = finding.get('severity', 'medium')
                finding_type = finding.get('finding_type', finding.get('type', 'Unknown Finding'))
                target = finding.get('target', '')
                target_ip = finding.get('target_ip', '')
                description = finding.get('description', '')
                payload = finding.get('payload', '')
                evidence = finding.get('evidence', '')
                source_ip = finding.get('source_ip', '')
                port = finding.get('port', '')
                service = finding.get('service', '')
                
                findings_html += f'<div class="finding {severity}">'
                findings_html += f'<h3>{html.escape(str(finding_type).replace("_", " ").title())}</h3>'
                if target:
                    findings_html += f'<p><strong>Target:</strong> {html.escape(str(target))}</p>'
                if target_ip:
                    findings_html += f'<p><strong>IP:</strong> {html.escape(str(target_ip))}</p>'
                if severity:
                    findings_html += f'<p><strong>Severity:</strong> <span class="severity severity-{severity}">{severity.upper()}</span></p>'
                if description:
                    findings_html += f'<p><strong>Description:</strong> {html.escape(str(description))}</p>'
                if service:
                    findings_html += f'<p><strong>Service:</strong> {html.escape(str(service))}</p>'
                if port:
                    findings_html += f'<p><strong>Port:</strong> {port}</p>'
                if payload:
                    findings_html += f'<p><strong>Payload:</strong> <code>{html.escape(str(payload))}</code></p>'
                if evidence:
                    findings_html += f'<p><strong>Evidence:</strong> {html.escape(str(evidence))}</p>'
                if source_ip:
                    findings_html += f'<p><strong>Source IP:</strong> {html.escape(str(source_ip))}</p>'
                findings_html += '</div>'
        
        # Check for attack patterns
        elif 'attack_patterns' in data and isinstance(data['attack_patterns'], list) and len(data['attack_patterns']) > 0:
            for pattern in data['attack_patterns']:
                pattern_type = pattern.get('pattern_type', 'Attack Pattern')
                source_ip = pattern.get('source_ip', '')
                dest_ip = pattern.get('destination_ip', '')
                count = pattern.get('count', 0)
                severity = 'high' if pattern_type in ['brute_force', 'port_scan'] else 'medium'
                
                findings_html += f'<div class="finding {severity}">'
                findings_html += f'<h3>{html.escape(str(pattern_type).replace("_", " ").title())}</h3>'
                findings_html += f'<p><strong>Source:</strong> {html.escape(str(source_ip))} → <strong>Destination:</strong> {html.escape(str(dest_ip))}</p>'
                if 'destination_port' in pattern and pattern['destination_port']:
                    findings_html += f'<p><strong>Port:</strong> {pattern["destination_port"]}</p>'
                findings_html += f'<p><strong>Count:</strong> {count} occurrences</p>'
                if 'indicators' in pattern and pattern['indicators']:
                    indicators = ', '.join([str(i) for i in pattern['indicators']])
                    findings_html += f'<p><strong>Indicators:</strong> {html.escape(indicators)}</p>'
                findings_html += '</div>'
        
        # Check for PCAP analysis results - filter out empty entries
        elif any(key in data for key in ['http_requests', 'sql_queries', 'radius_packets', 'ssh_connections', 'brute_force_patterns', 'port_scan_patterns']):
            if 'http_requests' in data:
                http_reqs = [r for r in data['http_requests'] if r and (r.get('method') or r.get('uri'))]
                if len(http_reqs) > 0:
                    findings_html += f'<div class="finding medium"><h3>HTTP Requests Detected</h3><p>Found {len(http_reqs)} HTTP requests</p><ul>'
                    for req in http_reqs[:10]:
                        if req.get('method') and req.get('uri'):
                            findings_html += f'<li><strong>{html.escape(str(req.get("method", "")))}</strong> {html.escape(str(req.get("uri", "")))}</li>'
                    findings_html += '</ul></div>'
            
            if 'sql_queries' in data:
                sql_reqs = [q for q in data['sql_queries'] if q and q.get('query')]
                if len(sql_reqs) > 0:
                    findings_html += f'<div class="finding high"><h3>SQL Queries Detected</h3><p>Found {len(sql_reqs)} SQL queries - potential SQL injection</p><ul>'
                    for query in sql_reqs[:10]:
                        if query.get('query'):
                            findings_html += f'<li><code>{html.escape(str(query.get("query", "")))}</code></li>'
                    findings_html += '</ul></div>'
            
            if 'brute_force_patterns' in data:
                bf_patterns = [p for p in data['brute_force_patterns'] if p and p.get('count') and str(p.get('count')).strip() and p.get('count') != '']
                if len(bf_patterns) > 0:
                    findings_html += f'<div class="finding high"><h3>Brute Force Patterns Detected</h3><p>Found {len(bf_patterns)} brute force patterns</p><ul>'
                    for pattern in bf_patterns[:10]:
                        if pattern.get('src') and pattern.get('dst'):
                            findings_html += f'<li><strong>{html.escape(str(pattern.get("src", "")))}</strong> → {html.escape(str(pattern.get("dst", "")))}, Port: {pattern.get("port", "N/A")}, Count: {pattern.get("count", 0)}</li>'
                    findings_html += '</ul></div>'
            
            if 'port_scan_patterns' in data:
                ps_patterns = [p for p in data['port_scan_patterns'] if p and p.get('count') and str(p.get('count')).strip() and p.get('count') != '']
                if len(ps_patterns) > 0:
                    findings_html += f'<div class="finding medium"><h3>Port Scan Patterns Detected</h3><p>Found {len(ps_patterns)} port scan patterns</p><ul>'
                    for pattern in ps_patterns[:10]:
                        if pattern.get('src'):
                            findings_html += f'<li><strong>{html.escape(str(pattern.get("src", "")))}</strong> scanned port {pattern.get("port", "N/A")} ({pattern.get("count", 0)} times)</li>'
                    findings_html += '</ul></div>'
            
            if 'ssh_connections' in data:
                ssh_conns = [c for c in data['ssh_connections'] if c and (c.get('src') or c.get('dst'))]
                if len(ssh_conns) > 0:
                    findings_html += f'<div class="finding medium"><h3>SSH Connections Detected</h3><p>Found {len(ssh_conns)} SSH connection attempts</p></div>'
            
            if 'radius_packets' in data:
                radius_pkts = [p for p in data['radius_packets'] if p and (p.get('code') or p.get('username'))]
                if len(radius_pkts) > 0:
                    findings_html += f'<div class="finding medium"><h3>RADIUS Packets Detected</h3><p>Found {len(radius_pkts)} RADIUS authentication packets</p></div>'
        
        # Check summary for quick stats
        elif 'summary' in data:
            summary = data['summary']
            if summary.get('total_findings', 0) > 0:
                findings_html += f'<div class="finding medium"><h3>Scan Summary</h3>'
                findings_html += f'<p><strong>Total Findings:</strong> {summary.get("total_findings", 0)}</p>'
                if summary.get('open_ports', 0) > 0:
                    findings_html += f'<p><strong>Open Ports:</strong> {summary.get("open_ports", 0)}</p>'
                if summary.get('vulnerabilities', 0) > 0:
                    findings_html += f'<p><strong>Vulnerabilities:</strong> {summary.get("vulnerabilities", 0)}</p>'
                findings_html += '</div>'
    
    except Exception as e:
        findings_html += f'<div class="finding low"><p>Error parsing {os.path.basename(json_file)}: {html.escape(str(e))}</p></div>'

# Return findings HTML and parsing status
# Format: SUCCESS|HTML_CONTENT
if findings_html:
    print(f"SUCCESS|{findings_html}")
else:
    print("SUCCESS|")  # Success but no findings
PYTHON_SCRIPT
)
    
    # Parse the result
    if echo "$PARSING_RESULT" | grep -q "^SUCCESS|"; then
        PARSING_SUCCEEDED=true
        FINDINGS_HTML=$(echo "$PARSING_RESULT" | sed 's/^SUCCESS|//')
    else
        PARSING_SUCCEEDED=false
        FINDINGS_HTML=""
    fi
    
    rm -f "$TEMP_FILE_LIST"
elif [ ${#FINDINGS_FILES[@]} -gt 0 ]; then
    echo "  ⚠ Python3 not found - cannot parse JSON findings"
fi

# Generate HTML report
cat > "$REPORT_FILE" <<EOF
<!DOCTYPE html>
<html>
<head>
    <title>External Penetration Test Report - $TARGET_IP</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #333;
            border-bottom: 3px solid #2196F3;
            padding-bottom: 10px;
        }
        h2 {
            color: #555;
            margin-top: 30px;
            border-bottom: 2px solid #ddd;
            padding-bottom: 5px;
        }
        .summary {
            background-color: #f9f9f9;
            padding: 20px;
            border-left: 4px solid #2196F3;
            margin: 20px 0;
        }
        .finding {
            border: 1px solid #ddd;
            padding: 15px;
            margin: 10px 0;
            border-radius: 5px;
        }
        .high {
            border-left: 5px solid #f44336;
        }
        .medium {
            border-left: 5px solid #ff9800;
        }
        .low {
            border-left: 5px solid #4CAF50;
        }
        .severity {
            font-weight: bold;
            padding: 3px 8px;
            border-radius: 3px;
            display: inline-block;
        }
        .severity.high {
            background-color: #ffebee;
            color: #c62828;
        }
        .severity.medium {
            background-color: #fff3e0;
            color: #e65100;
        }
        .severity.low {
            background-color: #e8f5e9;
            color: #2e7d32;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th, td {
            border: 1px solid #ddd;
            padding: 12px;
            text-align: left;
        }
        th {
            background-color: #2196F3;
            color: white;
        }
        tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        .code-block {
            background-color: #f4f4f4;
            padding: 10px;
            border-radius: 3px;
            font-family: monospace;
            white-space: pre-wrap; /* Ensures newlines are preserved */
            word-break: break-all; /* Breaks long words */
            overflow-x: auto;
            display: block; /* Ensures it takes up full width */
            margin-top: 5px;
        }
        .recommendations {
            background-color: #e3f2fd;
            padding: 20px;
            border-left: 4px solid #2196F3;
            margin: 20px 0;
        }
        .warning {
            background-color: #fff3cd;
            border: 1px solid #ffc107;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }
        ul {
            margin: 10px 0;
            padding-left: 20px;
        }
        li {
            margin: 5px 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>External Penetration Test Report</h1>
        
        <div class="warning">
            <strong>⚠️ Authorization Required:</strong> This report is for authorized testing only. 
            Ensure you have explicit written permission to test the target before proceeding.
        </div>
        
        <div class="summary">
            <h2>Executive Summary</h2>
            <table>
                <tr>
                    <th>Target IP</th>
                    <td>$TARGET_IP</td>
                </tr>
                <tr>
                    <th>Test Date</th>
                    <td>$(date +%Y-%m-%d\ %H:%M:%S)</td>
                </tr>
                <tr>
                    <th>Test Type</th>
                    <td>External Penetration Test</td>
                </tr>
                <tr>
                    <th>Findings Files Found</th>
                    <td>$FINDINGS_COUNT</td>
                </tr>
            </table>
        </div>

        <h2>Target Information</h2>
        <table>
            <tr>
                <th>IP Address</th>
                <td>$TARGET_IP</td>
            </tr>
            <tr>
                <th>Network Type</th>
                <td>External/Public</td>
            </tr>
            <tr>
                <th>Testing Approach</th>
                <td>Non-intrusive reconnaissance and vulnerability assessment</td>
            </tr>
        </table>

        <h2>Testing Methodology</h2>
        <p>This external penetration test was conducted using the following phases:</p>
        <ol>
            <li><strong>Network Discovery:</strong> Host discovery, port scanning, and service enumeration</li>
            <li><strong>Vulnerability Assessment:</strong> Automated vulnerability scanning using Nmap scripts</li>
            <li><strong>Web Application Testing:</strong> HTTP/HTTPS service testing, SQL injection, directory traversal</li>
            <li><strong>Credential Testing:</strong> Common credential and brute force testing (where applicable)</li>
            <li><strong>Traffic Analysis:</strong> PCAP analysis for attack pattern detection</li>
        </ol>

        <h2>Vulnerability Findings</h2>
EOF

# Add parsed findings to report
if [ "$PARSING_SUCCEEDED" = true ] && [ ${#FINDINGS_FILES[@]} -gt 0 ]; then
    if [ -n "$FINDINGS_HTML" ]; then
        # Findings were parsed and contain data
        echo "$FINDINGS_HTML" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    else
        # Findings were parsed but are empty
        echo "        <p>Found ${#FINDINGS_FILES[@]} findings file(s), but all contain empty findings arrays (no vulnerabilities detected).</p>" >> "$REPORT_FILE"
        echo "        <p>This could mean:" >> "$REPORT_FILE"
        echo "        <ul>" >> "$REPORT_FILE"
        echo "            <li>The target has no open ports or services</li>" >> "$REPORT_FILE"
        echo "            <li>The Nmap scan did not complete successfully</li>" >> "$REPORT_FILE"
        echo "            <li>Findings need to be extracted from XML files: <code>./scripts/parse-nmap-to-findings.sh $TARGET_IP</code></li>" >> "$REPORT_FILE"
        echo "        </ul>" >> "$REPORT_FILE"
        echo "        </p>" >> "$REPORT_FILE"
    fi
    
    echo "        <h3>Findings Files</h3>" >> "$REPORT_FILE"
    echo "        <p>Detailed findings are available in the following files:</p>" >> "$REPORT_FILE"
    echo "        <ul>" >> "$REPORT_FILE"
    for json_file in "${FINDINGS_FILES[@]}"; do
        if [ -f "$json_file" ]; then
            filename=$(basename "$json_file")
            echo "            <li><a href=\"../findings/$filename\">$filename</a></li>" >> "$REPORT_FILE"
        fi
    done
    echo "        </ul>" >> "$REPORT_FILE"
elif [ ${#FINDINGS_FILES[@]} -gt 0 ]; then
    echo "        <p>Found ${#FINDINGS_FILES[@]} findings file(s), but unable to parse. Python3 is required to parse JSON findings.</p>" >> "$REPORT_FILE"
    echo "        <p>Install python3 or use: <code>./scripts/parse-nmap-to-findings.sh $TARGET_IP</code> to extract findings from Nmap XML files.</p>" >> "$REPORT_FILE"
    echo "        <ul>" >> "$REPORT_FILE"
    for json_file in "${FINDINGS_FILES[@]}"; do
        if [ -f "$json_file" ]; then
            filename=$(basename "$json_file")
            echo "            <li><a href=\"../findings/$filename\">$filename</a></li>" >> "$REPORT_FILE"
        fi
    done
    echo "        </ul>" >> "$REPORT_FILE"
else
    echo "        <p>No findings files found for this target.</p>" >> "$REPORT_FILE"
    echo "        <p>To generate findings, run:</p>" >> "$REPORT_FILE"
    echo "        <div class=\"code\">./scripts/external-pentest.sh $TARGET_IP</div>" >> "$REPORT_FILE"
    echo "        <p>Or use the complete workflow:</p>" >> "$REPORT_FILE"
    echo "        <div class=\"code\">./scripts/run-external-pentest.sh $TARGET_IP</div>" >> "$REPORT_FILE"
    echo "        <p>To extract findings from existing Nmap XML files in Kali container:</p>" >> "$REPORT_FILE"
    echo "        <div class=\"code\">./scripts/parse-nmap-to-findings.sh $TARGET_IP</div>" >> "$REPORT_FILE"
fi

cat >> "$REPORT_FILE" <<EOF

        <h2>Recommended IDPS Rules</h2>
        <div class="recommendations">
            <p>Based on external pentest findings, the following IDPS rules are recommended:</p>
            <ul>
                <li><strong>Port Scan Detection:</strong> Detect rapid port scanning activities from external sources</li>
                <li><strong>Web Attack Detection:</strong> Detect SQL injection, XSS, and other web-based attacks</li>
                <li><strong>Brute Force Detection:</strong> Monitor for multiple failed authentication attempts</li>
                <li><strong>Anomaly Detection:</strong> Detect unusual traffic patterns and protocol usage</li>
            </ul>
            <p>Rules can be generated using the IDPS API or web interface:</p>
            <div class="code">
POST /api/pcap/analyze<br>
POST /api/rules/generate<br>
POST /api/rules/activate
            </div>
        </div>

        <h2>Remediation Recommendations</h2>
        <div class="recommendations">
            <h3>Immediate Actions</h3>
            <ul>
                <li>Review and close unnecessary open ports</li>
                <li>Update all software to latest versions</li>
                <li>Implement proper firewall rules</li>
                <li>Enable security monitoring and logging</li>
            </ul>

            <h3>Long-term Improvements</h3>
            <ul>
                <li>Regular security assessments</li>
                <li>Implement Web Application Firewall (WAF)</li>
                <li>Security header implementation</li>
                <li>Intrusion detection and prevention systems</li>
                <li>Regular patch management process</li>
            </ul>
        </div>

        <h2>Next Steps</h2>
        <ol>
            <li>Review all findings and prioritize vulnerabilities</li>
            <li>Generate IDPS rules from attack patterns</li>
            <li>Implement remediation measures</li>
            <li>Re-test to verify fixes</li>
            <li>Document lessons learned</li>
        </ol>

        <h2>Appendix</h2>
        <h3>Tools Used</h3>
        <ul>
            <li>Nmap - Network scanning and service enumeration</li>
            <li>Nmap Scripts - Vulnerability detection</li>
            <li>curl - Web application testing</li>
            <li>tcpdump - Traffic capture</li>
            <li>tshark - Traffic analysis</li>
        </ul>

        <h3>Report Generation</h3>
        <p>Report generated: $(date)</p>
        <p>Report version: 2.0</p>
        <p>Generated by: External Pentest Automation Script</p>
    </div>
</body>
</html>
EOF

echo ""
echo "External pentest report generated successfully!"
echo "Location: $REPORT_FILE"
echo "Findings files processed: ${#FINDINGS_FILES[@]}"
if [ "$PARSING_SUCCEEDED" = true ]; then
    if [ -n "$FINDINGS_HTML" ]; then
        echo "Findings HTML generated: Yes (findings found)"
    else
        echo "Findings HTML generated: Yes (parsing succeeded, but findings arrays are empty)"
    fi
else
    echo "Findings HTML generated: No (parsing failed - Python3 may not be available)"
fi
echo ""
echo "To view the report:"
echo "  open $REPORT_FILE"
echo "  or"
echo "  file://$REPORT_FILE"
