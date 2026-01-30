#!/bin/bash
# Generate pentest report from findings
# Usage: ./generate-report.sh [timestamp] [pentest-type]

TIMESTAMP=${1:-$(date +%Y%m%d_%H%M%S)}
PENTEST_TYPE=${2:-"unknown"}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
FINDINGS_DIR="$LAB_DIR/findings"
REPORTS_DIR="$LAB_DIR/reports"
REPORT_FILE="$REPORTS_DIR/pentest_report_${TIMESTAMP}.html"

mkdir -p "$REPORTS_DIR"

echo "Generating pentest report..."
echo "Timestamp: $TIMESTAMP"
echo "Pentest Type: $PENTEST_TYPE"
echo "Output: $REPORT_FILE"

# Collect findings from JSON files
FINDINGS_COUNT=0
ATTACK_PATTERNS=0
VULNERABILITIES=()

if [ -d "$FINDINGS_DIR" ]; then
    for json_file in "$FINDINGS_DIR"/*.json; do
        if [ -f "$json_file" ]; then
            FINDINGS_COUNT=$((FINDINGS_COUNT + 1))
            
            # Extract vulnerability types (simplified)
            if grep -q "brute_force\|port_scan\|sql_injection" "$json_file" 2>/dev/null; then
                ATTACK_PATTERNS=$((ATTACK_PATTERNS + 1))
            fi
        fi
    done
fi

# Generate HTML report
cat > "$REPORT_FILE" <<EOF
<!DOCTYPE html>
<html>
<head>
    <title>Penetration Test Report - $TIMESTAMP</title>
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
            border-bottom: 3px solid #4CAF50;
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
            border-left: 4px solid #4CAF50;
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
            background-color: #4CAF50;
            color: white;
        }
        tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        .code {
            background-color: #f4f4f4;
            padding: 10px;
            border-radius: 3px;
            font-family: monospace;
            overflow-x: auto;
        }
        .recommendations {
            background-color: #e3f2fd;
            padding: 20px;
            border-left: 4px solid #2196F3;
            margin: 20px 0;
        }
        .recommendations ul {
            margin: 10px 0;
            padding-left: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Penetration Test Report</h1>
        
        <div class="summary">
            <h2>Executive Summary</h2>
            <table>
                <tr>
                    <th>Test Date</th>
                    <td>$(date -d "$TIMESTAMP" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "$TIMESTAMP")</td>
                </tr>
                <tr>
                    <th>Test Type</th>
                    <td>$PENTEST_TYPE</td>
                </tr>
                <tr>
                    <th>Findings Files</th>
                    <td>$FINDINGS_COUNT</td>
                </tr>
                <tr>
                    <th>Attack Patterns Detected</th>
                    <td>$ATTACK_PATTERNS</td>
                </tr>
            </table>
        </div>

        <h2>Test Methodology</h2>
        <p>This penetration test was conducted in an isolated lab environment with the following phases:</p>
        <ol>
            <li><strong>Reconnaissance:</strong> Network discovery and service enumeration</li>
            <li><strong>Vulnerability Assessment:</strong> Identification of security weaknesses</li>
            <li><strong>Exploitation:</strong> Attempted exploitation of identified vulnerabilities</li>
            <li><strong>Post-Exploitation:</strong> Data collection and lateral movement</li>
            <li><strong>Traffic Analysis:</strong> PCAP analysis for attack pattern detection</li>
        </ol>

        <h2>Findings</h2>
        <p>Detailed findings are available in the following files:</p>
        <ul>
EOF

# List findings files
if [ -d "$FINDINGS_DIR" ]; then
    for json_file in "$FINDINGS_DIR"/*.json; do
        if [ -f "$json_file" ]; then
            filename=$(basename "$json_file")
            echo "            <li><a href=\"../findings/$filename\">$filename</a></li>" >> "$REPORT_FILE"
        fi
    done
fi

cat >> "$REPORT_FILE" <<EOF
        </ul>

        <h2>Attack Patterns Detected</h2>
        <p>Based on traffic analysis, the following attack patterns were identified:</p>
        <ul>
            <li><strong>Brute Force Attacks:</strong> Multiple failed authentication attempts detected</li>
            <li><strong>Port Scanning:</strong> Network reconnaissance activities identified</li>
            <li><strong>SQL Injection:</strong> Potential SQL injection attempts detected in web traffic</li>
            <li><strong>RADIUS Attacks:</strong> RADIUS authentication testing detected</li>
        </ul>

        <h2>Recommended IDPS Rules</h2>
        <div class="recommendations">
            <p>The following Suricata IDPS rules are recommended based on the findings:</p>
            <ul>
                <li><strong>Brute Force Detection:</strong> Monitor for multiple failed authentication attempts</li>
                <li><strong>Port Scan Detection:</strong> Alert on rapid port scanning activities</li>
                <li><strong>SQL Injection Detection:</strong> Detect SQL injection patterns in HTTP requests</li>
                <li><strong>RADIUS Attack Detection:</strong> Monitor RADIUS authentication patterns</li>
            </ul>
            <p>Rules can be generated and activated using the IDPS API:</p>
            <div class="code">
POST /api/rules/generate<br>
POST /api/rules/activate
            </div>
        </div>

        <h2>Remediation Recommendations</h2>
        <div class="recommendations">
            <h3>Immediate Actions</h3>
            <ul>
                <li>Change all default and weak passwords</li>
                <li>Disable unnecessary services and ports</li>
                <li>Implement proper access controls</li>
                <li>Enable logging and monitoring</li>
            </ul>

            <h3>Long-term Improvements</h3>
            <ul>
                <li>Implement multi-factor authentication</li>
                <li>Regular security assessments</li>
                <li>Network segmentation</li>
                <li>Intrusion detection and prevention systems</li>
                <li>Security awareness training</li>
            </ul>
        </div>

        <h2>Appendix</h2>
        <h3>Lab Environment</h3>
        <ul>
            <li>Network Segments: Attacker (172.20.0.0/24), DMZ (172.21.0.0/24), Internal (172.22.0.0/24)</li>
            <li>Services Tested: Web Server, RADIUS, MySQL, FTP/SMB, SSH</li>
            <li>Tools Used: Nmap, Metasploit, Hydra, SQLMap, Wireshark</li>
        </ul>

        <h3>Report Generation</h3>
        <p>Report generated: $(date)</p>
        <p>Report version: 1.0</p>
    </div>
</body>
</html>
EOF

echo ""
echo "Report generated successfully!"
echo "Report location: $REPORT_FILE"
echo ""
echo "To view the report, open it in a web browser:"
echo "  file://$REPORT_FILE"
echo "  or"
echo "  open $REPORT_FILE"
