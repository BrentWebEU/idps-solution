#!/bin/bash
# Network discovery script using nmap
# Scans lab networks for hosts, ports, and services

KALI_CONTAINER="pentest-kali"
OUTPUT_DIR="/root/pentest-results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

NETWORKS=(
    "172.20.0.0/24"  # Attacker network
    "172.21.0.0/24"  # DMZ network
    "172.22.0.0/24"  # Internal network
)

echo "Starting network discovery scan..."
echo "Timestamp: $TIMESTAMP"

# Create output directory
docker exec $KALI_CONTAINER mkdir -p $OUTPUT_DIR

for network in "${NETWORKS[@]}"; do
    echo ""
    echo "Scanning network: $network"
    OUTPUT_FILE="${OUTPUT_DIR}/nmap_discovery_${network//\//_}_${TIMESTAMP}.xml"
    
    # Host discovery scan
    echo "  - Host discovery..."
    docker exec $KALI_CONTAINER nmap -sn -oX "${OUTPUT_FILE}.hosts" $network
    
    # Port scan on discovered hosts
    echo "  - Port scanning..."
    docker exec $KALI_CONTAINER nmap -sS -sV -O -p- -oX "${OUTPUT_FILE}.ports" $network
    
    # Service enumeration
    echo "  - Service enumeration..."
    docker exec $KALI_CONTAINER nmap -sC -sV -oX "${OUTPUT_FILE}.services" $network
    
    echo "  Results saved to: $OUTPUT_FILE.*"
done

echo ""
echo "Network discovery complete!"
echo "Results saved in Kali container at: $OUTPUT_DIR"
