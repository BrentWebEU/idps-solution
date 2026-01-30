#!/bin/bash
# Filtered traffic capture script for specific protocols/ports
# Usage: ./capture-filtered.sh [protocol] [output-file]

CAPTURE_CONTAINER="pentest-capture"
CAPTURES_DIR="/captures"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
DEFAULT_OUTPUT="capture_filtered_${TIMESTAMP}.pcap"

PROTOCOL=${1:-all}
OUTPUT_FILE=${2:-$DEFAULT_OUTPUT}

# Protocol filters
declare -A FILTERS
FILTERS[radius]="port 1812 or port 1813"
FILTERS[http]="port 8080"
FILTERS[mysql]="port 3306"
FILTERS[ssh]="port 22"
FILTERS[ftp]="port 21"
FILTERS[smb]="port 445 or port 139"
FILTERS[all]="port 1812 or port 1813 or port 8080 or port 3306 or port 22 or port 21 or port 445 or port 139"

if [ -z "${FILTERS[$PROTOCOL]}" ]; then
    echo "Unknown protocol: $PROTOCOL"
    echo "Available protocols: radius, http, mysql, ssh, ftp, smb, all"
    exit 1
fi

FILTER="${FILTERS[$PROTOCOL]}"
echo "Starting filtered capture for protocol: $PROTOCOL"
echo "Filter: $FILTER"
echo "Output file: $OUTPUT_FILE"

docker exec -d $CAPTURE_CONTAINER sh -c "tcpdump -i any -w ${CAPTURES_DIR}/${OUTPUT_FILE} -s 0 $FILTER"

if [ $? -eq 0 ]; then
    echo "Filtered capture started successfully"
    echo "PCAP file will be saved to: ./captures/${OUTPUT_FILE}"
    echo "To stop capture, run: docker exec $CAPTURE_CONTAINER pkill tcpdump"
else
    echo "Failed to start filtered capture"
    exit 1
fi
