#!/bin/bash
# Traffic capture script for pentest lab
# Usage: ./capture.sh [start|stop|status] [interface] [output-file]

CAPTURE_CONTAINER="pentest-capture"
CAPTURES_DIR="/captures"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
DEFAULT_INTERFACE="any"
DEFAULT_OUTPUT="capture_${TIMESTAMP}.pcap"

ACTION=${1:-start}
INTERFACE=${2:-$DEFAULT_INTERFACE}
OUTPUT_FILE=${3:-$DEFAULT_OUTPUT}

start_capture() {
    echo "Starting traffic capture on interface: $INTERFACE"
    echo "Output file: $OUTPUT_FILE"
    
    docker exec -d $CAPTURE_CONTAINER sh -c "tcpdump -i $INTERFACE -w ${CAPTURES_DIR}/${OUTPUT_FILE} -s 0"
    
    if [ $? -eq 0 ]; then
        echo "Capture started successfully"
        echo "PCAP file will be saved to: ./captures/${OUTPUT_FILE}"
    else
        echo "Failed to start capture"
        exit 1
    fi
}

stop_capture() {
    echo "Stopping traffic capture..."
    docker exec $CAPTURE_CONTAINER sh -c "pkill tcpdump || true"
    echo "Capture stopped"
}

status_capture() {
    echo "Checking capture status..."
    if docker exec $CAPTURE_CONTAINER sh -c "pgrep tcpdump" > /dev/null 2>&1; then
        echo "Capture is running"
        docker exec $CAPTURE_CONTAINER sh -c "ps aux | grep tcpdump | grep -v grep"
    else
        echo "No capture process running"
    fi
}

case $ACTION in
    start)
        start_capture
        ;;
    stop)
        stop_capture
        ;;
    status)
        status_capture
        ;;
    *)
        echo "Usage: $0 [start|stop|status] [interface] [output-file]"
        echo "  start  - Start traffic capture (default: any interface)"
        echo "  stop   - Stop running capture"
        echo "  status - Check capture status"
        exit 1
        ;;
esac
