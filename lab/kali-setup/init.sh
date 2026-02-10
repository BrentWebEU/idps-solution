#!/bin/bash
# Kali Linux Container Initialization Script

echo "========================================="
echo "  Kali Linux Pentesting Container"
echo "========================================="
echo ""

INIT_FLAG="/root/.kali_initialized"

if [ ! -f "$INIT_FLAG" ]; then
    echo "[*] First run - initializing environment..."
    mkdir -p /root/pentest-results /root/tools
    touch "$INIT_FLAG"
    echo "[*] Initialization complete!"
    echo ""
fi

echo "Environment Ready:"
echo "  - Wordlists: /usr/share/wordlists/"
echo "  - Captures: /captures"
echo "  - Findings: /findings"
echo "  - Reports: /reports"
echo ""
echo "Tools: nmap, hydra, john, sqlmap, nikto, metasploit"
echo "Ready for pentesting!"
echo "========================================="

exec "$@"
