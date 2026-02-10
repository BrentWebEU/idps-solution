#!/bin/bash
# Interactive Lab Menu - Choose what, where and how to run pentests
# Connects to all existing lab scripts
# WARNING: Only use in authorized lab environments

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
KALI_CONTAINER="pentest-kali"

# Colors (use $'...' so escapes are interpreted; works when output goes to stderr)
RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
BLUE=$'\033[0;34m'
CYAN=$'\033[0;36m'
BOLD=$'\033[1m'
NC=$'\033[0m'

# Default lab targets (for quick selection)
DEFAULT_WEB="172.21.0.2"
DEFAULT_RADIUS="172.21.0.3"
DEFAULT_DB="172.22.0.3"
DEFAULT_FTP="172.22.0.4"
DEFAULT_LINUX="172.22.0.5"
DEFAULT_EXTERNAL="144.178.248.26"

# ---------------------------------------------------------------------------
# Validation & prompt helpers
# ---------------------------------------------------------------------------
validate_ip() {
    local ip=$1
    [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]
}

prompt_ip() {
    local prompt_text=$1
    local default_value=$2
    local ip=""
    while true; do
        if [ -n "$default_value" ]; then
            read -p "  $prompt_text [$default_value]: " ip
            ip=${ip:-$default_value}
        else
            read -p "  $prompt_text: " ip
        fi
        if validate_ip "$ip"; then
            echo "$ip"
            return 0
        fi
        echo -e "  ${RED}Invalid IP format. Try again.${NC}"
    done
}

prompt_number() {
    local prompt_text=$1
    local default_value=$2
    read -p "  $prompt_text [$default_value]: " val
    val=${val:-$default_value}
    if [[ "$val" =~ ^[0-9]+$ ]]; then
        echo "$val"
    else
        echo "$default_value"
    fi
}

prompt_yesno() {
    local prompt_text=$1
    local default=${2:-"n"}
    read -p "  $prompt_text (y/n) [$default]: " r
    r=${r:-$default}
    [[ $r =~ ^[Yy]$ ]]
}

# ---------------------------------------------------------------------------
# Lab check
# ---------------------------------------------------------------------------
check_lab_running() {
    if ! docker ps 2>/dev/null | grep -q "pentest-kali"; then
        echo -e "${RED}Lab is not running. Start with: cd $LAB_DIR && docker-compose up -d${NC}"
        return 1
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Main menu
# ---------------------------------------------------------------------------
show_main_menu() {
    # Send menu to stderr so it displays when choice=$(show_main_menu) captures stdout
    {
        echo ""
        echo -e "${CYAN}============================================${NC}"
        echo -e "${CYAN}     Pentest Lab - Interactive Menu${NC}"
        echo -e "${CYAN}============================================${NC}"
        echo ""
        echo "  What do you want to do?"
        echo ""
        echo "  ${BOLD}1)${NC} Internal Lab Pentest    (automated discovery, vuln scan, credentials, exploitation)"
        echo "  ${BOLD}2)${NC} External Pentest        (scan and test an external IP)"
        echo "  ${BOLD}3)${NC} Attack Testing          (DDOS, Brute-Force, Network Infiltration)"
        echo "  ${BOLD}4)${NC} Traffic Capture          (start / stop / status)"
        echo "  ${BOLD}5)${NC} Analysis & Reporting    (analyze PCAP, extract findings, generate reports)"
        echo "  ${BOLD}6)${NC} Run Full Attack Suite   (DDOS + Brute-Force + Infiltration with capture)"
        echo "  ${BOLD}0)${NC} Exit"
        echo ""
    } >&2
    read -p "  Select option [0-6]: " choice
    echo "$choice"
}

# ---------------------------------------------------------------------------
# 1) Internal Lab Pentest
# ---------------------------------------------------------------------------
menu_internal_pentest() {
    while true; do
        clear
        echo -e "${BLUE}--- Internal Lab Pentest ---${NC}"
        echo ""
        echo "  1) Full automated pentest (discovery + vuln scan + credentials + exploitation)"
        echo "  2) Network discovery only"
        echo "  3) Vulnerability scan only"
        echo "  4) Credential testing only"
        echo "  5) Exploitation only"
        echo "  6) Full workflow with traffic capture and report"
        echo ""
        echo "  0) Back to main menu"
        echo ""
        read -p "  Select [0-6]: " c
        case $c in
            1)  check_lab_running && bash "$SCRIPT_DIR/automated-pentest.sh"; pause ;;
            2)  check_lab_running && bash "$SCRIPT_DIR/network-discovery.sh"; pause ;;
            3)  check_lab_running && bash "$SCRIPT_DIR/vulnerability-scan.sh"; pause ;;
            4)  check_lab_running && bash "$SCRIPT_DIR/credential-testing.sh"; pause ;;
            5)  check_lab_running && bash "$SCRIPT_DIR/exploitation.sh"; pause ;;
            6)  check_lab_running && bash "$SCRIPT_DIR/run-pentest.sh"; pause ;;
            0)  return ;;
            *)  echo "  Invalid option"; sleep 1 ;;
        esac
    done
}

# ---------------------------------------------------------------------------
# 2) External Pentest
# ---------------------------------------------------------------------------
menu_external_pentest() {
    while true; do
        clear
        echo -e "${BLUE}--- External Pentest ---${NC}"
        echo ""
        echo "  1) Run external pentest only (scan + vuln + web tests)"
        echo "  2) Full external workflow (capture + pentest + extract findings + report)"
        echo ""
        echo "  0) Back to main menu"
        echo ""
        read -p "  Select [0-2]: " c
        case $c in
            1)
                check_lab_running || return
                ip=$(prompt_ip "Enter external target IP" "$DEFAULT_EXTERNAL")
                bash "$SCRIPT_DIR/external-pentest.sh" "$ip"
                pause
                ;;
            2)
                check_lab_running || return
                ip=$(prompt_ip "Enter external target IP" "$DEFAULT_EXTERNAL")
                bash "$SCRIPT_DIR/run-external-pentest.sh" "$ip"
                pause
                ;;
            0)  return ;;
            *)  echo "  Invalid option"; sleep 1 ;;
        esac
    done
}

# ---------------------------------------------------------------------------
# 3) Attack Testing
# ---------------------------------------------------------------------------
menu_attack_testing() {
    while true; do
        clear
        echo -e "${BLUE}--- Attack Testing ---${NC}"
        echo ""
        echo "  1) DDOS attack (SYN flood, UDP, HTTP, Slowloris, etc.)"
        echo "  2) Brute force (SSH, FTP, SMB, MySQL, HTTP, RADIUS)"
        echo "  3) Network infiltration (lateral movement, exfiltration, C2)"
        echo "  4) Run all attacks (DDOS + Brute-Force + Infiltration) with capture"
        echo ""
        echo "  0) Back to main menu"
        echo ""
        read -p "  Select [0-4]: " c
        case $c in
            1)  do_ddos_menu; pause ;;
            2)  do_bruteforce_menu; pause ;;
            3)  do_infiltration_menu; pause ;;
            4)  do_run_all_attacks; pause ;;
            0)  return ;;
            *)  echo "  Invalid option"; sleep 1 ;;
        esac
    done
}

do_ddos_menu() {
    check_lab_running || return
    echo ""
    ip=$(prompt_ip "Target IP" "$DEFAULT_WEB")
    port=$(prompt_number "Target port" "80")
    duration=$(prompt_number "Duration (seconds)" "30")
    echo "  Attack type: 1=syn_flood 2=udp_flood 3=http_flood 4=slowloris 5=icmp_flood 6=all"
    read -p "  Select type [6]: " t
    case $t in
        1) type="syn_flood" ;;
        2) type="udp_flood" ;;
        3) type="http_flood" ;;
        4) type="slowloris" ;;
        5) type="icmp_flood" ;;
        *) type="all" ;;
    esac
    if prompt_yesno "Start traffic capture before attack?" "y"; then
        capfile="ddos_${ip//\./_}_$(date +%Y%m%d_%H%M%S).pcap"
        bash "$SCRIPT_DIR/capture.sh" start any "$capfile"
        echo -e "${GREEN}Capture started: $capfile${NC}"
    fi
    bash "$SCRIPT_DIR/ddos-attack.sh" "$ip" "$port" "$duration" "$type"
    if prompt_yesno "Stop traffic capture?" "y"; then
        bash "$SCRIPT_DIR/capture.sh" stop
    fi
}

do_bruteforce_menu() {
    check_lab_running || return
    echo ""
    ip=$(prompt_ip "Target IP" "$DEFAULT_LINUX")
    echo "  Service: 1=ssh 2=ftp 3=smb 4=mysql 5=http 6=radius 7=all"
    read -p "  Select service [1]: " s
    case $s in
        2) svc="ftp" ;;
        3) svc="smb" ;;
        4) svc="mysql" ;;
        5) svc="http" ;;
        6) svc="radius" ;;
        7) svc="all" ;;
        *) svc="ssh" ;;
    esac
    read -p "  Username (optional, Enter to use wordlist): " user
    echo "  Wordlist: 1=small 2=medium 3=large"
    read -p "  Select wordlist [1]: " w
    case $w in
        2) wl="medium" ;;
        3) wl="large" ;;
        *) wl="small" ;;
    esac
    if prompt_yesno "Start traffic capture before attack?" "y"; then
        capfile="bruteforce_${ip//\./_}_$(date +%Y%m%d_%H%M%S).pcap"
        bash "$SCRIPT_DIR/capture.sh" start any "$capfile"
    fi
    if [ -n "$user" ]; then
        bash "$SCRIPT_DIR/brute-force-attack.sh" "$ip" "$svc" "$user" "$wl"
    else
        bash "$SCRIPT_DIR/brute-force-attack.sh" "$ip" "$svc" "" "$wl"
    fi
    if prompt_yesno "Stop traffic capture?" "y"; then
        bash "$SCRIPT_DIR/capture.sh" stop
    fi
}

do_infiltration_menu() {
    check_lab_running || return
    echo ""
    ip=$(prompt_ip "Initial target IP (e.g. DMZ host)" "$DEFAULT_WEB")
    echo "  Type: 1=lateral_movement 2=persistence 3=data_exfiltration 4=privilege_escalation 5=command_control 6=all"
    read -p "  Select type [6]: " t
    case $t in
        1) type="lateral_movement" ;;
        2) type="persistence" ;;
        3) type="data_exfiltration" ;;
        4) type="privilege_escalation" ;;
        5) type="command_control" ;;
        *) type="all" ;;
    esac
    if prompt_yesno "Start traffic capture before run?" "y"; then
        capfile="infiltration_${ip//\./_}_$(date +%Y%m%d_%H%M%S).pcap"
        bash "$SCRIPT_DIR/capture.sh" start any "$capfile"
    fi
    bash "$SCRIPT_DIR/network-infiltration.sh" "$ip" "$type"
    if prompt_yesno "Stop traffic capture?" "y"; then
        bash "$SCRIPT_DIR/capture.sh" stop
    fi
}

do_run_all_attacks() {
    check_lab_running || return
    # run-all-attacks.sh has its own IP prompts and capture
    bash "$SCRIPT_DIR/run-all-attacks.sh"
}

# ---------------------------------------------------------------------------
# 4) Traffic Capture
# ---------------------------------------------------------------------------
menu_traffic_capture() {
    while true; do
        clear
        echo -e "${BLUE}--- Traffic Capture ---${NC}"
        echo ""
        echo "  1) Start capture (prompt for filename)"
        echo "  2) Stop capture"
        echo "  3) Status"
        echo ""
        echo "  0) Back to main menu"
        echo ""
        read -p "  Select [0-3]: " c
        case $c in
            1)
                fname="capture_$(date +%Y%m%d_%H%M%S).pcap"
                read -p "  Output filename [$fname]: " f
                f=${f:-$fname}
                bash "$SCRIPT_DIR/capture.sh" start any "$f"
                echo -e "${GREEN}Capture started: $f${NC}"
                pause
                ;;
            2)  bash "$SCRIPT_DIR/capture.sh" stop; pause ;;
            3)  bash "$SCRIPT_DIR/capture.sh" status; pause ;;
            0)  return ;;
            *)  echo "  Invalid option"; sleep 1 ;;
        esac
    done
}

# ---------------------------------------------------------------------------
# 5) Analysis & Reporting
# ---------------------------------------------------------------------------
menu_analysis_reporting() {
    while true; do
        clear
        echo -e "${BLUE}--- Analysis & Reporting ---${NC}"
        echo ""
        echo "  1) Analyze PCAP file"
        echo "  2) Extract findings from Nmap XML (Kali container)"
        echo "  3) Generate internal pentest report"
        echo "  4) Generate external pentest report"
        echo "  5) Generate vulnerability summary (lab vulns)"
        echo ""
        echo "  0) Back to main menu"
        echo ""
        read -p "  Select [0-5]: " c
        case $c in
            1)
                if [ -d "$LAB_DIR/captures" ]; then
                    echo "  Recent captures:"
                    ls -1t "$LAB_DIR/captures"/*.pcap 2>/dev/null | head -5
                fi
                read -p "  PCAP file path (e.g. ./captures/capture_xxx.pcap): " pcap
                if [ -n "$pcap" ]; then
                    [ -f "$pcap" ] || pcap="$LAB_DIR/$pcap"
                    if [ -f "$pcap" ]; then
                        bash "$SCRIPT_DIR/analyze-pcap.sh" "$pcap" "$LAB_DIR/findings"
                    else
                        echo -e "${RED}File not found: $pcap${NC}"
                    fi
                fi
                pause
                ;;
            2)
                ip=$(prompt_ip "Target IP (to match Nmap XML files)" "$DEFAULT_EXTERNAL")
                bash "$SCRIPT_DIR/parse-nmap-to-findings.sh" "$ip"
                pause
                ;;
            3)
                bash "$SCRIPT_DIR/generate-report.sh"
                pause
                ;;
            4)
                ip=$(prompt_ip "External target IP for report" "$DEFAULT_EXTERNAL")
                bash "$SCRIPT_DIR/generate-external-report.sh" "$ip"
                pause
                ;;
            5)
                bash "$SCRIPT_DIR/generate-vulnerability-summary.sh"
                pause
                ;;
            0)  return ;;
            *)  echo "  Invalid option"; sleep 1 ;;
        esac
    done
}

# ---------------------------------------------------------------------------
# 6) Run full attack suite
# ---------------------------------------------------------------------------
do_full_attack_suite() {
    check_lab_running || return
    bash "$SCRIPT_DIR/run-all-attacks.sh"
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
pause() {
    echo ""
    read -p "  Press Enter to continue..."
}

# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------
main() {
    while true; do
        choice=$(show_main_menu)
        case $choice in
            1)  check_lab_running && menu_internal_pentest ;;
            2)  menu_external_pentest ;;
            3)  menu_attack_testing ;;
            4)  menu_traffic_capture ;;
            5)  menu_analysis_reporting ;;
            6)  do_full_attack_suite ;;
            0)
                echo ""
                echo "  Goodbye."
                exit 0
                ;;
            *)
                echo -e "  ${RED}Invalid option.${NC}"
                sleep 1
                ;;
        esac
    done
}

main "$@"
