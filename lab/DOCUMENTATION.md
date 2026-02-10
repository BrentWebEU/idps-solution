# Penetration Testing Lab Implementation - Detailed Documentation

This document outlines the implementation of enhanced penetration testing capabilities within the provided lab environment. It covers new scripts, modifications to existing ones, and their integration with the reporting infrastructure, enabling comprehensive security validation against both the virtual lab and external targets (with proper authorization).

## 1. Lab Environment Overview

The lab environment is orchestrated using `docker-compose.yml`, providing a multi-tiered network architecture with various vulnerable services. Key components include:

*   **`pentest-kali`**: The attacker machine (Kali Linux) from which all penetration testing scripts are executed.
*   **`web-server`**: An intentionally outdated Apache web server, serving as a public-facing target.
*   **`db-server`**: A MySQL database with weak credentials, exposed on the internal network.
*   **`file-server`**: An FTP and SMB file server with weak authentication and world-writable shares.
*   **`vulnerable-linux`**: A Linux system with weak SSH configurations, multiple user accounts with weak passwords, and privilege escalation vectors.
*   **`radius-server`**: (Intended) A FreeRADIUS server for WPA2-Enterprise authentication testing. **(Note: This service is currently non-functional due to configuration errors and was not fixed as part of this implementation.)**
*   **`gateway`**: An Alpine Linux instance acting as a router/firewall, segmenting traffic between `attacker-net`, `dmz-net`, and `internal-net`.
*   **`traffic-capture`**: A network utility container for capturing traffic across various network segments.

The network segmentation includes `attacker-net`, `dmz-net`, `internal-net`, and several VLANs (`admin-vlan`, `faculty-vlan`, `student-vlan`, `guest-vlan`) for simulating role-based access.

## 2. New and Modified Scripts

The following scripts have been created or significantly modified to implement the penetration testing strategy:

### 2.1. `scripts/test-network-segmentation.sh` (NEW)

*   **Purpose:** Verifies the effectiveness of network segmentation by testing expected reachability between the attacker network and various services in the DMZ and internal networks. It aims to identify unintended open access paths.
*   **Usage:** `./scripts/test-network-segmentation.sh`
*   **Execution:** Runs from the host machine, executing commands within the `pentest-kali` container.
*   **Output:** Generates a text log (`segmentation_test_<TIMESTAMP>.log`) and a structured JSON findings file (`segmentation_findings_<TIMESTAMP>.json`) in the `/root/pentest-results` directory of the Kali container. The JSON file is then copied to the host's `findings/` directory.
*   **JSON Findings Details:**
    *   `finding_type`: `network_segmentation`
    *   `severity`: `critical` (for segmentation breaches), `medium` (for unexpected service unavailability), `low` (for expected behavior).
    *   `description`: Detailed explanation of the test result (PASS/FAIL) and its implications.
    *   Includes `target_ip`, `port`, `protocol`, `service`, and Nmap output as `evidence`.

### 2.2. `scripts/wifi-brute-force.sh` (NEW / Modified for JSON output)

*   **Purpose:** Simulates WPA2-Enterprise / RADIUS brute-force attacks against a target RADIUS server using `radtest`. It attempts to find valid credentials from provided wordlists.
*   **Usage:** `./scripts/wifi-brute-force.sh [RADIUS_SERVER_IP] [RADIUS_SECRET] [USER_LIST_PATH] [PASS_LIST_PATH]`
    *   **Example:** `./scripts/wifi-brute-force.sh 172.21.0.X schoolradius123 /usr/share/wordlists/rockyou.txt /usr/share/wordlists/fasttrack.txt`
*   **Execution:** Runs from the host machine, executing commands within the `pentest-kali` container.
*   **Output:** Generates a text log (`wifi_brute_force_<TIMESTAMP>.log`) and a structured JSON findings file (`brute_force_findings_<TIMESTAMP>.json`) in the `/root/pentest-results` directory of the Kali container. The JSON file is then copied to the host's `findings/` directory.
*   **JSON Findings Details:**
    *   `finding_type`: `brute_force_success`
    *   `severity`: `critical` (for successful credential compromise).
    *   `description`: Indicates successful authentication with specific username and password.
    *   Includes `target_ip`, `port` (1812), `protocol` (udp), `service` (RADIUS), `username`, `password`, and `radtest` output as `evidence`.
*   **Note:** The effectiveness of this script is currently limited by the non-functional `radius-server` in the lab.

### 2.3. `scripts/capture.sh` (MODIFIED)

*   **Purpose:** Enhanced script for flexible network traffic capture within the `pentest-capture` container.
*   **Usage:** `./scripts/capture.sh [start|stop|status] [interface] [output-file] [filter-expression]`
    *   **New Feature:** Added `[filter-expression]` argument to pass raw `tcpdump` filters (e.g., `'host 172.22.0.2 and port 3306'`).
    *   **Example:** `./scripts/capture.sh start any capture_filtered.pcap 'port 80 or port 21'`
*   **Execution:** Runs from the host machine, controlling `tcpdump` within the `pentest-capture` container.
*   **Output:** `.pcap` files stored in the host's `captures/` directory.

### 2.4. `scripts/analyze-encryption.sh` (NEW / Modified for JSON output)

*   **Purpose:** Analyzes `.pcap` files for various types of unencrypted traffic, identifying potential data exposure or weak protocol usage.
*   **Usage:** `./scripts/analyze-encryption.sh <path_to_pcap_file_in_kali_container>`
    *   **Example:** `./scripts/analyze-encryption.sh /captures/my_capture.pcap`
*   **Execution:** Runs from the host machine, executing `tshark` commands within the `pentest-kali` container.
*   **Output:** Generates a text log (`encryption_analysis_<TIMESTAMP>.log`) and a structured JSON findings file (`encryption_findings_<TIMESTAMP>.json`) in the `/root/pentest-results` directory of the Kali container. The JSON file is then copied to the host's `findings/` directory.
*   **JSON Findings Details:**
    *   `finding_type`: `unencrypted_traffic`
    *   `severity`: `high` (indicating potential exposure of sensitive information).
    *   `description`: States the type of unencrypted traffic and packet count.
    *   Includes `target` (the PCAP file name), `protocol_detected`, `packet_count`, and a summary of packet information as `evidence`.

### 2.5. `scripts/ddos-attack.sh` (REVIEWED)

*   **Purpose:** Simulates various Distributed Denial of Service (DDoS) attack patterns against a target.
*   **Usage:** `./scripts/ddos-attack.sh [TARGET_IP] [TARGET_PORT] [DURATION] [ATTACK_TYPE]`
    *   **Example:** `./scripts/ddos-attack.sh 172.21.0.2 80 60 http_flood`
*   **Status:** This script was already robust and configurable, fulfilling the requirements for configurable attack types targeting the web server. No modifications were needed.

### 2.6. `scripts/vulnerability-scan.sh` & `scripts/network-discovery.sh` (REVIEWED)

*   **Purpose:** `network-discovery.sh` performs host discovery, port scanning, and service enumeration. `vulnerability-scan.sh` performs targeted vulnerability scanning using Nmap NSE scripts.
*   **Status:** Both scripts already extensively leverage Nmap's NSE (Nmap Scripting Engine) for robust vulnerability detection, including the `--script vuln` category and service-specific scripts. No modifications were needed. Their outputs (Nmap XML files) are directly consumed by `parse-nmap-to-findings.sh`.

### 2.7. `scripts/dns-security-check.sh` (NEW)

*   **Purpose:** Performs DNS enumeration and zone transfer attempts against a target domain or DNS server IP.
*   **Usage:** `./scripts/dns-security-check.sh <target_domain_or_ip>`
    *   **Example:** `./scripts/dns-security-check.sh example.com`
*   **Execution:** Runs from the host machine, executing commands within the `pentest-kali` container.
*   **Output:** Generates a text log (`dns_security_check_<TIMESTAMP>.log`) in the `/root/pentest-results` directory of the Kali container.

## 3. Integration with Reporting

The new and modified scripts are designed to seamlessly integrate with the existing reporting framework, primarily through:

*   **`scripts/parse-nmap-to-findings.sh`**: This script (and its embedded Python logic) is instrumental in converting Nmap XML output into a standardized JSON format.
*   **`scripts/generate-external-report.sh`**: This script is the central reporting tool. It now dynamically consumes the JSON findings generated by:
    *   `parse-nmap-to-findings.sh` (for Nmap scan results).
    *   `test-network-segmentation.sh` (for segmentation test results).
    *   `wifi-brute-force.sh` (for successful RADIUS brute-force attempts).
    *   `analyze-encryption.sh` (for unencrypted traffic findings).
    The `generate-external-report.sh`'s embedded Python script parses these JSON files from the host's `findings/` directory and renders detailed HTML sections within the final report, categorized by finding type and severity.

## 4. How to Use the Lab and Scripts

### 4.1. Lab Setup

1.  **Ensure Docker is running.**
2.  **Start the lab environment:**
    ```bash
    docker-compose up -d --build
    ```
    *(Note: The `radius-server` may not start correctly. This is a known issue but does not block other lab functionalities.)*

### 4.2. Running Penetration Tests

All pentesting scripts are designed to be executed from your host machine, which in turn runs the actual commands inside the `pentest-kali` container.

*   **Network Segmentation Test:**
    ```bash
    ./scripts/test-network-segmentation.sh
    ```
*   **Wi-Fi / RADIUS Brute-Force (requires functional RADIUS):**
    ```bash
    ./scripts/wifi-brute-force.sh 172.21.0.3 schoolradius123 /usr/share/wordlists/fasttrack.txt /usr/share/wordlists/rockyou.txt
    ```
    *(Adjust IP, secret, and wordlists as necessary. The example IP `172.21.0.3` is a placeholder for where the RADIUS server *should* be in the DMZ.)*
*   **Traffic Capture:**
    *   Start full capture: `./scripts/capture.sh start any my_full_capture.pcap`
    *   Start filtered capture (e.g., HTTP/FTP): `./scripts/capture.sh start eth0 web_traffic.pcap 'port 80 or port 21'`
    *   Stop capture: `./scripts/capture.sh stop`
*   **Analyze Encryption in PCAP:**
    ```bash
    ./scripts/analyze-encryption.sh /captures/my_full_capture.pcap
    ```
    *(Ensure the PCAP file exists in the `/captures` volume of the `pentest-kali` container)*
*   **DDoS Attack Simulation:**
    ```bash
    ./scripts/ddos-attack.sh 172.21.0.2 80 30 http_flood
    ```
*   **Network Discovery:**
    ```bash
    ./scripts/network-discovery.sh
    ```
*   **Vulnerability Scan:**
    ```bash
    ./scripts/vulnerability-scan.sh
    ```
    *(This script has hardcoded internal IPs. Adjust as needed if targeting specific IPs.)*
*   **DNS Security Check:**
    ```bash
    ./scripts/dns-security-check.sh example.com
    ```
    *(Replace `example.com` with a target domain or DNS server IP.)*

### 4.3. Generating Reports

1.  **Run `parse-nmap-to-findings.sh` for Nmap XML results:**
    ```bash
    ./scripts/parse-nmap-to-findings.sh 172.22.0.4  # Example: Parse Nmap results for vulnerable-linux
    # Run for all targets that `network-discovery.sh` or `vulnerability-scan.sh` scanned
    ```
    *(This script will automatically find Nmap XML files in the Kali container's /root/pentest-results directory based on the target IP and convert them to JSON findings in the host's `findings/` directory.)*

2.  **Generate the External Pentest Report:**
    ```bash
    ./scripts/generate-external-report.sh 172.21.0.2 # Example: Generate report focusing on web server IP
    ```
    *(This will create an HTML report in the host's `reports/` directory, aggregating all JSON findings relevant to the specified IP.)*

## 5. Adaptability for Real Targets

The design of the scripts emphasizes adaptability:

*   **Containerized Attacker:** All tools run within the `pentest-kali` container, ensuring a consistent testing environment.
*   **Parameter-Driven:** Scripts accept target IPs, ports, durations, and other configurations as command-line arguments, making them flexible for targeting different systems (virtual or real).
*   **Clear Authorization Warnings:** All offensive scripts include explicit warnings about ethical hacking and requiring authorization.

## 6. Caveats and Known Issues

*   **RADIUS Server Non-Functional:** The `radius-server` container repeatedly fails to start due to FreeRADIUS configuration issues. This prevents effective WPA2-Enterprise testing within the lab currently. Debugging efforts were extensive but unsuccessful given the scope.
*   **Simplified JSON Parsing:** The embedded Python parsers in reporting scripts are designed for the specific JSON format output by the new scripts and `parse-nmap-to-findings.sh`. They may require adjustments if findings JSON schemas change significantly.
*   **DNS Security Check Output:** The `dns-security-check.sh` script currently outputs findings to a text log only. For full integration into the `generate-external-report.sh` HTML, its output would need to be converted to a structured JSON format. This was not implemented in this iteration.
