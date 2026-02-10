# Interactive Lab Menu

The **lab menu** (`./scripts/lab-menu.sh`) is the main entry point to choose **what** to run, **where** (targets/IPs), and **how** (with capture, reports, etc.) in the pentest lab. It connects to all existing scripts and prompts for options when needed.

## Usage

```bash
cd lab
./scripts/lab-menu.sh
```

## Main Menu

| Option | Description |
|--------|-------------|
| **1) Internal Lab Pentest** | Automated discovery, vuln scan, credential testing, exploitation (full or individual phases). |
| **2) External Pentest** | Scan and test an external IP; optional full workflow with capture and report. |
| **3) Attack Testing** | DDOS, Brute-Force, or Network Infiltration; you choose target IP and options. |
| **4) Traffic Capture** | Start, stop, or check status of packet capture. |
| **5) Analysis & Reporting** | Analyze PCAP, extract findings from Nmap XML, generate internal/external reports or vulnerability summary. |
| **6) Run Full Attack Suite** | DDOS + Brute-Force + Infiltration with capture and report (with IP prompts). |
| **0) Exit** | Quit the menu. |

## Sub-menus and Scripts Used

### 1) Internal Lab Pentest

- **Full automated pentest** → `automated-pentest.sh`
- **Network discovery only** → `network-discovery.sh`
- **Vulnerability scan only** → `vulnerability-scan.sh`
- **Credential testing only** → `credential-testing.sh`
- **Exploitation only** → `exploitation.sh`
- **Full workflow with capture and report** → `run-pentest.sh`

### 2) External Pentest

- **External pentest only** → `external-pentest.sh <ip>` (IP prompted)
- **Full external workflow** → `run-external-pentest.sh <ip>` (IP prompted)

### 3) Attack Testing

- **DDOS** → Target IP, port, duration, attack type (syn_flood, udp_flood, http_flood, slowloris, icmp_flood, all). Optional capture before/after. → `ddos-attack.sh`
- **Brute force** → Target IP, service (ssh, ftp, smb, mysql, http, radius, all), optional username, wordlist size. Optional capture. → `brute-force-attack.sh`
- **Network infiltration** → Initial target IP, type (lateral_movement, persistence, data_exfiltration, privilege_escalation, command_control, all). Optional capture. → `network-infiltration.sh`
- **Run all attacks** → Full suite with its own IP prompts and capture. → `run-all-attacks.sh`

### 4) Traffic Capture

- **Start** → Prompts for output filename. → `capture.sh start any <file>`
- **Stop** → `capture.sh stop`
- **Status** → `capture.sh status`

### 5) Analysis & Reporting

- **Analyze PCAP** → Prompts for PCAP path. → `analyze-pcap.sh`
- **Extract findings from Nmap XML** → Prompts for target IP. → `parse-nmap-to-findings.sh <ip>`
- **Generate internal report** → `generate-report.sh`
- **Generate external report** → Prompts for target IP. → `generate-external-report.sh <ip>`
- **Generate vulnerability summary** → `generate-vulnerability-summary.sh`

### 6) Run Full Attack Suite

Runs `run-all-attacks.sh`, which prompts for web/linux/db/ftp IPs and DDOS duration, then runs DDOS, brute-force, and infiltration with capture, analysis, and report.

## Default Targets

When you press Enter at an IP prompt, the menu uses these defaults:

- **Web (DMZ):** 172.21.0.2  
- **RADIUS:** 172.21.0.3  
- **Database:** 172.22.0.3  
- **File server:** 172.22.0.4  
- **Linux (Internal):** 172.22.0.5  
- **External:** 144.178.248.26  

You can type a different IP anytime. IPs are validated (basic x.x.x.x format).

## Requirements

- Lab running: `docker-compose up -d`
- The menu checks for `pentest-kali` before running internal pentests or attack tests.

All actions are performed by the existing scripts under `lab/scripts/`; the menu only gathers your choices and invokes them with the right arguments.
