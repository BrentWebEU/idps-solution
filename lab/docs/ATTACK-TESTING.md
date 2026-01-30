# Attack Testing Guide

This guide covers testing DDOS, brute-force, and network infiltration attacks in the lab environment for IDPS rule development and testing.

## ⚠️ WARNING

**These scripts perform real attacks against lab targets. Only use in authorized lab environments!**

## Attack Types

### 1. DDOS Attacks

Simulates various distributed denial-of-service attacks to test IDPS detection capabilities.

#### Available Attack Types

- **SYN Flood**: Rapid SYN packets to exhaust connection tables
- **UDP Flood**: Rapid UDP packets to exhaust resources
- **HTTP Flood**: Rapid HTTP requests to exhaust web server resources
- **Slowloris**: Slow HTTP requests to exhaust connection pools
- **ICMP Flood**: Rapid ICMP echo requests (ping flood)

#### Usage

```bash
cd lab

# Run all DDOS attack types (default: 30 seconds)
./scripts/ddos-attack.sh [target_ip] [port] [duration] [attack_type]

# Examples:
# SYN flood against web server for 60 seconds
./scripts/ddos-attack.sh 172.21.0.2 80 60 syn_flood

# HTTP flood against external target
./scripts/ddos-attack.sh 144.178.248.26 80 45 http_flood

# All attack types against web server
./scripts/ddos-attack.sh 172.21.0.2 80 30 all
```

#### Parameters

- `target_ip`: Target IP address (default: 172.21.0.2)
- `port`: Target port (default: 80)
- `duration`: Attack duration in seconds (default: 30)
- `attack_type`: Type of attack - `syn_flood`, `udp_flood`, `http_flood`, `slowloris`, `icmp_flood`, or `all` (default: all)

#### With Traffic Capture

```bash
# Start capture
./scripts/capture.sh start any "ddos_test_$(date +%Y%m%d_%H%M%S).pcap"

# Run DDOS attack
./scripts/ddos-attack.sh 172.21.0.2 80 60 all

# Stop capture
./scripts/capture.sh stop

# Analyze traffic
./scripts/analyze-pcap.sh ./captures/ddos_test_*.pcap
```

### 2. Brute Force Attacks

Performs comprehensive brute force attacks against various services to test IDPS detection.

#### Available Services

- **SSH**: Brute force SSH authentication
- **FTP**: Brute force FTP authentication
- **SMB**: Brute force SMB authentication
- **MySQL**: Brute force MySQL authentication
- **HTTP**: Brute force HTTP Basic Auth
- **RADIUS**: Brute force RADIUS authentication

#### Usage

```bash
cd lab

# Brute force specific service
./scripts/brute-force-attack.sh [target_ip] [service] [username] [wordlist_size]

# Examples:
# SSH brute force against Linux server
./scripts/brute-force-attack.sh 172.22.0.5 ssh

# FTP brute force with specific username
./scripts/brute-force-attack.sh 172.22.0.4 ftp ftpuser medium

# All services brute force
./scripts/brute-force-attack.sh 172.22.0.5 all
```

#### Parameters

- `target_ip`: Target IP address (default: 172.22.0.5)
- `service`: Service to attack - `ssh`, `ftp`, `smb`, `mysql`, `http`, `radius`, or `all` (default: ssh)
- `username`: Optional specific username to test (default: all from wordlist)
- `wordlist_size`: Wordlist size - `small`, `medium`, or `large` (default: small)

#### Wordlists

- **Small**: 10 common passwords (quick testing)
- **Medium**: 30 common passwords (moderate testing)
- **Large**: RockYou wordlist if available (comprehensive testing)

#### With Traffic Capture

```bash
# Start capture
./scripts/capture.sh start any "bruteforce_test_$(date +%Y%m%d_%H%M%S).pcap"

# Run brute force attack
./scripts/brute-force-attack.sh 172.22.0.5 ssh

# Stop capture
./scripts/capture.sh stop

# Analyze traffic
./scripts/analyze-pcap.sh ./captures/bruteforce_test_*.pcap
```

### 3. Network Infiltration

Simulates advanced persistent threat (APT) and lateral movement attacks.

#### Available Infiltration Types

- **Lateral Movement**: Moving from DMZ to internal network
- **Persistence**: Establishing backdoors and persistence mechanisms
- **Data Exfiltration**: Simulating data theft via various channels
- **Privilege Escalation**: Attempting to gain elevated privileges
- **Command and Control**: Simulating C2 communication

#### Usage

```bash
cd lab

# Run infiltration scenario
./scripts/network-infiltration.sh [initial_target] [infiltration_type]

# Examples:
# Complete infiltration scenario
./scripts/network-infiltration.sh 172.21.0.2 all

# Lateral movement only
./scripts/network-infiltration.sh 172.21.0.2 lateral_movement

# Data exfiltration only
./scripts/network-infiltration.sh 172.21.0.2 data_exfiltration
```

#### Parameters

- `initial_target`: Initial compromised host (default: 172.21.0.2 - web server)
- `infiltration_type`: Type of infiltration - `lateral_movement`, `persistence`, `data_exfiltration`, `privilege_escalation`, `command_control`, or `all` (default: all)

#### Infiltration Phases

1. **Network Mapping**: Discovers network topology and identifies targets
2. **Lateral Movement**: Attempts to move from DMZ to internal network
3. **Persistence**: Establishes backdoors (cron jobs, SSH keys)
4. **Data Exfiltration**: Simulates data theft (HTTP POST, DNS tunneling, FTP)
5. **Privilege Escalation**: Checks for SUID binaries, sudo access, kernel exploits
6. **Command and Control**: Simulates C2 beacons and reverse shells

#### With Traffic Capture

```bash
# Start capture
./scripts/capture.sh start any "infiltration_test_$(date +%Y%m%d_%H%M%S).pcap"

# Run infiltration
./scripts/network-infiltration.sh 172.21.0.2 all

# Stop capture
./scripts/capture.sh stop

# Analyze traffic
./scripts/analyze-pcap.sh ./captures/infiltration_test_*.pcap
```

## Complete Attack Workflow

### Step 1: Start Traffic Capture

```bash
cd lab
./scripts/capture.sh start any "attack_test_$(date +%Y%m%d_%H%M%S).pcap"
```

### Step 2: Run Attacks

```bash
# DDOS attack
./scripts/ddos-attack.sh 172.21.0.2 80 60 all

# Brute force attack
./scripts/brute-force-attack.sh 172.22.0.5 ssh

# Network infiltration
./scripts/network-infiltration.sh 172.21.0.2 all
```

### Step 3: Stop Capture

```bash
./scripts/capture.sh stop
```

### Step 4: Analyze Traffic

```bash
# Analyze PCAP file
./scripts/analyze-pcap.sh ./captures/attack_test_*.pcap

# Upload to IDPS API for analysis
curl -X POST -F "pcap_file=@./captures/attack_test_*.pcap" http://localhost:8080/api/pcap/analyze
```

### Step 5: Generate IDPS Rules

```bash
# Generate rules from findings
curl -X POST http://localhost:8080/api/rules/generate \
  -H "Content-Type: application/json" \
  -d '{"finding_type": "brute_force", "target_ip": "172.22.0.5", "port": 22}'

# Activate rules
curl -X POST http://localhost:8080/api/rules/activate \
  -H "Content-Type: application/json" \
  -d '{"rule_file": "brute-force.rules"}'
```

## Attack Patterns for IDPS Detection

### DDOS Detection Patterns

- **SYN Flood**: High rate of SYN packets without ACK responses
- **UDP Flood**: High rate of UDP packets to random ports
- **HTTP Flood**: High rate of HTTP GET requests from single/multiple sources
- **Slowloris**: Slow HTTP requests keeping connections open
- **ICMP Flood**: High rate of ICMP echo requests

### Brute Force Detection Patterns

- **Multiple Failed Logins**: Repeated authentication failures from same source
- **Rapid Login Attempts**: High frequency of authentication attempts
- **Common Password Attempts**: Use of common password lists
- **Multiple Username Attempts**: Testing multiple usernames against single password

### Network Infiltration Detection Patterns

- **Lateral Movement**: Unusual connections between network segments
- **Persistence**: Scheduled tasks, SSH keys, backdoor processes
- **Data Exfiltration**: Large outbound transfers, DNS tunneling, unusual protocols
- **Privilege Escalation**: Exploit attempts, SUID binary execution
- **C2 Communication**: Regular beacons, reverse shell connections, unusual DNS queries

## IDPS Rule Generation

After running attacks and analyzing traffic, generate IDPS rules:

### Example: Brute Force Detection Rule

```bash
# Analyze PCAP with brute force traffic
curl -X POST -F "pcap_file=@./captures/bruteforce_test.pcap" \
  http://localhost:8080/api/pcap/analyze

# Generate rule from findings
curl -X POST http://localhost:8080/api/rules/generate \
  -H "Content-Type: application/json" \
  -d '{
    "finding_type": "brute_force",
    "target_ip": "172.22.0.5",
    "port": 22,
    "source_ip": "172.20.0.2",
    "count": 50,
    "time_window": 60
  }'
```

### Example: DDOS Detection Rule

```bash
# Generate SYN flood detection rule
curl -X POST http://localhost:8080/api/rules/generate \
  -H "Content-Type: application/json" \
  -d '{
    "finding_type": "ddos",
    "attack_type": "syn_flood",
    "target_ip": "172.21.0.2",
    "port": 80,
    "threshold": 1000,
    "time_window": 10
  }'
```

## Testing IDPS Detection

### Test Rule Effectiveness

```bash
# Test rules against PCAP
curl -X POST http://localhost:8080/api/rules/test \
  -H "Content-Type: application/json" \
  -d '{
    "pcap_file": "./captures/attack_test.pcap",
    "rule_file": "brute-force.rules"
  }'
```

### Verify Detection

1. Run attack with traffic capture
2. Analyze PCAP file
3. Generate IDPS rules
4. Activate rules
5. Replay attack traffic
6. Check IDPS logs for alerts

## Lab Targets

### DMZ Network (172.21.0.0/24)

- **Web Server**: 172.21.0.2:80 (HTTP)
- **RADIUS Server**: 172.21.0.3:1812/1813 (UDP)

### Internal Network (172.22.0.0/24)

- **MySQL Database**: 172.22.0.3:3306
- **File Server**: 172.22.0.4:21 (FTP), 445 (SMB)
- **Linux Server**: 172.22.0.5:22 (SSH)

### Attacker Network (172.20.0.0/24)

- **Kali Linux**: 172.20.0.2

## Best Practices

1. **Always capture traffic** when running attacks for analysis
2. **Use appropriate durations** - start with short attacks (30s) for testing
3. **Document attack parameters** for reproducibility
4. **Analyze PCAP files** before generating rules
5. **Test rules** against known attack traffic
6. **Review IDPS logs** to verify detection
7. **Iterate** on rules based on false positives/negatives

## Troubleshooting

### Attack Not Working

- Check target is accessible: `docker exec pentest-kali ping -c 1 <target_ip>`
- Verify service is running: `docker exec pentest-kali nmap -p <port> <target_ip>`
- Check firewall rules in docker-compose.yml

### No Traffic Captured

- Verify capture is running: `docker exec pentest-capture pgrep tcpdump`
- Check capture filters in capture.sh
- Verify network configuration

### IDPS Not Detecting

- Check rules are activated: `curl http://localhost:8080/api/rules/list`
- Verify rule syntax: Check Suricata logs
- Test with known attack patterns first

## References

- [Suricata Rule Writing](https://suricata.readthedocs.io/en/latest/rules/intro.html)
- [Nmap Documentation](https://nmap.org/book/)
- [Hydra Documentation](https://github.com/vanhauser-thc/thc-hydra)
