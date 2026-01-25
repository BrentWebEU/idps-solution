# Docker Network Pentesting Lab

A comprehensive Docker-based network pentesting lab for simulating real-world attack scenarios. This lab includes multiple vulnerable services across different network segments to practice penetration testing techniques.

## Network Topology

```
┌─────────────────────────────────────────────────────────┐
│                    Attacker Network                     │
│                     172.20.0.0/24                      │
│                                                         │
│  ┌──────────────┐                                      │
│  │  Kali Linux  │                                      │
│  │  (Attacker)  │                                      │
│  └──────────────┘                                      │
└─────────────────────────────────────────────────────────┘
                        │
                        │ Gateway
                        │
┌─────────────────────────────────────────────────────────┐
│                      DMZ Network                       │
│                     172.21.0.0/24                      │
│                                                         │
│  ┌──────────────┐  ┌──────────────┐                   │
│  │ Web Server   │  │ RADIUS Server │                   │
│  │  (Apache)    │  │ (WPA2 Ent.)   │                   │
│  │ Port 8080    │  │ Ports 1812/13 │                   │
│  └──────────────┘  └──────────────┘                   │
└─────────────────────────────────────────────────────────┘
                        │
                        │ Internal Gateway
                        │
┌─────────────────────────────────────────────────────────┐
│                    Internal Network                     │
│                     172.22.0.0/24                      │
│                                                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │   Database   │  │ File Server  │  │   Linux     │ │
│  │   (MySQL)    │  │  (FTP/SMB)   │  │   (SSH)     │ │
│  │  Port 3306   │  │ Ports 21/445 │  │  Port 22    │ │
│  └──────────────┘  └──────────────┘  └──────────────┘ │
└─────────────────────────────────────────────────────────┘

WPA2 Enterprise Network Segmentation:
  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
  │ Admin VLAN   │  │ Faculty VLAN │  │ Student VLAN │
  │ 172.23.0.0/24│  │ 172.24.0.0/24│  │ 172.25.0.0/24│
  └──────────────┘  └──────────────┘  └──────────────┘
  ┌──────────────┐
  │  Guest VLAN  │
  │ 172.26.0.0/24│
  └──────────────┘
```

## Services and Vulnerabilities

### 0. WPA2 Enterprise RADIUS Server (DMZ)
- **Service:** FreeRADIUS 3.0
- **Ports:** 1812/udp (Authentication), 1813/udp (Accounting), 18120/udp (Inner Tunnel)
- **Network:** DMZ (172.21.0.0/24) + Internal (172.22.0.0/24)
- **Authentication Methods:** PEAP-MSCHAPv2, EAP-TLS
- **Vulnerabilities:**
  - Weak RADIUS secret: `schoolradius123`
  - Default client configuration allows connections from any IP
  - Guest accounts with weak passwords
  - Role-based VLAN assignment (can be exploited for privilege escalation)
- **User Roles & VLAN Assignment:**
  - **Admin (VLAN 100):** Full network access
  - **Faculty (VLAN 200):** Restricted access
  - **Student (VLAN 300):** Limited access
  - **Guest (VLAN 400):** Isolated network

### 1. Web Server (DMZ)
- **Service:** Apache HTTP Server 2.4.41
- **Port:** 8080 (HTTP)
- **Network:** DMZ (172.21.0.0/24) + Internal (172.22.0.0/24)
- **Vulnerabilities:**
  - Information disclosure
  - Potential for directory traversal
  - Access to internal network

### 2. Database Server (Internal)
- **Service:** MySQL 5.7
- **Port:** 3306 (exposed)
- **Network:** Internal (172.22.0.0/24)
- **Vulnerabilities:**
  - Weak root password: `root`
  - Weak user credentials: `admin:admin123`
  - Exposed to network
  - Old MySQL version

### 3. File Server (Internal)
- **Services:** vsftpd (FTP), Samba (SMB)
- **Ports:** 21 (FTP), 445 (SMB), 139 (NetBIOS)
- **Network:** Internal (172.22.0.0/24)
- **Vulnerabilities:**
  - Anonymous FTP access enabled
  - Weak FTP credentials: `ftpuser:password123`
  - Weak SMB credentials: `smbuser:smbuser`
  - World-writable shares
  - Sensitive files in shared directory

### 4. Vulnerable Linux System (Internal)
- **Service:** OpenSSH Server
- **Port:** 22 (SSH)
- **Network:** Internal (172.22.0.0/24)
- **Vulnerabilities:**
  - Weak passwords for multiple users:
    - `root:root123`
    - `admin:admin123`
    - `user:password`
    - `guest:guest`
  - Root login enabled
  - Passwordless sudo for admin user
  - Sensitive files with credentials

## Quick Start

### Prerequisites
- Docker
- Docker Compose

### Starting the Lab

```bash
# Start all services
docker-compose up -d

# View running containers
docker-compose ps

# View logs
docker-compose logs -f
```

### Accessing Services

- **Web Server:** http://localhost:8080
- **RADIUS Server:** localhost:1812/udp, 1813/udp
- **MySQL:** localhost:3306
- **FTP:** localhost:21
- **SMB:** localhost:445
- **SSH:** localhost:22

### Accessing Kali Linux (Attacker)

```bash
# Enter Kali container
docker exec -it pentest-kali /bin/bash

# Install tools (if needed)
apt-get update
apt-get install -y nmap metasploit-framework sqlmap hydra john wireshark tcpdump
```

## Attack Scenarios

### Scenario 0: WPA2 Enterprise Authentication Testing
```bash
# Test RADIUS authentication
radtest student01 Student123! localhost:1812 0 schoolradius123

# Test with different user roles
radtest admin Admin@2024! localhost:1812 0 schoolradius123
radtest teacher01 Teacher2024! localhost:1812 0 schoolradius123
radtest guest guest localhost:1812 0 schoolradius123

# Brute force RADIUS credentials
# Install radclient if needed
apt-get install freeradius-utils

# Test weak guest credentials
radtest guest guest localhost:1812 0 schoolradius123
radtest guest01 password localhost:1812 0 schoolradius123

# Capture and analyze RADIUS traffic
tcpdump -i any -w radius_capture.pcap port 1812 or port 1813

# Test EAP authentication (requires wireless client simulation)
# Use tools like hostapd-wpe or create rogue access point
```

### Scenario 1: Network Discovery
```bash
# From Kali container
nmap -sn 172.21.0.0/24  # Scan DMZ
nmap -sn 172.22.0.0/24  # Scan Internal Network
nmap -p- 172.21.0.2     # Port scan web server
```

### Scenario 2: Database Enumeration
```bash
# Attempt MySQL connection
mysql -h 172.22.0.3 -u root -p
# Password: root

# Or with admin user
mysql -h 172.22.0.3 -u admin -p
# Password: admin123
```

### Scenario 3: FTP/SMB Access
```bash
# FTP anonymous access
ftp 172.22.0.4
# Username: anonymous
# Password: (empty or anonymous)

# FTP with credentials
ftp 172.22.0.4
# Username: ftpuser
# Password: password123

# SMB access
smbclient //172.22.0.4/shared -U smbuser
# Password: smbuser
```

### Scenario 4: SSH Brute Force
```bash
# Attempt SSH login
ssh admin@172.22.0.5
# Password: admin123

# Or use hydra for brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt 172.22.0.5 ssh
```

### Scenario 5: Lateral Movement
1. Gain initial access via web server or FTP
2. Enumerate internal network
3. Access database from internal network
4. Escalate privileges on Linux system
5. Capture flags from each system

## Network Information

### IP Addresses (may vary)
- **Kali:** 172.20.0.2
- **Web Server:** 172.21.0.2 (DMZ), 172.22.0.2 (Internal)
- **RADIUS Server:** 172.21.0.3 (DMZ), 172.22.0.3 (Internal)
- **Database:** 172.22.0.4
- **File Server:** 172.22.0.5
- **Vulnerable Linux:** 172.22.0.6
- **Gateway:** Multiple interfaces

### Credentials Summary

#### WPA2 Enterprise (RADIUS) Accounts

| Role | Username | Password | VLAN |
|------|----------|----------|------|
| Admin | admin | Admin@2024! | 100 |
| Admin | it-admin | IT@Secure123 | 100 |
| Faculty | teacher01 | Teacher2024! | 200 |
| Faculty | teacher02 | Teach@Pass123 | 200 |
| Faculty | smith.j | Smith2024! | 200 |
| Student | student01 | Student123! | 300 |
| Student | student02 | Pass2024! | 300 |
| Student | john.doe | John2024! | 300 |
| Student | jane.smith | Jane2024! | 300 |
| Guest | guest | guest | 400 |
| Guest | guest01 | password | 400 |

**RADIUS Secret:** `schoolradius123`

#### Other Services

| Service | Username | Password |
|---------|----------|----------|
| MySQL Root | root | root |
| MySQL User | admin | admin123 |
| FTP User | ftpuser | password123 |
| FTP Anonymous | anonymous | (empty) |
| SMB User | smbuser | smbuser |
| SSH Root | root | root123 |
| SSH Admin | admin | admin123 |
| SSH User | user | password |
| SSH Guest | guest | guest |

## Flags

Each service contains flag files:
- **File Server:** `/shared/flag.txt` - `FLAG{SMB_Access_Granted}`
- **Linux Admin:** `/home/admin/flag.txt` - `FLAG{SSH_Access_Obtained}`
- **Linux Root:** `/root/root_flag.txt` - `FLAG{Root_Access_Achieved}`

## Stopping the Lab

```bash
# Stop all services
docker-compose down

# Stop and remove volumes (clean slate)
docker-compose down -v
```

## Security Warning

⚠️ **WARNING:** This lab contains intentionally vulnerable services with weak passwords and misconfigurations. **DO NOT** deploy this in a production environment or expose it to the internet. This is for educational and authorized testing purposes only.

## Learning Objectives

- **WPA2 Enterprise Security:**
  - RADIUS authentication testing
  - EAP method enumeration (PEAP, EAP-TLS)
  - Role-based access control (RBAC) exploitation
  - VLAN hopping through credential compromise
  - RADIUS packet analysis and manipulation
- **Network Security:**
  - Network reconnaissance and enumeration
  - Service identification and version detection
  - Credential-based attacks
  - Lateral movement techniques
  - Privilege escalation
  - Network segmentation bypass
  - Post-exploitation activities

## Troubleshooting

### Services not starting
```bash
# Check logs
docker-compose logs [service-name]

# Restart specific service
docker-compose restart [service-name]
```

### Network connectivity issues
```bash
# Verify networks
docker network ls
docker network inspect lab_dmz-net
docker network inspect lab_internal-net
```

### Permission issues
```bash
# Rebuild containers
docker-compose down
docker-compose up -d --build
```

## WPA2 Enterprise Configuration

### School Network Setup

The lab simulates a school network with WPA2 Enterprise authentication:

1. **SSID:** `SCHOOL-WIFI` (configured on your wireless access point)
2. **Security:** WPA2-Enterprise
3. **EAP Method:** PEAP-MSCHAPv2 (or EAP-TLS)
4. **RADIUS Server:** Configure your AP to point to `localhost:1812`
5. **RADIUS Secret:** `schoolradius123`

### Connecting to the Network

1. **Configure Access Point:**
   - Set SSID to `SCHOOL-WIFI`
   - Enable WPA2-Enterprise
   - Set RADIUS server IP to your Docker host IP
   - Set RADIUS port to `1812`
   - Set RADIUS secret to `schoolradius123`

2. **Connect from Client:**
   - Select `SCHOOL-WIFI` network
   - Choose PEAP authentication
   - Enter username (e.g., `student01`)
   - Enter password (e.g., `Student123!`)
   - Accept certificate (if prompted)

### Testing RADIUS Authentication

```bash
# Install FreeRADIUS utilities in Kali
apt-get install freeradius-utils

# Test authentication
radtest student01 Student123! <RADIUS_IP> 0 schoolradius123

# View RADIUS logs
docker exec -it pentest-radius tail -f /var/log/freeradius/radius.log
```

### Attack Scenarios

1. **Credential Harvesting:**
   - Set up rogue access point
   - Capture EAP handshakes
   - Attempt offline password cracking

2. **VLAN Hopping:**
   - Compromise guest account
   - Attempt to access admin VLAN through misconfiguration
   - Exploit weak guest credentials to gain student access

3. **RADIUS Protocol Attacks:**
   - Test for RADIUS authentication bypass
   - Attempt to crack RADIUS secret
   - Analyze RADIUS traffic for information disclosure

## Additional Resources

- Practice using tools like: `nmap`, `metasploit`, `sqlmap`, `hydra`, `john`, `wireshark`, `radclient`, `hostapd-wpe`
- Document your findings and create a penetration test report
- Try to achieve full network compromise starting from the DMZ
- Practice wireless security testing with WPA2 Enterprise