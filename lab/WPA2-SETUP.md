# WPA2 Enterprise Setup Guide

This guide explains how to configure and test the WPA2 Enterprise authentication in the pentesting lab.

## Overview

The lab includes a FreeRADIUS server configured for WPA2 Enterprise authentication, simulating a school network environment with role-based access control (RBAC).

## Network Configuration

### RADIUS Server
- **IP:** Configured in Docker network (172.21.0.0/24 or 172.22.0.0/24)
- **Ports:** 
  - 1812/udp (Authentication)
  - 1813/udp (Accounting)
  - 18120/udp (Inner Tunnel for PEAP)
- **Secret:** `schoolradius123`

### User Roles and VLANs

| Role | VLAN ID | Network | Access Level |
|------|---------|---------|--------------|
| Admin | 100 | 172.23.0.0/24 | Full network access |
| Faculty | 200 | 172.24.0.0/24 | Restricted access |
| Student | 300 | 172.25.0.0/24 | Limited access |
| Guest | 400 | 172.26.0.0/24 | Isolated network |

## Testing RADIUS Authentication

### Method 1: Using radtest (Command Line)

```bash
# Enter the RADIUS container
docker exec -it pentest-radius /bin/bash

# Install radtest if needed
apt-get update && apt-get install -y freeradius-utils

# Test authentication
radtest student01 Student123! localhost 0 schoolradius123

# Expected output:
# Sending Access-Request of id 123 to 127.0.0.1 port 1812
# User-Name = "student01"
# User-Password = "Student123!"
# NAS-IP-Address = 127.0.0.1
# rad_recv: Access-Accept packet from host 127.0.0.1 port 1812
```

### Method 2: From Kali Container

```bash
# Enter Kali container
docker exec -it pentest-kali /bin/bash

# Install FreeRADIUS utilities
apt-get update
apt-get install -y freeradius-utils

# Test against RADIUS server (replace with actual IP)
radtest student01 Student123! 172.21.0.3 0 schoolradius123
```

### Method 3: Using radclient

```bash
# Create a test file
cat > /tmp/radtest.txt << EOF
User-Name = "student01"
User-Password = "Student123!"
NAS-IP-Address = 127.0.0.1
NAS-Port = 0
EOF

# Send request
radclient -x 172.21.0.3:1812 auth schoolradius123 < /tmp/radtest.txt
```

## Wireless Access Point Configuration

To test with a real wireless client, configure your access point:

### Access Point Settings

1. **SSID:** `SCHOOL-WIFI`
2. **Security:** WPA2-Enterprise
3. **EAP Method:** PEAP-MSCHAPv2 (or EAP-TLS)
4. **RADIUS Server IP:** Your Docker host IP address
5. **RADIUS Port:** 1812
6. **RADIUS Secret:** `schoolradius123`
7. **Certificate Validation:** Disable (for testing) or use generated CA certificate

### Client Connection

1. Connect to `SCHOOL-WIFI` network
2. Select "WPA2-Enterprise" or "PEAP"
3. Enter credentials:
   - **Username:** `student01`
   - **Password:** `Student123!`
4. Accept certificate warning (if using self-signed cert)

## Available Test Accounts

### Admin Accounts
- `admin` / `Admin@2024!` (VLAN 100)
- `it-admin` / `IT@Secure123` (VLAN 100)

### Faculty Accounts
- `teacher01` / `Teacher2024!` (VLAN 200)
- `teacher02` / `Teach@Pass123` (VLAN 200)
- `smith.j` / `Smith2024!` (VLAN 200)

### Student Accounts
- `student01` / `Student123!` (VLAN 300)
- `student02` / `Pass2024!` (VLAN 300)
- `john.doe` / `John2024!` (VLAN 300)
- `jane.smith` / `Jane2024!` (VLAN 300)

### Guest Accounts (Weak Passwords - Vulnerable)
- `guest` / `guest` (VLAN 400)
- `guest01` / `password` (VLAN 400)

## Viewing RADIUS Logs

```bash
# View authentication logs
docker exec -it pentest-radius tail -f /var/log/freeradius/radius.log

# View detailed logs
docker exec -it pentest-radius tail -f /var/log/freeradius/auth.log

# View accounting logs
docker exec -it pentest-radius ls -la /var/log/freeradius/radacct/
```

## Attack Scenarios

### 1. Credential Brute Force

```bash
# Using hydra
hydra -l student01 -P /usr/share/wordlists/rockyou.txt -t 4 172.21.0.3 radius

# Using medusa
medusa -h 172.21.0.3 -u student01 -P /usr/share/wordlists/rockyou.txt -M radius
```

### 2. RADIUS Secret Cracking

```bash
# Capture RADIUS traffic
tcpdump -i any -w radius.pcap port 1812 or port 1813

# Analyze with Wireshark
wireshark radius.pcap

# Look for:
# - RADIUS Access-Request packets
# - Message-Authenticator attributes
# - User-Password attributes (encrypted)
```

### 3. EAP Handshake Capture

```bash
# Capture wireless traffic (requires monitor mode)
airodump-ng -w school-wifi wlan0mon

# Or use hostapd-wpe for rogue AP
# This creates a fake access point to capture credentials
```

### 4. VLAN Hopping

Once authenticated with a guest account, attempt to:
- Access other VLANs through misconfiguration
- Exploit weak guest credentials to escalate to student role
- Use compromised student account to access faculty resources

## Troubleshooting

### RADIUS Server Not Responding

```bash
# Check if RADIUS is running
docker exec -it pentest-radius ps aux | grep freeradius

# Check RADIUS logs for errors
docker exec -it pentest-radius cat /var/log/freeradius/radius.log

# Test locally
docker exec -it pentest-radius radtest student01 Student123! localhost 0 schoolradius123
```

### Certificate Issues

```bash
# Regenerate certificates
docker exec -it pentest-radius bash -c "cd /etc/freeradius/3.0/certs && make clean && make"

# Check certificate validity
docker exec -it pentest-radius openssl x509 -in /etc/freeradius/3.0/certs/server.pem -text -noout
```

### Network Connectivity

```bash
# Test from Kali to RADIUS
docker exec -it pentest-kali ping -c 3 172.21.0.3

# Test RADIUS port
docker exec -it pentest-kali nc -u -v 172.21.0.3 1812
```

## Security Notes

⚠️ **This lab contains intentionally vulnerable configurations:**
- Weak RADIUS secret
- Default client configuration
- Weak guest passwords
- Self-signed certificates

**DO NOT** use these configurations in production environments!

## Additional Resources

- [FreeRADIUS Documentation](https://freeradius.org/documentation/)
- [WPA2 Enterprise Security](https://www.wi-fi.org/discover-wi-fi/security)
- [RADIUS Protocol RFC 2865](https://tools.ietf.org/html/rfc2865)
- [EAP Methods RFC 3748](https://tools.ietf.org/html/rfc3748)
