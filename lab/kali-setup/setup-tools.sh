#!/bin/bash
# Kali Linux Tools Installation Script
# Run this inside the Kali container to install pentesting tools

echo "============================================"
echo "  Kali Linux Pentesting Tools Setup"
echo "============================================"
echo ""

# Update package lists
echo "[1/3] Updating package lists..."
apt-get update > /dev/null 2>&1

# Install essential pentesting tools
echo "[2/3] Installing pentesting tools..."
apt-get install -y \
    nmap \
    hydra \
    john \
    sqlmap \
    nikto \
    dirb \
    gobuster \
    wfuzz \
    curl \
    wget \
    netcat-traditional \
    dnsutils \
    iputils-ping \
    ftp \
    lftp \
    smbclient \
    tcpdump \
    wireshark-common \
    tshark \
    python3 \
    python3-pip \
    git \
    vim \
    nano \
    tree \
    jq \
    whatweb \
    enum4linux \
    default-mysql-client \
    postgresql-client \
    redis-tools \
    > /dev/null 2>&1

# Create wordlists
echo "[3/3] Creating custom wordlists..."
mkdir -p /usr/share/wordlists

# Common usernames
cat > /usr/share/wordlists/common_users.txt << 'EOF'
admin
root
user
test
guest
administrator
Admin
Administrator
sa
sysadmin
webadmin
backup
support
developer
postgres
mysql
oracle
tomcat
jenkins
EOF

# Common passwords
cat > /usr/share/wordlists/common_passwords.txt << 'EOF'
password
Password123
admin
admin123
root
root123
123456
password123
P@ssw0rd
Admin@123
Password1
Welcome123
qwerty
letmein
monkey
dragon
master
sunshine
princess
football
shadow
EOF

# Common credential pairs
cat > /usr/share/wordlists/common_creds.txt << 'EOF'
admin:admin
root:root
admin:password
admin:admin123
root:root123
user:password
guest:guest
test:test
sa:sa
postgres:postgres
mysql:mysql
EOF

# Create working directories
mkdir -p /root/pentest-results
mkdir -p /root/tools

echo ""
echo "============================================"
echo "  ✅ Setup Complete!"
echo "============================================"
echo ""
echo "Installed Tools:"
which nmap hydra john sqlmap nikto mysql ftp smbclient tcpdump 2>/dev/null | sed 's/^/  - /'
echo ""
echo "Wordlists available in: /usr/share/wordlists/"
ls -1 /usr/share/wordlists/ 2>/dev/null | sed 's/^/  - /'
echo ""
echo "Ready for pentesting!"
echo "============================================"
