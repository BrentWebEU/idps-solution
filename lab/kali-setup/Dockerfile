FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

# Update package lists
RUN apt-get update

# Install core tools that are definitely available
RUN apt-get install -y \
    nmap \
    curl \
    wget \
    hydra \
    john \
    sqlmap \
    nikto \
    mysql-client \
    ftp \
    smbclient \
    tcpdump \
    python3 \
    python3-pip \
    git \
    vim \
    nano \
    netcat-traditional \
    dnsutils \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Create wordlists directory
RUN mkdir -p /usr/share/wordlists && \
    printf "admin\nroot\nuser\ntest\nguest\nadministrator\n" > /usr/share/wordlists/common_users.txt && \
    printf "password\nPassword123\nadmin\nadmin123\nroot\nroot123\n123456\npassword123\nP@ssw0rd\n" > /usr/share/wordlists/common_passwords.txt

# Create working directories
RUN mkdir -p /root/pentest-results /root/tools

WORKDIR /root

CMD ["/bin/bash"]
