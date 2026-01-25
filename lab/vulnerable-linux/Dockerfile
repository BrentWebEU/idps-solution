FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

# Install SSH and other services
RUN apt-get update && apt-get install -y \
    openssh-server \
    sudo \
    net-tools \
    iputils-ping \
    curl \
    wget \
    vim \
    && rm -rf /var/lib/apt/lists/*

# Configure SSH with weak settings
RUN mkdir /var/run/sshd && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Create vulnerable users with weak passwords
RUN useradd -m -s /bin/bash admin && \
    echo "admin:admin123" | chpasswd && \
    usermod -aG sudo admin && \
    useradd -m -s /bin/bash user && \
    echo "user:password" | chpasswd && \
    useradd -m -s /bin/bash guest && \
    echo "guest:guest" | chpasswd

# Set root password
RUN echo "root:root123" | chpasswd

# Create flag files
RUN mkdir -p /home/admin && \
    echo "FLAG{SSH_Access_Obtained}" > /home/admin/flag.txt && \
    chown admin:admin /home/admin/flag.txt && \
    mkdir -p /root && \
    echo "FLAG{Root_Access_Achieved}" > /root/root_flag.txt

# Create some sensitive files
RUN echo "Database credentials: admin:admin123" > /home/admin/notes.txt && \
    echo "API Key: sk_live_1234567890abcdef" >> /home/admin/notes.txt && \
    chown admin:admin /home/admin/notes.txt

# Allow passwordless sudo for admin (misconfiguration)
RUN echo "admin ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

# Start SSH
RUN mkdir -p /var/run/sshd

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D"]
