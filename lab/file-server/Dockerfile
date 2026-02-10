FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

# Install FTP and SMB services
RUN apt-get update && apt-get install -y \
    vsftpd \
    samba \
    openssh-server \
    net-tools \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Configure FTP
RUN echo "anonymous_enable=YES\n\
local_enable=YES\n\
write_enable=YES\n\
local_umask=022\n\
dirmessage_enable=YES\n\
use_localtime=YES\n\
xferlog_enable=YES\n\
connect_from_port_20=YES\n\
chroot_local_user=YES\n\
allow_writeable_chroot=YES\n\
secure_chroot_dir=/var/run/vsftpd/empty\n\
pam_service_name=vsftpd\n\
rsa_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem\n\
rsa_private_key_file=/etc/ssl/private/ssl-cert-snakeoil.key\n\
ssl_enable=NO" > /etc/vsftpd.conf

# Create FTP user with weak password
RUN useradd -m -s /bin/bash ftpuser && \
    echo "ftpuser:password123" | chpasswd && \
    mkdir -p /shared/ftp && \
    chown ftpuser:ftpuser /shared/ftp

# Configure Samba with weak security
RUN echo "[shared]\n\
   comment = Shared Files\n\
   path = /shared\n\
   browseable = yes\n\
   writable = yes\n\
   guest ok = yes\n\
   guest only = no\n\
   read only = no\n\
   create mask = 0777\n\
   directory mask = 0777" > /etc/samba/smb.conf

# Create SMB user
RUN useradd -m -s /bin/bash smbuser && \
    printf "smbuser\nsmbuser\n" | smbpasswd -a -s smbuser

# Create shared directory
RUN mkdir -p /shared && \
    chmod 777 /shared && \
    echo "FLAG{SMB_Access_Granted}" > /shared/flag.txt && \
    echo "Sensitive data file" > /shared/confidential.txt

# Create startup script
RUN echo '#!/bin/bash\n\
service vsftpd start\n\
service smbd start\n\
service nmbd start\n\
tail -f /dev/null' > /start.sh && \
    chmod +x /start.sh

EXPOSE 21 445 139

CMD ["/start.sh"]
