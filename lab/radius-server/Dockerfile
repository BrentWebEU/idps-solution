FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

# Install FreeRADIUS and dependencies
RUN apt-get update && apt-get install -y \
    freeradius \
    freeradius-utils \
    freeradius-mysql \
    freeradius-ldap \
    openssl \
    net-tools \
    iputils-ping \
    vim \
    && rm -rf /var/lib/apt/lists/*

# Create directories
RUN mkdir -p /etc/freeradius/3.0/certs

# Copy configuration files
COPY radius-config/ /etc/freeradius/3.0/
COPY users /etc/freeradius/3.0/users

# Generate certificates for EAP-TLS (if not provided)
RUN if [ ! -f /etc/freeradius/3.0/certs/server.pem ]; then \
    cd /etc/freeradius/3.0/certs && \
    make ca.pem && \
    make server.pem && \
    make dh; \
    fi

# Set permissions
RUN chown -R freerad:freerad /etc/freeradius/3.0/ \
    && chmod 640 /etc/freeradius/3.0/users \
    && chmod 755 /etc/freeradius/3.0/certs \
    && chmod 600 /etc/freeradius/3.0/certs/*.key 2>/dev/null || true \
    && chmod 644 /etc/freeradius/3.0/certs/*.pem 2>/dev/null || true

EXPOSE 1812/udp 1813/udp 18120/udp

CMD ["freeradius", "-f", "-X"]
