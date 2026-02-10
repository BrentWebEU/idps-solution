FROM rust:1.88-slim

WORKDIR /app

# Install dependencies
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy manifest files
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src ./src

# Build the application
RUN cargo build --release

# Expose API port
EXPOSE 8080

# Run the application
CMD ["./target/release/raspi-rust"]
