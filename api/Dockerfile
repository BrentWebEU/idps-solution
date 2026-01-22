# Stage 1: Build the application
FROM rust:1.92 AS builder

WORKDIR /usr/src/app

# Copy the Cargo.toml and Cargo.lock files
COPY Cargo.toml Cargo.lock ./

# Create a dummy main.rs to cache dependencies
RUN mkdir -p src && echo "fn main() {}" > src/main.rs

# Build dependencies
RUN cargo build --release
RUN rm -f target/release/deps/idps_api*

# Copy the actual source code
COPY src ./src/

# Build the actual application
RUN cargo build --release

# Stage 2: Create the final image
FROM debian:bookworm-slim

# Install runtime dependencies for Actix
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

# Copy the binary from the builder stage
COPY --from=builder /usr/src/app/target/release/idps-api /usr/local/bin/idps-api

# Expose port
EXPOSE 8080

# Ensure the application listens on localhost only
ENV LISTEN_ADDRESS=127.0.0.1

# Set environment variable (default to prod)
ENV APP_ENV=prod

# Set the command to run the application
CMD ["/usr/local/bin/idps-api"]
