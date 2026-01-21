# Stage 1: Build the application
FROM rust:1.73 as builder

WORKDIR /usr/src/app

# Copy the Cargo.toml and Cargo.lock files
COPY Cargo.toml Cargo.lock ./

# Create a dummy main.rs to cache dependencies
RUN mkdir -p src && echo "fn main() {}" > src/main.rs

# Build dependencies
RUN cargo build --release
RUN rm -f target/release/deps/idps_api*

# Copy the actual source code
COPY src/main.rs ./src/

# Build the application
RUN cargo build --release

# Stage 2: Create the final image
FROM debian:buster-slim

# Copy the binary from the builder stage
COPY --from=builder /usr/src/app/target/release/idps-api /usr/local/bin/idps-api

# Set the command to run the application
CMD ["idps-api"]
