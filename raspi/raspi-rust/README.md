# Raspi Rust API - Suricata Log Access

## Overview
This Rust API provides access to Suricata IDS logs through a simple HTTP interface.

## Shared Storage Configuration
The API shares the `/var/log/suricata` directory with the Suricata container via Docker volumes:
- **Host**: `./logs` (in the ids-pi directory)
- **Containers**: `/var/log/suricata` (mounted in both Suricata and API containers)

## API Endpoints

### `GET /`
Health check endpoint
- **Response**: Simple text message

### `GET /logs`
Lists all available log files in the Suricata log directory
- **Response**: JSON array of filenames

### `GET /logs/{filename}`
Retrieves the content of a specific log file
- **Parameters**: `filename` - name of the log file
- **Response**: Plain text content of the log file

## Running with Docker Compose

From the `ids-pi` directory:
```bash
docker-compose up -d
```

The API will be available at `http://localhost:8080`

## Example Usage

```bash
# List all log files
curl http://localhost:8080/logs

# Read a specific log file
curl http://localhost:8080/logs/eve.json
```
