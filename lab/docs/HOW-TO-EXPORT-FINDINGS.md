# How to Export Findings to HTML Reports

## Problem
Findings are not appearing in HTML reports because they need to be extracted from Nmap XML files first.

## Solution

The external pentest saves results as **Nmap XML files** in the Kali container, but the HTML report generator reads **JSON findings files**. You need to extract findings from the XML files first.

## Complete Workflow

### Step 1: Run External Pentest
```bash
cd lab
./scripts/external-pentest.sh 94.130.75.252
```

This creates Nmap XML files in the Kali container at `/root/pentest-results/external_*_94.130.75.252_*.xml`

### Step 2: Extract Findings from XML Files
```bash
./scripts/parse-nmap-to-findings.sh 94.130.75.252
```

This script:
- Finds all Nmap XML files for the target IP in the Kali container
- Parses them to extract open ports, services, and vulnerabilities
- Creates a JSON findings file: `findings/findings_94_130_75_252_*.json`

### Step 3: Generate HTML Report
```bash
./scripts/generate-external-report.sh 94.130.75.252
```

The report will now include all findings from the JSON file!

## Quick Workflow (All-in-One)

Use the complete workflow script:
```bash
./scripts/run-external-pentest.sh 94.130.75.252
```

This automatically:
1. Starts traffic capture
2. Runs the pentest
3. Stops capture
4. Analyzes PCAP
5. **Extracts findings from XML files**
6. Generates HTML report

## Manual Extraction

If you need to extract findings manually:

```bash
# List XML files in Kali container
docker exec -it pentest-kali ls -la /root/pentest-results/external_*

# Extract findings from specific XML file
./scripts/parse-nmap-to-findings.sh 94.130.75.252 /path/to/nmap-results.xml

# Or extract from all XML files for the target
./scripts/parse-nmap-to-findings.sh 94.130.75.252
```

## What Gets Extracted

The extraction script parses:
- **Open ports** - Ports, protocols, and services
- **Service versions** - Product and version information
- **Vulnerabilities** - CVE IDs and vulnerability information
- **Service information** - HTTP titles, SSL certificates, SSH hostkeys

## Findings JSON Format

The extracted findings follow this structure:
```json
{
  "target_ip": "94.130.75.252",
  "findings": [
    {
      "finding_type": "open_port",
      "severity": "medium",
      "port": 80,
      "service": "http",
      "description": "Open port 80 (http) detected"
    }
  ],
  "summary": {
    "total_findings": 1,
    "open_ports": 1,
    "vulnerabilities": 0
  }
}
```

## Troubleshooting

### No findings in HTML report?

1. **Check if XML files exist:**
   ```bash
   docker exec -it pentest-kali ls -la /root/pentest-results/external_*
   ```

2. **Extract findings:**
   ```bash
   ./scripts/parse-nmap-to-findings.sh 94.130.75.252
   ```

3. **Check findings JSON was created:**
   ```bash
   ls -la findings/findings_94_130_75_252_*.json
   ```

4. **Regenerate report:**
   ```bash
   ./scripts/generate-external-report.sh 94.130.75.252
   ```

### Python3 not found?

Install Python3:
```bash
# macOS
brew install python3

# Linux
apt-get install python3
```

### XML files not found?

Make sure you've run the external pentest:
```bash
./scripts/external-pentest.sh 94.130.75.252
```

## Example Output

After extraction, you'll see:
```
✓ Extracted 15 findings
✓ Open ports: 8
✓ Vulnerabilities: 2
✓ Output: findings/findings_94_130_75_252_20260127_160913.json
```

Then when generating the report:
```
Findings files processed: 1
Findings HTML generated: Yes
```

The HTML report will show all findings with:
- Color-coded severity (red=high, orange=medium, green=low)
- Detailed descriptions
- Port and service information
- Vulnerability details
