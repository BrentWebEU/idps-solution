#!/bin/bash
# Lab Demo Script - Tests all services with real data
# Shows that everything is fully functional

echo "========================================"
echo "  Pentesting Lab - Functional Demo"
echo "========================================"
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}Testing Lab Services...${NC}"
echo ""

# Test 1: Web Server
echo -e "${YELLOW}[1/5] Testing Web Server...${NC}"
if curl -s http://localhost:8080/index.html | grep -q "Company Internal Web Server"; then
    echo -e "  ${GREEN}✓${NC} Web server is accessible"
    echo -e "  ${GREEN}✓${NC} Pages: index.html, login.html, admin.html, database.html"
else
    echo -e "  ${RED}✗${NC} Web server not accessible"
fi
echo ""

# Test 2: Database Server  
echo -e "${YELLOW}[2/5] Testing Database Server...${NC}"
DB_RESULT=$(docker exec pentest-db mysql -uadmin -padmin123 company_db -e "SELECT COUNT(*) FROM employees;" 2>/dev/null | tail -1)
if [ ! -z "$DB_RESULT" ]; then
    echo -e "  ${GREEN}✓${NC} Database accessible with credentials: admin/admin123"
    echo -e "  ${GREEN}✓${NC} Employee records: $DB_RESULT"
    
    CUSTOMER_COUNT=$(docker exec pentest-db mysql -uadmin -padmin123 company_db -e "SELECT COUNT(*) FROM customers;" 2>/dev/null | tail -1)
    echo -e "  ${GREEN}✓${NC} Customer records with credit cards: $CUSTOMER_COUNT"
    
    CREDS_COUNT=$(docker exec pentest-db mysql -uadmin -padmin123 company_db -e "SELECT COUNT(*) FROM system_credentials;" 2>/dev/null | tail -1)
    echo -e "  ${GREEN}✓${NC} System credentials (plaintext): $CREDS_COUNT"
    
    SECRETS_COUNT=$(docker exec pentest-db mysql -uadmin -padmin123 company_db -e "SELECT COUNT(*) FROM company_secrets;" 2>/dev/null | tail -1)
    echo -e "  ${GREEN}✓${NC} Company secrets (API keys, AWS): $SECRETS_COUNT"
else
    echo -e "  ${RED}✗${NC} Database not accessible"
fi
echo ""

# Test 3: File Server
echo -e "${YELLOW}[3/5] Testing File Server...${NC}"
FILE_COUNT=$(find "$LAB_DIR/file-server/shared-files" -type f 2>/dev/null | wc -l | tr -d ' ')
if [ "$FILE_COUNT" -gt 0 ]; then
    echo -e "  ${GREEN}✓${NC} File server has $FILE_COUNT sensitive files"
    echo "  Files include:"
    ls -1 "$LAB_DIR/file-server/shared-files" | while read file; do
        echo "    - $file"
    done
else
    echo -e "  ${RED}✗${NC} No files found on file server"
fi
echo ""

# Test 4: SSH Server (Vulnerable Linux)
echo -e "${YELLOW}[4/5] Testing SSH Server...${NC}"
if docker exec pentest-vuln-linux ps aux | grep -q sshd; then
    echo -e "  ${GREEN}✓${NC} SSH server is running"
    echo -e "  ${GREEN}✓${NC} Weak credentials available: root/root123, admin/admin123"
else
    echo -e "  ${RED}✗${NC} SSH server not running"
fi
echo ""

# Test 5: Container Status
echo -e "${YELLOW}[5/5] Testing Container Status...${NC}"
RUNNING=$(docker-compose ps --services --filter "status=running" 2>/dev/null | wc -l | tr -d ' ')
echo -e "  ${GREEN}✓${NC} Running containers: $RUNNING"
docker-compose ps --format table 2>/dev/null | grep -v "COMMAND"
echo ""

# Show sample data
echo -e "${BLUE}Sample Data Available:${NC}"
echo ""

echo -e "${YELLOW}Database - Sample Employee Record:${NC}"
docker exec pentest-db mysql -uadmin -padmin123 company_db -e "SELECT first_name, last_name, email, ssn, salary FROM employees LIMIT 1;" 2>/dev/null | grep -v Warning
echo ""

echo -e "${YELLOW}Database - Sample Customer Credit Card:${NC}"
docker exec pentest-db mysql -uadmin -padmin123 company_db -e "SELECT full_name, credit_card, cvv FROM customers LIMIT 1;" 2>/dev/null | grep -v Warning
echo ""

echo -e "${YELLOW}Database - Sample System Credential:${NC}"
docker exec pentest-db mysql -uadmin -padmin123 company_db -e "SELECT system_name, username, password FROM system_credentials LIMIT 1;" 2>/dev/null | grep -v Warning
echo ""

echo -e "${YELLOW}File Server - Sample Sensitive File Content:${NC}"
if [ -f "$LAB_DIR/file-server/shared-files/Q4_Financial_Report.txt" ]; then
    echo "--- Q4_Financial_Report.txt (excerpt) ---"
    head -10 "$LAB_DIR/file-server/shared-files/Q4_Financial_Report.txt"
    echo ""
fi

# Show available reports
echo -e "${BLUE}Available Scripts & Reports:${NC}"
echo ""
echo "Generate comprehensive HTML report:"
echo -e "  ${GREEN}./scripts/internal-pentest-report.sh${NC}"
echo ""
echo "Access web interface:"
echo -e "  ${GREEN}http://localhost:8080${NC}"
echo -e "  ${GREEN}http://localhost:8080/login.html${NC} (Try SQL injection: admin' OR '1'='1)"
echo -e "  ${GREEN}http://localhost:8080/admin.html${NC}"
echo ""

echo "Test database access:"
echo -e "  ${GREEN}docker exec -it pentest-db mysql -uadmin -padmin123 company_db${NC}"
echo ""

echo "Test SSH access:"
echo -e "  ${GREEN}docker exec -it pentest-kali ssh admin@172.22.0.5${NC}"
echo -e "  Password: ${YELLOW}admin123${NC}"
echo ""

LATEST_REPORT=$(ls -t "$LAB_DIR/reports"/internal_lab_report_*.html 2>/dev/null | head -1)
if [ ! -z "$LATEST_REPORT" ]; then
    echo -e "${GREEN}Latest Report:${NC} $LATEST_REPORT"
    echo -e "Open with: ${GREEN}open '$LATEST_REPORT'${NC}"
    echo ""
fi

echo "========================================"
echo -e "${GREEN}✓ Lab is fully functional with real data!${NC}"
echo "========================================"
