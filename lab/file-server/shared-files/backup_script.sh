#!/bin/bash
# Backup script for production database
# Author: John Smith <john.smith@company.com>
# Last Updated: 2024-01-15

# Database credentials (TODO: Move to vault)
DB_HOST="172.22.0.3"
DB_USER="root"
DB_PASS="root"
DB_NAME="company_db"

# AWS S3 credentials for backup storage
AWS_ACCESS_KEY="AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
S3_BUCKET="s3://company-backups"

# Backup directory
BACKUP_DIR="/var/backups/mysql"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/company_db_$DATE.sql"

# Create backup
echo "Starting backup at $(date)"
mysqldump -h $DB_HOST -u $DB_USER -p$DB_PASS $DB_NAME > $BACKUP_FILE

# Compress backup
gzip $BACKUP_FILE

# Upload to S3
export AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY
export AWS_SECRET_ACCESS_KEY=$AWS_SECRET_KEY
aws s3 cp $BACKUP_FILE.gz $S3_BUCKET/

# Cleanup old backups (keep last 7 days)
find $BACKUP_DIR -name "*.sql.gz" -mtime +7 -delete

echo "Backup completed at $(date)"

# SSH keys for automation
# Private key located at: /root/.ssh/id_rsa
# Public key: ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDExample backup@company.com
