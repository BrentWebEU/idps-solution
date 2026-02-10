-- Company Database Initialization Script
-- Creates realistic data for penetration testing

USE company_db;

-- Employees table with sensitive information
CREATE TABLE IF NOT EXISTS employees (
    id INT PRIMARY KEY AUTO_INCREMENT,
    first_name VARCHAR(50),
    last_name VARCHAR(50),
    email VARCHAR(100),
    phone VARCHAR(20),
    ssn VARCHAR(11),
    salary DECIMAL(10,2),
    department VARCHAR(50),
    hire_date DATE,
    password_hash VARCHAR(255)
);

-- Insert realistic employee data
INSERT INTO employees (first_name, last_name, email, phone, ssn, salary, department, hire_date, password_hash) VALUES
('John', 'Smith', 'john.smith@company.com', '555-0101', '123-45-6789', 85000.00, 'IT', '2020-03-15', 'e10adc3949ba59abbe56e057f20f883e'),
('Sarah', 'Johnson', 'sarah.johnson@company.com', '555-0102', '234-56-7890', 92000.00, 'Finance', '2019-06-20', '5f4dcc3b5aa765d61d8327deb882cf99'),
('Michael', 'Williams', 'michael.williams@company.com', '555-0103', '345-67-8901', 78000.00, 'Marketing', '2021-01-10', '098f6bcd4621d373cade4e832627b4f6'),
('Emily', 'Brown', 'emily.brown@company.com', '555-0104', '456-78-9012', 95000.00, 'Engineering', '2018-11-05', '5ebe2294ecd0e0f08eab7690d2a6ee69'),
('David', 'Jones', 'david.jones@company.com', '555-0105', '567-89-0123', 105000.00, 'Management', '2017-08-12', 'e99a18c428cb38d5f260853678922e03'),
('Jennifer', 'Garcia', 'jennifer.garcia@company.com', '555-0106', '678-90-1234', 72000.00, 'HR', '2020-09-01', 'fcea920f7412b5da7be0cf42b8c93759'),
('Robert', 'Martinez', 'robert.martinez@company.com', '555-0107', '789-01-2345', 88000.00, 'IT', '2019-04-15', '827ccb0eea8a706c4c34a16891f84e7b'),
('Lisa', 'Rodriguez', 'lisa.rodriguez@company.com', '555-0108', '890-12-3456', 91000.00, 'Sales', '2021-07-20', '96e79218965eb72c92a549dd5a330112'),
('James', 'Wilson', 'james.wilson@company.com', '555-0109', '901-23-4567', 76000.00, 'Support', '2022-02-14', 'e807f1fcf82d132f9bb018ca6738a19f'),
('Mary', 'Anderson', 'mary.anderson@company.com', '555-0110', '012-34-5678', 98000.00, 'Engineering', '2018-05-30', '5f4dcc3b5aa765d61d8327deb882cf99');

-- Customer database with PII and payment info
CREATE TABLE IF NOT EXISTS customers (
    id INT PRIMARY KEY AUTO_INCREMENT,
    full_name VARCHAR(100),
    email VARCHAR(100),
    phone VARCHAR(20),
    address VARCHAR(255),
    city VARCHAR(50),
    state VARCHAR(2),
    zip VARCHAR(10),
    credit_card VARCHAR(19),
    cvv VARCHAR(4),
    expiry DATE,
    account_status VARCHAR(20)
);

INSERT INTO customers (full_name, email, phone, address, city, state, zip, credit_card, cvv, expiry, account_status) VALUES
('Alice Cooper', 'alice.cooper@email.com', '555-1001', '123 Main St', 'New York', 'NY', '10001', '4532-1234-5678-9010', '123', '2025-12-31', 'active'),
('Bob Taylor', 'bob.taylor@email.com', '555-1002', '456 Oak Ave', 'Los Angeles', 'CA', '90001', '5425-2345-6789-0123', '456', '2026-06-30', 'active'),
('Carol White', 'carol.white@email.com', '555-1003', '789 Pine Rd', 'Chicago', 'IL', '60601', '4916-3456-7890-1234', '789', '2025-09-30', 'suspended'),
('Dan Black', 'dan.black@email.com', '555-1004', '321 Elm St', 'Houston', 'TX', '77001', '4532-4567-8901-2345', '321', '2027-03-31', 'active'),
('Eve Green', 'eve.green@email.com', '555-1005', '654 Maple Dr', 'Phoenix', 'AZ', '85001', '5425-5678-9012-3456', '654', '2026-11-30', 'active');

-- System credentials table (plaintext passwords - vulnerability!)
CREATE TABLE IF NOT EXISTS system_credentials (
    id INT PRIMARY KEY AUTO_INCREMENT,
    system_name VARCHAR(100),
    username VARCHAR(50),
    password VARCHAR(100),
    access_level VARCHAR(20),
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO system_credentials (system_name, username, password, access_level) VALUES
('Production Database', 'db_admin', 'DbP@ssw0rd2024', 'admin'),
('Backup Server', 'backup_user', 'Backup123!', 'write'),
('File Server', 'fileadmin', 'FileServer2024', 'admin'),
('VPN Gateway', 'vpn_admin', 'Vpn@ccess!2024', 'admin'),
('AWS Console', 'aws_root', 'AWSSecretKey2024!', 'root'),
('SSH Jump Host', 'sshuser', 'JumpH0st!Pass', 'user'),
('API Service', 'api_key', 'ApiK3y_S3cr3t_2024', 'service'),
('Email Server', 'mail_admin', 'M@ilP@ss2024', 'admin');

-- Company secrets table
CREATE TABLE IF NOT EXISTS company_secrets (
    id INT PRIMARY KEY AUTO_INCREMENT,
    secret_type VARCHAR(50),
    secret_name VARCHAR(100),
    secret_value TEXT,
    classification VARCHAR(20)
);

INSERT INTO company_secrets (secret_type, secret_name, secret_value, classification) VALUES
('API_KEY', 'Stripe Payment Gateway', 'sk_live_51HxQR8K9mP3nL4oYvZ6T7wX8sY2aB3cD4eF5g', 'CONFIDENTIAL'),
('API_KEY', 'AWS Access Key', 'AKIAIOSFODNN7EXAMPLE', 'TOP_SECRET'),
('API_KEY', 'SendGrid Email API', 'SG.1234567890abcdefghijklmnopqrstuvwxyz', 'CONFIDENTIAL'),
('PASSWORD', 'Admin Master Password', 'Adm1n_M@ster_P@ss_2024!', 'TOP_SECRET'),
('TOKEN', 'GitHub Personal Access', 'ghp_1234567890abcdefghijklmnopqrstuvwxyz', 'SECRET'),
('LICENSE', 'Software License Key', 'XXXX-YYYY-ZZZZ-AAAA-BBBB-CCCC', 'INTERNAL'),
('CERTIFICATE', 'SSL Private Key Path', '/etc/ssl/private/company.key', 'SECRET');

-- Access logs for forensics
CREATE TABLE IF NOT EXISTS access_logs (
    id INT PRIMARY KEY AUTO_INCREMENT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_id INT,
    action VARCHAR(100),
    ip_address VARCHAR(45),
    status VARCHAR(20)
);

INSERT INTO access_logs (user_id, action, ip_address, status) VALUES
(1, 'LOGIN', '192.168.1.100', 'success'),
(2, 'FILE_DOWNLOAD', '192.168.1.105', 'success'),
(3, 'FAILED_LOGIN', '10.0.0.50', 'failed'),
(4, 'DATA_EXPORT', '192.168.1.110', 'success'),
(5, 'PASSWORD_CHANGE', '192.168.1.115', 'success'),
(1, 'ADMIN_ACCESS', '192.168.1.100', 'success'),
(6, 'FAILED_LOGIN', '203.0.113.45', 'failed'),
(7, 'FILE_UPLOAD', '192.168.1.120', 'success');

-- Create views for easier querying
CREATE OR REPLACE VIEW sensitive_employee_data AS
SELECT first_name, last_name, email, ssn, salary, department 
FROM employees 
WHERE salary > 80000;

CREATE OR REPLACE VIEW active_credentials AS
SELECT system_name, username, password, access_level
FROM system_credentials
WHERE access_level IN ('admin', 'root');

-- Grant permissions
GRANT SELECT ON company_db.* TO 'admin'@'%';
GRANT SELECT, INSERT ON company_db.access_logs TO 'admin'@'%';
