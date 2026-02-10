use crate::models::*;
use std::fs;
use std::path::Path;
use std::io::Write;

pub struct RuleGenerator;

impl RuleGenerator {
    pub fn generate_rule_from_finding(finding: &VulnerabilityFinding) -> Result<String, String> {
        let rule = match finding.finding_type.as_str() {
            "brute_force" => Self::generate_brute_force_rule(finding),
            "port_scan" => Self::generate_port_scan_rule(finding),
            "sql_injection" => Self::generate_sql_injection_rule(finding),
            "radius_attack" => Self::generate_radius_rule(finding),
            "directory_traversal" => Self::generate_directory_traversal_rule(finding),
            _ => Self::generate_generic_rule(finding),
        };
        
        Ok(rule)
    }
    
    fn generate_brute_force_rule(finding: &VulnerabilityFinding) -> String {
        let port = finding.port.unwrap_or(0);
        let protocol = match port {
            22 => "ssh",
            21 => "ftp",
            3306 => "mysql",
            1812 => "udp",
            _ => "tcp",
        };
        
        let target_ip = finding.target_ip.as_ref()
            .map(|ip| ip.as_str())
            .unwrap_or("$HOME_NET");
        
        let sid = Self::generate_sid(&finding.finding_type, port);
        
        format!(
            "alert {} any any -> {} {} (msg:\"{} Brute Force Attempt\"; flow:established,to_server; threshold:type threshold, track by_src, count 5, seconds 60; sid:{}; rev:1;)",
            protocol,
            target_ip,
            port,
            finding.finding_type.to_uppercase(),
            sid
        )
    }
    
    fn generate_port_scan_rule(finding: &VulnerabilityFinding) -> String {
        let target_ip = finding.target_ip.as_ref()
            .map(|ip| ip.as_str())
            .unwrap_or("$HOME_NET");
        
        let sid = Self::generate_sid(&finding.finding_type, 0);
        
        format!(
            "alert tcp any any -> {} any (msg:\"Port Scan Detected\"; flags:S,12; threshold:type threshold, track by_src, count 20, seconds 60; sid:{}; rev:1;)",
            target_ip,
            sid
        )
    }
    
    fn generate_sql_injection_rule(finding: &VulnerabilityFinding) -> String {
        let payload = finding.payload.as_ref()
            .map(|p| p.as_str())
            .unwrap_or("' OR '1'='1");
        
        let target_ip = finding.target_ip.as_ref()
            .map(|ip| ip.as_str())
            .unwrap_or("$HOME_NET");
        
        let sid = Self::generate_sid(&finding.finding_type, 0);
        
        // Escape special characters for Suricata content matching
        let escaped_payload = payload.replace('"', "\\\"");
        
        format!(
            "alert http any any -> {} any (msg:\"SQL Injection Attempt\"; flow:established,to_server; content:\"{}\"; http_uri; sid:{}; rev:1;)",
            target_ip,
            escaped_payload,
            sid
        )
    }
    
    fn generate_radius_rule(finding: &VulnerabilityFinding) -> String {
        let target_ip = finding.target_ip.as_ref()
            .map(|ip| ip.as_str())
            .unwrap_or("$HOME_NET");
        
        let sid = Self::generate_sid(&finding.finding_type, 1812);
        
        format!(
            "alert udp any any -> {} 1812 (msg:\"RADIUS Attack Detected\"; threshold:type threshold, track by_src, count 10, seconds 60; sid:{}; rev:1;)",
            target_ip,
            sid
        )
    }
    
    fn generate_directory_traversal_rule(finding: &VulnerabilityFinding) -> String {
        let target_ip = finding.target_ip.as_ref()
            .map(|ip| ip.as_str())
            .unwrap_or("$HOME_NET");
        
        let sid = Self::generate_sid(&finding.finding_type, 0);
        
        format!(
            "alert http any any -> {} any (msg:\"Directory Traversal Attempt\"; flow:established,to_server; content:\"../\"; http_uri; sid:{}; rev:1;)",
            target_ip,
            sid
        )
    }
    
    fn generate_generic_rule(finding: &VulnerabilityFinding) -> String {
        let target_ip = finding.target_ip.as_ref()
            .map(|ip| ip.as_str())
            .unwrap_or("$HOME_NET");
        
        let port = finding.port.map(|p| p.to_string()).unwrap_or_else(|| "any".to_string());
        let sid = Self::generate_sid(&finding.finding_type, 0);
        
        format!(
            "alert tcp any any -> {} {} (msg:\"{}\"; flow:established,to_server; sid:{}; rev:1;)",
            target_ip,
            port,
            finding.description,
            sid
        )
    }
    
    fn generate_sid(finding_type: &str, port: u16) -> u32 {
        // Generate SID based on finding type and port
        let base = match finding_type {
            "brute_force" => 1000000,
            "port_scan" => 1000100,
            "sql_injection" => 1000200,
            "radius_attack" => 1000300,
            "directory_traversal" => 1000400,
            _ => 1000500,
        };
        
        (base + (port as u32 % 100)) as u32
    }
    
    pub fn save_rule(rule: &str, filename: &str, rules_dir: &str) -> Result<String, String> {
        let custom_dir = Path::new(rules_dir).join("custom");
        fs::create_dir_all(&custom_dir).map_err(|e| format!("Failed to create directory: {}", e))?;
        
        let filepath = custom_dir.join(filename);
        let mut file = fs::File::create(&filepath)
            .map_err(|e| format!("Failed to create rule file: {}", e))?;
        
        file.write_all(rule.as_bytes())
            .map_err(|e| format!("Failed to write rule: {}", e))?;
        
        Ok(filepath.to_string_lossy().to_string())
    }
    
    pub fn load_template(template_name: &str, templates_dir: &str) -> Result<String, String> {
        let template_path = Path::new(templates_dir).join(format!("{}.rules", template_name));
        
        fs::read_to_string(&template_path)
            .map_err(|e| format!("Failed to read template {}: {}", template_name, e))
    }
    
    pub fn list_rules(rules_dir: &str) -> Result<Vec<String>, String> {
        let custom_dir = Path::new(rules_dir).join("custom");
        
        if !custom_dir.exists() {
            return Ok(Vec::new());
        }
        
        let mut rules = Vec::new();
        
        if let Ok(entries) = fs::read_dir(&custom_dir) {
            for entry in entries.flatten() {
                if let Some(filename) = entry.file_name().to_str() {
                    if filename.ends_with(".rules") {
                        rules.push(filename.to_string());
                    }
                }
            }
        }
        
        Ok(rules)
    }
    
    pub fn activate_rule(rule_file: &str, rules_dir: &str) -> Result<String, String> {
        let custom_path = Path::new(rules_dir).join("custom").join(rule_file);
        let active_path = Path::new(rules_dir).join("active").join(rule_file);
        
        if !custom_path.exists() {
            return Err(format!("Rule file not found: {}", rule_file));
        }
        
        fs::create_dir_all(Path::new(rules_dir).join("active"))
            .map_err(|e| format!("Failed to create active directory: {}", e))?;
        
        fs::copy(&custom_path, &active_path)
            .map_err(|e| format!("Failed to activate rule: {}", e))?;
        
        Ok(active_path.to_string_lossy().to_string())
    }
    
    pub fn deactivate_rule(rule_file: &str, rules_dir: &str) -> Result<(), String> {
        let active_path = Path::new(rules_dir).join("active").join(rule_file);
        
        if active_path.exists() {
            fs::remove_file(&active_path)
                .map_err(|e| format!("Failed to deactivate rule: {}", e))?;
        }
        
        Ok(())
    }
}
