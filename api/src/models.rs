use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VulnerabilityFinding {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub finding_type: String,
    pub severity: String,
    pub target: String,
    pub target_ip: Option<String>,
    pub description: String,
    pub evidence: Option<String>,
    pub payload: Option<String>,
    pub source_ip: Option<String>,
    pub port: Option<u16>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AttackPattern {
    pub pattern_type: String,
    pub source_ip: String,
    pub destination_ip: String,
    pub destination_port: Option<u16>,
    pub protocol: String,
    pub count: u32,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub indicators: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NetworkFlow {
    pub source_ip: String,
    pub destination_ip: String,
    pub source_port: u16,
    pub destination_port: u16,
    pub protocol: String,
    pub packet_count: u32,
    pub byte_count: u64,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PcapAnalysisRequest {
    pub pcap_file: String,
    pub analysis_options: Option<AnalysisOptions>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AnalysisOptions {
    pub extract_http: bool,
    pub extract_sql: bool,
    pub extract_radius: bool,
    pub extract_ssh: bool,
    pub extract_ftp: bool,
    pub extract_smb: bool,
    pub detect_port_scans: bool,
    pub detect_brute_force: bool,
}

impl Default for AnalysisOptions {
    fn default() -> Self {
        Self {
            extract_http: true,
            extract_sql: true,
            extract_radius: true,
            extract_ssh: true,
            extract_ftp: true,
            extract_smb: true,
            detect_port_scans: true,
            detect_brute_force: true,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PcapAnalysisResult {
    pub pcap_file: String,
    pub analysis_timestamp: DateTime<Utc>,
    pub findings: Vec<VulnerabilityFinding>,
    pub attack_patterns: Vec<AttackPattern>,
    pub network_flows: Vec<NetworkFlow>,
    pub summary: AnalysisSummary,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AnalysisSummary {
    pub total_packets: u64,
    pub total_flows: u32,
    pub findings_count: u32,
    pub attack_patterns_count: u32,
    pub protocols_detected: Vec<String>,
}
