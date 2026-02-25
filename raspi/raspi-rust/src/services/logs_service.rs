use serde::{Deserialize, Serialize};
use std::fs::{self, read_dir, OpenOptions};

#[derive(Serialize, Deserialize, Debug)]
pub struct SuricataLog {
    pub timestamp: String,
    pub flow_id: u64,
    /// Het type event (bijv. "alert", "http", "dns", "flow")
    pub event_type: String,

    pub src_ip: String,
    pub src_port: u16,

    pub dest_ip: String,
    pub dest_port: u16,

    pub proto: String,

    pub alert: Option<AlertData>,

    /// Netwerk interface waarop het verkeer is onderschept
    pub in_iface: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AlertData {
    /// ("allowed" of "blocked")
    pub action: String,

    /// De naam van de gedetecteerde dreiging (Signature)
    pub signature: String,

    pub category: String,

    /// De ernst van de dreiging (1 = hoog, 3 = laag)
    pub severity: u16,

    /// Signature ID voor koppeling aan CVE/NVD databases
    pub signature_id: u64,
}

use std::path::Path;

const SURICATA_LOG_DIR: &str = "/var/log/suricata";

/// Leest Suricata logs uit de gedeelde volume
pub fn get_logs() -> Result<Vec<String>, std::io::Error> {
    let log_path = Path::new(SURICATA_LOG_DIR);

    let mut log_files = Vec::new();

    if log_path.exists() {
        for entry in read_dir(log_path)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_file() {
                if let Some(file_name) = path.file_name() {
                    log_files.push(file_name.to_string_lossy().to_string());
                }
            }
        }
    }

    Ok(log_files)
}

pub fn read_log_file(filename: &str) -> Result<String, std::io::Error> {
    let log_path = Path::new(SURICATA_LOG_DIR).join(filename);
    fs::read_to_string(log_path)
}

pub fn delete_log_file(filename: &str) -> Result<(), std::io::Error> {
    let log_path = Path::new(SURICATA_LOG_DIR).join(filename);
    fs::write(log_path, "")?;
    Ok(())
}
