use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::path::Path;
use serde::Serialize;

pub fn save_log(path: impl AsRef<Path>, value: &impl Serialize) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)?;
    serde_json::to_writer(&mut file, value)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    file.write_all(b"\n")?;
    Ok(())
}

pub fn load_log(path: impl AsRef<Path>) -> io::Result<String> {
    let mut file = OpenOptions::new().read(true).open(path)?;
    let mut json_data = String::new();
    file.read_to_string(&mut json_data)?;
    Ok(json_data)
}