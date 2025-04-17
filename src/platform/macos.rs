use anyhow::{anyhow, Result};
use std::process::Command;
use super::DriveInfo;

/// Get the canonical device path for macOS
pub fn get_device_path(device_path: &str) -> Result<String> {
    // If it starts with "/dev/", it's already a device path
    if device_path.starts_with("/dev/") {
        return Ok(device_path.to_string());
    }
    
    // If it's "diskN", add the "/dev/" prefix
    if device_path.starts_with("disk") && device_path.len() > 4 {
        let rest: &str = &device_path[4..];
        if rest.parse::<usize>().is_ok() {
            return Ok(format!("/dev/{}", device_path));
        }
    }
    
    // If it's just a number, treat it as an index into the available drives list
    if let Ok(index) = device_path.parse::<usize>() {
        // Get available drives
        let drives = get_available_drives()?;
        
        // Index is 1-based in the user interface
        if index >= 1 && index <= drives.len() {
            return Ok(drives[index - 1].path.clone());
        } else {
            return Err(anyhow!("Invalid drive index: {}", index));
        }
    }
    
    // Otherwise, pass it through as-is
    Ok(device_path.to_string())
}

/// Get a list of available drives on macOS
pub fn get_available_drives() -> Result<Vec<DriveInfo>> {
    let mut drives = Vec::new();
    
    // Use diskutil to list disk information
    let output = Command::new("diskutil")
        .args(["list", "-plist"])
        .output()?;
    
    let output_str = String::from_utf8_lossy(&output.stdout);
    
    // For a proper implementation, we would parse the plist output
    // Here's a simplified version that parses the text output of diskutil list
    let standard_output = Command::new("diskutil")
        .args(["list"])
        .output()?;
    
    let standard_output_str = String::from_utf8_lossy(&standard_output.stdout);
    let lines: Vec<&str> = standard_output_str.lines().collect();
    
    let mut index = 1; // User-facing 1-indexed drives
    let mut current_disk = String::new();
    let mut current_name = String::new();
    let mut current_size = String::new();
    
    for line in lines {
        let line = line.trim();
        
        // Start of a new disk entry
        if line.starts_with("/dev/disk") {
            // Save previous disk if we have one
            if !current_disk.is_empty() {
                let is_system = current_disk == "/dev/disk0";
                
                let drive_info = DriveInfo {
                    index,
                    path: current_disk.clone(),
                    name: if current_name.is_empty() { 
                        format!("Disk {}", current_disk.replace("/dev/", "")) 
                    } else { 
                        current_name.clone() 
                    },
                    size: current_size.clone(),
                    drive_type: if is_system { "System".to_string() } else { "External".to_string() },
                    is_system,
                };
                
                drives.push(drive_info);
                index += 1;
            }
            
            // Start tracking new disk
            current_disk = line.split_whitespace().next().unwrap_or("").to_string();
            current_name = String::new();
            current_size = String::new();
        }
        
        // Extract size information
        if line.contains("GB") || line.contains("MB") || line.contains("TB") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                for i in 0..parts.len() - 1 {
                    if parts[i+1] == "GB" || parts[i+1] == "MB" || parts[i+1] == "TB" {
                        current_size = format!("{} {}", parts[i], parts[i+1]);
                        break;
                    }
                }
            }
        }
        
        // Extract disk name
        if line.contains("NAME:") {
            let parts: Vec<&str> = line.split("NAME:").collect();
            if parts.len() >= 2 {
                current_name = parts[1].trim().to_string();
            }
        }
    }
    
    // Add the last disk if we have one
    if !current_disk.is_empty() {
        let is_system = current_disk == "/dev/disk0";
        
        let drive_info = DriveInfo {
            index,
            path: current_disk.clone(),
            name: if current_name.is_empty() { 
                format!("Disk {}", current_disk.replace("/dev/", "")) 
            } else { 
                current_name 
            },
            size: current_size,
            drive_type: if is_system { "System".to_string() } else { "External".to_string() },
            is_system,
        };
        
        drives.push(drive_info);
    }
    
    Ok(drives)
} 