use std::process::Command;
use anyhow::{anyhow, Result};
use super::DriveInfo;

/// Get the canonical device path
pub fn get_device_path(device_path: &str) -> Result<String> {
    // If it starts with "/dev/", assume it's already a valid device path
    if device_path.starts_with("/dev/") {
        return Ok(device_path.to_string());
    }
    
    // If it's just a device name (e.g., "sda"), prepend "/dev/"
    if !device_path.contains("/") {
        return Ok(format!("/dev/{}", device_path));
    }
    
    // If it's a number, treat it as an index to available drives
    if let Ok(index) = device_path.parse::<usize>() {
        // Get available drives
        let drives = get_available_drives()?;
        
        // Index is 1-based in user interface
        if index >= 1 && index <= drives.len() {
            return Ok(drives[index - 1].path.clone());
        } else {
            return Err(anyhow!("Invalid drive index: {}", index));
        }
    }
    
    // Otherwise, return the path as-is
    Ok(device_path.to_string())
}

/// Get a list of available drives on Linux
pub fn get_available_drives() -> Result<Vec<DriveInfo>> {
    let mut drives = Vec::new();
    
    // Use lsblk to get block device information
    let output = Command::new("lsblk")
        .args(["-dpno", "NAME,SIZE,TYPE,MODEL"])
        .output()?;
    
    let output_str = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = output_str.lines().collect();
    
    // Process each line to extract device information
    let mut index = 1; // Starting index for user selection
    
    for line in lines {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        
        // Split the line into parts
        // Example: "/dev/sda 500G disk WD_BLACK SN750"
        let parts: Vec<&str> = line.split_whitespace().collect();
        
        if parts.len() >= 3 && parts[2] == "disk" {
            let path = parts[0].to_string();
            let size = parts[1].to_string();
            
            // Extract device name from path
            let name_parts: Vec<&str> = path.split('/').collect();
            let device_name = name_parts.last().unwrap_or(&"unknown").to_string();
            
            // Extract model from the remaining parts
            let mut model = String::new();
            for i in 3..parts.len() {
                model = format!("{} {}", model, parts[i]);
            }
            model = model.trim().to_string();
            
            // If no model name, use device name
            let name = if model.is_empty() {
                format!("Drive {}", device_name)
            } else {
                model
            };
            
            // Check if likely a system disk (heuristic: usually the first disk)
            let is_system = device_name == "sda" || path.contains("nvme0n1");
            
            // Create drive info
            let drive_info = DriveInfo {
                index,
                path,
                name,
                size,
                drive_type: if is_system { "System".to_string() } else { "Data".to_string() },
                is_system,
            };
            
            drives.push(drive_info);
            index += 1;
        }
    }
    
    Ok(drives)
} 