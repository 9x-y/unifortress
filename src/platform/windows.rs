/// Модуль для Windows-специфичных функций
use anyhow::anyhow;
use log::{info, warn};
use std::path::Path;
use std::process::Command;
use super::DriveInfo;

/// Проверяет, доступен ли драйвер Dokan
pub fn check_dokan_driver() -> anyhow::Result<bool> {
    // Теоретически здесь должна быть проверка наличия и статуса драйвера Dokan
    // Пока просто заглушка
    info!("Проверка наличия драйвера Dokan");
    Ok(true)
}

/// Проверяет доступность буквы диска для монтирования
pub fn check_drive_letter_availability(drive_letter: char) -> anyhow::Result<bool> {
    if !drive_letter.is_ascii_alphabetic() {
        warn!("Некорректная буква диска: {}", drive_letter);
        return Ok(false);
    }
    
    let drive_path = format!("{}:\\", drive_letter.to_uppercase());
    info!("Проверка доступности буквы диска: {}", drive_path);
    
    // Проверка, существует ли путь к диску
    let path_exists = Path::new(&drive_path).exists();
    
    if path_exists {
        warn!("Буква диска {} уже используется", drive_letter);
    }
    
    Ok(!path_exists)
}

/// Convert a device path to the correct format for Windows
pub fn get_device_path(device_path: &str) -> anyhow::Result<String> {
    // If it looks like a Windows physical drive path, return it as-is
    if device_path.starts_with(r"\\.\PhysicalDrive") {
        return Ok(device_path.to_string());
    }
    
    // If it's a drive letter, convert to physical drive
    if device_path.len() == 1 && device_path.chars().next().unwrap().is_alphabetic() {
        // This is just a placeholder, proper implementation would get the physical drive
        // number from the drive letter
        return Ok(format!(r"\\.\PhysicalDrive{}", device_path));
    }
    
    // Try to interpret as a disk number
    if let Ok(disk_num) = device_path.parse::<usize>() {
        return Ok(format!(r"\\.\PhysicalDrive{}", disk_num));
    }
    
    // Otherwise, return the path as-is (might be a file path)
    Ok(device_path.to_string())
}

/// Get a list of available physical drives on Windows
pub fn get_available_drives() -> anyhow::Result<Vec<DriveInfo>> {
    let mut drives = Vec::new();
    
    // Create a temporary script file for diskpart
    let diskpart_script = "list disk\nexit\n";
    let script_path = std::env::temp_dir().join("unifortress_list_disks.txt");
    std::fs::write(&script_path, diskpart_script)?;
    
    // Execute diskpart to get disk information
    let output = Command::new("diskpart")
        .args(["/s", script_path.to_str().unwrap()])
        .output()?;
    
    // Clean up the temporary script
    let _ = std::fs::remove_file(script_path);
    
    let output_str = String::from_utf8_lossy(&output.stdout);
    
    // Process the output to extract disk information
    // Find the table of disks in the output
    if let Some(start_idx) = output_str.find("Disk ###") {
        let table_start = start_idx;
        
        // Split the output into lines
        let lines: Vec<&str> = output_str[table_start..].lines().collect();
        
        // Skip header line and process disk entries
        let mut index = 1; // Starting index for user selection
        
        for line in lines.iter().skip(1) {
            let line = line.trim();
            if line.is_empty() || !line.starts_with("Disk ") {
                continue;
            }
            
            // Parse the line to extract disk information
            // Example line: "Disk 0    Online   238 GB  1024 KB  TOSHIBA THNSN5238GTNG"
            let parts: Vec<&str> = line.split_whitespace().collect();
            
            if parts.len() >= 4 {
                let disk_number = parts[1].parse::<usize>().unwrap_or(0);
                let status = parts[2].to_string();
                
                // Get size (might be in different positions depending on disk)
                let mut size_idx = 3;
                let mut size = String::new();
                
                while size_idx < parts.len() && (parts[size_idx].contains("GB") || parts[size_idx].contains("MB") || parts[size_idx].contains("TB")) {
                    size = format!("{} {}", size, parts[size_idx]);
                    size_idx += 1;
                }
                
                if size.is_empty() && size_idx < parts.len() {
                    size = format!("{} {}", parts[3], parts[4]); 
                }
                
                size = size.trim().to_string();
                
                // Rest of the line is likely the disk model/name
                let mut name = String::new();
                for i in size_idx..parts.len() {
                    name = format!("{} {}", name, parts[i]);
                }
                
                // If no name found, use generic description
                if name.trim().is_empty() {
                    name = format!("Disk {}", disk_number);
                } else {
                    name = name.trim().to_string();
                }
                
                // Determine if this is likely a system disk (typically disk 0)
                let is_system = disk_number == 0;
                
                // Determine drive type (removable vs fixed)
                // This is a simplified heuristic
                let drive_type = if is_system {
                    "Fixed (System)".to_string()
                } else {
                    // Try to determine if it's removable
                    // For a proper implementation, we would use DeviceIoControl with IOCTL_STORAGE_GET_DEVICE_NUMBER
                    // or other Win32 APIs, but this is a simplified version
                    let probable_size = if size.contains("GB") {
                        let size_num = size.split_whitespace().next()
                            .and_then(|s| s.parse::<f64>().ok())
                            .unwrap_or(0.0);
                        size_num < 200.0 // Assume drives smaller than 200GB might be removable
                    } else {
                        false
                    };
                    
                    if probable_size {
                        "Removable".to_string()
                    } else {
                        "Fixed".to_string()
                    }
                };
                
                // Create DriveInfo object
                let drive_info = DriveInfo {
                    index,
                    path: format!(r"\\.\PhysicalDrive{}", disk_number),
                    name,
                    size,
                    drive_type,
                    is_system,
                };
                
                drives.push(drive_info);
                index += 1;
            }
        }
    }
    
    Ok(drives)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_check_dokan_driver() {
        // Базовый тест, просто убеждаемся, что функция не паникует
        let _ = check_dokan_driver();
    }
    
    #[test]
    fn test_drive_letter_validation() {
        // Некорректные буквы дисков должны возвращать false
        assert!(!check_drive_letter_availability('1').unwrap());
        assert!(!check_drive_letter_availability('#').unwrap());
        
        // Корректные буквы - зависит от системы, не тестируем конкретные
        let _ = check_drive_letter_availability('Z');
    }
} 