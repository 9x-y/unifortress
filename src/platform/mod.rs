// Объявление подмодулей для папки platform
pub mod common;
pub mod volume_io;

// Платформенно-зависимые модули
#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "linux")]
pub mod linux;

// Убираем удаленные модули
// pub mod ios;
// pub mod android;

use anyhow::{Result, anyhow};

/// Функция для получения полного пути к устройству в зависимости от платформы
pub fn get_device_path(device: &str) -> Result<String> {
    if cfg!(target_os = "windows") {
        get_windows_device_path(device)
    } else if cfg!(target_os = "macos") {
        get_macos_device_path(device)
    } else if cfg!(target_os = "linux") {
        get_linux_device_path(device)
    } else {
        Err(anyhow!("Unsupported platform"))
    }
}

#[cfg(target_os = "windows")]
fn get_windows_device_path(device: &str) -> Result<String> {
    // Для Windows: если указана буква диска, преобразуем в путь к физическому устройству
    if device.len() == 1 && device.chars().next().unwrap().is_ascii_alphabetic() {
        return Ok(format!(r"\\.\{}:", device));
    } else if device.len() == 2 && device.ends_with(":") {
        return Ok(format!(r"\\.\{}", device));
    } else if device.starts_with(r"\\.\PhysicalDrive") {
        return Ok(device.to_string()); // Уже правильный формат
    }
    
    // Иначе возвращаем как есть
    Ok(device.to_string())
}

#[cfg(target_os = "macos")]
fn get_macos_device_path(device: &str) -> Result<String> {
    // Для macOS форматы /dev/disk0, /dev/rdisk0
    if device.starts_with("/dev/") {
        return Ok(device.to_string()); // Уже правильный формат
    }
    
    // Если указан только номер диска, добавляем префикс
    if let Ok(disk_num) = device.parse::<u32>() {
        return Ok(format!("/dev/rdisk{}", disk_num));
    }
    
    // Иначе возвращаем как есть
    Ok(device.to_string())
}

#[cfg(target_os = "linux")]
fn get_linux_device_path(device: &str) -> Result<String> {
    // Для Linux: форматы /dev/sdX, /dev/nvmeXnY
    if device.starts_with("/dev/") {
        return Ok(device.to_string()); // Уже правильный формат
    }
    
    // Если указана только буква диска, предполагаем /dev/sd<буква>
    if device.len() == 1 && device.chars().next().unwrap().is_ascii_alphabetic() {
        return Ok(format!("/dev/sd{}", device));
    }
    
    // Иначе возвращаем как есть
    Ok(device.to_string())
}

// Добавляем заглушки для Windows, чтобы сборка не ломалась в Linux/MacOS
#[cfg(not(target_os = "windows"))]
fn get_windows_device_path(_device: &str) -> Result<String> {
    Err(anyhow!("Windows-specific function called on non-Windows platform"))
}

// Заглушки для macOS/Linux для сборки на Windows
#[cfg(not(target_os = "macos"))]
fn get_macos_device_path(_device: &str) -> Result<String> {
    Err(anyhow!("macOS-specific function called on non-macOS platform"))
}

#[cfg(not(target_os = "linux"))]
fn get_linux_device_path(_device: &str) -> Result<String> {
    Err(anyhow!("Linux-specific function called on non-Linux platform"))
}

/// Struct to represent available drive information
#[derive(Debug, Clone)]
pub struct DriveInfo {
    /// Drive index (for user selection)
    pub index: usize,
    /// System path to the drive
    pub path: String,
    /// User-friendly name of the drive
    pub name: String,
    /// Size of the drive
    pub size: String,
    /// Drive type (removable, fixed, etc.)
    pub drive_type: String,
    /// Is this likely a system drive
    pub is_system: bool,
}

/// Get a list of available drives on the system
pub fn get_available_drives() -> anyhow::Result<Vec<DriveInfo>> {
    if cfg!(windows) {
        #[cfg(target_os = "windows")]
        {
            windows::get_available_drives()
        }
        #[cfg(not(target_os = "windows"))]
        {
            Err(anyhow::anyhow!("Windows support not compiled in this binary"))
        }
    } else if cfg!(target_os = "macos") {
        #[cfg(target_os = "macos")]
        {
            macos::get_available_drives()
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(anyhow::anyhow!("macOS support not compiled in this binary"))
        }
    } else if cfg!(target_os = "linux") {
        #[cfg(target_os = "linux")]
        {
            linux::get_available_drives()
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(anyhow::anyhow!("Linux support not compiled in this binary"))
        }
    } else {
        Err(anyhow::anyhow!("Unsupported platform"))
    }
} 