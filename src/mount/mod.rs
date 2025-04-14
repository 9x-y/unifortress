// Модуль для монтирования зашифрованного диска
use anyhow::{anyhow, Result};
use crate::platform::get_device_path;

// Базовый интерфейс для монтирования
pub trait MountService {
    fn mount(&self, mount_point: &str) -> Result<()>;
    fn unmount(&self) -> Result<()>;
}

// Экспортируем обработчик файловой системы
mod dokan_handler;
pub use dokan_handler::EncryptedFsHandler;

// Тут могут быть платформенно-зависимые импорты и реализации
#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "linux")]
pub mod linux;

/// Монтирует зашифрованный диск
/// 
/// # Arguments
/// * `device_path` - Путь к устройству
/// * `password` - Пароль для расшифровки
/// * `mount_point` - Точка монтирования
pub fn mount(device_path: &str, password: &str, mount_point: &str) -> Result<()> {
    if cfg!(target_os = "windows") {
        #[cfg(target_os = "windows")]
        {
            windows::mount_encrypted_disk(device_path, password, mount_point)
        }
        #[cfg(not(target_os = "windows"))]
        {
            Err(anyhow!("Windows support not compiled in this binary"))
        }
    } else if cfg!(target_os = "macos") {
        #[cfg(target_os = "macos")]
        {
            macos::mount_encrypted_disk(device_path, password, mount_point)
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(anyhow!("macOS support not compiled in this binary"))
        }
    } else if cfg!(target_os = "linux") {
        #[cfg(target_os = "linux")]
        {
            linux::mount_encrypted_disk(device_path, password, mount_point)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(anyhow!("Linux support not compiled in this binary"))
        }
    } else {
        Err(anyhow!("Unsupported platform"))
    }
}

/// Размонтирует ранее примонтированный зашифрованный диск
/// 
/// # Arguments
/// * `mount_point` - Точка монтирования
pub fn unmount(mount_point: &str) -> Result<()> {
    if cfg!(target_os = "windows") {
        #[cfg(target_os = "windows")]
        {
            windows::unmount_encrypted_disk(mount_point)
        }
        #[cfg(not(target_os = "windows"))]
        {
            Err(anyhow!("Windows support not compiled in this binary"))
        }
    } else if cfg!(target_os = "macos") {
        #[cfg(target_os = "macos")]
        {
            macos::unmount_encrypted_disk(mount_point)
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(anyhow!("macOS support not compiled in this binary"))
        }
    } else if cfg!(target_os = "linux") {
        #[cfg(target_os = "linux")]
        {
            linux::unmount_encrypted_disk(mount_point)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(anyhow!("Linux support not compiled in this binary"))
        }
    } else {
        Err(anyhow!("Unsupported platform"))
    }
}

// Проверка на административные права для Windows
#[cfg(target_os = "windows")]
fn is_admin() -> bool {
    use std::process::Command;
    
    // На Windows, проверяем права администратора
    match Command::new("net")
        .args(["session"])
        .output() {
        Ok(output) => output.status.success(),
        Err(_) => false,
    }
}

// Проверка на административные права для Unix-систем
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn is_admin() -> bool {
    use std::process::Command;
    
    // На Unix, проверяем права root
    match Command::new("id")
        .args(["-u"])
        .output() {
        Ok(output) => {
            if let Ok(stdout) = String::from_utf8(output.stdout) {
                stdout.trim() == "0"
            } else {
                false
            }
        },
        Err(_) => false,
    }
}

// Функция для монтирования зашифрованного устройства
fn mount_device(device_path: &str, password: &str, mount_point: &str) -> Result<()> {
    // Проверка прав администратора
    if !is_admin() {
        return Err(anyhow!("This operation requires administrator privileges"));
    }

    println!("Mounting device: {}", device_path);
    let device_path = get_device_path(device_path)?;
    
    // Монтируем устройство
    println!("Mounting to: {}", mount_point);
    crate::mount::mount(&device_path, password, mount_point)?;
    
    println!("Device successfully mounted!");
    
    Ok(())
} 