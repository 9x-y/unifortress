pub mod common;
// Comment out the windows module to avoid compilation errors
// #[cfg(target_os = "windows")]
// pub mod windows;
#[cfg(target_os = "linux")]
pub mod linux;

use std::path::Path;
use std::io::Result;

/// Trait для монтирования зашифрованного хранилища
pub trait EncryptedStorage {
    /// Монтирует зашифрованное хранилище в указанную точку монтирования
    fn mount(&self, mount_point: &Path) -> Result<Box<dyn MountedStorage>>;
}

/// Trait для управления смонтированным хранилищем
pub trait MountedStorage {
    /// Размонтирует хранилище
    fn unmount(&self) -> Result<()>;
    
    /// Возвращает точку монтирования
    fn get_mount_point(&self) -> &Path;
}

/// Создает и возвращает реализацию EncryptedStorage для текущей платформы
pub fn create_encrypted_storage(_config: common::EncryptedStorageBase) -> Box<dyn EncryptedStorage> {
    #[cfg(target_os = "windows")]
    {
        // Temporarily return a placeholder until the Windows module is fixed
        unimplemented!("Windows filesystem module is currently disabled");
        // Box::new(windows::WindowsEncryptedStorage::new(config))
    }
    
    #[cfg(target_os = "linux")]
    {
        Box::new(linux::LinuxEncryptedStorage::new(_config))
    }
    
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        compile_error!("Unsupported platform. Only Windows and Linux are supported.");
    }
} 