pub mod encryption;
pub mod decryption;
pub mod platform;
pub mod utils;
pub mod fs_access;
pub mod crypto;
pub mod mount;
pub mod deferred;

use anyhow::{Result, anyhow};

/// Структура для работы с зашифрованными дисками, представляющая
/// кроссплатформенный API для работы с UniFortress
pub struct UniFortressDisk {
    /// Путь к устройству (физическому или файлу)
    pub device_path: String,
    /// Флаг, указывающий, зашифрован ли диск
    pub is_encrypted: bool,
}

impl UniFortressDisk {
    /// Создает новый экземпляр для работы с устройством
    pub fn new(device_path: &str) -> Self {
        Self {
            device_path: platform::get_device_path(device_path)
                .unwrap_or_else(|_| device_path.to_string()),
            is_encrypted: false,
        }
    }

    /// Проверяет, зашифрован ли диск с помощью UniFortress
    pub fn check_encrypted(&mut self) -> Result<bool> {
        // Пока просто заглушка, в будущем нужно реализовать
        Err(anyhow!("Not implemented yet"))
    }

    /// Шифрует диск с указанным паролем
    pub fn encrypt(&self, _password: &str) -> Result<()> {
        // В будущем реализовать с использованием encryption::encrypt_volume
        Err(anyhow!("Not implemented yet"))
    }

    /// Проверяет пароль для зашифрованного диска
    pub fn verify_password(&self, _password: &str) -> Result<bool> {
        // В будущем реализовать с использованием decryption::verify_password
        Err(anyhow!("Not implemented yet"))
    }

    /// Монтирует зашифрованный диск
    pub fn mount(&self, _password: &str, _mount_point: &str) -> Result<()> {
        // В будущем реализовать с использованием mount::mount
        Err(anyhow!("Not implemented yet"))
    }

    /// Размонтирует зашифрованный диск
    pub fn unmount(&self, _mount_point: &str) -> Result<()> {
        // В будущем реализовать с использованием mount::unmount
        Err(anyhow!("Not implemented yet"))
    }
}

/// Платформенно-независимая функция для определения того,
/// нужны ли права администратора для работы с устройством
pub fn requires_admin() -> bool {
    if cfg!(windows) {
        true // На Windows всегда нужны права администратора для работы с физическими устройствами
    } else if cfg!(unix) {
        true // На Unix системах обычно тоже требуются права root
    } else {
        false
    }
}

/// Функция для получения списка доступных дисков
pub fn list_available_drives() -> Result<Vec<String>> {
    // В будущем реализовать через platform-специфичные функции
    Err(anyhow!("Not implemented yet"))
} 