/// Модуль для Windows-специфичных функций
use anyhow::{Result, Context};
use log::{info, warn};
use std::path::Path;

/// Проверяет, доступен ли драйвер Dokan
pub fn check_dokan_driver() -> Result<bool> {
    // Теоретически здесь должна быть проверка наличия и статуса драйвера Dokan
    // Пока просто заглушка
    info!("Проверка наличия драйвера Dokan");
    Ok(true)
}

/// Проверяет доступность буквы диска для монтирования
pub fn check_drive_letter_availability(drive_letter: char) -> Result<bool> {
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