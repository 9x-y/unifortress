use anyhow::{bail, Result, anyhow};
use rand::{rngs::OsRng, RngCore};
use sha2::{Sha256, Digest};

/// Парсит строку размера в байты.
/// Поддерживаемые суффиксы: K, M, G, T для Кило-, Мега-, Гига- и Терабайт.
/// Примеры: "10K", "5M", "1G", "2T".
/// Число без суффикса интерпретируется как байты.
pub fn parse_size(size_str: &str) -> Result<u64> {
    let size_str = size_str.trim();
    
    if size_str.is_empty() {
        bail!("Пустая строка размера");
    }
    
    let last_char = size_str.chars().last().unwrap();
    
    if last_char.is_digit(10) {
        // Число без суффикса (простые байты)
        return size_str.parse::<u64>().map_err(|_| anyhow!("Не удалось преобразовать '{}' в число", size_str));
    }
    
    let multiplier = match last_char.to_uppercase().next().unwrap() {
        'K' => 1024u64,
        'M' => 1024u64 * 1024,
        'G' => 1024u64 * 1024 * 1024,
        'T' => 1024u64 * 1024 * 1024 * 1024,
        _ => bail!("Неизвестный суффикс размера: '{}'", last_char),
    };
    
    let number_part = &size_str[..size_str.len() - 1];
    let number = number_part.parse::<u64>()
        .map_err(|_| anyhow!("Не удалось преобразовать '{}' в число", number_part))?;
    
    Ok(number * multiplier)
}

/// Генерирует случайную соль для KDF
pub fn generate_salt() -> [u8; 32] {
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Проверяет, является ли пароль достаточно сложным
pub fn check_password(password: &str) -> bool {
    // Минимальная длина 8 символов
    if password.len() < 8 {
        return false;
    }

    // Флаги для проверки разных типов символов
    let mut has_lowercase = false;
    let mut has_uppercase = false;
    let mut has_digit = false;
    let mut has_special = false;

    for c in password.chars() {
        if c.is_ascii_lowercase() {
            has_lowercase = true;
        } else if c.is_ascii_uppercase() {
            has_uppercase = true;
        } else if c.is_ascii_digit() {
            has_digit = true;
        } else if !c.is_ascii_alphanumeric() {
            has_special = true;
        }
    }

    // Требуем как минимум 3 из 4 типов символов
    let types_count = [has_lowercase, has_uppercase, has_digit, has_special]
        .iter()
        .filter(|&&x| x)
        .count();

    types_count >= 3
}

/// Генерирует ключ шифрования из пароля и соли
/// 
/// В реальной реализации следует использовать Argon2id или PBKDF2 с большим числом итераций
pub fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 64]> {
    // Проверяем длину соли
    if salt.len() < 16 {
        return Err(anyhow!("Salt is too short, must be at least 16 bytes"));
    }

    // В реальной системе здесь должен быть вызов Argon2id или PBKDF2
    // Данная реализация - упрощенный вариант для демонстрации
    
    // Создаем массив для ключа
    let mut key = [0u8; 64];
    
    // Первая половина ключа (для XTS нужны 2 ключа)
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update(salt);
    hasher.update(b"1"); // Добавляем суффикс "1" для первой половины
    let hash1 = hasher.finalize();
    
    // Вторая половина ключа
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update(salt);
    hasher.update(b"2"); // Добавляем суффикс "2" для второй половины
    let hash2 = hasher.finalize();
    
    // Копируем хеши в массив ключа
    key[0..32].copy_from_slice(&hash1);
    key[32..64].copy_from_slice(&hash2);
    
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*; 

    #[test]
    fn test_parse_size_simple() {
        assert_eq!(parse_size("1024").unwrap(), 1024);
        assert_eq!(parse_size("1K").unwrap(), 1024);
        assert_eq!(parse_size("1KB").unwrap(), 1024);
        assert_eq!(parse_size("1M").unwrap(), 1024 * 1024);
        assert_eq!(parse_size("1G").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(parse_size("1T").unwrap(), 1024 * 1024 * 1024 * 1024);
        assert_eq!(parse_size("1.5G").unwrap(), (1.5 * 1024.0 * 1024.0 * 1024.0) as u64);
        assert_eq!(parse_size(" 512 M ").unwrap(), 512 * 1024 * 1024);
    }

     #[test]
    fn test_parse_size_invalid() {
        assert!(parse_size("abc").is_err());
        assert!(parse_size("1.1.1G").is_err());
        assert!(parse_size("1P").is_err()); // Петабайты не поддерживаем пока
        assert!(parse_size("-1G").is_err());
    }
} 