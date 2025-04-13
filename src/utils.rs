use anyhow::{bail, Result};

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
        return size_str.parse::<u64>().map_err(|_| anyhow::anyhow!("Не удалось преобразовать '{}' в число", size_str));
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
        .map_err(|_| anyhow::anyhow!("Не удалось преобразовать '{}' в число", number_part))?;
    
    Ok(number * multiplier)
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