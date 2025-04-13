use anyhow::{bail, Result};
use hmac::digest::KeyInit;
use crate::crypto::xts::{self, XTS_KEY_SIZE};

/// Расшифровывает один сектор данных с использованием AES-256 XTS.
///
/// # Arguments
/// * `sector_data` - Зашифрованные данные сектора для расшифровки.
/// * `sector_index` - Номер сектора (используется как tweak).
/// * `xts_key` - 64-байтный ключ для XTS.
///
/// # Returns
/// Расшифрованные данные сектора.
pub fn decrypt_sector(
    sector_data: &mut [u8],
    sector_index: u64,
    xts_key: &[u8; XTS_KEY_SIZE],
) -> Result<()> {
    xts::decrypt_sector(sector_data, sector_index, xts_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::encrypt_sector;
    
    #[test]
    fn test_decrypt_sector() {
        // Произвольный ключ для теста
        let xts_key = [0u8; XTS_KEY_SIZE];
        
        // Тестовые данные (должны быть кратны 16 байтам для XTS)
        let original_data = b"This is a test message for XTS encryption!";
        let mut test_data = original_data.to_vec();
        
        // Зашифруем данные
        encrypt_sector(&mut test_data, 1, &xts_key).unwrap();
        
        // Проверим, что данные изменились
        assert_ne!(&test_data[..], &original_data[..]);
        
        // Расшифруем данные
        decrypt_sector(&mut test_data, 1, &xts_key).unwrap();
        
        // Проверим, что данные восстановились
        assert_eq!(&test_data[..], &original_data[..]);
    }
} 