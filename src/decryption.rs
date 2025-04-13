use anyhow::{bail, Result};
use xts_mode::{get_tweak_default, Xts128};
use aes::Aes256;
use crate::encryption::XTS_KEY_SIZE;

/// Расшифровывает один сектор данных с использованием AES-256 XTS.
///
/// # Arguments
/// * `xts_key` - 64-байтный ключ для XTS.
/// * `sector_index` - Номер сектора (используется как tweak).
/// * `sector_data` - Зашифрованные данные сектора для расшифровки (должны быть >= 16 байт).
///
/// # Returns
/// Расшифрованные данные сектора.
pub fn decrypt_sector(
    xts_key: &[u8; XTS_KEY_SIZE],
    sector_index: u128,
    sector_data: &mut [u8],
) -> Result<()> {
    if sector_data.len() < 16 {
        bail!("Sector data must be at least 16 bytes for XTS");
    }

    let tweak = get_tweak_default(sector_index);
    let cipher = Xts128::<Aes256>::new_from_slices(xts_key)
        .map_err(|e| anyhow::anyhow!("Failed to create XTS cipher: {}", e))?;

    cipher.decrypt_sector(sector_data, tweak);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*; // Импортируем все из родительского модуля
    // Нужно импортировать и функции шифрования для roundtrip теста
    use crate::encryption::{derive_key, encrypt_sector, generate_salt, split_derived_key};

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let password = b"super_secret_password";
        let salt = generate_salt();
        let derived_key = derive_key(password, &salt).expect("Key derivation failed");
        let (xts_key, _hmac_key) = split_derived_key(&derived_key).expect("Splitting key failed");

        let sector_index: u128 = 12345;
        let original_data = b"This is a test sector data block, must be long enough for XTS mode!".to_vec();
        let mut data_to_encrypt = original_data.clone();

        // Шифруем
        encrypt_sector(&xts_key, sector_index, &mut data_to_encrypt)
            .expect("Encryption failed");
        
        // Убедимся, что данные изменились
        assert_ne!(original_data, data_to_encrypt, "Encryption did not change data");

        // Расшифровываем
        let mut data_to_decrypt = data_to_encrypt;
        decrypt_sector(&xts_key, sector_index, &mut data_to_decrypt)
            .expect("Decryption failed");

        // Проверяем, что данные совпали с оригиналом
        assert_eq!(original_data, data_to_decrypt, "Decryption did not restore original data");
    }

    // TODO: Добавить другие тесты для decrypt_sector (граничные случаи, ошибки)
} 