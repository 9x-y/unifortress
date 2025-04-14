use anyhow::{bail, Result};
use xts_mode::{get_tweak_default, Xts128};
use aes::Aes256;
use hmac::digest::KeyInit;

/// Размер ключа AES-256
const AES256_KEY_SIZE: usize = 32;
/// Размер ключа XTS (два ключа AES-256)
pub const XTS_KEY_SIZE: usize = 64;

/// Шифрует сектор данных с использованием AES-256 XTS
pub fn encrypt_sector(
    sector_data: &mut [u8],
    sector_index: u64,
    xts_key: &[u8; XTS_KEY_SIZE]
) -> Result<()> {
    if sector_data.len() < 16 {
        bail!("Размер данных сектора должен быть не менее 16 байт для XTS");
    }

    let tweak = get_tweak_default(sector_index as u128);
    
    // Разделение ключа на две части (для AES-XTS нужны два ключа)
    let key_size = XTS_KEY_SIZE / 2;
    let key1 = &xts_key[..key_size];
    let key2 = &xts_key[key_size..];
    
    // Создание двух экземпляров Aes256
    let cipher1 = Aes256::new_from_slice(key1)
        .map_err(|e| anyhow::anyhow!("Ошибка создания первого шифра AES: {}", e))?;
    let cipher2 = Aes256::new_from_slice(key2)
        .map_err(|e| anyhow::anyhow!("Ошибка создания второго шифра AES: {}", e))?;
        
    // Создание XTS шифра
    let cipher = Xts128::new(cipher1, cipher2);

    cipher.encrypt_sector(sector_data, tweak);

    Ok(())
}

/// Расшифровывает сектор данных с использованием AES-256 XTS
pub fn decrypt_sector(
    sector_data: &mut [u8],
    sector_index: u64,
    xts_key: &[u8; XTS_KEY_SIZE]
) -> Result<()> {
    if sector_data.len() < 16 {
        bail!("Размер данных сектора должен быть не менее 16 байт для XTS");
    }

    let tweak = get_tweak_default(sector_index as u128);
    
    // Разделение ключа на две части (для AES-XTS нужны два ключа)
    let key_size = XTS_KEY_SIZE / 2;
    let key1 = &xts_key[..key_size];
    let key2 = &xts_key[key_size..];
    
    // Создание двух экземпляров Aes256
    let cipher1 = Aes256::new_from_slice(key1)
        .map_err(|e| anyhow::anyhow!("Ошибка создания первого шифра AES: {}", e))?;
    let cipher2 = Aes256::new_from_slice(key2)
        .map_err(|e| anyhow::anyhow!("Ошибка создания второго шифра AES: {}", e))?;
        
    // Создание XTS шифра
    let cipher = Xts128::new(cipher1, cipher2);

    cipher.decrypt_sector(sector_data, tweak);

    Ok(())
}

// Функция для создания двух ключей Aes256 из XTS ключа
fn create_aes_ciphers(key: &[u8; XTS_KEY_SIZE]) -> (Aes256, Aes256) {
    let key1 = Aes256::new_from_slice(&key[0..32]).expect("Неверная длина ключа");
    let key2 = Aes256::new_from_slice(&key[32..64]).expect("Неверная длина ключа");
    (key1, key2)
}

// Функция для шифрования блока данных в режиме XTS
pub fn encrypt_block(block: &mut [u8], tweak: u64, key: &[u8; XTS_KEY_SIZE]) -> Result<()> {
    // Создаем два шифра AES-256
    let (cipher1, cipher2) = create_aes_ciphers(key);
    
    // Создаем XTS шифратор
    let xts = Xts128::new(cipher1, cipher2);
    
    // Преобразуем tweak в u128 и создаем tweak value
    let tweak_value = get_tweak_default(tweak as u128);
    
    // Шифруем данные
    xts.encrypt_sector(block, tweak_value);
    
    Ok(())
}

// Функция для расшифрования блока данных в режиме XTS
pub fn decrypt_block(block: &mut [u8], tweak: u64, key: &[u8; XTS_KEY_SIZE]) -> Result<()> {
    // Создаем два шифра AES-256
    let (cipher1, cipher2) = create_aes_ciphers(key);
    
    // Создаем XTS шифратор
    let xts = Xts128::new(cipher1, cipher2);
    
    // Преобразуем tweak в u128 и создаем tweak value
    let tweak_value = get_tweak_default(tweak as u128);
    
    // Расшифровываем данные
    xts.decrypt_sector(block, tweak_value);
    
    Ok(())
} 