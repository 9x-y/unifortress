use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use anyhow::{anyhow, Result};

// Размер ключа ChaCha20Poly1305
pub const CHACHA_KEY_SIZE: usize = 32;

/// Шифрует блок данных с использованием ChaCha20-Poly1305
/// 
/// # Arguments
/// * `data` - Данные для шифрования
/// * `sector_index` - Индекс сектора (используется для создания уникального nonce)
/// * `key` - 32-байтовый ключ для ChaCha20
/// 
/// # Returns
/// Результат шифрования или ошибку
pub fn encrypt_block(data: &mut [u8], sector_index: u64, key: &[u8]) -> Result<()> {
    if key.len() != CHACHA_KEY_SIZE {
        return Err(anyhow!("Invalid key size: expected {}, got {}", CHACHA_KEY_SIZE, key.len()));
    }

    // Минимальная длина данных для шифрования
    if data.len() < 16 {
        return Err(anyhow!("Data too small for encryption: {} bytes", data.len()));
    }

    // Создаем шифр ChaCha20-Poly1305
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| anyhow!("Failed to create ChaCha20Poly1305 cipher: {}", e))?;

    // Создаем nonce из индекса сектора (12 байт)
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[0..8].copy_from_slice(&sector_index.to_le_bytes());
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Шифруем данные
    let encrypted = cipher.encrypt(nonce, data.as_ref())
        .map_err(|e| anyhow!("Encryption failed: {}", e))?;
    
    // Копируем зашифрованные данные обратно в буфер
    data.copy_from_slice(&encrypted);
    
    Ok(())
}

/// Расшифровывает блок данных с использованием ChaCha20-Poly1305
/// 
/// # Arguments
/// * `data` - Зашифрованные данные для расшифровки
/// * `sector_index` - Индекс сектора (используется для создания уникального nonce)
/// * `key` - 32-байтовый ключ для ChaCha20
/// 
/// # Returns
/// Результат расшифровки или ошибку
pub fn decrypt_block(data: &mut [u8], sector_index: u64, key: &[u8]) -> Result<()> {
    if key.len() != CHACHA_KEY_SIZE {
        return Err(anyhow!("Invalid key size: expected {}, got {}", CHACHA_KEY_SIZE, key.len()));
    }

    // Минимальная длина данных для расшифровки
    if data.len() < 16 {
        return Err(anyhow!("Data too small for decryption: {} bytes", data.len()));
    }

    // Создаем шифр ChaCha20-Poly1305
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| anyhow!("Failed to create ChaCha20Poly1305 cipher: {}", e))?;

    // Создаем nonce из индекса сектора (12 байт)
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[0..8].copy_from_slice(&sector_index.to_le_bytes());
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Расшифровываем данные
    let decrypted = cipher.decrypt(nonce, data.as_ref())
        .map_err(|e| anyhow!("Decryption failed: {}", e))?;
    
    // Копируем расшифрованные данные обратно в буфер
    data.copy_from_slice(&decrypted);
    
    Ok(())
} 