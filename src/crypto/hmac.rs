use anyhow::Result;
use hmac::{Hmac, Mac};
use sha2::Sha256;

// Тип для HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

// Константы
pub const HMAC_SIZE: usize = 32; // SHA-256 даёт 32 байта

/// Создаёт HMAC для данных с использованием указанного ключа
pub fn create_hmac(data: &[u8], key: &[u8]) -> Result<[u8; HMAC_SIZE]> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|e| anyhow::anyhow!("Error creating HMAC: {}", e))?;

    mac.update(data);

    let result = mac.finalize().into_bytes();
    if result.len() != HMAC_SIZE {
        return Err(anyhow::anyhow!("Invalid HMAC length, expected {} bytes", HMAC_SIZE));
    }

    let mut hmac_bytes = [0u8; HMAC_SIZE];
    hmac_bytes.copy_from_slice(&result[..HMAC_SIZE]);

    Ok(hmac_bytes)
} 