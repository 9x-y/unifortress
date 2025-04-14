use anyhow::Result;
use argon2::{
    password_hash::SaltString,
    Argon2, PasswordHasher
};
use rand_core::{OsRng, RngCore};

// Константы для KDF
pub const KDF_SALT_SIZE: usize = 16;
pub const DERIVED_KEY_SIZE: usize = 64; // 32 для AES-256 и 32 для HMAC-SHA256

/// Генерирует случайную соль для KDF
pub fn generate_salt() -> [u8; KDF_SALT_SIZE] {
    let mut salt = [0u8; KDF_SALT_SIZE];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Получает производный ключ из пароля и соли
pub fn derive_key(password: &[u8], salt: &[u8; KDF_SALT_SIZE]) -> Result<[u8; DERIVED_KEY_SIZE]> {
    // Создаем соль в формате, требуемом Argon2
    let salt = SaltString::encode_b64(salt)
        .map_err(|e| anyhow::anyhow!("Error encoding salt: {}", e))?;

    // Настраиваем Argon2 с параметрами по умолчанию
    let argon2 = Argon2::default();
    
    // Получаем хеш
    let password_hash = argon2
        .hash_password(password, &salt)
        .map_err(|e| anyhow::anyhow!("Error hashing password: {}", e))?
        .hash
        .ok_or_else(|| anyhow::anyhow!("No hash value produced"))?;

    // Преобразуем хеш в массив байтов нужной длины
    let hash_bytes = password_hash.as_bytes();
    if hash_bytes.len() < DERIVED_KEY_SIZE {
        return Err(anyhow::anyhow!("Hash too short, expected at least {} bytes", DERIVED_KEY_SIZE));
    }

    let mut result = [0u8; DERIVED_KEY_SIZE];
    result.copy_from_slice(&hash_bytes[..DERIVED_KEY_SIZE]);
    
    Ok(result)
}

/// Разделяет производный ключ на ключ шифрования и ключ HMAC
pub fn split_derived_key(derived_key: &[u8; DERIVED_KEY_SIZE]) -> (
    [u8; DERIVED_KEY_SIZE / 2],  // Ключ шифрования
    [u8; DERIVED_KEY_SIZE / 2],  // Ключ HMAC
) {
    let mut encryption_key = [0u8; DERIVED_KEY_SIZE / 2];
    let mut hmac_key = [0u8; DERIVED_KEY_SIZE / 2];
    
    encryption_key.copy_from_slice(&derived_key[..DERIVED_KEY_SIZE / 2]);
    hmac_key.copy_from_slice(&derived_key[DERIVED_KEY_SIZE / 2..]);
    
    (encryption_key, hmac_key)
} 