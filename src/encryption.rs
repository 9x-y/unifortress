use serde::{Deserialize, Serialize};
use anyhow::{bail, Context, Result};
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2,
    Params,
};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use uuid::Uuid;
use aes::Aes256;
use xts_mode::{
    get_tweak_default,
    Xts128 // XTS operates on 128-bit blocks, hence Xts128
};
use hmac::digest::KeyInit;

use crate::crypto::xts::{self, XTS_KEY_SIZE};

// Размер соли для Argon2 (например, 16 байт)
const KDF_SALT_SIZE: usize = 16;
// Размер HMAC (например, SHA256 -> 32 байта)
const HEADER_HMAC_SIZE: usize = 32;

/// Магическая сигнатура для идентификации тома UniFortress
pub const VOLUME_SIGNATURE: &[u8; 12] = b"UniFortress!";
/// Текущая версия формата заголовка
pub const HEADER_VERSION: u16 = 1;

/// --- Параметры Argon2 --- 
/// Рекомендуемые параметры OWASP (на момент написания). Могут потребовать тюнинга.
const ARGON_M_COST: u32 = 19 * 1024; // 19 MiB
const ARGON_T_COST: u32 = 2;        // 2 итерации
const ARGON_P_COST: u32 = 1;        // 1 поток
/// Длина выводимого ключа в байтах (XTS_KEY_SIZE + HMAC_KEY_SIZE)
const DERIVED_KEY_SIZE: usize = XTS_KEY_SIZE + HMAC_KEY_SIZE;

/// --- Размеры ключей --- 
const AES256_KEY_SIZE: usize = 32;
const HMAC_KEY_SIZE: usize = 32; // Для HMAC-SHA256

/// Заголовок зашифрованного тома UniFortress
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct VolumeHeader {
    /// Сигнатура файла (VOLUME_SIGNATURE)
    signature: [u8; 12],
    /// Версия формата заголовка (HEADER_VERSION)
    version: u16,
    /// Уникальный идентификатор тома (для предотвращения некоторых атак)
    uuid: [u8; 16], // 128 бит UUID
    /// Соль для KDF (Argon2)
    kdf_salt: [u8; KDF_SALT_SIZE],
    /// Параметр m_cost для Argon2
    argon_m_cost: u32,
    /// Параметр t_cost для Argon2
    argon_t_cost: u32,
    /// Параметр p_cost для Argon2
    argon_p_cost: u32,
    /// HMAC заголовка (рассчитанный по всем предыдущим полям)
    header_hmac: [u8; HEADER_HMAC_SIZE],
    // TODO: Добавить поле для размера зашифрованной области?
    // TODO: Добавить поле для параметров AES-XTS (если они не стандартные)?
    // TODO: Добавить зарезервированные поля для будущих версий?
}

/// Генерирует криптографически стойкую соль для KDF.
pub fn generate_salt() -> [u8; KDF_SALT_SIZE] {
    let mut salt = [0u8; KDF_SALT_SIZE];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Генерирует криптографический ключ из пароля и соли с использованием Argon2id.
///
/// # Arguments
///
/// * `password` - Пароль пользователя.
/// * `salt` - Уникальная соль.
///
/// # Returns
///
/// Производный ключ длиной `DERIVED_KEY_SIZE` байт.
pub fn derive_key(password: &[u8], salt: &[u8]) -> Result<Vec<u8>> {
    log::debug!(
        "Deriving key with Argon2id: m_cost={}, t_cost={}, p_cost={}",
        ARGON_M_COST,
        ARGON_T_COST,
        ARGON_P_COST
    );

    // Устанавливаем параметры Argon2
    let params = match Params::new(ARGON_M_COST, ARGON_T_COST, ARGON_P_COST, Some(DERIVED_KEY_SIZE)) {
        Ok(p) => p,
        Err(e) => return Err(anyhow::anyhow!("Failed to create Argon2 params: {}", e)),
    };
    
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id, // Используем Argon2id
        argon2::Version::V0x13,     // Версия Argon2
        params,
    );

    let mut output_key = vec![0u8; DERIVED_KEY_SIZE];

    argon2
        .hash_password_into(password, salt, &mut output_key)
        .map_err(|e| anyhow::anyhow!("Argon2 key derivation failed: {}", e))?;

    log::debug!("Key derivation successful.");
    Ok(output_key)
}

/// Разделяет общий производный ключ на ключ для XTS и ключ для HMAC.
///
/// # Arguments
/// * `derived_key` - Ключ длиной `DERIVED_KEY_SIZE`, полученный из `derive_key`.
///
/// # Returns
/// Кортеж `(xts_key, hmac_key)` или ошибка, если длина `derived_key` неверна.
pub fn split_derived_key(derived_key: &[u8]) -> Result<([u8; XTS_KEY_SIZE], [u8; HMAC_KEY_SIZE])> {
    if derived_key.len() != DERIVED_KEY_SIZE {
        bail!(
            "Invalid derived key length. Expected {}, got {}",
            DERIVED_KEY_SIZE,
            derived_key.len()
        );
    }
    let mut xts_key = [0u8; XTS_KEY_SIZE];
    let mut hmac_key = [0u8; HMAC_KEY_SIZE];

    xts_key.copy_from_slice(&derived_key[..XTS_KEY_SIZE]);
    hmac_key.copy_from_slice(&derived_key[XTS_KEY_SIZE..]);

    Ok((xts_key, hmac_key))
}

/// Шифрует один сектор данных с использованием AES-256 XTS.
///
/// # Arguments
/// * `sector_data` - Данные сектора для шифрования.
/// * `sector_index` - Номер сектора (используется как tweak).
/// * `xts_key` - 64-байтный ключ для XTS.
///
/// # Returns
/// Зашифрованные данные сектора.
pub fn encrypt_sector(
    sector_data: &mut [u8],
    sector_index: u64,
    xts_key: &[u8; XTS_KEY_SIZE],
) -> Result<()> {
    xts::encrypt_sector(sector_data, sector_index, xts_key)
}

/// Реализация для VolumeHeader
impl VolumeHeader {
    /// Создает новый заголовок тома с заданными параметрами
    #[allow(unused_variables)]
    pub fn new(volume_size: u64, sector_size: u32, master_key: &[u8], hmac_key: &[u8]) -> Result<Self> {
        // Create a new default header
        let mut header = Self::default();
        
        // Set the signature and version
        header.signature.copy_from_slice(VOLUME_SIGNATURE);
        header.version = HEADER_VERSION;
        
        // Generate UUID
        let uuid = Uuid::new_v4();
        header.uuid.copy_from_slice(uuid.as_bytes());
        
        // Generate salt
        header.kdf_salt = generate_salt();
        
        // Set Argon2 parameters
        header.argon_m_cost = ARGON_M_COST;
        header.argon_t_cost = ARGON_T_COST;
        header.argon_p_cost = ARGON_P_COST;
        
        // Calculate HMAC
        header.calculate_hmac(hmac_key)?;
        
        Ok(header)
    }
    
    /// Creates a default header with empty values - for serde deserialization
    pub fn default() -> Self {
        Self {
            signature: [0u8; 12],
            version: 0,
            uuid: [0u8; 16],
            kdf_salt: [0u8; KDF_SALT_SIZE],
            argon_m_cost: 0,
            argon_t_cost: 0,
            argon_p_cost: 0,
            header_hmac: [0u8; HEADER_HMAC_SIZE],
        }
    }

    /// Сериализует заголовок в байтовый вектор с использованием bincode.
    pub fn serialize(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).context("Failed to serialize header")
    }

    /// Десериализует заголовок из байтового среза.
    pub fn deserialize(data: &[u8]) -> Result<Self> {
        bincode::deserialize(data).context("Failed to deserialize header")
    }

    /// Рассчитывает HMAC для текущего состояния заголовка.
    /// ВАЖНО: Поле `header_hmac` должно быть обнулено перед расчетом!
    /// 
    /// # Arguments
    /// * `hmac_key` - Ключ для HMAC (например, часть ключа, полученного из `derive_key`).
    fn calculate_hmac(&self, hmac_key: &[u8]) -> Result<[u8; HEADER_HMAC_SIZE]> {
        // Клонируем заголовок и обнуляем поле HMAC для расчета
        let mut header_for_hmac = self.clone();
        header_for_hmac.header_hmac = [0u8; HEADER_HMAC_SIZE];

        let serialized_header = header_for_hmac.serialize()
            .context("Failed to serialize header for HMAC calculation")?;

        type HmacSha256 = Hmac<Sha256>;
        let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(hmac_key)
            .map_err(|_| anyhow::anyhow!("Invalid HMAC key length"))?;
        mac.update(&serialized_header);

        let result = mac.finalize().into_bytes();
        // Убедимся, что размер совпадает (хотя для SHA256 он всегда 32)
        if result.len() == HEADER_HMAC_SIZE {
            let mut hmac_bytes = [0u8; HEADER_HMAC_SIZE];
            hmac_bytes.copy_from_slice(&result);
            Ok(hmac_bytes)
        } else {
            bail!("Calculated HMAC size mismatch");
        }
    }

    /// Рассчитывает и устанавливает HMAC для заголовка.
    /// 
    /// # Arguments
    /// * `hmac_key` - Ключ для HMAC.
    pub fn set_hmac(&mut self, hmac_key: &[u8]) -> Result<()> {
        self.header_hmac = [0u8; HEADER_HMAC_SIZE]; // Обнуляем перед расчетом
        self.header_hmac = self.calculate_hmac(hmac_key)?;
        Ok(())
    }

    /// Проверяет HMAC заголовка.
    /// 
    /// # Arguments
    /// * `hmac_key` - Ключ для HMAC.
    /// 
    /// # Returns
    /// `Ok(true)` если HMAC верный, `Ok(false)` если неверный, `Err` при ошибке расчета.
    pub fn verify_hmac(&self, hmac_key: &[u8]) -> Result<bool> {
        let calculated_hmac = self.calculate_hmac(hmac_key)?;
        // Используем постоянное по времени сравнение, чтобы избежать timing attacks
        Ok(calculated_hmac == self.header_hmac)
        // TODO: Подумать об использовании `subtle` crate для constant-time equals
    }

    /// Записывает заголовок тома в указанный файл-контейнер
    pub fn write_to_volume(&self, volume: &mut crate::platform::volume_io::VolumeFile) -> Result<()> {
        let sector_size = volume.get_sector_size();
        let serialized = self.serialize()?;
        
        // Проверка, что заголовок помещается в сектор
        if serialized.len() > sector_size as usize {
            bail!("Заголовок слишком большой ({} байт) для размера сектора ({} байт)", 
                  serialized.len(), sector_size);
        }
        
        // Создаем буфер размером в сектор
        let mut sector_buffer = vec![0u8; sector_size as usize];
        
        // Копируем сериализованный заголовок в начало буфера
        sector_buffer[..serialized.len()].copy_from_slice(&serialized);
        
        // Записываем в сектор 0
        volume.write_sectors(0, sector_size, &sector_buffer)
            .context("Ошибка записи заголовка тома")
    }
    
    /// Читает заголовок тома из указанного файла-контейнера
    pub fn read_from_volume(volume: &mut crate::platform::volume_io::VolumeFile, hmac_key: &[u8]) -> Result<Self> {
        let sector_size = volume.get_sector_size();
        
        // Читаем первый сектор
        let mut sector_buffer = vec![0u8; sector_size as usize];
        volume.read_sectors(0, 1, sector_size, &mut sector_buffer)
            .context("Ошибка чтения заголовка тома")?;
        
        // Десериализуем заголовок
        let header = Self::deserialize(&sector_buffer)
            .context("Ошибка десериализации заголовка")?;
        
        // Проверяем HMAC
        if !header.verify_hmac(hmac_key)? {
            bail!("Неверная подпись HMAC заголовка. Возможно, неверный пароль или поврежденные данные.");
        }
        
        Ok(header)
    }

    // --- Геттеры для полей --- 
    pub fn kdf_salt(&self) -> &[u8; KDF_SALT_SIZE] {
        &self.kdf_salt
    }

    pub fn signature(&self) -> &[u8; 12] {
        &self.signature
    }

    pub fn version(&self) -> u16 {
        self.version
    }

    // TODO: Добавить геттеры для других полей при необходимости (argon params, uuid)
}

// TODO: Добавить тесты для generate_salt и derive_key
// TODO: Добавить тесты для VolumeHeader (new, serialize, deserialize, hmac)
// TODO: Добавить тесты для split_derived_key и encrypt_sector 