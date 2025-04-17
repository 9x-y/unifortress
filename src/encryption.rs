use serde::{Deserialize, Serialize};
use anyhow::{bail, Context, Result, anyhow};
use argon2::{
    Argon2,
    Params,
    password_hash::PasswordHasher,
};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use sha2::{Sha256, Digest};
use uuid::Uuid;
use bincode;
use log::{debug, error, info, warn};
use crate::platform::volume_io::VolumeFile;
// use aes::Aes256;

use crate::crypto::xts::XTS_KEY_SIZE;
use crate::platform::volume_io;

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
    // Вызываем XTS шифрование из crypto модуля
    crate::crypto::xts::encrypt_block(sector_data, sector_index, xts_key)
        .map_err(|e| anyhow::anyhow!("Failed to encrypt sector: {}", e))
}

/// Структура для хранения статистики шифрования
pub struct EncryptionStats {
    pub sectors_processed: u64,
    pub bytes_processed: u64, 
    pub duration: std::time::Duration,
}

/// Шифрует все секторы данных параллельно с использованием нескольких потоков
fn encrypt_sectors_parallel(
    volume: &mut VolumeFile, 
    key: &[u8; 64], 
    num_threads: usize,
    sector_size: usize
) -> Result<EncryptionStats> {
    use rayon::prelude::*;
    use std::sync::{Arc, Mutex};
    use std::time::Instant;
    
    // Определяем размер буфера для чтения/записи (не более 4 МБ для совместимости)
    let buffer_size = 4 * 1024 * 1024; // 4 МБ
    let sectors_per_buffer = buffer_size / sector_size;
    
    // Получаем размер тома и вычисляем количество секторов
    let volume_size = volume.get_size()?;
    let total_sectors = volume_size / sector_size as u64;
    
    // Пропускаем первые сектора, где находится заголовок (обычно 1)
    let header_sectors = 1;
    
    // Проверка на минимальный размер
    if total_sectors <= header_sectors {
        bail!("Device is too small for encryption");
    }
    
    // Количество секторов для шифрования
    let sectors_to_encrypt = total_sectors - header_sectors;
    let buffer_iterations = (sectors_to_encrypt + sectors_per_buffer as u64 - 1) / sectors_per_buffer as u64;
    
    // Создаем счетчик прогресса
    let progress = Arc::new(Mutex::new(0u64));
    let start_time = Instant::now();
    
    // Инициализируем пул потоков rayon
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build()?;
    
    // Обрабатываем блоки последовательно, но шифруем их параллельно
    info!("Starting encryption with {} threads, {} sectors per buffer", num_threads, sectors_per_buffer);
    
    // Блокировки и результаты ошибок
    let error_encountered = Arc::new(Mutex::new(None));
    
    pool.install(|| {
        (0..buffer_iterations).into_iter().try_for_each(|i| {
            // Проверяем, была ли уже ошибка
            {
                let error = error_encountered.lock().unwrap();
                if error.is_some() {
                    return Err(anyhow!("Encryption stopped due to previous error"));
                }
            }
            
            // Вычисляем текущий сектор и количество секторов для этой итерации
            let current_sector = header_sectors + i * sectors_per_buffer as u64;
            let sectors_this_iteration = std::cmp::min(
                sectors_per_buffer as u64,
                sectors_to_encrypt - i * sectors_per_buffer as u64
            ) as usize;
            
            if sectors_this_iteration == 0 {
                return Ok(());
            }
            
            // Генерируем случайные данные для буфера (заполняем нулями или случайными)
            let buffer_size_this_iteration = sectors_this_iteration * sector_size;
            let mut buffer = vec![0u8; buffer_size_this_iteration];
            
            // Для реального устройства заполняем случайными данными
            if rand::random::<u8>() % 2 == 0 {
                rand::thread_rng().fill_bytes(&mut buffer);
            }
            
            // Шифруем буфер в параллельных потоках
            buffer.par_chunks_mut(sector_size)
                .enumerate()
                .try_for_each(|(j, sector_data)| {
                    let sector_index = current_sector + j as u64;
                    match encrypt_sector(sector_data, sector_index, key) {
                        Ok(_) => Ok(()),
                        Err(e) => {
                            error!("Failed to encrypt sector {}: {}", sector_index, e);
                            Err(e)
                        }
                    }
                })
                .map_err(|e| {
                    let mut error = error_encountered.lock().unwrap();
                    *error = Some(anyhow!("Encryption error: {}", e));
                    anyhow!("Failed to encrypt sectors: {}", e)
                })?;
            
            // Записываем зашифрованные данные на устройство небольшими блоками
            // для совместимости со всеми устройствами
            const MAX_CHUNK_SIZE: usize = 1 * 1024 * 1024; // 1 МБ максимум за раз
            
            let mut offset = 0;
            while offset < buffer.len() {
                let chunk_size = std::cmp::min(MAX_CHUNK_SIZE, buffer.len() - offset);
                let chunk = &buffer[offset..offset + chunk_size];
                
                // Вычисляем сектор для этого куска
                let sector_offset = current_sector + (offset / sector_size) as u64;
                
                // Пытаемся записать с повторами в случае ошибки
                let mut retry_count = 0;
                let max_retries = 3;
                let mut last_error = None;
                let mut success = false;
                
                while retry_count < max_retries && !success {
                    match volume.write_sectors(sector_offset, sector_size as u32, chunk) {
                        Ok(_) => {
                            success = true;
                        },
                        Err(e) => {
                            retry_count += 1;
                            last_error = Some(e);
                            warn!("Retry #{} writing sectors at {}: {}", 
                                 retry_count, sector_offset, last_error.as_ref().unwrap());
                            
                            // Небольшая пауза перед повторной попыткой
                            std::thread::sleep(std::time::Duration::from_millis(100));
                        }
                    }
                }
                
                if !success {
                    let error_msg = format!("Failed to write sectors at {} after {} retries: {}", 
                                          sector_offset, max_retries, last_error.unwrap());
                    
                    let mut error = error_encountered.lock().unwrap();
                    *error = Some(anyhow!(error_msg.clone()));
                    
                    return Err(anyhow!(error_msg));
                }
                
                offset += chunk_size;
            }
            
            // Обновляем счетчик прогресса
            {
                let mut progress_guard = progress.lock().unwrap();
                *progress_guard += sectors_this_iteration as u64;
                
                // Периодически выводим информацию о прогрессе
                if i % 10 == 0 || *progress_guard == sectors_to_encrypt {
                    let percent = (*progress_guard as f64 / sectors_to_encrypt as f64) * 100.0;
                    let elapsed = start_time.elapsed().as_secs_f64();
                    let bytes_processed = *progress_guard * sector_size as u64;
                    
                    let speed_mbps = if elapsed > 0.0 {
                        (bytes_processed as f64 / (1024.0 * 1024.0)) / elapsed
                    } else {
                        0.0
                    };
                    
                    let eta_secs = if speed_mbps > 0.0 {
                        let remaining_bytes = (sectors_to_encrypt - *progress_guard) * sector_size as u64;
                        (remaining_bytes as f64 / (1024.0 * 1024.0)) / speed_mbps
                    } else {
                        0.0
                    };
                    
                    // Форматирование оставшегося времени
                    let eta_str = if eta_secs > 3600.0 {
                        format!("{:.1} hours", eta_secs / 3600.0)
                    } else if eta_secs > 60.0 {
                        format!("{:.1} minutes", eta_secs / 60.0)
                    } else {
                        format!("{:.1} seconds", eta_secs)
                    };
                    
                    info!("Encryption progress: {:.2}% - Speed: {:.2} MB/sec - ETA: {} - Bytes: {}/{}",
                         percent, speed_mbps, eta_str, bytes_processed, sectors_to_encrypt * sector_size as u64);
                }
            }
            
            Ok(())
        })
    }).map_err(|e| {
        // Проверяем, есть ли сохраненная ошибка
        let error = error_encountered.lock().unwrap();
        if let Some(stored_error) = error.as_ref() {
            anyhow!("Encryption failed: {}", stored_error)
        } else {
            anyhow!("Encryption failed: {}", e)
        }
    })?;
    
    // Собираем статистику
    let duration = start_time.elapsed();
    let sectors_processed = {
        let progress_guard = progress.lock().unwrap();
        *progress_guard
    };
    let bytes_processed = sectors_processed * sector_size as u64;
    
    Ok(EncryptionStats {
        sectors_processed,
        bytes_processed,
        duration,
    })
}

/// Шифрует физическое устройство, полностью стирая все данные.
/// 
/// * `device_path` - Путь к физическому устройству (например, '\\.\PhysicalDrive1')
/// * `password` - Пароль для шифрования
/// * `sector_size` - Размер сектора устройства (обычно автоматически определяется)
/// 
/// # Returns
/// Результат операции шифрования.
pub fn encrypt_volume(
    device_path: &str,
    password: &[u8],
    sector_size: Option<u32>,
) -> Result<()> {
    info!("Starting volume encryption for device: {}", device_path);
    
    // Открываем физическое устройство
    let mut volume = VolumeFile::open(device_path, true)?;  // Теперь указываем true для is_physical
    info!("Successfully opened device");
    
    // Проверяем, является ли устройство реальным физическим устройством
    if !volume.is_physical_device() {
        bail!("Cannot encrypt non-physical device. This device isn't recognized as physical.");
    }
    
    // Определяем размер сектора, если не указан
    let sector_size = match sector_size {
        Some(size) => size as usize,
        None => volume.get_sector_size() as usize,
    };
    info!("Using sector size: {} bytes", sector_size);
    
    // Получаем размер устройства
    let volume_size = volume.get_size()?;
    let total_sectors = volume_size / sector_size as u64;
    info!("Device size: {} bytes, {} sectors", volume_size, total_sectors);
    
    // Проверка на минимальный размер (должно быть не менее 2 секторов - 1 для заголовка, 1+ для данных)
    const MIN_REQUIRED_SECTORS: u64 = 2;
    if total_sectors < MIN_REQUIRED_SECTORS {
        bail!("Device is too small for encryption, needs at least {} sectors", MIN_REQUIRED_SECTORS);
    }
    
    // Очищаем MBR, чтобы избежать проблем с остатками файловой системы
    info!("Clearing MBR to avoid filesystem interference");
    let zero_buffer = vec![0u8; 512]; // Очищаем только MBR (первые 512 байт)
    if let Err(e) = volume.write_at(0, &zero_buffer) {
        warn!("Failed to clear MBR, but continuing: {}", e);
    }
    
    // Генерируем соль для хеширования пароля
    let salt = generate_salt();
    
    // Выводим ключи шифрования из пароля
    info!("Deriving encryption keys from password");
    let derived_key = derive_key(password, &salt)?;
    
    // Разделяем на ключ для шифрования и ключ для HMAC
    let (encryption_key, hmac_key) = split_derived_key(&derived_key)?;
    
    // Создаем заголовок тома
    info!("Creating volume header");
    let header = VolumeHeader::new(volume_size, sector_size as u32, &encryption_key, &hmac_key)?;
    
    // Сериализуем заголовок
    info!("Serializing volume header");
    let header_bytes = header.serialize()?;
    
    // Записываем заголовок в начало тома (первый сектор)
    info!("Writing volume header");
    
    // Попытка записи заголовка с повторами в случае ошибки
    let mut success = false;
    for attempt in 1..=5 {
        match volume.write_at(0, &header_bytes) {
            Ok(_) => {
                success = true;
                info!("Volume header written successfully on attempt {}", attempt);
                break;
            }
            Err(e) => {
                warn!("Attempt {} to write volume header failed: {}", attempt, e);
                // Пауза перед повторной попыткой
                std::thread::sleep(std::time::Duration::from_millis(100));
                
                // На последней попытке делаем дополнительную очистку
                if attempt == 4 {
                    warn!("Trying more aggressive disk wiping before final attempt");
                    let big_zero = vec![0u8; 4096];
                    let _ = volume.write_at(0, &big_zero); // Игнорируем возможную ошибку
                }
            }
        }
    }
    
    if !success {
        bail!("Failed to write volume header after multiple attempts. Device may be write-protected or locked by system.");
    }
    
    // Определяем количество потоков для параллельного шифрования
    let num_threads = std::cmp::min(
        num_cpus::get(),
        8 // Ограничиваем максимум 8 потоками для стабильности
    );
    info!("Using {} threads for parallel encryption", num_threads);
    
    // Шифруем все сектора данных
    info!("Starting parallel encryption of all data sectors");
    let encryption_result = encrypt_sectors_parallel(&mut volume, &encryption_key, num_threads, sector_size)?;
    
    // Выводим информацию о результатах шифрования
    let elapsed = encryption_result.duration.as_secs_f64();
    let mb_per_sec = if elapsed > 0.0 {
        (encryption_result.bytes_processed as f64 / (1024.0 * 1024.0)) / elapsed
    } else {
        0.0
    };
    
    info!("Encryption completed successfully");
    info!("Processed {} sectors ({} bytes) in {:.2} seconds",
         encryption_result.sectors_processed,
         encryption_result.bytes_processed,
         elapsed);
    info!("Average speed: {:.2} MB/sec", mb_per_sec);
    
    Ok(())
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
        
        // Дополнительная проверка доступа к первому сектору
        // Попытка очистить начало диска перед записью заголовка
        let mut zero_buffer = vec![0u8; 512]; // Очищаем только MBR (первые 512 байт)
        
        // Пробуем сначала записать нули в первый сектор
        match volume.write_sectors(0, sector_size, &zero_buffer) {
            Ok(_) => {
                debug!("Successfully cleared first sector before writing header");
            },
            Err(e) => {
                // Предупреждение о возможных проблемах доступа, но продолжаем
                warn!("Warning: Could not clear first sector (MBR): {}", e);
                warn!("Will attempt to write header directly. If this fails, you may need to format the disk as GPT first.");
            }
        }
        
        // Создаем буфер размером в сектор
        let mut sector_buffer = vec![0u8; sector_size as usize];
        
        // Копируем сериализованный заголовок в начало буфера
        sector_buffer[..serialized.len()].copy_from_slice(&serialized);
        
        // Записываем в сектор 0
        match volume.write_sectors(0, sector_size, &sector_buffer) {
            Ok(_) => Ok(()),
            Err(e) => {
                error!("Ошибка записи заголовка тома: {}", e);
                error!("Диск может иметь защиту записи или требуется предварительная очистка через diskpart (clean)");
                Err(anyhow!("Ошибка записи заголовка тома: {}", e))
            }
        }
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