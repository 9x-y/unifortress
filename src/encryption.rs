use serde::{Deserialize, Serialize};
use anyhow::{bail, Context, Result};
use argon2::{
    Argon2,
    Params,
};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use uuid::Uuid;
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

/// Шифрует полное устройство/том с заданным паролем.
///
/// # Arguments
/// * `device_path` - Путь к устройству, которое нужно зашифровать.
/// * `password` - Пароль для шифрования.
///
/// # Returns
/// Ok(()) при успешном шифровании или ошибку.
pub fn encrypt_volume(device_path: &str, password: &str) -> Result<()> {
    // Import rayon for parallel processing and tokio for async IO
    use rayon::prelude::*;
    use std::sync::{Arc, Mutex};
    use tokio::runtime::Runtime;
    use tokio::sync::Semaphore;
    use futures::stream::{StreamExt, FuturesUnordered};
    
    // Create tokio runtime for async operations
    let rt = Runtime::new()
        .context("Failed to create tokio runtime")?;
    
    // Execute async encryption process in the tokio runtime
    rt.block_on(async {
        // Открываем устройство
        let mut volume = volume_io::open_device(device_path)?;
        
        // Получаем параметры устройства
        let volume_size = volume.get_size()?;
        let sector_size = volume.get_sector_size();
        
        // Генерируем соль
        let salt = generate_salt();
        
        // Выводим ключ из пароля
        let derived_key = derive_key(password.as_bytes(), &salt)?;
        
        // Разделяем ключ на XTS ключ и HMAC ключ
        let (xts_key, hmac_key) = split_derived_key(&derived_key)?;
        
        // Создаем заголовок тома
        let header = VolumeHeader::new(volume_size, sector_size, &xts_key, &hmac_key)?;
        
        // Записываем заголовок в устройство
        header.write_to_volume(&mut volume)?;
        
        // Увеличим размер буфера для более эффективного I/O
        let buffer_size = 16 * 1024 * 1024; // 16 МБ
        let sectors_per_buffer = buffer_size / sector_size as usize;
        
        // Вычисляем, сколько секторов нужно зашифровать (за вычетом заголовка)
        let header_sectors = 1; // Сейчас заголовок занимает 1 сектор
        let total_sectors = volume_size / sector_size as u64;
        
        if total_sectors <= header_sectors {
            bail!("Устройство слишком маленькое для шифрования");
        }
        
        // Шифруем секторы данных
        let sectors_to_encrypt = total_sectors - header_sectors;
        let buffer_iterations = (sectors_to_encrypt + sectors_per_buffer as u64 - 1) / sectors_per_buffer as u64;
        
        log::info!("Starting encryption of {} sectors (sector size: {} bytes)...", 
                   sectors_to_encrypt, sector_size);
        
        // Create a thread-safe reference to the XTS key and volume
        let xts_key = Arc::new(xts_key);
        let volume = Arc::new(Mutex::new(volume));
        
        // Create a thread-safe progress counter
        let progress_counter = Arc::new(Mutex::new(0u64));
        let encrypted_bytes = Arc::new(Mutex::new(0u64));
        let start_time = std::time::Instant::now();
        let total_bytes = sectors_to_encrypt * sector_size as u64;
        let total_iterations = buffer_iterations;
        
        // Limit concurrent async tasks with a semaphore
        let semaphore = Arc::new(Semaphore::new(8)); // Limit to 8 concurrent writes
        
        // Setup progress reporting in a separate task
        let progress_counter_clone = Arc::clone(&progress_counter);
        let encrypted_bytes_clone = Arc::clone(&encrypted_bytes);
        
        log::info!("Total data to encrypt: {:.2} GB", total_bytes as f64 / 1_073_741_824.0);
        
        let progress_task = tokio::spawn(async move {
            let mut last_progress_percent = 0.0;
            let mut last_update = std::time::Instant::now();
            let mut last_bytes = 0u64;
            
            loop {
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                let current = *progress_counter_clone.lock().unwrap();
                let current_bytes = *encrypted_bytes_clone.lock().unwrap();
                let elapsed = start_time.elapsed().as_secs_f64();
                
                if current >= total_iterations {
                    // Calculate final speed
                    let speed_mb_sec = if elapsed > 0.0 {
                        (current_bytes as f64 / 1_048_576.0) / elapsed
                    } else {
                        0.0
                    };
                    
                    log::info!("Encryption progress: 100.0% - Completed in {:.1} seconds ({:.2} MB/sec)",
                               elapsed, speed_mb_sec);
                    break;
                }
                
                let progress = current_bytes as f64 / total_bytes as f64 * 100.0;
                let now = std::time::Instant::now();
                let update_interval = now.duration_since(last_update).as_secs_f64();
                
                // Update progress more frequently - every 0.1% change or every 100ms
                if (progress - last_progress_percent).abs() >= 0.1 || update_interval >= 0.1 {
                    // Calculate speed in MB/sec
                    let bytes_since_last = current_bytes - last_bytes;
                    let speed_mb_sec = if update_interval > 0.0 {
                        (bytes_since_last as f64 / 1_048_576.0) / update_interval
                    } else {
                        0.0
                    };
                    
                    // Estimate time remaining
                    let remaining_bytes = total_bytes - current_bytes;
                    let remaining_secs = if speed_mb_sec > 0.0 {
                        (remaining_bytes as f64 / 1_048_576.0) / speed_mb_sec
                    } else {
                        0.0
                    };
                    
                    // Format remaining time
                    let remaining_fmt = if remaining_secs > 60.0 * 60.0 {
                        format!("{:.1} hours", remaining_secs / 3600.0)
                    } else if remaining_secs > 60.0 {
                        format!("{:.1} minutes", remaining_secs / 60.0)
                    } else {
                        format!("{:.1} seconds", remaining_secs)
                    };
                    
                    log::info!("Encryption progress: {:.3}% - Speed: {:.2} MB/sec - ETA: {} - Bytes: {}/{}", 
                               progress, speed_mb_sec, remaining_fmt, current_bytes, total_bytes);
                    
                    last_progress_percent = progress;
                    last_update = now;
                    last_bytes = current_bytes;
                }
            }
        });
        
        // Use FuturesUnordered to process multiple buffers concurrently
        let mut futures = FuturesUnordered::new();
        
        // Get the number of CPU cores for optimal parallelism
        let num_cpus = num_cpus::get();
        log::info!("Using {} CPU cores for parallel encryption", num_cpus);
        
        for i in 0..buffer_iterations {
            let current_sector = header_sectors + i * sectors_per_buffer as u64;
            let sectors_this_iteration = std::cmp::min(
                sectors_per_buffer as u64,
                sectors_to_encrypt - i * sectors_per_buffer as u64
            ) as u32;
            
            if sectors_this_iteration == 0 {
                break;
            }
            
            // Acquire semaphore permit to limit concurrent tasks
            let permit = semaphore.clone().acquire_owned().await?;
            
            // Clone Arc references for the async task
            let xts_key_ref = Arc::clone(&xts_key);
            let volume_ref = Arc::clone(&volume);
            let progress_counter_ref = Arc::clone(&progress_counter);
            let encrypted_bytes_ref = Arc::clone(&encrypted_bytes);
            
            // Spawn an async task for each buffer
            let task = tokio::spawn(async move {
                // Генерируем случайные данные для буфера
                let buffer_size_this_iteration = sectors_this_iteration as usize * sector_size as usize;
                let mut buffer = vec![0u8; buffer_size_this_iteration];
                OsRng.fill_bytes(&mut buffer);
                
                // Шифруем в параллельных потоках
                let chunks_size = sector_size as usize;
                
                // Parallel encryption of sectors within the buffer using rayon
                buffer.par_chunks_mut(chunks_size)
                    .enumerate()
                    .for_each(|(j, sector_data)| {
                        let sector_index = current_sector + j as u64;
                        let _ = encrypt_sector(sector_data, sector_index, &xts_key_ref);
                    });
                
                // Записываем зашифрованные секторы на устройство
                {
                    let mut volume_guard = volume_ref.lock().unwrap();
                    if let Err(e) = volume_guard.write_sectors(current_sector, sector_size, &buffer) {
                        log::error!("Failed to write sectors at {}: {}", current_sector, e);
                        return Err(anyhow::anyhow!("Write operation failed: {}", e));
                    }
                }
                
                // Update progress
                {
                    let mut progress = progress_counter_ref.lock().unwrap();
                    *progress = *progress + 1;
                    
                    // Also update the total bytes encrypted
                    let mut bytes = encrypted_bytes_ref.lock().unwrap();
                    *bytes += buffer_size_this_iteration as u64;
                }
                
                // Drop permit automatically when the task completes
                drop(permit);
                
                // Return success
                Ok::<_, anyhow::Error>(())
            });
            
            futures.push(task);
            
            // Limit the number of spawned tasks to avoid memory pressure
            if futures.len() >= num_cpus * 2 {
                if let Some(result) = futures.next().await {
                    match result {
                        Ok(Ok(_)) => {}, // Task completed successfully
                        Ok(Err(e)) => return Err(e), // Task returned an error
                        Err(e) => return Err(anyhow::anyhow!("Task panicked: {}", e)),
                    }
                }
            }
        }
        
        // Wait for all remaining tasks to complete
        while let Some(result) = futures.next().await {
            match result {
                Ok(Ok(_)) => {}, // Task completed successfully
                Ok(Err(e)) => return Err(e), // Task returned an error
                Err(e) => return Err(anyhow::anyhow!("Task panicked: {}", e)),
            }
        }
        
        // Wait for progress reporting task to finish
        let _ = progress_task.await;
        
        log::info!("Encryption completed successfully!");
        Ok(())
    })
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