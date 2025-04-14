use anyhow::{Result, anyhow};
use std::sync::{Arc, Mutex};
use crate::platform::volume_io::{VolumeFile, open_device, open_device_readonly};
use crate::crypto::xts::XTS_KEY_SIZE;

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
    crate::crypto::xts::decrypt_sector(sector_data, sector_index, xts_key)
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

// Структура для представления открытого зашифрованного устройства
pub struct EncryptedVolume {
    // Путь к устройству
    pub device_path: String,
    // Файл устройства с доступом на чтение/запись
    pub volume: Arc<Mutex<VolumeFile>>,
    // Ключ для XTS шифрования (64 байта = 2 ключа по 32 байта для AES-256-XTS)
    pub xts_key: [u8; 64],
    // Размер устройства в байтах
    pub volume_size: u64,
    // Размер сектора
    pub sector_size: u32,
    // Количество секторов, занятых заголовком
    pub header_sectors: u64,
}

impl EncryptedVolume {
    // Создает новый экземпляр открытого зашифрованного устройства
    pub fn new(device_path: &str, volume: VolumeFile, xts_key: [u8; 64], 
              volume_size: u64, sector_size: u32, header_sectors: u64) -> Self {
        Self {
            device_path: device_path.to_string(),
            volume: Arc::new(Mutex::new(volume)),
            xts_key,
            volume_size,
            sector_size,
            header_sectors,
        }
    }
    
    // Монтирует зашифрованное устройство
    pub fn mount(&mut self, _mount_point: &str) -> Result<()> {
        // Implementation will be added later
        Err(anyhow!("Not implemented yet"))
    }
    
    // Преобразует абсолютное смещение в номер сектора данных
    pub fn offset_to_sector(&self, offset: u64) -> u64 {
        (offset / self.sector_size as u64) + self.header_sectors
    }
    
    // Возвращает размер данных (без учета заголовка)
    pub fn get_data_size(&self) -> u64 {
        let total_sectors = self.volume_size / self.sector_size as u64;
        if total_sectors <= self.header_sectors {
            return 0;
        }
        (total_sectors - self.header_sectors) * self.sector_size as u64
    }
}

// Открывает зашифрованное устройство с указанным паролем
pub fn open_encrypted_volume(device_path: &str, password: &str) -> Result<EncryptedVolume> {
    // Проверяем, зашифровано ли устройство с помощью UniFortress
    if !is_encrypted_volume(device_path)? {
        return Err(anyhow!("Device is not encrypted with UniFortress"));
    }
    
    // Проверяем пароль
    if !verify_password(device_path, password)? {
        return Err(anyhow!("Incorrect password"));
    }
    
    // Открываем устройство
    let mut volume = match open_device(device_path) {
        Ok(vol) => vol,
        Err(e) => return Err(anyhow!("Failed to open device: {}", e)),
    };
    
    // Получаем параметры устройства
    let volume_size = volume.get_size()?;
    let sector_size = volume.get_sector_size();
    
    // Считываем заголовок
    let mut header = vec![0u8; 4096]; // Размер заголовка
    volume.read_sectors(0, 1, sector_size, &mut header)?;
    
    // Получаем соль из заголовка
    let salt = &header[16..16+32]; // Соль - 32 байта
    
    // Генерируем ключ из пароля и соли (используя тот же метод, что и при шифровании)
    let derived_key = crate::encryption::derive_key(password.as_bytes(), salt)?;
    
    // Разделяем ключ на XTS ключ и HMAC ключ
    let (xts_key, _hmac_key) = crate::encryption::split_derived_key(&derived_key)?;
    
    // Создаем EncryptedVolume
    let encrypted_volume = EncryptedVolume::new(
        device_path,
        volume,
        xts_key,
        volume_size,
        sector_size,
        8, // Предполагаем, что заголовок занимает 8 секторов (4 КБ)
    );
    
    Ok(encrypted_volume)
}

// Проверяет, зашифровано ли устройство с помощью UniFortress
pub fn is_encrypted_volume(device_path: &str) -> Result<bool> {
    // Открываем устройство только для чтения
    let mut volume = match open_device_readonly(device_path) {
        Ok(vol) => vol,
        Err(e) => return Err(anyhow!("Failed to open device: {}", e)),
    };
    
    // Считываем заголовок
    let mut header = vec![0u8; 4096]; // Размер заголовка
    let sector_size = volume.get_sector_size();
    if let Err(e) = volume.read_sectors(0, 1, sector_size, &mut header) {
        return Err(anyhow!("Failed to read header: {}", e));
    }
    
    // Проверяем сигнатуру VOLUME_SIGNATURE ("UniFortress!")
    // Импортируем константу из модуля encryption
    Ok(&header[0..crate::encryption::VOLUME_SIGNATURE.len()] == crate::encryption::VOLUME_SIGNATURE.as_slice())
}

// Проверяет пароль для зашифрованного устройства
pub fn verify_password(device_path: &str, password: &str) -> Result<bool> {
    // Открываем устройство только для чтения
    let mut volume = match open_device_readonly(device_path) {
        Ok(vol) => vol,
        Err(e) => return Err(anyhow!("Failed to open device: {}", e)),
    };
    
    // Считываем заголовок
    let mut header = vec![0u8; 4096]; // Размер заголовка
    let sector_size = volume.get_sector_size();
    volume.read_sectors(0, 1, sector_size, &mut header)?;
    
    // Проверяем сигнатуру VOLUME_SIGNATURE ("UniFortress!")
    if &header[0..crate::encryption::VOLUME_SIGNATURE.len()] != crate::encryption::VOLUME_SIGNATURE.as_slice() {
        return Err(anyhow!("Device is not encrypted with UniFortress"));
    }
    
    // Получаем соль из заголовка
    let salt = &header[16..16+32]; // Соль - 32 байта
    
    // Генерируем ключ из пароля и соли используя ту же функцию, что и при шифровании
    let derived_key = crate::encryption::derive_key(password.as_bytes(), salt)?;
    
    // Разделяем ключ на XTS ключ и HMAC ключ
    let (xts_key, _hmac_key) = crate::encryption::split_derived_key(&derived_key)?;
    
    // Создаем хеш ключа для сравнения с сохраненным в заголовке
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(&xts_key);
    let checksum = hasher.finalize();
    
    // Сравниваем с сохраненным в заголовке
    Ok(&header[48..48+32] == checksum.as_slice())
}

// Расшифровывает все устройство или его часть
pub fn decrypt_volume(device_path: &str, password: &str) -> Result<()> {
    // Открываем зашифрованное устройство
    let _volume = open_encrypted_volume(device_path, password)?;
    
    // Здесь будет код для расшифровки всего устройства
    Err(anyhow!("Not implemented yet"))
} 