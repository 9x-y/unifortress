use std::sync::{Arc, Mutex};
use crate::platform::volume_io::VolumeFile;
use std::path::PathBuf;

/// Константа размера ключа XTS
pub const XTS_KEY_SIZE: usize = 64; // 512 бит (два ключа AES-256)

/// Базовая структура для хранения данных о зашифрованном хранилище
pub struct EncryptedStorageBase {
    pub volume: Arc<Mutex<VolumeFile>>,
    pub xts_key: [u8; XTS_KEY_SIZE],
    pub volume_size: u64,
    pub sector_size: u32,
    pub header_sectors: u64,
    /// Путь к директории с зашифрованными файлами
    pub base_path: PathBuf,
    /// Ключ шифрования
    pub encryption_key: Arc<[u8]>,
    /// Флаг, указывающий, открыто ли хранилище только для чтения
    pub read_only: bool,
}

impl EncryptedStorageBase {
    pub fn new(
        volume: VolumeFile, 
        xts_key: [u8; XTS_KEY_SIZE], 
        volume_size: u64,
        sector_size: u32,
        header_sectors: u64,
        base_path: PathBuf,
        encryption_key: Vec<u8>,
        read_only: bool
    ) -> Self {
        Self {
            volume: Arc::new(Mutex::new(volume)),
            xts_key,
            volume_size,
            sector_size,
            header_sectors,
            base_path,
            encryption_key: Arc::from(encryption_key),
            read_only,
        }
    }
    
    /// Преобразует абсолютное смещение в номер сектора данных
    pub fn offset_to_sector(&self, offset: u64) -> u64 {
        (offset / self.sector_size as u64) + self.header_sectors
    }
    
    /// Возвращает размер данных (без учета заголовка)
    pub fn get_data_size(&self) -> u64 {
        let total_sectors = self.volume_size / self.sector_size as u64;
        if total_sectors <= self.header_sectors {
            return 0;
        }
        (total_sectors - self.header_sectors) * self.sector_size as u64
    }
}

/// Определяет тип файла
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    /// Обычный файл
    Regular,
    /// Директория
    Directory,
    /// Символическая ссылка
    Symlink,
}

/// Информация о файле
#[derive(Debug, Clone)]
pub struct FileInfo {
    /// Размер файла в байтах
    pub size: u64,
    /// Время последнего изменения файла
    pub modified_time: std::time::SystemTime,
    /// Время создания файла
    pub creation_time: std::time::SystemTime,
    /// Время последнего доступа к файлу
    pub access_time: std::time::SystemTime,
    /// Тип файла
    pub file_type: FileType,
    /// Атрибуты файла (в Windows) или права доступа (в Linux)
    pub attributes: u32,
}

/// Флаги для создания или открытия файла
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateOptions {
    /// Файл открывается для чтения
    pub read: bool,
    /// Файл открывается для записи
    pub write: bool,
    /// Файл должен быть создан, если он не существует
    pub create: bool,
    /// Файл должен быть создан, существующий файл должен быть перезаписан
    pub overwrite: bool,
    /// Открыть файл с прямым доступом (без кэширования)
    pub direct_io: bool,
    /// Открыть файл в режиме добавления
    pub append: bool,
    /// Открыть директорию
    pub directory: bool,
    /// Открыть для записи с синхронизацией (запись сразу на диск)
    pub sync: bool,
} 