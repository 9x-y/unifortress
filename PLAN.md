# План разработки UniFortress (Начальный этап)

## Фаза 1: Настройка проекта и базовая структура

1.  **Создание структуры каталогов:**
    *   Создать директории: `src/`, `tests/`, `scripts/`, `docs/`.
2.  **Инициализация Rust проекта:**
    *   Выполнить `cargo init` в корневой директории.
3.  **Настройка `Cargo.toml`:**
    *   Добавить базовые зависимости:
        *   Криптография (например, `aes`, `xts-mode`, `hmac`, `sha2`, `pbkdf2`/`argon2`).
        *   Обработка ошибок (например, `anyhow` или `thiserror`).
        *   Сериализация/десериализация (например, `serde`, `bincode`).
        *   Логирование (например, `log`, `env_logger`).
4.  **Создание основных файлов:**
    *   Создать пустые файлы согласно структуре в ТЗ (`src/main.rs`, `src/encryption.rs`, `src/decryption.rs`, `src/platform/mod.rs`, `src/platform/common.rs`, `src/utils.rs`, `tests/integration_test.rs` и т.д.).
5.  **Базовые утилиты и структуры (`src/utils.rs`, `src/lib.rs` или `src/common.rs`):**
    *   Определить основные структуры данных (формат заголовка тома, метаданные).
    *   Реализовать базовые функции для логирования и обработки ошибок.

## Фаза 2: Ядро криптографии

1.  **Производная ключа (KDF):**
    *   Реализовать функцию генерации ключа шифрования из пароля пользователя с использованием PBKDF2 или Argon2.
2.  **Работа с заголовком:**
    *   Реализовать сериализацию и десериализацию структуры заголовка.
    *   Добавить проверку целостности заголовка с помощью HMAC.
3.  **Шифрование/Дешифрование (AES-XTS):**
    *   Реализовать обертки над библиотечными функциями для шифрования и дешифрования блоков данных с использованием AES-256 XTS.
4.  **Модульные тесты:**
    *   Написать тесты для KDF, работы с заголовком и функций шифрования/дешифрования.

## Фаза 3: Начальная интеграция с платформой (например, Windows) и базовый CLI

1.  **Базовый интерфейс (CLI):**
    *   Создать простое CLI-приложение (используя, например, `clap`) для основных команд: `encrypt`, `unlock`.
2.  **Взаимодействие с ОС:**
    *   Реализовать функции для обнаружения USB-накопителей (в `src/platform/windows.rs`).
    *   Реализовать базовые операции ввода-вывода для чтения/записи секторов на устройстве.
3.  **Реализация сценария "Encrypt":**
    *   Чтение пароля.
    *   Форматирование (если необходимо).
    *   Генерация ключа, запись заголовка на флешку.
    *   (Опционально) Начало фонового шифрования.
4.  **Реализация сценария "Unlock":**
    *   Чтение заголовка с флешки.
    *   Проверка пароля (через KDF и сравнение ключей или проверку HMAC).
    *   Подготовка к предоставлению доступа к данным (например, монтирование виртуального диска или запуск прокси-сервиса).

## Следующие шаги (последующие фазы):

*   Реализация адаптеров для других платформ (macOS, Linux).
*   Разработка мобильных приложений (Android, iOS) и взаимодействие с ядром Rust.
*   Разработка GUI.
*   Расширенное тестирование (интеграционное, производительности, безопасности).
*   Документация.

## Вариант реализации доступа к зашифрованным данным

```rust
// src/fs_access/mod.rs
mod common;
mod windows;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

pub use common::*;

#[cfg(target_os = "windows")]
pub use windows::*;
#[cfg(target_os = "linux")]
pub use linux::*;
#[cfg(target_os = "macos")]
pub use macos::*;

/// Общий интерфейс для монтирования зашифрованного хранилища
pub trait EncryptedStorage {
    /// Монтирует зашифрованное хранилище и предоставляет к нему доступ
    fn mount(&self, mount_point: &str) -> anyhow::Result<Box<dyn MountedStorage>>;
}

/// Интерфейс примонтированного хранилища
pub trait MountedStorage {
    /// Размонтирует хранилище
    fn unmount(&self) -> anyhow::Result<()>;
    
    /// Возвращает путь к точке монтирования
    fn get_mount_point(&self) -> &str;
}
```

```rust
// src/fs_access/common.rs
use std::sync::{Arc, Mutex};
use crate::encryption::XTS_KEY_SIZE;
use crate::platform::volume_io::VolumeFile;

/// Базовая структура для хранения данных о зашифрованном хранилище
pub struct EncryptedStorageBase {
    pub volume: Arc<Mutex<VolumeFile>>,
    pub xts_key: [u8; XTS_KEY_SIZE],
    pub volume_size: u64,
    pub sector_size: u32,
    pub header_sectors: u64,
}

impl EncryptedStorageBase {
    pub fn new(
        volume: VolumeFile, 
        xts_key: [u8; XTS_KEY_SIZE], 
        volume_size: u64,
        sector_size: u32,
        header_sectors: u64
    ) -> Self {
        Self {
            volume: Arc::new(Mutex::new(volume)),
            xts_key,
            volume_size,
            sector_size,
            header_sectors,
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
```

### Windows-специфичная реализация (использует Dokan)

```rust
// src/fs_access/windows.rs
use std::ffi::{OsStr, OsString};
use std::path::Path;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, atomic::{AtomicU64, Ordering}};
use std::time::SystemTime;
use anyhow::{bail, Context, Result};
use log::{debug, error, info};
use dokan::{
    CreateFileInfo, DiskSpaceInfo, DokanFileInfo, Drive, FileInfo,
    FileSystemHandler, FindData, MountOptions, OperationError, VolumeInfo
};
use widestring::UCString;

use crate::encryption::encrypt_sector;
use crate::decryption::decrypt_sector;
use super::{EncryptedStorage, EncryptedStorageBase, MountedStorage};

// Константы для файловой системы
const DATA_FILE_NAME: &str = "data.bin";

pub struct WindowsEncryptedStorage {
    base: EncryptedStorageBase,
}

impl WindowsEncryptedStorage {
    pub fn new(base: EncryptedStorageBase) -> Self {
        Self { base }
    }
}

impl EncryptedStorage for WindowsEncryptedStorage {
    fn mount(&self, mount_point: &str) -> Result<Box<dyn MountedStorage>> {
        // Проверяем, что точка монтирования допустима (буква диска)
        if mount_point.len() != 1 || !mount_point.chars().next().unwrap().is_ascii_alphabetic() {
            bail!("Точка монтирования должна быть одной буквой (например, 'M')");
        }
        
        // Создаем обработчик файловой системы
        let fs_handler = FileSystemHandlerImpl::new(self.base.clone());
        
        // Настройки монтирования
        let mount_options = MountOptions {
            mount_point: mount_point.to_string(),
            options: dokan::MountFlags::REMOVABLE,
            ..Default::default()
        };
        
        // Монтируем диск
        info!("Монтирование диска на {} с использованием Dokan", mount_point);
        match Drive::mount(fs_handler, &mount_options) {
            Ok(drive) => {
                info!("Диск успешно смонтирован на {}", mount_point);
                Ok(Box::new(WindowsMountedStorage { 
                    drive, 
                    mount_point: mount_point.to_string() 
                }))
            },
            Err(e) => {
                error!("Ошибка монтирования: {:?}", e);
                bail!("Не удалось смонтировать диск: {}", e)
            }
        }
    }
}

struct WindowsMountedStorage {
    drive: Drive,
    mount_point: String,
}

impl MountedStorage for WindowsMountedStorage {
    fn unmount(&self) -> Result<()> {
        self.drive.unmount()?;
        Ok(())
    }
    
    fn get_mount_point(&self) -> &str {
        &self.mount_point
    }
}

struct FileSystemHandlerImpl {
    base: EncryptedStorageBase,
    next_handle: AtomicU64,
    handles: Arc<Mutex<HashMap<u64, ()>>>,
}

impl FileSystemHandlerImpl {
    fn new(base: EncryptedStorageBase) -> Self {
        Self {
            base,
            next_handle: AtomicU64::new(1),
            handles: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    
    fn get_new_handle(&self) -> u64 {
        let handle = self.next_handle.fetch_add(1, Ordering::SeqCst);
        if let Ok(mut handles) = self.handles.lock() {
            handles.insert(handle, ());
        }
        handle
    }
    
    fn is_data_file(&self, file_name: &OsStr) -> bool {
        file_name.to_string_lossy() == DATA_FILE_NAME
    }
}

impl<'a, 'b> FileSystemHandler<'a, 'b> for FileSystemHandlerImpl {
    fn create_file(
        &'a self,
        file_name: &OsStr,
        _security_context: &'b dokan::DOKAN_IO_SECURITY_CONTEXT,
        _desired_access: u32,
        _file_attributes: u32,
        _share_access: u32,
        _create_disposition: u32,
        _create_options: u32,
        _info: &DokanFileInfo,
    ) -> Result<CreateFileInfo, OperationError> {
        debug!("create_file: {:?}", file_name);
        
        // Корневой каталог
        if file_name.to_string_lossy() == "\\" {
            return Ok(CreateFileInfo {
                context: 0,
                is_directory: true,
                new_file_created: false,
            });
        }
        
        // Наш единственный файл data.bin
        if self.is_data_file(file_name) {
            let handle = self.get_new_handle();
            
            return Ok(CreateFileInfo {
                context: handle,
                is_directory: false,
                new_file_created: false,
            });
        }
        
        // Любой другой файл/каталог
        Err(OperationError::FileNotFound)
    }
    
    fn close_file(&'a self, _file_name: &OsStr, info: &DokanFileInfo) -> Result<(), OperationError> {
        debug!("close_file: context={}", info.context);
        // Удаляем хендл, если он существует
        if info.context != 0 {
            if let Ok(mut handles) = self.handles.lock() {
                handles.remove(&info.context);
            }
        }
        Ok(())
    }
    
    fn read_file(
        &'a self,
        file_name: &OsStr,
        offset: i64,
        buffer: &mut [u8],
        _info: &DokanFileInfo,
    ) -> Result<u32, OperationError> {
        if !self.is_data_file(file_name) {
            return Err(OperationError::FileNotFound);
        }
        
        let offset = offset as u64;
        if offset >= self.base.get_data_size() {
            return Ok(0); // EOF
        }
        
        let mut volume = match self.base.volume.lock() {
            Ok(v) => v,
            Err(_) => return Err(OperationError::AccessDenied),
        };
        
        // Вычисляем начальный сектор и смещение внутри него
        let sector_size = self.base.sector_size as u64;
        let start_sector = self.base.offset_to_sector(offset);
        let sector_offset = offset % sector_size;
        
        // Сколько байт нам нужно прочитать
        let bytes_to_read = buffer.len() as u64;
        let bytes_to_end = self.base.get_data_size() - offset;
        let actual_bytes_to_read = bytes_to_read.min(bytes_to_end);
        
        if actual_bytes_to_read == 0 {
            return Ok(0);
        }
        
        let mut bytes_read = 0;
        let mut buffer_offset = 0;
        
        // Читаем первый сектор (возможно, частично)
        let mut current_sector = start_sector;
        let mut sector_buffer = vec![0u8; sector_size as usize];
        
        while bytes_read < actual_bytes_to_read {
            // Читаем и расшифровываем сектор
            match volume.read_sector(current_sector, &mut sector_buffer) {
                Ok(_) => {
                    // Расшифровываем сектор
                    if let Err(e) = decrypt_sector(
                        &mut sector_buffer, 
                        &self.base.xts_key, 
                        current_sector
                    ) {
                        error!("Ошибка расшифровки сектора {}: {:?}", current_sector, e);
                        return Err(OperationError::IoError);
                    }
                    
                    // Определяем, сколько байтов копировать из этого сектора
                    let source_offset = if current_sector == start_sector {
                        sector_offset as usize
                    } else {
                        0
                    };
                    
                    let bytes_left_in_sector = sector_size as usize - source_offset;
                    let bytes_to_copy = ((actual_bytes_to_read - bytes_read) as usize)
                        .min(bytes_left_in_sector);
                    
                    // Копируем данные из сектора в буфер
                    buffer[buffer_offset..buffer_offset + bytes_to_copy]
                        .copy_from_slice(&sector_buffer[source_offset..source_offset + bytes_to_copy]);
                    
                    bytes_read += bytes_to_copy as u64;
                    buffer_offset += bytes_to_copy;
                    
                    // Переходим к следующему сектору
                    current_sector += 1;
                }
                Err(e) => {
                    error!("Ошибка чтения сектора {}: {:?}", current_sector, e);
                    return Err(OperationError::IoError);
                }
            }
        }
        
        Ok(bytes_read as u32)
    }

    fn write_file(
        &'a self,
        file_name: &OsStr,
        offset: i64,
        buffer: &[u8],
        _info: &DokanFileInfo,
    ) -> Result<u32, OperationError> {
        if !self.is_data_file(file_name) {
            return Err(OperationError::FileNotFound);
        }
        
        let offset = offset as u64;
        if offset >= self.base.get_data_size() {
            return Err(OperationError::DiskFull);
        }
        
        let mut volume = match self.base.volume.lock() {
            Ok(v) => v,
            Err(_) => return Err(OperationError::AccessDenied),
        };
        
        // Вычисляем начальный сектор и смещение внутри него
        let sector_size = self.base.sector_size as u64;
        let start_sector = self.base.offset_to_sector(offset);
        let sector_offset = offset % sector_size;
        
        // Сколько байт нам нужно записать
        let bytes_to_write = buffer.len() as u64;
        let bytes_to_end = self.base.get_data_size() - offset;
        let actual_bytes_to_write = bytes_to_write.min(bytes_to_end);
        
        if actual_bytes_to_write == 0 {
            return Ok(0);
        }
        
        let mut bytes_written = 0;
        let mut buffer_offset = 0;
        
        // Записываем первый сектор (возможно, частично)
        let mut current_sector = start_sector;
        let mut sector_buffer = vec![0u8; sector_size as usize];
        
        while bytes_written < actual_bytes_to_write {
            // Если пишем не полный сектор, нужно сначала прочитать существующие данные
            let source_offset = if current_sector == start_sector {
                sector_offset as usize
            } else {
                0
            };
            
            let bytes_left_in_sector = sector_size as usize - source_offset;
            let bytes_to_copy = ((actual_bytes_to_write - bytes_written) as usize)
                .min(bytes_left_in_sector);
            
            // Если пишем не весь сектор, сначала читаем его
            if source_offset > 0 || bytes_to_copy < sector_size as usize {
                match volume.read_sector(current_sector, &mut sector_buffer) {
                    Ok(_) => {
                        // Расшифровываем сектор
                        if let Err(e) = decrypt_sector(
                            &mut sector_buffer, 
                            &self.base.xts_key, 
                            current_sector
                        ) {
                            error!("Ошибка расшифровки сектора {}: {:?}", current_sector, e);
                            return Err(OperationError::IoError);
                        }
                    }
                    Err(e) => {
                        error!("Ошибка чтения сектора {}: {:?}", current_sector, e);
                        return Err(OperationError::IoError);
                    }
                }
            }
            
            // Копируем данные из буфера в сектор
            sector_buffer[source_offset..source_offset + bytes_to_copy]
                .copy_from_slice(&buffer[buffer_offset..buffer_offset + bytes_to_copy]);
            
            // Шифруем и записываем сектор
            if let Err(e) = encrypt_sector(
                &mut sector_buffer, 
                &self.base.xts_key, 
                current_sector
            ) {
                error!("Ошибка шифрования сектора {}: {:?}", current_sector, e);
                return Err(OperationError::IoError);
            }
            
            match volume.write_sector(current_sector, &sector_buffer) {
                Ok(_) => {
                    bytes_written += bytes_to_copy as u64;
                    buffer_offset += bytes_to_copy;
                    
                    // Переходим к следующему сектору
                    current_sector += 1;
                }
                Err(e) => {
                    error!("Ошибка записи сектора {}: {:?}", current_sector, e);
                    return Err(OperationError::IoError);
                }
            }
        }
        
        Ok(bytes_written as u32)
    }

    fn get_file_information(
        &'a self,
        file_name: &OsStr,
        _info: &DokanFileInfo,
    ) -> Result<FileInfo, OperationError> {
        debug!("get_file_information: {:?}", file_name);
        
        // Корневой каталог
        if file_name.to_string_lossy() == "\\" {
            return Ok(FileInfo {
                attributes: 0x10, // FILE_ATTRIBUTE_DIRECTORY
                creation_time: SystemTime::now(),
                last_access_time: SystemTime::now(),
                last_write_time: SystemTime::now(),
                file_size: 0,
            });
        }
        
        // Файл данных
        if self.is_data_file(file_name) {
            return Ok(FileInfo {
                attributes: 0x20, // FILE_ATTRIBUTE_NORMAL
                creation_time: SystemTime::now(),
                last_access_time: SystemTime::now(),
                last_write_time: SystemTime::now(),
                file_size: self.base.get_data_size(),
            });
        }
        
        Err(OperationError::FileNotFound)
    }

    fn find_files(
        &'a self,
        file_name: &OsStr,
        fill_find_data: &mut dyn FnMut(&FindData) -> Result<(), OperationError>,
        _info: &DokanFileInfo,
    ) -> Result<(), OperationError> {
        debug!("find_files: {:?}", file_name);
        
        // Корневой каталог - перечисляем его содержимое
        if file_name.to_string_lossy() == "\\" {
            // Текущий каталог "."
            let current_dir = FindData {
                file_name: UCString::from("."),
                attributes: 0x10, // FILE_ATTRIBUTE_DIRECTORY
                creation_time: SystemTime::now(),
                last_access_time: SystemTime::now(), 
                last_write_time: SystemTime::now(),
                file_size: 0,
            };
            fill_find_data(&current_dir)?;
            
            // Родительский каталог ".."
            let parent_dir = FindData {
                file_name: UCString::from(".."),
                attributes: 0x10, // FILE_ATTRIBUTE_DIRECTORY
                creation_time: SystemTime::now(),
                last_access_time: SystemTime::now(),
                last_write_time: SystemTime::now(),
                file_size: 0,
            };
            fill_find_data(&parent_dir)?;
            
            // Наш файл данных
            let data_file = FindData {
                file_name: UCString::from(DATA_FILE_NAME),
                attributes: 0x20, // FILE_ATTRIBUTE_NORMAL
                creation_time: SystemTime::now(),
                last_access_time: SystemTime::now(),
                last_write_time: SystemTime::now(),
                file_size: self.base.get_data_size(),
            };
            fill_find_data(&data_file)?;
            
            return Ok(());
        }
        
        Err(OperationError::FileNotFound)
    }

    fn get_volume_information(&'a self) -> Result<VolumeInfo, OperationError> {
        debug!("get_volume_information");
        
        Ok(VolumeInfo {
            name: UCString::from("UniFortress"),
            serial_number: 0x12345678,
            max_component_length: 255,
            fs_flags: 0,
            fs_name: UCString::from("UniFortressFS"),
        })
    }

    fn get_disk_free_space(&'a self) -> Result<DiskSpaceInfo, OperationError> {
        debug!("get_disk_free_space");
        
        let total_size = self.base.get_data_size();
        
        Ok(DiskSpaceInfo {
            free_byte_count: 0,             // Свободное место (в нашем случае 0)
            available_byte_count: 0,        // Доступное для пользователя
            total_byte_count: total_size,   // Общий размер
        })
    }

    // Реализации других методов по умолчанию
    fn flush_file_buffers(
        &'a self,
        _file_name: &OsStr,
        _info: &DokanFileInfo,
    ) -> Result<(), OperationError> {
        Ok(())
    }
    
    fn get_file_security(
        &'a self,
        _file_name: &OsStr,
        _security_information: u32,
        _security_descriptor: Option<&mut [u8]>,
        _info: &DokanFileInfo,
    ) -> Result<u32, OperationError> {
        Ok(0)
    }
    
    fn set_file_security(
        &'a self,
        _file_name: &OsStr,
        _security_information: u32,
        _security_descriptor: &[u8],
        _info: &DokanFileInfo,
    ) -> Result<(), OperationError> {
        Ok(())
    }
    
    fn set_file_attributes(
        &'a self,
        _file_name: &OsStr,
        _file_attributes: u32,
        _info: &DokanFileInfo,
    ) -> Result<(), OperationError> {
        Ok(())
    }
}

### Linux-специфичная реализация (FUSE)

```rust
// src/fs_access/linux.rs
#[cfg(target_os = "linux")]
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use anyhow::{bail, Context, Result};
use fuser::{
    FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyData, ReplyDirectory,
    ReplyEntry, ReplyOpen, ReplyWrite, Request
};
use libc::{ENOENT, EISDIR, EIO};
use log::{debug, error, info};

use crate::encryption::encrypt_sector;
use crate::decryption::decrypt_sector;
use super::{EncryptedStorage, EncryptedStorageBase, MountedStorage};

const TTL: Duration = Duration::from_secs(1); // 1 second
const ROOT_INO: u64 = 1;
const DATA_INO: u64 = 2;

pub struct LinuxEncryptedStorage {
    base: EncryptedStorageBase,
}

impl LinuxEncryptedStorage {
    pub fn new(base: EncryptedStorageBase) -> Self {
        Self { base }
    }
}

impl EncryptedStorage for LinuxEncryptedStorage {
    fn mount(&self, mount_point: &str) -> Result<Box<dyn MountedStorage>> {
        // Проверяем, что точка монтирования существует
        let mount_path = Path::new(mount_point);
        if !mount_path.exists() || !mount_path.is_dir() {
            bail!("Точка монтирования не существует или не является директорией: {}", mount_point);
        }
        
        // Создаем обработчик файловой системы
        let fs = UniFortressFS::new(self.base.clone());
        
        // Опции монтирования
        let options = vec![
            MountOption::RO,
            MountOption::FSName("unifortress".to_string()),
            MountOption::AutoUnmount,
            MountOption::AllowOther,
        ];
        
        // Клонируем mount_point для передачи в поток
        let mount_point_owned = mount_point.to_string();
        
        // Монтируем файловую систему в отдельном потоке
        info!("Монтирование FUSE на {}", mount_point);
        let (tx, rx) = std::sync::mpsc::channel();
        
        std::thread::spawn(move || {
            let session = match fuser::spawn_mount(fs, &mount_point_owned, &options) {
                Ok(session) => {
                    tx.send(Ok(())).unwrap_or(());
                    session
                },
                Err(e) => {
                    tx.send(Err(e)).unwrap_or(());
                    return;
                }
            };
            
            // Ожидаем, пока не будет вызван unmount
            session.join();
        });
        
        // Проверяем, успешно ли запустилось монтирование
        match rx.recv()? {
            Ok(_) => {
                info!("FUSE успешно примонтирована на {}", mount_point);
                Ok(Box::new(LinuxMountedStorage {
                    mount_point: mount_point.to_string(),
                }))
            },
            Err(e) => {
                error!("Ошибка монтирования FUSE: {:?}", e);
                bail!("Не удалось смонтировать FUSE: {}", e)
            }
        }
    }
}

struct LinuxMountedStorage {
    mount_point: String,
}

impl MountedStorage for LinuxMountedStorage {
    fn unmount(&self) -> Result<()> {
        // Для unmount в Linux используем fusermount
        let status = std::process::Command::new("fusermount")
            .arg("-u")
            .arg(&self.mount_point)
            .status()?;
            
        if !status.success() {
            bail!("Ошибка при размонтировании FUSE");
        }
        
        Ok(())
    }
    
    fn get_mount_point(&self) -> &str {
        &self.mount_point
    }
}

struct UniFortressFS {
    base: EncryptedStorageBase,
}

impl UniFortressFS {
    fn new(base: EncryptedStorageBase) -> Self {
        Self { base }
    }
    
    fn sector_to_offset(&self, sector: u64) -> u64 {
        (sector - self.base.header_sectors) * self.base.sector_size as u64
    }
}

impl Filesystem for UniFortressFS {
    fn lookup(&mut self, _req: &Request, parent: u64, name: &std::ffi::OsStr, reply: ReplyEntry) {
        if parent != ROOT_INO {
            reply.error(ENOENT);
            return;
        }
        
        if name.to_str() == Some("data.bin") {
            // Атрибуты для data.bin
            let attr = FileAttr {
                ino: DATA_INO,
                size: self.base.get_data_size(),
                blocks: (self.base.get_data_size() + 511) / 512, // округление вверх
                atime: SystemTime::now(),
                mtime: SystemTime::now(),
                ctime: SystemTime::now(),
                crtime: SystemTime::now(),
                kind: FileType::RegularFile,
                perm: 0o644,
                nlink: 1,
                uid: 0,
                gid: 0,
                rdev: 0,
                flags: 0,
                blksize: self.base.sector_size as u32,
            };
            reply.entry(&TTL, &attr, 0);
        } else {
            reply.error(ENOENT);
        }
    }
    
    fn getattr(&mut self, _req: &Request, ino: u64, reply: ReplyAttr) {
        match ino {
            ROOT_INO => {
                // Атрибуты для корневой директории
                let attr = FileAttr {
                    ino: ROOT_INO,
                    size: 0,
                    blocks: 0,
                    atime: SystemTime::now(),
                    mtime: SystemTime::now(),
                    ctime: SystemTime::now(),
                    crtime: SystemTime::now(),
                    kind: FileType::Directory,
                    perm: 0o755,
                    nlink: 2,
                    uid: 0,
                    gid: 0,
                    rdev: 0,
                    flags: 0,
                    blksize: self.base.sector_size as u32,
                };
                reply.attr(&TTL, &attr);
            },
            DATA_INO => {
                // Атрибуты для data.bin
                let attr = FileAttr {
                    ino: DATA_INO,
                    size: self.base.get_data_size(),
                    blocks: (self.base.get_data_size() + 511) / 512, // округление вверх
                    atime: SystemTime::now(),
                    mtime: SystemTime::now(),
                    ctime: SystemTime::now(),
                    crtime: SystemTime::now(),
                    kind: FileType::RegularFile,
                    perm: 0o644,
                    nlink: 1,
                    uid: 0,
                    gid: 0,
                    rdev: 0,
                    flags: 0,
                    blksize: self.base.sector_size as u32,
                };
                reply.attr(&TTL, &attr);
            },
            _ => {
                reply.error(ENOENT);
            }
        }
    }

    fn readdir(&mut self, _req: &Request, parent: u64, _fill: &mut dyn FnMut(ReplyEntry) -> Result<()>, _cookie: u64) {
        if parent != ROOT_INO {
            return;
        }
        
        // Реализация чтения директории
        // ...
    }

    fn open(&mut self, _req: &Request, file: &std::ffi::OsStr, _info: &DokanFileInfo) -> Result<ReplyOpen> {
        // Реализация открытия файла
        // ...
        Ok(ReplyOpen::Allow)
    }

    fn create(&mut self, _req: &Request, file: &std::ffi::OsStr, _info: &DokanFileInfo) -> Result<ReplyCreate> {
        // Реализация создания файла
        // ...
        Ok(ReplyCreate::Allow)
    }

    fn write(&mut self, _req: &Request, file: &std::ffi::OsStr, data: &[u8], _info: &DokanFileInfo) -> Result<ReplyWrite> {
        // Реализация записи данных в файл
        // ...
        Ok(ReplyWrite::Allow)
    }

    fn flush(&mut self, _req: &Request, _info: &DokanFileInfo) -> Result<ReplyFlush> {
        // Реализация очистки буферов файла
        // ...
        Ok(ReplyFlush::Allow)
    }

    fn get_file_info(&mut self, _req: &Request, file: &std::ffi::OsStr, _info: &DokanFileInfo) -> Result<ReplyData> {
        // Реализация получения информации о файле
        // ...
        Ok(ReplyData::Allow)
    }

    fn set_file_info(&mut self, _req: &Request, file: &std::ffi::OsStr, _info: &DokanFileInfo) -> Result<ReplySetInfo> {
        // Реализация установки информации о файле
        // ...
        Ok(ReplySetInfo::Allow)
    }

    fn delete_file(&mut self, _req: &Request, file: &std::ffi::OsStr) -> Result<ReplyDelete> {
        // Реализация удаления файла
        // ...
        Ok(ReplyDelete::Allow)
    }

    fn move_file(&mut self, _req: &Request, file: &std::ffi::OsStr, new_file: &std::ffi::OsStr) -> Result<ReplyMove> {
        // Реализация перемещения файла
        // ...
        Ok(ReplyMove::Allow)
    }

    fn delete_dir(&mut self, _req: &Request, file: &std::ffi::OsStr) -> Result<ReplyDelete> {
        // Реализация удаления директории
        // ...
        Ok(ReplyDelete::Allow)
    }

    fn move_dir(&mut self, _req: &Request, file: &std::ffi::OsStr, new_file: &std::ffi::OsStr) -> Result<ReplyMove> {
        // Реализация перемещения директории
        // ...
        Ok(ReplyMove::Allow)
    }

    fn get_volume_info(&mut self) -> Result<ReplyVolume> {
        // Реализация получения информации о томе
        // ...
        Ok(ReplyVolume::Allow)
    }

    fn get_disk_info(&mut self) -> Result<ReplyDiskInfo> {
        // Реализация получения информации о диске
        // ...
        Ok(ReplyDiskInfo::Allow)
    }

    fn get_security(&mut self, _req: &Request, _file: &std::ffi::OsStr, _info: &DokanFileInfo) -> Result<ReplySecurity> {
        // Реализация получения информации о безопасности
        // ...
        Ok(ReplySecurity::Allow)
    }

    fn set_security(&mut self, _req: &Request, _file: &std::ffi::OsStr, _info: &DokanFileInfo) -> Result<ReplySecurity> {
        // Реализация установки информации о безопасности
        // ...
        Ok(ReplySecurity::Allow)
    }

    fn get_file_name(&mut self, _req: &Request, file: &std::ffi::OsStr, reply: &mut dyn FnMut(ReplyEntry) -> Result<()>) {
        // Реализация получения имени файла
        // ...
    }

    fn find_files(&mut self, _req: &Request, file: &std::ffi::OsStr, _fill: &mut dyn FnMut(ReplyEntry) -> Result<()>, _info: &DokanFileInfo) {
        // Реализация поиска файлов
        // ...
    }
} 