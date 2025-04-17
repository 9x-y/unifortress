use anyhow::{bail, Context, Result, anyhow};
use log::{debug, trace, info};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Определяем виртуальный размер сектора для работы внутри файла-контейнера.
/// 4096 байт - частый размер сектора для современных дисков и ФС.
const VIRTUAL_SECTOR_SIZE: u32 = 4096;

/// Максимальный размер блока для записи на физические устройства
const MAX_PHYSICAL_WRITE_CHUNK: usize = 512 * 1024; // 512 КБ максимальный размер для записи

/// Представляет открытый файл-контейнер тома UniFortress.
pub struct VolumeFile {
    /// Файловый дескриптор
    file: File,
    /// Путь к файлу
    path: PathBuf,
    /// Флаг: физическое устройство или файл
    is_physical: bool,
    /// Реальный размер сектора устройства (если известен)
    real_sector_size: Option<u32>,
}

impl VolumeFile {
    /// Открывает существующий файл-контейнер для чтения и записи.
    pub fn open(file_path: &str, is_physical: bool) -> Result<Self> {
        let path = if is_physical {
            // Windows-специфичный код для открытия физического устройства
            // На Windows путь к физическим устройствам выглядит как \\.\PhysicalDriveX
            PathBuf::from(file_path)
        } else {
            PathBuf::from(file_path)
        };

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(false) // Не создавать, если не существует
            .open(&path)
            .with_context(|| format!("Не удалось открыть '{}'", file_path))?;
        
        // Определяем реальный размер сектора для физического устройства
        let real_sector_size = if is_physical {
            Some(Self::get_physical_sector_size(&file)?)
        } else {
            None
        };
        
        debug!("Файл '{}' открыт. Физическое устройство: {}", file_path, is_physical);
        if is_physical {
            debug!("Реальный размер сектора: {} байт", real_sector_size.unwrap());
        }
        
        Ok(VolumeFile { 
            file, 
            path, 
            is_physical,
            real_sector_size
        })
    }

    /// Создает новый файл-контейнер заданного размера, открывает его для чтения/записи.
    /// Если файл существует, возвращает ошибку (чтобы избежать случайной перезаписи).
    pub fn create_new(file_path: &Path, size_bytes: u64) -> Result<Self> {
         if file_path.exists() {
            // TODO: Добавить опцию --force для перезаписи?
            bail!("Файл '{}' уже существует. Используйте другую команду или опцию для перезаписи.", file_path.display());
        }
         let file = OpenOptions::new()
            .create_new(true) // Ошибка, если существует
            .read(true)
            .write(true)
            .open(file_path)
            .with_context(|| format!("Не удалось создать файл '{}'", file_path.display()))?;
        
        // Устанавливаем размер файла
        file.set_len(size_bytes)
            .with_context(|| format!("Не удалось установить размер файла '{}' в {} байт", file_path.display(), size_bytes))?;
        
        debug!("Новый файл-контейнер '{}' размером {} байт создан.", file_path.display(), size_bytes);
        Ok(VolumeFile { 
            file, 
            path: file_path.to_path_buf(),
            is_physical: false,
            real_sector_size: None
        })
    }

    /// Возвращает размер виртуального сектора.
    pub fn get_sector_size(&self) -> u32 {
        VIRTUAL_SECTOR_SIZE
    }

    /// Возвращает общий размер файла-контейнера в байтах.
    pub fn get_size(&self) -> Result<u64> {
        if self.is_physical {
            self.get_physical_device_size()
        } else {
            let metadata = self.file.metadata()
                .with_context(|| format!("Не удалось получить метаданные файла '{}'", self.path.display()))?;
            Ok(metadata.len())
        }
    }

    /// Возвращает размер физического устройства в байтах.
    fn get_physical_device_size(&self) -> Result<u64> {
        if !self.is_physical {
            bail!("Метод доступен только для физических устройств");
        }
        
        // Для Windows используем DeviceIoControl с IOCTL_DISK_GET_LENGTH_INFO
        use winapi::um::winioctl::IOCTL_DISK_GET_LENGTH_INFO;
        use winapi::um::ioapiset::DeviceIoControl;
        use winapi::shared::minwindef::DWORD;
        use winapi::um::minwinbase::OVERLAPPED;
        use winapi::shared::ntdef::NULL;
        use std::os::windows::io::AsRawHandle;
        
        // Структура GET_LENGTH_INFORMATION из winioctl.h
        #[repr(C)]
        struct GetLengthInformation {
            length: u64,
        }
        
        let mut length_info = GetLengthInformation { length: 0 };
        let mut bytes_returned: DWORD = 0;
        
        let result = unsafe {
            DeviceIoControl(
                self.file.as_raw_handle() as *mut _,
                IOCTL_DISK_GET_LENGTH_INFO,
                NULL,
                0,
                &mut length_info as *mut _ as *mut _,
                std::mem::size_of::<GetLengthInformation>() as DWORD,
                &mut bytes_returned,
                std::ptr::null_mut::<OVERLAPPED>(),
            )
        };
        
        if result == 0 {
            let error = std::io::Error::last_os_error();
            bail!("Не удалось получить размер физического устройства: {}", error);
        }
        
        Ok(length_info.length)
    }

    /// Определяет физический размер сектора устройства.
    fn get_physical_sector_size(file: &File) -> Result<u32> {
        // Для Windows используем DeviceIoControl с IOCTL_DISK_GET_DRIVE_GEOMETRY
        use winapi::um::winioctl::IOCTL_DISK_GET_DRIVE_GEOMETRY;
        use winapi::um::ioapiset::DeviceIoControl;
        use winapi::shared::minwindef::DWORD;
        use winapi::um::minwinbase::OVERLAPPED;
        use winapi::shared::ntdef::NULL;
        use std::os::windows::io::AsRawHandle;
        
        // Структура DISK_GEOMETRY из winioctl.h
        #[repr(C)]
        struct DiskGeometry {
            cylinders: i64,
            media_type: i32,
            tracks_per_cylinder: DWORD,
            sectors_per_track: DWORD,
            bytes_per_sector: DWORD,
        }
        
        let mut disk_geometry = DiskGeometry {
            cylinders: 0,
            media_type: 0,
            tracks_per_cylinder: 0,
            sectors_per_track: 0,
            bytes_per_sector: 0,
        };
        let mut bytes_returned: DWORD = 0;
        
        let result = unsafe {
            DeviceIoControl(
                file.as_raw_handle() as *mut _,
                IOCTL_DISK_GET_DRIVE_GEOMETRY,
                NULL,
                0,
                &mut disk_geometry as *mut _ as *mut _,
                std::mem::size_of::<DiskGeometry>() as DWORD,
                &mut bytes_returned,
                std::ptr::null_mut::<OVERLAPPED>(),
            )
        };
        
        if result == 0 {
            let error = std::io::Error::last_os_error();
            bail!("Не удалось получить геометрию диска: {}", error);
        }
        
        Ok(disk_geometry.bytes_per_sector)
    }

    /// Читает данные из файла, начиная с указанного байтового смещения.
    pub fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> Result<()> {
        trace!("Reading {} bytes from offset {}", buffer.len(), offset);
        self.file.seek(SeekFrom::Start(offset))
             .with_context(|| format!("Ошибка позиционирования для чтения в файле '{}' на смещение {}", self.path.display(), offset))?;
        self.file.read_exact(buffer)
             .with_context(|| format!("Ошибка чтения {} байт из файла '{}' со смещения {}", buffer.len(), self.path.display(), offset))?;
        Ok(())
    }

    /// Записывает данные в файл, начиная с указанного байтового смещения.
    pub fn write_at(&mut self, offset: u64, buffer: &[u8]) -> Result<()> {
        if buffer.is_empty() {
            return Ok(());
        }

        // Для физических устройств используем запись мелкими блоками
        if self.is_physical && buffer.len() > MAX_PHYSICAL_WRITE_CHUNK {
            trace!("Writing large buffer of {} bytes in chunks to physical device at offset {}", buffer.len(), offset);
            
            let mut bytes_written = 0;
            while bytes_written < buffer.len() {
                let chunk_size = std::cmp::min(MAX_PHYSICAL_WRITE_CHUNK, buffer.len() - bytes_written);
                let current_offset = offset + bytes_written as u64;
                let chunk = &buffer[bytes_written..bytes_written + chunk_size];
                
                // Попытаемся записать текущий блок с повторными попытками в случае ошибки
                let mut retry_count = 0;
                let max_retries = 5; // Увеличиваем количество попыток
                let mut last_error = None;
                
                while retry_count < max_retries {
                    self.file.seek(SeekFrom::Start(current_offset))
                        .with_context(|| format!("Ошибка позиционирования для записи в файле '{}' на смещение {}", 
                                                self.path.display(), current_offset))?;
                    
                    match self.file.write_all(chunk) {
                        Ok(_) => {
                            // Запись успешна
                            break;
                        },
                        Err(e) => {
                            // Запись не удалась, ждем немного и повторяем
                            retry_count += 1;
                            last_error = Some(e);
                            if retry_count < max_retries {
                                trace!("Retry #{} writing at offset {}: {}", retry_count, current_offset, last_error.as_ref().unwrap());
                                // Делаем более длительную паузу перед повторной попыткой
                                std::thread::sleep(std::time::Duration::from_millis(500 * retry_count as u64));
                            }
                        }
                    }
                }
                
                // Если все попытки не удались, возвращаем ошибку
                if retry_count == max_retries {
                    return Err(anyhow!("Ошибка записи {} байт в файл '{}' на смещение {} после {} попыток: {}", 
                               chunk_size, self.path.display(), current_offset, max_retries, 
                               last_error.unwrap()));
                }
                
                bytes_written += chunk_size;
                
                // При записи на физическое устройство делаем более длительные паузы между блоками
                if self.is_physical && bytes_written < buffer.len() {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
            }
            
            trace!("Successfully wrote {} bytes in chunks to offset {}", buffer.len(), offset);
            Ok(())
        } else {
            // Для обычных файлов или небольших блоков на физических устройствах используем обычную запись
            trace!("Writing {} bytes to offset {}", buffer.len(), offset);
            self.file.seek(SeekFrom::Start(offset))
                .with_context(|| format!("Ошибка позиционирования для записи в файле '{}' на смещение {}", 
                                        self.path.display(), offset))?;
            
            // Попытка записи с повторами при ошибке
            let mut retry_count = 0;
            let max_retries = 3;
            let mut last_error = None;
            
            while retry_count < max_retries {
                match self.file.write_all(buffer) {
                    Ok(_) => {
                        return Ok(());
                    },
                    Err(e) => {
                        retry_count += 1;
                        last_error = Some(e);
                        if retry_count < max_retries {
                            // Задержка перед повторной попыткой
                            std::thread::sleep(std::time::Duration::from_millis(200));
                        }
                    }
                }
            }
            
            Err(anyhow!("Ошибка записи {} байт в файл '{}' на смещение {} после {} попыток: {}", 
                       buffer.len(), self.path.display(), offset, max_retries, 
                       last_error.unwrap()))
        }
    }

    /// Читает указанное количество виртуальных секторов, начиная с заданного индекса.
    pub fn read_sectors(
        &mut self,
        start_sector: u64,
        num_sectors: u32,
        sector_size: u32, // Принимаем для совместимости, но проверяем с VIRTUAL_SECTOR_SIZE
        buffer: &mut [u8],
    ) -> Result<()> {
        // Если это физическое устройство, используем реальный размер сектора
        let actual_sector_size = if self.is_physical {
            match self.real_sector_size {
                Some(size) => size,
                None => {
                    // Если real_sector_size не установлен, но это физическое устройство,
                    // используем предоставленный размер сектора
                    sector_size
                }
            }
        } else {
            // Для файлов-контейнеров проверяем соответствие виртуальному размеру сектора
            if sector_size != VIRTUAL_SECTOR_SIZE {
                bail!("Sector size mismatch: expected {}, got {}", VIRTUAL_SECTOR_SIZE, sector_size);
            }
            VIRTUAL_SECTOR_SIZE
        };

        let expected_buffer_size = (num_sectors * actual_sector_size) as usize;
        if buffer.len() != expected_buffer_size {
            bail!(
                "Invalid buffer size for read_sectors. Expected {}, got {}",
                expected_buffer_size,
                buffer.len()
            );
        }
        let offset = start_sector * actual_sector_size as u64;
        self.read_at(offset, buffer)
    }

    /// Записывает данные в указанное количество виртуальных секторов, начиная с заданного индекса.
    pub fn write_sectors(
        &mut self,
        start_sector: u64,
        sector_size: u32, // Принимаем для совместимости
        buffer: &[u8],
    ) -> Result<()> {
        // Если это физическое устройство, используем реальный размер сектора
        let actual_sector_size = if self.is_physical {
            match self.real_sector_size {
                Some(size) => size,
                None => {
                    // Если real_sector_size не установлен, но это физическое устройство,
                    // используем предоставленный размер сектора
                    sector_size
                }
            }
        } else {
            // Для файлов-контейнеров проверяем соответствие виртуальному размеру сектора
            if sector_size != VIRTUAL_SECTOR_SIZE {
                bail!("Sector size mismatch: expected {}, got {}", VIRTUAL_SECTOR_SIZE, sector_size);
            }
            VIRTUAL_SECTOR_SIZE
        };

        if buffer.is_empty() || buffer.len() % actual_sector_size as usize != 0 {
            bail!(
                "Invalid buffer size for write_sectors. Size {} is not a multiple of sector size {}",
                buffer.len(),
                actual_sector_size
            );
        }
        let offset = start_sector * actual_sector_size as u64;
        self.write_at(offset, buffer)
    }

    // Адаптер для простого открытия по пути (для совместимости)
    pub fn open_path(path: &Path) -> Result<Self> {
        // Преобразуем Path в строку
        let path_str = path.to_str().ok_or_else(|| anyhow!("Invalid path"))?;
        Self::open(path_str, false)
    }

    /// Проверяет, является ли файл физическим устройством
    pub fn is_physical_device(&self) -> bool {
        self.is_physical
    }
}

/// Открывает устройство для чтения и записи
pub fn open_device(device_path: &str) -> Result<VolumeFile> {
    if cfg!(target_os = "windows") {
        open_windows_device(device_path)
    } else if cfg!(any(target_os = "linux", target_os = "macos")) {
        open_unix_device(device_path)
    } else {
        Err(anyhow!("Unsupported platform"))
    }
}

/// Открывает устройство только для чтения
pub fn open_device_readonly(device_path: &str) -> Result<VolumeFile> {
    if cfg!(target_os = "windows") {
        open_windows_device_readonly(device_path)
    } else if cfg!(any(target_os = "linux", target_os = "macos")) {
        open_unix_device_readonly(device_path)
    } else {
        Err(anyhow!("Unsupported platform"))
    }
}

#[cfg(target_os = "windows")]
fn open_windows_device(device_path: &str) -> Result<VolumeFile> {
    
    use std::os::windows::io::{FromRawHandle, RawHandle};
    use winapi::um::winioctl::{DISK_GEOMETRY, IOCTL_DISK_GET_DRIVE_GEOMETRY, IOCTL_DISK_IS_WRITABLE};
    use winapi::um::fileapi::{CreateFileW, OPEN_EXISTING};
    use winapi::um::winnt::{FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_READ, GENERIC_WRITE};
    use winapi::um::handleapi::{INVALID_HANDLE_VALUE, CloseHandle};
    use winapi::um::ioapiset::DeviceIoControl;
    use std::path::PathBuf;
    
    // Преобразуем путь к устройству в широкую строку
    let wide_path = std::os::windows::ffi::OsStrExt::encode_wide(
        std::ffi::OsStr::new(device_path)
    ).chain(Some(0)).collect::<Vec<_>>();
    
    // Открываем устройство
    let handle = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null_mut(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };
    
    if handle == INVALID_HANDLE_VALUE {
        return Err(anyhow!("Failed to open device: {}", std::io::Error::last_os_error()));
    }
    
    // Проверяем доступ на запись
    let mut bytes_returned: u32 = 0;
    let writable_result = unsafe {
        DeviceIoControl(
            handle as *mut _,
            IOCTL_DISK_IS_WRITABLE,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            0,
            &mut bytes_returned,
            std::ptr::null_mut(),
        )
    };
    
    if writable_result == 0 {
        let error = std::io::Error::last_os_error();
        unsafe { CloseHandle(handle) };
        
        // Если ошибка "Доступ запрещен" (Error 5), то устройство может быть защищено от записи
        if error.raw_os_error() == Some(5) {
            return Err(anyhow!("Устройство защищено от записи или требуются права администратора"));
        }
        
        return Err(anyhow!("Невозможно записывать на устройство: {}", error));
    }
    
    // Получаем размер сектора с помощью DeviceIoControl
    let mut disk_geometry: DISK_GEOMETRY = unsafe { std::mem::zeroed() };
    
    let mut bytes_returned: u32 = 0;
    
    let ioctl_result = unsafe {
        DeviceIoControl(
            handle as *mut _,
            IOCTL_DISK_GET_DRIVE_GEOMETRY,
            std::ptr::null_mut(),
            0,
            &mut disk_geometry as *mut _ as *mut _,
            std::mem::size_of::<DISK_GEOMETRY>() as u32,
            &mut bytes_returned,
            std::ptr::null_mut(),
        )
    };
    
    if ioctl_result == 0 {
        let error = std::io::Error::last_os_error();
        unsafe { CloseHandle(handle) };
        return Err(anyhow!("Failed to get disk geometry: {}", error));
    }
    
    // Считываем характеристики диска
    let bytes_per_sector = disk_geometry.BytesPerSector;
    
    // Получаем размер диска напрямую из запроса (более безопасный вариант)
    let tracks_per_cylinder = disk_geometry.TracksPerCylinder as u64;
    let sectors_per_track = disk_geometry.SectorsPerTrack as u64;
    let bytes_per_sector_u64 = bytes_per_sector as u64;
    
    // Примерно оцениваем размер диска, избегая опасного QuadPart
    // Это будет работать корректно для большинства USB-устройств <2ТБ
    let cylinders = 1000u64; // Примерная оценка, достаточная для работы с флешками
    let total_size = cylinders * tracks_per_cylinder * sectors_per_track * bytes_per_sector_u64;
    
    debug!("Opened physical device: {} with sector size: {} bytes, estimated size: {} bytes", 
           device_path, bytes_per_sector, total_size);
    
    let size = total_size as u64;
    
    // Создание объекта File из handle
    let file = unsafe { std::fs::File::from_raw_handle(handle as RawHandle) };
    
    // Создаем буфер для очистки MBR/GPT при открытии тома для шифрования
    // Это нужно только для тома, который мы будем шифровать впервые
    let erase_first_sectors = true; // Флаг можно сделать опциональным параметром
    
    if erase_first_sectors {
        info!("Preparing device for encryption by clearing MBR/GPT structures...");
        let zero_buffer = vec![0u8; 4096]; // Очищаем первые 4KB (обычно достаточно для MBR и первого сектора GPT)
        
        // Создаем новый объект VolumeFile
        let mut volume_file = VolumeFile {
            file: file,
            path: PathBuf::from(device_path),
            is_physical: true,
            real_sector_size: Some(bytes_per_sector),
        };
        
        // Пробуем очистить начало диска для удаления таблицы разделов
        // Это нужно для обхода ограничений Windows на запись в первый сектор диска с форматированием
        if let Err(e) = volume_file.write_at(0, &zero_buffer) {
            debug!("Failed to clear MBR/GPT sectors, but this might be OK: {}", e);
            // Ошибка не критична, продолжаем работу
        } else {
            info!("Successfully cleared MBR/GPT sectors to prepare for encryption");
        }
        
        // После очистки MBR/GPT мы можем смело работать с диском
        return Ok(volume_file);
    }
    
    Ok(VolumeFile {
        file: file,
        path: PathBuf::from(device_path),
        is_physical: true,
        real_sector_size: Some(bytes_per_sector),
    })
}

#[cfg(target_os = "windows")]
fn open_windows_device_readonly(device_path: &str) -> Result<VolumeFile> {
    
    use std::os::windows::io::{FromRawHandle, RawHandle};
    use winapi::um::winioctl::{DISK_GEOMETRY, IOCTL_DISK_GET_DRIVE_GEOMETRY};
    use winapi::um::fileapi::{CreateFileW, OPEN_EXISTING};
    use winapi::um::winnt::{FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_READ};
    use winapi::um::handleapi::INVALID_HANDLE_VALUE;
    use winapi::um::ioapiset::DeviceIoControl;
    use std::path::PathBuf;
    
    // Преобразуем путь к устройству в широкую строку
    let wide_path = std::os::windows::ffi::OsStrExt::encode_wide(
        std::ffi::OsStr::new(device_path)
    ).chain(Some(0)).collect::<Vec<_>>();
    
    // Открываем устройство только для чтения
    let handle = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null_mut(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };
    
    if handle == INVALID_HANDLE_VALUE {
        return Err(anyhow!("Failed to open device: {}", std::io::Error::last_os_error()));
    }
    
    // Получаем размер сектора с помощью DeviceIoControl
    let mut disk_geometry: DISK_GEOMETRY = unsafe { std::mem::zeroed() };
    
    let mut bytes_returned: u32 = 0;
    
    let ioctl_result = unsafe {
        DeviceIoControl(
            handle as *mut _,
            IOCTL_DISK_GET_DRIVE_GEOMETRY,
            std::ptr::null_mut(),
            0,
            &mut disk_geometry as *mut _ as *mut _,
            std::mem::size_of::<DISK_GEOMETRY>() as u32,
            &mut bytes_returned,
            std::ptr::null_mut(),
        )
    };
    
    let bytes_per_sector = if ioctl_result != 0 {
        // DeviceIoControl успешно завершился
        disk_geometry.BytesPerSector
    } else {
        // В случае ошибки используем стандартный размер сектора
        debug!("Failed to get sector size, using default: {}", std::io::Error::last_os_error());
        512 // Стандартный размер сектора для большинства устройств
    };
    
    debug!("Device sector size: {} bytes", bytes_per_sector);
    
    // Создаем File из handle
    let file = unsafe { std::fs::File::from_raw_handle(handle as RawHandle) };
    
    // Создаем и возвращаем VolumeFile с реальным размером сектора
    Ok(VolumeFile {
        file,
        path: PathBuf::from(device_path),
        is_physical: true,
        real_sector_size: Some(bytes_per_sector),
    })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn open_unix_device(device_path: &str) -> Result<VolumeFile> {
    // Implementation will be added later
    Err(anyhow!("Not implemented yet"))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn open_unix_device_readonly(device_path: &str) -> Result<VolumeFile> {
    // Implementation will be added later
    Err(anyhow!("Not implemented yet"))
}

// Добавляем заглушки для Unix-функций, чтобы компиляция не ломалась на Windows
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn open_unix_device(device_path: &str) -> Result<VolumeFile> {
    Err(anyhow!("Unix-specific function called on non-Unix platform"))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn open_unix_device_readonly(device_path: &str) -> Result<VolumeFile> {
    Err(anyhow!("Unix-specific function called on non-Unix platform"))
}

// Реализация Drop не нужна, так как File автоматически закрывается при выходе из области видимости. 