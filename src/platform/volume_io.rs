use anyhow::{bail, Context, Result};
use log::{debug, trace};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;

/// Определяем виртуальный размер сектора для работы внутри файла-контейнера.
/// 4096 байт - частый размер сектора для современных дисков и ФС.
const VIRTUAL_SECTOR_SIZE: u32 = 4096;

/// Представляет открытый файл-контейнер тома UniFortress.
pub struct VolumeFile {
    file: File, // Обертка над стандартным файлом
    path: PathBuf, // Сохраняем путь для сообщений об ошибках
    is_physical: bool, // Флаг для работы с физическим устройством
    real_sector_size: Option<u32>, // Реальный размер сектора для физического устройства
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
        trace!("Writing {} bytes to offset {}", buffer.len(), offset);
        self.file.seek(SeekFrom::Start(offset))
             .with_context(|| format!("Ошибка позиционирования для записи в файле '{}' на смещение {}", self.path.display(), offset))?;
        self.file.write_all(buffer)
            .with_context(|| format!("Ошибка записи {} байт в файл '{}' на смещение {}", buffer.len(), self.path.display(), offset))?;
        Ok(())
    }

    /// Читает указанное количество виртуальных секторов, начиная с заданного индекса.
    pub fn read_sectors(
        &mut self,
        start_sector: u64,
        num_sectors: u32,
        sector_size: u32, // Принимаем для совместимости, но проверяем с VIRTUAL_SECTOR_SIZE
        buffer: &mut [u8],
    ) -> Result<()> {
        if sector_size != VIRTUAL_SECTOR_SIZE {
             bail!("Несоответствие размера сектора: ожидался {}, получен {}", VIRTUAL_SECTOR_SIZE, sector_size);
        }
        let expected_buffer_size = (num_sectors * VIRTUAL_SECTOR_SIZE) as usize;
        if buffer.len() != expected_buffer_size {
            bail!(
                "Неверный размер буфера для read_sectors. Ожидался {}, получен {}",
                expected_buffer_size,
                buffer.len()
            );
        }
        let offset = start_sector * VIRTUAL_SECTOR_SIZE as u64;
        self.read_at(offset, buffer)
    }

    /// Записывает данные в указанное количество виртуальных секторов, начиная с заданного индекса.
    pub fn write_sectors(
        &mut self,
        start_sector: u64,
        sector_size: u32, // Принимаем для совместимости
        buffer: &[u8],
    ) -> Result<()> {
         if sector_size != VIRTUAL_SECTOR_SIZE {
             bail!("Несоответствие размера сектора: ожидался {}, получен {}", VIRTUAL_SECTOR_SIZE, sector_size);
        }
        if buffer.is_empty() || buffer.len() % VIRTUAL_SECTOR_SIZE as usize != 0 {
            bail!(
                "Неверный размер буфера для write_sectors. Размер {} не кратен размеру сектора {}",
                buffer.len(),
                VIRTUAL_SECTOR_SIZE
            );
        }
        let offset = start_sector * VIRTUAL_SECTOR_SIZE as u64;
        self.write_at(offset, buffer)
    }
}

// Реализация Drop не нужна, так как File автоматически закрывается при выходе из области видимости. 