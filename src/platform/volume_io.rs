use anyhow::{bail, Context, Result};
use log::{debug, trace};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Определяем виртуальный размер сектора для работы внутри файла-контейнера.
/// 4096 байт - частый размер сектора для современных дисков и ФС.
const VIRTUAL_SECTOR_SIZE: u32 = 4096;

/// Представляет открытый файл-контейнер тома UniFortress.
pub struct VolumeFile {
    file: File, // Обертка над стандартным файлом
    path: PathBuf, // Сохраняем путь для сообщений об ошибках
}

impl VolumeFile {
    /// Открывает существующий файл-контейнер для чтения и записи.
    pub fn open(file_path: &Path) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(file_path)
            .with_context(|| format!("Не удалось открыть файл '{}'", file_path.display()))?;
        debug!("Файл-контейнер '{}' открыт.", file_path.display());
        Ok(VolumeFile { 
            file, 
            path: file_path.to_path_buf() 
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
            path: file_path.to_path_buf() 
        })
    }

    /// Возвращает размер виртуального сектора.
    pub fn get_sector_size(&self) -> u32 {
        VIRTUAL_SECTOR_SIZE
    }

    /// Возвращает общий размер файла-контейнера в байтах.
    pub fn get_file_size(&self) -> Result<u64> {
        let metadata = self.file.metadata()
            .with_context(|| format!("Не удалось получить метаданные файла '{}'", self.path.display()))?;
        Ok(metadata.len())
    }

     /// Читает данные из файла, начиная с указанного байтового смещения.
    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> Result<()> {
        trace!("Reading {} bytes from offset {}", buffer.len(), offset);
        self.file.seek(SeekFrom::Start(offset))
             .with_context(|| format!("Ошибка позиционирования для чтения в файле '{}' на смещение {}", self.path.display(), offset))?;
        self.file.read_exact(buffer)
             .with_context(|| format!("Ошибка чтения {} байт из файла '{}' со смещения {}", buffer.len(), self.path.display(), offset))?;
        Ok(())
    }

     /// Записывает данные в файл, начиная с указанного байтового смещения.
    fn write_at(&mut self, offset: u64, buffer: &[u8]) -> Result<()> {
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