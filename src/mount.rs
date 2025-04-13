use crate::platform::volume_io::VolumeFile;
use crate::encryption::{XTS_KEY_SIZE}; // Импортируем константу
use crate::decryption::decrypt_sector;
use crate::encryption::encrypt_sector;
use anyhow::Result;
use dokan_rust::{
    DokanHandle, FileSystemHandler, DokanFileInfo, 
    FileInfo, VolumeInfo, DiskSpaceInfo, FindData,
    FileAttribute, FileSystemFeature, FileAccess, FileShare,
    FileDisposition, FileOptions, FileSecurity
};
use std::sync::{Arc, Mutex}; // Нужен Mutex для VolumeFile, т.к. Dokan может вызывать методы из разных потоков
use std::io::{self, Error, ErrorKind};
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use std::ffi::{OsString, OsStr};
use std::path::{Path, PathBuf};
use log::{info, error, debug, warn};

// Определяем константу или импортируем из encryption?
// Пока определим здесь для простоты, но лучше вынести в общее место.
// const XTS_KEY_SIZE: usize = 64;

// Константы для файловой системы
const DATA_FILE_NAME: &str = "data.bin";
const SECTOR_SIZE: u32 = 4096; // Синхронизировано с VIRTUAL_SECTOR_SIZE из volume_io.rs
const HEADER_SECTORS: u64 = 2; // Количество секторов занятых под заголовок

pub struct EncryptedFsHandler {
    volume: Arc<Mutex<VolumeFile>>, // VolumeFile нужно обернуть в Mutex для потокобезопасности
    xts_key: [u8; XTS_KEY_SIZE],
    volume_size: u64,
    // TODO: Добавить поля для кеширования или управления файловой системой, если потребуется
}

impl EncryptedFsHandler {
    pub fn new(volume: VolumeFile, xts_key: [u8; XTS_KEY_SIZE]) -> Self {
        let volume_size = volume.get_file_size().unwrap_or(0);
        EncryptedFsHandler {
            volume: Arc::new(Mutex::new(volume)), // Оборачиваем volume в Arc<Mutex>
            xts_key,
            volume_size,
        }
    }

    // Конвертирует относительное смещение в файле в номер сектора
    // Учитывает смещение заголовка (первые HEADER_SECTORS)
    fn offset_to_sector(&self, offset: u64) -> u64 {
        let sector_size = SECTOR_SIZE as u64;
        let sector = (offset / sector_size) + HEADER_SECTORS;
        sector
    }

    // Проверяет, является ли путь нашим data.bin файлом
    fn is_data_file(&self, path: &OsStr) -> bool {
        let path_str = path.to_string_lossy();
        let path = Path::new(&*path_str);
        
        if let Some(file_name) = path.file_name() {
            return file_name.to_string_lossy() == DATA_FILE_NAME;
        }
        false
    }
    
    // Возвращает размер данных (без заголовка)
    fn get_data_size(&self) -> u64 {
        if self.volume_size <= (HEADER_SECTORS * SECTOR_SIZE as u64) {
            return 0;
        }
        self.volume_size - (HEADER_SECTORS * SECTOR_SIZE as u64)
    }
}

impl FileSystemHandler for EncryptedFsHandler {
    fn create_file(
        &self,
        file_name: &OsStr,
        _security_context: FileSecurity,
        desired_access: FileAccess,
        file_attributes: FileAttribute,
        share_access: FileShare,
        disposition: FileDisposition,
        options: FileOptions,
        info: &DokanFileInfo,
    ) -> io::Result<DokanHandle> {
        debug!("create_file: {:?}, disposition: {:?}", file_name, disposition);
        
        // Корневой каталог
        if file_name.to_string_lossy() == "\\" {
            return Ok(DokanHandle::root_directory());
        }
        
        // Наш единственный файл data.bin
        if self.is_data_file(file_name) {
            // Проверка наличия доступа на запись
            if desired_access.contains(FileAccess::GENERIC_WRITE) 
                || desired_access.contains(FileAccess::FILE_WRITE_DATA) {
                debug!("Write access requested for data.bin");
            }
            
            // Открываем файл
            return Ok(DokanHandle::named_pipe());  // Используем любой ненулевой хэндл
        }
        
        // Любой другой файл/каталог
        Err(io::Error::new(ErrorKind::NotFound, "File not found"))
    }
    
    fn close_file(&self, _file_name: &OsStr, _info: &DokanFileInfo) -> io::Result<()> {
        debug!("close_file called");
        Ok(())
    }
    
    fn read_file(
        &self,
        file_name: &OsStr,
        _offset: i64,
        buffer: &mut [u8],
        _info: &DokanFileInfo,
    ) -> io::Result<u32> {
        if !self.is_data_file(file_name) {
            return Err(io::Error::new(ErrorKind::NotFound, "File not found"));
        }
        
        let offset = _offset as u64;
        if offset >= self.get_data_size() {
            return Ok(0); // EOF
        }
        
        let mut volume = match self.volume.lock() {
            Ok(v) => v,
            Err(_) => return Err(io::Error::new(ErrorKind::Other, "Failed to lock volume")),
        };
        
        // Вычисляем начальный сектор и смещение внутри него
        let sector_size = SECTOR_SIZE as u64;
        let start_sector = self.offset_to_sector(offset);
        let sector_offset = offset % sector_size;
        
        // Сколько байт нам нужно прочитать
        let bytes_to_read = buffer.len() as u64;
        let bytes_to_end = self.get_data_size() - offset;
        let actual_bytes_to_read = bytes_to_read.min(bytes_to_end);
        
        if actual_bytes_to_read == 0 {
            return Ok(0);
        }
        
        let mut bytes_read = 0;
        let mut buffer_offset = 0;
        
        // Читаем первый сектор (возможно, частично)
        if sector_offset > 0 || actual_bytes_to_read < sector_size {
            let mut sector_buffer = vec![0u8; sector_size as usize];
            match volume.read_sectors(start_sector, 1, SECTOR_SIZE, &mut sector_buffer) {
                Ok(_) => {
                    // Расшифровываем сектор
                    if let Err(e) = decrypt_sector(&self.xts_key, start_sector as u128, &mut sector_buffer) {
                        error!("Failed to decrypt sector {}: {:?}", start_sector, e);
                        return Err(io::Error::new(ErrorKind::Other, "Decryption error"));
                    }
                    
                    // Копируем данные в выходной буфер
                    let first_chunk_size = ((sector_size - sector_offset) as usize).min(actual_bytes_to_read as usize);
                    buffer[0..first_chunk_size].copy_from_slice(&sector_buffer[sector_offset as usize..(sector_offset as usize + first_chunk_size)]);
                    
                    buffer_offset += first_chunk_size;
                    bytes_read += first_chunk_size as u64;
                },
                Err(e) => {
                    error!("Failed to read sector {}: {:?}", start_sector, e);
                    return Err(io::Error::new(ErrorKind::Other, "Read error"));
                }
            }
        }
        
        // Читаем остальные полные сектора
        let remaining_bytes = actual_bytes_to_read - bytes_read;
        let full_sectors = remaining_bytes / sector_size;
        
        if full_sectors > 0 {
            for i in 0..full_sectors {
                let current_sector = start_sector + (if sector_offset > 0 { 1 } else { 0 }) + i;
                let mut sector_buffer = vec![0u8; sector_size as usize];
                
                match volume.read_sectors(current_sector, 1, SECTOR_SIZE, &mut sector_buffer) {
                    Ok(_) => {
                        // Расшифровываем сектор
                        if let Err(e) = decrypt_sector(&self.xts_key, current_sector as u128, &mut sector_buffer) {
                            error!("Failed to decrypt sector {}: {:?}", current_sector, e);
                            return Err(io::Error::new(ErrorKind::Other, "Decryption error"));
                        }
                        
                        // Копируем данные в выходной буфер
                        buffer[buffer_offset..(buffer_offset + sector_size as usize)]
                            .copy_from_slice(&sector_buffer[0..sector_size as usize]);
                        
                        buffer_offset += sector_size as usize;
                        bytes_read += sector_size;
                    },
                    Err(e) => {
                        error!("Failed to read sector {}: {:?}", current_sector, e);
                        return Err(io::Error::new(ErrorKind::Other, "Read error"));
                    }
                }
            }
        }
        
        // Читаем последний частичный сектор, если нужно
        let remaining_bytes = actual_bytes_to_read - bytes_read;
        if remaining_bytes > 0 {
            let final_sector = start_sector + (if sector_offset > 0 { 1 } else { 0 }) + full_sectors;
            let mut sector_buffer = vec![0u8; sector_size as usize];
            
            match volume.read_sectors(final_sector, 1, SECTOR_SIZE, &mut sector_buffer) {
                Ok(_) => {
                    // Расшифровываем сектор
                    if let Err(e) = decrypt_sector(&self.xts_key, final_sector as u128, &mut sector_buffer) {
                        error!("Failed to decrypt sector {}: {:?}", final_sector, e);
                        return Err(io::Error::new(ErrorKind::Other, "Decryption error"));
                    }
                    
                    // Копируем данные в выходной буфер
                    buffer[buffer_offset..(buffer_offset + remaining_bytes as usize)]
                        .copy_from_slice(&sector_buffer[0..remaining_bytes as usize]);
                    
                    bytes_read += remaining_bytes;
                },
                Err(e) => {
                    error!("Failed to read sector {}: {:?}", final_sector, e);
                    return Err(io::Error::new(ErrorKind::Other, "Read error"));
                }
            }
        }
        
        Ok(bytes_read as u32)
    }

    fn write_file(
        &self,
        file_name: &OsStr,
        _offset: i64,
        buffer: &[u8],
        _info: &DokanFileInfo,
    ) -> io::Result<u32> {
        if !self.is_data_file(file_name) {
            return Err(io::Error::new(ErrorKind::NotFound, "File not found"));
        }
        
        let offset = _offset as u64;
        if offset >= self.get_data_size() {
            return Err(io::Error::new(ErrorKind::InvalidInput, "Offset beyond file size"));
        }
        
        let mut volume = match self.volume.lock() {
            Ok(v) => v,
            Err(_) => return Err(io::Error::new(ErrorKind::Other, "Failed to lock volume")),
        };
        
        // Вычисляем начальный сектор и смещение внутри него
        let sector_size = SECTOR_SIZE as u64;
        let start_sector = self.offset_to_sector(offset);
        let sector_offset = offset % sector_size;
        
        // Сколько байт нам нужно записать
        let bytes_to_write = buffer.len() as u64;
        let bytes_to_end = self.get_data_size() - offset;
        let actual_bytes_to_write = bytes_to_write.min(bytes_to_end);
        
        if actual_bytes_to_write == 0 {
            return Ok(0);
        }
        
        let mut bytes_written = 0;
        let mut buffer_offset = 0;
        
        // Записываем первый сектор (возможно, частично)
        if sector_offset > 0 || actual_bytes_to_write < sector_size {
            let mut sector_buffer = vec![0u8; sector_size as usize];
            
            // Сначала читаем текущий сектор, чтобы не перезаписать ненужные данные
            match volume.read_sectors(start_sector, 1, SECTOR_SIZE, &mut sector_buffer) {
                Ok(_) => {
                    // Расшифровываем сектор
                    if let Err(e) = decrypt_sector(&self.xts_key, start_sector as u128, &mut sector_buffer) {
                        error!("Failed to decrypt sector {}: {:?}", start_sector, e);
                        return Err(io::Error::new(ErrorKind::Other, "Decryption error"));
                    }
                    
                    // Модифицируем данные в буфере сектора
                    let first_chunk_size = ((sector_size - sector_offset) as usize).min(actual_bytes_to_write as usize);
                    sector_buffer[sector_offset as usize..(sector_offset as usize + first_chunk_size)]
                        .copy_from_slice(&buffer[0..first_chunk_size]);
                    
                    // Шифруем сектор обратно
                    if let Err(e) = encrypt_sector(&self.xts_key, start_sector as u128, &mut sector_buffer) {
                        error!("Failed to encrypt sector {}: {:?}", start_sector, e);
                        return Err(io::Error::new(ErrorKind::Other, "Encryption error"));
                    }
                    
                    // Записываем зашифрованный сектор обратно
                    if let Err(e) = volume.write_sectors(start_sector, SECTOR_SIZE, &sector_buffer) {
                        error!("Failed to write sector {}: {:?}", start_sector, e);
                        return Err(io::Error::new(ErrorKind::Other, "Write error"));
                    }
                    
                    buffer_offset += first_chunk_size;
                    bytes_written += first_chunk_size as u64;
                },
                Err(e) => {
                    error!("Failed to read sector {}: {:?}", start_sector, e);
                    return Err(io::Error::new(ErrorKind::Other, "Read error"));
                }
            }
        }
        
        // Записываем остальные полные сектора
        let remaining_bytes = actual_bytes_to_write - bytes_written;
        let full_sectors = remaining_bytes / sector_size;
        
        if full_sectors > 0 {
            for i in 0..full_sectors {
                let current_sector = start_sector + (if sector_offset > 0 { 1 } else { 0 }) + i;
                let mut sector_buffer = vec![0u8; sector_size as usize];
                
                // Копируем данные из входного буфера
                sector_buffer[0..sector_size as usize]
                    .copy_from_slice(&buffer[buffer_offset..(buffer_offset + sector_size as usize)]);
                
                // Шифруем сектор
                if let Err(e) = encrypt_sector(&self.xts_key, current_sector as u128, &mut sector_buffer) {
                    error!("Failed to encrypt sector {}: {:?}", current_sector, e);
                    return Err(io::Error::new(ErrorKind::Other, "Encryption error"));
                }
                
                // Записываем зашифрованный сектор
                if let Err(e) = volume.write_sectors(current_sector, SECTOR_SIZE, &sector_buffer) {
                    error!("Failed to write sector {}: {:?}", current_sector, e);
                    return Err(io::Error::new(ErrorKind::Other, "Write error"));
                }
                
                buffer_offset += sector_size as usize;
                bytes_written += sector_size;
            }
        }
        
        // Записываем последний частичный сектор, если нужно
        let remaining_bytes = actual_bytes_to_write - bytes_written;
        if remaining_bytes > 0 {
            let final_sector = start_sector + (if sector_offset > 0 { 1 } else { 0 }) + full_sectors;
            let mut sector_buffer = vec![0u8; sector_size as usize];
            
            // Сначала читаем текущий сектор
            match volume.read_sectors(final_sector, 1, SECTOR_SIZE, &mut sector_buffer) {
                Ok(_) => {
                    // Расшифровываем сектор
                    if let Err(e) = decrypt_sector(&self.xts_key, final_sector as u128, &mut sector_buffer) {
                        error!("Failed to decrypt sector {}: {:?}", final_sector, e);
                        return Err(io::Error::new(ErrorKind::Other, "Decryption error"));
                    }
                    
                    // Модифицируем данные в буфере сектора
                    sector_buffer[0..remaining_bytes as usize]
                        .copy_from_slice(&buffer[buffer_offset..(buffer_offset + remaining_bytes as usize)]);
                    
                    // Шифруем сектор обратно
                    if let Err(e) = encrypt_sector(&self.xts_key, final_sector as u128, &mut sector_buffer) {
                        error!("Failed to encrypt sector {}: {:?}", final_sector, e);
                        return Err(io::Error::new(ErrorKind::Other, "Encryption error"));
                    }
                    
                    // Записываем зашифрованный сектор обратно
                    if let Err(e) = volume.write_sectors(final_sector, SECTOR_SIZE, &sector_buffer) {
                        error!("Failed to write sector {}: {:?}", final_sector, e);
                        return Err(io::Error::new(ErrorKind::Other, "Write error"));
                    }
                    
                    bytes_written += remaining_bytes;
                },
                Err(e) => {
                    error!("Failed to read sector {}: {:?}", final_sector, e);
                    return Err(io::Error::new(ErrorKind::Other, "Read error"));
                }
            }
        }
        
        Ok(bytes_written as u32)
    }

    fn get_file_information(
        &self,
        file_name: &OsStr,
        _info: &DokanFileInfo,
    ) -> io::Result<FileInfo> {
        debug!("get_file_information: {:?}", file_name);
        
        // Корневой каталог
        if file_name.to_string_lossy() == "\\" {
            return Ok(FileInfo {
                attributes: FileAttribute::DIRECTORY,
                creation_time: SystemTime::now(),
                last_access_time: SystemTime::now(),
                last_write_time: SystemTime::now(),
                file_size: 0,
                number_of_links: 1,
                file_index: 0,
            });
        }
        
        // Наш единственный файл data.bin
        if self.is_data_file(file_name) {
            return Ok(FileInfo {
                attributes: FileAttribute::NORMAL | FileAttribute::ARCHIVE,
                creation_time: SystemTime::now(),
                last_access_time: SystemTime::now(),
                last_write_time: SystemTime::now(),
                file_size: self.get_data_size(),
                number_of_links: 1,
                file_index: 1,
            });
        }
        
        Err(io::Error::new(ErrorKind::NotFound, "File not found"))
    }

    fn find_files(
        &self,
        file_name: &OsStr,
        fill_find_data: &mut dyn FnMut(&FindData) -> io::Result<()>,
        _info: &DokanFileInfo,
    ) -> io::Result<()> {
        debug!("find_files: {:?}", file_name);
        
        // Только корневой каталог содержит файлы
        if file_name.to_string_lossy() == "\\" {
            // Добавляем точку и двоеточие для текущего и родительского каталогов
            fill_find_data(&FindData {
                file_name: OsString::from("."),
                attributes: FileAttribute::DIRECTORY,
                creation_time: SystemTime::now(),
                last_access_time: SystemTime::now(),
                last_write_time: SystemTime::now(),
                file_size: 0,
            })?;
            
            fill_find_data(&FindData {
                file_name: OsString::from(".."),
                attributes: FileAttribute::DIRECTORY,
                creation_time: SystemTime::now(),
                last_access_time: SystemTime::now(),
                last_write_time: SystemTime::now(),
                file_size: 0,
            })?;
            
            // Добавляем data.bin
            fill_find_data(&FindData {
                file_name: OsString::from(DATA_FILE_NAME),
                attributes: FileAttribute::NORMAL | FileAttribute::ARCHIVE,
                creation_time: SystemTime::now(),
                last_access_time: SystemTime::now(),
                last_write_time: SystemTime::now(),
                file_size: self.get_data_size(),
            })?;
            
            return Ok(());
        }
        
        // Для всех остальных каталогов ничего не находим
        Err(io::Error::new(ErrorKind::NotFound, "Directory not found"))
    }

    fn get_volume_information(&self) -> io::Result<VolumeInfo> {
        debug!("get_volume_information called");
        
        Ok(VolumeInfo {
            name: OsString::from("UniFortress"),
            serial_number: 0x12345678,
            max_component_length: 255,
            fs_flags: FileSystemFeature::CASE_PRESERVED_NAMES 
                | FileSystemFeature::CASE_SENSITIVE_SEARCH
                | FileSystemFeature::UNICODE_ON_DISK,
            fs_name: OsString::from("UniFortressFS"),
        })
    }

    fn get_disk_free_space(&self) -> io::Result<DiskSpaceInfo> {
        debug!("get_disk_free_space called");
        
        let total_size = self.get_data_size();
        
        Ok(DiskSpaceInfo {
            byte_count: SECTOR_SIZE as u64,  // Размер одного сектора
            free_bytes_count: 0,             // Свободное место (в нашем случае 0)
            total_bytes_count: total_size,   // Общий размер
        })
    }

    // Реализации других методов по умолчанию (флаши - не реализуем)
    fn flush_file_buffers(&self, _file_name: &OsStr, _info: &DokanFileInfo) -> io::Result<()> {
        Ok(())
    }

    fn get_file_security(
        &self,
        _file_name: &OsStr,
        _security_information: u32,
        _security_descriptor: Option<&mut [u8]>,
        _info: &DokanFileInfo,
    ) -> io::Result<u32> {
        Err(io::Error::new(ErrorKind::Unsupported, "Not implemented"))
    }

    fn set_file_security(
        &self,
        _file_name: &OsStr,
        _security_information: u32,
        _security_descriptor: &[u8],
        _info: &DokanFileInfo,
    ) -> io::Result<()> {
        Err(io::Error::new(ErrorKind::Unsupported, "Not implemented"))
    }

    fn set_file_attributes(
        &self,
        _file_name: &OsStr,
        _file_attributes: FileAttribute,
        _info: &DokanFileInfo,
    ) -> io::Result<()> {
        Ok(())
    }

    fn set_file_time(
        &self,
        _file_name: &OsStr,
        _creation_time: Option<SystemTime>,
        _last_access_time: Option<SystemTime>,
        _last_write_time: Option<SystemTime>,
        _info: &DokanFileInfo,
    ) -> io::Result<()> {
        Ok(())
    }
} 