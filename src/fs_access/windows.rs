use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::io::{Result, Error, ErrorKind};
use std::time::{SystemTime, UNIX_EPOCH};
use std::os::windows::ffi::OsStringExt;
use std::convert::TryFrom;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use dokan_sys::*;
use widestring::U16CString;
use widestring::U16Str;
use windows::Win32::Storage::FileSystem::{GetVolumePathNameW, GetDiskFreeSpaceExW};
use windows::Win32::Foundation::{HANDLE, CloseHandle};
use windows::core::PWSTR;
use windows::Win32::System::WindowsProgramming::MAXIMUM_ALLOWED;
use windows::Win32::System::IO::*;

// Add missing winapi imports
use winapi::shared::ntdef::{NTSTATUS, LPCWSTR, LPWSTR, LONGLONG, PULONGLONG, ULONG, PULONG};
use winapi::shared::minwindef::{DWORD, LPDWORD, BOOL, FILETIME, ULONG as MINWINDEF_ULONG};
use winapi::shared::ntstatus::{STATUS_SUCCESS, STATUS_ACCESS_DENIED, STATUS_INTERNAL_ERROR, STATUS_END_OF_FILE, STATUS_NOT_IMPLEMENTED};
use winapi::um::winnt::{FILE_READ_ONLY_VOLUME, FILE_CASE_PRESERVED_NAMES, FILE_CASE_SENSITIVE_SEARCH, PSECURITY_INFORMATION, PSECURITY_DESCRIPTOR};

use super::common::EncryptedStorageBase;
use super::{EncryptedStorage, MountedStorage};
use crate::crypto::xts;

/// Реализация для Windows с использованием Dokan
pub struct WindowsDokanMount {
    mount_point: PathBuf,
    storage: Arc<WindowsEncryptedStorage>,
}

impl MountedStorage for WindowsDokanMount {
    fn unmount(&self) -> Result<()> {
        unsafe {
            let mount_point = U16CString::from_os_str(self.mount_point.as_os_str())
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid mount point path"))?;
            if DokanRemoveMountPoint(mount_point.as_ptr()) == 0 {
                return Err(Error::new(ErrorKind::Other, "Failed to unmount volume"));
            }
        }
        Ok(())
    }

    fn get_mount_point(&self) -> &Path {
        &self.mount_point
    }
}

pub struct WindowsEncryptedStorage {
    base: EncryptedStorageBase,
}

impl WindowsEncryptedStorage {
    pub fn new(base: EncryptedStorageBase) -> Self {
        Self { base }
    }
    
    fn get_base(&self) -> &EncryptedStorageBase {
        &self.base
    }
}

impl fmt::Debug for WindowsEncryptedStorage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WindowsEncryptedStorage")
            .field("volume_size", &self.base.volume_size)
            .field("sector_size", &self.base.sector_size)
            .field("header_sectors", &self.base.header_sectors)
            .finish()
    }
}

impl EncryptedStorage for WindowsEncryptedStorage {
    fn mount(&self, mount_point: &Path) -> Result<Box<dyn MountedStorage>> {
        // Проверка путь монтирования
        let mount_path = mount_point.to_path_buf();
        
        // Создаем структуру для хранения операций Dokan
        let operations = DokanOperations {
            create_file: Some(create_file),
            cleanup: Some(cleanup),
            close_file: Some(close_file),
            read_file: Some(read_file),
            write_file: Some(write_file),
            flush_file_buffers: Some(flush_file_buffers),
            get_file_information: Some(get_file_information),
            find_files: Some(find_files),
            find_files_with_pattern: None,
            set_file_attributes: Some(set_file_attributes),
            set_file_time: Some(set_file_time),
            delete_file: Some(delete_file),
            delete_directory: Some(delete_directory),
            move_file: Some(move_file),
            set_end_of_file: Some(set_end_of_file),
            set_allocation_size: Some(set_allocation_size),
            lock_file: Some(lock_file),
            unlock_file: Some(unlock_file),
            get_disk_free_space: Some(get_disk_free_space),
            get_volume_information: Some(get_volume_information),
            mounted: Some(mounted),
            unmounted: Some(unmounted),
            get_file_security: Some(get_file_security),
            set_file_security: Some(set_file_security),
            fill_win32_find_data: None,
            fill_find_data: None,
            find_streams: None,
        };

        // Создаем Arc для хранилища
        let storage_arc = Arc::new(self.clone());
        
        // Настройки для Dokan
        let mut options = DokanOptions {
            version: DOKAN_VERSION,
            thread_count: 1,
            options: DOKAN_OPTION_ALT_STREAM | DOKAN_OPTION_WRITE_PROTECT,
            global_context: Arc::into_raw(storage_arc.clone()) as *mut _,
            mount_point: U16CString::from_os_str(mount_path.as_os_str())
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid mount point path"))?
                .into_raw(),
            umount_point: std::ptr::null_mut(),
            timeout: 0,
            allocation_unit_size: 0,
            sector_size: self.base.sector_size,
            file_system_flags: 0,
            file_info_timeout: 0,
            volume_security_descriptor_length: 0,
            volume_security_descriptor: std::ptr::null_mut(),
        };

        // Запускаем Dokan
        let result = unsafe { DokanMain(&mut options, &operations) };
        
        if result != DOKAN_SUCCESS as i32 {
            return Err(Error::new(ErrorKind::Other, 
                format!("Failed to mount volume. Dokan error: {}", result)));
        }

        // Создаем объект для управления монтированием
        Ok(Box::new(WindowsDokanMount {
            mount_point: mount_path,
            storage: storage_arc,
        }))
    }
}

impl Clone for WindowsEncryptedStorage {
    fn clone(&self) -> Self {
        Self {
            base: EncryptedStorageBase {
                volume: self.base.volume.clone(),
                xts_key: self.base.xts_key.clone(),
                volume_size: self.base.volume_size,
                sector_size: self.base.sector_size,
                header_sectors: self.base.header_sectors,
                base_path: self.base.base_path.clone(),
                encryption_key: self.base.encryption_key.clone(),
                read_only: self.base.read_only,
            }
        }
    }
}

// Обработчики операций для Dokan

unsafe extern "C" fn create_file(
    file_name: PDOKAN_IO_SECURITY_CONTEXT,
    desired_access: DWORD,
    file_attributes: DWORD,
    share_access: DWORD,
    creation_disposition: DWORD,
    flags_and_attrs: DWORD,
    dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
    // Пока просто разрешаем открыть файл
    dokan_file_info.as_mut().unwrap().IsDirectory = if file_name == std::ptr::null_mut() { 1 } else { 0 };
    return STATUS_SUCCESS;
}

unsafe extern "C" fn cleanup(
    _file_name: LPCWSTR,
    _dokan_file_info: PDOKAN_FILE_INFO,
) {
    // Не требуется реализация
}

unsafe extern "C" fn close_file(
    _file_name: LPCWSTR,
    _dokan_file_info: PDOKAN_FILE_INFO,
) {
    // Не требуется реализация
}

unsafe extern "C" fn read_file(
    file_name: LPCWSTR,
    buffer: LPVOID,
    buffer_length: DWORD,
    bytes_read: LPDWORD,
    offset: LONGLONG,
    dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
    let info = dokan_file_info.as_ref().unwrap();
    let storage = get_storage(info.DokanContext);
    
    if storage.is_none() {
        return STATUS_INTERNAL_ERROR;
    }
    let storage = storage.unwrap();
    
    // Запрашиваем только данные внутри доступной области
    let data_size = storage.get_base().get_data_size();
    if offset >= data_size as LONGLONG {
        *bytes_read = 0;
        return STATUS_END_OF_FILE;
    }
    
    // Ограничиваем чтение концом файла
    let actual_read_length = std::cmp::min(
        buffer_length as u64,
        data_size - offset as u64
    ) as DWORD;
    
    if actual_read_length == 0 {
        *bytes_read = 0;
        return STATUS_SUCCESS;
    }
    
    // Чтение и дешифрование данных из хранилища
    let mut volume = storage.get_base().volume.lock().unwrap();
    let sector_size = storage.get_base().sector_size as u64;
    let start_sector = storage.get_base().offset_to_sector(offset as u64);
    let end_sector = storage.get_base().offset_to_sector((offset as u64) + (actual_read_length as u64) - 1);
    
    // Буфер для расшифрованных данных
    let sector_buffer_size = ((end_sector - start_sector + 1) * sector_size) as usize;
    let mut sector_buffer = vec![0u8; sector_buffer_size];
    
    // Читаем и расшифровываем по секторам
    for i in 0..(end_sector - start_sector + 1) {
        let sector = start_sector + i;
        let sector_offset = (sector * sector_size) as u64;
        let sector_data_offset = (i * sector_size) as usize;
        
        // Чтение сектора
        if let Err(_) = volume.read_at(
            sector_offset,
            &mut sector_buffer[sector_data_offset..(sector_data_offset + sector_size as usize)]
        ) {
            return STATUS_INTERNAL_ERROR;
        }
        
        // Расшифровка сектора с XTS-AES
        if let Err(_) = xts::decrypt_sector(
            &mut sector_buffer[sector_data_offset..(sector_data_offset + sector_size as usize)],
            sector,
            &storage.get_base().xts_key
        ) {
            return STATUS_INTERNAL_ERROR;
        }
    }
    
    // Определяем смещение в буфере секторов
    let buffer_offset = (offset as u64 % sector_size) as usize;
    let buffer_slice = &sector_buffer[buffer_offset..(buffer_offset + actual_read_length as usize)];
    
    // Копируем расшифрованные данные в выходной буфер
    let output_buffer = std::slice::from_raw_parts_mut(buffer as *mut u8, actual_read_length as usize);
    output_buffer.copy_from_slice(buffer_slice);
    
    *bytes_read = actual_read_length;
    STATUS_SUCCESS
}

unsafe extern "C" fn write_file(
    _file_name: LPCWSTR,
    _buffer: LPCVOID,
    _number_of_bytes_to_write: DWORD,
    _number_of_bytes_written: LPDWORD,
    _offset: LONGLONG,
    _dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
    // Запрещаем запись (только чтение)
    STATUS_ACCESS_DENIED
}

unsafe extern "C" fn flush_file_buffers(
    _file_name: LPCWSTR,
    _dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
    STATUS_SUCCESS
}

unsafe extern "C" fn get_file_information(
    file_name: LPCWSTR,
    file_info: LPBY_HANDLE_FILE_INFORMATION,
    dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
    let info = dokan_file_info.as_ref().unwrap();
    let storage = get_storage(info.DokanContext);
    
    if storage.is_none() {
        return STATUS_INTERNAL_ERROR;
    }
    let storage = storage.unwrap();
    
    // Преобразуем file_name в строку
    let file_path = if !file_name.is_null() {
        let len = (0..).take_while(|&i| *file_name.add(i) != 0).count();
        let slice = std::slice::from_raw_parts(file_name, len);
        OsString::from_wide(slice).to_string_lossy().to_string()
    } else {
        String::from("")
    };
    
    // Проверяем, корневой каталог или файл
    let is_root = file_path.is_empty() || file_path == "\\" || file_path == "/";
    
    // Текущее время для метаданных
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    
    // Заполняем информацию о файле
    let buf = file_info.as_mut().unwrap();
    
    if is_root {
        // Для корневого каталога
        buf.dwFileAttributes = FILE_ATTRIBUTE_DIRECTORY;
        buf.ftCreationTime = filetime_from_unix(now);
        buf.ftLastAccessTime = filetime_from_unix(now);
        buf.ftLastWriteTime = filetime_from_unix(now);
        buf.nFileSizeHigh = 0;
        buf.nFileSizeLow = 0;
    } else {
        // Проверяем, не encrypted.img ли это
        if file_path == "\\encrypted.img" || file_path == "/encrypted.img" {
            let file_size = storage.get_base().get_data_size();
            buf.dwFileAttributes = FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_READONLY;
            buf.ftCreationTime = filetime_from_unix(now);
            buf.ftLastAccessTime = filetime_from_unix(now);
            buf.ftLastWriteTime = filetime_from_unix(now);
            buf.nFileSizeHigh = (file_size >> 32) as DWORD;
            buf.nFileSizeLow = (file_size & 0xFFFFFFFF) as DWORD;
        } else {
            // Файл не существует
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
    }
    
    STATUS_SUCCESS
}

unsafe extern "C" fn find_files(
    file_name: LPCWSTR,
    fill_find_data: PFillFindData,
    dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
    let info = dokan_file_info.as_ref().unwrap();
    let storage = get_storage(info.DokanContext);
    
    if storage.is_none() {
        return STATUS_INTERNAL_ERROR;
    }
    let storage = storage.unwrap();
    
    // Проверяем, что файл существует
    let path = unsafe_wstr_to_string(file_name);
    if !storage.file_exists(&path) {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }
    
    // Если это не директория, возвращаем ошибку
    if !storage.is_directory(&path) {
        return STATUS_NOT_A_DIRECTORY;
    }
    
    // Получаем список файлов и директорий
    let entries = match storage.list_directory(&path) {
        Ok(entries) => entries,
        Err(_) => return STATUS_ACCESS_DENIED,
    };
    
    // Для каждого файла/директории вызываем callback
    for entry in entries {
        let mut find_data = WIN32_FIND_DATAW::default();
        
        // Заполняем информацию о файле
        let name = entry.name.encode_utf16().collect::<Vec<u16>>();
        let name_len = name.len().min(MAX_PATH as usize - 1);
        find_data.cFileName[..name_len].copy_from_slice(&name[..name_len]);
        
        // Заполняем другие поля
        find_data.dwFileAttributes = if entry.is_directory {
            FILE_ATTRIBUTE_DIRECTORY
        } else {
            FILE_ATTRIBUTE_NORMAL
        };
        
        // Размер файла
        find_data.nFileSizeLow = (entry.size & 0xFFFFFFFF) as u32;
        find_data.nFileSizeHigh = (entry.size >> 32) as u32;
        
        // Время
        let ft = filetime_from_unix(entry.modified);
        find_data.ftLastWriteTime = ft;
        find_data.ftCreationTime = ft;
        find_data.ftLastAccessTime = ft;
        
        // Вызываем callback
        // Safety: fill_find_data is a function pointer that needs to be called directly
        let fill_function = fill_find_data;
        if !fill_function.is_null() {
            let result = fill_function(&find_data, dokan_file_info);
            if result != 0 {
                return result as NTSTATUS;
            }
        }
    }
    
    STATUS_SUCCESS
}

unsafe extern "C" fn set_file_attributes(
    _file_name: LPCWSTR,
    _file_attributes: DWORD,
    _dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
    // Запрещаем изменение атрибутов (только чтение)
    STATUS_ACCESS_DENIED
}

unsafe extern "C" fn set_file_time(
    _file_name: LPCWSTR,
    _creation_time: PFILETIME,
    _last_access_time: PFILETIME,
    _last_write_time: PFILETIME,
    _dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
    // Запрещаем изменение времени (только чтение)
    STATUS_ACCESS_DENIED
}

unsafe extern "C" fn delete_file(
    _file_name: LPCWSTR,
    _dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
    // Запрещаем удаление (только чтение)
    STATUS_ACCESS_DENIED
}

unsafe extern "C" fn delete_directory(
    _file_name: LPCWSTR,
    _dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
    // Запрещаем удаление (только чтение)
    STATUS_ACCESS_DENIED
}

unsafe extern "C" fn move_file(
    _file_name: LPCWSTR,
    _new_file_name: LPCWSTR,
    _replace_if_existing: BOOL,
    _dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
    // Запрещаем перемещение (только чтение)
    STATUS_ACCESS_DENIED
}

unsafe extern "C" fn set_end_of_file(
    _file_name: LPCWSTR,
    _byte_offset: LONGLONG,
    _dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
    // Запрещаем изменение размера (только чтение)
    STATUS_ACCESS_DENIED
}

unsafe extern "C" fn set_allocation_size(
    _file_name: LPCWSTR,
    _allocation_size: LONGLONG,
    _dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
    // Запрещаем изменение размера (только чтение)
    STATUS_ACCESS_DENIED
}

unsafe extern "C" fn lock_file(
    _file_name: LPCWSTR,
    _byte_offset: LONGLONG,
    _length: LONGLONG,
    _dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
    // Для совместимости разрешаем блокировки
    STATUS_SUCCESS
}

unsafe extern "C" fn unlock_file(
    _file_name: LPCWSTR,
    _byte_offset: LONGLONG,
    _length: LONGLONG,
    _dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
    // Для совместимости разрешаем разблокировки
    STATUS_SUCCESS
}

unsafe extern "C" fn get_disk_free_space(
    _free_bytes_available: PULONGLONG,
    _total_number_of_bytes: PULONGLONG,
    _total_number_of_free_bytes: PULONGLONG,
    dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
    let info = dokan_file_info.as_ref().unwrap();
    let storage = get_storage(info.DokanContext);
    
    if storage.is_none() {
        return STATUS_INTERNAL_ERROR;
    }
    let storage = storage.unwrap();
    
    let total_bytes = storage.get_base().get_data_size();
    
    // Виртуальный диск только для чтения, свободного места нет
    *_free_bytes_available = 0;
    *_total_number_of_bytes = total_bytes;
    *_total_number_of_free_bytes = 0;
    
    STATUS_SUCCESS
}

unsafe extern "C" fn get_volume_information(
    volume_name: LPWSTR,
    volume_name_size: DWORD,
    volume_serial_number: LPDWORD,
    maximum_component_length: LPDWORD,
    file_system_flags: LPDWORD,
    file_system_name: LPWSTR,
    file_system_name_size: DWORD,
    _dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
    // Имя тома
    let name = "UniFortress";
    let wide_name: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    for (i, &c) in wide_name.iter().enumerate().take(volume_name_size as usize) {
        *volume_name.add(i) = c;
    }
    
    // Серийный номер
    *volume_serial_number = 0x19452023;
    
    // Максимальная длина имени 
    *maximum_component_length = 255;
    
    // Флаги файловой системы (только чтение)
    *file_system_flags = FILE_READ_ONLY_VOLUME | FILE_CASE_PRESERVED_NAMES | FILE_CASE_SENSITIVE_SEARCH;
    
    // Имя файловой системы
    let fs_name = "NTFS";
    let wide_fs_name: Vec<u16> = fs_name.encode_utf16().chain(std::iter::once(0)).collect();
    for (i, &c) in wide_fs_name.iter().enumerate().take(file_system_name_size as usize) {
        *file_system_name.add(i) = c;
    }
    
    STATUS_SUCCESS
}

unsafe extern "C" fn mounted(
    _mount_point: LPCWSTR,
    _dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
    STATUS_SUCCESS
}

unsafe extern "C" fn unmounted(
    _dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
    STATUS_SUCCESS
}

unsafe extern "C" fn get_file_security(
    _file_name: LPCWSTR,
    _security_information: PSECURITY_INFORMATION,
    _security_descriptor: PSECURITY_DESCRIPTOR,
    _buffer_length: ULONG,
    _length_needed: PULONG,
    _dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
    // Упрощенная реализация безопасности
    *_length_needed = 0;
    STATUS_NOT_IMPLEMENTED
}

unsafe extern "C" fn set_file_security(
    _file_name: LPCWSTR,
    _security_information: PSECURITY_INFORMATION,
    _security_descriptor: PSECURITY_DESCRIPTOR,
    _buffer_length: ULONG,
    _dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
    // Запрещаем изменение безопасности (только чтение)
    STATUS_ACCESS_DENIED
}

// Вспомогательные функции

unsafe fn get_storage(context: *mut std::ffi::c_void) -> Option<Arc<WindowsEncryptedStorage>> {
    if context.is_null() {
        return None;
    }
    Some(Arc::from_raw(context as *const WindowsEncryptedStorage))
}

fn filetime_from_unix(secs: u64) -> FILETIME {
    // Windows FILETIME - 100-наносекундные интервалы с 1 января 1601
    // Unix time - секунды с 1 января 1970
    // Разница между эпохами в 100-наносекундных интервалах
    const EPOCH_DIFFERENCE: u64 = 11644473600;
    let win_time = (secs + EPOCH_DIFFERENCE) * 10000000;
    
    FILETIME {
        dwLowDateTime: (win_time & 0xFFFFFFFF) as DWORD,
        dwHighDateTime: (win_time >> 32) as DWORD,
    }
} 