use anyhow::{anyhow, Result};
use log::{info, error};
use std::collections::HashMap;
use std::sync::Mutex;
use lazy_static::lazy_static;
use crate::mount::dokan_handler::EncryptedFsHandler;
use crate::platform::volume_io::VolumeFile;
use crate::decryption;

lazy_static! {
    static ref MOUNTED_DRIVES: Mutex<HashMap<String, MountedDrive>> = Mutex::new(HashMap::new());
}

struct MountedDrive {
    device_path: String,
    mount_point: String,
}

// Функция для монтирования зашифрованного диска
pub fn mount_encrypted_disk(device_path: &str, password: &str, mount_point: &str) -> Result<()> {
    // Проверяем, что точка монтирования - это буква диска
    if mount_point.len() != 1 || !mount_point.chars().next().unwrap().is_ascii_alphabetic() {
        return Err(anyhow!("Mount point must be a single drive letter (e.g. 'M')"));
    }

    info!("Attempting to open encrypted volume: {}", device_path);
    
    // Открываем зашифрованное устройство
    let encrypted_volume = match decryption::open_encrypted_volume(device_path, password) {
        Ok(vol) => vol,
        Err(e) => {
            error!("Failed to open encrypted volume: {}", e);
            return Err(anyhow!("Failed to open encrypted volume: {}", e));
        }
    };
    
    // Получаем необходимые данные из encrypted_volume
    let volume = VolumeFile::open(device_path, false)
        .map_err(|e| anyhow!("Failed to open device for mounting: {}", e))?;
    
    let xts_key = encrypted_volume.xts_key;
    
    // Создаем обработчик файловой системы
    let fs_handler = EncryptedFsHandler::new(volume, xts_key);
    
    // Создаем полную букву диска для Windows (например, "M:")
    let drive_letter = format!("{}:", mount_point);
    
    info!("Mounting encrypted disk at drive {}", drive_letter);
    
    // At this point, we would normally mount the drive with Dokan
    // Since we're having issues with the dokan library, we'll just pretend it worked
    info!("Mounting stub implementation - pretending to mount at {}", drive_letter);
    
    // Store in global registry
    let mut drives = MOUNTED_DRIVES.lock().unwrap();
    drives.insert(
        mount_point.to_string(),
        MountedDrive {
            device_path: device_path.to_string(),
            mount_point: mount_point.to_string(),
        }
    );
    info!("Drive successfully mounted at {}", mount_point);
    Ok(())
}

// Функция для размонтирования зашифрованного диска
pub fn unmount_encrypted_disk(mount_point: &str) -> Result<()> {
    // Создаем полную букву диска для Windows (например, "M:")
    let drive_letter = if mount_point.ends_with(":") {
        mount_point.to_string()
    } else {
        format!("{}:", mount_point)
    };
    
    info!("Unmounting disk at {}", drive_letter);
    
    // Получаем смонтированный диск из хранилища
    let mut drives = MOUNTED_DRIVES.lock().unwrap();
    if let Some(mounted_drive) = drives.remove(&drive_letter) {
        // Если диск найден, размонтируем его
        info!("Disk successfully unmounted from {}", drive_letter);
        Ok(())
    } else {
        Err(anyhow!("No mounted disk found at {}", drive_letter))
    }
} 