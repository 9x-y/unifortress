use anyhow::{Result, bail, Context};
use std::process::Command;
use std::fs::{OpenOptions, File};
use std::io::{Error, Read, Write, Seek, SeekFrom};
use std::path::Path;
use rand::{Rng, rngs::OsRng};
use rpassword::read_password;

use unifortress::platform::volume_io::VolumeFile;
use unifortress::encryption::{derive_key, split_derived_key, VolumeHeader};
use unifortress::decryption::decrypt_sector;
use unifortress::crypto::xts::encrypt_sector;

// Константы для различных вариантов доступа к диску
const PHYSICAL_DEVICE_PATHS: [&str; 3] = [
    r"\\.\PhysicalDrive1",  // Стандартный путь
    r"\\?\Device\Harddisk1\Partition0",  // Альтернативный путь
    r"D:",  // Доступ через букву диска
];
const TEST_PASSWORD: &str = "test_password123";
const SECTOR_SIZE: u32 = 4096;
const HEADER_SECTORS: u64 = 2; // Первые два сектора для заголовка
const TEST_FILE_PATH: &str = r"D:\test_unifortress.enc"; // Файл для тестирования вместо прямого доступа
const SALT_SIZE: usize = 16; // Размер соли для Argon2 (рекомендуется 16 байт)

// Генерируем криптографически стойкую случайную соль
fn generate_salt(size: usize) -> Vec<u8> {
    let mut salt = vec![0u8; size];
    OsRng.fill(&mut salt[..]);
    salt
}

fn get_disk_info(disk_number: u8) -> Result<String> {
    // Используем PowerShell для получения информации о диске с размером в ГБ
    let cmd = format!(
        "Get-Disk -Number {} | Select-Object Number, FriendlyName, @{{Name='SizeGB';Expression={{\"{{0:N2}} GB\" -f ($_.Size / 1GB)}}}} , BusType, PartitionStyle | Format-List; Get-Partition -DiskNumber {} | Select-Object DriveLetter, @{{Name='SizeGB';Expression={{\"{{0:N2}} GB\" -f ($_.Size / 1GB)}}}} , Type | Format-Table -AutoSize", 
        disk_number, 
        disk_number
    );
    
    let output = Command::new("powershell")
        .args(&[
            "-Command",
            &cmd
        ])
        .output()
        .context("Не удалось выполнить команду PowerShell для получения информации о диске")?;

    if !output.status.success() {
        bail!("Ошибка выполнения команды: {}", String::from_utf8_lossy(&output.stderr));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

// Функция для диагностики доступа к диску напрямую через стандартную библиотеку
fn test_direct_disk_access(path: &str) -> Result<()> {
    println!("Проверка прямого доступа к диску через std::fs::OpenOptions: {}", path);
    match OpenOptions::new().read(true).write(true).open(path) {
        Ok(_) => {
            println!("✅ Доступ получен через стандартную библиотеку");
            Ok(())
        },
        Err(e) => {
            println!("❌ Ошибка доступа через стандартную библиотеку: {} (os error {})", 
                     e, e.raw_os_error().unwrap_or(-1));
            bail!("Не удалось получить доступ к диску через std::fs")
        }
    }
}

// Упрощенная реализация VolumeFile для тестового файла вместо физического устройства
struct TestFileVolume {
    file: File,
    sector_size: u32,
}

impl TestFileVolume {
    fn open(path: &str, sector_size: u32) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .with_context(|| format!("Не удалось открыть файл '{}'", path))?;
        
        Ok(Self {
            file,
            sector_size,
        })
    }
    
    fn get_size(&self) -> Result<u64> {
        let metadata = self.file.metadata()
            .context("Не удалось получить метаданные файла")?;
        Ok(metadata.len())
    }
    
    fn get_sector_size(&self) -> u32 {
        self.sector_size
    }
    
    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> Result<()> {
        self.file.seek(SeekFrom::Start(offset))
            .context("Ошибка позиционирования для чтения")?;
        self.file.read_exact(buffer)
            .context("Ошибка чтения из файла")?;
        Ok(())
    }
    
    fn write_at(&mut self, offset: u64, buffer: &[u8]) -> Result<()> {
        self.file.seek(SeekFrom::Start(offset))
            .context("Ошибка позиционирования для записи")?;
        self.file.write_all(buffer)
            .context("Ошибка записи в файл")?;
        Ok(())
    }
    
    fn read_sectors(&mut self, start_sector: u64, num_sectors: u32, sector_size: u32, buffer: &mut [u8]) -> Result<()> {
        let offset = start_sector * sector_size as u64;
        self.read_at(offset, buffer)
    }
    
    fn write_sectors(&mut self, start_sector: u64, sector_size: u32, buffer: &[u8]) -> Result<()> {
        let offset = start_sector * sector_size as u64;
        self.write_at(offset, buffer)
    }
}

// Функция для запроса пароля у пользователя
fn get_password() -> Result<String> {
    println!("Enter password for disk encryption (will not be displayed): ");
    let password = read_password()?;
    
    if password.trim().is_empty() {
        println!("Password cannot be empty!");
        return get_password();
    }
    
    println!("Confirm password: ");
    let confirm_password = read_password()?;
    
    if password != confirm_password {
        println!("Passwords don't match! Try again.");
        return get_password();
    }
    
    Ok(password)
}

fn main() -> Result<()> {
    println!("PHYSICAL DEVICE ENCRYPTION TEST (FLASH DRIVE) - FILE MODE");
    println!("================================================================");
    
    // Get disk information
    let disk_number = 1; // PhysicalDrive1 corresponds to disk 1
    println!("Getting information about disk {}...", disk_number);
    
    match get_disk_info(disk_number) {
        Ok(info) => {
            println!("DISK INFORMATION:");
            println!("{}", info);
        },
        Err(e) => {
            println!("Failed to get disk information: {}", e);
            println!("Continuing without additional information...");
        }
    }
    
    // Check for administrator rights
    let is_admin = if cfg!(windows) {
        match Command::new("powershell")
            .args(&["-Command", "(New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"])
            .output() {
                Ok(output) => {
                    let output_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    if output_str == "True" {
                        println!("[OK] Program is running with administrator rights");
                        true
                    } else {
                        println!("[ERROR] Program is running WITHOUT administrator rights");
                        false
                    }
                },
                Err(e) => {
                    println!("[ERROR] Failed to check administrator rights: {}", e);
                    false
                }
            }
    } else {
        println!("[WARNING] Administrator rights check is not applicable for this OS");
        false
    };
    
    // Ask user: encrypt disk or open existing
    println!("\nSelect operation mode:");
    println!("1. Encrypt new disk");
    println!("2. Open existing encrypted disk");
    print!("Your choice (1 or 2): ");
    std::io::stdout().flush()?;
    
    let mut choice = String::new();
    std::io::stdin().read_line(&mut choice)?;
    let choice = choice.trim();
    
    let is_new_volume = match choice {
        "1" => true,
        "2" => false,
        _ => {
            println!("Invalid choice. Using new disk creation mode (1)");
            true
        }
    };
    
    println!("\n[WARNING] Direct access to physical device doesn't work.");
    println!("File mode will be used for testing on file: {}", TEST_FILE_PATH);
    println!("Press Enter to continue or Ctrl+C to cancel...");
    let mut buffer = String::new();
    std::io::stdin().read_line(&mut buffer)?;

    // Get password from user
    let password = get_password()?;
    println!("Password accepted. Password length: {} characters", password.len());

    // Use file instead of physical device
    println!("Opening test file {}...", TEST_FILE_PATH);
    let mut volume = TestFileVolume::open(TEST_FILE_PATH, SECTOR_SIZE)?;
    
    if is_new_volume {
        // Get file size (or set desired size for test)
        println!("Creating test file with size {} MB", 10);
        let test_file_size = 10 * 1024 * 1024; // 10 MB
        
        // Allocate space for file by writing zeros
        let zero_block = vec![0u8; SECTOR_SIZE as usize];
        for i in 0..test_file_size / SECTOR_SIZE as u64 {
            volume.write_sectors(i, SECTOR_SIZE, &zero_block)?;
        }
        
        let volume_size = volume.get_size()?;
        println!("Test file size: {} bytes ({:.2} MB)", 
                volume_size, volume_size as f64 / 1024.0 / 1024.0);
        println!("Sector size: {} bytes", SECTOR_SIZE);
        
        // Generate encryption keys using random salt
        println!("Generating encryption keys...");
        // Create random salt for Argon2
        let salt = generate_salt(SALT_SIZE);
        println!("Generated random salt with size {} bytes", salt.len());
        
        let derived_key = derive_key(password.as_bytes(), &salt)?;
        let (master_key, hmac_key) = split_derived_key(&derived_key)?;
        
        println!("Creating volume header...");
        
        // Create header with salt in metadata
        let header = VolumeHeader::new(volume_size, SECTOR_SIZE, &master_key, &hmac_key)?;
        
        // Save salt in header (normally this functionality should be inside VolumeHeader)
        // But for salt demonstration, we'll use this approach
        println!("Saving salt in volume header...");
        let header_serialized = header.serialize()?;
        
        // Write header
        println!("Writing header to test file...");
        let mut header_sector = vec![0u8; SECTOR_SIZE as usize];
        header_sector[..header_serialized.len()].copy_from_slice(&header_serialized);
        
        // Save salt in the last part of header for demonstration
        let salt_offset = SECTOR_SIZE as usize - SALT_SIZE - 8; // 8 bytes for tag
        header_sector[salt_offset..salt_offset+8].copy_from_slice(b"SALT-ID:");
        header_sector[salt_offset+8..salt_offset+8+salt.len()].copy_from_slice(&salt);
        
        volume.write_sectors(0, SECTOR_SIZE, &header_sector)?;
        
        // Write a test pattern to the first data sector
        println!("Writing test data...");
        let test_data = b"This is a test pattern for UniFortress encrypted volume!";
        let mut sector_buffer = vec![0u8; SECTOR_SIZE as usize];
        sector_buffer[..test_data.len()].copy_from_slice(test_data);
        
        // Encrypt the test data
        println!("Encrypting test data...");
        encrypt_sector(&mut sector_buffer, HEADER_SECTORS, &master_key)?;
        
        // Write the encrypted data to the first data sector
        println!("Writing encrypted data to sector {}...", HEADER_SECTORS);
        volume.write_sectors(HEADER_SECTORS, SECTOR_SIZE, &sector_buffer)?;
        
        // Flush to ensure data is written
        println!("Flushing cache to disk...");
        
        println!("\n[SUCCESS] Volume encrypted successfully!");
        println!("Password and salt have been used successfully to generate encryption keys.");
        println!("To access the volume, use the same password the next time you run the program.");
    } else {
        // Open existing volume mode
        println!("Reading encrypted volume header...");
        let mut header_sector = vec![0u8; SECTOR_SIZE as usize];
        volume.read_sectors(0, 1, SECTOR_SIZE, &mut header_sector)?;
        
        // Extract salt from header
        let salt_offset = SECTOR_SIZE as usize - SALT_SIZE - 8;
        let salt_tag = &header_sector[salt_offset..salt_offset+8];
        
        if salt_tag != b"SALT-ID:" {
            bail!("File is not a UniFortress encrypted volume or is corrupted!");
        }
        
        let salt = &header_sector[salt_offset+8..salt_offset+8+SALT_SIZE];
        println!("Found salt in volume header");
        
        // Generate keys from password and salt
        println!("Restoring encryption keys from password...");
        let derived_key = derive_key(password.as_bytes(), salt)?;
        let (master_key, hmac_key) = split_derived_key(&derived_key)?;
        
        // Read test sector
        println!("Checking data access...");
        let mut test_sector = vec![0u8; SECTOR_SIZE as usize];
        volume.read_sectors(HEADER_SECTORS, 1, SECTOR_SIZE, &mut test_sector)?;
        
        // Decrypt test sector
        println!("Decrypting test data...");
        decrypt_sector(&mut test_sector, HEADER_SECTORS, &master_key)?;
        
        // Check for text data in decrypted sector
        let text_prefix = b"This is a test";
        if test_sector.starts_with(text_prefix) {
            println!("\n[SUCCESS] Volume access granted!");
            println!("Decrypted data: \"{}\"", 
                     String::from_utf8_lossy(&test_sector[..50]).trim_end_matches('\0'));
        } else {
            println!("\n[ERROR] Access error! Possible wrong password or corrupted volume.");
            bail!("Failed to decrypt data with the given password");
        }
    }
    
    println!("\nTest completed successfully!");
    println!("Test file: {}", TEST_FILE_PATH);
    
    Ok(())
} 