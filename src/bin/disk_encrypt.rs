use std::fs::{File, OpenOptions};
use std::io::{Read, Write, Seek, SeekFrom};
use std::process::Command;
use std::cmp::min;
use anyhow::{Result, Context, anyhow, bail};
use clap::{Parser, Subcommand};
use rpassword::read_password;
use sha2::{Sha256, Digest};
use sha2::digest::KeyInit;
use rand::{rngs::OsRng, RngCore};
use rand::RngCore as _;
use aes::Aes256;
use xts_mode::Xts128 as Xts;
use env_logger;
use unifortress::mount;
use log::{debug, error, info, warn, LevelFilter};
use std::path::Path;
use std::time::Instant;
use unifortress::encryption;
use unifortress::platform::volume_io;
use unifortress::decryption;
use unifortress::deferred::DeferredEncryptedVolume;

// Constants
const HEADER_SIZE: usize = 4096; // 4KB for header
const SECTOR_SIZE: usize = 512; // Standard sector size
const SALT_SIZE: usize = 32; // Salt size
const KEY_SIZE: usize = 64; // 512 bits for XTS (2 keys, 256 bits each)

#[derive(Parser)]
#[command(author, version, about = "UniFortress - USB drive encryption utility")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt USB drive
    Encrypt {
        /// Drive letter (Windows only) or device path
        #[arg(short, long)]
        device: String,
    },
    /// Fast encrypt USB drive (deferred encryption)
    FastEncrypt {
        /// Drive letter (Windows only) or device path
        #[arg(short, long)]
        device: String,
    },
    /// Check encrypted USB drive
    Check {
        /// Drive letter (Windows only) or device path
        #[arg(short, long)]
        device: String,
    },
    /// List available drives
    List,
    /// Mount encrypted USB drive
    Mount {
        /// Drive letter (Windows only) or device path
        #[arg(short, long)]
        device: String,
        
        /// Mount point (folder path)
        #[arg(short, long, name = "mount-point")]
        mount_point: String,
    },
    /// Unmount encrypted USB drive
    Unmount {
        /// Mount point (folder path or drive letter)
        #[arg(short, long, name = "mount-point")]
        mount_point: String,
    },
}

fn main() -> Result<()> {
    // Инициализация логирования
    env_logger::builder()
        .filter_level(LevelFilter::Info)
        .init();
    
    // Проверка прав администратора
    println!("Running with admin privileges: {}", is_admin());
    
    // Получение конфигурации из аргументов командной строки
    let cli = Cli::parse();

    match &cli.command {
        Commands::Encrypt { device } => {
            info!("Starting encryption process for device: {}", device);

            // Получаем и выводим информацию о диске
            match get_disk_details(&device) {
                Ok((name, size)) => {
                    println!("Device details:");
                    println!("  Name: {}", name);
                    println!("  Size: {}", size);
                },
                Err(e) => {
                    println!("Warning: Could not retrieve full device details: {}", e);
                }
            }

            // ВНИМАНИЕ: Подтверждение, что мы действительно хотим зашифровать устройство
            println!("WARNING: All data on the device will be DESTROYED!");
            println!("Device to encrypt: {}", device);
            print!("Are you SURE you want to continue? (yes/NO): ");
            std::io::stdout().flush()?;

            let mut response = String::new();
            std::io::stdin().read_line(&mut response)?;
            let response = response.trim().to_lowercase();

            if response != "yes" {
                println!("Encryption cancelled.");
                return Ok(());
            }

            // Проверка доступа к устройству
            info!("Verifying device accessibility...");
            match volume_io::open_device(&device) {
                Ok(_) => info!("Device accessible!"),
                Err(e) => {
                    error!("Cannot access device: {}", e);
                    return Err(anyhow!("Cannot access device: {}", e));
                }
            }

            // Запрашиваем пароль для шифрования
            println!("Enter password for encryption (will not be displayed):");
            let password = rpassword::read_password()?;
            println!("Confirm password:");
            let confirm_password = rpassword::read_password()?;

            if password != confirm_password {
                println!("Passwords do not match. Encryption cancelled.");
                return Ok(());
            }

            if password.len() < 8 {
                println!("Password must be at least 8 characters long. Encryption cancelled.");
                return Ok(());
            }

            // Начинаем процесс шифрования
            info!("Starting encryption...");
            let start = Instant::now();
            encrypt_device(&device, &password)?;
            let duration = start.elapsed();

            info!("Encryption completed successfully in {:.2?}!", duration);
            println!("Device {} has been encrypted.", device);
            println!("Please keep your password safe. If you lose it, all data will be unrecoverable!");

            Ok(())
        },
        Commands::FastEncrypt { device } => {
            info!("Starting FAST encryption process for device: {}", device);

            // Получаем и выводим информацию о диске
            match get_disk_details(&device) {
                Ok((name, size)) => {
                    println!("Device details:");
                    println!("  Name: {}", name);
                    println!("  Size: {}", size);
                },
                Err(e) => {
                    println!("Warning: Could not retrieve full device details: {}", e);
                }
            }

            // ВНИМАНИЕ: Подтверждение, что мы действительно хотим зашифровать устройство
            println!("WARNING: All data on the device will be DESTROYED!");
            println!("Device to encrypt: {}", device);
            print!("Are you SURE you want to continue? (yes/NO): ");
            std::io::stdout().flush()?;

            let mut response = String::new();
            std::io::stdin().read_line(&mut response)?;
            let response = response.trim().to_lowercase();

            if response != "yes" {
                println!("Encryption cancelled.");
                return Ok(());
            }

            // Проверка доступа к устройству
            info!("Verifying device accessibility...");
            match volume_io::open_device(&device) {
                Ok(_) => info!("Device accessible!"),
                Err(e) => {
                    error!("Cannot access device: {}", e);
                    return Err(anyhow!("Cannot access device: {}", e));
                }
            }

            // Запрашиваем пароль для шифрования
            println!("Enter password for encryption (will not be displayed):");
            let password = rpassword::read_password()?;
            println!("Confirm password:");
            let confirm_password = rpassword::read_password()?;

            if password != confirm_password {
                println!("Passwords do not match. Encryption cancelled.");
                return Ok(());
            }

            if password.len() < 8 {
                println!("Password must be at least 8 characters long. Encryption cancelled.");
                return Ok(());
            }

            // Начинаем процесс быстрого шифрования
            info!("Starting fast encryption (deferred encryption)...");
            let start = Instant::now();
            fast_encrypt_device(&device, &password)?;
            let duration = start.elapsed();

            info!("Fast encryption completed successfully in {:.2?}!", duration);
            println!("Device {} has been prepared for encryption.", device);
            println!("Note: Only the header has been encrypted. Data will be encrypted on-the-fly when written.");
            println!("Please keep your password safe. If you lose it, all data will be unrecoverable!");

            Ok(())
        },
        Commands::Check { device } => {
            info!("Checking if device is encrypted: {}", device);

            match decryption::is_encrypted_volume(&device) {
                Ok(true) => {
                    println!("Device is encrypted with UniFortress.");
                    Ok(())
                }
                Ok(false) => {
                    println!("Device is NOT encrypted with UniFortress.");
                    Ok(())
                }
                Err(e) => {
                    error!("Error checking device: {}", e);
                    Err(anyhow!("Error checking device: {}", e))
                }
            }
        },
        Commands::List => {
            info!("Listing available drives");
            if let Err(e) = list_drives() {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
            Ok(())
        },
        Commands::Mount { device, mount_point } => {
            info!("Mounting encrypted device: {} at {}", device, mount_point);
            
            // Запрашиваем пароль из консоли
            println!("Enter password for decryption:");
            let password = rpassword::read_password()?;
            
            match mount::windows::mount_encrypted_disk(&device, &password, &mount_point) {
                Ok(_) => {
                    println!("Device successfully mounted at {}:", mount_point);
                    Ok(())
                }
                Err(e) => {
                    error!("Failed to mount device: {}", e);
                    Err(anyhow!("Failed to mount device: {}", e))
                }
            }
        },
        Commands::Unmount { mount_point } => {
            info!("Unmounting encrypted device from {}", mount_point);
            
            match mount::windows::unmount_encrypted_disk(&mount_point) {
                Ok(_) => {
                    println!("Device successfully unmounted from {}:", mount_point);
                    Ok(())
                }
                Err(e) => {
                    error!("Failed to unmount device: {}", e);
                    Err(anyhow!("Failed to unmount device: {}", e))
                }
            }
        },
    }
}

// Function to list all available drives
fn list_drives() -> Result<()> {
    println!("Available drives:");
    
    if cfg!(windows) {
        // For Windows, use diskpart to get all disks (similar to the example)
        // Create a temporary script file for diskpart
        let diskpart_script = "list disk\nexit\n";
        let script_path = std::env::temp_dir().join("unifortress_diskpart.txt");
        std::fs::write(&script_path, diskpart_script)?;
        
        // Execute diskpart with the script
        let output = Command::new("diskpart")
            .args(["/s", script_path.to_str().unwrap()])
            .output()?;
        
        let output_str = String::from_utf8_lossy(&output.stdout);
        
        // Extract and print only the disk list part
        if let Some(start_idx) = output_str.find("DISKPART>") {
            if let Some(disk_list_start) = output_str[start_idx..].find("Disk ###") {
                let disk_list = &output_str[start_idx + disk_list_start..];
                println!("{}", disk_list);
            }
        } else {
            // If parsing fails, print the entire output
            println!("{}", output_str);
        }
        
        // Clean up the temporary script
        let _ = std::fs::remove_file(script_path);
        
        // Show clear usage examples
        println!("\nUsage examples:");
        println!("  To encrypt system disk (usually disk 0): unifortress encrypt --device \\\\.\\PhysicalDrive0");
        println!("  To encrypt removable disk: unifortress encrypt --device \\\\.\\PhysicalDrive1");
        println!("");
        println!("WARNING: BE EXTREMELY CAREFUL when selecting a system disk! This will DESTROY ALL DATA!");
    } else {
        // For Unix-like systems, use lsblk with better formatting
        let output = Command::new("lsblk")
            .args(["-o", "NAME,SIZE,TYPE,MOUNTPOINT,MODEL", "--noheadings"])
            .output()?;
        
        let output_str = String::from_utf8_lossy(&output.stdout);
        println!("{}", output_str);
        
        println!("Usage example:");
        println!("  To encrypt a USB drive: unifortress encrypt --device /dev/sdb");
    }
    
    // Additional safeguard message
    println!("\nIMPORTANT: Before encrypting, make sure you have selected the correct device!");
    println!("           ALL DATA on the selected device WILL BE DESTROYED!");
    
    Ok(())
}

// Function to get disk details
fn get_disk_details(device_path: &str) -> Result<(String, String)> {
    if cfg!(windows) {
        // Extract disk number from path
        let disk_number = if device_path.starts_with(r"\\.\PhysicalDrive") {
            device_path.trim_start_matches(r"\\.\PhysicalDrive")
        } else {
            return Err(anyhow!("Invalid device path format"));
        };
        
        // Create a temporary script file for diskpart
        let diskpart_script = format!("select disk {}\ndetail disk\nexit\n", disk_number);
        let script_path = std::env::temp_dir().join("unifortress_diskpart_detail.txt");
        std::fs::write(&script_path, diskpart_script)?;
        
        // Execute diskpart with the script
        let output = Command::new("diskpart")
            .args(["/s", script_path.to_str().unwrap()])
            .output()?;
        
        let output_str = String::from_utf8_lossy(&output.stdout);
        
        // Clean up the temporary script
        let _ = std::fs::remove_file(script_path);
        
        // Extract disk model/name
        let friendly_name = match output_str
            .lines()
            .find(|line| line.contains("Model") || line.contains("Disk ID"))
        {
            Some(line) => {
                let parts: Vec<&str> = line.split(":").collect();
                if parts.len() >= 2 {
                    parts[1].trim().to_string()
                } else {
                    "Unknown Disk".to_string()
                }
            },
            None => "Unknown Disk".to_string()
        };
        
        // Extract disk size
        let size_str = match output_str
            .lines()
            .find(|line| line.contains("Size:") || line.contains("GB"))
        {
            Some(line) => {
                let parts: Vec<&str> = line.split(":").collect();
                if parts.len() >= 2 {
                    parts[1].trim().to_string()
                } else {
                    // If the line doesn't have a colon, use the whole line
                    line.trim().to_string()
                }
            },
            None => {
                // Fallback: get size from the main output of diskpart
                match output_str
                    .lines()
                    .find(|line| line.contains("GB") && line.contains("Disk"))
                {
                    Some(line) => {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        match parts.iter().find(|part| part.contains("GB")) {
                            Some(size_part) => size_part.to_string(),
                            None => "Unknown Size".to_string()
                        }
                    },
                    None => "Unknown Size".to_string()
                }
            }
        };
        
        Ok((friendly_name, size_str))
    } else {
        // For Unix-like systems, use a simpler approach
        let device_name = device_path.split('/').last().unwrap_or("unknown").to_string();
        
        // Get disk size using lsblk
        let output = Command::new("lsblk")
            .args(["-bdno", "SIZE", device_path])
            .output()?;
        
        let size_bytes = String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse::<u64>()
            .unwrap_or(0);
        
        let size_gb = size_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
        let size_str = format!("{:.2} GB", size_gb);
        
        Ok((device_name, size_str))
    }
}

// Check if running with administrator privileges
fn is_admin() -> bool {
    if cfg!(windows) {
        // On Windows, check for admin rights
        match Command::new("net")
            .args(["session"])
            .output() {
            Ok(output) => output.status.success(),
            Err(_) => false,
        }
    } else if cfg!(unix) {
        // On Unix, check if running as root
        match Command::new("id")
            .args(["-u"])
            .output() {
            Ok(output) => {
                if let Ok(stdout) = String::from_utf8(output.stdout) {
                    stdout.trim() == "0"
                } else {
                    false
                }
            },
            Err(_) => false,
        }
    } else {
        // On other platforms, assume not admin
        false
    }
}

// Derive encryption key from password and salt
fn derive_key(password: &str, salt: &[u8]) -> Result<Vec<u8>> {
    // Create a key derivation function (simplified for the example)
    // In a real implementation, should use a proper KDF like PBKDF2 or Argon2
    let mut key = vec![0u8; KEY_SIZE];
    
    // Simple KDF for demonstration
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update(salt);
    let hash = hasher.finalize();
    
    // First half of the key
    let mut hasher = Sha256::new();
    hasher.update(&hash);
    hasher.update(b"1");
    let hash1 = hasher.finalize();
    
    // Second half of the key
    let mut hasher = Sha256::new();
    hasher.update(&hash);
    hasher.update(b"2");
    let hash2 = hasher.finalize();
    
    // Combine the two hashes
    key[0..32].copy_from_slice(&hash1);
    key[32..64].copy_from_slice(&hash2);
    
    Ok(key)
}

// Initialize XTS cipher with the given key
fn init_cipher(key: &[u8]) -> Result<Xts<Aes256>> {
    if key.len() != KEY_SIZE {
        return Err(anyhow!("Invalid key size, expected {} bytes", KEY_SIZE));
    }
    
    // Split the key into two parts for XTS
    let key1 = &key[0..32];
    let key2 = &key[32..64];
    
    // Create AES-256 instances
    let cipher1 = Aes256::new_from_slice(key1)
        .map_err(|e| anyhow!("Failed to create first AES cipher: {}", e))?;
    let cipher2 = Aes256::new_from_slice(key2)
        .map_err(|e| anyhow!("Failed to create second AES cipher: {}", e))?;
    
    // Create XTS cipher
    let cipher = Xts::new(cipher1, cipher2);
    
    Ok(cipher)
}

// Encrypt buffer using XTS mode
fn encrypt_buffer(cipher: &Xts<Aes256>, buffer: &mut [u8], sector: u64) -> Result<()> {
    // Check buffer length
    if buffer.len() % 16 != 0 {
        return Err(anyhow!("Buffer length must be a multiple of 16 bytes"));
    }
    
    // Encrypt each sector (512 bytes)
    for (i, chunk) in buffer.chunks_mut(SECTOR_SIZE).enumerate() {
        // Convert sector number to tweak bytes (16 byte array)
        let sector_num = sector as u128 + i as u128;
        let mut tweak = [0u8; 16];
        
        // Convert u128 to byte array (little endian)
        tweak[0..8].copy_from_slice(&(sector_num as u64).to_le_bytes());
        tweak[8..16].copy_from_slice(&((sector_num >> 64) as u64).to_le_bytes());
        
        cipher.encrypt_sector(chunk, tweak);
    }
    
    Ok(())
}

// Функция для монтирования зашифрованного устройства
fn mount_device(device_path: &str, password: &str, mount_point: &str) -> Result<()> {
    // Проверка прав администратора
    if !is_admin() {
        return Err(anyhow!("This operation requires administrator privileges"));
    }

    println!("Mounting device: {}", device_path);
    let device_path = get_device_path(device_path)?;
    
    // Проверяем, что устройство действительно зашифровано
    if !is_encrypted_volume(&device_path)? {
        return Err(anyhow!("The device is not encrypted with UniFortress"));
    }
    
    // Проверяем пароль
    if !verify_password(&device_path, password)? {
        return Err(anyhow!("Authentication failed: incorrect password"));
    }
    
    // Монтируем устройство
    println!("Mounting to: {}", mount_point);
    mount::mount(&device_path, password, mount_point)?;
    
    println!("Device successfully mounted!");
    
    Ok(())
}

// Функция для проверки, зашифровано ли устройство с помощью UniFortress
fn is_encrypted_volume(device_path: &str) -> Result<bool> {
    // Открываем устройство только для чтения
    let mut device = open_device_for_reading(device_path)?;
    
    // Читаем заголовок
    let mut header = vec![0u8; HEADER_SIZE];
    if let Err(e) = device.seek(SeekFrom::Start(0)).and_then(|_| device.read_exact(&mut header)) {
        return Err(anyhow!("Failed to read device header: {}", e));
    }
    
    // Проверяем сигнатуру
    Ok(&header[0..7] == b"UNIFORT")
}

// Функция для проверки пароля без вывода сообщений
fn verify_password(device_path: &str, password: &str) -> Result<bool> {
    // Открываем устройство только для чтения
    let mut device = open_device_for_reading(device_path)?;
    
    // Читаем заголовок
    let mut header = vec![0u8; HEADER_SIZE];
    if let Err(e) = device.seek(SeekFrom::Start(0)).and_then(|_| device.read_exact(&mut header)) {
        return Err(anyhow!("Failed to read device header: {}", e));
    }
    
    // Проверяем сигнатуру
    if &header[0..7] != b"UNIFORT" {
        return Err(anyhow!("Device is not encrypted with UniFortress"));
    }
    
    // Получаем соль
    if 16 + SALT_SIZE > header.len() {
        return Err(anyhow!("Invalid header format: salt section missing"));
    }
    let salt = &header[16..16+SALT_SIZE];
    
    // Генерируем ключ
    let key = derive_key(password, salt)?;
    
    // Проверяем контрольную сумму
    let mut hasher = Sha256::new();
    hasher.update(&key);
    let checksum = hasher.finalize();
    
    if 48 + 32 > header.len() {
        return Err(anyhow!("Invalid header format: checksum section missing"));
    }
    
    Ok(&header[48..48+32] == checksum.as_slice())
}

// Open device for reading
fn open_device_for_reading(path: &str) -> Result<File> {
    OpenOptions::new()
        .read(true)
        .open(path)
        .context("Failed to open device for reading")
}

// Open device for writing
fn open_device_for_writing(path: &str) -> Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .context("Failed to open device for writing")
}

// Get full device path
fn get_device_path(device: &str) -> Result<String> {
    if cfg!(windows) {
        // For Windows: if a drive letter is specified, convert to physical device path
        if device.len() == 1 && device.chars().next().unwrap().is_alphabetic() {
            return Ok(format!(r"\\.\{}:", device));
        } else if device.len() == 2 && device.ends_with(":") {
            return Ok(format!(r"\\.\{}", device));
        }
    }
    
    // Otherwise return as is
    Ok(device.to_string())
}

// Function to encrypt the device
fn encrypt_device(device_path: &str, password: &str) -> anyhow::Result<()> {
    // Проверка прав администратора
    #[cfg(target_os = "windows")]
    if !is_admin() {
        anyhow::bail!("This command requires administrator privileges!");
    }

    #[cfg(not(target_os = "windows"))]
    if !is_admin() {
        anyhow::bail!("This command requires root privileges!");
    }
    
    // Вызов функции шифрования из модуля encryption
    unifortress::encryption::encrypt_volume(device_path, &password)?;
    
    println!("Device encrypted successfully!");
    println!("To mount this device, use: unifortress mount {}", device_path);
    
    Ok(())
}

/// Выполняет быстрое шифрование устройства с использованием отложенного шифрования
/// 
/// # Arguments
/// * `device_path` - Путь к устройству
/// * `password` - Пароль для шифрования
/// 
/// # Returns
/// Результат операции
fn fast_encrypt_device(device_path: &str, password: &str) -> Result<()> {
    // Преобразуем путь к устройству в полный путь, если это необходимо
    let device_path = get_device_path(device_path)?;
    
    // Создаем новый том с отложенным шифрованием
    info!("Creating new deferred encrypted volume at {}", device_path);
    let mut volume = DeferredEncryptedVolume::new(&device_path, password)?;
    
    // Выполняем быстрое шифрование (только заголовок)
    info!("Performing fast encryption (headers only)...");
    volume.fast_encrypt()?;
    
    info!("Fast encryption completed successfully");
    
    Ok(())
}

fn run_command(cli: &Cli) -> anyhow::Result<()> {
    match &cli.command {
        Commands::Encrypt { device } => {
            encrypt_device(device, &prompt_for_password()?)?;
            println!("Encryption completed successfully.");
        },
        Commands::FastEncrypt { device } => {
            fast_encrypt_device(device, &prompt_for_password()?)?;
            println!("Fast encryption completed successfully.");
        },
        Commands::Check { device } => {
            match decryption::is_encrypted_volume(device) {
                Ok(true) => {
                    println!("Device is encrypted with UniFortress.");
                    
                    // Запрашиваем пароль для проверки
                    match decryption::verify_password(device, &prompt_for_password()?) {
                        Ok(true) => println!("Password is correct."),
                        Ok(false) => println!("Password is incorrect."),
                        Err(e) => eprintln!("Error verifying password: {}", e),
                    }
                }
                Ok(false) => println!("Device is not encrypted."),
                Err(e) => eprintln!("Error checking device: {}", e),
            }
        },
        Commands::List => {
            list_drives()?;
        },
        Commands::Mount { device, mount_point } => {
            mount::windows::mount_encrypted_disk(device, &prompt_for_password()?, mount_point)?;
            println!("Device mounted successfully at {}", mount_point);
        },
        Commands::Unmount { mount_point } => {
            mount::windows::unmount_encrypted_disk(mount_point)?;
            println!("Device unmounted successfully from {}", mount_point);
        },
    }
    Ok(())
}

fn prompt_for_password() -> Result<String> {
    println!("Enter password:");
    let password = rpassword::read_password()
        .context("Failed to read password")?;
    
    // Добавляем проверку минимальной длины пароля
    if password.len() < 8 {
        bail!("Password must be at least 8 characters long");
    }
    
    Ok(password)
} 