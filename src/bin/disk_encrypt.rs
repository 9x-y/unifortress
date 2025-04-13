use anyhow::{Result, bail, Context};
use std::process::Command;
use std::fs::{OpenOptions, File};
use std::io::{Read, Write, Seek, SeekFrom};
use std::os::windows::io::FromRawHandle;
use rand::{Rng, rngs::OsRng};
use rpassword::read_password;
use std::path::Path;
use std::ptr;
use std::mem;
use winapi::um::fileapi::{CreateFileA, OPEN_EXISTING};
use winapi::um::winnt::{FILE_SHARE_READ, FILE_SHARE_WRITE};
use winapi::um::winnt::{GENERIC_READ, GENERIC_WRITE};
use winapi::um::winioctl::{DISK_GEOMETRY, IOCTL_DISK_GET_DRIVE_GEOMETRY};
use winapi::um::winioctl::FSCTL_LOCK_VOLUME;
use winapi::um::winioctl::FSCTL_DISMOUNT_VOLUME;
use winapi::um::ioapiset::DeviceIoControl;
use winapi::shared::minwindef::DWORD;
use std::ffi::CString;

use unifortress::encryption::{derive_key, split_derived_key, VolumeHeader};
use unifortress::decryption::decrypt_sector;
use unifortress::crypto::xts::encrypt_sector;

const SECTOR_SIZE: u32 = 4096;
const HEADER_SECTORS: u64 = 2; // First two sectors for header
const SALT_SIZE: usize = 16; // Argon2 salt size (16 bytes recommended)

// Define a common trait for both volume types
trait Volume {
    fn get_size(&self) -> Result<u64>;
    fn get_sector_size(&self) -> u32;
    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> Result<()>;
    fn write_at(&mut self, offset: u64, buffer: &[u8]) -> Result<()>;
    fn read_sectors(&mut self, start_sector: u64, num_sectors: u32, sector_size: u32, buffer: &mut [u8]) -> Result<()>;
    fn write_sectors(&mut self, start_sector: u64, sector_size: u32, buffer: &[u8]) -> Result<()>;
    fn lock_and_dismount(&mut self) -> Result<()>;
}

// Generate cryptographically secure random salt
fn generate_salt(size: usize) -> Vec<u8> {
    let mut salt = vec![0u8; size];
    OsRng.fill(&mut salt[..]);
    salt
}

fn get_disk_info(disk_number: u8) -> Result<String> {
    // Use PowerShell to get disk information with GB size
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
        .context("Failed to execute PowerShell command to get disk information")?;

    if !output.status.success() {
        bail!("Command execution error: {}", String::from_utf8_lossy(&output.stderr));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

// Get list of available disks
fn list_available_disks() -> Result<String> {
    println!("Scanning for available disks...");
    
    let cmd = "Get-Disk | Select-Object Number, FriendlyName, @{Name='SizeGB';Expression={\"[{0:N2} GB]\" -f ($_.Size / 1GB)}}, BusType, PartitionStyle | Format-Table -AutoSize";
    
    let output = Command::new("powershell")
        .args(&[
            "-Command",
            cmd
        ])
        .output()
        .context("Failed to execute PowerShell command to list disks")?;

    if !output.status.success() {
        bail!("Command execution error: {}", String::from_utf8_lossy(&output.stderr));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

// Function to test direct disk access via standard library
fn test_direct_disk_access(disk_number: u8) -> Result<()> {
    let path = format!(r"\\.\PhysicalDrive{}", disk_number);
    println!("Testing direct disk access via std::fs::OpenOptions: {}", path);
    
    match OpenOptions::new().read(true).write(true).open(&path) {
        Ok(_) => {
            println!("[OK] Access granted via standard library");
            Ok(())
        },
        Err(e) => {
            println!("[ERROR] Access error via standard library: {} (os error {})", 
                     e, e.raw_os_error().unwrap_or(-1));
            bail!("Failed to get disk access via std::fs")
        }
    }
}

// Physical device implementation for VolumeFile
struct PhysicalDiskVolume {
    file: File,
    sector_size: u32,
    disk_number: u8,
    handle: winapi::um::winnt::HANDLE,
}

impl PhysicalDiskVolume {
    fn open(disk_number: u8, sector_size: u32) -> Result<Self> {
        let path = format!(r"\\.\PhysicalDrive{}", disk_number);
        println!("Opening physical disk: {}", path);
        
        // Use WinAPI for low-level disk access with full control
        unsafe {
            let path_cstr = CString::new(path.clone()).unwrap();
            let handle = CreateFileA(
                path_cstr.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null_mut(),
                OPEN_EXISTING,
                0,
                ptr::null_mut(),
            );
            
            if handle == winapi::um::handleapi::INVALID_HANDLE_VALUE {
                let error = std::io::Error::last_os_error();
                println!("[ERROR] Failed to open disk with WinAPI: {}", error);
                bail!("Could not open physical disk: {}", error);
            }
            
            println!("[OK] Successfully opened disk using WinAPI");
            
            // Get disk geometry to verify sector size
            let mut geometry: DISK_GEOMETRY = mem::zeroed();
            let mut bytes_returned: DWORD = 0;
            
            let result = DeviceIoControl(
                handle,
                IOCTL_DISK_GET_DRIVE_GEOMETRY,
                ptr::null_mut(),
                0,
                &mut geometry as *mut _ as *mut _,
                mem::size_of::<DISK_GEOMETRY>() as DWORD,
                &mut bytes_returned,
                ptr::null_mut(),
            );
            
            if result == 0 {
                let error = std::io::Error::last_os_error();
                println!("[WARNING] Failed to get disk geometry: {}", error);
                println!("Using specified sector size: {}", sector_size);
            } else {
                let disk_sector_size = geometry.BytesPerSector;
                println!("Disk geometry: {} bytes per sector", disk_sector_size);
                
                if disk_sector_size != sector_size as DWORD {
                    println!("[WARNING] Disk sector size ({}) differs from specified sector size ({})",
                             disk_sector_size, sector_size);
                    println!("Using specified sector size for encryption: {}", sector_size);
                }
            }
            
            // Convert HANDLE to File
            let file = File::from_raw_handle(handle as *mut _);
            
            Ok(Self {
                file,
                sector_size,
                disk_number,
                handle: handle,
            })
        }
    }
    
    // Function to lock and dismount volume for exclusive access
    fn lock_volume(&mut self) -> Result<bool> {
        unsafe {
            let mut bytes_returned: DWORD = 0;
            
            // Try to lock the volume
            println!("Attempting to lock the volume for exclusive access...");
            let lock_result = DeviceIoControl(
                self.handle,
                FSCTL_LOCK_VOLUME,
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                0,
                &mut bytes_returned,
                ptr::null_mut()
            );
            
            if lock_result == 0 {
                let error = std::io::Error::last_os_error();
                println!("[WARNING] Could not lock volume: {}", error);
                println!("The disk may be in use by another process.");
                return Ok(false);
            }
            
            // Try to dismount the volume
            println!("Attempting to dismount the volume...");
            let dismount_result = DeviceIoControl(
                self.handle,
                FSCTL_DISMOUNT_VOLUME,
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                0,
                &mut bytes_returned,
                ptr::null_mut()
            );
            
            if dismount_result == 0 {
                let error = std::io::Error::last_os_error();
                println!("[WARNING] Could not dismount volume: {}", error);
                println!("Continuing anyway, but operations may fail...");
                return Ok(false);
            }
            
            println!("[OK] Volume successfully locked and dismounted for exclusive access");
            Ok(true)
        }
    }
}

// Implement Volume trait for PhysicalDiskVolume
impl Volume for PhysicalDiskVolume {
    fn get_size(&self) -> Result<u64> {
        // Use PowerShell to get disk size - more reliable for physical devices
        let cmd = format!(
            "Get-Disk -Number {} | Select-Object -ExpandProperty Size",
            self.disk_number
        );
        
        let output = Command::new("powershell")
            .args(&[
                "-Command",
                &cmd
            ])
            .output()
            .context("Failed to execute PowerShell command to get disk size")?;

        if !output.status.success() {
            // If failed to get size via PowerShell, use a fixed value
            println!("Failed to get actual disk size. Using fallback size of 60 GB.");
            return Ok(60 * 1024 * 1024 * 1024); // 60 GB as safe value for most flash drives
        }

        let size_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
        match size_str.parse::<u64>() {
            Ok(size) => Ok(size),
            Err(_) => {
                println!("Failed to parse disk size '{}'. Using fallback size of 60 GB.", size_str);
                Ok(60 * 1024 * 1024 * 1024) // 60 GB as safe value
            }
        }
    }
    
    fn get_sector_size(&self) -> u32 {
        self.sector_size
    }
    
    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> Result<()> {
        self.file.seek(SeekFrom::Start(offset))
            .context("Error positioning for reading")?;
        self.file.read_exact(buffer)
            .context("Error reading from device")?;
        Ok(())
    }
    
    fn write_at(&mut self, offset: u64, buffer: &[u8]) -> Result<()> {
        // First try with the regular method
        let result = self.file.seek(SeekFrom::Start(offset))
            .and_then(|_| self.file.write_all(buffer))
            .and_then(|_| self.file.flush());
        
        if result.is_err() {
            // If that fails, try with direct WinAPI calls
            unsafe {
                let mut bytes_written: DWORD = 0;
                
                // Get the file handle
                let handle = self.handle;
                
                // Position at the right offset (low and high parts of 64-bit offset)
                let mut overlapped: winapi::um::minwinbase::OVERLAPPED = mem::zeroed();
                
                // Access OVERLAPPED union field correctly
                // OVERLAPPED has a union 'u' that contains Anonymous struct with Offset and OffsetHigh
                // We need to access it through that structure
                // First create a pointer to the overlapped structure
                let p_overlapped = &mut overlapped as *mut winapi::um::minwinbase::OVERLAPPED;
                
                // Now access the union fields using the proper method
                unsafe {
                    // Access the union and set Offset and OffsetHigh
                    (*p_overlapped).u.s_mut().Offset = (offset & 0xFFFFFFFF) as DWORD;
                    (*p_overlapped).u.s_mut().OffsetHigh = ((offset >> 32) & 0xFFFFFFFF) as DWORD;
                }
                
                // Write using WriteFile
                let result = winapi::um::fileapi::WriteFile(
                    handle,
                    buffer.as_ptr() as *const _,
                    buffer.len() as DWORD,
                    &mut bytes_written,
                    &mut overlapped
                );
                
                if result == 0 {
                    let error = std::io::Error::last_os_error();
                    bail!("Error writing to device using WinAPI: {}", error);
                }
                
                if bytes_written != buffer.len() as DWORD {
                    bail!("Incomplete write: wrote {} out of {} bytes", bytes_written, buffer.len());
                }
            }
        }
        
        Ok(())
    }
    
    fn read_sectors(&mut self, start_sector: u64, _num_sectors: u32, sector_size: u32, buffer: &mut [u8]) -> Result<()> {
        let offset = start_sector * sector_size as u64;
        self.read_at(offset, buffer)
    }
    
    fn write_sectors(&mut self, start_sector: u64, sector_size: u32, buffer: &[u8]) -> Result<()> {
        let offset = start_sector * sector_size as u64;
        self.write_at(offset, buffer)
    }
    
    fn lock_and_dismount(&mut self) -> Result<()> {
        self.lock_volume()?;
        Ok(())
    }
}

// TestFileVolume structure for file operations
struct TestFileVolume {
    file: File,
    sector_size: u32,
    disk_number: u8,
}

impl TestFileVolume {
    fn new(file: File, sector_size: u32, disk_number: u8) -> Self {
        Self {
            file,
            sector_size,
            disk_number,
        }
    }
}

// Implement Volume trait for TestFileVolume
impl Volume for TestFileVolume {
    fn get_size(&self) -> Result<u64> {
        let metadata = self.file.metadata()
            .context("Failed to get file metadata")?;
        Ok(metadata.len())
    }
    
    fn get_sector_size(&self) -> u32 {
        self.sector_size
    }
    
    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> Result<()> {
        self.file.seek(SeekFrom::Start(offset))
            .context("Error positioning for reading")?;
        self.file.read_exact(buffer)
            .context("Error reading from file")?;
        Ok(())
    }
    
    fn write_at(&mut self, offset: u64, buffer: &[u8]) -> Result<()> {
        self.file.seek(SeekFrom::Start(offset))
            .context("Error positioning for writing")?;
        self.file.write_all(buffer)
            .context("Error writing to file")?;
        self.file.flush()
            .context("Error flushing to file")?;
        Ok(())
    }
    
    fn read_sectors(&mut self, start_sector: u64, _num_sectors: u32, sector_size: u32, buffer: &mut [u8]) -> Result<()> {
        let offset = start_sector * sector_size as u64;
        self.read_at(offset, buffer)
    }
    
    fn write_sectors(&mut self, start_sector: u64, sector_size: u32, buffer: &[u8]) -> Result<()> {
        let offset = start_sector * sector_size as u64;
        self.write_at(offset, buffer)
    }
    
    fn lock_and_dismount(&mut self) -> Result<()> {
        // No need to lock or dismount file-based volumes
        Ok(())
    }
}

// Function to request password from user
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

fn verify_password() -> Result<String> {
    println!("Enter password to decrypt volume (will not be displayed): ");
    let password = read_password()?;
    
    if password.trim().is_empty() {
        println!("Password cannot be empty!");
        return verify_password();
    }
    
    Ok(password)
}

// Add new function to run diskpart for disk preparation
fn prepare_disk_with_diskpart(disk_number: u8) -> Result<()> {
    println!("Using diskpart to prepare the disk for exclusive access...");
    
    // Create a temporary script file
    let script_path = std::env::temp_dir().join("unifortress_diskpart.txt");
    let script_content = format!("select disk {}\nclean\nexit", disk_number);
    
    std::fs::write(&script_path, script_content)
        .context("Failed to create diskpart script file")?;
    
    println!("Running diskpart to clean disk {}. This will erase ALL data!", disk_number);
    
    // Run diskpart with the script
    let output = Command::new("diskpart")
        .args(&["/s", script_path.to_str().unwrap()])
        .output()
        .context("Failed to execute diskpart command")?;
    
    // Clean up script file
    let _ = std::fs::remove_file(script_path);
    
    if !output.status.success() {
        let error_msg = String::from_utf8_lossy(&output.stderr);
        println!("Diskpart error: {}", error_msg);
        bail!("Diskpart failed: {}", error_msg);
    }
    
    let output_text = String::from_utf8_lossy(&output.stdout);
    println!("Diskpart output:\n{}", output_text);
    
    if output_text.contains("DiskPart successfully cleaned the disk") {
        println!("[OK] Disk successfully cleaned and ready for encryption");
        Ok(())
    } else {
        println!("[WARNING] Diskpart completed but clean confirmation message not found.");
        println!("Continuing anyway, but operations may fail...");
        Ok(())
    }
}

fn main() -> Result<()> {
    println!("PHYSICAL DEVICE ENCRYPTION TOOL - UNIFORTRESS");
    println!("================================================================");
    
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
                        println!("This program requires administrator rights to access physical disks.");
                        println!("Please restart the program with administrator privileges.");
                        return Ok(());
                    }
                },
                Err(e) => {
                    println!("[ERROR] Failed to check administrator rights: {}", e);
                    println!("Please make sure you're running with administrator privileges.");
                    return Ok(());
                }
            }
    } else {
        println!("[WARNING] Administrator rights check is not applicable for this OS");
        true
    };
    
    if !is_admin {
        bail!("Administrator rights required for disk operations");
    }
    
    // List available disks
    match list_available_disks() {
        Ok(disks) => {
            println!("\nAVAILABLE DISKS:");
            println!("{}", disks);
        },
        Err(e) => {
            println!("Failed to list disks: {}", e);
            println!("Continuing without disk list...");
        }
    }
    
    // Ask for disk number
    println!("\n[WARNING] Be extremely careful when selecting a disk!");
    println!("Disk 0 is typically your system disk. DO NOT select it!");
    println!("Make sure you select the correct removable disk (USB drive) number.");
    
    let mut disk_number: u8 = 0;
    let mut valid_disk = false;
    
    while !valid_disk {
        print!("Enter disk number to encrypt/decrypt (e.g., 1 for Disk 1): ");
        std::io::stdout().flush()?;
        
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        
        match input.trim().parse::<u8>() {
            Ok(num) => {
                if num == 0 {
                    println!("[ERROR] Disk 0 is typically your system disk and cannot be selected.");
                    println!("Choose another disk number.");
                } else {
                    disk_number = num;
                    valid_disk = true;
                }
            },
            Err(_) => {
                println!("[ERROR] Invalid disk number. Please enter a valid number.");
            }
        }
    }
    
    // Get disk information and confirm
    println!("\nGetting information about disk {}...", disk_number);
    
    match get_disk_info(disk_number) {
        Ok(info) => {
            println!("DISK INFORMATION:");
            println!("{}", info);
            
            println!("\n[WARNING] You are about to perform operations on the disk shown above.");
            println!("[WARNING] ALL DATA ON THIS DISK WILL BE LOST during encryption.");
            print!("Are you sure you want to continue? (yes/no): ");
            std::io::stdout().flush()?;
            
            let mut confirmation = String::new();
            std::io::stdin().read_line(&mut confirmation)?;
            
            if confirmation.trim().to_lowercase() != "yes" {
                println!("Operation canceled by user.");
                return Ok(());
            }
        },
        Err(e) => {
            println!("Failed to get disk information: {}", e);
            println!("Do you want to continue without disk information? This is risky!");
            print!("Continue anyway? (yes/no): ");
            std::io::stdout().flush()?;
            
            let mut confirmation = String::new();
            std::io::stdin().read_line(&mut confirmation)?;
            
            if confirmation.trim().to_lowercase() != "yes" {
                println!("Operation canceled by user.");
                return Ok(());
            }
        }
    }
    
    // Test direct disk access
    let use_file_mode = match test_direct_disk_access(disk_number) {
        Ok(_) => {
            println!("[OK] Direct disk access test passed");
            false // Use physical disk
        },
        Err(e) => {
            println!("[WARNING] Direct disk access test failed: {}", e);
            println!("This might be due to permissions or disk is in use by another process.");
            println!("Switching to FILE MODE for testing purposes");
            
            print!("Do you want to continue in file mode? (yes/no): ");
            std::io::stdout().flush()?;
            
            let mut confirmation = String::new();
            std::io::stdin().read_line(&mut confirmation)?;
            
            if confirmation.trim().to_lowercase() != "yes" {
                println!("Operation canceled by user.");
                return Ok(());
            }
            
            true // Use file mode
        }
    };
    
    // Create path for file mode if needed
    let file_mode_path = if use_file_mode {
        let drive_letter = match get_drive_letter_by_disk_number(disk_number) {
            Ok(letter) => letter,
            Err(_) => "D".to_string(), // Default to D: if we can't get the letter
        };
        
        let test_file_path = format!("{}:\\test_unifortress.enc", drive_letter);
        println!("File mode will be used for testing on file: {}", test_file_path);
        Some(test_file_path)
    } else {
        None
    };
    
    // Ask user: encrypt disk or open existing
    println!("\nSelect operation mode:");
    println!("1. Encrypt new disk (WILL ERASE ALL DATA)");
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
            println!("[ERROR] Invalid choice. Operation canceled for safety.");
            return Ok(());
        }
    };
    
    // One final confirmation for encrypting a new disk
    if is_new_volume {
        println!("\n[WARNING] You are about to ENCRYPT DISK {} which will ERASE ALL DATA on it.", disk_number);
        print!("Type 'ERASE ALL DATA' to confirm: ");
        std::io::stdout().flush()?;
        
        let mut confirmation = String::new();
        std::io::stdin().read_line(&mut confirmation)?;
        
        if confirmation.trim() != "ERASE ALL DATA" {
            println!("Confirmation failed. Operation canceled.");
            return Ok(());
        }
    }

    // Open physical device or file - return a Box<dyn Volume> instead of concrete types
    let mut volume: Box<dyn Volume> = if !use_file_mode {
        match PhysicalDiskVolume::open(disk_number, SECTOR_SIZE) {
            Ok(v) => Box::new(v),
            Err(e) => {
                println!("[ERROR] Failed to open physical disk: {}", e);
                println!("Switching to file mode as fallback...");
                
                // Create a test file for the encrypted volume
                let file_path = file_mode_path.unwrap_or_else(|| "D:\\test_unifortress.enc".to_string());
                
                // If encrypting a new volume, create a 100MB test file
                if is_new_volume {
                    let file_size = 100 * 1024 * 1024; // 100MB
                    println!("Creating test file: {} ({}MB)", file_path, file_size / 1024 / 1024);
                    
                    let file = OpenOptions::new()
                        .read(true)
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .open(&file_path)
                        .with_context(|| format!("Failed to create test file '{}'", file_path))?;
                    
                    // Set file size
                    file.set_len(file_size)
                        .with_context(|| format!("Failed to set file size for '{}'", file_path))?;
                    
                    Box::new(TestFileVolume::new(file, SECTOR_SIZE, disk_number))
                } else {
                    // Open existing file
                    let file = OpenOptions::new()
                        .read(true)
                        .write(true)
                        .open(&file_path)
                        .with_context(|| format!("Failed to open test file '{}'", file_path))?;
                    
                    Box::new(TestFileVolume::new(file, SECTOR_SIZE, disk_number))
                }
            }
        }
    } else {
        // Use file mode directly
        let file_path = file_mode_path.unwrap();
        
        // If encrypting a new volume, create a 100MB test file
        if is_new_volume {
            let file_size = 100 * 1024 * 1024; // 100MB
            println!("Creating test file: {} ({}MB)", file_path, file_size / 1024 / 1024);
            
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(&file_path)
                .with_context(|| format!("Failed to create test file '{}'", file_path))?;
            
            // Set file size
            file.set_len(file_size)
                .with_context(|| format!("Failed to set file size for '{}'", file_path))?;
            
            Box::new(TestFileVolume::new(file, SECTOR_SIZE, disk_number))
        } else {
            // Open existing file
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&file_path)
                .with_context(|| format!("Failed to open test file '{}'", file_path))?;
            
            Box::new(TestFileVolume::new(file, SECTOR_SIZE, disk_number))
        }
    };
    
    // Get password depending on mode
    let password = if is_new_volume {
        get_password()?
    } else {
        verify_password()?
    };
    
    println!("Password accepted. Password length: {} characters", password.len());
    
    let volume_size = volume.get_size()?;
    println!("Disk size: {} bytes ({:.2} GB)", 
             volume_size, volume_size as f64 / 1024.0 / 1024.0 / 1024.0);
    println!("Sector size: {} bytes", SECTOR_SIZE);
    
    if is_new_volume {
        // New volume encryption
        
        // First use diskpart to prepare the disk (if on Windows)
        if cfg!(windows) {
            match prepare_disk_with_diskpart(disk_number) {
                Ok(_) => println!("[OK] Disk prepared using diskpart"),
                Err(e) => {
                    println!("[WARNING] Failed to prepare disk with diskpart: {}", e);
                    println!("This may cause write operations to fail. Continuing anyway...");
                }
            }
        }
        
        // Attempt to lock and dismount the volume for exclusive access
        println!("Preparing disk for encryption...");
        if let Err(e) = volume.lock_and_dismount() {
            println!("[WARNING] Failed to prepare disk: {}", e);
            println!("This may cause write operations to fail if the disk is in use.");
        }
        
        println!("Generating encryption keys...");
        let salt = generate_salt(SALT_SIZE);
        println!("Generated random salt with size {} bytes", salt.len());
        
        let derived_key = derive_key(password.as_bytes(), &salt)?;
        let (master_key, hmac_key) = split_derived_key(&derived_key)?;
        
        println!("Creating volume header...");
        let header = VolumeHeader::new(volume_size, SECTOR_SIZE, &master_key, &hmac_key)?;
        
        println!("Saving salt in volume header...");
        let header_serialized = header.serialize()?;
        
        println!("Writing header to disk...");
        let mut header_sector = vec![0u8; SECTOR_SIZE as usize];
        header_sector[..header_serialized.len()].copy_from_slice(&header_serialized);
        
        // Save salt in the last part of header for demonstration
        let salt_offset = SECTOR_SIZE as usize - SALT_SIZE - 8;
        header_sector[salt_offset..salt_offset+8].copy_from_slice(b"SALT-ID:");
        header_sector[salt_offset+8..salt_offset+8+salt.len()].copy_from_slice(&salt);
        
        // Try to write to physical disk, do not switch to file mode if it fails
        match volume.write_sectors(0, SECTOR_SIZE, &header_sector) {
            Ok(_) => println!("[OK] Header successfully written to disk"),
            Err(e) => {
                println!("[ERROR] Failed to write header to disk: {}", e);
                println!("Please make sure:");
                println!("1. You have administrator privileges");
                println!("2. The disk is not being used by another process");
                println!("3. You have dismounted the volume (using Disk Management)");
                bail!("Could not write to physical disk");
            }
        }
        
        // Write a test pattern to the first data sector to verify later
        println!("Writing verification data...");
        let test_data = b"This is a UniFortress encrypted volume created on: 2025-04-13";
        let mut sector_buffer = vec![0u8; SECTOR_SIZE as usize];
        sector_buffer[..test_data.len()].copy_from_slice(test_data);
        
        println!("Encrypting verification data...");
        encrypt_sector(&mut sector_buffer, HEADER_SECTORS, &master_key)?;
        
        println!("Writing encrypted verification data to sector {}...", HEADER_SECTORS);
        match volume.write_sectors(HEADER_SECTORS, SECTOR_SIZE, &sector_buffer) {
            Ok(_) => println!("[OK] Verification data successfully written to disk"),
            Err(e) => {
                println!("[ERROR] Failed to write verification data: {}", e);
                println!("The header was written successfully, but verification data failed.");
                println!("The volume may not be usable. Please try again.");
                bail!("Failed to complete disk encryption");
            }
        }
        
        println!("\n[SUCCESS] Disk encrypted successfully!");
        println!("Password and salt have been used to generate encryption keys.");
        println!("The disk can now be mounted with the same password.");
        
        // После успешного шифрования устанавливаем файлы автозапуска
        if setup_autorun_on_disk(disk_number)?.is_empty() {
            println!("Warning: Disk encrypted successfully, but autorun setup failed.");
            println!("For manual mounting, use the command:");
            println!("  unifortress unlock -f <path_to_encrypted_file>");
        }
        
    } else {
        // Open existing volume
        println!("Reading encrypted volume header...");
        let mut header_sector = vec![0u8; SECTOR_SIZE as usize];
        volume.read_sectors(0, 1, SECTOR_SIZE, &mut header_sector)?;
        
        // Extract salt from header
        let salt_offset = SECTOR_SIZE as usize - SALT_SIZE - 8;
        let salt_tag = &header_sector[salt_offset..salt_offset+8];
        
        if salt_tag != b"SALT-ID:" {
            bail!("Disk is not a UniFortress encrypted volume or is corrupted!");
        }
        
        let salt = &header_sector[salt_offset+8..salt_offset+8+SALT_SIZE];
        println!("Found salt in volume header");
        
        // Generate keys from password and salt
        println!("Restoring encryption keys from password...");
        let derived_key = derive_key(password.as_bytes(), salt)?;
        #[allow(unused_variables)]
        let (master_key, hmac_key) = split_derived_key(&derived_key)?;
        
        // Read verification sector
        println!("Checking data access...");
        let mut test_sector = vec![0u8; SECTOR_SIZE as usize];
        volume.read_sectors(HEADER_SECTORS, 1, SECTOR_SIZE, &mut test_sector)?;
        
        // Decrypt verification sector
        println!("Decrypting verification data...");
        decrypt_sector(&mut test_sector, HEADER_SECTORS, &master_key)?;
        
        // Check for expected data in decrypted sector
        let text_prefix = b"This is a UniFortress";
        if test_sector.starts_with(text_prefix) {
            println!("\n[SUCCESS] Volume access granted!");
            println!("Verification data: \"{}\"", 
                     String::from_utf8_lossy(&test_sector[..60]).trim_end_matches('\0'));
            println!("You can now mount this encrypted volume.");
        } else {
            println!("\n[ERROR] Access error! Incorrect password or corrupted volume.");
            bail!("Failed to decrypt data with the given password");
        }
    }
    
    println!("\nOperation completed successfully!");
    
    Ok(())
}

// Add file creation functions for autorun setup
fn setup_autorun_on_disk(disk_number: u8) -> Result<String> {
    // Determine drive letter by disk number
    let drive_letter = get_drive_letter_by_disk_number(disk_number)?;
    
    // Path to disk
    let drive_path = format!("{}:\\", drive_letter);
    
    // Create directories for autorun
    let autorun_dir = format!("{}unifortress", drive_path);
    std::fs::create_dir_all(&autorun_dir)?;
    
    // Copy binaries
    // 1. Get path to current executable
    let current_exe = std::env::current_exe()?;
    let current_exe_dir = current_exe.parent().unwrap_or(Path::new(""));
    
    // 2. Path to main binary and launcher
    let unifortress_src = current_exe_dir.join("unifortress.exe");
    let launcher_src = current_exe_dir.join("unifortress_launcher.exe");
    
    // 3. Destination paths
    let unifortress_dst = format!("{}\\unifortress\\unifortress.exe", drive_path);
    let launcher_dst = format!("{}\\unifortress\\launcher.exe", drive_path);
    
    // 4. Copy main binary if it exists
    if unifortress_src.exists() {
        std::fs::copy(&unifortress_src, &unifortress_dst)?;
        println!("Copied file {}", unifortress_dst);
    } else {
        println!("Warning: unifortress.exe not found. Skipping copy.");
    }
    
    // 5. Copy launcher if it exists
    if launcher_src.exists() {
        std::fs::copy(&launcher_src, &launcher_dst)?;
        println!("Copied file {}", launcher_dst);
    } else {
        println!("Warning: unifortress_launcher.exe not found. Skipping copy.");
    }
    
    // Create autorun.inf in disk root
    let autorun_path = format!("{}autorun.inf", drive_path);
    let mut autorun_file = File::create(&autorun_path)?;
    
    // Content of autorun.inf
    let autorun_content = format!(r#"[AutoRun]
open=unifortress\launcher.exe
icon=unifortress\launcher.exe,0
label=UniFortress Encrypted Drive
action=Open UniFortress Encrypted Drive
"#);
    
    autorun_file.write_all(autorun_content.as_bytes())?;
    println!("Created file {}", autorun_path);
    
    // Create README file on disk
    let readme_path = format!("{}README.txt", drive_path);
    let mut readme_file = File::create(&readme_path)?;
    
    let readme_content = r#"=== UniFortress Encrypted Drive ===

This disk is protected by UniFortress encryption.

To access encrypted data:
1. When connecting the disk, the UniFortress application will automatically start
2. Enter the password you specified when encrypting the disk
3. After successful password verification, the encrypted disk will be mounted as drive V:

Note: If autorun doesn't work, manually run the unifortress\launcher.exe program.

=== Technical Information ===
- Uses AES-256 encryption in XTS mode
- Encryption key is derived from password using Argon2
- Random salt is used to protect against password brute force attacks
"#;
    
    readme_file.write_all(readme_content.as_bytes())?;
    println!("Created file {}", readme_path);
    
    Ok(drive_letter)
}

// Helper function to get drive letter by disk number
fn get_drive_letter_by_disk_number(disk_number: u8) -> Result<String> {
    // Request information through PowerShell
    let cmd = format!(
        "Get-Partition -DiskNumber {} | Select-Object -ExpandProperty DriveLetter", 
        disk_number
    );
    
    let output = Command::new("powershell")
        .args(&[
            "-Command",
            &cmd
        ])
        .output()
        .context("Failed to execute PowerShell command to get drive letter")?;

    if !output.status.success() {
        bail!("Command execution error: {}", String::from_utf8_lossy(&output.stderr));
    }

    let drive_letter = String::from_utf8_lossy(&output.stdout).trim().to_string();
    
    if drive_letter.is_empty() {
        bail!("Failed to get drive letter for disk {}", disk_number);
    }
    
    Ok(drive_letter)
} 