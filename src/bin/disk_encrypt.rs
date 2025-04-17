use std::process::Command;
use std::io::{self, Write};
use std::path::PathBuf;
use anyhow::{anyhow, bail, Result, Context};
use clap::{Parser, Subcommand};
use log::*;
use unifortress::encryption::encrypt_volume;
use unifortress::deferred::DeferredEncryptedVolume;
use unifortress::decryption;
use rpassword;
use std::fs;
use std::time::Instant;
use unifortress::platform::volume_io;

// Constants
const HEADER_SIZE: usize = 4096; // 4KB for header
const SECTOR_SIZE: usize = 512; // Standard sector size
const SALT_SIZE: usize = 32; // Salt size
const KEY_SIZE: usize = 64; // 512 bits for XTS (2 keys, 256 bits each)

#[derive(Parser)]
#[command(name = "UniFortress Disk Encryption Tool")]
#[command(author = "UniFortress Team")]
#[command(version = "1.0")]
#[command(about = "Encrypt and manage encrypted USB drives", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt USB drive with full encryption
    Encrypt {
        /// Device path to encrypt
        #[arg(short, long)]
        device: String,
        /// Fast encrypt USB drive (deferred encryption)
        #[arg(short, long)]
        fast: bool,
        /// Password for encryption
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Fast encrypt USB drive (deferred encryption)
    FastEncrypt {
        /// Device path to encrypt
        #[arg(short, long)]
        device: String,
    },
    /// Decrypt USB drive
    Decrypt {
        /// Device path to decrypt
        #[arg(short, long)]
        device: String,
    },
    /// Check if USB drive is encrypted
    Check {
        /// Device path to check
        #[arg(short, long)]
        device: String,
    },
    /// Mount encrypted USB drive
    Mount {
        /// Device path to mount
        #[arg(short, long)]
        device: String,
        /// Mount point
        #[arg(short, long)]
        mount_point: String,
    },
    /// Unmount encrypted USB drive
    Unmount {
        /// Mount point
        #[arg(short, long)]
        mount_point: String,
    },
    /// List all available drives
    ListDevices,
    /// Verify password for encrypted device
    Verify {
        /// Device path to verify
        #[arg(short, long)]
        device: String,
    },
    /// Get encryption status
    Status {
        /// Device path to check
        #[arg(short, long)]
        device: String,
    },
}

fn main() -> anyhow::Result<()> {
    // Initialize logger
    env_logger::init();
    
    // Parse command line arguments
    let cli = Cli::parse();
    
    // Run command
    run_command(&cli)
}

/// Formats a disk using diskpart before encryption (Windows only)
fn format_disk_before_encryption(device_path: &str) -> Result<()> {
    if !cfg!(windows) {
        warn!("Disk formatting is only supported on Windows");
        return Ok(());
    }

    // Extract disk number from path
    let disk_number = if device_path.starts_with(r"\\.\PhysicalDrive") {
        device_path.trim_start_matches(r"\\.\PhysicalDrive")
    } else {
        return Err(anyhow!("Invalid device path format"));
    };

    println!("AUTOMATIC DISK FORMATTING");
    println!("====================================");
    println!("For reliable encryption, the disk needs to be formatted first.");
    println!("All data on disk {} will be destroyed!", disk_number);
    println!("Continue? (y/n): ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    
    if input.trim().to_lowercase() != "y" {
        return Err(anyhow!("Formatting cancelled by user"));
    }

    // Create diskpart script for formatting
    // This script:
    // 1. Selects the disk
    // 2. Cleans it (removes all partitions)
    // 3. Creates a new primary partition
    // 4. Formats it with NTFS quick format
    // 5. Assigns a drive letter automatically
    let diskpart_script = format!(
        "select disk {}\n\
         clean\n\
         create partition primary\n\
         format fs=ntfs quick\n\
         assign\n\
         exit\n",
        disk_number
    );
    
    let script_path = std::env::temp_dir().join("unifortress_format.txt");
    std::fs::write(&script_path, diskpart_script)?;
    
    println!("Formatting disk {}...", disk_number);
    
    // Execute diskpart with administrative privileges
    let output = Command::new("diskpart")
        .args(["/s", script_path.to_str().unwrap()])
        .output()?;
    
    let _output_str = String::from_utf8_lossy(&output.stdout);
    let error_str = String::from_utf8_lossy(&output.stderr);
    
    // Clean up the temporary script
    let _ = std::fs::remove_file(script_path);
    
    if !output.status.success() {
        println!("Error formatting disk:");
        println!("{}", error_str);
        return Err(anyhow!("Failed to format disk"));
    }
    
    println!("Disk successfully formatted and ready for encryption.");
    println!("====================================");
    
    Ok(())
}

fn list_drives() -> Result<()> {
    println!("Available disks:");
    println!("================");
    
    match unifortress::platform::get_available_drives() {
        Ok(drives) => {
            if drives.is_empty() {
                println!("No available disks found.");
                return Ok(());
            }
            
            // Print header
            println!("{:<5} {:<25} {:<15} {:<12} {}", 
                "#", "Name", "Size", "Type", "Path");
            println!("{:-<70}", "");
            
            // Print drives in formatted table
            for drive in &drives {
                let drive_name = if drive.name.len() > 23 {
                    format!("{}...", &drive.name[0..20])
                } else {
                    drive.name.clone()
                };
                
                // Format with warnings for system disks
                let warning = if drive.is_system { " (SYSTEM!)" } else { "" };
                println!("[{:<3}] {:<25} {:<15} {:<12} {}{}", 
                    drive.index, drive_name, drive.size, drive.drive_type, drive.path, warning);
            }
            
            // Print usage examples
            println!("\nUsage examples:");
            
            if cfg!(windows) {
                println!("  To encrypt disk #1: unifortress encrypt --device 1");
                println!("  Or directly: unifortress encrypt --device {}", 
                    drives.first().map_or("\\\\(.\\PhysicalDrive1", |d| d.path.as_str()));
            } else if cfg!(target_os = "macos") {
                println!("  To encrypt disk #1: unifortress encrypt --device 1");
                println!("  Or directly: unifortress encrypt --device {}", 
                    drives.first().map_or("/dev/disk1", |d| d.path.as_str()));
            } else {
                println!("  To encrypt disk #1: unifortress encrypt --device 1");
                println!("  Or directly: unifortress encrypt --device {}", 
                    drives.first().map_or("/dev/sdb", |d| d.path.as_str()));
            }
            
            // Security warnings
            println!("\nWARNING: Before encryption, make sure you've selected the correct disk!");
            println!("         ALL DATA on the selected disk WILL BE DESTROYED!");
            println!("         Never encrypt your system disk!");
        },
        Err(e) => {
            println!("Error getting disk list: {}", e);
            
            // Fallback to old implementation for compatibility
            if cfg!(windows) {
                let diskpart_script = "list disk\nexit\n";
                let script_path = std::env::temp_dir().join("unifortress_diskpart.txt");
                std::fs::write(&script_path, diskpart_script)?;
                
                let output = Command::new("diskpart")
                    .args(["/s", script_path.to_str().unwrap()])
                    .output()?;
                
                let output_str = String::from_utf8_lossy(&output.stdout);
                
                if let Some(start_idx) = output_str.find("DISKPART>") {
                    if let Some(disk_list_start) = output_str[start_idx..].find("Disk ###") {
                        let disk_list = &output_str[start_idx + disk_list_start..];
                        println!("{}", disk_list);
                    }
                } else {
                    println!("{}", output_str);
                }
                
                let _ = std::fs::remove_file(script_path);
            } else {
                let output = Command::new("lsblk")
                    .args(["-o", "NAME,SIZE,TYPE,MOUNTPOINT", "--noheadings"])
                    .output()?;
                
                let output_str = String::from_utf8_lossy(&output.stdout);
                println!("{}", output_str);
            }
        }
    }
    
    Ok(())
}

// Process device path, which might be an index
fn process_device_path(device_path: &str) -> Result<String> {
    unifortress::platform::get_device_path(device_path)
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

// Prompt user for password
fn prompt_for_password() -> Result<String> {
    print!("Enter password: ");
    io::stdout().flush()?;
    let password = rpassword::read_password()
        .context("Failed to read password")?;
    
    if password.is_empty() {
        return Err(anyhow!("Password cannot be empty"));
    }
    
    Ok(password)
}

// Function to encrypt the device
fn encrypt_device(device_path: &str, password: &str) -> Result<()> {
    info!("Starting encryption for device: {}", device_path);
    encrypt_volume(device_path, password.as_bytes(), None)
}

// Fast encrypt device (only header)
fn fast_encrypt_device(device_path: &str, password: &str) -> Result<()> {
    info!("Starting fast encryption for device: {}", device_path);
    let mut volume = DeferredEncryptedVolume::new(device_path, password)?;
    volume.fast_encrypt()?;
    Ok(())
}

fn encrypt_command(device_path: &str, fast: bool, password: &str) -> Result<()> {
    // Extract drive details for better user information
    let (disk_name, disk_size) = get_disk_details(device_path)?;
    
    // Format disk before encryption
    if let Err(e) = format_disk_before_encryption(device_path) {
        println!("Warning: Failed to automatically format the disk: {}", e);
        println!("To avoid write issues, it's recommended to manually format the disk before encryption.");
        
        println!("Continue encryption without formatting? (y/n): ");
        io::stdout().flush()?;
        
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        
        if input.trim().to_lowercase() != "y" {
            return Err(anyhow!("Encryption cancelled by user"));
        }
    }
    
    // Final warning with details of the disk to be encrypted
    println!("\nWARNING: You are about to encrypt:");
    println!("Device: {}", device_path);
    println!("Name: {}", disk_name);
    println!("Size: {}", disk_size);
    println!("\nALL DATA ON THIS DEVICE WILL BE DESTROYED!");
    println!("Continue? (y/n): ");
    io::stdout().flush()?;
    
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    
    if input.trim().to_lowercase() != "y" {
        return Err(anyhow!("Encryption cancelled by user"));
    }
    
    // Initialize the encryption process
    if fast {
        println!("Starting fast encryption (only header)...");
        fast_encrypt_device(device_path, password)
    } else {
        println!("Starting full encryption process...");
        encrypt_device(device_path, password)
    }
}

fn run_command(cli: &Cli) -> anyhow::Result<()> {
    match &cli.command {
        Commands::Encrypt { device, fast, password } => {
            // Process device path, which might be an index
            let device_path = process_device_path(device)?;
                
            let password_str = match password {
                Some(pass) => pass.clone(),
                None => {
                    print!("Enter encryption password: ");
                    io::stdout().flush()?;
                    let password = rpassword::read_password()?;
                    print!("Confirm password: ");
                    io::stdout().flush()?;
                    let confirm = rpassword::read_password()?;
                    
                    if password != confirm {
                        return Err(anyhow!("Passwords do not match"));
                    }
                    
                    if password.is_empty() {
                        return Err(anyhow!("Password cannot be empty"));
                    }
                    
                    password
                }
            };
            
            encrypt_command(&device_path, *fast, &password_str)?;
            println!("Encryption completed successfully.");
            Ok(())
        },
        Commands::FastEncrypt { device } => {
            info!("Starting fast encryption for device: {}", device);
            // Process device path, which might be an index
            let device_path = process_device_path(device)?;
            let password = prompt_for_password()?;
            fast_encrypt_device(&device_path, &password)?;
            println!("Fast encryption completed successfully.");
            Ok(())
        },
        Commands::Check { device } => {
            info!("Checking encryption status for device: {}", device);
            // Process device path, which might be an index
            let device_path = process_device_path(device)?;
            let (name, size) = get_disk_details(&device_path)?;
            println!("Device: {} ({} - {})", device_path, name, size);
            
            match decryption::is_encrypted_volume(&device_path) {
                Ok(true) => {
                    println!("Status: ENCRYPTED (UniFortress format detected)");
                    Ok(())
                },
                Ok(false) => {
                    println!("Status: NOT ENCRYPTED (No UniFortress format detected)");
                    Ok(())
                },
                Err(e) => {
                    println!("Status: ERROR - Could not determine encryption status: {}", e);
                    Err(e)
                }
            }
        },
        Commands::Decrypt { device } => {
            info!("Starting decryption for device: {}", device);
            let password = prompt_for_password()?;
            decryption::decrypt_volume(device, &password)?;
            println!("Decryption completed successfully.");
            Ok(())
        },
        Commands::Mount { device, mount_point } => {
            info!("Mounting encrypted volume from: {} to {}", device, mount_point);
            println!("Mounting not yet implemented");
            // TODO: implement mounting
            Ok(())
        },
        Commands::Unmount { mount_point } => {
            info!("Unmounting encrypted volume from: {}", mount_point);
            println!("Unmounting not yet implemented");
            // TODO: implement unmounting
            Ok(())
        },
        Commands::ListDevices => {
            info!("Listing available devices");
            list_drives()?;
            Ok(())
        },
        Commands::Verify { device } => {
            info!("Verifying password for device: {}", device);
            let password = prompt_for_password()?;
            match decryption::verify_password(device, &password) {
                Ok(true) => {
                    println!("Password verification successful.");
                    Ok(())
                },
                Ok(false) => {
                    println!("Password verification failed: incorrect password.");
                    Err(anyhow!("Password verification failed"))
                },
                Err(e) => {
                    println!("Password verification error: {}", e);
                    Err(e)
                }
            }
        },
        Commands::Status { device } => {
            info!("Checking encryption status for device: {}", device);
            
            // First check if the volume is encrypted
            match decryption::is_encrypted_volume(device) {
                Ok(true) => {
                    println!("Device: {} is encrypted with UniFortress format", device);
                    
                    // Try to get password to check encryption status
                    println!("Enter password to get detailed information:");
                    match prompt_for_password() {
                        Ok(password) => {
                            // Verify password
                            match decryption::verify_password(device, &password) {
                                Ok(true) => {
                                    // Password correct, open volume to check status
                                    match DeferredEncryptedVolume::open(device, &password) {
                                        Ok(volume) => {
                                            // Get status report and display it
                                            let status = volume.get_status_report();
                                            println!("\nENCRYPTION STATUS:");
                                            println!("=================");
                                            if let Some(status_str) = status {
                                                println!("{}", status_str);
                                            } else {
                                                println!("Status information not available");
                                            }
                                            
                                            // Display additional information
                                            if volume.is_fully_encrypted() {
                                                println!("\nDevice is fully encrypted.");
                                            } else {
                                                println!("\nWARNING: Device is undergoing background encryption.");
                                                println!("Do not remove device until encryption process is complete!");
                                                println!("You can safely use the device during the encryption process.");
                                            }
                                        },
                                        Err(e) => {
                                            println!("Error opening encrypted volume: {}", e);
                                            return Err(e);
                                        }
                                    }
                                },
                                Ok(false) => {
                                    println!("Incorrect password. Cannot retrieve encryption status.");
                                    return Err(anyhow!("Password verification failed"));
                                },
                                Err(e) => {
                                    println!("Error verifying password: {}", e);
                                    return Err(e);
                                }
                            }
                        },
                        Err(e) => {
                            println!("Failed to get password: {}", e);
                            return Err(e);
                        }
                    }
                },
                Ok(false) => {
                    println!("Device: {} is NOT encrypted (UniFortress format not detected)", device);
                },
                Err(e) => {
                    println!("Error determining encryption status: {}", e);
                    return Err(e);
                }
            }
            
            Ok(())
        },
    }
} 