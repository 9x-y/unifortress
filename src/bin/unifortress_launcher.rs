use anyhow::{bail, Context, Result};
use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::fs;
use std::io::{self, Write};

const APP_NAME: &str = "UniFortress Auto-Mount";

fn main() -> Result<()> {
    // Display application information
    println!("{} - Automatic encrypted disk mounter", APP_NAME);
    println!("===========================================================");
    
    // Determine the drive letter of the flash drive from which the application was launched
    let flash_drive_letter = detect_flash_drive_letter()?;
    println!("Detected flash drive: {}:", flash_drive_letter);
    
    // Check for the presence of an encrypted volume on the flash drive
    let encrypted_volume_path = format!("{}:\\unifortress.enc", flash_drive_letter);
    
    if !Path::new(&encrypted_volume_path).exists() {
        println!("Encrypted volume not found on this flash drive.");
        println!("Expected path: {}", encrypted_volume_path);
        pause_exit(1);
        return Ok(());
    }
    
    // Check the UniFortress signature in the encrypted volume
    if !is_unifortress_volume(&encrypted_volume_path)? {
        println!("File found, but it is not a UniFortress volume or is corrupted.");
        pause_exit(1);
        return Ok(());
    }
    
    // Request password for unlocking
    print!("Enter password to decrypt: ");
    io::stdout().flush()?;
    let password = rpassword::read_password().context("Failed to read password")?;
    
    // Start mounting process
    println!("Mounting encrypted volume...");
    
    // Find path to the main UniFortress binary
    let unifortress_path = find_unifortress_binary()?;
    
    // Check if Dokan driver is installed
    if !check_dokan_installed()? {
        println!("[ERROR] Dokan driver is not installed.");
        println!("To use encrypted disk, you need to install Dokan.");
        println!("Download Dokan from https://github.com/dokan-dev/dokany/releases");
        pause_exit(1);
        return Ok(());
    }
    
    // Launch the mounting process
    let status = Command::new(unifortress_path)
        .args([
            "unlock",
            "-f",
            &encrypted_volume_path,
            "-m",
            "V:", // Use V: for virtual disk
            "--password",
            &password
        ])
        .status()
        .context("Failed to start mounting program")?;
    
    if !status.success() {
        println!("[ERROR] Failed to mount encrypted volume.");
        println!("Possible wrong password or corrupted volume.");
        pause_exit(status.code().unwrap_or(1));
    }
    
    Ok(())
}

// Determines the disk letter of the flash drive from which the application was launched
fn detect_flash_drive_letter() -> Result<String> {
    // Get path to executable file
    let exe_path = env::current_exe()?;
    
    // Extract drive letter from path
    if let Some(drive_letter) = exe_path.to_string_lossy().chars().next() {
        return Ok(drive_letter.to_string().to_uppercase());
    }
    
    bail!("Failed to determine flash drive letter")
}

// Checks if the file is an encrypted UniFortress volume
fn is_unifortress_volume(path: &str) -> Result<bool> {
    // Open file for reading
    let mut file = fs::File::open(path)?;
    
    // Read the first 16 bytes (there should be a UniFortress signature)
    let mut signature = [0u8; 16];
    
    // In a real application, you need to read the signature from a specific sector
    // This is a simplified check - just read the beginning of the file
    if let Err(_) = file.read_exact(&mut signature) {
        return Ok(false);
    }
    
    // Check for "UniFortress" string in the read bytes
    // In a real application, you should compare with the exact signature
    let signature_str = String::from_utf8_lossy(&signature);
    Ok(signature_str.contains("UniFortress"))
}

// Finds the main UniFortress binary file
fn find_unifortress_binary() -> Result<PathBuf> {
    // First check the current directory
    let current_dir = env::current_dir()?;
    let exe_in_current = current_dir.join("unifortress.exe");
    
    if exe_in_current.exists() {
        return Ok(exe_in_current);
    }
    
    // Check the directory with the executable file
    let exe_dir = env::current_exe()?.parent().unwrap_or(Path::new("")).to_path_buf();
    let exe_in_exe_dir = exe_dir.join("unifortress.exe");
    
    if exe_in_exe_dir.exists() {
        return Ok(exe_in_exe_dir);
    }
    
    // If not on the flash drive, use the path to the main application
    // In this case, we assume that the main application is installed on the computer
    // If not, return an error
    bail!("Failed to find the main UniFortress binary file")
}

// Checks if the Dokan driver is installed
fn check_dokan_installed() -> Result<bool> {
    // Check for the Dokan service via PowerShell
    let output = Command::new("powershell")
        .args([
            "-Command",
            "Get-Service -Name 'dokan*' | Select-Object -ExpandProperty Status"
        ])
        .output()?;
    
    // If we got output and it contains "Running", consider the driver installed
    let status = String::from_utf8_lossy(&output.stdout);
    Ok(status.trim().to_lowercase() == "running")
}

// Pause before exit to display messages
fn pause_exit(code: i32) {
    println!("\nPress Enter to exit...");
    let _ = io::stdin().read_line(&mut String::new());
    std::process::exit(code);
} 