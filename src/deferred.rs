use anyhow::{anyhow, Result};
use std::sync::{Arc, RwLock};
use crate::encryption::{VolumeHeader, derive_key, split_derived_key, VOLUME_SIGNATURE, encrypt_sector};
use crate::platform::volume_io::{VolumeFile, open_device, open_device_readonly};
use std::collections::HashSet;
use std::collections::HashMap;
use log::*;
use crate::crypto::xts;
use std::cmp::min;
use std::thread;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use crossbeam_channel::{bounded, Sender, Receiver};
use std::io::{Error, ErrorKind};
use std::io::{self, Write};

/// Buffer size used for encryption
const BUFFER_SIZE: usize = 64 * 1024 * 1024; // 64 MB (increased from 16MB)

/// Adding parameters for multi-threaded encryption
const DEFAULT_THREAD_COUNT: usize = 4;
const SECTOR_BATCH_SIZE: usize = 1024; // Increased from 128 (8 times larger)

/// Minimum block size for Direct I/O (usually 4KB)
const DIRECT_IO_ALIGNMENT: usize = 4096;

/// Structure for tracking encrypted sectors
struct EncryptedSectors {
    /// Table of encrypted sectors (using HashSet for efficient lookup)
    encrypted: HashSet<u64>,
    
    /// Cache of decrypted sectors (to speed up repeated reads)
    decrypted_cache: HashMap<u64, Vec<u8>>,
    
    /// Maximum cache size in sectors
    max_cache_sectors: usize,
}

impl EncryptedSectors {
    /// Creates a new tracking object for sectors
    fn new(max_cache_mb: usize) -> Self {
        Self {
            encrypted: HashSet::new(),
            decrypted_cache: HashMap::new(),
            max_cache_sectors: max_cache_mb * 1024 * 1024 / 4096, // Assuming sector size 4096
        }
    }
    
    /// Checks if a sector is encrypted
    fn is_encrypted(&self, sector_index: u64) -> bool {
        self.encrypted.contains(&sector_index)
    }
    
    /// Marks a sector as encrypted
    fn mark_encrypted(&mut self, sector_index: u64) {
        self.encrypted.insert(sector_index);
    }
    
    /// Marks a range of sectors as encrypted
    fn mark_range_encrypted(&mut self, start_sector: u64, count: u64) {
        for i in 0..count {
            self.encrypted.insert(start_sector + i);
        }
    }
    
    /// Adds decrypted data to cache
    fn cache_decrypted(&mut self, sector_index: u64, data: &[u8], _sector_size: usize) {
        // Check if cache needs to be cleared before adding new sector
        if self.decrypted_cache.len() >= self.max_cache_sectors {
            // Simple strategy: clear entire cache
            self.decrypted_cache.clear();
        }
        
        // Add sector to cache
        self.decrypted_cache.insert(sector_index, data.to_vec());
    }
    
    /// Gets decrypted data from cache
    fn get_cached(&self, sector_index: u64) -> Option<&Vec<u8>> {
        self.decrypted_cache.get(&sector_index)
    }
}

/// Message for worker encryption thread
enum EncryptionTask {
    /// Encrypt a range of sectors
    EncryptRange {
        start_sector: u64,
        count: usize,
    },
    /// Finish work
    Shutdown,
}

/// Background encryption process state
pub struct BackgroundEncryptionState {
    /// Current encryption progress (in percentage)
    progress: AtomicUsize,
    /// Background encryption activity flag
    active: AtomicBool,
    /// Encryption speed (MB/s)
    speed: AtomicUsize,
    /// Last error
    last_error: RwLock<Option<String>>,
    /// Encrypted sectors counter
    encrypted_sectors: AtomicUsize,
    /// Total number of sectors
    total_sectors: AtomicUsize,
}

impl BackgroundEncryptionState {
    fn new(total_sectors: usize) -> Self {
        Self {
            progress: AtomicUsize::new(0),
            active: AtomicBool::new(false),
            speed: AtomicUsize::new(0),
            last_error: RwLock::new(None),
            encrypted_sectors: AtomicUsize::new(0),
            total_sectors: AtomicUsize::new(total_sectors),
        }
    }
    
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }
    
    pub fn get_progress(&self) -> f64 {
        self.progress.load(Ordering::Relaxed) as f64 / 100.0
    }
    
    pub fn get_speed(&self) -> f64 {
        self.speed.load(Ordering::Relaxed) as f64 / 100.0
    }
    
    pub fn get_last_error(&self) -> Option<String> {
        let guard = self.last_error.read().unwrap();
        guard.clone()
    }
    
    pub fn get_encrypted_sectors(&self) -> usize {
        self.encrypted_sectors.load(Ordering::Relaxed)
    }
    
    pub fn get_total_sectors(&self) -> usize {
        self.total_sectors.load(Ordering::Relaxed)
    }
    
    fn set_error(&self, error: String) {
        let mut guard = self.last_error.write().unwrap();
        *guard = Some(error);
    }
    
    fn update_progress(&self, encrypted: usize, speed_mbps: f64) {
        self.encrypted_sectors.store(encrypted, Ordering::Relaxed);
        self.speed.store((speed_mbps * 100.0) as usize, Ordering::Relaxed);
        
        let total = self.total_sectors.load(Ordering::Relaxed);
        if total > 0 {
            let progress = encrypted * 10000 / total;
            self.progress.store(progress, Ordering::Relaxed);
        }
    }
    
    /// Returns current encryption state as a string for user output
    pub fn get_status_report(&self) -> String {
        let progress = self.get_progress();
        let speed = self.get_speed();
        let encrypted = self.get_encrypted_sectors();
        let total = self.get_total_sectors();
        
        let remaining_sectors = total.saturating_sub(encrypted);
        let remaining_secs = if speed > 0.0 {
            (remaining_sectors as f64) / (speed * 1024.0 * 1024.0 / 512.0)
        } else {
            0.0
        };
        
        // Formatting remaining time
        let remaining_fmt = if remaining_secs > 60.0 * 60.0 {
            format!("{:.1} hours", remaining_secs / 3600.0)
        } else if remaining_secs > 60.0 {
            format!("{:.1} minutes", remaining_secs / 60.0)
        } else {
            format!("{:.1} seconds", remaining_secs)
        };
        
        format!(
            "Encryption progress: {:.2}% ({}/{} sectors)\nSpeed: {:.2} MB/sec\nRemaining: {}",
            progress, encrypted, total, speed, remaining_fmt
        )
    }
}

/// Structure for deferred volume encryption
pub struct DeferredEncryptedVolume {
    /// Volume file
    volume: Arc<RwLock<VolumeFile>>,
    
    /// XTS encryption key
    encryption_key: [u8; crate::crypto::xts::XTS_KEY_SIZE],
    
    /// HMAC key
    hmac_key: [u8; 32],
    
    /// Volume header
    header: VolumeHeader,
    
    /// Tracking encrypted sectors
    sectors: Arc<RwLock<EncryptedSectors>>,
    
    /// Sector size
    sector_size: u32,
    
    /// Total number of sectors (excluding header)
    total_sectors: u64,
    
    /// Number of header sectors
    header_sectors: u64,
    
    /// Channel for sending tasks to worker threads
    task_sender: Option<Sender<EncryptionTask>>,
    
    /// Background encryption state
    background_state: Arc<BackgroundEncryptionState>,
    
    /// Worker threads
    worker_threads: Vec<thread::JoinHandle<()>>,
}

impl DeferredEncryptedVolume {
    /// Creates a new volume with deferred encryption
    pub fn new(device_path: &str, password: &str) -> Result<Self> {
        // Open device
        let volume = open_device(device_path)?;
        let volume = Arc::new(RwLock::new(volume));
        
        // Get device parameters
        let volume_size = {
            let guard = volume.read().unwrap();
            guard.get_size()?
        };
        let sector_size = {
            let guard = volume.read().unwrap();
            guard.get_sector_size()
        };
        
        // Number of sectors in header
        let header_size = 4096; // 4KB
        let header_sectors = (header_size + sector_size as usize - 1) / sector_size as usize;
        let header_sectors = header_sectors as u64;
        
        // Total number of data sectors (excluding header)
        let total_sectors = volume_size / sector_size as u64 - header_sectors;
        
        // Generate salt
        let salt = crate::encryption::generate_salt();
        
        // Derive key from password
        let derived_key = derive_key(password.as_bytes(), &salt)?;
        
        // Split key into encryption key and HMAC key
        let (encryption_key_vec, hmac_key_vec) = split_derived_key(&derived_key)?;
        
        // Convert keys to required format
        let mut encryption_key = [0u8; crate::crypto::xts::XTS_KEY_SIZE];
        let mut hmac_key = [0u8; 32];
        
        encryption_key.copy_from_slice(&encryption_key_vec);
        hmac_key.copy_from_slice(&hmac_key_vec);
        
        // Create volume header
        let header = VolumeHeader::new(volume_size, sector_size, &encryption_key, &hmac_key)?;
        
        // Write header to device
        {
            let mut guard = volume.write().unwrap();
            header.write_to_volume(&mut *guard)?;
        }
        
        // Create structure for tracking encrypted sectors
        let sectors = EncryptedSectors::new(128); // Cache 128 MB
        
        let background_state = Arc::new(BackgroundEncryptionState::new(total_sectors as usize));
        
        info!("Deferred encryption initialized. Volume size: {} bytes, Sector size: {} bytes",
             volume_size, sector_size);
        
        Ok(Self {
            volume,
            encryption_key,
            hmac_key,
            header,
            sectors: Arc::new(RwLock::new(sectors)),
            sector_size,
            total_sectors,
            header_sectors,
            task_sender: None,
            background_state,
            worker_threads: Vec::new(),
        })
    }
    
    /// Opens an existing encrypted volume
    pub fn open(device_path: &str, password: &str) -> Result<Self> {
        // Open device for read-only to check password
        let mut volume_readonly = open_device_readonly(device_path)?;
        
        // Read first part of header for signature check
        let mut header_buffer = vec![0u8; 4096]; // Buffer for header
        volume_readonly.read_sectors(0, volume_readonly.get_sector_size() as u32, volume_readonly.get_sector_size(), &mut header_buffer)?;
        
        // Check signature (first bytes of header)
        if &header_buffer[0..VOLUME_SIGNATURE.len()] != VOLUME_SIGNATURE.as_slice() {
            return Err(anyhow!("Invalid volume signature. Device is not encrypted with UniFortress."));
        }
        
        // Now derive keys from password
        // We need salt - usually it's in the header
        // Temporary solution: use fixed salt and improve later
        let salt = &header_buffer[VOLUME_SIGNATURE.len()..VOLUME_SIGNATURE.len() + 16]; // Approximate salt position
        
        // Derive keys from password
        let derived_key = derive_key(password.as_bytes(), salt)?;
        let (encryption_key_vec, hmac_key_vec) = split_derived_key(&derived_key)?;
        
        // Convert keys to required format
        let mut encryption_key = [0u8; crate::crypto::xts::XTS_KEY_SIZE];
        let mut hmac_key = [0u8; 32];
        
        encryption_key.copy_from_slice(&encryption_key_vec);
        hmac_key.copy_from_slice(&hmac_key_vec);
        
        // Create header - we'll restore it from buffer later, use new one for now
        let header = VolumeHeader::new(0, 0, &encryption_key, &hmac_key)?;
        
        // Close readonly access and open with full access
        drop(volume_readonly);
        let volume = open_device(device_path)?;
        let volume = Arc::new(RwLock::new(volume));
        
        // Get device parameters
        let sector_size = {
            let guard = volume.read().unwrap();
            guard.get_sector_size()
        };
        
        let volume_size = {
            let guard = volume.read().unwrap();
            guard.get_size()?
        };
        
        // Number of sectors in header
        let header_size = 4096; // 4KB
        let header_sectors = (header_size + sector_size as usize - 1) / sector_size as usize;
        let header_sectors = header_sectors as u64;
        
        // Total number of data sectors (excluding header)
        let total_sectors = volume_size / sector_size as u64 - header_sectors;
        
        // Create structure for tracking encrypted sectors
        // Assuming all sectors are not encrypted yet
        let sectors = EncryptedSectors::new(128); // Cache 128 MB
        
        info!("Deferred encryption volume opened. Volume size: {} bytes, Sector size: {} bytes",
              volume_size, sector_size);
        
        Ok(Self {
            volume,
            encryption_key,
            hmac_key,
            header,
            sectors: Arc::new(RwLock::new(sectors)),
            sector_size,
            total_sectors,
            header_sectors,
            task_sender: None,
            background_state: Arc::new(BackgroundEncryptionState::new(total_sectors as usize)),
            worker_threads: Vec::new(),
        })
    }
    
    /// Reads sectors from disk
    /// Returns decrypted data for encrypted sectors
    pub fn read_sectors(&self, sector_index: u64, num_sectors: u32) -> Result<Vec<u8>> {
        // Check boundaries
        if sector_index < self.header_sectors {
            return Err(anyhow!("Cannot read header sectors"));
        }
        
        if sector_index + num_sectors as u64 > self.header_sectors + self.total_sectors {
            return Err(anyhow!("Sector index out of bounds"));
        }
        
        // Allocate buffer for data
        let sector_size = self.sector_size as usize;
        let mut buffer = vec![0u8; num_sectors as usize * sector_size];
        
        // Read data from device
        {
            let mut volume_guard = self.volume.write().unwrap();
            volume_guard.read_sectors(sector_index, num_sectors, self.sector_size, &mut buffer)?;
        }
        
        // Check which sectors are encrypted and decrypt them if necessary
        let sectors_guard = self.sectors.read().unwrap();
        
        for i in 0..num_sectors as usize {
            let current_sector = sector_index + i as u64;
            let offset = i * sector_size;
            let sector_data = &mut buffer[offset..offset + sector_size];
            
            // If sector is encrypted, decrypt it
            if sectors_guard.is_encrypted(current_sector) {
                // First check if data exists in cache
                if let Some(cached_data) = sectors_guard.get_cached(current_sector) {
                    // Use cached data
                    sector_data.copy_from_slice(cached_data);
                } else {
                    // Decrypt data
                    if let Err(e) = xts::decrypt_sector(sector_data, current_sector, &self.encryption_key) {
                        error!("Failed to decrypt sector {}: {}", current_sector, e);
                        continue;
                    }
                    
                    // Cache decrypted data
                    drop(sectors_guard);
                    let mut sectors_guard = self.sectors.write().unwrap();
                    sectors_guard.cache_decrypted(current_sector, sector_data, sector_size);
                    break; // Exit, as we already released and re-acquired the mutex
                }
            }
        }
        
        Ok(buffer)
    }
    
    /// Writes sectors to disk
    /// Encrypts data before writing
    pub fn write_sectors(&mut self, sector_index: u64, data: &[u8]) -> Result<()> {
        // Check boundaries
        if sector_index < self.header_sectors {
            return Err(anyhow!("Cannot write to header sectors"));
        }
        
        if sector_index + data.len() as u64 / self.sector_size as u64 > self.header_sectors + self.total_sectors {
            return Err(anyhow!("Sector index out of bounds"));
        }
        
        let sector_size = self.sector_size as usize;
        let num_sectors = data.len() / sector_size;
        
        // Copy data for encryption
        let mut encrypted_data = data.to_vec();
        
        // Encrypt each sector
        for i in 0..num_sectors {
            let current_sector = sector_index + i as u64;
            let offset = i * sector_size;
            let sector_data = &mut encrypted_data[offset..offset + sector_size];
            
            // Encrypt data
            encrypt_sector(sector_data, current_sector, &self.encryption_key)?;
            
            // Mark sector as encrypted
            let mut sectors_guard = self.sectors.write().unwrap();
            sectors_guard.mark_encrypted(current_sector);
        }
        
        // Write encrypted data to device
        let mut volume_guard = self.volume.write().unwrap();
        volume_guard.write_sectors(sector_index, self.sector_size, &encrypted_data)?;
        
        Ok(())
    }
    
    /// Starts background encryption process
    pub fn start_background_encryption(&mut self, thread_count: Option<usize>) -> Result<()> {
        if self.task_sender.is_some() {
            return Err(anyhow!("Background encryption is already running"));
        }
        
        // Output information about starting encryption directly to console
        println!("\n========================================================");
        println!("STARTING ENCRYPTION USING MULTI-THREADED PROCESSING");
        println!("========================================================");
        std::io::stdout().flush().ok(); // Force output to display immediately
        
        let threads = thread_count.unwrap_or_else(|| {
            let cpu_count = num_cpus::get();
            min(cpu_count, DEFAULT_THREAD_COUNT)
        });
        
        info!("Starting background encryption using {} threads", threads);
        println!("* Using {} threads for parallel encryption", threads);
        println!("* Encryption block size: {} sectors ({} MB)", 
                SECTOR_BATCH_SIZE, SECTOR_BATCH_SIZE * self.sector_size as usize / (1024*1024));
        println!("* Total volume size: {} sectors ({:.2} GB)",
                self.total_sectors, self.total_sectors as f64 * self.sector_size as f64 / (1024.0*1024.0*1024.0));
        println!("* Statistics will be updated every second");
        std::io::stdout().flush().ok(); // Force output to display immediately
        
        // Create channel for message exchange
        let (sender, receiver) = bounded::<EncryptionTask>(threads * 2);
        self.task_sender = Some(sender);
        
        // Update state
        self.background_state.active.store(true, Ordering::SeqCst);
        
        // Start worker threads with high priority
        for thread_id in 0..threads {
            let thread_receiver = receiver.clone();
            let volume = self.volume.clone();
            let sectors = self.sectors.clone();
            let encryption_key = self.encryption_key;
            let sector_size = self.sector_size;
            let background_state = self.background_state.clone();
            
            // Create thread with name and increased priority
            let worker = thread::Builder::new()
                .name(format!("encryption-worker-{}", thread_id))
                .stack_size(2 * 1024 * 1024) // 2MB stack for better efficiency
                .spawn(move || {
                    // Set high priority for thread
                    #[cfg(target_os = "windows")]
                    {
                        use winapi::um::processthreadsapi::{SetThreadPriority, GetCurrentThread};
                        use winapi::um::winbase::THREAD_PRIORITY_ABOVE_NORMAL;
                        
                        unsafe {
                            SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL as i32);
                        }
                    }
                    
                    #[cfg(target_os = "linux")]
                    {
                        // On Linux we use nice values for process priority
                        // Lower value = higher priority (-20 to 19)
                        let _ = nix::sys::resource::setpriority(
                            nix::sys::resource::PriorityWhich::Process,
                            nix::unistd::gettid().as_raw() as u32,
                            -10, // High priority
                        );
                    }
                    
                    Self::encryption_worker(
                        thread_id,
                        thread_receiver,
                        volume,
                        sectors,
                        encryption_key,
                        sector_size,
                        background_state,
                    );
                })?;
            
            self.worker_threads.push(worker);
        }
        
        // Start encryption scheduler in separate thread
        let sender = self.task_sender.as_ref().unwrap().clone();
        let total_sectors = self.total_sectors;
        let header_sectors = self.header_sectors;
        let background_state = self.background_state.clone();
        let sectors_clone = self.sectors.clone();
        let sector_size = self.sector_size;
        
        // Start a separate thread for regular statistics output
        let bg_state = self.background_state.clone();
        
        // Add progress reporting thread back
        thread::spawn(move || {
            // Allow time for worker thread initialization
            thread::sleep(Duration::from_millis(100));
            
            println!("\nENCRYPTION PROGRESS:");
            println!("--------------------");
            std::io::stdout().flush().ok(); // Force output
            
            // Output encryption status frequently
            while bg_state.is_active() {
                let encrypted = bg_state.get_encrypted_sectors();
                let total = bg_state.get_total_sectors();
                let progress = if total > 0 { encrypted as f64 * 100.0 / total as f64 } else { 0.0 };
                let speed = bg_state.get_speed();
                
                println!("[ENCRYPTION] Progress: {:.2}% ({}/{} sectors) | Speed: {:.2} MB/sec", 
                         progress, encrypted, total, speed);
                std::io::stdout().flush().ok(); // Force output
                
                // Sleep shorter time for more frequent updates
                thread::sleep(Duration::from_millis(100));
            }
            
            println!("\nENCRYPTION COMPLETED");
            println!("===================");
            std::io::stdout().flush().ok(); // Force output
        });
        
        thread::spawn(move || {
            // Start encryption from beginning to end of volume
            let mut start_sector = header_sectors;
            let stats_time = Instant::now();
            let mut _sector_count = 0;
            let mut last_report_time = Instant::now();
            
            // Immediately output status
            println!("\nStarting encryption scheduler - processing {} sectors...", total_sectors);
            std::io::stdout().flush().ok(); // Force output immediately
            
            while start_sector < header_sectors + total_sectors {
                // Check if this range is already encrypted
                let is_already_encrypted = {
                    let sectors = sectors_clone.read().unwrap();
                    sectors.is_encrypted(start_sector)
                };
                
                if !is_already_encrypted {
                    // Send encryption task
                    let batch_count = min(SECTOR_BATCH_SIZE, (header_sectors + total_sectors - start_sector) as usize);
                    
                    // If background encryption is stopped, exit
                    if !background_state.is_active() {
                        break;
                    }
                    
                    if let Err(e) = sender.send(EncryptionTask::EncryptRange {
                        start_sector,
                        count: batch_count,
                    }) {
                        error!("Failed to send task: {}", e);
                        background_state.set_error(format!("Send error: {}", e));
                        break;
                    }
                    
                    // Output scheduler status occasionally
                    if _sector_count % (SECTOR_BATCH_SIZE * 10) == 0 {
                        println!("Scheduler: queued sectors {}-{} for encryption", 
                                start_sector, start_sector + batch_count as u64);
                        std::io::stdout().flush().ok(); // Force output
                    }
                    
                    _sector_count += batch_count;
                }
                
                // Move to next sector range
                start_sector += SECTOR_BATCH_SIZE as u64;
                
                // Update encryption statistics much more frequently (every 1 ms)
                let now = Instant::now();
                if now.duration_since(last_report_time) > Duration::from_millis(1) {
                    let elapsed = now.duration_since(stats_time).as_secs_f64();
                    let encrypted_sectors = background_state.get_encrypted_sectors();
                    
                    if elapsed > 0.0 {
                        let speed = (encrypted_sectors as f64 * sector_size as f64) / (1024.0 * 1024.0 * elapsed);
                        background_state.update_progress(encrypted_sectors, speed);
                    }
                    
                    last_report_time = now;
                }
                
                // Short pause, but even less than before
                thread::sleep(Duration::from_micros(100)); // 0.1ms sleep
            }
            
            info!("Encryption scheduler finished");
            println!("Encryption scheduler finished processing all sectors");
            std::io::stdout().flush().ok(); // Force output
            
            // After completing encryption of the entire volume, send shutdown signal to all workers
            let worker_count = background_state.get_encrypted_sectors(); // Use as temporary counter
            for _ in 0..worker_count {
                if let Err(e) = sender.send(EncryptionTask::Shutdown) {
                    error!("Failed to send shutdown signal: {}", e);
                }
            }
            
            // Mark that background encryption is complete
            background_state.active.store(false, Ordering::SeqCst);
        });
        
        Ok(())
    }
    
    /// Stops background encryption process
    pub fn stop_background_encryption(&mut self) -> Result<()> {
        if self.task_sender.is_none() {
            return Ok(());
        }
        
        info!("Stopping background encryption...");
        
        // Mark that background encryption should stop
        self.background_state.active.store(false, Ordering::SeqCst);
        
        // Send shutdown signal to all worker threads
        if let Some(sender) = &self.task_sender {
            for _ in 0..self.worker_threads.len() {
                if let Err(e) = sender.send(EncryptionTask::Shutdown) {
                    error!("Failed to send shutdown signal: {}", e);
                }
            }
        }
        
        // Wait for all worker threads to finish
        let mut remaining_threads = Vec::new();
        std::mem::swap(&mut self.worker_threads, &mut remaining_threads);
        
        for thread in remaining_threads {
            if let Err(e) = thread.join() {
                error!("Error waiting for worker thread: {:?}", e);
            }
        }
        
        // Close channel
        self.task_sender = None;
        
        info!("Background encryption stopped");
        
        Ok(())
    }
    
    /// Worker encryption thread
    fn encryption_worker(
        thread_id: usize,
        receiver: Receiver<EncryptionTask>,
        volume: Arc<RwLock<VolumeFile>>,
        sectors: Arc<RwLock<EncryptedSectors>>,
        encryption_key: [u8; crate::crypto::xts::XTS_KEY_SIZE],
        sector_size: u32,
        background_state: Arc<BackgroundEncryptionState>,
    ) {
        info!("Encryption worker #{} started", thread_id);
        println!("Encryption worker #{} started", thread_id);
        std::io::stdout().flush().ok(); // Force output

        for task in receiver {
            match task {
                EncryptionTask::EncryptRange { start_sector, count } => {
                    // Immediately update interface about starting encryption
                    println!("Worker #{}: starting encryption of sector {} (block size: {} sectors)", 
                           thread_id, start_sector, count);
                    std::io::stdout().flush().ok(); // Force output
                    
                    let result = (|| -> Result<()> {
                        // Check if encryption is stopped
                        if !background_state.is_active() {
                            return Ok(());
                        }
                        
                        // Determine if block is large enough for Direct I/O
                        let use_direct_io = count * sector_size as usize >= DIRECT_IO_ALIGNMENT;
                        
                        // Buffer for reading/writing
                        let buffer_size = count * sector_size as usize;
                        
                        // For Direct I/O, buffer needs to be page-aligned
                        let mut buffer = if use_direct_io {
                            // Allocate buffer with correct alignment for Direct I/O
                            // In simplest case, just make a buffer, although better to use
                            // specialized allocator for aligned memory
                            let aligned_size = (buffer_size + DIRECT_IO_ALIGNMENT - 1) & !(DIRECT_IO_ALIGNMENT - 1);
                            vec![0u8; aligned_size]
                        } else {
                            vec![0u8; buffer_size]
                        };
                        
                        // Read sectors
                        {
                            let mut volume_guard = volume.write().unwrap();
                            if use_direct_io {
                                // Use optimized reading for large blocks
                                debug!("Using optimized reading for block {} (size: {}KB)", 
                                       start_sector, buffer_size / 1024);
                            }
                            volume_guard.read_sectors(
                                start_sector,
                                count as u32,
                                sector_size,
                                &mut buffer[0..buffer_size],
                            )?;
                        }
                        
                        // Encrypt each sector (process blocks for better cache performance)
                        const CACHE_FRIENDLY_BATCH: usize = 16; // Optimization for CPU cache
                        
                        // Update progress more frequently
                        let update_frequency = CACHE_FRIENDLY_BATCH * 2;
                        let mut progress_counter = 0;
                        
                        for batch_idx in 0..(count + CACHE_FRIENDLY_BATCH - 1) / CACHE_FRIENDLY_BATCH {
                            let start_idx = batch_idx * CACHE_FRIENDLY_BATCH;
                            let end_idx = min(start_idx + CACHE_FRIENDLY_BATCH, count);
                            
                            for i in start_idx..end_idx {
                                let current_sector = start_sector + i as u64;
                                let offset = i * sector_size as usize;
                                let end_offset = min(offset + sector_size as usize, buffer.len());
                                
                                if offset < buffer_size && end_offset <= buffer_size {
                                    let sector_data = &mut buffer[offset..end_offset];
                                    encrypt_sector(sector_data, current_sector, &encryption_key)?;
                                }
                                
                                // Update progress counter
                                progress_counter += 1;
                                if progress_counter % update_frequency == 0 {
                                    // Output intermediate encryption progress
                                    let percent_complete = (progress_counter as f64 / count as f64) * 100.0;
                                    print!("\rWorker #{}: encrypting... {:.1}% completed", thread_id, percent_complete);
                                    std::io::stdout().flush().ok(); // Update output without newline
                                    
                                    // Update encryption status in real time
                                    let current_encrypted = background_state.get_encrypted_sectors();
                                    background_state.encrypted_sectors.store(current_encrypted + progress_counter, Ordering::Relaxed);
                                }
                            }
                        }
                        
                        // Write encrypted sectors back
                        {
                            let mut volume_guard = volume.write().unwrap();
                            if use_direct_io {
                                // Use optimized writing for large blocks
                                debug!("Using optimized writing for block {} (size: {}KB)", 
                                       start_sector, buffer_size / 1024);
                            }
                            volume_guard.write_sectors(start_sector, sector_size, &buffer[0..buffer_size])?;
                        }
                        
                        // Mark sectors as encrypted
                        {
                            let mut sectors_guard = sectors.write().unwrap();
                            sectors_guard.mark_range_encrypted(start_sector, count as u64);
                        }
                        
                        // Update encrypted sectors counter
                        let current = background_state.encrypted_sectors.fetch_add(count, Ordering::Relaxed);
                        if current % 5000 == 0 {
                            debug!("Encrypted {} sectors", current + count);
                        }
                        
                        Ok(())
                    })();
                    
                    if let Err(e) = result {
                        error!("Encryption error for sector range {}-{}: {}", 
                               start_sector, start_sector + count as u64, e);
                        background_state.set_error(e.to_string());
                    }
                }
                EncryptionTask::Shutdown => {
                    info!("Encryption worker #{} received shutdown command", thread_id);
                    break;
                }
            }
        }
        
        info!("Encryption worker #{} finished", thread_id);
    }

    /// Performs fast encryption of the volume
    /// This function only prepares the volume for encryption without encrypting all data
    pub fn fast_encrypt(&mut self) -> Result<()> {
        info!("Fast encryption initiated");
        println!("Fast encryption initiated");
        std::io::stdout().flush().ok(); // Force output
        
        // 1. Prepare volume header
        info!("Preparing volume header...");
        println!("Preparing volume header...");
        std::io::stdout().flush().ok(); // Force output
        {
            let mut volume = self.volume.write().unwrap();
            self.header.write_to_volume(&mut *volume)?;
        }
        
        // 2. Encrypt first and last few megabytes of volume for quick access
        let priority_sectors = 2048; // ~8 MB at 4 KB sector size
        
        // Encrypt volume beginning (right after header)
        info!("Encrypting initial volume sectors...");
        println!("Encrypting initial volume sectors...");
        std::io::stdout().flush().ok(); // Force output
        let start_sectors = self.encrypt_sector_range(self.header_sectors, priority_sectors as u32)?;
        
        // Encrypt volume end, if it exists
        if self.total_sectors > priority_sectors as u64 * 2 {
            info!("Encrypting final volume sectors...");
            println!("Encrypting final volume sectors...");
            std::io::stdout().flush().ok(); // Force output
            let end_start = self.header_sectors + self.total_sectors - priority_sectors as u64;
            let end_sectors = self.encrypt_sector_range(end_start, priority_sectors as u32)?;
            
            info!("Fast encryption completed. Encrypted {} + {} sectors.", 
                  start_sectors, end_sectors);
            println!("Fast encryption completed. Encrypted {} + {} sectors.", 
                  start_sectors, end_sectors);
            std::io::stdout().flush().ok(); // Force output
        } else {
            info!("Fast encryption completed. Encrypted {} sectors.", start_sectors);
            println!("Fast encryption completed. Encrypted {} sectors.", start_sectors);
            std::io::stdout().flush().ok(); // Force output
        }
        
        // 3. Start background encryption of remaining data
        info!("Starting background encryption of remaining data...");
        println!("Starting background encryption of remaining data...");
        std::io::stdout().flush().ok(); // Force output
        
        // Start background encryption with very frequent status output (5 ms)
        self.start_background_encryption_with_status(None, 5)?;
        
        Ok(())
    }

    /// Encrypts specific sector range
    /// Useful for background encryption
    pub fn encrypt_sector_range(&mut self, start_sector: u64, num_sectors: u32) -> Result<u64> {
        // Check boundaries
        if start_sector < self.header_sectors {
            return Err(anyhow!("Cannot encrypt header sectors"));
        }
        
        if start_sector + num_sectors as u64 > self.header_sectors + self.total_sectors {
            return Err(anyhow!("Sector index out of bounds"));
        }
        
        // Buffer size for reading/writing
        let sector_size = self.sector_size as usize;
        let buffer_size = std::cmp::min(
            num_sectors as usize * sector_size,
            BUFFER_SIZE - (BUFFER_SIZE % sector_size) // Align to sector boundary
        );
        
        // Number of sectors to process at once
        let sectors_per_buffer = buffer_size / sector_size;
        let buffer_iterations = (num_sectors as usize + sectors_per_buffer - 1) / sectors_per_buffer;
        
        // Buffer for reading/writing
        let mut buffer = vec![0u8; buffer_size];
        
        // Track progress
        let mut processed_sectors = 0;
        let start_time = std::time::Instant::now();
        let mut last_progress_time = start_time;
        
        for i in 0..buffer_iterations {
            // Calculate current sector range
            let current_start = start_sector + i as u64 * sectors_per_buffer as u64;
            let sectors_this_iteration = std::cmp::min(
                sectors_per_buffer as u32,
                num_sectors - i as u32 * sectors_per_buffer as u32
            );
            
            if sectors_this_iteration == 0 {
                break;
            }
            
            // Data size in current iteration
            let data_size = sectors_this_iteration as usize * sector_size;
            
            // Read data from device
            {
                let mut volume_guard = self.volume.write().unwrap();
                volume_guard.read_sectors(current_start, sectors_this_iteration, self.sector_size, &mut buffer[0..data_size])?;
            }
            
            // Encrypt each sector
            for j in 0..sectors_this_iteration as usize {
                let current_sector = current_start + j as u64;
                let offset = j * sector_size;
                let sector_data = &mut buffer[offset..offset + sector_size];
                
                // Use AES-XTS for encryption
                encrypt_sector(sector_data, current_sector, &self.encryption_key)?;
            }
            
            // Write encrypted data back to device
            {
                let mut volume_guard = self.volume.write().unwrap();
                volume_guard.write_sectors(current_start, self.sector_size, &buffer[0..data_size])?;
            }
            
            // Mark sectors as encrypted
            {
                let mut sectors_guard = self.sectors.write().unwrap();
                sectors_guard.mark_range_encrypted(current_start, sectors_this_iteration as u64);
            }
            
            // Update progress
            processed_sectors += sectors_this_iteration as u64;
            let now = std::time::Instant::now();
            
            // Output progress every 100ms
            if now.duration_since(last_progress_time).as_millis() >= 100 {
                let progress = processed_sectors as f64 / num_sectors as f64 * 100.0;
                let elapsed = now.duration_since(start_time).as_secs_f64();
                let speed_mb_sec = if elapsed > 0.0 {
                    (processed_sectors as f64 * sector_size as f64 / 1_048_576.0) / elapsed
                } else {
                    0.0
                };
                
                // Estimate remaining time
                let remaining_sectors = num_sectors as u64 - processed_sectors;
                let remaining_secs = if speed_mb_sec > 0.0 {
                    (remaining_sectors as f64 * sector_size as f64 / 1_048_576.0) / speed_mb_sec
                } else {
                    0.0
                };
                
                // Format remaining time
                let remaining_fmt = if remaining_secs > 60.0 * 60.0 {
                    format!("{:.1} hours", remaining_secs / 3600.0)
                } else if remaining_secs > 60.0 {
                    format!("{:.1} minutes", remaining_secs / 60.0)
                } else {
                    format!("{:.1} seconds", remaining_secs)
                };
                
                info!("Encryption range: {:.3}% - Speed: {:.2} MB/sec - Remaining: {}", 
                      progress, speed_mb_sec, remaining_fmt);
                
                last_progress_time = now;
            }
        }
        
        let total_time = start_time.elapsed().as_secs_f64();
        info!("Encryption range completed in {:.1} seconds", total_time);
        
        Ok(processed_sectors as u64)
    }
    
    /// Returns total number of sectors in volume (excluding header)
    pub fn get_total_sectors(&self) -> u64 {
        self.total_sectors
    }
    
    /// Returns sector size
    pub fn get_sector_size(&self) -> u32 {
        self.sector_size
    }
    
    /// Returns number of header sectors
    pub fn get_header_sectors(&self) -> u64 {
        self.header_sectors
    }
    
    /// Checks if specified sector is encrypted
    pub fn is_sector_encrypted(&self, sector_index: u64) -> bool {
        let sectors_guard = self.sectors.read().unwrap();
        sectors_guard.is_encrypted(sector_index)
    }
    
    /// Returns total number of encrypted sectors
    pub fn get_encrypted_sectors_count(&self) -> usize {
        let sectors_guard = self.sectors.read().unwrap();
        sectors_guard.encrypted.len()
    }
    
    /// Returns encryption percentage
    pub fn get_encryption_percentage(&self) -> f64 {
        let encrypted_count = self.get_encrypted_sectors_count() as f64;
        let total = self.total_sectors as f64;
        
        if total > 0.0 {
            encrypted_count / total * 100.0
        } else {
            0.0
        }
    }

    pub fn encrypt_sector(&mut self, sector_index: u64) -> Result<()> {
        // Check if sector is already encrypted
        if self.is_sector_encrypted(sector_index) {
            return Ok(());
        }

        // Get sector data from the volume
        let sector_size = self.sector_size as usize;
        let mut buffer = vec![0u8; sector_size];
        let mut encrypted_data = vec![0u8; sector_size];
        
        // Read the sector data
        {
            let mut volume = self.volume.write().unwrap();
            if let Err(e) = volume.read_sectors(sector_index, 1, self.sector_size, &mut buffer) {
                return Err(anyhow!("Failed to read sector {}: {}", sector_index, e));
            }
        }
        
        // Copy data for encryption
        encrypted_data.copy_from_slice(&buffer);
        
        // Encrypt the data
        if let Err(e) = xts::encrypt_sector(&mut encrypted_data, sector_index, &self.encryption_key) {
            return Err(anyhow!("Failed to encrypt sector {}: {}", sector_index, e));
        }

        // Write back the encrypted data
        {
            let mut volume = self.volume.write().unwrap();
            if let Err(e) = volume.write_sectors(sector_index, self.sector_size, &encrypted_data) {
                return Err(anyhow!("Failed to write encrypted sector {}: {}", sector_index, e));
            }
        }
        
        // Mark sector as encrypted
        {
            let mut sectors = self.sectors.write().unwrap();
            sectors.mark_encrypted(sector_index);
        }
        
        Ok(())
    }

    pub fn flush_metadata(&mut self) -> Result<()> {
        // Update header with encryption status
        let header_bytes = self.header.serialize()?;
        
        // Write the updated header to the volume
        let mut volume = self.volume.write().unwrap();
        volume.write_sectors(0, self.sector_size, &header_bytes)?;
        
        // Flush any other metadata that needs to be written
        
        Ok(())
    }

    /// Outputs current encryption status to console
    pub fn print_encryption_status(&self) {
        println!("\n--- Encryption status ---");
        
        if self.background_state.is_active() {
            println!("{}", self.background_state.get_status_report());
            
            if let Some(error) = self.background_state.get_last_error() {
                println!("Last error: {}", error);
            }
        } else {
            let percent = self.get_encryption_percentage();
            let encrypted = self.get_encrypted_sectors_count();
            let total = self.total_sectors;
            
            println!(
                "Background encryption is not active.\nEncrypted: {:.2}% ({}/{} sectors)",
                percent, encrypted, total
            );
        }
        
        println!("------------------------\n");
    }
    
    /// Starts background encryption process with periodic status display
    pub fn start_background_encryption_with_status(&mut self, thread_count: Option<usize>, status_interval_ms: u64) -> Result<()> {
        // Start encryption as usual
        self.start_background_encryption(thread_count)?;
        
        // Start separate thread for status output
        let background_state = self.background_state.clone();
        
        // Immediately output first status message
        println!("\n--- Starting encryption ---");
        println!("{}", background_state.get_status_report());
        println!("------------------------\n");
        std::io::stdout().flush().ok(); // Force output to display immediately
        
        thread::spawn(move || {
            println!("Started encryption monitoring. Update interval: {} ms", status_interval_ms);
            std::io::stdout().flush().ok(); // Force output to display immediately
            
            // Reduce interval to 30 ms for maximum responsiveness
            let actual_interval = 30;
            
            while background_state.is_active() {
                println!("\n--- Encryption status ---");
                println!("{}", background_state.get_status_report());
                
                if let Some(error) = background_state.get_last_error() {
                    println!("Last error: {}", error);
                }
                
                println!("------------------------\n");
                std::io::stdout().flush().ok(); // Force output to display immediately
                
                thread::sleep(Duration::from_millis(actual_interval));
            }
            
            println!("Encryption monitoring completed.");
            std::io::stdout().flush().ok(); // Force output to display immediately
        });
        
        Ok(())
    }
} 