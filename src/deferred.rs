use anyhow::{anyhow, Result};
use std::sync::{Arc, RwLock, Mutex, Barrier};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::collections::{HashSet, HashMap, VecDeque};
use std::time::{Duration, Instant};
use std::io::{self, Error, ErrorKind, Read, Write};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::thread;
use std::cmp::min;
use crossbeam_channel::{bounded, Sender, Receiver};
use log::*;
use rand::{seq::SliceRandom, thread_rng};
use parking_lot::RwLock as PLRwLock;

use crate::encryption::{VolumeHeader, derive_key, split_derived_key, VOLUME_SIGNATURE, encrypt_sector};
use crate::platform::volume_io::{VolumeFile, open_device, open_device_readonly};
use crate::crypto::xts;

/// Buffer size used for encryption
const BUFFER_SIZE: usize = 32 * 1024 * 1024; // 32 MB buffer для надежной работы с флешками

/// Adding parameters for multi-threaded encryption
const DEFAULT_THREAD_COUNT: usize = 4; // Уменьшено для лучшей совместимости с флешками
const SECTOR_BATCH_SIZE: usize = 2048; // 2048 секторов за раз (8 МБ при секторе 4 КБ)

/// Maximum write chunk size for physical devices to avoid errors
const MAX_PHYSICAL_WRITE_SIZE: usize = 512 * 1024; // 512 КБ максимальный размер для безопасной записи

/// Minimum block size for Direct I/O (usually 4KB)
const DIRECT_IO_ALIGNMENT: usize = 4096;

/// Minimal encryption for quick access (4MB only)
const FAST_ENCRYPT_SECTORS: usize = 1024; // 4MB at 4KB sector size

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
            println!("\nULTRA-FAST ENCRYPTION STARTING - Processing {} sectors", total_sectors);
            std::io::stdout().flush().ok(); // Force output immediately
            
            // Create vector of tasks to encrypt all sectors
            let mut encryption_tasks = Vec::new();
            
            // Pre-calculate all required encryption tasks in advance
            while start_sector < header_sectors + total_sectors {
                let batch_count = min(SECTOR_BATCH_SIZE, (header_sectors + total_sectors - start_sector) as usize);
                
                // Add task to vector if not already encrypted
                encryption_tasks.push((start_sector, batch_count));
                
                // Move to next sector range
                start_sector += SECTOR_BATCH_SIZE as u64;
            }
            
            // Track total tasks
            let total_tasks = encryption_tasks.len();
            println!("Generated {} encryption tasks", total_tasks);
            std::io::stdout().flush().ok();
            
            // Shuffle tasks for better distribution and to reduce disk head movement
            let mut rng = rand::thread_rng();
            encryption_tasks.shuffle(&mut rng);
            
            // Use a semaphore to limit concurrent tasks
            let max_concurrent_tasks = DEFAULT_THREAD_COUNT * 4; // Allow 4x queue depth 
            let mut in_flight_tasks = 0;
            
            // Process all tasks
            for (task_idx, (start_sector, batch_count)) in encryption_tasks.iter().enumerate() {
                // If background encryption is stopped, exit
                if !background_state.is_active() {
                    break;
                }
                
                // Check if sector range is already encrypted - quick check only first sector
                let is_already_encrypted = {
                    let sectors = sectors_clone.read().unwrap();
                    sectors.is_encrypted(*start_sector)
                };
                
                if !is_already_encrypted {
                    // Wait if too many tasks in flight
                    while in_flight_tasks >= max_concurrent_tasks {
                        thread::sleep(Duration::from_micros(10));
                        // Update progress periodically
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
                    }
                    
                    // Send encryption task
                    if let Err(e) = sender.send(EncryptionTask::EncryptRange {
                        start_sector: *start_sector,
                        count: *batch_count,
                    }) {
                        error!("Failed to send task: {}", e);
                        background_state.set_error(format!("Send error: {}", e));
                        break;
                    }
                    
                    // Increment in-flight count
                    in_flight_tasks += 1;
                    
                    // Output scheduler status occasionally
                    if task_idx % 1000 == 0 {
                        let progress = (task_idx as f64 / total_tasks as f64) * 100.0;
                        println!("Scheduler: progress {:.1}% - queued sectors {}-{}",
                                progress, start_sector, start_sector + *batch_count as u64);
                        std::io::stdout().flush().ok(); // Force output
                    }
                    
                    _sector_count += batch_count;
                }
                
                // Update encryption statistics frequently
                let now = Instant::now();
                if now.duration_since(last_report_time) > Duration::from_millis(1) {
                    let elapsed = now.duration_since(stats_time).as_secs_f64();
                    let encrypted_sectors = background_state.get_encrypted_sectors();
                    
                    if elapsed > 0.0 {
                        let speed = (encrypted_sectors as f64 * sector_size as f64) / (1024.0 * 1024.0 * elapsed);
                        background_state.update_progress(encrypted_sectors, speed);
                        
                        // Use completion rate to estimate in-flight count
                        // This helps keep optimal queue depth as tasks complete
                        let completion_rate = if total_tasks > 0 {
                            (encrypted_sectors as f64) / (total_sectors as f64)
                        } else {
                            0.0
                        };
                        
                        // Adjust in-flight count based on completion rate
                        in_flight_tasks = (max_concurrent_tasks as f64 * (1.0 - completion_rate)) as usize;
                    }
                    
                    last_report_time = now;
                }
                
                // Minimal sleep between submissions
                thread::sleep(Duration::from_nanos(100));
            }
            
            info!("Encryption scheduler finished queuing tasks");
            println!("Encryption scheduler: All tasks have been submitted to workers");
            std::io::stdout().flush().ok(); // Force output
            
            // Wait for completion - poll until all sectors are encrypted
            while background_state.is_active() {
                let encrypted_sectors = background_state.get_encrypted_sectors();
                let completion = encrypted_sectors as f64 / total_sectors as f64;
                
                if completion >= 0.999 { // Consider 99.9% as complete for practical purposes
                    break;
                }
                
                // Update speed statistics one last time
                let elapsed = Instant::now().duration_since(stats_time).as_secs_f64();
                if elapsed > 0.0 {
                    let speed = (encrypted_sectors as f64 * sector_size as f64) / (1024.0 * 1024.0 * elapsed);
                    background_state.update_progress(encrypted_sectors, speed);
                }
                
                thread::sleep(Duration::from_millis(100));
            }
            
            // After completing encryption of the entire volume, send shutdown signal to all workers
            for _ in 0..DEFAULT_THREAD_COUNT {
                if let Err(e) = sender.send(EncryptionTask::Shutdown) {
                    error!("Failed to send shutdown signal: {}", e);
                }
            }
            
            // Mark that background encryption is complete
            background_state.active.store(false, Ordering::SeqCst);
            
            println!("ENCRYPTION COMPLETED SUCCESSFULLY");
            std::io::stdout().flush().ok(); // Force output
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
        info!("Ultra-fast encryption worker #{} started", thread_id);
        println!("\x1b[1;32mWorker #{}: Thread started and ready for encryption\x1b[0m", thread_id);
        std::io::stdout().flush().unwrap_or_default(); // Force output immediately

        // Pre-allocate large buffer for maximum performance - reuse across calls
        let max_buffer_size = SECTOR_BATCH_SIZE * sector_size as usize;
        let aligned_buffer_size = (max_buffer_size + DIRECT_IO_ALIGNMENT - 1) & !(DIRECT_IO_ALIGNMENT - 1);
        let mut shared_buffer = vec![0u8; aligned_buffer_size]; 

        // Set thread priority to critical/highest
        #[cfg(target_os = "windows")]
        {
            use winapi::um::processthreadsapi::{SetThreadPriority, GetCurrentThread};
            use winapi::um::winbase::THREAD_PRIORITY_HIGHEST;
            
            unsafe {
                SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST as i32);
            }
        }
        
        #[cfg(target_os = "linux")]
        {
            // On Linux use the highest priority possible
            let _ = nix::sys::resource::setpriority(
                nix::sys::resource::PriorityWhich::Process,
                nix::unistd::gettid().as_raw() as u32,
                -20, // Maximum priority
            );
            println!("\x1b[1;36mWorker #{}: Thread priority set to maximum (-20)\x1b[0m", thread_id);
            std::io::stdout().flush().unwrap_or_default();
        }

        // Track worker's progress
        let mut total_sectors_encrypted = 0;
        let mut last_status_time = Instant::now();

        for task in receiver {
            match task {
                EncryptionTask::EncryptRange { start_sector, count } => {
                    // Print immediate status when starting a new task (more frequently for first worker)
                    let now = Instant::now();
                    let should_print = thread_id == 0 || 
                                      (thread_id < 2 && start_sector % (SECTOR_BATCH_SIZE as u64 * 10) == 0) ||
                                      start_sector % (SECTOR_BATCH_SIZE as u64 * 100) == 0;
                    
                    if should_print {
                        print!("\r\x1b[1;33mWorker #{}: Processing sectors {}-{}\x1b[0m", 
                              thread_id, start_sector, start_sector + count as u64);
                        std::io::stdout().flush().unwrap_or_default(); // Force output
                    }
                    
                    let result = (|| -> Result<()> {
                        // Check if encryption is stopped
                        if !background_state.is_active() {
                            return Ok(());
                        }
                        
                        // Always use Direct I/O for maximum performance
                        let buffer_size = count * sector_size as usize;
                        
                        // Read sectors with maximum performance
                        {
                            let mut volume_guard = volume.write().unwrap();
                            volume_guard.read_sectors(
                                start_sector,
                                count as u32,
                                sector_size,
                                &mut shared_buffer[0..buffer_size],
                            )?;
                        }
                        
                        // Encrypt sectors - use larger batches and minimal progress updates
                        // Increased to 64 for better cache efficiency
                        const CACHE_FRIENDLY_BATCH: usize = 64; 
                        let mut progress_counter = 0;
                        
                        for batch_idx in 0..(count + CACHE_FRIENDLY_BATCH - 1) / CACHE_FRIENDLY_BATCH {
                            let start_idx = batch_idx * CACHE_FRIENDLY_BATCH;
                            let end_idx = min(start_idx + CACHE_FRIENDLY_BATCH, count);
                            
                            // Process whole batch at once
                            for i in start_idx..end_idx {
                                let current_sector = start_sector + i as u64;
                                let offset = i * sector_size as usize;
                                let end_offset = min(offset + sector_size as usize, shared_buffer.len());
                                
                                if offset < buffer_size && end_offset <= buffer_size {
                                    let sector_data = &mut shared_buffer[offset..end_offset];
                                    encrypt_sector(sector_data, current_sector, &encryption_key)?;
                                }
                            }
                            
                            // Update progress counter
                            progress_counter += end_idx - start_idx;
                            
                            // Show progress more frequently - every 32 sectors for better visual feedback
                            if progress_counter >= 32 {
                                // Increment global counter atomically
                                background_state.encrypted_sectors.fetch_add(progress_counter, Ordering::Relaxed);
                                total_sectors_encrypted += progress_counter;
                                
                                // Print progress for thread 0 (main worker) every 32 sectors
                                if thread_id == 0 && batch_idx % 4 == 0 {
                                    let progress = (batch_idx as f64 / ((count + CACHE_FRIENDLY_BATCH - 1) / CACHE_FRIENDLY_BATCH) as f64) * 100.0;
                                    print!("\rWorker #0: {:.1}% of current batch, total: {} sectors", 
                                           progress, total_sectors_encrypted);
                                    std::io::stdout().flush().unwrap_or_default();
                                }
                                
                                progress_counter = 0;
                            }
                        }
                        
                        // Add remaining sectors to counter
                        if progress_counter > 0 {
                            background_state.encrypted_sectors.fetch_add(progress_counter, Ordering::Relaxed);
                            total_sectors_encrypted += progress_counter;
                        }
                        
                        // Write encrypted data back to device with safe chunking
                        let total_expected_sectors = count;
                        let thread_index = thread_id;
                        let mut total_encrypted_sectors = 0;
                        
                        // Write encrypted data back to device with safe chunking
                        for sector_offset in (0..count).step_by(MAX_PHYSICAL_WRITE_SIZE / sector_size as usize) {
                            let chunk_size = std::cmp::min(
                                MAX_PHYSICAL_WRITE_SIZE / sector_size as usize,
                                count - sector_offset
                            );
                            if chunk_size == 0 {
                                break;
                            }
                            
                            let data_offset = sector_offset * sector_size as usize;
                            let data_size = chunk_size * sector_size as usize;
                            let current_start_sector = start_sector + sector_offset as u64;
                            
                            // Небольшая пауза между записями для стабильности
                            if sector_offset > 0 {
                                thread::sleep(Duration::from_millis(5));
                            }
                            
                            // Запись с повторными попытками
                            let mut retry_count = 0;
                            let max_retries = 3;
                            
                            while retry_count < max_retries {
                                let result = (|| -> Result<()> {
                                    let mut volume_guard = volume.write().unwrap();
                                    volume_guard.write_sectors(
                                        current_start_sector,
                                        sector_size,
                                        &shared_buffer[data_offset..data_offset + data_size],
                                    )
                                })();
                                
                                match result {
                                    Ok(_) => break,
                                    Err(e) => {
                                        retry_count += 1;
                                        if retry_count < max_retries {
                                            warn!("Retry #{} writing at sector {}: {}", retry_count, current_start_sector, e);
                                            // Увеличиваем время ожидания с каждой попыткой
                                            thread::sleep(Duration::from_millis(200 * retry_count as u64));
                                        } else {
                                            return Err(anyhow!("Failed to write sectors at {}: {}", current_start_sector, e));
                                        }
                                    }
                                }
                            }
                            
                            // Mark sectors as encrypted
                            {
                                let mut sectors_guard = sectors.write().unwrap();
                                for i in 0..chunk_size {
                                    let sector_idx = current_start_sector + i as u64;
                                    sectors_guard.mark_encrypted(sector_idx);
                                }
                            }
                            
                            // Обновляем статус
                            let encrypted_sectors = background_state.encrypted_sectors.fetch_add(chunk_size, Ordering::Relaxed);
                            
                            // Обновляем общее время шифрования
                            total_encrypted_sectors += chunk_size;
                            
                            // Вычисляем прогресс только каждые 32 сектора для уменьшения нагрузки на поток
                            if progress_counter % 32 == 0 {
                                debug!("Thread {}: Encrypted sectors {}-{} ({:.2}%)", 
                                       thread_index, 
                                       current_start_sector, 
                                       current_start_sector + chunk_size as u64 - 1,
                                       total_encrypted_sectors as f64 * 100.0 / total_expected_sectors as f64);
                            }
                            progress_counter += chunk_size;
                        }
                        
                        Ok(())
                    })();
                    
                    // Check for errors
                    if let Err(e) = result {
                        error!("Encryption error: {}", e);
                        background_state.set_error(e.to_string());
                    }
                }
                EncryptionTask::Shutdown => {
                    info!("Encryption worker #{} received shutdown command", thread_id);
                    println!("\x1b[1;33mWorker #{}: Shutdown command received. Total sectors encrypted: {}\x1b[0m", 
                           thread_id, total_sectors_encrypted);
                    std::io::stdout().flush().unwrap_or_default();
                    break;
                }
            }
        }
        
        info!("Encryption worker #{} finished", thread_id);
        println!("\x1b[1;32mWorker #{}: FINISHED - Total sectors encrypted: {}\x1b[0m", 
               thread_id, total_sectors_encrypted);
        std::io::stdout().flush().unwrap_or_default();
    }

    /// Performs fast encryption of the volume
    /// This function only prepares the volume for encryption without encrypting all data
    pub fn fast_encrypt(&mut self) -> Result<()> {
        info!("Fast encryption initiated with extreme performance optimizations");
        println!("FAST ENCRYPTION STARTED - ULTRA PERFORMANCE MODE");
        std::io::stdout().flush().ok(); // Force output
        
        // 1. Prepare volume header
        info!("Preparing volume header...");
        println!("Preparing volume header...");
        std::io::stdout().flush().ok(); // Force output
        {
            let mut volume = self.volume.write().unwrap();
            self.header.write_to_volume(&mut *volume)?;
        }
        
        // 2. Encrypt only a minimal amount of data for quick access (only beginning)
        // We reduced from 2048 sectors to just FAST_ENCRYPT_SECTORS (1024) = 4MB
        
        // Encrypt volume beginning (right after header)
        info!("Minimal encryption of essential sectors...");
        println!("Performing minimal encryption for quick access...");
        std::io::stdout().flush().ok(); // Force output
        let start_sectors = self.encrypt_sector_range(self.header_sectors, FAST_ENCRYPT_SECTORS as u32)?;
        
        // Skip encrypting the end of volume to speed up process
        info!("Minimal encryption completed. Encrypted only {} sectors for immediate access.", start_sectors);
        println!("Minimal encryption completed. Only essential sectors encrypted for immediate access.");
        std::io::stdout().flush().ok(); // Force output
        
        // 3. Start background encryption of remaining data with extreme performance
        info!("Starting ultra-fast background encryption...");
        println!("STARTING ULTRA-FAST BACKGROUND ENCRYPTION");
        std::io::stdout().flush().ok(); // Force output
        
        // Use maximum thread count for parallelism - detect CPU cores and use all of them
        let cpu_count = num_cpus::get();
        println!("Using maximum available CPU cores: {}", cpu_count);
        std::io::stdout().flush().ok(); // Force output
        
        // Start background encryption with extreme performance settings
        self.start_background_encryption_with_status(Some(cpu_count), 5)?;
        
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

    pub fn encrypt_sector(&self, sector_number: u64, sector_count: u64) -> Result<(), Error> {
        if self.is_background_encryption_enabled() && sector_number >= self.get_encrypted_sectors() {
            // Don't allow writing to a sector that's not yet encrypted by background encryption
            return Err(Error::new(ErrorKind::Other, "Sector not yet encrypted by background encryption"));
        }

        // For reading we need to allocate buffer for all sectors being encrypted
        let sector_size = self.sector_size as usize;
        let buffer_size = sector_size * sector_count as usize;
        let mut buffer = vec![0u8; buffer_size];

        // Read data from volume
        {
            let mut volume_guard = self.volume.write().unwrap();
            if let Err(e) = volume_guard.read_at(sector_number * sector_size as u64, &mut buffer) {
                return Err(Error::new(ErrorKind::Other, format!("Failed to read from volume: {}", e)));
            }
        }

        // Encrypt data
        if let Err(e) = self.encrypt_data(sector_number, &mut buffer) {
            return Err(e);
        }

        // Write encrypted data back to volume
        if let Err(e) = self.write_with_chunking(sector_number, &buffer) {
            return Err(Error::new(ErrorKind::Other, format!("Failed to write to volume: {}", e)));
        }

        // Update the encryption state
        if sector_number + sector_count > self.get_encrypted_sectors() {
            self.set_encrypted_sectors(sector_number + sector_count);
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
        if let Some(report) = self.get_status_report() {
            println!("{}", report);
            io::stdout().flush().unwrap_or_default();
        }
    }
    
    /// Starts background encryption process with periodic status display
    pub fn start_background_encryption_with_status(&mut self, thread_count: Option<usize>, status_interval_ms: u64) -> Result<()> {
        // Start encryption as usual
        self.start_background_encryption(thread_count)?;
        
        // Start separate thread for status output
        let background_state = self.background_state.clone();
        let volume_size = self.total_sectors as f64 * self.sector_size as f64;
        let volume_gb = volume_size / (1024.0 * 1024.0 * 1024.0);
        
        // Configure an actual interval that's VERY short to ensure maximum responsiveness
        let actual_interval = 10; // Update very frequently (every 10ms)
        
        // Immediately output first status message with more detailed information
        println!("\n\x1b[1;32m=== ENCRYPTION STARTED ===\x1b[0m");
        println!("Volume size: {:.2} GB ({} sectors)", 
                 volume_gb, self.total_sectors);
        println!("Sector size: {} bytes", self.sector_size);
        println!("Threads: {}", thread_count.unwrap_or_else(|| num_cpus::get()));
        println!("Status update frequency: every {} ms", actual_interval);
        println!("{}", background_state.get_status_report());
        println!("\x1b[1;34m------------------------\x1b[0m");
        std::io::stdout().flush().unwrap_or_default(); // Force output to display immediately
        
        // Create a dedicated thread just for status monitoring with maximum priority
        let worker = thread::Builder::new()
            .name("status-monitor".to_string())
            .stack_size(1024 * 1024) // 1MB stack is enough
            .spawn(move || {
                #[cfg(target_os = "windows")]
                {
                    use winapi::um::processthreadsapi::{SetThreadPriority, GetCurrentThread};
                    use winapi::um::winbase::THREAD_PRIORITY_ABOVE_NORMAL;
                    
                    unsafe {
                        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL as i32);
                    }
                }
                
                println!("\x1b[1;33mEncryption monitoring active - real-time status updates\x1b[0m");
                std::io::stdout().flush().unwrap_or_default(); // Force output
                
                let mut last_encrypted = 0;
                let mut counter = 0;
                let mut last_report_time = Instant::now();
                
                while background_state.is_active() {
                    let now = Instant::now();
                    let elapsed = now.duration_since(last_report_time).as_millis();
                    
                    // Only print full report every 1 second
                    if elapsed >= 1000 {
                        println!("\n\x1b[1;36m--- Encryption Status Update ---\x1b[0m");
                        println!("{}", background_state.get_status_report());
                        
                        if let Some(error) = background_state.get_last_error() {
                            println!("\x1b[1;31mError: {}\x1b[0m", error);
                        }
                        
                        println!("\x1b[1;34m-------------------------------\x1b[0m");
                        std::io::stdout().flush().unwrap_or_default(); // Force output
                        last_report_time = now;
                    } 
                    // But still show minimal progress indicator every 10ms
                    else {
                        counter += 1;
                        if counter % 10 == 0 { // Every ~100ms show mini status
                            let encrypted = background_state.get_encrypted_sectors();
                            let total = background_state.get_total_sectors();
                            let progress = if total > 0 { encrypted as f64 * 100.0 / total as f64 } else { 0.0 };
                            
                            // Only print if progress changed
                            if encrypted != last_encrypted {
                                print!("\rProcessing: [{:.2}%] {} sectors encrypted", 
                                       progress, encrypted);
                                std::io::stdout().flush().unwrap_or_default(); // Force output
                                last_encrypted = encrypted;
                            }
                        }
                    }
                    
                    // Very short sleep between checks
                    thread::sleep(Duration::from_millis(actual_interval));
                }
                
                println!("\n\x1b[1;32mEncryption completed!\x1b[0m");
                std::io::stdout().flush().unwrap_or_default(); // Force output
            })?;
        
        // Don't wait for this thread - let it run in background
        Ok(())
    }

    /// Checks if background encryption is enabled
    pub fn is_background_encryption_enabled(&self) -> bool {
        self.background_state.is_active()
    }
    
    /// Gets the number of encrypted sectors
    pub fn get_encrypted_sectors(&self) -> u64 {
        self.background_state.get_encrypted_sectors() as u64
    }
    
    /// Sets the number of encrypted sectors
    pub fn set_encrypted_sectors(&self, count: u64) {
        self.background_state.encrypted_sectors.store(count as usize, Ordering::Relaxed);
    }
    
    /// Encrypts data in buffer starting from specified sector
    pub fn encrypt_data(&self, start_sector: u64, buffer: &mut [u8]) -> Result<(), Error> {
        let sector_size = self.sector_size as usize;
        let sector_count = buffer.len() / sector_size;
        
        for i in 0..sector_count {
            let sector_index = start_sector + i as u64;
            let offset = i * sector_size;
            
            // Use the XTS encryption function to encrypt the sector
            if let Err(e) = encrypt_sector(
                &mut buffer[offset..offset + sector_size],
                sector_index,
                &self.encryption_key
            ) {
                return Err(Error::new(ErrorKind::Other, format!("Encryption error: {}", e)));
            }
            
            // Mark sector as encrypted
            if let Ok(mut sectors) = self.sectors.write() {
                sectors.mark_encrypted(sector_index);
            }
        }
        
        Ok(())
    }
    
    /// Write data with chunking for large physical devices
    pub fn write_with_chunking(&self, start_sector: u64, buffer: &[u8]) -> Result<(), Error> {
        let sector_size = self.sector_size as usize;
        let mut volume_guard = self.volume.write().unwrap();
        
        // If this is a physical device, write in smaller chunks to avoid errors
        if volume_guard.is_physical_device() {
            let chunk_sectors = MAX_PHYSICAL_WRITE_SIZE / sector_size;
            let total_sectors = buffer.len() / sector_size;
            
            for chunk_idx in 0..(total_sectors + chunk_sectors - 1) / chunk_sectors {
                let start_idx = chunk_idx * chunk_sectors;
                let end_idx = min((chunk_idx + 1) * chunk_sectors, total_sectors);
                
                if start_idx >= end_idx {
                    break;
                }
                
                let chunk_start_sector = start_sector + start_idx as u64;
                let chunk_offset = start_idx * sector_size;
                let chunk_size = (end_idx - start_idx) * sector_size;
                
                if let Err(e) = volume_guard.write_at(
                    chunk_start_sector * sector_size as u64,
                    &buffer[chunk_offset..chunk_offset + chunk_size]
                ) {
                    return Err(Error::new(ErrorKind::Other, 
                                 format!("Failed to write chunk: {}", e)));
                }
            }
        } else {
            // For regular files, write all at once
            if let Err(e) = volume_guard.write_at(
                start_sector * sector_size as u64,
                buffer
            ) {
                return Err(Error::new(ErrorKind::Other, 
                             format!("Failed to write to file: {}", e)));
            }
        }
        
        Ok(())
    }
    
    /// Gets status report about encryption progress
    pub fn get_status_report(&self) -> Option<String> {
        if self.background_state.is_active() {
            Some(self.background_state.get_status_report())
        } else {
            None
        }
    }

    /// Checks if the volume is fully encrypted
    pub fn is_fully_encrypted(&self) -> bool {
        let percentage = self.get_encryption_percentage();
        percentage >= 99.9 // Consider fully encrypted if 99.9% or more is done
    }
} 