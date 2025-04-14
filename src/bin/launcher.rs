use std::env;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::io::{self, Write, Read, Seek, SeekFrom};
use anyhow::{Result, Context, anyhow};
use rpassword::read_password;
use sha2::{Sha256, Digest};
use aes::Aes256;
use sha2::digest::KeyInit;
use xts_mode::Xts128 as Xts;

// Константы
const HEADER_SIZE: usize = 4096; // 4KB для заголовка
const SECTOR_SIZE: usize = 512; // Стандартный размер сектора
const SALT_SIZE: usize = 32; // Размер соли
const KEY_SIZE: usize = 64; // 512 бит для XTS (2 ключа по 256 бит)

fn main() -> Result<()> {
    // Проверяем, запущен ли процесс с правами администратора
    if !is_admin() {
        println!("Запустите программу от имени администратора.");
        pause();
        return Ok(());
    }
    
    println!("UniFortress CLI - Доступ к зашифрованному диску");
    println!("=============================================");

    // Автоопределение диска, на котором запущена программа
    let exe_path = env::current_exe()
        .context("Не удалось определить путь к исполняемому файлу")?;
    
    let drive_letter = get_drive_letter(&exe_path)
        .context("Не удалось определить букву диска")?;
    
    println!("Программа запущена с диска {}", drive_letter);
    
    // Определяем путь к физическому устройству
    let device_path = format!(r"\\.\{}:", drive_letter);
    
    // Открываем устройство для чтения
    let mut device = open_device_for_reading(&device_path)?;
    
    // Читаем заголовок
    let mut header = vec![0u8; HEADER_SIZE];
    device.seek(SeekFrom::Start(0))?;
    device.read_exact(&mut header)
        .context("Не удалось прочитать заголовок. Устройство не зашифровано или повреждено.")?;
    
    // Проверяем сигнатуру
    if &header[0..7] != b"UNIFORT" {
        return Err(anyhow!("Устройство не зашифровано с помощью UniFortress"));
    }
    
    // Получаем соль из заголовка
    let salt = &header[16..16+SALT_SIZE];
    
    // Запрашиваем пароль
    print!("Введите пароль для доступа к зашифрованному тому: ");
    io::stdout().flush()?;
    let password = read_password()?;
    
    if password.is_empty() {
        return Err(anyhow!("Пароль не может быть пустым"));
    }
    
    println!("\nПроверка пароля...");
    
    // Генерируем ключ
    let key = derive_key(&password, salt)?;
    
    // Проверяем контрольную сумму
    let mut hasher = Sha256::new();
    hasher.update(&key);
    let checksum = hasher.finalize();
    
    if &header[48..48+32] != checksum.as_slice() {
        return Err(anyhow!("Неверный пароль"));
    }
    
    println!("Пароль верный. Доступ к зашифрованному тому разрешен.");
    
    // Инициализируем XTS шифр
    let cipher = init_cipher(&key).context("Не удалось инициализировать шифр")?;
    
    // Открываем CLI меню для работы с зашифрованным томом
    command_line_interface(&device_path, &cipher)?;
    
    Ok(())
}

// CLI интерфейс для работы с зашифрованным томом
fn command_line_interface(device_path: &str, cipher: &Xts<Aes256>) -> Result<()> {
    loop {
        println!("\nДоступные действия:");
        println!("[1] Просмотр информации о томе");
        println!("[2] Выйти");
        
        print!("Выберите действие (номер): ");
        io::stdout().flush()?;
        let mut choice = String::new();
        io::stdin().read_line(&mut choice)?;
        
        match choice.trim() {
            "1" => show_volume_info(device_path, cipher)?,
            "2" => break,
            _ => println!("Неверный выбор. Попробуйте снова."),
        }
    }
    
    println!("Работа с томом завершена.");
    Ok(())
}

// Просмотр информации о томе
fn show_volume_info(device_path: &str, _cipher: &Xts<Aes256>) -> Result<()> {
    println!("Информация о зашифрованном томе: {}", device_path);
    println!("Тип шифрования: XTS-AES-256");
    println!("Размер сектора: {} байт", SECTOR_SIZE);
    println!("Том успешно проверен и готов к использованию.");
    
    Ok(())
}

// Получение буквы диска из пути
fn get_drive_letter(path: &Path) -> Result<char> {
    let path_str = path.to_string_lossy();
    if path_str.len() > 2 && path_str.chars().nth(1) == Some(':') {
        Ok(path_str.chars().next().unwrap())
    } else {
        Err(anyhow!("Путь не содержит буквы диска"))
    }
}

// Проверка прав администратора
fn is_admin() -> bool {
    let output = Command::new("powershell")
        .args(&["-Command", "[bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match 'S-1-5-32-544')"])
        .output();
    
    match output {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout).trim().to_string();
            stdout == "True"
        },
        Err(_) => false
    }
}

// Открытие устройства для чтения
fn open_device_for_reading(path: &str) -> Result<File> {
    OpenOptions::new()
        .read(true)
        .open(path)
        .context("Не удалось открыть устройство для чтения")
}

// Открытие устройства для записи
fn open_device_for_writing(path: &str) -> Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .context("Не удалось открыть устройство для записи")
}

// Генерация ключа из пароля
fn derive_key(password: &str, salt: &[u8]) -> Result<Vec<u8>> {
    // Используем простой SHA-256 для вывода ключа
    let mut key = Vec::with_capacity(KEY_SIZE);
    
    // Первый ключ
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update(salt);
    let key1 = hasher.finalize();
    
    // Второй ключ для XTS
    let mut hasher = Sha256::new();
    hasher.update(&key1);
    hasher.update(b"xts-key-2");
    let key2 = hasher.finalize();
    
    // Объединяем ключи
    key.extend_from_slice(&key1);
    key.extend_from_slice(&key2);
    
    Ok(key)
}

// Инициализация XTS шифра
fn init_cipher(key: &[u8]) -> Result<Xts<Aes256>> {
    if key.len() != KEY_SIZE {
        return Err(anyhow!("Неверная длина ключа"));
    }
    
    // Разделяем ключ на две части по 32 байта
    let key1 = &key[0..32];
    let key2 = &key[32..64];
    
    // Создаем два экземпляра Aes256
    let cipher1 = Aes256::new_from_slice(key1)
        .map_err(|_| anyhow!("Ошибка создания первого шифра"))?;
    let cipher2 = Aes256::new_from_slice(key2)
        .map_err(|_| anyhow!("Ошибка создания второго шифра"))?;
    
    // Создаем XTS шифр
    Ok(Xts::new(cipher1, cipher2))
}

// Пауза выполнения до нажатия Enter
fn pause() {
    println!("Нажмите Enter для выхода...");
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap_or_default();
} 