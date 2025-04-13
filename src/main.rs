mod encryption;
mod decryption;
mod platform;
mod utils;
mod mount;

use anyhow::{bail, Context};
use clap::Parser;
use log::{error, info};
use std::path::PathBuf;
// Добавляем импорты
use crate::encryption::{derive_key, split_derived_key, VolumeHeader, encrypt_sector, VOLUME_SIGNATURE, HEADER_VERSION};
use crate::platform::volume_io::VolumeFile;
use crate::utils::parse_size;
use std::io::{self, Write};
use crate::mount::EncryptedFsHandler;
use crate::platform::windows::{check_drive_letter_availability, check_dokan_driver};
use dokan::{Dokan, MountFlags, MountPoint, MountOptions};

/// Структура для парсинга аргументов командной строки
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// Перечисление доступных подкоманд
#[derive(clap::Subcommand, Debug)]
enum Commands {
    /// Зашифровать указанное устройство (флешку)
    Encrypt(EncryptArgs),
    /// Разблокировать (расшифровать) указанное устройство
    Unlock(UnlockArgs),
}

/// Аргументы для команды шифрования
#[derive(clap::Args, Debug)]
struct EncryptArgs {
    /// Путь к файлу-контейнеру для создания/шифрования
    #[arg(short, long, value_name = "FILE_PATH")]
    file: PathBuf, 
    
    /// Размер создаваемого контейнера (например, 1G, 512M, 100K)
    #[arg(short, long, value_name = "SIZE")]
    size: String, // Будем парсить размер позже

    // TODO: Добавить опции (например, --password-from-stdin, --force - перезаписать существующий)
}

/// Аргументы для команды разблокировки
#[derive(clap::Args, Debug)]
struct UnlockArgs {
    /// Путь к зашифрованному файлу-контейнеру
    #[arg(short, long, value_name = "FILE_PATH")]
    file: PathBuf,
    
    /// Куда монтировать (или как предоставить доступ) - ЗАГЛУШКА
    #[arg(short, long, value_name = "MOUNT_POINT")]
    mount_point: Option<PathBuf>,
    // TODO: Добавить опции
}

fn main() -> anyhow::Result<()> {
    env_logger::init();
    info!("UniFortress v{} запущен", env!("CARGO_PKG_VERSION"));

    let cli = Cli::parse();
    info!("Получена команда: {:?}", cli.command);

    // Обработка команды
    match cli.command {
        Commands::Encrypt(args) => {
            info!("Выбрана команда Encrypt для устройства: {:?}", args.file);
            // Запускаем обработчик в отдельной функции, чтобы main не разрасталась
            if let Err(e) = handle_encrypt(args) {
                // Выводим ошибку в stderr для пользователя
                eprintln!("\nОшибка шифрования: {}", e); // Добавим \n на случай если ошибка после прогресса
                // Логируем с деталями
                error!("Encryption failed: {:?}", e);
                std::process::exit(1); // Завершаемся с кодом ошибки
            }
        }
        Commands::Unlock(args) => {
            info!(
                "Выбрана команда Unlock для устройства: {:?} (точка монтирования: {:?})",
                args.file,
                args.mount_point
            );
            if let Err(e) = handle_unlock(args) {
                eprintln!("Ошибка разблокировки: {}", e);
                error!("Unlock failed: {:?}", e);
                std::process::exit(1);
            }
        }
    }

    Ok(())
}

// --- Обработчики команд ---

fn handle_encrypt(args: EncryptArgs) -> anyhow::Result<()> {
    // Валидация входных параметров
    if args.size.trim().is_empty() {
        bail!("Не указан размер контейнера");
    }
    
    // Проверка, что путь к файлу не пустой и валидный
    let file_path = args.file.to_string_lossy();
    if file_path.is_empty() || file_path == "." || file_path == ".." {
        bail!("Указан некорректный путь к файлу");
    }
    
    // 1. Получить пароль
    let password = prompt_password_repeatedly("Введите пароль для шифрования: ")?;

    // 1.5 Парсим размер
    let container_size = parse_size(&args.size)
        .with_context(|| format!("Неверный формат размера контейнера: '{}'", args.size))?;
    if container_size == 0 {
        bail!("Размер контейнера не может быть 0");
    }
    info!("Запрошенный размер контейнера: {} байт", container_size);

    // 2. Создать файл-контейнер
    info!("Создание файла-контейнера: {:?}", args.file);
    // Используем VolumeFile::create_new
    let mut volume = VolumeFile::create_new(&args.file, container_size)
        .with_context(|| format!("Не удалось создать файл '{}'", args.file.display()))?;

    // 3. Получить размер сектора (виртуального)
    let sector_size = volume.get_sector_size();
    info!("Виртуальный размер сектора: {} байт", sector_size);
    let sector_size_usize = sector_size as usize;
    
    // Проверка кратности размера файла размеру сектора
    if container_size % sector_size as u64 != 0 {
         // Можно или округлить размер вверх до кратного сектору, или выдать ошибку
         // Пока выдадим ошибку
         bail!("Размер контейнера ({}) не кратен размеру виртуального сектора ({})", container_size, sector_size);
    }
    let total_sectors = container_size / sector_size as u64;
    info!("Общий размер контейнера: {} секторов", total_sectors);

    if total_sectors < 2 {
        bail!("Размер контейнера слишком мал (менее 2 секторов).");
    }

    // --- Подготовка заголовка ---
    // 4. Создать заголовок
    let mut header = VolumeHeader::new();
    info!("Создан новый заголовок тома.");

    // 5. Рассчитать ключи (KDF)
    info!("Генерация ключей из пароля (может занять некоторое время)...");
    let derived_key = derive_key(password.as_bytes(), header.kdf_salt())?;
    info!("Ключи успешно сгенерированы.");

    // 6. Разделить ключи
    // Теперь нам нужен xts_key
    let (xts_key, hmac_key) = split_derived_key(&derived_key)?;

    // 7. Рассчитать и установить HMAC заголовка
    header.set_hmac(&hmac_key)?;
    info!("HMAC заголовка рассчитан и установлен.");

    // 8. Сериализовать заголовок
    let serialized_header = header.serialize()?;
    let header_size = serialized_header.len();
    info!("Заголовок сериализован (размер: {} байт).", header_size);

    // Проверим, помещается ли заголовок в один сектор
    if header_size > sector_size_usize {
        bail!(
            "Сериализованный заголовок ({} байт) больше размера сектора ({} байт)!",
            header_size,
            sector_size
        );
    }

    // 9. Записать заголовок в файл
    let mut header_sector_buffer = vec![0u8; sector_size_usize];
    header_sector_buffer[..header_size].copy_from_slice(&serialized_header);
    let header_sector_index: u64 = 1;
    info!("Запись заголовка в сектор {} файла...", header_sector_index);
    volume.write_sectors(header_sector_index, sector_size, &header_sector_buffer)
         .with_context(|| format!("Не удалось записать заголовок в сектор {}", header_sector_index))?;
    info!("Заголовок успешно записан в файл.");

    // --- 10. Шифрование данных ---
    println!("Начинается шифрование данных в файле...");
    let data_start_sector: u64 = 2; // Начинаем с сектора 2
    let data_sectors_count = total_sectors - data_start_sector;
     if data_sectors_count == 0 {
         println!("Нет данных для шифрования (только заголовок).");
         return Ok(()); // Завершаем успешно, если шифровать нечего
    }
    info!("Шифрование {} секторов данных (с {} по {})...", data_sectors_count, data_start_sector, total_sectors - 1);

    let mut sector_buffer = vec![0u8; sector_size_usize];
    let mut last_reported_percent = 0;
    
    // Оптимизация - не читаем каждый сектор, если файл только что создан и он заполнен нулями
    // Просто шифруем нулевой буфер и записываем его
    info!("Оптимизированное шифрование - файл только что создан, заполнен нулями");
    
    for current_sector_index in data_start_sector..total_sectors {
        // Шифруем сектор (используем xts_key)
        if let Err(e) = encrypt_sector(&xts_key, current_sector_index as u128, &mut sector_buffer) {
            error!("Ошибка шифрования сектора {}: {:?}. Шифрование прервано.", current_sector_index, e);
            bail!("Ошибка шифрования сектора {}: {}", current_sector_index, e);
        }

        // Записываем зашифрованный сектор
        if let Err(e) = volume.write_sectors(current_sector_index, sector_size, &sector_buffer) {
            error!("Ошибка записи сектора {}: {:?}. Шифрование прервано.", current_sector_index, e);
            bail!("Ошибка записи зашифрованного сектора {}: {}", current_sector_index, e);
        }
        
        // Очищаем буфер для следующего сектора (он был изменен при шифровании)
        sector_buffer.fill(0);

        // Обновление прогресса
        let processed_sectors = current_sector_index - data_start_sector + 1;
        let current_percent = ((processed_sectors * 100) / data_sectors_count) as u8;

        if current_percent > last_reported_percent || processed_sectors == data_sectors_count {
            print!("\rПрогресс шифрования: {}%", current_percent);
            io::stdout().flush()?; // Убедимся, что прогресс выводится немедленно
            last_reported_percent = current_percent;
        }
    }

    println!("\nШифрование файла-контейнера успешно завершено.");
    println!("Для доступа к зашифрованному контейнеру используйте команду:");
    println!("  unifortress unlock -f \"{}\"", args.file.display());

    Ok(())
}

fn handle_unlock(args: UnlockArgs) -> anyhow::Result<()> {
    // Валидация входных параметров
    let file_path = args.file.to_string_lossy();
    if file_path.is_empty() || file_path == "." || file_path == ".." {
        bail!("Указан некорректный путь к файлу");
    }
    
    // Проверяем существование файла
    if !args.file.exists() {
        bail!("Файл не существует: {}", file_path);
    }
    
    // 1. Открыть файл-контейнер
    info!("Открытие файла-контейнера: {:?}", args.file);
    // Используем VolumeFile::open
    let mut volume = VolumeFile::open(&args.file)
        .with_context(|| format!("Не удалось открыть файл '{}'", args.file.display()))?;

    // 2. Получить размер сектора (виртуального)
    let sector_size = volume.get_sector_size();
    info!("Виртуальный размер сектора: {}", sector_size);

    // 3. Прочитать первый сектор (сектор 1)
    let header_sector_index: u64 = 1;
    let mut header_buffer = vec![0u8; sector_size as usize];
    info!("Чтение заголовка из сектора {} файла...", header_sector_index);
    // Используем volume.read_sectors
    volume.read_sectors(header_sector_index, 1, sector_size, &mut header_buffer)
        .with_context(|| format!("Не удалось прочитать заголовок из сектора {}", header_sector_index))?;

    // 4. Десериализовать заголовок
    let header = VolumeHeader::deserialize(&header_buffer)?;
    info!("Заголовок успешно десериализован. Версия: {}", header.version());

    // ---> Проверка сигнатуры и версии <-----
    if header.signature() != VOLUME_SIGNATURE {
        bail!("Неверная сигнатура тома. Это не устройство UniFortress или оно повреждено.");
    }
    if header.version() != HEADER_VERSION {
        bail!(
            "Неподдерживаемая версия заголовка ({}). Требуется версия {}.",
            header.version(),
            HEADER_VERSION
        );
        // TODO: В будущем здесь может быть логика для обработки старых версий
    }
    info!("Сигнатура и версия заголовка корректны.");
    // <-------------------------------------->

    // 5. Запросить пароль
    print!("Введите пароль для разблокировки: ");
    io::stdout().flush()?;
    let password = rpassword::read_password().context("Не удалось прочитать пароль")?;

    // 6. Рассчитать ключи (KDF)
    info!("Проверка пароля (генерация ключей)...");
    let derived_key = derive_key(password.as_bytes(), header.kdf_salt())?;

    // 7. Разделить ключи
    let (xts_key, hmac_key) = split_derived_key(&derived_key)?;

    // 8. Проверить HMAC заголовка
    let is_hmac_valid = header.verify_hmac(&hmac_key)?;

    // 9. Результат проверки
    if is_hmac_valid {
        info!("HMAC заголовка верный. Пароль корректен.");
        println!("Пароль верный! Запуск монтирования...");
        
        // Проверяем наличие драйвера Dokan
        if !check_dokan_driver()? {
            bail!("Драйвер Dokan не установлен или не запущен. Установите Dokan для монтирования виртуальных дисков.");
        }
        
        // ---> Запуск монтирования Dokan <--- 
        let mount_point_str = args.mount_point // Получаем точку монтирования из аргументов
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| "U:".to_string()); // По умолчанию диск U:
            
        info!("Попытка монтирования на {}", mount_point_str);
        
        // Проверка доступности буквы диска (только первый символ как букву диска)
        if let Some(drive_letter) = mount_point_str.chars().next() {
            if !check_drive_letter_availability(drive_letter)? {
                bail!("Буква диска {} уже используется. Выберите другую букву.", drive_letter);
            }
        }
        
        // Создаем обработчик файловой системы
        // volume передается во владение обработчику
        let fs_handler = EncryptedFsHandler::new(volume, xts_key);
        
        // Настраиваем опции монтирования
        let mount_options = MountOptions {
            mount_point: mount_point_str,
            options: dokan::MountFlags::REMOVABLE,
            ..Default::default()
        };

        // Создаем и запускаем Dokan
        // Это блокирующий вызов - он будет работать, пока диск не будет размонтирован
        info!("Инициализация Dokan для точки монтирования {}", mount_point_str);
        
        match dokan::Drive::mount(fs_handler, &mount_options) {
            Ok(drive) => {
                println!("Диск успешно смонтирован на {}.", mount_point_str);
                println!("Теперь вы можете получить доступ к данным через проводник или командную строку.");
                println!("Нажмите Ctrl+C для размонтирования и завершения работы программы.");
                
                info!("Диск успешно смонтирован на {}. Ожидание сигнала для размонтирования.", mount_point_str);
                // Ждем завершения (например, по Ctrl+C или другому сигналу)
                drive.join(); // Ожидаем завершения работы Dokan
                info!("Диск размонтирован.");
                println!("Диск успешно размонтирован. Доступ к зашифрованным данным прекращен.");
            },
            Err(e) => {
                error!("Ошибка монтирования Dokan: {:?}", e);
                bail!("Не удалось смонтировать виртуальный диск: {}", e);
            }
        }
        // <-------------------------------------->
    } else {
        // 10. Ошибка HMAC
        error!("Проверка HMAC заголовка не пройдена! Неверный пароль или заголовок поврежден.");
        bail!("Неверный пароль или заголовок поврежден.");
    }

    Ok(())
}

/// Запрашивает пароль у пользователя дважды и проверяет совпадение.
fn prompt_password_repeatedly(prompt: &str) -> anyhow::Result<String> {
    loop {
        print!("{}", prompt);
        io::stdout().flush()?; // Убедимся, что приглашение вывелось перед вводом пароля
        let pass1 = rpassword::read_password().context("Не удалось прочитать пароль")?;

        print!("Повторите пароль для подтверждения: ");
        io::stdout().flush()?;
        let pass2 = rpassword::read_password().context("Не удалось прочитать пароль для подтверждения")?;

        if pass1 == pass2 {
            if pass1.is_empty() {
                println!("Пароль не может быть пустым. Попробуйте снова.");
            } else {
                return Ok(pass1);
            }
        } else {
            println!("Пароли не совпадают. Попробуйте снова.");
        }
    }
}
