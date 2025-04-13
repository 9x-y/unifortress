// Объявление подмодулей для папки platform
pub mod common;
pub mod volume_io;

// Платформенно-зависимые модули
#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "linux")]
pub mod linux;

// Убираем удаленные модули
// pub mod ios;
// pub mod android; 