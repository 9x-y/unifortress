# UniFortress Disk Encryption Utility

A cross-platform utility for disk encryption, mounting, and management.

## Requirements

- Windows: PowerShell
- Unix/Linux: Bash shell, sudo privileges

## Usage

### Windows

First, set execution permissions:
```
.\set-permissions.ps1
```

Then use the PowerShell script:
```
.\unifortress.ps1 [command] [parameters]
```

Or use the batch files directly:
```
.\list_devices.bat
.\test_encrypt_disk.bat [disk_number]
.\test_check_disk.bat [disk_number]
.\test_mount_disk.bat [disk_number]
```

### Unix/Linux

Make the scripts executable first:
```
chmod +x *.sh
```

Then use the universal launcher:
```
./unifortress.sh [command] [parameters]
```

Or use the individual scripts:
```
./list_devices.sh
./encrypt_disk.sh [disk_number]
./check_disk.sh [disk_number]
./mount_disk.sh [disk_number]
```

## Available Commands

- `list` - List available devices
- `encrypt [disk_number]` - Encrypt a disk
- `check [disk_number]` - Check disk encryption status
- `mount [disk_number]` - Mount an encrypted disk
- `unmount [disk_number]` - Unmount an encrypted disk

## Warning

Disk encryption operations can potentially result in data loss. Always back up important data before performing encryption operations.

## Building from Source

```
cargo build --release
```

## Системные требования

- Windows 10/11, macOS или Linux
- Rust 1.71+ для разработки
- Пользователям Windows необходима библиотека Dokan для поддержки виртуальной файловой системы 