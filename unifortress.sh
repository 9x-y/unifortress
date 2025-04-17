#!/bin/bash
# Universal launcher for UniFortress that works across platforms

# Detect OS
OS="unknown"
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
elif [[ "$OSTYPE" == "cygwin" ]] || [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]]; then
    OS="windows"
fi

# Function to print usage
print_usage() {
    echo "UniFortress - Cross-platform disk encryption utility"
    echo "Usage: ./unifortress.sh COMMAND [DISK_NUMBER]"
    echo ""
    echo "Commands:"
    echo "  list           List available disks"
    echo "  encrypt [n]    Encrypt disk number n"
    echo "  check [n]      Check encryption status of disk n"
    echo "  mount [n]      Mount encrypted disk n"
    echo "  unmount [n]    Unmount encrypted disk n"
    echo ""
    echo "If DISK_NUMBER is not provided, you will be prompted to choose one."
}

# Check for help flags
if [[ "$1" == "--help" ]] || [[ "$1" == "-h" ]] || [[ -z "$1" ]]; then
    print_usage
    exit 0
fi

# Process commands
case "$1" in
    list)
        if [[ "$OS" == "windows" ]]; then
            ./list_devices.bat
        else
            ./list_devices.sh
        fi
        ;;
    encrypt)
        if [[ "$OS" == "windows" ]]; then
            ./test_encrypt_disk.bat $2
        else
            ./encrypt_disk.sh $2
        fi
        ;;
    check)
        if [[ "$OS" == "windows" ]]; then
            ./test_check_disk.bat $2
        else
            ./check_disk.sh $2
        fi
        ;;
    mount)
        if [[ "$OS" == "windows" ]]; then
            ./test_mount_disk.bat $2
        else
            ./mount_disk.sh $2
        fi
        ;;
    unmount)
        if [[ "$OS" == "windows" ]]; then
            ./test_unmount_disk.bat
        else
            echo "Unmount not yet implemented for Unix systems"
            exit 1
        fi
        ;;
    *)
        echo "Unknown command: $1"
        print_usage
        exit 1
        ;;
esac 