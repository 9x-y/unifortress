#!/bin/bash
echo "==================================================="
echo "       UniFortress - Mount Encrypted Disk          "
echo "==================================================="
echo
echo "WARNING! This script requires sudo privileges!"
echo

# Check if a disk number was provided
if [ -z "$1" ]; then
    echo "Starting without parameters. Will show list of disks."
    echo "---------------------------------------------------"
    
    if [ "$EUID" -ne 0 ]; then
        sudo ./target/release/unifortress list-devices
    else
        ./target/release/unifortress list-devices
    fi
    echo "---------------------------------------------------"
    
    read -p "Enter disk number to mount: " DISK_NUMBER
else
    DISK_NUMBER=$1
fi

# Set mount point based on OS
if [[ "$(uname)" == "Darwin" ]]; then
    # macOS typically mounts to /Volumes
    MOUNT_POINT="/Volumes/UniFortress"
    # Create mount point if it doesn't exist
    if [ ! -d "$MOUNT_POINT" ]; then
        sudo mkdir -p "$MOUNT_POINT"
    fi
else
    # Linux typically mounts to /mnt
    MOUNT_POINT="/mnt/unifortress"
    # Create mount point if it doesn't exist
    if [ ! -d "$MOUNT_POINT" ]; then
        sudo mkdir -p "$MOUNT_POINT"
    fi
fi

echo
echo "WARNING: Disk #$DISK_NUMBER will be mounted"
echo "It will be mounted to $MOUNT_POINT"
echo
read -p "Continue with mounting? (y/n): " confirm

if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo "Operation cancelled."
    read -p "Press Enter to exit..."
    exit 0
fi

read -sp "Enter password for the disk: " PASSWORD
echo

echo
echo "Starting disk mount:"
echo "---------------------------------------------------"
if [ "$EUID" -ne 0 ]; then
    sudo ./target/release/unifortress mount --device $DISK_NUMBER --password "$PASSWORD" --mount_point "$MOUNT_POINT"
else
    ./target/release/unifortress mount --device $DISK_NUMBER --password "$PASSWORD" --mount_point "$MOUNT_POINT"
fi
echo "---------------------------------------------------"
echo

echo "Mount operation completed."
read -p "Press Enter to exit..." 