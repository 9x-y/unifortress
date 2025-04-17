#!/bin/bash
echo "==================================================="
echo "       UniFortress - Disk Encryption               "
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
    
    read -p "Enter disk number to encrypt: " DISK_NUMBER
else
    DISK_NUMBER=$1
fi

echo
echo "WARNING: Disk #$DISK_NUMBER will be encrypted"
echo
echo "ALL DATA ON THE DISK WILL BE DESTROYED!"
echo
read -p "Continue with encryption? (y/n): " confirm

if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo "Operation cancelled."
    read -p "Press Enter to exit..."
    exit 0
fi

echo
echo "Starting disk encryption:"
echo "---------------------------------------------------"
if [ "$EUID" -ne 0 ]; then
    sudo ./target/release/unifortress encrypt --device $DISK_NUMBER
else
    ./target/release/unifortress encrypt --device $DISK_NUMBER
fi
echo "---------------------------------------------------"
echo

echo "Operation completed."
read -p "Press Enter to exit..." 