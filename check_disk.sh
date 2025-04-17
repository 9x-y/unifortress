#!/bin/bash
echo "==================================================="
echo "       UniFortress - Check Encrypted Disk          "
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
    
    read -p "Enter disk number to check: " DISK_NUMBER
else
    DISK_NUMBER=$1
fi

echo
echo "WARNING: Disk #$DISK_NUMBER will be checked"
echo
read -p "Continue with check? (y/n): " confirm

if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo "Operation cancelled."
    read -p "Press Enter to exit..."
    exit 0
fi

echo
echo "Starting disk check:"
echo "---------------------------------------------------"
if [ "$EUID" -ne 0 ]; then
    sudo ./target/release/unifortress check --device $DISK_NUMBER
else
    ./target/release/unifortress check --device $DISK_NUMBER
fi
echo "---------------------------------------------------"
echo

echo "Check operation completed."
read -p "Press Enter to exit..." 