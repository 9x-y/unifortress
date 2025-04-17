# Universal PowerShell launcher for UniFortress on Windows

# Function to print usage
function Print-Usage {
    Write-Host "UniFortress - Cross-platform disk encryption utility"
    Write-Host "Usage: .\unifortress.ps1 COMMAND [DISK_NUMBER]"
    Write-Host ""
    Write-Host "Commands:"
    Write-Host "  list           List available disks"
    Write-Host "  encrypt [n]    Encrypt disk number n"
    Write-Host "  check [n]      Check encryption status of disk n"
    Write-Host "  mount [n]      Mount encrypted disk n"
    Write-Host "  unmount [n]    Unmount encrypted disk n"
    Write-Host ""
    Write-Host "If DISK_NUMBER is not provided, you will be prompted to choose one."
}

# Check if help requested or no arguments
if ($args.Count -eq 0 -or $args[0] -eq "--help" -or $args[0] -eq "-h") {
    Print-Usage
    exit 0
}

# Get command and optional disk number
$command = $args[0]
$diskNumber = if ($args.Count -gt 1) { $args[1] } else { $null }

# Process commands
switch ($command) {
    "list" {
        # Check if running as admin, if not elevate
        if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
            Start-Process -Verb RunAs "powershell" -ArgumentList "-File $PSCommandPath list"
            exit
        }
        
        & .\target\release\unifortress.exe list-devices
    }
    
    "encrypt" {
        # Check if running as admin, if not elevate
        if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
            if ($diskNumber) {
                Start-Process -Verb RunAs "powershell" -ArgumentList "-File $PSCommandPath encrypt $diskNumber"
            } else {
                Start-Process -Verb RunAs "powershell" -ArgumentList "-File $PSCommandPath encrypt"
            }
            exit
        }
        
        if (-Not $diskNumber) {
            # Show disk list and ask user for selection
            Write-Host "Starting without parameters. Will show list of disks."
            Write-Host "---------------------------------------------------"
            & .\target\release\unifortress.exe list-devices
            Write-Host "---------------------------------------------------"
            
            $diskNumber = Read-Host "Enter disk number to encrypt"
        }
        
        Write-Host ""
        Write-Host "WARNING: Disk #$diskNumber will be encrypted"
        Write-Host ""
        Write-Host "ALL DATA ON THE DISK WILL BE DESTROYED!"
        Write-Host ""
        $confirm = Read-Host "Continue with encryption? (y/n)"
        
        if ($confirm -ne "y") {
            Write-Host "Operation cancelled."
            Read-Host "Press Enter to exit..."
            exit 0
        }
        
        Write-Host ""
        Write-Host "Starting disk encryption:"
        Write-Host "---------------------------------------------------"
        & .\target\release\unifortress.exe encrypt --device $diskNumber
        Write-Host "---------------------------------------------------"
        Write-Host ""
        
        Write-Host "Operation completed."
        Read-Host "Press Enter to exit..."
    }
    
    "check" {
        # Check if running as admin, if not elevate
        if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
            if ($diskNumber) {
                Start-Process -Verb RunAs "powershell" -ArgumentList "-File $PSCommandPath check $diskNumber"
            } else {
                Start-Process -Verb RunAs "powershell" -ArgumentList "-File $PSCommandPath check"
            }
            exit
        }
        
        if (-Not $diskNumber) {
            # Show disk list and ask user for selection
            Write-Host "Starting without parameters. Will show list of disks."
            Write-Host "---------------------------------------------------"
            & .\target\release\unifortress.exe list-devices
            Write-Host "---------------------------------------------------"
            
            $diskNumber = Read-Host "Enter disk number to check"
        }
        
        Write-Host ""
        Write-Host "WARNING: Disk #$diskNumber will be checked"
        Write-Host ""
        $confirm = Read-Host "Continue with check? (y/n)"
        
        if ($confirm -ne "y") {
            Write-Host "Operation cancelled."
            Read-Host "Press Enter to exit..."
            exit 0
        }
        
        Write-Host ""
        Write-Host "Starting disk check:"
        Write-Host "---------------------------------------------------"
        & .\target\release\unifortress.exe check --device $diskNumber
        Write-Host "---------------------------------------------------"
        Write-Host ""
        
        Write-Host "Check operation completed."
        Read-Host "Press Enter to exit..."
    }
    
    "mount" {
        # Check if running as admin, if not elevate
        if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
            if ($diskNumber) {
                Start-Process -Verb RunAs "powershell" -ArgumentList "-File $PSCommandPath mount $diskNumber"
            } else {
                Start-Process -Verb RunAs "powershell" -ArgumentList "-File $PSCommandPath mount"
            }
            exit
        }
        
        if (-Not $diskNumber) {
            # Show disk list and ask user for selection
            Write-Host "Starting without parameters. Will show list of disks."
            Write-Host "---------------------------------------------------"
            & .\target\release\unifortress.exe list-devices
            Write-Host "---------------------------------------------------"
            
            $diskNumber = Read-Host "Enter disk number to mount"
        }
        
        $mountPoint = "M:\"
        
        Write-Host ""
        Write-Host "WARNING: Disk #$diskNumber will be mounted"
        Write-Host "It will be mounted as $mountPoint"
        Write-Host ""
        $confirm = Read-Host "Continue with mounting? (y/n)"
        
        if ($confirm -ne "y") {
            Write-Host "Operation cancelled."
            Read-Host "Press Enter to exit..."
            exit 0
        }
        
        $password = Read-Host "Enter password for the disk" -AsSecureString
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
        $password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        
        Write-Host ""
        Write-Host "Starting disk mount:"
        Write-Host "---------------------------------------------------"
        & .\target\release\unifortress.exe mount --device $diskNumber --password $password --mount_point $mountPoint
        Write-Host "---------------------------------------------------"
        Write-Host ""
        
        Write-Host "Mount operation completed."
        Read-Host "Press Enter to exit..."
    }
    
    "unmount" {
        # Check if running as admin, if not elevate
        if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
            Start-Process -Verb RunAs "powershell" -ArgumentList "-File $PSCommandPath unmount"
            exit
        }
        
        $mountPoint = "M:\"
        
        Write-Host ""
        Write-Host "WARNING: Will unmount from $mountPoint"
        Write-Host ""
        $confirm = Read-Host "Continue with unmounting? (y/n)"
        
        if ($confirm -ne "y") {
            Write-Host "Operation cancelled."
            Read-Host "Press Enter to exit..."
            exit 0
        }
        
        Write-Host ""
        Write-Host "Starting disk unmount:"
        Write-Host "---------------------------------------------------"
        & .\target\release\unifortress.exe unmount --mount_point $mountPoint
        Write-Host "---------------------------------------------------"
        Write-Host ""
        
        Write-Host "Unmount operation completed."
        Read-Host "Press Enter to exit..."
    }
    
    default {
        Write-Host "Unknown command: $command"
        Print-Usage
        exit 1
    }
} 