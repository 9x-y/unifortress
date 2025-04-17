# Set execution policy for current session
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

# Make all .ps1 files executable
Get-ChildItem *.ps1 -Exclude set-permissions.ps1 | ForEach-Object {
    Write-Host "Setting execution permissions for $_"
    Unblock-File $_
}

# Make batch files executable (they are executable by default, but ensure they have the right extension)
Get-ChildItem *.bat | ForEach-Object {
    Write-Host "Checking batch file $_"
    # Batch files don't need special permissions on Windows, just ensuring they exist in output
}

Write-Host "All scripts are now ready to use!"
Write-Host "Run PowerShell scripts with: .\script_name.ps1"
Write-Host "Run batch files with: .\script_name.bat" 