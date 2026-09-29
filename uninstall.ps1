# Network Slinger - Uninstaller Script
$appName = "Network Slinger"
$installDir = "$env:LOCALAPPDATA\Programs\NetworkSlinger"
$shortcutPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Network Slinger.lnk"
$regKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\NetworkSlinger"

Write-Host "Uninstalling $appName..." -ForegroundColor Cyan

# Terminate running instances
Get-Process NetworkSlinger -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

# Remove Start Menu shortcut
if (Test-Path $shortcutPath) {
    Remove-Item $shortcutPath -Force -ErrorAction SilentlyContinue
    Write-Host "[+] Removed Start Menu shortcut." -ForegroundColor Green
}

# Remove Registry Uninstall Entry
if (Test-Path $regKey) {
    Remove-Item $regKey -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "[+] Removed Windows registry entries." -ForegroundColor Green
}

# Remove Application Directory
if (Test-Path $installDir) {
    # If uninstaller is running from within the directory, schedule directory removal
    Start-Process cmd -ArgumentList "/c timeout /t 2 /nobreak >nul & rmdir /s /q `"$installDir`"" -WindowStyle Hidden
    Write-Host "[+] Removed application files." -ForegroundColor Green
}

Write-Host "`n$appName has been successfully uninstalled from your computer." -ForegroundColor Green
