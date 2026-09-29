# Network Slinger - Windows Application Installer
[CmdletBinding()]
param(
    [switch]$NoLaunch
)

$ErrorActionPreference = "Stop"
$appName = "Network Slinger"
$version = "1.0.0"
$scriptRoot = $PSScriptRoot
if (-not $scriptRoot) { $scriptRoot = Get-Location }

$distDir = Join-Path $scriptRoot "dist\NetworkSlinger"
$installDir = "$env:LOCALAPPDATA\Programs\NetworkSlinger"
$exePath = Join-Path $installDir "NetworkSlinger.exe"
$shortcutPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Network Slinger.lnk"
$regKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\NetworkSlinger"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "       $appName - Windows Application Installer" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# Verify compiled application exists
if (-not (Test-Path (Join-Path $distDir "NetworkSlinger.exe"))) {
    Write-Host "[!] Compiled binaries not found in $distDir." -ForegroundColor Yellow
    Write-Host "[*] Building application with PyInstaller..." -ForegroundColor Cyan
    Set-Location $scriptRoot
    & pyinstaller NetworkSlinger.spec --noconfirm
    if (-not (Test-Path (Join-Path $distDir "NetworkSlinger.exe"))) {
        Write-Host "[ERROR] Build failed. Could not find NetworkSlinger.exe." -ForegroundColor Red
        exit 1
    }
}

Write-Host "[1/4] Preparing installation directory: $installDir" -ForegroundColor Cyan
# Close any active instance before replacing files
Get-Process NetworkSlinger -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 500

if (-not (Test-Path $installDir)) {
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
}

Write-Host "[2/4] Deploying application binaries and local assets..." -ForegroundColor Cyan
Copy-Item -Path "$distDir\*" -Destination $installDir -Recurse -Force

# Copy uninstaller into install directory
if (Test-Path (Join-Path $scriptRoot "uninstall.ps1")) {
    Copy-Item -Path (Join-Path $scriptRoot "uninstall.ps1") -Destination (Join-Path $installDir "uninstall.ps1") -Force
}

Write-Host "[3/4] Creating Windows Start Menu entry..." -ForegroundColor Cyan
$wsh = New-Object -ComObject WScript.Shell
$shortcut = $wsh.CreateShortcut($shortcutPath)
$shortcut.TargetPath = $exePath
$shortcut.WorkingDirectory = $installDir
$shortcut.Description = "Network Slinger - Asset Discovery, Reconnaissance & Security Auditor"
$shortcut.Save()

Write-Host "[4/4] Registering application in Windows Programs list..." -ForegroundColor Cyan
if (-not (Test-Path $regKey)) {
    New-Item -Path $regKey -Force | Out-Null
}

Set-ItemProperty -Path $regKey -Name "DisplayName" -Value $appName
Set-ItemProperty -Path $regKey -Name "DisplayVersion" -Value $version
Set-ItemProperty -Path $regKey -Name "Publisher" -Value "Network Slinger Project"
Set-ItemProperty -Path $regKey -Name "DisplayIcon" -Value $exePath
Set-ItemProperty -Path $regKey -Name "InstallLocation" -Value $installDir
Set-ItemProperty -Path $regKey -Name "UninstallString" -Value "powershell.exe -ExecutionPolicy Bypass -File `"$installDir\uninstall.ps1`""
Set-ItemProperty -Path $regKey -Name "QuietUninstallString" -Value "powershell.exe -ExecutionPolicy Bypass -File `"$installDir\uninstall.ps1`""

Write-Host "`n[+] Installation complete! $appName has been installed successfully." -ForegroundColor Green
Write-Host "    - Install Directory: $installDir" -ForegroundColor White
Write-Host "    - Start Menu: Accessible from your Windows Start Menu" -ForegroundColor White
Write-Host "    - Programs & Features: Manageable via Windows Settings > Apps" -ForegroundColor White

if (-not $NoLaunch) {
    Write-Host "`n[*] Launching $appName..." -ForegroundColor Cyan
    Start-Process $exePath
}
