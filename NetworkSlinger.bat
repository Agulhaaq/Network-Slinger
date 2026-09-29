@echo off
:: Network Slinger - Single-Instance Local Desktop Application Launcher
title Network Slinger
cd /d "%~dp0"

echo [+] Initializing Network Slinger Local Desktop Application...
where pythonw >nul 2>&1
if %ERRORLEVEL% equ 0 (
    start "" pythonw run.py app
) else (
    where python >nul 2>&1
    if %ERRORLEVEL% equ 0 (
        start "" python run.py app
    ) else (
        echo [ERROR] Python not found in system PATH.
        echo Please ensure Python is installed and added to PATH.
        pause
    )
)
