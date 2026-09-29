@echo off
title Network Slinger Setup
echo ========================================================
echo       Network Slinger - Windows Application Setup
echo ========================================================
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1"
if %ERRORLEVEL% neq 0 (
    echo.
    echo [ERROR] Installation encountered an issue.
    pause
)
