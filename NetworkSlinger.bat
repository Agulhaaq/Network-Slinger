@echo off
:: Network Slinger - Single-Instance Local Desktop Application Launcher
title Network Slinger
cd /d "%~dp0"

where pythonw >nul 2>&1
if %ERRORLEVEL% equ 0 (
    start "" pythonw run.py app
) else (
    start "" python run.py app
)
