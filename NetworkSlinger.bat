@echo off
:: Network Slinger Single-Instance Launcher
title Network Slinger
cd /d "%~dp0"
start "" python run.py app
