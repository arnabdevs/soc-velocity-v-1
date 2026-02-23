@echo off
title AEGIS SOC ENGINE - Windows Setup
echo 🛡️ AEGIS SOC ENGINE - WINDOWS SETUP 🛡️
echo ------------------------------------------

:: Check for Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] ERROR: Python is not installed. Please install it from python.org
    pause
    exit /b
)

echo [+] Installing Python dependencies...
python -m pip install psutil requests python-whois flask flask-cors waitress

:: Check for Nmap
nmap --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] WARNING: Nmap is not found in your PATH.
    echo Please download and install it from: https://nmap.org/download.html#windows
    echo Restart this script after installation.
    pause
) else (
    echo [+] Nmap detected!
)

echo.
echo [+] Setup Finished.
echo [+] Starting AEGIS SOC Engine...
echo.
python backend/app.py
pause
