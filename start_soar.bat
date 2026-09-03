@echo off
setlocal enabledelayedexpansion
title CyberGuard SOAR - Launcher
color 0B

cd /d "%~dp0"

echo ======================================================================
echo           CYBERGUARD MINI SOAR - AI INCIDENT RESPONSE PLATFORM
echo ======================================================================
echo.

:: 1. Kiem tra Python
where python >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Khong tim thay Python trong PATH! Vui long cai dat Python 3.10+
    echo Hay dam bao da tich vao "Add Python to PATH" khi cai dat.
    echo.
    pause
    exit /b 1
)

:: 2. Kiem tra Node / NPM
where npm >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Khong tim thay Node.js/NPM trong PATH! Vui long cai dat Node.js
    echo.
    pause
    exit /b 1
)

echo [1/3] Dang khoi dong Backend API (Port 8000)...
start "CyberGuard SOAR - Backend" cmd /k "cd /d ""%~dp0backend"" && python run.py"

echo [2/3] Dang khoi dong Frontend Dashboard (Port 5173)...
start "CyberGuard SOAR - Frontend" cmd /k "cd /d ""%~dp0frontend"" && npm run dev"

echo.
echo [3/3] Dang cho cac server khoi tao trong 3 giay...
timeout /t 3 >nul

echo [*] Dang mo Web Dashboard tren trinh duyet...
start http://localhost:5173

echo.
echo ======================================================================
echo   [SUCCESS] HE THONG CYBERGUARD SOAR DA HOAT DONG SAN SANG!
echo   - Web Dashboard:    http://localhost:5173
echo   - Backend REST API: http://localhost:8000
echo   - Swagger API Docs: http://localhost:8000/docs
echo ======================================================================
echo.
echo Cac cua so Backend va Frontend dang chay ngam rieng biet.
echo Ban co the dong cua so nay hoac nhan phim bat ky de thoat.
echo.
pause
