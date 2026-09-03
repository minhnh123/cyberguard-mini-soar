@echo off
title CyberGuard SOAR - Standalone Production Mode
color 0A

echo ======================================================================
echo           CYBERGUARD SOAR - STANDALONE UNIFIED MODE (PORT 8000)
echo ======================================================================
echo.

echo [*] Dang build lai frontend ban production moi nhat...
cd /d %~dp0frontend
call npm run build

echo.
echo [*] Dang khoi chay Standalone Server tai: http://localhost:8000 ...
cd /d %~dp0backend
start "CyberGuard SOAR Standalone Server" cmd /k "python run.py"

timeout /t 2 >nul
start http://localhost:8000

echo.
echo [OK] He thong da khoi dong tai http://localhost:8000
pause >nul
