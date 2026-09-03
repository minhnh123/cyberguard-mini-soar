@echo off
title Stop CyberGuard SOAR
color 0C

echo ======================================================================
echo               DANG DUNG CAC TIEN TRINH CYBERGUARD SOAR
echo ======================================================================
echo.

echo [*] Dang tat cac cua so Backend va Frontend...
taskkill /FI "WINDOWTITLE eq CyberGuard SOAR - Backend*" /T /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq CyberGuard SOAR - Frontend*" /T /F >nul 2>&1

echo [*] Hoan tat! Tat ca tien trinh SOAR da duoc dong an toan.
echo.
timeout /t 2 >nul
exit
