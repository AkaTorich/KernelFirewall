@echo off
echo ============================================
echo  Kernel Firewall Driver Uninstaller
echo ============================================
echo.

set DRIVER_NAME=KernelFirewall

echo [*] Stopping service...
sc stop %DRIVER_NAME%
timeout /t 2 >nul

echo [*] Deleting service...
sc delete %DRIVER_NAME%
timeout /t 1 >nul

echo [*] Removing driver file...
del /f "%SystemRoot%\System32\drivers\%DRIVER_NAME%.sys" >nul 2>&1

echo.
echo [SUCCESS] Driver uninstalled!
echo.
pause

