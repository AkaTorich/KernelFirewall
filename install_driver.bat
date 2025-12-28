@echo off
echo ============================================
echo  Kernel Firewall Driver Installer
echo ============================================
echo.

:: Check for admin rights
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] This script requires Administrator privileges!
    echo Right-click and select "Run as administrator"
    pause
    exit /b 1
)

set DRIVER_NAME=KernelFirewall
set DRIVER_PATH=%~dp0bin\Release\x64\KernelFirewall.sys

if not exist "%DRIVER_PATH%" (
    set DRIVER_PATH=%~dp0bin\Debug\x64\KernelFirewall.sys
)

if not exist "%DRIVER_PATH%" (
    echo [ERROR] Driver not found!
    echo Please build the driver first.
    pause
    exit /b 1
)

echo [*] Stopping existing service if running...
sc stop %DRIVER_NAME% >nul 2>&1
timeout /t 2 >nul

echo [*] Deleting existing service...
sc delete %DRIVER_NAME% >nul 2>&1
timeout /t 1 >nul

echo [*] Copying driver to System32\drivers...
copy /Y "%DRIVER_PATH%" "%SystemRoot%\System32\drivers\%DRIVER_NAME%.sys" >nul

echo [*] Creating service...
sc create %DRIVER_NAME% type=kernel binPath="%SystemRoot%\System32\drivers\%DRIVER_NAME%.sys" start=demand error=normal

if %errorLevel% neq 0 (
    echo [ERROR] Failed to create service!
    pause
    exit /b 1
)

echo [*] Starting service...
sc start %DRIVER_NAME%

if %errorLevel% neq 0 (
    echo [WARNING] Failed to start service. You may need to enable test signing.
    echo Run: bcdedit /set testsigning on
    echo Then reboot and try again.
) else (
    echo.
    echo [SUCCESS] Driver installed and started!
)

echo.
pause

