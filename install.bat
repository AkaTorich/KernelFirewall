@echo off
setlocal enabledelayedexpansion

echo ============================================
echo  Wire Firewall Driver Installer (Root)
echo ============================================
echo.

set DRIVER_NAME=KernelFirewall
set DRIVER_PATH=%~dp0KernelFirewall.sys

:: Check admin
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] This script must be run as Administrator!
    echo Right-click and select "Run as administrator".
    pause
    exit /b 1
)

:: Check driver exists
if not exist "%DRIVER_PATH%" (
    echo [ERROR] Driver not found at:
    echo   %DRIVER_PATH%
    echo.
    echo Place KernelFirewall.sys in the project root folder.
    pause
    exit /b 1
)

echo [*] Driver source: %DRIVER_PATH%
echo.

:: Check if test signing is enabled
bcdedit /enum | findstr /i "testsigning.*Yes" >nul
if %errorLevel% neq 0 (
    echo [WARNING] Test signing is NOT enabled.
    echo You may need to run: bcdedit /set testsigning on
    echo Then reboot before installing.
    echo.
    choice /c YN /m "Continue anyway"
    if !errorLevel! neq 1 exit /b 0
    echo.
)

echo [*] Stopping existing service if running...
sc stop %DRIVER_NAME% >nul 2>&1
timeout /t 2 /nobreak >nul

echo [*] Deleting existing service...
sc delete %DRIVER_NAME% >nul 2>&1
timeout /t 1 /nobreak >nul

echo [*] Copying driver to System32\drivers...
if defined PROCESSOR_ARCHITEW6432 (
    set TARGET=%SystemRoot%\Sysnative\drivers\%DRIVER_NAME%.sys
) else (
    set TARGET=%SystemRoot%\System32\drivers\%DRIVER_NAME%.sys
)

copy /Y "%DRIVER_PATH%" "!TARGET!" >nul
if %errorLevel% neq 0 (
    echo [ERROR] Failed to copy driver file!
    pause
    exit /b 1
)
echo     -^> !TARGET!

echo [*] Creating kernel service...
sc create %DRIVER_NAME% type=kernel binPath="%SystemRoot%\System32\drivers\%DRIVER_NAME%.sys" start=demand error=normal DisplayName="Wire Firewall Driver"
if %errorLevel% neq 0 (
    echo [ERROR] Failed to create service!
    pause
    exit /b 1
)

echo [*] Setting service description...
sc description %DRIVER_NAME% "Kernel-mode WFP firewall driver for Wire Firewall" >nul

echo [*] Starting service...
sc start %DRIVER_NAME%
if %errorLevel% neq 0 (
    echo.
    echo [WARNING] Failed to start service. Common reasons:
    echo   1. Test signing is not enabled. Run:
    echo        bcdedit /set testsigning on
    echo      Then reboot and try again.
    echo   2. Driver is not signed with a trusted certificate.
    echo   3. Secure Boot may be blocking the driver.
    echo.
    pause
    exit /b 1
)

echo.
echo ============================================
echo  [SUCCESS] Driver installed and started!
echo ============================================
echo.
echo Service name: %DRIVER_NAME%
echo Device path:  \\.\KernelFirewall
echo.
echo You can now launch WireFirewall.exe
echo.
pause
endlocal
