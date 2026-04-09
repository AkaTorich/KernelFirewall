@echo off
setlocal enabledelayedexpansion

echo ============================================
echo  Kernel Firewall - Test Signing Script
echo ============================================
echo.

set DRIVER_PATH=%~dp0bin\Release\x64\KernelFirewall.sys
set CERT_NAME=KernelFirewallTestCert

if not exist "%DRIVER_PATH%" (
    set DRIVER_PATH=%~dp0bin\Debug\x64\KernelFirewall.sys
)

if not exist "%DRIVER_PATH%" (
    echo [ERROR] Driver not found!
    echo Build the driver first.
    pause
    exit /b 1
)

echo [*] Driver found: %DRIVER_PATH%
echo.

:: Check if test signing is enabled
echo [*] Checking test signing mode...
bcdedit /enum {current} | findstr /i "testsigning.*Yes" >nul
if %errorLevel% neq 0 (
    echo [WARNING] Test signing is NOT enabled!
    echo.
    choice /C YN /M "Enable test signing mode? (requires reboot)"
    if !errorLevel! equ 1 (
        echo [*] Enabling test signing...
        bcdedit /set testsigning on
        echo.
        echo [!] You MUST reboot for changes to take effect!
        echo     After reboot, run this script again.
        pause
        exit /b 0
    ) else (
        echo [!] Test signing not enabled. Driver will not load without it.
        echo.
    )
)

:: Create PowerShell script for certificate operations
echo [*] Creating/finding test certificate...

echo $certName = '%CERT_NAME%' > "%~dp0_cert_helper.ps1"
echo $existingCert = Get-ChildItem -Path Cert:\CurrentUser\My ^| Where-Object { $_.Subject -like "*$certName*" } ^| Select-Object -First 1 >> "%~dp0_cert_helper.ps1"
echo if ($existingCert) { >> "%~dp0_cert_helper.ps1"
echo     Write-Host '[*] Using existing certificate:' $existingCert.Thumbprint >> "%~dp0_cert_helper.ps1"
echo     $existingCert.Thumbprint ^| Out-File -FilePath '%~dp0cert_thumbprint.txt' -Encoding ASCII -NoNewline >> "%~dp0_cert_helper.ps1"
echo } else { >> "%~dp0_cert_helper.ps1"
echo     Write-Host '[*] Creating new certificate...' >> "%~dp0_cert_helper.ps1"
echo     $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=$certName" -CertStoreLocation 'Cert:\CurrentUser\My' -NotAfter (Get-Date).AddYears(10) >> "%~dp0_cert_helper.ps1"
echo     Write-Host '[*] Certificate created:' $cert.Thumbprint >> "%~dp0_cert_helper.ps1"
echo     $cert.Thumbprint ^| Out-File -FilePath '%~dp0cert_thumbprint.txt' -Encoding ASCII -NoNewline >> "%~dp0_cert_helper.ps1"
echo } >> "%~dp0_cert_helper.ps1"

powershell -ExecutionPolicy Bypass -File "%~dp0_cert_helper.ps1"
del /f "%~dp0_cert_helper.ps1" 2>nul

if not exist "%~dp0cert_thumbprint.txt" (
    echo [ERROR] Failed to create certificate!
    pause
    exit /b 1
)

set /p THUMBPRINT=<"%~dp0cert_thumbprint.txt"
echo [*] Certificate thumbprint: %THUMBPRINT%

:: Install certificate to trusted stores
echo [*] Installing certificate to trusted stores...

echo $thumb = '%THUMBPRINT%' > "%~dp0_install_cert.ps1"
echo $cert = Get-ChildItem -Path "Cert:\CurrentUser\My\$thumb" >> "%~dp0_install_cert.ps1"
echo $rootStore = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', 'LocalMachine') >> "%~dp0_install_cert.ps1"
echo $rootStore.Open('ReadWrite') >> "%~dp0_install_cert.ps1"
echo $rootStore.Add($cert) >> "%~dp0_install_cert.ps1"
echo $rootStore.Close() >> "%~dp0_install_cert.ps1"
echo $pubStore = New-Object System.Security.Cryptography.X509Certificates.X509Store('TrustedPublisher', 'LocalMachine') >> "%~dp0_install_cert.ps1"
echo $pubStore.Open('ReadWrite') >> "%~dp0_install_cert.ps1"
echo $pubStore.Add($cert) >> "%~dp0_install_cert.ps1"
echo $pubStore.Close() >> "%~dp0_install_cert.ps1"
echo Write-Host '[*] Certificate installed to Root and TrustedPublisher stores' >> "%~dp0_install_cert.ps1"

powershell -ExecutionPolicy Bypass -File "%~dp0_install_cert.ps1"
del /f "%~dp0_install_cert.ps1" 2>nul

:: Find signtool - WDK 10.0.26100.0
set SIGNTOOL=

if exist "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe" (
    set "SIGNTOOL=C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe"
    goto :found_signtool
)
if exist "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe" (
    set "SIGNTOOL=C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe"
    goto :found_signtool
)
if exist "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22000.0\x64\signtool.exe" (
    set "SIGNTOOL=C:\Program Files (x86)\Windows Kits\10\bin\10.0.22000.0\x64\signtool.exe"
    goto :found_signtool
)

echo [ERROR] signtool.exe not found!
echo Install Windows SDK or WDK.
pause
exit /b 1

:found_signtool

echo [*] Using signtool: %SIGNTOOL%
echo.

:: Sign the driver
echo [*] Signing driver...
"%SIGNTOOL%" sign /v /fd SHA256 /sha1 %THUMBPRINT% "%DRIVER_PATH%"

if %errorLevel% equ 0 (
    echo.
    echo ============================================
    echo  [SUCCESS] Driver signed successfully!
    echo ============================================
    echo.
    echo [*] Verifying signature...
    "%SIGNTOOL%" verify /pa "%DRIVER_PATH%"
    echo.
    echo Next steps:
    echo 1. Reboot if you enabled test signing
    echo 2. Run install_driver.bat as Administrator
) else (
    echo.
    echo [ERROR] Failed to sign driver!
)

:: Cleanup
del /f "%~dp0cert_thumbprint.txt" 2>nul

echo.
pause
