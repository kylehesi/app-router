@echo off
setlocal
chcp 65001 >nul

rem Yönetici değilse kendini yönetici olarak yeniden başlat (UAC onayı istenir).
net session >nul 2>&1
if errorlevel 1 (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"
set "BIN=%~dp0target\release"
if not exist "%BIN%\router-service.exe" (
    echo [HATA] %BIN%\router-service.exe bulunamadı.
    echo        Önce derleyin:  cargo build --release
    pause
    exit /b 1
)
if not exist "%BIN%\wintun.dll" (
    echo wintun.dll eksik, indiriliyor...
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\fetch-wintun.ps1"
)
set "SVC=%BIN%\router-service.exe"
title Router

:menu
cls
echo ==================================================
echo   Router - Uygulama Bazlı İnternet
echo ==================================================
echo.
echo   1. Uygulamayı başlat (yönlendirme + arayüz)
echo   2. Motor testi
echo   3. Motor testi (belirli bir adaptörle)
echo   4. Adaptörleri listele
echo   5. Bir adaptörden dış IP'yi göster
echo   6. Ağ kullanan uygulamaları listele
echo   7. Sistem kontrolü (doctor)
echo   8. Güvenlik duvarı kuralını ekle
echo   0. Çıkış
echo.
set "CHOICE="
set /p "CHOICE=Seçiminiz: "

if "%CHOICE%"=="1" goto start
if "%CHOICE%"=="2" goto enginetest
if "%CHOICE%"=="3" goto enginetest_adapter
if "%CHOICE%"=="4" goto adapters
if "%CHOICE%"=="5" goto probe
if "%CHOICE%"=="6" goto apps
if "%CHOICE%"=="7" goto doctor
if "%CHOICE%"=="8" goto firewall
if "%CHOICE%"=="0" exit /b 0
goto menu

:start
echo.
echo Arayüz açılıyor. Yönlendirme bu pencerede çalışacak.
echo Durdurmak için bu pencerede Ctrl+C'ye basın; internet hemen normale döner.
echo.
start "" "%BIN%\router-ui.exe"
"%SVC%" run --engine
echo.
echo Yönlendirme durdu.
pause
goto menu

:enginetest
echo.
"%SVC%" engine-test
echo.
pause
goto menu

:enginetest_adapter
echo.
"%SVC%" adapters
echo.
set "ADAPTER="
set /p "ADAPTER=Adaptör adı (örn. Wi-Fi veya Ethernet 2): "
if "%ADAPTER%"=="" goto menu
echo.
"%SVC%" engine-test "%ADAPTER%"
echo.
pause
goto menu

:adapters
echo.
"%SVC%" adapters
echo.
pause
goto menu

:probe
echo.
"%SVC%" adapters
echo.
set "ADAPTER="
set /p "ADAPTER=Adaptör adı (örn. Wi-Fi veya Ethernet 2): "
if "%ADAPTER%"=="" goto menu
echo.
"%SVC%" probe "%ADAPTER%"
echo.
pause
goto menu

:apps
echo.
"%SVC%" apps
echo.
pause
goto menu

:doctor
echo.
"%SVC%" doctor
echo.
pause
goto menu

:firewall
echo.
"%SVC%" firewall
echo.
pause
goto menu
