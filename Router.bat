@echo off
setlocal
chcp 65001 >nul

rem If not running as administrator, relaunch elevated (shows a UAC prompt).
net session >nul 2>&1
if errorlevel 1 (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"
rem Release ZIP: the exes sit next to this file. Source checkout: target\release.
set "BIN=%~dp0target\release"
if exist "%~dp0router-service.exe" set "BIN=%~dp0."
if not exist "%BIN%\router-service.exe" (
    echo [ERROR] %BIN%\router-service.exe not found.
    echo         Build it first:  cargo build --release
    pause
    exit /b 1
)
if not exist "%BIN%\wintun.dll" (
    echo wintun.dll is missing, downloading...
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\fetch-wintun.ps1"
)
set "SVC=%BIN%\router-service.exe"
title Router

:menu
cls
echo ==================================================
echo   Router - Per-App Internet
echo ==================================================
echo.
echo   1. Start the app (routing + UI)
echo   2. Engine test
echo   3. Engine test (with a specific adapter)
echo   4. List adapters
echo   5. Show the public IP through an adapter
echo   6. List apps using the network
echo   7. System check (doctor)
echo   8. Add the firewall rule
echo   9. Watch adapter changes live
echo   0. Exit
echo.
set "CHOICE="
set /p "CHOICE=Your choice: "

if "%CHOICE%"=="1" goto start
if "%CHOICE%"=="2" goto enginetest
if "%CHOICE%"=="3" goto enginetest_adapter
if "%CHOICE%"=="4" goto adapters
if "%CHOICE%"=="5" goto probe
if "%CHOICE%"=="6" goto apps
if "%CHOICE%"=="7" goto doctor
if "%CHOICE%"=="8" goto firewall
if "%CHOICE%"=="9" goto watch
if "%CHOICE%"=="0" exit /b 0
goto menu

:start
echo.
echo Opening the UI. Routing runs in this window.
echo To stop, press Ctrl+C in this window; networking returns to normal right away.
echo.
start "" "%BIN%\router-ui.exe"
"%SVC%" run --engine
echo.
echo Routing stopped.
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
set /p "ADAPTER=Adapter name (e.g. Wi-Fi or Ethernet 2): "
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
set /p "ADAPTER=Adapter name (e.g. Wi-Fi or Ethernet 2): "
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

:watch
echo.
echo Press Ctrl+C to stop watching.
"%SVC%" watch
echo.
pause
goto menu
