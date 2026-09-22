@echo off
setlocal
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0c20r7n-two-run-controller.ps1" -PackageDir "%~dp0"
set "RC=%ERRORLEVEL%"
if exist "%~dp0c20r7n-summary.json" echo Summary: %~dp0c20r7n-summary.json
if exist "%~dp0CONFIRMATION_REQUIRED.txt" echo STOP: explicit PM/user confirmation is required before any Norton configuration change.
exit /b %RC%
