@echo off
setlocal
cd /d "%~dp0"
del /q "%~dp0c20r7n-console.log" >nul 2>&1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0c20r7n-two-run-controller.ps1" -PackageDir "%~dp0" > "%~dp0c20r7n-console.log" 2>&1
set "RC=%ERRORLEVEL%"
if not "%RC%"=="0" (
  echo.
  echo C20R7N failed. Error details were saved to:
  echo %~dp0c20r7n-error.txt
  echo.
  if exist "%~dp0c20r7n-error.txt" type "%~dp0c20r7n-error.txt"
  echo.
  echo Do not change Norton. Close this window and send c20r7n-error.txt to PM.
  pause
  exit /b %RC%
)
if exist "%~dp0c20r7n-run1.json" echo Run 1 result: %~dp0c20r7n-run1.json
if exist "%~dp0c20r7n-summary.json" echo Summary: %~dp0c20r7n-summary.json
if exist "%~dp0CONFIRMATION_REQUIRED.txt" (
  echo.
  echo STOP: Run 1 completed. Do not change Norton until PM/user explicitly approves it.
  echo Result: %~dp0c20r7n-run1.json
  pause
)
exit /b %RC%
