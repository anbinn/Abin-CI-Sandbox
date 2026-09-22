@echo off
setlocal
cd /d "%~dp0"
set "TARGET=%~dp0Abin.exe"
set "RESULT=%~dp0c20r7n-result.json"
if not exist "%TARGET%" (
  echo Missing exact Candidate A: %TARGET%
  exit /b 2
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0c20r7n-norton-discriminator.ps1" -ExePath "%TARGET%" -ExpectedSha256 "18599C12A9A00E75F13A58F48E355F6F6FF20DBAEE049D8E856373AF5006A358" -ResultPath "%RESULT%" -ObserveSeconds 12
set "RC=%ERRORLEVEL%"
echo Result: %RESULT%
exit /b %RC%
