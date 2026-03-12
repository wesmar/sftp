@echo off
setlocal
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install_sftp_plugin.ps1"
set "ec=%ERRORLEVEL%"
if not "%ec%"=="0" (
  echo.
  echo Installation failed. Exit code: %ec%
  pause
  exit /b %ec%
)
echo.
echo Plugin installed successfully.
pause
exit /b 0
