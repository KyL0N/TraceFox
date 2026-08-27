@echo off
setlocal

set "TRACEFOX_ROOT=%~dp0"
where powershell.exe >nul 2>nul
if errorlevel 1 (
    echo [TraceFox] powershell.exe was not found.
    exit /b 1
)

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%TRACEFOX_ROOT%windows\tracefox.ps1" %*
exit /b %ERRORLEVEL%
