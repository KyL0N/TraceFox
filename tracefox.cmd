@echo off
setlocal

set "TRACEFOX_ROOT=%~dp0"
set "TRACEFOX_POWERSHELL=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%TRACEFOX_POWERSHELL%" (
    echo [TraceFox] powershell.exe was not found.
    exit /b 1
)

rem Do not inherit a PowerShell 7-only module path into Windows PowerShell 5.1.
set "PSModulePath="
"%TRACEFOX_POWERSHELL%" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%TRACEFOX_ROOT%windows\tracefox.ps1" %*
exit /b %ERRORLEVEL%
