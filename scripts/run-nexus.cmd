@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
set "EXE=%SCRIPT_DIR%nexus-core.exe"
set "PAUSE_AT_END=0"

if "%~1"=="" set "PAUSE_AT_END=1"

if not exist "%EXE%" (
  echo [ERROR] nexus-core.exe not found in:
  echo         %SCRIPT_DIR%
  set "EXIT_CODE=1"
  goto :finish
)

if "%~1"=="" (
  "%EXE%" --help
) else (
  "%EXE%" %*
)
set "EXIT_CODE=%ERRORLEVEL%"

:finish
if "%PAUSE_AT_END%"=="1" (
  echo.
  pause
)

exit /b %EXIT_CODE%
