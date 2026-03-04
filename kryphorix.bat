@echo off
REM kryphorix.bat  —  Kryphorix v2.0.0 Windows Launcher
REM Finds Python 3.8+ and launches the tool.

setlocal enabledelayedexpansion

set SCRIPT_DIR=%~dp0
set PYTHON=

REM Try py launcher first (Python Windows installer)
py -3 --version >nul 2>&1
if %ERRORLEVEL% == 0 (
    set PYTHON=py -3
    goto :launch
)

REM Try python3
python3 --version >nul 2>&1
if %ERRORLEVEL% == 0 (
    set PYTHON=python3
    goto :launch
)

REM Try python
python --version >nul 2>&1
if %ERRORLEVEL% == 0 (
    set PYTHON=python
    goto :launch
)

echo [FATAL] Python 3.8+ not found.
echo Install from: https://www.python.org/downloads/
pause
exit /b 1

:launch
cd /d "%SCRIPT_DIR%"
%PYTHON% kryphorix.py %*
