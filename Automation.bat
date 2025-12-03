@echo off
chcp 65001 >nul
setlocal EnableDelayedExpansion

title AstraVault AI - Secure Launch (Windows)
color 0B

cd /d "%~dp0"
echo.
echo ============================================================
echo   🔐 AstraVault AI - Secure Launch (Windows)
echo   © 2025 BYLICKILABS - Intelligence Systems/Communications
echo ============================================================
echo.
echo [*] Project directory: %CD%
echo.

set VENV_DIR=%CD%\.venv
set ACTIVATE_SCRIPT=%VENV_DIR%\Scripts\activate

if not exist "%ACTIVATE_SCRIPT%" (
    echo [!] Virtual environment not found.
    echo [*] Creating new virtual environment in root directory...
    python -m venv "%VENV_DIR%"
    if errorlevel 1 (
        echo [X] Failed to create virtual environment!
        pause
        exit /b
    )
)

echo [*] Activating virtual environment...
call "%ACTIVATE_SCRIPT%"

echo [*] Upgrading PIP package manager...
python -m pip install --upgrade pip >nul 2>&1

if exist "%CD%\requirements.txt" (
    echo [*] Installing required dependencies...
    pip install -r "%CD%\requirements.txt" >nul 2>&1
) else (
    echo [!] No requirements.txt found – continuing...
)

if exist "%CD%\app.py" (
    echo [*] Launching AstraVault AI...
    python "%CD%\app.py"
) else (
    echo [X] The file app.py was not found!
)

echo.
echo [*] Application has exited.
pause
endlocal
