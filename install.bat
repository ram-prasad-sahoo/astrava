@echo off
REM Astrava AI Security Scanner Installation Script for Windows
REM Requires Python 3.8+ and internet connection

setlocal enabledelayedexpansion

echo.
echo ================================================================
echo    🛡️  ASTRAVA AI SECURITY SCANNER - Installation (Windows)
echo ================================================================
echo.
echo [INFO] Starting installation process...
echo.

REM Check if Python is installed
echo [INFO] Checking Python installation...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python not found. Please install Python 3.8+ from https://python.org
    pause
    exit /b 1
)

REM Get Python version
for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
echo [SUCCESS] Python %PYTHON_VERSION% found

REM Check pip
echo [INFO] Checking pip installation...
pip --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] pip not found. Please install pip
    pause
    exit /b 1
)
echo [SUCCESS] pip found

REM Install Python dependencies
echo [INFO] Installing Python dependencies...
if exist requirements.txt (
    pip install -r requirements.txt
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to install Python dependencies
        pause
        exit /b 1
    )
    echo [SUCCESS] Python dependencies installed
) else (
    echo [ERROR] requirements.txt not found
    pause
    exit /b 1
)

REM Check if Ollama is installed
echo [INFO] Checking Ollama installation...
ollama --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [WARNING] Ollama not found
    echo [INFO] Please install Ollama manually:
    echo   1. Visit https://ollama.ai
    echo   2. Download and install Ollama for Windows
    echo   3. Run: ollama pull llama3.2:3b
    echo   4. Re-run this installation script
    pause
    exit /b 1
) else (
    echo [SUCCESS] Ollama found
)

REM Check if Ollama service is running
echo [INFO] Checking Ollama service...
curl -s http://localhost:11434/api/tags >nul 2>&1
if %errorlevel% neq 0 (
    echo [INFO] Starting Ollama service...
    start /b ollama serve
    timeout /t 5 /nobreak >nul
    
    REM Check again
    curl -s http://localhost:11434/api/tags >nul 2>&1
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to start Ollama service
        echo Please start Ollama manually and try again
        pause
        exit /b 1
    )
)
echo [SUCCESS] Ollama service is running

REM Check if LLaMA model is available
echo [INFO] Checking LLaMA 3.2:3b model...
ollama list 2>nul | findstr /C:"llama3.2:3b" >nul 2>&1
if %errorlevel% neq 0 (
    echo [WARNING] LLaMA 3.2:3b model not found
    echo [INFO] Downloading LLaMA 3.2:3b model...
    echo [INFO] This will download approximately 2GB of data. Please wait...
    echo.
    ollama pull llama3.2:3b
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to download LLaMA model
        echo [INFO] Please try manually: ollama pull llama3.2:3b
        pause
        exit /b 1
    )
    echo [SUCCESS] LLaMA 3.2:3b model downloaded successfully
) else (
    echo [SUCCESS] LLaMA 3.2:3b model already installed
)

REM Create necessary directories
echo [INFO] Creating directories...
if not exist logs mkdir logs
if not exist reports mkdir reports
if not exist payloads mkdir payloads
echo [SUCCESS] Directories created

REM Run comprehensive verification
echo.
echo [INFO] Running comprehensive installation verification...
echo.
python verify_installation.py
if %errorlevel% neq 0 (
    echo.
    echo [WARNING] Some verification checks failed
    echo [INFO] Please review the output above and fix any issues
    echo.
    pause
    exit /b 1
)

echo [SUCCESS] All verification checks passed!

echo.
echo ================================================================
echo    🎉 ASTRAVA Installation Completed Successfully!
echo ================================================================
echo.
echo ✅ All components verified and working correctly!
echo.
echo 📋 Quick Start Guide:
echo.
echo   Launch GUI:
echo     python astrava_gui.py
echo     python astrava.py
echo.
echo   CLI Scans:
echo     python astrava.py -u https://httpbin.org --basic
echo     python astrava.py -u https://httpbin.org
echo     python astrava.py -u https://httpbin.org --aggressive
echo.
echo   Verify Installation Anytime:
echo     python verify_installation.py
echo.
echo   Get Help:
echo     python astrava.py --help
echo     python main.py --help
echo.
echo ⚠️  IMPORTANT: Only scan systems you own or have permission to test!
echo.
echo 📖 For detailed documentation, see README.md
echo.

pause
