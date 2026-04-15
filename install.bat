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

REM Check if Ollama is installed (optional)
echo [INFO] Checking Ollama installation (optional for AI features)...
ollama --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [INFO] Ollama not found - you can install it later for AI features
    echo [INFO] To use AI-powered analysis:
    echo   1. Visit https://ollama.ai
    echo   2. Download and install Ollama for Windows
    echo   3. Run: ollama pull xploiter/pentester
    echo   4. Or use any other model you prefer
    echo.
    echo [INFO] Configure AI settings in the Web GUI after installation
    echo.
) else (
    echo [SUCCESS] Ollama found
    
    REM Check if Ollama service is running
    echo [INFO] Checking Ollama service...
    curl -s http://localhost:11434/api/tags >nul 2>&1
    if %errorlevel% neq 0 (
        echo [INFO] Starting Ollama service...
        start /b ollama serve
        timeout /t 3 /nobreak >nul
    )
    
    REM List available models
    echo [INFO] Checking available AI models...
    ollama list 2>nul
    echo.
    echo [INFO] AI Model Recommendations:
    echo   Based on your system, you can download AI models:
    echo.
    echo   Recommended (Security-focused):
    echo     ollama pull xploiter/pentester
    echo.
    echo   Alternative models (choose based on your system):
    echo     ollama pull llama3.2:3b         (2GB RAM, general purpose)
    echo     ollama pull qwen2.5:3b          (2GB RAM, alternative)
    echo     ollama pull mistral:7b          (4GB RAM, more powerful)
    echo     ollama pull llama3.2:1b         (1GB RAM, lightweight)
    echo.
    echo   Configure your preferred model in Web GUI after installation
    echo.
)

REM Create necessary directories
echo [INFO] Creating directories...
if not exist logs mkdir logs
if not exist reports mkdir reports
if not exist payloads mkdir payloads
echo [SUCCESS] Directories created

echo.
echo ================================================================
echo    🎉 ASTRAVA Installation Completed Successfully!
echo ================================================================
echo.
echo ✅ Python dependencies installed
echo.
echo 📋 Quick Start Guide:
echo.
echo   Launch Web GUI (Recommended):
echo     python astrava.py
echo.
echo   CLI Scans:
echo     python astrava.py -u https://example.com
echo     python astrava.py -u https://example.com --owasp-all
echo     python astrava.py -u https://example.com --owasp-all --chain-attacks
echo.
echo   Get Help:
echo     python astrava.py --help
echo     python astrava.py --version
echo.
echo 🤖 AI Configuration:
echo   - Launch the Web GUI: python astrava.py
echo   - Go to AI Model Settings
echo   - Install Ollama from https://ollama.ai
echo   - Recommended models:
echo       ollama pull xploiter/pentester  (security-focused)
echo       ollama pull llama3.2:3b         (general purpose)
echo.
echo ⚠️  IMPORTANT: Only scan systems you own or have permission to test!
echo.
echo 📖 For detailed documentation, see README.md
echo.

pause
