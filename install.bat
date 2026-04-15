@echo off
REM Astrava AI Security Scanner Installation Script for Windows
REM Requires Python 3.8+ and internet connection

setlocal enabledelayedexpansion

echo.
echo ================================================================
echo    ASTRAVA AI SECURITY SCANNER - Installation (Windows)
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

REM Get and validate Python version
for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
echo [SUCCESS] Python %PYTHON_VERSION% found

REM Validate Python version is 3.8 or higher
for /f "tokens=1,2 delims=." %%a in ("%PYTHON_VERSION%") do (
    set PYTHON_MAJOR=%%a
    set PYTHON_MINOR=%%b
)

if %PYTHON_MAJOR% LSS 3 (
    echo [ERROR] Python 3.8+ required, found %PYTHON_VERSION%
    pause
    exit /b 1
)

if %PYTHON_MAJOR% EQU 3 if %PYTHON_MINOR% LSS 8 (
    echo [ERROR] Python 3.8+ required, found %PYTHON_VERSION%
    pause
    exit /b 1
)

echo [SUCCESS] Python version %PYTHON_VERSION% is compatible

REM Check pip
echo [INFO] Checking pip installation...
pip --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] pip not found. Please install pip
    pause
    exit /b 1
)
echo [SUCCESS] pip found

REM Create virtual environment
echo [INFO] Creating Python virtual environment...
if exist venv (
    echo [INFO] Virtual environment already exists, using existing one
) else (
    python -m venv venv
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to create virtual environment
        pause
        exit /b 1
    )
    echo [SUCCESS] Virtual environment created
)

REM Activate virtual environment
echo [INFO] Activating virtual environment...
call venv\Scripts\activate.bat
if %errorlevel% neq 0 (
    echo [ERROR] Failed to activate virtual environment
    pause
    exit /b 1
)
echo [SUCCESS] Virtual environment activated

REM Install Python dependencies
echo [INFO] Installing Python dependencies in virtual environment...
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
echo [INFO] Checking Ollama installation - optional for AI features
ollama --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [WARNING] Ollama not found
    echo.
    echo Ollama is optional for AI-powered analysis.
    echo.
    set /p INSTALL_OLLAMA="Install Ollama now? (y/n): "
    
    if /i "!INSTALL_OLLAMA!"=="y" (
        echo [INFO] Installing Ollama...
        echo [INFO] Please download and install Ollama from https://ollama.ai/download/windows
        echo [INFO] After installation, restart this script to complete setup
        echo.
        start https://ollama.ai/download/windows
        echo [INFO] Opening Ollama download page in your browser...
        echo [INFO] After installing Ollama, please run this script again
        pause
        exit /b 0
    ) else (
        echo [WARNING] Skipping Ollama installation
        echo [INFO] You can install it later from: https://ollama.ai
        echo.
    )
) else (
    echo [SUCCESS] Ollama found
    
    REM Check if Ollama service is running
    echo [INFO] Checking Ollama service...
    curl -s http://localhost:11434/api/tags >nul 2>&1
    if %errorlevel% neq 0 (
        echo [INFO] Starting Ollama service...
        start /b ollama serve
        timeout /t 3 /nobreak >nul
        
        REM Verify Ollama is running
        curl -s http://localhost:11434/api/tags >nul 2>&1
        if %errorlevel% neq 0 (
            echo [WARNING] Ollama service may not be running
            echo [INFO] You can start it manually with: ollama serve
        ) else (
            echo [SUCCESS] Ollama service started
        )
    ) else (
        echo [SUCCESS] Ollama is already running
    )
    
    REM List available models
    echo [INFO] Checking available AI models...
    echo.
    ollama list 2>nul
    if %errorlevel% neq 0 (
        echo [WARNING] Could not retrieve model list
    )
    echo.
    echo [INFO] AI Model Recommendations:
    echo Based on your system, you can download AI models:
    echo.
    echo Recommended (Security-focused^):
    echo   ollama pull xploiter/pentester
    echo.
    echo Alternative models (choose based on your system^):
    echo   ollama pull llama3.2:3b         (2GB RAM, general purpose^)
    echo   ollama pull qwen2.5:3b          (2GB RAM, alternative^)
    echo   ollama pull mistral:7b          (4GB RAM, more powerful^)
    echo   ollama pull llama3.2:1b         (1GB RAM, lightweight^)
    echo.
    echo Configure your preferred model in Web GUI after installation
    echo.
)

REM Create necessary directories
echo [INFO] Creating directories...
if not exist logs mkdir logs
if not exist reports mkdir reports
if not exist payloads mkdir payloads
echo [SUCCESS] Directories created

REM Run installation verification
echo.
echo [INFO] Running comprehensive installation verification...
echo.
python verify_installation.py
if %errorlevel% neq 0 (
    echo [WARNING] Some verification checks failed
    echo [WARNING] Please review the output above and fix any issues
) else (
    echo [SUCCESS] All verification checks passed!
)

echo.
echo ================================================================
echo    ASTRAVA Installation Completed Successfully!
echo ================================================================
echo.
echo [SUCCESS] Python dependencies installed
echo.
echo.
echo Quick Start Guide:
echo.
echo   Activate Virtual Environment:
echo     venv\Scripts\activate
echo.
echo   Launch Web GUI (Recommended):
echo     python astrava.py
echo.
echo   CLI Scans:
echo     python astrava.py -u https://example.com
echo     python astrava.py -u https://example.com --owasp-all
echo     python astrava.py -u https://example.com --owasp-all --chain-attacks
echo.
echo   Deactivate Virtual Environment:
echo     deactivate
echo.
echo   Get Help:
echo     python astrava.py --help
echo     python astrava.py --version
echo.
echo AI Configuration:
echo   - Launch the Web GUI: python astrava.py
echo   - Go to AI Model Settings
echo   - Install Ollama from https://ollama.ai
echo   - Recommended models:
echo       ollama pull xploiter/pentester  (security-focused)
echo       ollama pull llama3.2:3b         (general purpose)
echo.
echo Note: Virtual environment is activated automatically
echo    To manually activate: venv\Scripts\activate
echo    To deactivate: deactivate
echo.
echo IMPORTANT: Only scan systems you own or have permission to test!
echo.
echo For detailed documentation, see README.md
echo.

pause
