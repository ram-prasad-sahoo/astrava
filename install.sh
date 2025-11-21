#!/bin/bash

# Astrava AI Security Scanner Installation Script
# Supports Linux and macOS

set -e

echo "🛡️  ASTRAVA AI SECURITY SCANNER - Installation"
echo "================================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   print_error "This script should not be run as root for security reasons"
   exit 1
fi

# Detect OS
OS="unknown"
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
else
    print_error "Unsupported operating system: $OSTYPE"
    exit 1
fi

print_status "Detected OS: $OS"

# Check Python version
check_python() {
    print_status "Checking Python installation..."
    
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
        PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d'.' -f1)
        PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d'.' -f2)
        
        if [[ $PYTHON_MAJOR -eq 3 && $PYTHON_MINOR -ge 8 ]]; then
            print_success "Python $PYTHON_VERSION found"
            PYTHON_CMD="python3"
        else
            print_error "Python 3.8+ required, found $PYTHON_VERSION"
            exit 1
        fi
    else
        print_error "Python 3 not found. Please install Python 3.8+"
        exit 1
    fi
}

# Check pip
check_pip() {
    print_status "Checking pip installation..."
    
    if command -v pip3 &> /dev/null; then
        print_success "pip3 found"
        PIP_CMD="pip3"
    elif command -v pip &> /dev/null; then
        print_success "pip found"
        PIP_CMD="pip"
    else
        print_error "pip not found. Please install pip"
        exit 1
    fi
}

# Install Python dependencies
install_python_deps() {
    print_status "Installing Python dependencies..."
    
    if [[ -f "requirements.txt" ]]; then
        $PIP_CMD install -r requirements.txt
        print_success "Python dependencies installed"
    else
        print_error "requirements.txt not found"
        exit 1
    fi
}

# Install Ollama
install_ollama() {
    print_status "Checking Ollama installation..."
    
    if command -v ollama &> /dev/null; then
        print_success "Ollama already installed"
        return 0
    fi
    
    print_status "Installing Ollama..."
    
    if [[ "$OS" == "linux" ]]; then
        curl -fsSL https://ollama.ai/install.sh | sh
    elif [[ "$OS" == "macos" ]]; then
        if command -v brew &> /dev/null; then
            brew install ollama
        else
            print_warning "Homebrew not found. Please install Ollama manually from https://ollama.ai"
            return 1
        fi
    fi
    
    print_success "Ollama installed"
}

# Start Ollama service
start_ollama() {
    print_status "Starting Ollama service..."
    
    # Check if Ollama is already running
    if pgrep -x "ollama" > /dev/null; then
        print_success "Ollama is already running"
        return 0
    fi
    
    # Start Ollama in background
    if [[ "$OS" == "linux" ]]; then
        nohup ollama serve > /dev/null 2>&1 &
        sleep 3
    elif [[ "$OS" == "macos" ]]; then
        brew services start ollama
        sleep 3
    fi
    
    # Verify Ollama is running
    if curl -s http://localhost:11434/api/tags > /dev/null; then
        print_success "Ollama service started"
    else
        print_error "Failed to start Ollama service"
        return 1
    fi
}

# Download LLaMA model
download_model() {
    print_status "Checking LLaMA 3.2:3b model..."
    
    # Check if model already exists
    if ollama list 2>/dev/null | grep -q "llama3.2:3b"; then
        print_success "LLaMA 3.2:3b model already installed"
        return 0
    fi
    
    print_warning "LLaMA 3.2:3b model not found"
    print_status "Downloading LLaMA 3.2:3b model..."
    print_status "This will download approximately 2GB of data. Please wait..."
    echo
    
    # Download model
    ollama pull llama3.2:3b
    
    if [[ $? -eq 0 ]]; then
        print_success "LLaMA 3.2:3b model downloaded successfully"
    else
        print_error "Failed to download LLaMA model"
        print_error "Please try manually: ollama pull llama3.2:3b"
        return 1
    fi
}

# Create directories
create_directories() {
    print_status "Creating necessary directories..."
    
    mkdir -p logs
    mkdir -p reports
    mkdir -p payloads
    
    print_success "Directories created"
}

# Set permissions
set_permissions() {
    print_status "Setting file permissions..."
    
    chmod +x main.py
    chmod +x install.sh
    
    print_success "Permissions set"
}

# Verify installation
verify_installation() {
    echo
    print_status "Running comprehensive installation verification..."
    echo
    
    # Run the verification script
    $PYTHON_CMD verify_installation.py
    
    if [[ $? -eq 0 ]]; then
        print_success "All verification checks passed!"
        return 0
    else
        print_warning "Some verification checks failed"
        print_warning "Please review the output above and fix any issues"
        return 1
    fi
}

# Main installation process
main() {
    echo
    print_status "Starting Astrava AI Security Scanner installation..."
    echo
    
    # Check system requirements
    check_python
    check_pip
    
    # Install dependencies
    install_python_deps
    
    # Install and configure Ollama
    install_ollama
    start_ollama
    download_model
    
    # Setup project
    create_directories
    set_permissions
    
    # Verify everything works
    verify_installation
    
    echo
    print_success "🎉 ASTRAVA Installation Completed Successfully!"
    echo
    echo "✅ All components verified and working correctly!"
    echo
    echo "📋 Quick Start Guide:"
    echo
    echo "  Launch GUI:"
    echo "    $PYTHON_CMD astrava_gui.py"
    echo "    $PYTHON_CMD astrava.py"
    echo
    echo "  CLI Scans:"
    echo "    $PYTHON_CMD astrava.py -u https://httpbin.org --basic"
    echo "    $PYTHON_CMD astrava.py -u https://httpbin.org"
    echo "    $PYTHON_CMD astrava.py -u https://httpbin.org --aggressive"
    echo
    echo "  Verify Installation Anytime:"
    echo "    $PYTHON_CMD verify_installation.py"
    echo
    echo "  Get Help:"
    echo "    $PYTHON_CMD astrava.py --help"
    echo "    $PYTHON_CMD main.py --help"
    echo
    echo "⚠️  IMPORTANT: Only scan systems you own or have permission to test!"
    echo
    echo "📖 For detailed documentation, see README.md"
    echo
}

# Handle interruption
trap 'print_error "Installation interrupted"; exit 1' INT

# Run main installation
main

exit 0
