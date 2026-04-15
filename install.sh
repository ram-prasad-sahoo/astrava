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

# Install Ollama (optional)
install_ollama() {
    print_status "Checking Ollama installation (optional for AI features)..."
    
    if command -v ollama &> /dev/null; then
        print_success "Ollama already installed"
        return 0
    fi
    
    print_warning "Ollama not found"
    echo
    echo "Ollama is optional for AI-powered analysis."
    echo
    read -p "Install Ollama now? (y/n): " -n 1 -r
    echo
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_warning "Skipping Ollama installation"
        print_status "You can install it later from: https://ollama.ai"
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
            return 0
        fi
    fi
    
    print_success "Ollama installed"
}

# Start Ollama service (if installed)
start_ollama() {
    if ! command -v ollama &> /dev/null; then
        print_warning "Ollama not installed - skipping service start"
        return 0
    fi
    
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
        brew services start ollama 2>/dev/null || nohup ollama serve > /dev/null 2>&1 &
        sleep 3
    fi
    
    # Verify Ollama is running
    if curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
        print_success "Ollama service started"
    else
        print_warning "Ollama service may not be running - you can start it manually with: ollama serve"
    fi
}

# List available models (if Ollama is installed)
list_models() {
    if ! command -v ollama &> /dev/null; then
        return 0
    fi
    
    print_status "Checking available AI models..."
    
    if ollama list 2>/dev/null | grep -q "NAME"; then
        echo
        ollama list 2>/dev/null
        echo
    else
        print_warning "No AI models found"
        echo
        echo "AI Model Recommendations:"
        echo "Based on your system, you can download AI models:"
        echo
        echo "Recommended (Security-focused):"
        echo "  ollama pull xploiter/pentester"
        echo
        echo "Alternative models (choose based on your system):"
        echo "  ollama pull llama3.2:3b         (2GB RAM, general purpose)"
        echo "  ollama pull qwen2.5:3b          (2GB RAM, alternative)"
        echo "  ollama pull mistral:7b          (4GB RAM, more powerful)"
        echo "  ollama pull llama3.2:1b         (1GB RAM, lightweight)"
        echo
        echo "Configure your preferred model in Web GUI after installation"
        echo
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
    
    # Install and configure Ollama (optional)
    install_ollama
    start_ollama
    list_models
    
    # Setup project
    create_directories
    set_permissions
    
    echo
    print_success "🎉 ASTRAVA Installation Completed Successfully!"
    echo
    echo "✅ Python dependencies installed"
    echo
    echo "📋 Quick Start Guide:"
    echo
    echo "  Launch Web GUI (Recommended):"
    echo "    $PYTHON_CMD astrava.py"
    echo
    echo "  CLI Scans:"
    echo "    $PYTHON_CMD astrava.py -u https://example.com"
    echo "    $PYTHON_CMD astrava.py -u https://example.com --owasp-all"
    echo "    $PYTHON_CMD astrava.py -u https://example.com --owasp-all --chain-attacks"
    echo
    echo "  Get Help:"
    echo "    $PYTHON_CMD astrava.py --help"
    echo "    $PYTHON_CMD astrava.py --version"
    echo
    echo "🤖 AI Configuration:"
    echo "  - Launch the Web GUI: $PYTHON_CMD astrava.py"
    echo "  - Go to AI Model Settings"
    echo "  - Install Ollama from https://ollama.ai"
    echo "  - Recommended models:"
    echo "      ollama pull xploiter/pentester  (security-focused)"
    echo "      ollama pull llama3.2:3b         (general purpose)"
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
