<div align="center">

![Astrava Logo](logo.png)

# ASTRAVA AI Security Scanner

### Professional AI-Powered Web Application Security Testing Platform

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-Proprietary-red.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-v1.0.0-orange.svg)](https://github.com/ram-prasad-sahoo/astrava)

**Enterprise-grade security scanner combining traditional penetration testing with AI analysis**

</div>

---

## 📖 Table of Contents

- [What is ASTRAVA?](#-what-is-astrava)
- [Key Features](#-key-features)
- [System Requirements](#-system-requirements)
- [Installation](#-installation)
- [How to Run](#-how-to-run)
- [Usage Examples](#-usage-examples)
- [Scan Modes](#-scan-modes)
- [Troubleshooting](#-troubleshooting)
- [Help & Support](#-help--support)
- [Legal Notice](#️-legal-notice)
- [Author](#-author)
- [License](#-license)
- [Acknowledgments](#-acknowledgments)
- [Share & Promote](#-share--promote)

---

## 🎯 What is ASTRAVA?

**ASTRAVA** (Advanced Security Testing & Risk Assessment with Vulnerability Analysis) is a professional-grade AI-powered web application security scanner designed for:

- 🔒 **Security Professionals** - Comprehensive penetration testing
- 👨‍💻 **Developers** - Pre-deployment security checks
- 🏢 **Organizations** - Regular security assessments
- 🎓 **Students** - Learning security testing

### Why Choose ASTRAVA?

ASTRAVA combines traditional vulnerability scanning with cutting-edge AI technology to provide:

✅ **Intelligent Analysis** - AI-powered vulnerability detection using LLaMA 3.2  
✅ **OWASP Coverage** - Complete OWASP Top 10 2021 testing  
✅ **Multiple Modes** - Basic, Medium, and Aggressive scanning  
✅ **Detailed Reports** - Beautiful HTML reports with risk scoring  
✅ **Easy to Use** - Simple installation and intuitive interface  

---

## ✨ Key Features

### 🤖 AI-Powered Intelligence

- **LLaMA 3.2 Integration** - Advanced AI model for intelligent vulnerability analysis
- **Smart Payload Generation** - Context-aware exploit payloads
- **Chain Attack Detection** - Identifies multi-step exploitation paths
- **Risk Assessment** - AI-driven vulnerability prioritization
- **Executive Summaries** - Business impact analysis

### 🔍 Comprehensive Testing

**OWASP Top 10 2021 Coverage:**

| # | Category | Tests Included |
|---|----------|----------------|
| A01 | Broken Access Control | IDOR, Path Traversal, Privilege Escalation |
| A02 | Cryptographic Failures | Weak SSL/TLS, Insecure Protocols |
| A03 | Injection | SQL, NoSQL, Command, LDAP, XXE |
| A04 | Insecure Design | Business Logic Flaws |
| A05 | Security Misconfiguration | Default Credentials, Unnecessary Features |
| A06 | Vulnerable Components | Outdated Software Detection |
| A07 | Authentication Failures | Weak Passwords, Session Issues |
| A08 | Data Integrity Failures | Deserialization Attacks |
| A09 | Logging Failures | Security Event Analysis |
| A10 | SSRF | Server-Side Request Forgery |

### 🎨 Professional Interface

- **Modern GUI** - Burp Suite-inspired blue-gray theme
- **Real-time Monitoring** - Live vulnerability detection
- **Color-coded Severity** - Critical (Red), High (Orange), Medium (Yellow), Low (Blue)
- **Multiple Views** - Console, Vulnerabilities, Summary, AI Analysis
- **Export Options** - HTML and JSON reports

---

## 💻 System Requirements

### Minimum Requirements

- **Operating System**: 
  - Windows 10/11
  - Linux: Ubuntu 20.04+, Kali Linux, Parrot OS, Debian, Fedora, Arch
  - macOS 11+
- **Python**: 3.8 or higher
- **RAM**: 4GB minimum
- **Storage**: 5GB free space
- **Internet**: Required for initial setup

### ✅ Tested On

ASTRAVA has been tested and works perfectly on:
- ✅ **Kali Linux** (2023.x and later)
- ✅ **Parrot Security OS** (5.x and later)
- ✅ **Ubuntu** (20.04, 22.04, 24.04)
- ✅ **Debian** (11, 12)
- ✅ **Windows** (10, 11)
- ✅ **macOS** (11+)

### Recommended Specifications

- **RAM**: 8GB or more
- **CPU**: Multi-core processor (4+ cores)
- **Storage**: 10GB free space
- **Internet**: Stable connection

---

## 🚀 Installation

### Quick Install (Recommended)

**Step 1: Clone the Repository**
```bash
git clone https://github.com/ram-prasad-sahoo/astrava.git
cd astrava
```

**Step 2: Run the Installer**

**Windows:**
```bash
# Run the automated installer
install.bat
```

**Linux/macOS:**
```bash
# Make installer executable
chmod +x install.sh

# Run installer
./install.sh
```

The installer will automatically:
- ✅ Check Python 3.8+
- ✅ Install all dependencies
- ✅ Install Ollama + LLaMA 3.2:3b
- ✅ Create necessary directories
- ✅ Verify installation

### Manual Installation

**Step 1: Install Python**
- Download Python 3.8+ from [python.org](https://python.org)
- Make sure to check "Add Python to PATH"

**Step 2: Install Dependencies**
```bash
pip install -r requirements.txt
```

**Step 3: Install Ollama**

**Windows:**
- Download from [ollama.ai](https://ollama.ai)
- Run the installer

**Linux (Ubuntu/Debian/Kali/Parrot):**
```bash
curl -fsSL https://ollama.ai/install.sh | sh
```

**Kali Linux / Parrot OS (Alternative):**
```bash
# If above doesn't work, use:
sudo apt update
sudo apt install curl
curl -fsSL https://ollama.ai/install.sh | sudo sh
```

**macOS:**
```bash
brew install ollama
```

**Step 4: Download AI Model**
```bash
ollama pull llama3.2:3b
```

**Step 5: Verify Installation**
```bash
python verify_installation.py
```

---

## 🎮 How to Run

### GUI Mode (Recommended)

**Launch Professional GUI:**
```bash
python astrava_gui.py
```

Or use the main launcher:
```bash
python astrava.py
```

**GUI Features:**
- 📊 Real-time vulnerability statistics
- 🔍 Live console output
- 📈 Interactive vulnerability tree
- 🤖 AI analysis dashboard

### CLI Mode

**Basic Commands:**
```bash
# Show help
python astrava.py --help

# Basic scan (Fast)
python astrava.py -u https://example.com --basic

# Medium scan (Standard)
python astrava.py -u https://example.com

# Aggressive scan (Thorough)
python astrava.py -u https://example.com --aggressive
```

**Advanced Commands:**
```bash
# Full OWASP testing
python main.py -u https://example.com --owasp-all

# Chain attack detection
python main.py -u https://example.com --chain-attacks

# Custom payloads
python main.py -u https://example.com --custom-payloads payloads.txt

# Verbose output with JSON report
python main.py -u https://example.com --verbose --format json
```

---

## 📊 Usage Examples

### Example 1: Quick Security Check

```bash
# Fast scan for quick assessment
python astrava.py -u http://testphp.vulnweb.com/ --basic
```

**Use Case:** Quick initial assessment before detailed testing

### Example 2: Standard Security Assessment

```bash
# Medium scan with OWASP Top 10
python astrava.py -u http://demo.testfire.net/
```

**Use Case:** Regular security testing and compliance checks

### Example 3: Thorough Security Audit

```bash
# Aggressive scan with all features
python astrava.py -u https://example.com --aggressive --verbose
```

**Use Case:** Pre-production security audit and penetration testing

### Example 4: Custom Testing

```bash
# Advanced scan with custom payloads
python main.py -u https://example.com --owasp-all --chain-attacks \
               --custom-payloads payloads/custom.txt --threads 20
```

**Use Case:** Specialized testing with custom attack vectors

### Test Targets (For Practice)

```bash
# Vulnerable PHP application
python astrava.py -u http://testphp.vulnweb.com/

# Banking demo application
python astrava.py -u http://demo.testfire.net/

# HTTP testing service
python astrava.py -u https://httpbin.org/
```

---

## 🎯 Scan Modes

### ⚡ Basic Scan

**Duration:** Fast scan

**Features:**
- Fast vulnerability detection
- Common security issues
- OWASP Top 10: OFF by default
- Chain Attacks: Not available

**Best For:**
- Quick initial assessment
- Time-sensitive scans
- Basic security checks

**Command:**
```bash
python astrava.py -u <URL> --basic
```

### 🔍 Medium Scan (Default)

**Duration:** Standard scan

**Features:**
- Comprehensive OWASP Top 10 testing
- AI-powered vulnerability analysis
- OWASP Top 10: ON by default
- Chain Attacks: Optional

**Best For:**
- Standard security assessment
- Regular testing
- Compliance checks

**Command:**
```bash
python astrava.py -u <URL>
```

### 🔥 Aggressive Scan

**Duration:** Thorough scan

**Features:**
- Deep penetration testing
- AI chain attack detection
- OWASP Top 10: ON by default
- Chain Attacks: ON by default

**Best For:**
- Thorough security audit
- Pre-production testing
- Penetration testing

**Command:**
```bash
python astrava.py -u <URL> --aggressive
```

---

## 🔧 Troubleshooting

### Common Issues and Solutions

#### Issue 1: Python Not Found

**Problem:** `python: command not found`

**Solution:**
```bash
# Windows: Reinstall Python and check "Add to PATH"
# Linux/Mac: Install Python 3
sudo apt install python3  # Ubuntu/Debian
brew install python3      # macOS
```

#### Issue 2: Ollama Not Starting

**Problem:** Ollama service won't start

**Solution:**
```bash
# Start Ollama manually
ollama serve

# Check if running
curl http://localhost:11434/api/tags
```

#### Issue 3: LLaMA Model Not Found

**Problem:** Model download interrupted or missing

**Solution:**
```bash
# Download model again
ollama pull llama3.2:3b

# Verify installation
ollama list
```

#### Issue 4: Dependencies Installation Failed

**Problem:** pip install fails

**Solution:**
```bash
# Upgrade pip first
python -m pip install --upgrade pip

# Install dependencies again
pip install -r requirements.txt

# If specific package fails, install individually
pip install aiohttp requests dnspython beautifulsoup4
```

#### Issue 5: Permission Denied (Linux/Mac)

**Problem:** Permission errors during installation

**Solution:**
```bash
# Don't use sudo for the installer
# But you may need sudo for Ollama
curl -fsSL https://ollama.ai/install.sh | sudo sh
```

#### Issue 6: GUI Not Opening

**Problem:** GUI window doesn't appear

**Solution:**
```bash
# Check if tkinter is installed
python -c "import tkinter"

# If error, install tkinter
# Ubuntu/Debian:
sudo apt-get install python3-tk

# macOS: (usually included with Python)
brew install python-tk
```

#### Issue 7: Unicode/Encoding Errors

**Problem:** Character encoding errors in console

**Solution:**
```bash
# Set environment variable
# Windows:
set PYTHONIOENCODING=utf-8

# Linux/Mac:
export PYTHONIOENCODING=utf-8
```

#### Issue 8: Scan Hangs or Freezes

**Problem:** Scan stops responding

**Solution:**
- Reduce threads: `--threads 5`
- Increase timeout: `--timeout 60`
- Check internet connection
- Try basic scan first

### Verification

Run the verification script to check your installation:

```bash
python verify_installation.py
# or on some Linux systems:
python3 verify_installation.py
```

This will check:
- ✅ Python version
- ✅ All dependencies
- ✅ Ollama installation
- ✅ LLaMA model
- ✅ Project structure

### 🐧 Special Notes for Kali/Parrot Users

**Python Command:**
```bash
# Kali/Parrot usually use python3
python3 astrava.py --help
python3 astrava_gui.py
```

**If pip not found:**
```bash
sudo apt update
sudo apt install python3-pip
```

**If tkinter not found (for GUI):**
```bash
sudo apt install python3-tk
```

---

## �  Running on Kali Linux / Parrot OS

### Quick Start for Kali/Parrot Users

**1. Install Dependencies:**
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Python and pip (if not already installed)
sudo apt install python3 python3-pip python3-tk -y

# Install required packages
pip3 install -r requirements.txt
```

**2. Install Ollama:**
```bash
# Download and install Ollama
curl -fsSL https://ollama.ai/install.sh | sudo sh

# Start Ollama service
ollama serve &

# Download LLaMA model
ollama pull llama3.2:3b
```

**3. Run ASTRAVA:**
```bash
# Launch GUI
python3 astrava_gui.py

# Or use CLI
python3 astrava.py -u http://testphp.vulnweb.com/ --basic
```

### Kali/Parrot Specific Commands

**Check Python Version:**
```bash
python3 --version
# Should show Python 3.8 or higher
```

**Install Missing Dependencies:**
```bash
# If you get import errors
pip3 install aiohttp requests dnspython beautifulsoup4 lxml
```

**Run as Root (Not Recommended):**
```bash
# If you must run as root
sudo python3 astrava.py -u <URL>
```

**Add to PATH (Optional):**
```bash
# Add alias to .bashrc or .zshrc
echo "alias astrava='python3 ~/path/to/astrava.py'" >> ~/.bashrc
source ~/.bashrc

# Now you can run:
astrava -u <URL>
```

### Integration with Kali Tools

ASTRAVA works alongside other Kali tools:

```bash
# Use with nmap results
nmap -sV target.com -oX scan.xml
python3 astrava.py -u http://target.com

# Use with nikto
nikto -h target.com
python3 astrava.py -u http://target.com --aggressive

# Use with burpsuite
# Export targets from Burp and scan with ASTRAVA
python3 astrava.py -u http://target.com --owasp-all
```

### Performance Tips for Kali/Parrot

**Optimize for VM:**
```bash
# If running in VM, reduce threads
python3 astrava.py -u <URL> --threads 5

# Increase timeout for slow connections
python3 astrava.py -u <URL> --timeout 60
```

**Save Resources:**
```bash
# Use basic scan for quick checks
python3 astrava.py -u <URL> --basic

# Close other applications
# Allocate at least 4GB RAM to VM
```

---

## 📚 Help & Support

### Getting Help

**Command Line Help:**
```bash
# Main launcher help
python astrava.py --help

# Advanced options help
python main.py --help

# Verify installation
python verify_installation.py
```



### Contact & Support

- 📧 **Email**: ramprasadsahoo42@gmail.com
- 🐛 **Issues**: [GitHub Issues](https://github.com/ram-prasad-sahoo/astrava/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/ram-prasad-sahoo/astrava/discussions)

### Frequently Asked Questions

**Q: Is ASTRAVA free to use?**  
A: Yes, ASTRAVA is open-source and free under MIT License.

**Q: Can I use it for commercial purposes?**  
A: Yes, but only on systems you own or have permission to test.

**Q: Does it work on Windows?**  
A: Yes, ASTRAVA supports Windows, Linux, and macOS.

**Q: How much does the AI model cost?**  
A: The LLaMA model is free and runs locally via Ollama.

**Q: Can I add custom payloads?**  
A: Yes, use `--custom-payloads` option with your payload file.

**Q: Is it safe to use?**  
A: Yes, but only use on authorized systems. Unauthorized scanning is illegal.

**Q: Does it work on Kali Linux?**  
A: Yes! ASTRAVA works perfectly on Kali Linux, Parrot OS, and all Debian-based distributions.

**Q: Can I run it in a VM?**  
A: Yes, but allocate at least 4GB RAM and 10GB storage for best performance.

---

## ⚖️ Legal Notice

**⚠️ IMPORTANT: Authorized Use Only**

ASTRAVA is designed for authorized security testing and educational purposes only.

**Legal Requirements:**

✅ **DO:**
- Only scan systems you own
- Get explicit written permission before testing
- Use for educational purposes
- Follow responsible disclosure practices
- Comply with all applicable laws

❌ **DON'T:**
- Scan systems without permission
- Use for malicious purposes
- Violate computer crime laws
- Ignore terms of service
- Exploit vulnerabilities beyond proof-of-concept

**Disclaimer:**
- Users are responsible for complying with all applicable laws
- Unauthorized access to computer systems is illegal
- The developer assumes no liability for misuse
- This tool is provided "as is" without warranty

**Responsible Disclosure:**

If you discover vulnerabilities:
1. Do not exploit beyond proof-of-concept
2. Report to the system owner immediately
3. Allow reasonable time for fixes
4. Follow responsible disclosure practices

---

## 👨‍💻 Author

**Made with ❤️ by RAM**

**Developer:** Ram Prasad Sahoo  
**Email:** ramprasadsahoo42@gmail.com  
**GitHub:** [@ram-prasad-sahoo](https://github.com/ram-prasad-sahoo)

*Empowering security professionals with AI-driven vulnerability assessment*

---

## 📄 License

This project is licensed under a **Proprietary License** with the following terms:

✅ **Allowed:**
- Free to use for personal, educational, and commercial security testing
- Download and run the software
- Use on authorized systems
- **Promote, share, and recommend the software**
- **Create tutorials, reviews, and educational content**
- **Share the GitHub repository link with attribution**

❌ **Not Allowed Without Permission:**
- Modify or create derivative works
- Copy or redistribute the source code
- Sell or sublicense the software
- Claim ownership or remove attribution

📧 **For Modifications or Commercial Licensing:** Contact ramprasadsahoo42@gmail.com

🌟 **Help Us Grow:** We encourage you to share and promote ASTRAVA! Create tutorials, write reviews, or recommend it to others in the security community.

See the [LICENSE](LICENSE) file for complete terms and conditions.

---

## 🙏 Acknowledgments

- **Ollama Team** - For the amazing AI runtime
- **Meta AI** - For LLaMA models
- **OWASP** - For security testing standards
- **Security Community** - For continuous feedback

---

## 🌟 Share & Promote

**Love ASTRAVA? Help us grow!**

We encourage you to share and promote ASTRAVA with the security community:

✅ **Star the Repository** - Show your support on GitHub  
✅ **Share on Social Media** - Twitter, LinkedIn, Reddit, Discord  
✅ **Write Reviews** - Blog posts, Medium articles, YouTube videos  
✅ **Create Tutorials** - Help others learn to use ASTRAVA  
✅ **Recommend to Friends** - Share with fellow security professionals  
✅ **Include in Tool Lists** - Add to your favorite security tools collection  

**When sharing, please:**
- Give credit to Ram Prasad Sahoo
- Link to: https://github.com/ram-prasad-sahoo/astrava
- Use hashtags: #ASTRAVA #SecurityScanner #AISecurityTesting #OWASP

**Share Links:**
- 🐦 Twitter: "Check out ASTRAVA - AI-Powered Security Scanner! 🔐 https://github.com/ram-prasad-sahoo/astrava"
- 💼 LinkedIn: "Discovered an amazing AI-powered security scanner for OWASP Top 10 testing"
- 🎥 YouTube: Create installation guides, tutorials, or demo videos
- 📝 Blog: Write about your experience using ASTRAVA

Your support helps make security testing accessible to everyone! 🚀

---

---

**© 2025 RAM (Ram Prasad Sahoo). All Rights Reserved.**

This software is proprietary and protected by copyright law. Unauthorized copying, modification, distribution, or use of this software without explicit written permission from the copyright holder is strictly prohibited and may result in legal action.

**Version:** v1.0.0  
**Last Updated:** November 2025

For licensing inquiries: ramprasadsahoo42@gmail.com
