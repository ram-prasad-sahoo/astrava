<div align="center">

<img src="logo.png" alt="Astrava Logo" width="200"/>

# 🛡️ Astrava AI Security Scanner

### *Advanced AI-Powered Web Vulnerability Scanner*

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010%202021-red?style=for-the-badge&logo=owasp&logoColor=white)](https://owasp.org/)
[![AI](https://img.shields.io/badge/AI-Ollama%20Powered-green?style=for-the-badge&logo=ai&logoColor=white)](https://ollama.ai/)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=for-the-badge)](https://github.com/ram-prasad-sahoo/astrava)

**Professional-grade security testing tool for penetration testers and security researchers**

[🚀 Quick Start](#-quick-start) • [📖 Documentation](#-documentation) • [🤝 Contributing](#-contributing) • [⭐ Star Us](https://github.com/ram-prasad-sahoo/astrava)

</div>

---

## 🌟 Overview

**Astrava** is a cutting-edge web security scanner that seamlessly combines traditional vulnerability detection with AI-powered analysis using local Ollama models. Built for security professionals who value both power and privacy.

### ✨ Key Features

<table>
<tr>
<td width="50%">

#### 🤖 **AI-Powered Analysis**
- Local Ollama integration
- Privacy-focused processing
- No cloud dependencies
- Multiple model support

#### 🛡️ **OWASP Top 10 2021**
- Complete coverage
- A01 to A10 categories
- Real-world attack scenarios
- Professional reporting

</td>
<td width="50%">

#### 🌐 **Modern Web Interface**
- Real-time vulnerability feed
- Live scan statistics
- Intuitive dashboard
- Dark theme UI

#### ⚡ **Smart & Fast**
- Intelligent payload caching
- Multi-threaded scanning
- Optimized performance
- Quick scan modes

</td>
</tr>
</table>

### 🎯 Why Choose Astrava?

```
✓ Privacy First      → All AI processing happens locally on your machine
✓ One Command        → Unified interface for both GUI and CLI modes
✓ Cross-Platform     → Works seamlessly on Windows, Linux, and macOS
✓ Professional       → Enterprise-grade reports with remediation guidance
✓ Open Source        → MIT License, free forever
✓ Easy Setup         → One-command installation, ready in minutes
```

---

## 🚀 Quick Start

### 📦 Installation

<details open>
<summary><b>🪟 Windows</b></summary>

```bash
git clone https://github.com/ram-prasad-sahoo/astrava.git
cd astrava
install.bat
```

**Note**: The installer automatically creates a Python virtual environment and installs all dependencies.

</details>

<details>
<summary><b>🐧 Linux</b></summary>

```bash
git clone https://github.com/ram-prasad-sahoo/astrava.git
cd astrava
chmod +x install.sh
./install.sh
```

**Note**: The installer automatically creates a Python virtual environment and installs all dependencies.

</details>

<details>
<summary><b>🍎 macOS</b></summary>

```bash
git clone https://github.com/ram-prasad-sahoo/astrava.git
cd astrava
chmod +x install.sh
./install.sh
```

**Note**: The installer automatically creates a Python virtual environment and installs all dependencies.

</details>

### 🎮 Launch Application

#### 🌐 Web GUI Mode (Recommended)

```bash
python astrava.py
```

Then open your browser at: **http://localhost:5000**

#### 💻 CLI Mode

```bash
# Basic scan
python astrava.py -u https://example.com

# Full OWASP Top 10 scan
python astrava.py -u https://example.com --owasp-all

# Aggressive scan with chain attacks
python astrava.py -u https://example.com --owasp-all --chain-attacks

# Get help
python astrava.py --help
```

---

## 💻 System Requirements

### Minimum Requirements

<table>
<tr>
<td width="50%">

#### 🖥️ **Hardware**
- **CPU**: Dual-core processor (2 GHz+)
- **RAM**: 4 GB minimum
  - 2 GB for Astrava
  - 2 GB for AI models (if using Ollama)
- **Storage**: 5 GB free space
  - 500 MB for Astrava
  - 2-4 GB for AI models
- **Network**: Internet connection required

</td>
<td width="50%">

#### 💿 **Software**
- **OS**: Windows 10+, Linux, macOS 10.15+
- **Python**: 3.8 or higher
- **Browser**: Modern browser (Chrome, Firefox, Edge)
- **Ollama**: Optional (for AI features)
- **Git**: For installation from source

</td>
</tr>
</table>

### Recommended Requirements

<table>
<tr>
<td width="50%">

#### 🚀 **For Best Performance**
- **CPU**: Quad-core processor (3 GHz+)
- **RAM**: 8 GB or more
- **Storage**: 10 GB free space
- **Network**: Broadband connection

</td>
<td width="50%">

#### 🤖 **For AI Features**
- **RAM**: 
  - 2 GB: llama3.2:1b (lightweight)
  - 4 GB: llama3.2:3b (balanced)
  - 8 GB: mistral:7b (powerful)
- **Ollama**: Latest version
- **GPU**: Optional (speeds up AI)

</td>
</tr>
</table>

### Supported Platforms

| Platform | Versions | Status | Notes |
|:--------:|:---------|:------:|:------|
| 🪟 **Windows** | 10, 11, Server 2019+ | ✅ Fully Supported | Use install.bat |
| 🐧 **Linux** | Ubuntu 20.04+, Debian 10+, Fedora 35+, Arch, Kali | ✅ Fully Supported | Use install.sh |
| 🍎 **macOS** | 10.15+ (Catalina and later) | ✅ Fully Supported | Intel & Apple Silicon |

---

## 📋 Software Requirements

| Component | Version | Required | Notes |
|-----------|---------|----------|-------|
| 🐍 **Python** | 3.8+ | ✅ Yes | Core runtime |
| 🌐 **Internet** | - | ✅ Yes | For scanning targets |
| 🤖 **Ollama** | Latest | ⚠️ Optional | For AI features |

### 🤖 AI Setup (Optional but Recommended)

<details>
<summary><b>Click to expand AI setup instructions</b></summary>

#### Step 1: Install Ollama

- **Windows**: Download from [ollama.ai](https://ollama.ai)
- **Linux**: `curl -fsSL https://ollama.ai/install.sh | sh`
- **macOS**: `brew install ollama`

#### Step 2: Download AI Model

Choose based on your system resources:

```bash
# 🎯 Recommended (Security-focused)
ollama pull xploiter/pentester

# 💡 Alternatives
ollama pull llama3.2:1b    # 1GB RAM - Lightweight
ollama pull llama3.2:3b    # 2GB RAM - Balanced
ollama pull qwen2.5:3b     # 2GB RAM - Alternative
ollama pull mistral:7b     # 4GB RAM - Powerful
```

#### Step 3: Configure in Astrava

1. Launch: `python astrava.py`
2. Navigate to **AI Model Settings**
3. Select your downloaded model
4. Click **Save Settings**

✅ Done! AI-powered scanning is now active.

</details>

---

## 🎚️ Scan Modes

<table>
<thead>
<tr>
<th width="20%">Mode</th>
<th width="30%">Description</th>
<th width="15%">Duration</th>
<th width="35%">Best For</th>
</tr>
</thead>
<tbody>
<tr>
<td><b>⚡ Basic</b></td>
<td>Fast scan, core vulnerabilities</td>
<td>1-3 min</td>
<td>Quick security assessment</td>
</tr>
<tr>
<td><b>🎯 Standard</b></td>
<td>OWASP Top 10 + vulnerability scan</td>
<td>5-15 min</td>
<td>Regular security testing</td>
</tr>
<tr>
<td><b>🔥 Aggressive</b></td>
<td>Full scan + chain attacks + deep AI</td>
<td>15-45 min</td>
<td>Comprehensive security audit</td>
</tr>
</tbody>
</table>

---

## 🛡️ OWASP Top 10 Coverage

<div align="center">

| # | Category | Tests Included | Status |
|:-:|----------|----------------|:------:|
| **A01** | 🔓 Broken Access Control | IDOR, Path Traversal, Forced Browsing | ✅ |
| **A02** | 🔐 Cryptographic Failures | SSL/TLS, Weak Ciphers, Sensitive Data | ✅ |
| **A03** | 💉 Injection | SQL, NoSQL, LDAP, Command, XSS | ✅ |
| **A04** | 🎨 Insecure Design | Debug Info, Business Logic Flaws | ✅ |
| **A05** | ⚙️ Security Misconfiguration | Headers, Default Creds, Error Handling | ✅ |
| **A06** | 📦 Vulnerable Components | Version Detection, CVE Matching | ✅ |
| **A07** | 🔑 Authentication Failures | Cookie Security, Session Management | ✅ |
| **A08** | 🔗 Software & Data Integrity | Deserialization, Supply Chain | ✅ |
| **A09** | 📊 Logging & Monitoring | Logging Gap Assessment | ✅ |
| **A10** | 🌐 SSRF | Cloud Metadata, Internal Services | ✅ |

</div>

---

## 🔧 Advanced Usage

### 📝 Command-Line Options

```bash
python astrava.py --help
```

<details>
<summary><b>View all available options</b></summary>

#### 🎯 Basic Options
- **No arguments** → Launch Web GUI (default)
- `-u, --url URL` → Target URL for CLI scan
- `--version` → Show version information
- `--help` → Display help message

#### 🔍 Scan Options
- `--owasp-all` → Test all OWASP Top 10 categories
- `--chain-attacks` → Enable multi-step attack detection
- `--passive-only` → Passive reconnaissance only
- `--active-only` → Active scanning only

#### ⚙️ Configuration
- `--model MODEL` → AI model to use (default: xploiter/pentester)
- `--threads N` → Concurrent threads (default: 10)
- `--timeout SEC` → Request timeout (default: 30)
- `--custom-payloads FILE` → Custom payload file

#### 📊 Output Options
- `-o, --output DIR` → Output directory for reports
- `--format FORMAT` → Report format (html, json, pdf)
- `-v, --verbose` → Enable detailed logging

</details>

### 🎯 Usage Examples

```bash
# 🌐 Launch Web GUI
python astrava.py

# ⚡ Quick scan
python astrava.py -u https://example.com

# 🎯 Standard OWASP scan
python astrava.py -u https://example.com --owasp-all

# 🔥 Aggressive scan with all features
python astrava.py -u https://example.com --owasp-all --chain-attacks --verbose

# 🔍 Passive reconnaissance only
python astrava.py -u https://example.com --passive-only

# 🎨 Custom payloads
python astrava.py -u https://example.com --custom-payloads payloads/custom.txt

# 📊 JSON output with 20 threads
python astrava.py -u https://example.com --format json --threads 20
```

---

## 📊 Reports

Reports are automatically saved to the `reports/` directory with:

<table>
<tr>
<td width="50%">

### 📈 **Report Contents**
- ✅ Executive Summary
- ✅ Risk Score (0-100)
- ✅ Vulnerability Breakdown
- ✅ Detailed Findings
- ✅ AI-Generated Analysis
- ✅ Remediation Guidance

</td>
<td width="50%">

### 🎨 **Report Features**
- 🌐 Professional HTML format
- 📊 Visual charts and graphs
- 🎯 Severity classification
- 🔗 CWE references
- 📝 OWASP mapping
- 💡 Fix recommendations

</td>
</tr>
</table>

---

## 📁 Project Structure

```
astrava/
├── 🎯 astrava.py                 # MAIN ENTRY POINT (GUI + CLI)
├── 🌐 web_gui.py                 # Flask web server backend
├── 💻 main.py                    # Legacy CLI entry point
│
├── 🧠 core/
│   ├── ai_engine.py              # AI engine with streaming
│   ├── scanner_engine.py         # Main scan orchestrator
│   └── config.py                 # Scan configuration
│
├── 🔍 modules/
│   ├── vulnerability_scanner.py  # Core vulnerability detection
│   ├── owasp_scanner.py          # OWASP Top 10 tests
│   ├── reconnaissance.py         # Passive/active recon
│   └── chain_attacks.py          # Attack chain analysis
│
├── 🛠️ utils/
│   ├── model_manager.py          # AI routing
│   ├── ollama_manager.py         # Ollama lifecycle
│   ├── config_store.py           # Encrypted config
│   └── report_generator.py       # HTML reports
│
├── 🎨 templates/
│   └── index.html                # Web GUI template
│
├── 📦 Installation
│   ├── install.bat               # Windows installer
│   ├── install.sh                # Linux/macOS installer
│   ├── requirements.txt          # Python dependencies
│   └── verify_installation.py   # Installation check
│
└── 📖 Documentation
    ├── README.md                 # This file
    └── LICENSE                   # MIT License
```

---

## 🌍 Cross-Platform Support

<div align="center">

| Platform | Status | Tested Versions |
|:--------:|:------:|:----------------|
| 🪟 **Windows** | ✅ Fully Supported | 10, 11, Server 2019+ |
| 🐧 **Linux** | ✅ Fully Supported | Ubuntu 20.04+, Debian 10+, Fedora 35+, Arch, Kali |
| 🍎 **macOS** | ✅ Fully Supported | 10.15+ (Intel & Apple Silicon) |

</div>

---

## 🚀 Performance

<table>
<tr>
<td align="center" width="33%">
<h3>⚡ Fast</h3>
Multi-threaded scanning<br/>
Smart payload caching<br/>
Optimized algorithms
</td>
<td align="center" width="33%">
<h3>🎯 Accurate</h3>
Low false positives<br/>
AI-powered validation<br/>
Real-world attack scenarios
</td>
<td align="center" width="33%">
<h3>🔒 Secure</h3>
Local AI processing<br/>
No data leakage<br/>
Privacy-focused design
</td>
</tr>
</table>

---

## 📚 Documentation

### 🎓 Quick Reference

| Command | Description |
|---------|-------------|
| `python astrava.py` | Launch Web GUI |
| `python astrava.py -u <URL>` | CLI scan mode |
| `python astrava.py --help` | Show help |
| `python astrava.py --version` | Show version |
| `python verify_installation.py` | Verify installation |

### 📖 Additional Resources

- 🌐 [GitHub Repository](https://github.com/ram-prasad-sahoo/astrava)
- 📧 [Email Support](mailto:ramprasadsahoo42@gmail.com)
- 🐛 [Report Issues](https://github.com/ram-prasad-sahoo/astrava/issues)
- ⭐ [Star on GitHub](https://github.com/ram-prasad-sahoo/astrava)

---

## ⚠️ Legal Disclaimer

<div align="center">

### 🚨 **IMPORTANT: READ BEFORE USE** 🚨

</div>

> **This tool is designed for AUTHORIZED SECURITY TESTING ONLY.**

#### ✅ Permitted Use
- ✓ Testing systems you **own**
- ✓ Testing with **explicit written permission**
- ✓ Educational purposes in **controlled environments**
- ✓ Security research with **proper authorization**

#### ❌ Prohibited Use
- ✗ Unauthorized scanning of third-party systems
- ✗ Malicious activities or attacks
- ✗ Violating computer crime laws (CFAA, GDPR, etc.)
- ✗ Any illegal or unethical activities

#### 📜 Your Responsibilities
- Obtain proper authorization before scanning
- Comply with all applicable laws and regulations
- Use the tool ethically and responsibly
- Respect privacy and data protection laws

**By using this tool, you agree to use it responsibly and legally. The authors assume NO LIABILITY for misuse or damages.**

---

## 🤝 Contributing

We welcome contributions from the community! Here's how you can help:

<table>
<tr>
<td align="center" width="25%">
<h3>🐛</h3>
<b>Report Bugs</b><br/>
Found a bug?<br/>
<a href="https://github.com/ram-prasad-sahoo/astrava/issues">Open an issue</a>
</td>
<td align="center" width="25%">
<h3>💡</h3>
<b>Suggest Features</b><br/>
Have an idea?<br/>
<a href="https://github.com/ram-prasad-sahoo/astrava/issues">Share it with us</a>
</td>
<td align="center" width="25%">
<h3>🔧</h3>
<b>Submit PRs</b><br/>
Want to code?<br/>
<a href="https://github.com/ram-prasad-sahoo/astrava/pulls">Create a pull request</a>
</td>
<td align="center" width="25%">
<h3>⭐</h3>
<b>Star the Repo</b><br/>
Like the project?<br/>
<a href="https://github.com/ram-prasad-sahoo/astrava">Give us a star!</a>
</td>
</tr>
</table>

### 🔄 Contribution Process

1. 🍴 Fork the repository
2. 🌿 Create a feature branch (`git checkout -b feature/amazing-feature`)
3. ✍️ Commit your changes (`git commit -m 'Add amazing feature'`)
4. 📤 Push to the branch (`git push origin feature/amazing-feature`)
5. 🎉 Open a Pull Request

---

## 📝 License

<div align="center">

**MIT License** - Free and Open Source

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](LICENSE)

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

</div>

---

## 👤 Author

<div align="center">

### **RAM (Ram Prasad Sahoo)**

[![GitHub](https://img.shields.io/badge/GitHub-ram--prasad--sahoo-181717?style=for-the-badge&logo=github)](https://github.com/ram-prasad-sahoo)
[![Email](https://img.shields.io/badge/Email-ramprasadsahoo42%40gmail.com-D14836?style=for-the-badge&logo=gmail&logoColor=white)](mailto:ramprasadsahoo42@gmail.com)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Ram%20Prasad%20Sahoo-0077B5?style=for-the-badge&logo=linkedin)](https://linkedin.com/in/ram-prasad-sahoo)

</div>

---

## 🙏 Acknowledgments

<div align="center">

Special thanks to:

🛡️ **OWASP Foundation** - For security testing guidelines  
🤖 **Ollama Team** - For local AI infrastructure  
🌟 **Open Source Community** - For inspiration and support  
💻 **Contributors** - For making this project better

</div>

---

## 📊 Project Stats

<div align="center">

![GitHub stars](https://img.shields.io/github/stars/ram-prasad-sahoo/astrava?style=social)
![GitHub forks](https://img.shields.io/github/forks/ram-prasad-sahoo/astrava?style=social)
![GitHub watchers](https://img.shields.io/github/watchers/ram-prasad-sahoo/astrava?style=social)

</div>

---

<div align="center">

### 🌟 **If you find Astrava useful, please consider giving it a star!** ⭐

[![Star History Chart](https://api.star-history.com/svg?repos=ram-prasad-sahoo/astrava&type=Date)](https://star-history.com/#ram-prasad-sahoo/astrava&Date)

---

**Made with ❤️ by [Ram Prasad Sahoo](https://github.com/ram-prasad-sahoo)**

**Happy Ethical Hacking! 🛡️**

</div>

---

<div align="center">

*Last Updated: April 2026 • Version 1.1.0*

</div>
