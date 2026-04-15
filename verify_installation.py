#!/usr/bin/env python3
"""
ASTRAVA AI Security Scanner - Installation Verification Script
Checks if all dependencies are properly installed
"""

import sys
import subprocess

def print_header():
    """Print verification header"""
    print("\n" + "="*70)
    print("  ASTRAVA AI SECURITY SCANNER - Installation Verification")
    print("="*70 + "\n")

def check_python_version():
    """Check Python version"""
    print("[1/6] Checking Python version...")
    version = sys.version_info
    if version.major == 3 and version.minor >= 8:
        print(f"    ✅ Python {version.major}.{version.minor}.{version.micro} (OK)")
        return True
    else:
        print(f"    ❌ Python {version.major}.{version.minor}.{version.micro} (Need 3.8+)")
        return False

def check_core_dependencies():
    """Check core Python dependencies"""
    print("\n[2/6] Checking core dependencies...")
    
    dependencies = {
        'aiohttp': 'Async HTTP client',
        'requests': 'HTTP library',
        'dns.resolver': 'DNS toolkit (dnspython)',
        'bs4': 'HTML parser (beautifulsoup4)',
        'urllib3': 'HTTP client',
    }
    
    all_ok = True
    for module, description in dependencies.items():
        try:
            __import__(module)
            print(f"    ✅ {module:20s} - {description}")
        except ImportError:
            print(f"    ❌ {module:20s} - {description} (MISSING)")
            all_ok = False
    
    return all_ok

def check_optional_dependencies():
    """Check optional dependencies"""
    print("\n[3/6] Checking optional dependencies...")
    
    optional = {
        'colorlog': 'Colored console output',
        'PIL': 'Image processing (Pillow)',
        'jinja2': 'Templating engine',
        'markdown': 'Markdown processing',
    }
    
    for module, description in optional.items():
        try:
            __import__(module)
            print(f"    ✅ {module:20s} - {description}")
        except ImportError:
            print(f"    ⚠️  {module:20s} - {description} (Optional, not installed)")

def check_ollama():
    """Check Ollama installation (optional)"""
    print("\n[4/6] Checking Ollama (optional for AI features)...")
    
    try:
        result = subprocess.run(['ollama', '--version'], 
                              capture_output=True, 
                              text=True, 
                              timeout=5)
        if result.returncode == 0:
            version = result.stdout.strip()
            print(f"    ✅ Ollama installed: {version}")
            return True
        else:
            print("    ⚠️  Ollama not responding")
            print("       Optional: Install from https://ollama.ai for AI features")
            return True  # Not critical
    except FileNotFoundError:
        print("    ⚠️  Ollama not found (optional)")
        print("       Install from https://ollama.ai for AI-powered analysis")
        return True  # Not critical
    except Exception as e:
        print(f"    ⚠️  Error checking Ollama: {e}")
        return True  # Not critical

def check_ollama_service():
    """Check if Ollama service is running (optional)"""
    print("\n[5/6] Checking Ollama service (optional)...")
    
    try:
        import requests
        response = requests.get('http://localhost:11434/api/tags', timeout=2)
        if response.status_code == 200:
            print("    ✅ Ollama service is running")
            
            # List available models
            models = response.json().get('models', [])
            if models:
                print(f"    ✅ Found {len(models)} AI model(s):")
                for model in models[:5]:  # Show first 5
                    print(f"       • {model.get('name', 'Unknown')}")
                if len(models) > 5:
                    print(f"       ... and {len(models) - 5} more")
            else:
                print("    ⚠️  No AI models found")
                print("       Download with: ollama pull xploiter/pentester")
            return True
        else:
            print("    ⚠️  Ollama service not responding (optional)")
            return True  # Not critical
    except Exception:
        print("    ⚠️  Ollama service not running (optional)")
        print("       Start Ollama with: ollama serve")
        print("       Or install from: https://ollama.com/")
        return True  # Not critical

def check_ai_config():
    """Check AI configuration"""
    print("\n[6/6] Checking AI configuration...")
    
    try:
        from pathlib import Path
        config_file = Path.home() / '.astrava' / 'config.json'
        
        if config_file.exists():
            print("    ✅ AI configuration file found")
            return True
        else:
            print("    ⚠️  No AI configuration yet")
            print("       Configure AI in Web GUI → AI Model Settings")
            return True  # Not critical
    except Exception as e:
        print(f"    ⚠️  Could not check AI config: {e}")
        return True  # Not critical

def check_project_structure():
    """Check if project directories exist"""
    print("\n[BONUS] Checking project structure...")
    
    from pathlib import Path
    
    directories = ['logs', 'reports', 'payloads', 'core', 'modules', 'utils']
    all_ok = True
    
    for directory in directories:
        if Path(directory).exists():
            print(f"    ✅ {directory}/ directory exists")
        else:
            print(f"    ⚠️  {directory}/ directory missing (will be created)")
            all_ok = False
    
    return all_ok

def print_summary(results):
    """Print verification summary"""
    print("\n" + "="*70)
    print("  VERIFICATION SUMMARY")
    print("="*70)
    
    total = len(results)
    passed = sum(results.values())
    
    print(f"\n  Total Checks: {total}")
    print(f"  Passed: {passed}")
    print(f"  Failed: {total - passed}")
    
    if all(results.values()):
        print("\n  ✅ ALL CHECKS PASSED - Installation is complete!")
        print("\n  You can now run:")
        print("     python astrava.py        # Launch Web GUI (Recommended)")
        print("     python main.py --help    # View CLI options")
        print("\n  🤖 AI Setup:")
        print("     - Launch Web GUI: python astrava.py")
        print("     - Go to AI Model Settings")
        print("     - Install Ollama from https://ollama.ai")
    else:
        print("\n  ⚠️  SOME CHECKS FAILED - Please fix critical issues above")
        print("\n  Note: Ollama and AI configuration are optional")
        print("  You can configure AI later in the Web GUI")
        print("\n  Run the installer again:")
        print("     Windows: install.bat")
        print("     Linux/Mac: ./install.sh")
    
    print("\n" + "="*70 + "\n")

def main():
    """Main verification function"""
    print_header()
    
    results = {
        'Python Version': check_python_version(),
        'Core Dependencies': check_core_dependencies(),
        'Ollama (Optional)': check_ollama(),
        'Ollama Service (Optional)': check_ollama_service(),
        'AI Configuration': check_ai_config(),
    }
    
    # Optional checks
    check_optional_dependencies()
    check_project_structure()
    
    # Print summary
    print_summary(results)
    
    # Return exit code
    return 0 if all(results.values()) else 1

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\n⚠️  Verification interrupted by user\n")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Verification error: {e}\n")
        sys.exit(1)
