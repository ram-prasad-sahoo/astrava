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
    """Check Ollama installation"""
    print("\n[4/6] Checking Ollama...")
    
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
            print("    ❌ Ollama not responding")
            return False
    except FileNotFoundError:
        print("    ❌ Ollama not found")
        print("       Install from: https://ollama.ai")
        return False
    except Exception as e:
        print(f"    ❌ Error checking Ollama: {e}")
        return False

def check_ollama_service():
    """Check if Ollama service is running"""
    print("\n[5/6] Checking Ollama service...")
    
    try:
        import requests
        response = requests.get('http://localhost:11434/api/tags', timeout=2)
        if response.status_code == 200:
            print("    ✅ Ollama service is running")
            return True
        else:
            print("    ❌ Ollama service not responding")
            return False
    except Exception as e:
        print("    ❌ Ollama service not running")
        print("       Start with: ollama serve")
        return False

def check_llama_model():
    """Check if LLaMA model is available"""
    print("\n[6/6] Checking LLaMA 3.2:3b model...")
    
    try:
        result = subprocess.run(['ollama', 'list'], 
                              capture_output=True, 
                              text=True, 
                              timeout=5)
        if 'llama3.2:3b' in result.stdout:
            print("    ✅ LLaMA 3.2:3b model available")
            return True
        else:
            print("    ❌ LLaMA 3.2:3b model not found")
            print("       Download with: ollama pull llama3.2:3b")
            return False
    except Exception as e:
        print(f"    ❌ Error checking model: {e}")
        return False

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
        print("     python astrava_gui.py    # Launch GUI")
        print("     python astrava.py        # Launch GUI")
        print("     python astrava.py --help # View CLI options")
    else:
        print("\n  ❌ SOME CHECKS FAILED - Please fix the issues above")
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
        'Ollama': check_ollama(),
        'Ollama Service': check_ollama_service(),
        'LLaMA Model': check_llama_model(),
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
