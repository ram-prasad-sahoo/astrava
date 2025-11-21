#!/usr/bin/env python3
"""
Astrava AI Security Scanner - Main Launcher
Clean, simple launcher for the Astrava security scanner
"""

import sys
import os
from pathlib import Path

def main():
    """Main launcher function"""
    
    print("""

                    ASTRAVA AI SECURITY SCANNER                        
                      Professional Edition                            
                                                                      
  [TARGET] 3 Attack Modes: Basic, Medium, Aggressive                      
  [AI] AI Integration with LLaMA Models                               
  [REPORT] Large Results Display (Fixed Unicode Issues)                   
  [SHIELD] OWASP Top 10 Comprehensive Testing                            
                                                                      
  FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY                        

    """)
    
    # No arguments - launch GUI
    if len(sys.argv) == 1:
        print(" Launching Professional GUI Interface...")
        print("Features: Large results display, 3 attack modes, AI analysis")
        print()
        
        try:
            from astrava_gui import AstravaAdvancedGUI
            import tkinter as tk
            
            root = tk.Tk()
            app = AstravaAdvancedGUI(root)
            root.mainloop()
            return 0
            
        except ImportError as e:
            print(f"[ERROR] Error: {e}")
            print(" Install dependencies: pip install -r requirements.txt")
            return 1
    
    # CLI mode
    elif '-u' in sys.argv:
        url_index = sys.argv.index('-u') + 1
        if url_index >= len(sys.argv):
            print("[ERROR] Error: No URL provided")
            return 1
        
        target_url = sys.argv[url_index]
        
        # Attack modes
        if '--basic' in sys.argv:
            print("[GREEN] Basic Scan (Fast)")
            import subprocess
            cmd = ['python', 'fast_scan.py', '-u', target_url]
        elif '--aggressive' in sys.argv:
            print("[RED] Aggressive Scan (Thorough)")
            import subprocess
            cmd = ['python', 'main.py', '-u', target_url, '--owasp-all', '--chain-attacks']
        else:
            print("[YELLOW] Medium Scan (Standard)")
            import subprocess
            cmd = ['python', 'main.py', '-u', target_url, '--owasp-all']
        
        if '--verbose' in sys.argv:
            cmd.append('--verbose')
        
        return subprocess.run(cmd).returncode
    
    # Help
    elif '--help' in sys.argv or '-h' in sys.argv:
        print("""
========================================================================
                                                                       
     ASTRAVA AI SECURITY SCANNER v1.0                                 
     Professional Edition - Main Launcher                             
                                                                       
========================================================================

ASTRAVA - Professional AI-Powered Web Application Security Scanner
Simplified launcher with three attack modes for easy scanning

========================================================================
USAGE:
========================================================================

GUI Mode (Recommended):
  python astrava.py                    # Launch professional GUI interface
  python astrava_gui.py                # Direct GUI launch

CLI Mode:
  python astrava.py -u <URL> [OPTIONS]

========================================================================
ATTACK MODES:
========================================================================

[BASIC SCAN] (--basic)
   Speed: Fast
   Features: - Fast vulnerability detection
             - Common security issues
             - OWASP Top 10: OFF by default
             - Chain Attacks: Not available
   Best for: Quick initial assessment, time-sensitive scans
   Command:  python astrava.py -u <URL> --basic

[MEDIUM SCAN] (default)
   Speed: Standard
   Features: - Comprehensive OWASP Top 10 testing
             - AI-powered vulnerability analysis
             - OWASP Top 10: ON by default
             - Chain Attacks: Optional
   Best for: Standard security assessment, regular testing
   Command:  python astrava.py -u <URL>

[AGGRESSIVE SCAN] (--aggressive)
   Speed: Thorough
   Features: - Deep penetration testing
             - AI chain attack detection
             - OWASP Top 10: ON by default
             - Chain Attacks: ON by default
   Best for: Thorough security audit, pre-production testing
   Command:  python astrava.py -u <URL> --aggressive

========================================================================
OPTIONS:
========================================================================

  -u, --url <URL>        Target URL to scan (required for CLI mode)
  --basic                Run basic/fast scan (Fast)
  --aggressive           Run aggressive/deep scan (Thorough)
  --verbose              Enable detailed output logging
  -h, --help             Show this help message

========================================================================
EXAMPLES:
========================================================================

Launch GUI:
  python astrava.py

Basic Scan (Fast):
  python astrava.py -u http://testphp.vulnweb.com/ --basic

Medium Scan (Recommended):
  python astrava.py -u http://testphp.vulnweb.com/

Aggressive Scan (Thorough):
  python astrava.py -u http://testphp.vulnweb.com/ --aggressive

Verbose Output:
  python astrava.py -u http://testphp.vulnweb.com/ --verbose

Test Targets (For Practice):
  python astrava.py -u http://testphp.vulnweb.com/      # Vulnerable PHP app
  python astrava.py -u http://demo.testfire.net/        # Banking demo
  python astrava.py -u https://httpbin.org/             # HTTP testing

========================================================================
ADVANCED OPTIONS:
========================================================================

For advanced scanning options, use main.py:
  python main.py --help                # Show all advanced options
  python main.py -u <URL> --owasp-all  # Full OWASP testing
  python main.py -u <URL> --chain-attacks  # Chain attack detection

========================================================================
LEGAL NOTICE:
========================================================================

WARNING: This tool is for AUTHORIZED SECURITY TESTING ONLY

   - Only scan systems you own or have explicit written permission to test
   - Unauthorized scanning may violate computer crime laws
   - Users are responsible for complying with all applicable laws
   - The developers assume no liability for misuse

========================================================================
SUPPORT & DOCUMENTATION:
========================================================================

  Documentation: README.md
  Installation:  docs/INSTALLATION_GUIDE.md
  Commands:      docs/CLI_COMMANDS.md
  Issues:        https://github.com/astrava-security/astrava-scanner/issues
  Email:         ramprasadsahoo42@gmail.com

========================================================================

Made with Love by RAM (Ram Prasad Sahoo)
Email: ramprasadsahoo42@gmail.com
        """)
        return 0
    
    else:
        print("[ERROR] Invalid arguments. Use --help for usage information.")
        return 1

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[WARNING] Interrupted by user")
        sys.exit(1)
