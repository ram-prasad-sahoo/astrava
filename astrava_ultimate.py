#!/usr/bin/env python3
"""
Astrava AI Security Scanner - Ultimate Professional Version
Advanced GUI with large results display and proper encoding
"""

import sys
import os
from pathlib import Path

def print_banner():
    """Print professional banner"""
    print("""

                    Astrava AI SECURITY SCANNER                        
                   ULTIMATE PROFESSIONAL VERSION                     
                                                                      
  [OK] LARGE RESULTS DISPLAY (70% of screen)                          
  [OK] FIXED UNICODE ENCODING (No more errors)                        
  [OK] 3 ATTACK MODES (Basic/Medium/Aggressive)                       
  [OK] REAL-TIME VULNERABILITY DETECTION                               
  [OK] AI ANALYSIS WITH LLAMA MODELS                                   
  [OK] PROFESSIONAL STATISTICS DISPLAY                                 
  [OK] ADVANCED CONFIGURATION OPTIONS                                  
                                                                      
  FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY                        

    """)

def main():
    """Ultimate launcher"""
    print_banner()
    
    if len(sys.argv) == 1 or '--gui' in sys.argv:
        print(" Launching Astrava AI Security Scanner - Ultimate Professional GUI")
        print()
        print("FEATURES:")
        print(" Large Results Display (1800x1200 window)")
        print(" Real-time Vulnerability Detection")
        print(" Professional Statistics Dashboard")
        print(" 4 Result Tabs: Console, Vulnerabilities, Summary, AI Analysis")
        print(" Fixed Unicode Encoding (No more charmap errors)")
        print(" 3 Attack Modes with AI Integration")
        print(" Advanced Configuration Options")
        print(" Professional Color-coded Output")
        print()
        
        try:
            from Astrava_advanced_gui import AstravaAdvancedGUI
            import tkinter as tk
            
            root = tk.Tk()
            app = AstravaAdvancedGUI(root)
            root.mainloop()
            
        except ImportError as e:
            print(f"[ERROR] Error: {e}")
            print(" Please install dependencies: pip install -r requirements.txt")
            return 1
        except Exception as e:
            print(f"[ERROR] Unexpected error: {e}")
            return 1
    
    elif '--cli' in sys.argv or '-u' in sys.argv:
        print(" Running CLI mode with advanced features...")
        
        if '-u' in sys.argv:
            url_index = sys.argv.index('-u') + 1
            if url_index < len(sys.argv):
                target_url = sys.argv[url_index]
                
                # Determine attack mode
                if '--basic' in sys.argv:
                    print("[GREEN] Running Basic Attack Mode (Fast)")
                    import subprocess
                    cmd = ['python', 'fast_scan.py', '-u', target_url]
                    if '--verbose' in sys.argv:
                        cmd.append('--verbose')
                    subprocess.run(cmd)
                    
                elif '--aggressive' in sys.argv:
                    print("[RED] Running Aggressive Attack Mode (Thorough)")
                    import subprocess
                    cmd = ['python', 'main.py', '-u', target_url, 
                          '--owasp-all', '--chain-attacks', '--active-only',
                          '--threads', '20', '--timeout', '60']
                    if '--verbose' in sys.argv:
                        cmd.append('--verbose')
                    subprocess.run(cmd)
                    
                else:
                    print("[YELLOW] Running Medium Attack Mode (Standard)")
                    import subprocess
                    cmd = ['python', 'main.py', '-u', target_url, 
                          '--owasp-all', '--threads', '10', '--timeout', '30']
                    if '--verbose' in sys.argv:
                        cmd.append('--verbose')
                    subprocess.run(cmd)
            else:
                print("[ERROR] Error: No URL provided after -u")
                return 1
        else:
            print("[ERROR] Error: No target URL specified. Use -u <URL>")
            return 1
    
    elif '--help' in sys.argv or '-h' in sys.argv:
        print("""
Astrava AI SECURITY SCANNER - ULTIMATE VERSION
============================================

GUI MODE (Recommended):
    python Astrava_ultimate.py
    python Astrava_ultimate.py --gui

CLI MODE:
    python Astrava_ultimate.py -u <URL> [OPTIONS]

ATTACK MODES:
    --basic      [GREEN] Basic Scan (Fast)
                 Fast vulnerability detection
                 
    --aggressive [RED] Aggressive Scan (Thorough)
                 Deep penetration + AI chains
                 
    (default)    [YELLOW] Medium Scan (Standard)
                 OWASP Top 10 + AI analysis

OPTIONS:
    --verbose    Detailed output
    --gui        Force GUI mode

EXAMPLES:
=========
# Launch Ultimate GUI
python Astrava_ultimate.py

# Basic CLI scan
python Astrava_ultimate.py -u http://testphp.vulnweb.com/ --basic --verbose

# Aggressive CLI scan  
python Astrava_ultimate.py -u http://testphp.vulnweb.com/ --aggressive --verbose

# Medium CLI scan (default)
python Astrava_ultimate.py -u http://testphp.vulnweb.com/ --verbose

GUI FEATURES:
============
[OK] Large Results Display (1800x1200 window)
[OK] Real-time Vulnerability Statistics
[OK] Professional Color-coded Console
[OK] Advanced Vulnerability Tree View
[OK] AI Analysis & Recommendations Tab
[OK] Detailed Scan Summary
[OK] Fixed Unicode Encoding Issues
[OK] 3 Attack Modes with AI Integration
[OK] Custom Payloads Support
[OK] Professional HTML Reports

ATTACK MODES EXPLAINED:
======================
[GREEN] BASIC SCAN:
    Fast vulnerability detection (Fast)
    Common security issues
    Minimal system impact
    Perfect for quick assessments

[YELLOW] MEDIUM SCAN:
    OWASP Top 10 comprehensive testing (Standard)
    AI-powered vulnerability analysis
    Balanced speed and coverage
    Recommended for standard assessments

[RED] AGGRESSIVE SCAN:
    Deep penetration testing (Thorough)
    AI chain attack analysis
    Maximum coverage and intensity
    For thorough security audits

LEGAL NOTICE:
============
This tool is for authorized security testing only.
Users are responsible for complying with applicable laws.
Unauthorized scanning may violate computer crime laws.
        """)
    
    else:
        print("[ERROR] Invalid arguments. Use --help for usage information.")
        return 1
    
    return 0

if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n[WARNING] Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Error: {e}")
        sys.exit(1)
