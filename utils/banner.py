"""
Banner and ASCII art for Astrava AI Security Scanner
"""

import random
from datetime import datetime

def display_banner():
    """Display the Astrava AI Security Scanner banner (Windows compatible)"""
    
    banners = [
        """
    ╔═══════════════════════════════════════════════════════════════════════╗
    ║                                                                       ║
    ║     █████╗ ███████╗████████╗██████╗  █████╗ ██╗   ██╗ █████╗        ║
    ║    ██╔══██╗██╔════╝╚══██╔══╝██╔══██╗██╔══██╗██║   ██║██╔══██╗       ║
    ║    ███████║███████╗   ██║   ██████╔╝███████║██║   ██║███████║       ║
    ║    ██╔══██║╚════██║   ██║   ██╔══██╗██╔══██║╚██╗ ██╔╝██╔══██║       ║
    ║    ██║  ██║███████║   ██║   ██║  ██║██║  ██║ ╚████╔╝ ██║  ██║       ║
    ║    ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚═╝  ╚═╝       ║
    ║                                                                       ║
    ║              AI SECURITY SCANNER v1.0                                ║
    ║         Advanced OWASP Top 10 2021 Scanner                           ║
    ║                                                                       ║
    ║    🤖 AI-Powered Vulnerability Detection                             ║
    ║    🔍 Comprehensive Reconnaissance & Exploitation                    ║
    ║    📊 Professional Reports with Risk Assessment                      ║
    ║    ⚡ 85%+ Accuracy with False Positive Reduction                    ║
    ║                                                                       ║
    ║         FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY                  ║
    ║                                                                       ║
    ╚═══════════════════════════════════════════════════════════════════════╝
        """,
        """
    ┌───────────────────────────────────────────────────────────────────────┐
    │                                                                       │
    │      █████╗ ███████╗████████╗██████╗  █████╗ ██╗   ██╗ █████╗       │
    │     ██╔══██╗██╔════╝╚══██╔══╝██╔══██╗██╔══██╗██║   ██║██╔══██╗      │
    │     ███████║███████╗   ██║   ██████╔╝███████║██║   ██║███████║      │
    │     ██╔══██║╚════██║   ██║   ██╔══██╗██╔══██║╚██╗ ██╔╝██╔══██║      │
    │     ██║  ██║███████║   ██║   ██║  ██║██║  ██║ ╚████╔╝ ██║  ██║      │
    │     ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚═╝  ╚═╝      │
    │                                                                       │
    │              🔐 AI Security Scanner | OWASP Top 10 2021              │
    │              🎯 Reconnaissance | Exploitation | Reporting            │
    │              ⚠️  AUTHORIZED TESTING ONLY                             │
    │                                                                       │
    └───────────────────────────────────────────────────────────────────────┘
        """,
        """
    ╔═══════════════════════════════════════════════════════════════════════╗
    ║                                                                       ║
    ║     █████╗ ███████╗████████╗██████╗  █████╗ ██╗   ██╗ █████╗        ║
    ║    ██╔══██╗██╔════╝╚══██╔══╝██╔══██╗██╔══██╗██║   ██║██╔══██╗       ║
    ║    ███████║███████╗   ██║   ██████╔╝███████║██║   ██║███████║       ║
    ║    ██╔══██║╚════██║   ██║   ██╔══██╗██╔══██║╚██╗ ██╔╝██╔══██║       ║
    ║    ██║  ██║███████║   ██║   ██║  ██║██║  ██║ ╚████╔╝ ██║  ██║       ║
    ║    ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚═╝  ╚═╝       ║
    ║                                                                       ║
    ║                  AI SECURITY SCANNER v1.0                            ║
    ║                                                                       ║
    ║        🚀 Powered by Ollama LLaMA 3.2                                ║
    ║        🔍 Advanced Reconnaissance & Vulnerability Detection          ║
    ║        🛡️  OWASP Top 10 2021 Comprehensive Testing                  ║
    ║        🤖 AI-Generated Chain Attack Analysis                         ║
    ║        � Pdrofessional HTML/PDF Reports                              ║
    ║        ⚡ 85%+ Accuracy | False Positive Reduction                   ║
    ║                                                                       ║
    ║        FOR EDUCATIONAL AND AUTHORIZED PENETRATION TESTING ONLY       ║
    ║                                                                       ║
    ╚═══════════════════════════════════════════════════════════════════════╝
        """
    ]
    
    # Select random banner
    banner = random.choice(banners)
    
    # Safe print with encoding handling
    try:
        print(banner)
    except UnicodeEncodeError:
        # Fallback to simple ASCII banner
        print("""
    ====================================================================
                        ASTRAVA AI SECURITY SCANNER
                       Advanced OWASP Top 10 Scanner
    
        AI-Powered Vulnerability Detection & Chain Attack Analysis
        Comprehensive Reconnaissance & Exploitation Testing
        Professional Reports with Risk Assessment
    
                FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY
    ====================================================================
        """)
    
    # Additional info
    print(f"    Version: v1.0.0")
    print(f"    Author: RAM (Ram Prasad Sahoo)")
    print(f"    Email: ramprasadsahoo42@gmail.com")
    print(f"    GitHub: https://github.com/astrava-security/astrava-scanner")
    print()
    
    # Legal disclaimer
    print("    " + "="*70)
    print("    LEGAL DISCLAIMER:")
    print("    This tool is designed for authorized security testing only.")
    print("    Users are responsible for complying with applicable laws.")
    print("    Unauthorized scanning may violate computer crime laws.")
    print("    " + "="*70)
    print()

def display_scan_start(target_url: str, scan_type: str = "Full"):
    """Display scan start information"""
    try:
        print(f"    Target: {target_url}")
        print(f"    Scan Type: {scan_type}")
        print(f"    Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("    " + "-"*70)
        print()
    except UnicodeEncodeError:
        print(f"    Target: {target_url}")
        print(f"    Scan Type: {scan_type}")
        print(f"    Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("    " + "-"*70)
        print()

def display_scan_complete(duration: float, vulnerabilities_found: int, risk_score: int):
    """Display scan completion information"""
    try:
        print()
        print("    " + "="*70)
        print("    SCAN COMPLETED")
        print("    " + "="*70)
        print(f"    Duration: {duration:.2f} seconds")
        print(f"    Vulnerabilities Found: {vulnerabilities_found}")
        print(f"    Risk Score: {risk_score}/100")
        
        # Risk level indicator
        if risk_score >= 80:
            print("    Risk Level: CRITICAL")
        elif risk_score >= 60:
            print("    Risk Level: HIGH")
        elif risk_score >= 40:
            print("    Risk Level: MEDIUM")
        elif risk_score >= 20:
            print("    Risk Level: LOW")
        else:
            print("    Risk Level: MINIMAL")
        
        print("    " + "="*70)
        print()
    except UnicodeEncodeError:
        print()
        print("    " + "="*70)
        print("    SCAN COMPLETED")
        print("    " + "="*70)
        print(f"    Duration: {duration:.2f} seconds")
        print(f"    Vulnerabilities Found: {vulnerabilities_found}")
        print(f"    Risk Score: {risk_score}/100")
        print("    " + "="*70)
        print()

def display_progress(phase: str, current: int, total: int):
    """Display progress bar for current phase"""
    if total == 0:
        percentage = 100
    else:
        percentage = (current / total) * 100
    
    bar_length = 40
    filled_length = int(bar_length * percentage // 100)
    bar = '' * filled_length + '-' * (bar_length - filled_length)
    
    print(f"\r    {phase}: |{bar}| {percentage:.1f}% ({current}/{total})", end='', flush=True)
    
    if current == total:
        print()  # New line when complete

def display_vulnerability_summary(vulnerabilities):
    """Display a summary of found vulnerabilities"""
    try:
        if not vulnerabilities:
            print("    No vulnerabilities detected")
            return
        
        # Count by severity
        severity_counts = {}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        print("    Vulnerability Summary:")
        for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
            count = severity_counts.get(severity, 0)
            if count > 0:
                print(f"    {severity}: {count}")
    except UnicodeEncodeError:
        print("    Vulnerability summary available in report")

def display_ai_status(status: str):
    """Display AI engine status"""
    try:
        print(f"    AI Engine: {status}")
    except UnicodeEncodeError:
        print(f"    AI Engine: {status}")

def display_module_status(module: str, status: str):
    """Display module status"""
    try:
        print(f"    {module}: {status}")
    except UnicodeEncodeError:
        print(f"    {module}: {status}")

def display_error(message: str):
    """Display error message"""
    try:
        print(f"    ERROR: {message}")
    except UnicodeEncodeError:
        print(f"    ERROR: {message}")

def display_warning(message: str):
    """Display warning message"""
    try:
        print(f"    WARNING: {message}")
    except UnicodeEncodeError:
        print(f"    WARNING: {message}")

def display_info(message: str):
    """Display info message"""
    try:
        print(f"    INFO: {message}")
    except UnicodeEncodeError:
        print(f"    INFO: {message}")

def display_success(message: str):
    """Display success message"""
    try:
        print(f"    SUCCESS: {message}")
    except UnicodeEncodeError:
        print(f"    SUCCESS: {message}")