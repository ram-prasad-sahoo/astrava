#!/usr/bin/env python3
"""
Quick Test Script for Astrava AI Security Scanner
Demonstrates key features with a safe test target
"""

import asyncio
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from core.scanner_engine import AstravaAIScanner
from core.config import Config
from utils.logger import setup_logger
from utils.banner import display_banner

async def quick_test():
    """Run a quick test of the scanner"""
    
    display_banner()
    
    print(" Running Quick Test of Astrava AI Security Scanner")
    print("=" * 60)
    print("Target: https://httpbin.org (safe test target)")
    print("Mode: Basic scan with AI analysis")
    print("=" * 60)
    print()
    
    # Setup
    logger = setup_logger("quick_test", verbose=True)
    config = Config(
        target_url="https://httpbin.org",
        passive_only=True,  # Safe passive scan only
        output_dir="./reports/quick_test"
    )
    
    try:
        # Initialize scanner
        scanner = AstravaAIScanner(config, logger)
        
        # Run scan
        print("[SEARCH] Starting scan...")
        results = await scanner.run_passive_scan()
        
        # Display results
        print("\n" + "=" * 60)
        print("[OK] SCAN COMPLETED SUCCESSFULLY!")
        print("=" * 60)
        print(f"[TARGET] Target: {results['target']}")
        print(f"[REPORT] Risk Score: {results.get('risk_score', 0)}/100")
        print(f"[SEARCH] Vulnerabilities: {len(results.get('vulnerabilities', []))}")
        print(f"[FILE] Report: {results.get('report_path', 'Not generated')}")
        print(f"  Duration: {results.get('scan_duration', 0):.2f} seconds")
        
        # Show reconnaissance data
        recon = results.get('reconnaissance', {})
        passive_data = recon.get('passive', {})
        
        if passive_data:
            print("\n Reconnaissance Summary:")
            dns_info = passive_data.get('dns', {})
            if dns_info:
                total_records = sum(len(records) for records in dns_info.values() if isinstance(records, list))
                print(f"    DNS Records: {total_records}")
            
            subdomains = passive_data.get('subdomains', [])
            print(f"   [SEARCH] Subdomains: {len(subdomains)}")
            
            ct_domains = passive_data.get('certificate_transparency', [])
            print(f"    Certificate Transparency: {len(ct_domains)} domains")
        
        print("\n Test completed successfully!")
        print(" Try running with different options:")
        print("   python main.py -u https://httpbin.org --owasp-all")
        print("   python main.py -u https://httpbin.org --chain-attacks")
        
    except KeyboardInterrupt:
        print("\n[WARNING]  Test interrupted by user")
    except Exception as e:
        print(f"\n[ERROR] Test failed: {str(e)}")
        import traceback
        traceback.print_exc()

def show_features():
    """Display key features of the scanner"""
    
    print("[SHIELD] Astrava AI SECURITY SCANNER - KEY FEATURES")
    print("=" * 60)
    print()
    
    features = [
        "[AI] AI-Powered Analysis using LLaMA 3.2:3b",
        "[SEARCH] Comprehensive OWASP Top 10 2021 Testing",
        " Advanced Reconnaissance (Passive & Active)",
        "[TARGET] Smart Payload Generation",
        " Chain Attack Detection",
        "[REPORT] Professional HTML Reports",
        " Asynchronous High-Performance Scanning",
        "[SHIELD] Ethical & Responsible Security Testing"
    ]
    
    for feature in features:
        print(f"  {feature}")
    
    print()
    print(" OWASP Top 10 2021 Coverage:")
    owasp_categories = [
        "A01:2021 - Broken Access Control",
        "A02:2021 - Cryptographic Failures", 
        "A03:2021 - Injection",
        "A04:2021 - Insecure Design",
        "A05:2021 - Security Misconfiguration",
        "A06:2021 - Vulnerable and Outdated Components",
        "A07:2021 - Identification and Authentication Failures",
        "A08:2021 - Software and Data Integrity Failures",
        "A09:2021 - Security Logging and Monitoring Failures",
        "A10:2021 - Server-Side Request Forgery (SSRF)"
    ]
    
    for category in owasp_categories:
        print(f"  [OK] {category}")
    
    print()
    print(" Usage Examples:")
    examples = [
        "python main.py -u https://example.com",
        "python main.py -u https://example.com --owasp-all",
        "python main.py -u https://example.com --chain-attacks",
        "python main.py -u https://example.com --passive-only",
        "python main.py -u https://example.com --format json"
    ]
    
    for example in examples:
        print(f"  {example}")
    
    print()

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Astrava AI Security Scanner Quick Test")
    parser.add_argument('--features', action='store_true', help='Show features only')
    parser.add_argument('--test', action='store_true', help='Run quick test')
    
    args = parser.parse_args()
    
    if args.features:
        show_features()
    elif args.test:
        asyncio.run(quick_test())
    else:
        # Default: show features and run test
        show_features()
        print("\n" + "="*60)
        print("Running Quick Test...")
        print("="*60)
        asyncio.run(quick_test())
