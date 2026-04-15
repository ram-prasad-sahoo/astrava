#!/usr/bin/env python3
"""
Fast Astrava AI Security Scanner
Optimized version with minimal AI usage for faster scanning
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
from utils.ollama_manager import OllamaManager

async def fast_scan(target_url: str, model: str = None):
    """Run a fast scan with minimal AI usage"""
    
    display_banner()
    
    print("BASIC/FAST Astrava AI SECURITY SCANNER")
    print("=" * 70)
    print(f"Target: {target_url}")
    print("Mode: Basic/Fast scan - Quick vulnerability detection")
    print("Features: Basic web crawling + Core vulnerability detection")
    print("Excluded: OWASP Top 10, Port Scanning, Chain Attacks, Deep AI Analysis")
    print("=" * 70)
    print()
    
    # Get model from parameter or config
    if not model:
        try:
            from utils import config_store
            config = config_store.load_config()
            model = config.get("active_model", "xploiter/pentester")
        except:
            model = "xploiter/pentester"

    # Initialize AI Engine (Ollama only)
    print("Initializing AI Engine...")
    print(f"  Selected model: {model}")
    ollama_manager = OllamaManager(model=model)
    success, message = ollama_manager.initialize(auto_download=True)
    if success:
        print(f"✓ {message}")
        print(f"  Mode: Ollama | Model: {model}")
    else:
        print(f"⚠ {message}")
        print("  Continuing without AI features...")
    
    print()
    
    # Setup optimized configuration for BASIC/FAST scan
    logger = setup_logger("fast_scan", verbose=True)
    config = Config(
        target_url=target_url,
        owasp_all=False,  # NO OWASP testing in basic mode
        chain_attacks=False,  # Skip chain attacks for speed
        model=model,  # Use the selected model
        max_threads=10,
        timeout=45,  # Sufficient for slow sites
        output_dir="./reports",  # Same as main.py so GUI report finder picks it up
        skip_port_scan=True,  # Skip port scanning in basic mode
        max_crawl_depth=2  # Slightly deeper for better coverage
    )
    
    try:
        # Initialize scanner
        scanner = AstravaAIScanner(config, logger)
        
        print("STARTING FAST SCAN...")
        print("=" * 70)
        
        # Modify scanner to skip heavy AI analysis
        scanner.skip_ai_analysis = True
        
        # Run the scan
        results = await scanner.run_full_scan()
        
        # Display results
        print("\n" + "=" * 70)
        print("FAST SCAN COMPLETED!")
        print("=" * 70)
        print(f"Target: {results['target']}")
        print(f"Risk Score: {results.get('risk_score', 0)}/100")
        print(f"Total Vulnerabilities: {len(results.get('vulnerabilities', []))}")
        print(f"Report: {results.get('report_path', 'Not generated')}")
        print(f"Duration: {results.get('scan_duration', 0):.2f} seconds")
        
        # Show vulnerability summary
        vulnerabilities = results.get('vulnerabilities', [])
        if vulnerabilities:
            print(f"\nVULNERABILITY SUMMARY:")
            vuln_types = {}
            for vuln in vulnerabilities:
                vuln_type = vuln.get('type', 'Unknown')
                vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
            
            for vuln_type, count in vuln_types.items():
                print(f"   {vuln_type}: {count}")
            
            print(f"\nTOP VULNERABILITIES:")
            for i, vuln in enumerate(vulnerabilities[:5], 1):
                print(f"   {i}. {vuln.get('type', 'Unknown')}")
                print(f"      URL: {vuln.get('url', 'N/A')}")
                print(f"      Parameter: {vuln.get('parameter', 'N/A')}")
                print(f"      Severity: {vuln.get('severity', 'N/A')}")
                print()
        
        print(f"\nBASIC/FAST SCAN FEATURES:")
        print(f"   ✓ Quick vulnerability detection")
        print(f"   ✓ Basic web crawling (depth: 1)")
        print(f"   ✓ Core security checks")
        print(f"   ✓ Professional HTML reports")
        print(f"   ✓ Minimal AI overhead")
        print(f"\nEXCLUDED FROM BASIC SCAN:")
        print(f"   ✗ OWASP Top 10 comprehensive testing")
        print(f"   ✗ Port scanning and service detection")
        print(f"   ✗ Chain attack analysis")
        print(f"   ✗ Deep AI-powered analysis")
        
        return results
        
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        return None
    except Exception as e:
        print(f"\nScan failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return None

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Fast Astrava AI Security Scanner")
    parser.add_argument('-u', '--url', required=True, help='Target URL to scan')
    parser.add_argument('--model', type=str, help='AI model to use (e.g., qwen3:4b, llama3.2:3b)')
    
    args = parser.parse_args()
    
    # Run fast scan with specified model
    asyncio.run(fast_scan(args.url, model=args.model))

if __name__ == "__main__":
    main()
