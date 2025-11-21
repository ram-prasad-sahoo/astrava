#!/usr/bin/env python3
"""
Astrava AI Security Scanner - Main Entry Point
Advanced AI-Powered Web Security Scanner for OWASP Top 10 and Beyond
"""

import asyncio
import argparse
import sys
import os
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from core.scanner_engine import AstravaAIScanner
from core.config import Config
from utils.logger import setup_logger
from utils.banner import display_banner
from utils.ollama_manager import OllamaManager
from core.ai_engine import AIEngine

async def main():
    """Main entry point for Astrava AI Security Scanner"""
    
    # Display banner
    display_banner()
    
    # Initialize Ollama automatically
    print("Initializing AI Engine...")
    ollama_manager = OllamaManager()
    success, message = ollama_manager.initialize(auto_download=True)
    if success:
        print(f"✓ {message}")
    else:
        print(f"⚠ {message}")
        print("  Continuing without AI features...")
    print()
    
    # Setup argument parser with professional help
    parser = argparse.ArgumentParser(
        prog='astrava',
        description="""
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
╚═══════════════════════════════════════════════════════════════════════╝

ASTRAVA - Professional AI-Powered Web Application Security Scanner
Combines traditional penetration testing with cutting-edge AI analysis
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
═══════════════════════════════════════════════════════════════════════
EXAMPLES:
═══════════════════════════════════════════════════════════════════════

Basic Scan (Fast):
  python main.py -u https://example.com

OWASP Top 10 Testing:
  python main.py -u https://example.com --owasp-all

Aggressive Scan with Chain Attacks:
  python main.py -u https://example.com --owasp-all --chain-attacks

Passive Reconnaissance Only:
  python main.py -u https://example.com --passive-only

Custom Payloads:
  python main.py -u https://example.com --custom-payloads payloads/custom.txt

Verbose Output with JSON Report:
  python main.py -u https://example.com --verbose --format json

Full Scan with All Options:
  python main.py -u https://example.com --owasp-all --chain-attacks \\
                 --threads 20 --timeout 60 --verbose

═══════════════════════════════════════════════════════════════════════
SCAN MODES:
═══════════════════════════════════════════════════════════════════════

Use astrava.py for simplified mode selection:
  python astrava.py -u <URL> --basic       # Fast scan (Fast)
  python astrava.py -u <URL>               # Medium scan (Standard)
  python astrava.py -u <URL> --aggressive  # Deep scan (Thorough)

Or launch GUI:
  python astrava_gui.py                    # Professional GUI interface

═══════════════════════════════════════════════════════════════════════
LEGAL NOTICE:
═══════════════════════════════════════════════════════════════════════

⚠️  This tool is for AUTHORIZED SECURITY TESTING ONLY
   - Only scan systems you own or have explicit permission to test
   - Unauthorized scanning may violate computer crime laws
   - Users are responsible for complying with all applicable laws

For more information: https://github.com/ram-prasad-sahoo/astrava
        """
    )
    
    # Required Arguments
    required = parser.add_argument_group('Required Arguments')
    required.add_argument('-u', '--url', 
                         required=True,
                         metavar='URL',
                         help='Target URL to scan (e.g., https://example.com)')
    
    # Scan Type Options
    scan_type = parser.add_argument_group('Scan Type Options')
    scan_type.add_argument('--passive-only',
                          action='store_true',
                          help='Perform only passive reconnaissance (DNS, subdomains, certificates)')
    scan_type.add_argument('--active-only',
                          action='store_true',
                          help='Perform only active scanning (skip passive reconnaissance)')
    scan_type.add_argument('--owasp-all',
                          action='store_true',
                          help='Test all OWASP Top 10 2021 vulnerabilities (recommended)')
    scan_type.add_argument('--chain-attacks',
                          action='store_true',
                          help='Enable AI-powered chain attack detection (multi-step exploits)')
    
    # Customization Options
    custom = parser.add_argument_group('Customization Options')
    custom.add_argument('--custom-payloads',
                       metavar='FILE',
                       help='Path to custom payloads file (one payload per line)')
    custom.add_argument('--model',
                       default='llama3.2:3b',
                       metavar='MODEL',
                       help='AI model to use (default: llama3.2:3b)')
    
    # Output Options
    output = parser.add_argument_group('Output Options')
    output.add_argument('-o', '--output',
                       metavar='DIR',
                       help='Output directory for reports (default: ./reports)')
    output.add_argument('--format',
                       choices=['html', 'json', 'pdf'],
                       default='html',
                       metavar='FORMAT',
                       help='Report format: html, json, or pdf (default: html)')
    output.add_argument('-v', '--verbose',
                       action='store_true',
                       help='Enable verbose output (detailed logging)')
    
    # Performance Options
    perf = parser.add_argument_group('Performance Options')
    perf.add_argument('--threads',
                     type=int,
                     default=10,
                     metavar='N',
                     help='Number of concurrent threads (default: 10, max: 50)')
    perf.add_argument('--timeout',
                     type=int,
                     default=30,
                     metavar='SEC',
                     help='Request timeout in seconds (default: 30)')
    
    args = parser.parse_args()
    
    # Setup logging
    logger = setup_logger(verbose=args.verbose)
    
    # Validate Ollama connection
    ai_engine = AIEngine(model=args.model)
    if not await ai_engine.validate_connection():
        logger.error("Cannot connect to Ollama. Please ensure it's running and the model is available.")
        return 1
    
    # Initialize scanner
    config = Config(
        target_url=args.url,
        passive_only=args.passive_only,
        active_only=args.active_only,
        owasp_all=args.owasp_all,
        chain_attacks=args.chain_attacks,
        custom_payloads=args.custom_payloads,
        output_dir=args.output,
        report_format=args.format,
        max_threads=args.threads,
        timeout=args.timeout,
        model=args.model
    )
    
    scanner = AstravaAIScanner(config, logger)
    
    try:
        # Run the scan
        results = await scanner.run_full_scan()
        
        # Display summary
        logger.info("=" * 80)
        logger.info("SCAN COMPLETED SUCCESSFULLY")
        logger.info("=" * 80)
        logger.info(f"Target: {results['target']}")
        logger.info(f"Vulnerabilities Found: {len(results['vulnerabilities'])}")
        logger.info(f"Risk Score: {results['risk_score']}/100")
        logger.info(f"Report Location: {results['report_path']}")
        
        return 0
        
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user")
        return 1
    except Exception as e:
        logger.error(f"Scan failed: {str(e)}")
        return 1

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
