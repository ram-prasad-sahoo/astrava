#!/usr/bin/env python3
"""
Astrava AI Security Scanner - Unified Entry Point

Usage:
  python astrava.py              # Launch Web GUI (default)
  python astrava.py -u <URL>     # CLI scan mode
  python astrava.py --help       # Show help
"""

import sys
import asyncio
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

def launch_gui():
    """Launch the Web GUI"""
    try:
        # Initialize Ollama and detect models BEFORE starting GUI
        print("=" * 60)
        print("  ASTRAVA AI Security Scanner")
        print("=" * 60)
        print("[*] Initializing AI system...")
        
        from utils.ollama_manager import OllamaManager
        ollama = OllamaManager()
        
        # Start Ollama service and ensure it's running
        success, message = ollama.initialize(auto_download=False)
        if success:
            print(f"[✓] {message}")
            
            # Detect all available models
            models = ollama.list_models(force_refresh=True)
            if models:
                print(f"[✓] Detected {len(models)} AI models:")
                for model in models:
                    print(f"    • {model}")
            else:
                print("[!] No AI models found. Install with: ollama pull xploiter/pentester")
        else:
            print(f"[!] {message}")
            print("[!] AI features may be limited")
        
        print("\n[*] Starting Web GUI...")
        from web_gui import run
        run()
    except ImportError as e:
        print(f"[ERROR] Failed to start: {e}")
        print("Install dependencies: pip install -r requirements.txt")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
        sys.exit(0)

async def run_cli_scan(args):
    """Run CLI scan mode"""
    from core.scanner_engine import AstravaAIScanner
    from core.config import Config
    from utils.logger import setup_logger
    from utils.banner import display_banner
    from utils.ollama_manager import OllamaManager
    from core.ai_engine import AIEngine
    
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
    
    # Setup logging
    logger = setup_logger(verbose=args.verbose)
    
    # Check active model from config
    try:
        from utils import config_store
        config = config_store.load_config()
        active_model = config.get("active_model", "xploiter/pentester")
    except:
        active_model = "xploiter/pentester"

    # Validate Ollama connection
    ai_engine = AIEngine(model=args.model)
    if not await ai_engine.validate_connection():
        logger.warning("Cannot connect to Ollama. Continuing without AI features...")
    
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

def main():
    # Parse arguments
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
║              AI SECURITY SCANNER v1.1.0                              ║
║         Advanced OWASP Top 10 2021 Scanner                           ║
║                                                                       ║
╚═══════════════════════════════════════════════════════════════════════╝

ASTRAVA - Professional AI-Powered Web Application Security Scanner
Combines traditional penetration testing with cutting-edge AI analysis

MODES:
  python astrava.py              Launch Web GUI (default, recommended)
  python astrava.py -u <URL>     CLI scan mode
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
═══════════════════════════════════════════════════════════════════════
EXAMPLES:
═══════════════════════════════════════════════════════════════════════

Launch Web GUI (Recommended):
  python astrava.py

Basic CLI Scan:
  python astrava.py -u https://example.com

OWASP Top 10 Testing:
  python astrava.py -u https://example.com --owasp-all

Aggressive Scan with Chain Attacks:
  python astrava.py -u https://example.com --owasp-all --chain-attacks

Passive Reconnaissance Only:
  python astrava.py -u https://example.com --passive-only

Custom Payloads:
  python astrava.py -u https://example.com --custom-payloads payloads/custom.txt

Verbose Output:
  python astrava.py -u https://example.com --verbose

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
    
    # Optional URL argument (if not provided, launch GUI)
    parser.add_argument('-u', '--url',
                       metavar='URL',
                       help='Target URL to scan (if not provided, launches Web GUI)')
    
    # Version
    parser.add_argument('--version',
                       action='version',
                       version='Astrava AI Security Scanner v1.1.0')
    
    # Scan Type Options
    scan_type = parser.add_argument_group('Scan Type Options')
    scan_type.add_argument('--passive-only',
                          action='store_true',
                          help='Perform only passive reconnaissance')
    scan_type.add_argument('--active-only',
                          action='store_true',
                          help='Perform only active scanning')
    scan_type.add_argument('--owasp-all',
                          action='store_true',
                          help='Test all OWASP Top 10 2021 vulnerabilities')
    scan_type.add_argument('--chain-attacks',
                          action='store_true',
                          help='Enable AI-powered chain attack detection')
    
    # Customization Options
    custom = parser.add_argument_group('Customization Options')
    custom.add_argument('--custom-payloads',
                       metavar='FILE',
                       help='Path to custom payloads file')
    custom.add_argument('--model',
                       default='xploiter/pentester',
                       metavar='MODEL',
                       help='AI model to use (default: xploiter/pentester)')
    
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
                       help='Enable verbose output')
    
    # Performance Options
    perf = parser.add_argument_group('Performance Options')
    perf.add_argument('--threads',
                     type=int,
                     default=10,
                     metavar='N',
                     help='Number of concurrent threads (default: 10)')
    perf.add_argument('--timeout',
                     type=int,
                     default=30,
                     metavar='SEC',
                     help='Request timeout in seconds (default: 30)')
    
    args = parser.parse_args()
    
    # If no URL provided, launch GUI
    if not args.url:
        launch_gui()
    else:
        # Run CLI scan
        exit_code = asyncio.run(run_cli_scan(args))
        sys.exit(exit_code)

if __name__ == "__main__":
    main()
