#!/usr/bin/env python3
"""
Astrava AI Security Scanner - Usage Examples
Demonstrates various scanning scenarios and configurations
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

async def example_basic_scan():
    """Example 1: Basic vulnerability scan"""
    print("=" * 60)
    print("EXAMPLE 1: Basic Vulnerability Scan")
    print("=" * 60)
    
    # Setup
    logger = setup_logger("basic_scan", verbose=True)
    config = Config(
        target_url="https://httpbin.org",
        owasp_all=False,
        chain_attacks=False,
        output_dir="./examples/basic_scan"
    )
    
    # Run scan
    scanner = AstravaAIScanner(config, logger)
    results = await scanner.run_full_scan()
    
    print(f"[OK] Basic scan completed!")
    print(f"[REPORT] Risk Score: {results['risk_score']}/100")
    print(f"[SEARCH] Vulnerabilities: {len(results['vulnerabilities'])}")
    print(f"[FILE] Report: {results['report_path']}")

async def example_owasp_comprehensive():
    """Example 2: Comprehensive OWASP Top 10 scan"""
    print("=" * 60)
    print("EXAMPLE 2: Comprehensive OWASP Top 10 Scan")
    print("=" * 60)
    
    # Setup
    logger = setup_logger("owasp_scan", verbose=True)
    config = Config(
        target_url="https://httpbin.org",
        owasp_all=True,
        chain_attacks=True,
        max_threads=15,
        timeout=45,
        output_dir="./examples/owasp_scan"
    )
    
    # Run scan
    scanner = AstravaAIScanner(config, logger)
    results = await scanner.run_full_scan()
    
    print(f"[OK] OWASP scan completed!")
    print(f"[REPORT] Risk Score: {results['risk_score']}/100")
    print(f"[SEARCH] Vulnerabilities: {len(results['vulnerabilities'])}")
    print(f" Chain Attacks: {len(results.get('chain_attacks', []))}")
    print(f"[FILE] Report: {results['report_path']}")

async def example_passive_only():
    """Example 3: Passive reconnaissance only"""
    print("=" * 60)
    print("EXAMPLE 3: Passive Reconnaissance Only")
    print("=" * 60)
    
    # Setup
    logger = setup_logger("passive_scan", verbose=True)
    config = Config(
        target_url="https://example.com",
        passive_only=True,
        output_dir="./examples/passive_scan"
    )
    
    # Run scan
    scanner = AstravaAIScanner(config, logger)
    results = await scanner.run_passive_scan()
    
    print(f"[OK] Passive scan completed!")
    print(f"[REPORT] Subdomains found: {len(results.get('reconnaissance', {}).get('passive', {}).get('subdomains', []))}")
    print(f"[FILE] Report: {results['report_path']}")

async def example_custom_model():
    """Example 4: Using custom AI model"""
    print("=" * 60)
    print("EXAMPLE 4: Custom AI Model Usage")
    print("=" * 60)
    
    # Setup with different model
    logger = setup_logger("custom_model", verbose=True)
    config = Config(
        target_url="https://httpbin.org",
        model="llama3.2:3b",  # AI model for analysis
        owasp_all=True,
        output_dir="./examples/custom_model"
    )
    
    # Run scan
    scanner = AstravaAIScanner(config, logger)
    results = await scanner.run_full_scan()
    
    print(f"[OK] Custom model scan completed!")
    print(f"[AI] Model used: {config.model}")
    print(f"[REPORT] Risk Score: {results['risk_score']}/100")
    print(f"[FILE] Report: {results['report_path']}")

async def example_json_output():
    """Example 5: JSON output format"""
    print("=" * 60)
    print("EXAMPLE 5: JSON Output Format")
    print("=" * 60)
    
    # Setup
    logger = setup_logger("json_output", verbose=True)
    config = Config(
        target_url="https://httpbin.org",
        report_format="json",
        output_dir="./examples/json_output"
    )
    
    # Run scan
    scanner = AstravaAIScanner(config, logger)
    results = await scanner.run_full_scan()
    
    print(f"[OK] JSON scan completed!")
    print(f"[FILE] JSON Report: {results['report_path']}")

def print_usage_examples():
    """Print command-line usage examples"""
    print("=" * 80)
    print("Astrava AI SECURITY SCANNER - COMMAND LINE EXAMPLES")
    print("=" * 80)
    print()
    
    examples = [
        {
            "title": "Basic Scan",
            "command": "python main.py -u https://example.com",
            "description": "Perform a basic vulnerability scan"
        },
        {
            "title": "Comprehensive OWASP Scan",
            "command": "python main.py -u https://example.com --owasp-all --chain-attacks",
            "description": "Full OWASP Top 10 testing with chain attack analysis"
        },
        {
            "title": "Passive Reconnaissance",
            "command": "python main.py -u https://example.com --passive-only",
            "description": "Only perform passive information gathering"
        },
        {
            "title": "Custom Output Directory",
            "command": "python main.py -u https://example.com --output ./my_reports",
            "description": "Save reports to custom directory"
        },
        {
            "title": "JSON Output Format",
            "command": "python main.py -u https://example.com --format json",
            "description": "Generate machine-readable JSON report"
        },
        {
            "title": "AI-Powered Scan",
            "command": "python main.py -u https://example.com --model llama3.2:3b",
            "description": "Use AI model for enhanced analysis"
        },
        {
            "title": "High Performance Scan",
            "command": "python main.py -u https://example.com --threads 20 --timeout 60",
            "description": "Increase concurrency and timeout for faster scanning"
        },
        {
            "title": "Verbose Logging",
            "command": "python main.py -u https://example.com --verbose",
            "description": "Enable detailed logging output"
        }
    ]
    
    for i, example in enumerate(examples, 1):
        print(f"{i}. {example['title']}")
        print(f"   Command: {example['command']}")
        print(f"   Description: {example['description']}")
        print()

async def run_all_examples():
    """Run all examples sequentially"""
    display_banner()
    
    print(" Running Astrava AI Security Scanner Examples")
    print("[WARNING]  These examples use test targets - ensure you have permission!")
    print()
    
    try:
        # Run examples
        await example_basic_scan()
        print("\n" + "="*60 + "\n")
        
        await example_passive_only()
        print("\n" + "="*60 + "\n")
        
        await example_json_output()
        print("\n" + "="*60 + "\n")
        
        # Skip comprehensive scans in examples to save time
        print("[OK] All examples completed successfully!")
        print("\n For more advanced examples, run:")
        print("   python examples.py --comprehensive")
        
    except KeyboardInterrupt:
        print("\n[WARNING]  Examples interrupted by user")
    except Exception as e:
        print(f"\n[ERROR] Example failed: {str(e)}")

async def run_comprehensive_examples():
    """Run comprehensive examples (longer running)"""
    display_banner()
    
    print(" Running Comprehensive Astrava Examples")
    print("[WARNING]  These examples may take longer to complete")
    print()
    
    try:
        await example_owasp_comprehensive()
        print("\n" + "="*60 + "\n")
        
        await example_custom_model()
        print("\n" + "="*60 + "\n")
        
        print("[OK] All comprehensive examples completed!")
        
    except KeyboardInterrupt:
        print("\n[WARNING]  Examples interrupted by user")
    except Exception as e:
        print(f"\n[ERROR] Example failed: {str(e)}")

def main():
    """Main example runner"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Astrava AI Security Scanner Examples")
    parser.add_argument('--comprehensive', action='store_true', 
                       help='Run comprehensive examples (longer)')
    parser.add_argument('--commands', action='store_true',
                       help='Show command-line examples only')
    
    args = parser.parse_args()
    
    if args.commands:
        print_usage_examples()
        return
    
    # Create examples directory
    Path("examples").mkdir(exist_ok=True)
    
    if args.comprehensive:
        asyncio.run(run_comprehensive_examples())
    else:
        asyncio.run(run_all_examples())

if __name__ == "__main__":
    main()
