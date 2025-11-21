#!/usr/bin/env python3
"""
Astrava AI Security Scanner - Attack Modes System
Defines Basic, Medium, and Aggressive attack configurations
"""

import sys
import subprocess
from pathlib import Path
from datetime import datetime

class AstravaAttackModes:
    """Attack modes configuration for Astrava AI Security Scanner"""
    
    def __init__(self):
        self.modes = {
            'basic': {
                'name': 'Basic Scan',
                'description': 'Fast reconnaissance and common vulnerabilities (Fast scan)',
                'threads': 5,
                'timeout': 15,
                'options': ['--passive-only'],
                'ai_enabled': False,
                'duration': 'Fast'
            },
            'medium': {
                'name': 'Medium Scan', 
                'description': 'Comprehensive OWASP testing with AI analysis (Standard scan)',
                'threads': 10,
                'timeout': 30,
                'options': ['--owasp-all'],
                'ai_enabled': True,
                'duration': 'Standard'
            },
            'aggressive': {
                'name': 'Aggressive Scan',
                'description': 'Deep penetration testing with AI chain attacks (Thorough scan)',
                'threads': 20,
                'timeout': 60,
                'options': ['--owasp-all', '--chain-attacks', '--active-only'],
                'ai_enabled': True,
                'duration': 'Thorough'
            }
        }
    
    def get_mode_config(self, mode):
        """Get configuration for specified attack mode"""
        return self.modes.get(mode, self.modes['medium'])
    
    def run_attack(self, mode, target_url, ai_model='llama3.2:3b', custom_payloads=None, 
                   output_format='html', verbose=False):
        """Run attack with specified mode"""
        
        config = self.get_mode_config(mode)
        
        # Safe print without Unicode
        print("=" * 70)
        print(f"Astrava AI SECURITY SCANNER - {config['name'].upper()}")
        print("=" * 70)
        print(f"Target: {target_url}")
        print(f"Mode: {config['name']}")
        print(f"Description: {config['description']}")
        print(f"AI Model: {ai_model if config['ai_enabled'] else 'Disabled'}")
        print(f"Expected Duration: {config['duration']}")
        print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 70)
        
        # Build command
        cmd = ['python', 'main.py', '-u', target_url]
        
        # Add mode-specific options
        cmd.extend(config['options'])
        
        # Add performance settings
        cmd.extend(['--threads', str(config['threads'])])
        cmd.extend(['--timeout', str(config['timeout'])])
        
        # Add AI model if enabled
        if config['ai_enabled']:
            cmd.extend(['--model', ai_model])
        
        # Add custom payloads if provided
        if custom_payloads:
            cmd.extend(['--custom-payloads', custom_payloads])
        
        # Add output format
        cmd.extend(['--format', output_format])
        
        # Add verbose if requested
        if verbose:
            cmd.append('--verbose')
        
        print(f"Command: {' '.join(cmd)}")
        print()
        
        try:
            # Run the scan with proper encoding handling
            process = subprocess.Popen(
                cmd,
                cwd=Path(__file__).parent,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding='utf-8',
                errors='replace'  # Replace problematic characters
            )
            
            # Read output line by line
            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    # Clean output of problematic characters
                    clean_output = output.encode('ascii', 'ignore').decode('ascii')
                    print(clean_output.strip())
            
            return_code = process.poll()
            
            print()
            print("=" * 70)
            if return_code == 0:
                print(f"{config['name'].upper()} COMPLETED SUCCESSFULLY")
            else:
                print(f"{config['name'].upper()} COMPLETED WITH ERRORS")
            print("=" * 70)
            
            return return_code
            
        except Exception as e:
            print(f"ERROR: Failed to run {config['name']}: {e}")
            return 1

def main():
    """Main function for attack modes"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Astrava AI Security Scanner - Attack Modes')
    parser.add_argument('-u', '--url', required=True, help='Target URL to scan')
    parser.add_argument('-m', '--mode', choices=['basic', 'medium', 'aggressive'], 
                       default='medium', help='Attack mode')
    parser.add_argument('--ai-model', default='llama3.2:3b', 
                       help='AI model for analysis')
    parser.add_argument('--custom-payloads', help='Custom payloads file')
    parser.add_argument('--format', choices=['html', 'json', 'pdf'], 
                       default='html', help='Output format')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Create attack modes instance
    attack_modes = AstravaAttackModes()
    
    # Show mode information
    config = attack_modes.get_mode_config(args.mode)
    print()
    print("Astrava AI SECURITY SCANNER - ATTACK MODES")
    print("=" * 50)
    print("Available Modes:")
    for mode_key, mode_config in attack_modes.modes.items():
        marker = " >>> " if mode_key == args.mode else "     "
        print(f"{marker}{mode_config['name']}: {mode_config['description']}")
    print()
    
    # Confirm aggressive mode
    if args.mode == 'aggressive':
        print("WARNING: Aggressive mode uses intensive scanning techniques.")
        print("Only use on systems you own or have explicit permission to test.")
        response = input("Continue with aggressive scan? (y/N): ")
        if response.lower() != 'y':
            print("Scan cancelled.")
            return 1
    
    # Run the attack
    return attack_modes.run_attack(
        args.mode, 
        args.url, 
        args.ai_model, 
        args.custom_payloads,
        args.format,
        args.verbose
    )

if __name__ == "__main__":
    sys.exit(main())
