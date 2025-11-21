"""
Main Scanner Engine for Astrava AI Security Scanner
Orchestrates all scanning modules and AI analysis
"""

import asyncio
import time
from datetime import datetime
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse
import logging

from .ai_engine import AIEngine
from .config import Config, OWASP_TOP_10
from modules.reconnaissance import ReconnaissanceModule
from modules.vulnerability_scanner import VulnerabilityScanner
from modules.owasp_scanner import OWASPScanner
from modules.chain_attacks import ChainAttackModule
from utils.report_generator import ReportGenerator
from utils.risk_calculator import RiskCalculator

class AstravaAIScanner:
    """Main scanner engine that orchestrates all modules"""
    
    def __init__(self, config: Config, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.ai_engine = AIEngine(config.model, config.ollama_url)
        
        # Initialize modules
        self.recon_module = ReconnaissanceModule(config, logger)
        self.vuln_scanner = VulnerabilityScanner(config, logger, self.ai_engine)
        self.owasp_scanner = OWASPScanner(config, logger, self.ai_engine)
        self.chain_attack_module = ChainAttackModule(config, logger, self.ai_engine)
        
        # Results storage
        self.scan_results = {
            'target': config.target_url,
            'timestamp': datetime.now().isoformat(),
            'config': {
                'passive_only': config.passive_only,
                'active_only': config.active_only,
                'owasp_all': config.owasp_all,
                'chain_attacks': config.chain_attacks,
                'model': config.model
            },
            'reconnaissance': {},
            'vulnerabilities': [],
            'owasp_results': {},
            'chain_attacks': [],
            'ai_analysis': {},
            'risk_score': 0,
            'scan_duration': 0
        }
    
    async def run_full_scan(self) -> Dict[str, Any]:
        """Run a complete security scan"""
        start_time = time.time()
        
        self.logger.info(f"Starting comprehensive scan of {self.config.target_url}")
        
        try:
            async with self.ai_engine:
                # Phase 1: Reconnaissance
                if not self.config.active_only:
                    self.logger.info("Phase 1: Passive Reconnaissance")
                    passive_recon = await self.recon_module.passive_reconnaissance()
                    self.scan_results['reconnaissance']['passive'] = passive_recon
                
                if not self.config.passive_only and not self.config.skip_port_scan:
                    self.logger.info("Phase 1: Active Reconnaissance")
                    active_recon = await self.recon_module.active_reconnaissance()
                    self.scan_results['reconnaissance']['active'] = active_recon
                elif self.config.skip_port_scan:
                    self.logger.info("Skipping Active Reconnaissance (Basic Mode)")
                    self.scan_results['reconnaissance']['active'] = {'ports': [], 'services': []}
                
                # AI Analysis of reconnaissance data
                recon_data = self.scan_results['reconnaissance']
                if recon_data:
                    self.logger.info("Analyzing reconnaissance data with AI...")
                    recon_analysis = await self.ai_engine.generate_reconnaissance_analysis(recon_data)
                    self.scan_results['ai_analysis']['reconnaissance'] = recon_analysis
                
                # Phase 2: Vulnerability Scanning
                if not self.config.passive_only:
                    self.logger.info("Phase 2: Vulnerability Scanning")
                    vulnerabilities = await self.vuln_scanner.scan_vulnerabilities()
                    self.scan_results['vulnerabilities'].extend(vulnerabilities)
                
                # Phase 3: OWASP Top 10 Testing
                if self.config.owasp_all and not self.config.passive_only:
                    self.logger.info("Phase 3: OWASP Top 10 Testing")
                    owasp_results = await self.owasp_scanner.test_owasp_top_10()
                    self.scan_results['owasp_results'] = owasp_results
                    
                    # Add OWASP vulnerabilities to main list
                    for category, results in owasp_results.items():
                        if 'vulnerabilities' in results:
                            self.scan_results['vulnerabilities'].extend(results['vulnerabilities'])
                
                # Phase 4: Chain Attack Analysis
                if self.config.chain_attacks and self.scan_results['vulnerabilities']:
                    self.logger.info("Phase 4: Chain Attack Analysis")
                    chain_attacks = await self.chain_attack_module.analyze_attack_chains(
                        self.scan_results['vulnerabilities']
                    )
                    self.scan_results['chain_attacks'] = chain_attacks
                
                # Phase 5: AI Analysis and Risk Assessment
                self.logger.info("Phase 5: AI Analysis and Risk Assessment")
                
                # Skip AI analysis if requested for speed
                if not getattr(self, 'skip_ai_analysis', False):
                    # Optimize AI analysis - only analyze unique vulnerability types
                    unique_vulns = {}
                    for vuln in self.scan_results['vulnerabilities']:
                        vuln_type = vuln.get('type', 'Unknown')
                        if vuln_type not in unique_vulns:
                            unique_vulns[vuln_type] = vuln
                    
                    # Analyze only one vulnerability per type with AI (max 3 types for speed)
                    if len(unique_vulns) <= 3:
                        print("AI analyzing vulnerability types...")
                        for vuln_type, sample_vuln in list(unique_vulns.items())[:3]:
                            ai_analysis = await self.ai_engine.analyze_vulnerability(sample_vuln)
                            # Apply analysis to all vulnerabilities of this type
                            for vuln in self.scan_results['vulnerabilities']:
                                if vuln.get('type') == vuln_type:
                                    vuln['ai_analysis'] = ai_analysis
                    else:
                        print("Skipping detailed AI analysis (too many vulnerability types)")
                else:
                    print("Skipping AI analysis for faster scanning")
                
                # Calculate risk score
                risk_calculator = RiskCalculator()
                self.scan_results['risk_score'] = risk_calculator.calculate_risk_score(
                    self.scan_results['vulnerabilities'],
                    self.scan_results['reconnaissance']
                )
                
                # Generate executive summary (only if we have vulnerabilities)
                if len(self.scan_results['vulnerabilities']) > 0:
                    print("[AI] AI generating executive summary...")
                    executive_summary = await self.ai_engine.generate_executive_summary(self.scan_results)
                    self.scan_results['ai_analysis']['executive_summary'] = executive_summary
                else:
                    self.scan_results['ai_analysis']['executive_summary'] = "No significant vulnerabilities detected during automated scanning."
                
                # Phase 6: Report Generation
                self.logger.info("Phase 6: Report Generation")
                scan_duration = time.time() - start_time
                self.scan_results['scan_duration'] = scan_duration
                
                report_generator = ReportGenerator(self.config, self.logger)
                report_path = await report_generator.generate_report(self.scan_results)
                self.scan_results['report_path'] = report_path
                
                return self.scan_results
                
        except Exception as e:
            self.logger.error(f"Scan failed: {str(e)}")
            raise
    
    async def run_passive_scan(self) -> Dict[str, Any]:
        """Run only passive reconnaissance"""
        self.logger.info("Running passive reconnaissance scan")
        
        async with self.ai_engine:
            passive_recon = await self.recon_module.passive_reconnaissance()
            self.scan_results['reconnaissance']['passive'] = passive_recon
            
            # AI analysis
            recon_analysis = await self.ai_engine.generate_reconnaissance_analysis(passive_recon)
            self.scan_results['ai_analysis']['reconnaissance'] = recon_analysis
            
            # Generate report
            report_generator = ReportGenerator(self.config, self.logger)
            report_path = await report_generator.generate_report(self.scan_results)
            self.scan_results['report_path'] = report_path
            
            return self.scan_results
    
    async def run_active_scan(self) -> Dict[str, Any]:
        """Run only active scanning (no passive recon)"""
        self.logger.info("Running active vulnerability scan")
        
        async with self.ai_engine:
            # Quick active recon for context
            active_recon = await self.recon_module.active_reconnaissance()
            self.scan_results['reconnaissance']['active'] = active_recon
            
            # Vulnerability scanning
            vulnerabilities = await self.vuln_scanner.scan_vulnerabilities()
            self.scan_results['vulnerabilities'].extend(vulnerabilities)
            
            # OWASP testing
            if self.config.owasp_all:
                owasp_results = await self.owasp_scanner.test_owasp_top_10()
                self.scan_results['owasp_results'] = owasp_results
                
                for category, results in owasp_results.items():
                    if 'vulnerabilities' in results:
                        self.scan_results['vulnerabilities'].extend(results['vulnerabilities'])
            
            # Risk assessment
            risk_calculator = RiskCalculator()
            self.scan_results['risk_score'] = risk_calculator.calculate_risk_score(
                self.scan_results['vulnerabilities'],
                self.scan_results['reconnaissance']
            )
            
            # Generate report
            report_generator = ReportGenerator(self.config, self.logger)
            report_path = await report_generator.generate_report(self.scan_results)
            self.scan_results['report_path'] = report_path
            
            return self.scan_results
    
    def get_scan_progress(self) -> Dict[str, Any]:
        """Get current scan progress"""
        return {
            'phase': getattr(self, 'current_phase', 'Initializing'),
            'vulnerabilities_found': len(self.scan_results['vulnerabilities']),
            'current_risk_score': self.scan_results['risk_score'],
            'elapsed_time': time.time() - self.scan_results['timestamp']
        }
