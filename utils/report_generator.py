"""
Report Generator for Astrava AI Security Scanner
Generates comprehensive HTML and PDF reports
"""

import json
import asyncio
import html
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import logging
from urllib.parse import urlparse

from core.config import Config
from utils.risk_calculator import RiskCalculator

class ReportGenerator:
    """Advanced report generator with multiple formats"""
    
    def __init__(self, config: Config, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.risk_calculator = RiskCalculator()
        
        # Ensure output directory exists
        Path(config.output_dir).mkdir(parents=True, exist_ok=True)
    
    def format_timestamp(self, timestamp):
        """Format timestamp handling both string and float formats"""
        try:
            if isinstance(timestamp, str):
                # ISO format string
                return datetime.fromisoformat(timestamp).strftime('%Y-%m-%d %H:%M:%S')
            elif isinstance(timestamp, (int, float)):
                # Unix timestamp
                return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
            else:
                return str(timestamp)
        except Exception:
            return "Unknown"
    
    async def generate_report(self, scan_results: Dict[str, Any]) -> str:
        """Generate report in specified format"""
        
        if self.config.report_format.lower() == 'html':
            return await self.generate_html_report(scan_results)
        elif self.config.report_format.lower() == 'json':
            return await self.generate_json_report(scan_results)
        elif self.config.report_format.lower() == 'pdf':
            return await self.generate_pdf_report(scan_results)
        else:
            # Default to HTML
            return await self.generate_html_report(scan_results)
    
    async def generate_html_report(self, scan_results: Dict[str, Any]) -> str:
        """Generate comprehensive HTML report"""
        
        self.logger.info("Generating HTML report...")
        
        # Calculate additional metrics
        risk_score = scan_results.get('risk_score', 0)
        vulnerabilities = scan_results.get('vulnerabilities', [])
        
        # Business impact assessment
        business_impact = self.risk_calculator.calculate_business_impact(risk_score, vulnerabilities)
        
        # Risk recommendations
        recommendations = self.risk_calculator.generate_risk_recommendations(risk_score, vulnerabilities)
        
        # Generate filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        domain = urlparse(scan_results['target']).netloc.replace('.', '_')
        filename = f"Astrava_report_{domain}_{timestamp}.html"
        filepath = Path(self.config.output_dir) / filename
        
        # Generate HTML content
        html_content = self.create_html_content(scan_results, business_impact, recommendations)
        
        # Write to file
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        self.logger.info(f"HTML report generated: {filepath}")
        return str(filepath)
    
    def create_html_content(self, scan_results: Dict[str, Any], 
                          business_impact: Dict[str, Any], 
                          recommendations: List[str]) -> str:
        """Create comprehensive HTML report content"""
        
        risk_score = scan_results.get('risk_score', 0)
        vulnerabilities = scan_results.get('vulnerabilities', [])
        reconnaissance = scan_results.get('reconnaissance', {})
        owasp_results = scan_results.get('owasp_results', {})
        chain_attacks = scan_results.get('chain_attacks', [])
        ai_analysis = scan_results.get('ai_analysis', {})
        
        # Risk level and color
        risk_level = self.risk_calculator.get_risk_level(risk_score)
        risk_colors = {
            'Critical': '#dc3545',
            'High': '#fd7e14', 
            'Medium': '#ffc107',
            'Low': '#28a745',
            'Minimal': '#17a2b8'
        }
        risk_color = risk_colors.get(risk_level, '#6c757d')
        
        # Vulnerability statistics
        vuln_stats = self.calculate_vulnerability_statistics(vulnerabilities)
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Astrava AI Security Report - {scan_results['target']}</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        :root {{
            --primary-color: #2c3e50;
            --secondary-color: #3498db;
            --success-color: #27ae60;
            --warning-color: #f39c12;
            --danger-color: #e74c3c;
            --info-color: #3498db;
            --dark-color: #2c3e50;
            --light-color: #ecf0f1;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            margin: 0;
            padding: 20px;
        }}
        
        .main-container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        
        .report-header {{
            background: rgba(255, 255, 255, 0.95);
            border-radius: 20px;
            padding: 40px;
            margin-bottom: 30px;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.1);
            backdrop-filter: blur(10px);
            text-align: center;
        }}
        
        .report-title {{
            font-size: 3rem;
            font-weight: bold;
            background: linear-gradient(135deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 20px;
        }}
        
        .report-subtitle {{
            color: #6c757d;
            font-size: 1.2rem;
            margin-bottom: 30px;
        }}
        
        .scan-info {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 30px;
        }}
        
        .info-card {{
            background: rgba(255, 255, 255, 0.8);
            padding: 20px;
            border-radius: 15px;
            text-align: center;
            border-left: 4px solid var(--secondary-color);
        }}
        
        .risk-dashboard {{
            display: grid;
            grid-template-columns: 1fr 2fr;
            gap: 30px;
            margin-bottom: 30px;
        }}
        
        .risk-score-card {{
            background: rgba(255, 255, 255, 0.95);
            border-radius: 20px;
            padding: 40px;
            text-align: center;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.1);
            backdrop-filter: blur(10px);
        }}
        
        .risk-meter {{
            width: 200px;
            height: 200px;
            border-radius: 50%;
            background: conic-gradient(
                {risk_color} 0deg {risk_score * 3.6}deg,
                #e9ecef {risk_score * 3.6}deg 360deg
            );
            margin: 20px auto;
            display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2);
        }}
        
        .risk-meter::before {{
            content: '';
            width: 160px;
            height: 160px;
            background: white;
            border-radius: 50%;
            position: absolute;
        }}
        
        .risk-score-text {{
            position: relative;
            z-index: 1;
            font-size: 2.5rem;
            font-weight: bold;
            color: {risk_color};
        }}
        
        .risk-level {{
            font-size: 1.8rem;
            color: {risk_color};
            font-weight: bold;
            margin: 15px 0;
        }}
        
        .executive-summary {{
            background: rgba(255, 255, 255, 0.95);
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.1);
            backdrop-filter: blur(10px);
        }}
        
        .summary-stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }}
        
        .stat-card {{
            background: linear-gradient(135deg, #f8f9fa, #e9ecef);
            padding: 25px;
            border-radius: 15px;
            text-align: center;
            border-left: 4px solid var(--secondary-color);
        }}
        
        .stat-number {{
            font-size: 2.5rem;
            font-weight: bold;
            color: var(--primary-color);
        }}
        
        .stat-label {{
            color: #6c757d;
            font-size: 0.9rem;
            margin-top: 5px;
        }}
        
        .section {{
            background: rgba(255, 255, 255, 0.95);
            border-radius: 20px;
            padding: 40px;
            margin-bottom: 30px;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.1);
            backdrop-filter: blur(10px);
        }}
        
        .section-title {{
            font-size: 2rem;
            color: var(--primary-color);
            border-bottom: 3px solid var(--secondary-color);
            padding-bottom: 15px;
            margin-bottom: 30px;
            display: flex;
            align-items: center;
            gap: 15px;
        }}
        
        .vulnerability-card {{
            background: #fff;
            border: 1px solid #dee2e6;
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 25px;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.05);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }}
        
        .vulnerability-card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(0, 0, 0, 0.1);
        }}
        
        .vulnerability-card.critical {{
            border-left: 5px solid var(--danger-color);
        }}
        
        .vulnerability-card.high {{
            border-left: 5px solid #fd7e14;
        }}
        
        .vulnerability-card.medium {{
            border-left: 5px solid var(--warning-color);
        }}
        
        .vulnerability-card.low {{
            border-left: 5px solid var(--success-color);
        }}
        
        .vulnerability-header {{
            display: flex;
            justify-content: between;
            align-items: center;
            margin-bottom: 20px;
        }}
        
        .vulnerability-title {{
            font-size: 1.3rem;
            font-weight: bold;
            color: var(--primary-color);
            margin: 0;
        }}
        
        .severity-badge {{
            padding: 8px 16px;
            border-radius: 25px;
            color: white;
            font-weight: bold;
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        
        .severity-critical {{
            background: var(--danger-color);
        }}
        
        .severity-high {{
            background: #fd7e14;
        }}
        
        .severity-medium {{
            background: var(--warning-color);
            color: #333;
        }}
        
        .severity-low {{
            background: var(--success-color);
        }}
        
        .vulnerability-details {{
            display: grid;
            gap: 15px;
        }}
        
        .detail-item {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 10px;
            border-left: 3px solid var(--secondary-color);
        }}
        
        .detail-label {{
            font-weight: bold;
            color: var(--primary-color);
            display: block;
            margin-bottom: 5px;
        }}
        
        .code-block {{
            background: #2d3748;
            color: #e2e8f0;
            padding: 15px;
            border-radius: 10px;
            font-family: 'Courier New', monospace;
            overflow-x: auto;
            margin: 15px 0;
            border: 1px solid #4a5568;
        }}
        
        .ai-analysis {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 20px;
            margin: 25px 0;
            box-shadow: 0 10px 30px rgba(102, 126, 234, 0.3);
        }}
        
        .ai-analysis h4 {{
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            font-size: 1.3rem;
        }}
        
        .ai-analysis h4::before {{
            content: "[AI]";
            margin-right: 15px;
            font-size: 1.5rem;
        }}
        
        .chain-attack-card {{
            background: linear-gradient(135deg, #ff6b6b, #ee5a24);
            color: white;
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 20px;
            box-shadow: 0 10px 30px rgba(255, 107, 107, 0.3);
        }}
        
        .attack-steps {{
            display: grid;
            gap: 15px;
            margin-top: 20px;
        }}
        
        .attack-step {{
            background: rgba(255, 255, 255, 0.1);
            padding: 15px;
            border-radius: 10px;
            border-left: 4px solid rgba(255, 255, 255, 0.5);
        }}
        
        .business-impact-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }}
        
        .impact-card {{
            background: linear-gradient(135deg, #f8f9fa, #e9ecef);
            padding: 20px;
            border-radius: 15px;
            text-align: center;
        }}
        
        .impact-high {{
            border-left: 4px solid var(--danger-color);
        }}
        
        .impact-medium {{
            border-left: 4px solid var(--warning-color);
        }}
        
        .impact-low {{
            border-left: 4px solid var(--success-color);
        }}
        
        .recommendations-list {{
            list-style: none;
            padding: 0;
        }}
        
        .recommendations-list li {{
            background: #f8f9fa;
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 10px;
            border-left: 4px solid var(--secondary-color);
        }}
        
        .owasp-category {{
            background: linear-gradient(135deg, #3498db, #2980b9);
            color: white;
            padding: 20px;
            border-radius: 15px;
            margin-bottom: 20px;
        }}
        
        .footer {{
            text-align: center;
            color: rgba(255, 255, 255, 0.9);
            margin-top: 50px;
            padding: 30px;
            background: rgba(0, 0, 0, 0.1);
            border-radius: 15px;
        }}
        
        @media (max-width: 768px) {{
            .main-container {{
                padding: 10px;
            }}
            
            .report-title {{
                font-size: 2rem;
            }}
            
            .risk-dashboard {{
                grid-template-columns: 1fr;
            }}
            
            .risk-meter {{
                width: 150px;
                height: 150px;
            }}
            
            .risk-meter::before {{
                width: 120px;
                height: 120px;
            }}
        }}
        
        .progress-bar {{
            width: 100%;
            height: 8px;
            background: #e9ecef;
            border-radius: 4px;
            overflow: hidden;
            margin: 10px 0;
        }}
        
        .progress-fill {{
            height: 100%;
            background: {risk_color};
            width: {risk_score}%;
            transition: width 0.3s ease;
        }}
        
        .table-responsive {{
            background: white;
            border-radius: 15px;
            overflow: hidden;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.05);
        }}
        
        .table {{
            margin: 0;
        }}
        
        .table th {{
            background: var(--primary-color);
            color: white;
            border: none;
            padding: 15px;
        }}
        
        .table td {{
            padding: 15px;
            border-color: #e9ecef;
        }}
    </style>
</head>
<body>
    <div class="main-container">
        <!-- Header -->
        <div class="report-header">
            <h1 class="report-title">
                <i class="fas fa-shield-alt"></i> Astrava AI Security Report
            </h1>
            <p class="report-subtitle">Comprehensive AI-Powered Security Assessment</p>
            
            <div class="scan-info">
                <div class="info-card">
                    <i class="fas fa-bullseye fa-2x text-primary mb-2"></i>
                    <h5>Target</h5>
                    <p class="mb-0">{scan_results['target']}</p>
                </div>
                <div class="info-card">
                    <i class="fas fa-calendar fa-2x text-primary mb-2"></i>
                    <h5>Scan Date</h5>
                    <p class="mb-0">{self.format_timestamp(scan_results['timestamp'])}</p>
                </div>
                <div class="info-card">
                    <i class="fas fa-clock fa-2x text-primary mb-2"></i>
                    <h5>Duration</h5>
                    <p class="mb-0">{scan_results.get('scan_duration', 0):.2f} seconds</p>
                </div>
                <div class="info-card">
                    <i class="fas fa-robot fa-2x text-primary mb-2"></i>
                    <h5>AI Model</h5>
                    <p class="mb-0">{scan_results.get('config', {}).get('model', 'llama3.2:3b')}</p>
                </div>
            </div>
        </div>
        
        <!-- Risk Dashboard -->
        <div class="risk-dashboard">
            <div class="risk-score-card">
                <h2><i class="fas fa-tachometer-alt"></i> Risk Assessment</h2>
                <div class="risk-meter">
                    <div class="risk-score-text">{risk_score}</div>
                </div>
                <div class="risk-level">{risk_level} Risk</div>
                <div class="progress-bar">
                    <div class="progress-fill"></div>
                </div>
                <p class="mt-3 text-muted">Risk Score: {risk_score}/100</p>
                <p class="small">{self.risk_calculator.get_risk_description(risk_score)}</p>
            </div>
            
            <div class="executive-summary">
                <h2><i class="fas fa-chart-bar"></i> Executive Summary</h2>
                <div class="summary-stats">
                    <div class="stat-card">
                        <div class="stat-number">{len(vulnerabilities)}</div>
                        <div class="stat-label">Total Vulnerabilities</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{vuln_stats['critical']}</div>
                        <div class="stat-label">Critical</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{vuln_stats['high']}</div>
                        <div class="stat-label">High</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{vuln_stats['medium']}</div>
                        <div class="stat-label">Medium</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{vuln_stats['low']}</div>
                        <div class="stat-label">Low</div>
                    </div>
                </div>
                
                {self.generate_executive_summary_content(ai_analysis.get('executive_summary', ''))}
            </div>
        </div>"""
        
        # Add Business Impact section
        html_content += self.generate_business_impact_section(business_impact)
        
        # Add Reconnaissance section
        html_content += self.generate_reconnaissance_section(reconnaissance)
        
        # Add Vulnerabilities section
        html_content += self.generate_vulnerabilities_section(vulnerabilities)
        
        # Add OWASP Top 10 section
        html_content += self.generate_owasp_section(owasp_results)
        
        # Add Chain Attacks section
        if chain_attacks:
            html_content += self.generate_chain_attacks_section(chain_attacks)
        
        # Add Recommendations section
        html_content += self.generate_recommendations_section(recommendations)
        
        # Add AI Analysis section
        html_content += self.generate_ai_analysis_section(ai_analysis)
        
        # Footer
        html_content += f"""
        <div class="footer">
            <p><i class="fas fa-robot"></i> Generated by Astrava AI Security Scanner</p>
            <p><i class="fas fa-exclamation-triangle"></i> This report is for educational and authorized testing purposes only</p>
            <p class="small mt-3">
                Powered by Ollama {scan_results.get('config', {}).get('model', 'llama3.2:3b')} | 
                Scan completed in {scan_results.get('scan_duration', 0):.2f} seconds
            </p>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>"""
        
        return html_content
    
    def calculate_vulnerability_statistics(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
        """Calculate vulnerability statistics"""
        stats = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Low').lower()
            if severity in stats:
                stats[severity] += 1
        
        return stats
    
    def generate_executive_summary_content(self, ai_summary: str) -> str:
        """Generate executive summary content"""
        if ai_summary:
            # Format markdown to HTML
            formatted_summary = self.format_markdown_to_html(ai_summary)
            return f"""
                <div class="ai-analysis">
                    <h4>AI Executive Summary</h4>
                    <div style="white-space: normal; line-height: 1.8;">{formatted_summary}</div>
                </div>
            """
        return ""
    
    def generate_business_impact_section(self, business_impact: Dict[str, Any]) -> str:
        """Generate business impact section"""
        return f"""
        <div class="section">
            <h2 class="section-title">
                <i class="fas fa-building"></i> Business Impact Assessment
            </h2>
            
            <div class="business-impact-grid">
                <div class="impact-card impact-{business_impact['confidentiality'].lower()}">
                    <i class="fas fa-eye-slash fa-2x mb-3"></i>
                    <h5>Confidentiality</h5>
                    <p class="mb-0">{business_impact['confidentiality']} Impact</p>
                </div>
                <div class="impact-card impact-{business_impact['integrity'].lower()}">
                    <i class="fas fa-shield-alt fa-2x mb-3"></i>
                    <h5>Integrity</h5>
                    <p class="mb-0">{business_impact['integrity']} Impact</p>
                </div>
                <div class="impact-card impact-{business_impact['availability'].lower()}">
                    <i class="fas fa-server fa-2x mb-3"></i>
                    <h5>Availability</h5>
                    <p class="mb-0">{business_impact['availability']} Impact</p>
                </div>
                <div class="impact-card impact-{business_impact['financial_impact'].lower()}">
                    <i class="fas fa-dollar-sign fa-2x mb-3"></i>
                    <h5>Financial</h5>
                    <p class="mb-0">{business_impact['financial_impact']} Impact</p>
                </div>
                <div class="impact-card impact-{business_impact['regulatory_impact'].lower()}">
                    <i class="fas fa-gavel fa-2x mb-3"></i>
                    <h5>Regulatory</h5>
                    <p class="mb-0">{business_impact['regulatory_impact']} Impact</p>
                </div>
                <div class="impact-card impact-{business_impact['reputation_impact'].lower()}">
                    <i class="fas fa-star fa-2x mb-3"></i>
                    <h5>Reputation</h5>
                    <p class="mb-0">{business_impact['reputation_impact']} Impact</p>
                </div>
            </div>
        </div>
        """
    
    def generate_reconnaissance_section(self, reconnaissance: Dict[str, Any]) -> str:
        """Generate reconnaissance section"""
        if not reconnaissance:
            return ""
        
        content = """
        <div class="section">
            <h2 class="section-title">
                <i class="fas fa-search"></i> Reconnaissance Results
            </h2>
        """
        
        # Passive reconnaissance
        passive_data = reconnaissance.get('passive', {})
        if passive_data:
            content += """
            <h3><i class="fas fa-eye"></i> Passive Reconnaissance</h3>
            <div class="row">
            """
            
            # DNS information
            dns_info = passive_data.get('dns', {})
            if dns_info:
                content += f"""
                <div class="col-md-6">
                    <div class="detail-item">
                        <span class="detail-label">DNS Records</span>
                        <div class="table-responsive">
                            <table class="table table-sm">
                                <thead>
                                    <tr><th>Type</th><th>Records</th></tr>
                                </thead>
                                <tbody>
                """
                for record_type, records in dns_info.items():
                    if isinstance(records, list) and records:
                        content += f"<tr><td>{record_type}</td><td>{len(records)} records</td></tr>"
                content += """
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
                """
            
            # Subdomains
            subdomains = passive_data.get('subdomains', [])
            if subdomains:
                content += f"""
                <div class="col-md-6">
                    <div class="detail-item">
                        <span class="detail-label">Discovered Subdomains ({len(subdomains)})</span>
                        <ul class="list-unstyled">
                """
                for subdomain in subdomains[:10]:  # Show first 10
                    content += f'<li><i class="fas fa-globe"></i> {subdomain}</li>'
                if len(subdomains) > 10:
                    content += f"<li><small>... and {len(subdomains) - 10} more</small></li>"
                content += """
                        </ul>
                    </div>
                </div>
                """
            
            content += "</div>"
        
        # Active reconnaissance
        active_data = reconnaissance.get('active', {})
        if active_data:
            content += """
            <h3><i class="fas fa-crosshairs"></i> Active Reconnaissance</h3>
            <div class="row">
            """
            
            # Open ports
            open_ports = active_data.get('open_ports', [])
            services = active_data.get('services', {})
            if open_ports:
                content += f"""
                <div class="col-md-6">
                    <div class="detail-item">
                        <span class="detail-label">Open Ports & Services</span>
                        <div class="table-responsive">
                            <table class="table table-sm">
                                <thead>
                                    <tr><th>Port</th><th>Service</th></tr>
                                </thead>
                                <tbody>
                """
                for port in open_ports:
                    service = services.get(port, 'Unknown')
                    content += f"<tr><td>{port}</td><td>{service}</td></tr>"
                content += """
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
                """
            
            # Technologies
            technologies = active_data.get('technologies', [])
            if technologies:
                content += f"""
                <div class="col-md-6">
                    <div class="detail-item">
                        <span class="detail-label">Detected Technologies</span>
                        <div class="d-flex flex-wrap gap-2">
                """
                for tech in technologies:
                    content += f'<span class="badge bg-primary">{tech}</span>'
                content += """
                        </div>
                    </div>
                </div>
                """
            
            content += "</div>"
        
        content += "</div>"
        return content
    
    def generate_vulnerabilities_section(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Generate vulnerabilities section"""
        if not vulnerabilities:
            return """
            <div class="section">
                <h2 class="section-title">
                    <i class="fas fa-check-circle text-success"></i> Vulnerabilities
                </h2>
                <div class="alert alert-success" role="alert">
                    <h4 class="alert-heading">No Critical Vulnerabilities Detected</h4>
                    <p>The automated scan did not detect any obvious vulnerabilities. However, this does not guarantee the application is secure. Consider manual testing and comprehensive code review.</p>
                </div>
            </div>
            """
        
        # Group vulnerabilities by severity
        vuln_by_severity = {'Critical': [], 'High': [], 'Medium': [], 'Low': [], 'Info': []}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Low')
            if severity in vuln_by_severity:
                vuln_by_severity[severity].append(vuln)
        
        content = f"""
        <div class="section">
            <h2 class="section-title">
                <i class="fas fa-exclamation-triangle"></i> Vulnerabilities Detected ({len(vulnerabilities)})
            </h2>
        """
        
        for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
            vulns = vuln_by_severity[severity]
            if vulns:
                content += f"""
                <h3 class="mt-4">
                    <i class="fas fa-bug"></i> {severity} Severity ({len(vulns)})
                </h3>
                """
                
                for vuln in vulns:
                    content += self.generate_vulnerability_card(vuln, severity.lower())
        
        content += "</div>"
        return content
    
    def generate_vulnerability_card(self, vuln: Dict[str, Any], severity_class: str) -> str:
        """Generate individual vulnerability card"""
        return f"""
        <div class="vulnerability-card {severity_class}">
            <div class="vulnerability-header">
                <h4 class="vulnerability-title">
                    <i class="fas fa-exclamation-circle"></i>
                    {vuln.get('type', 'Unknown Vulnerability')}
                </h4>
                <span class="severity-badge severity-{severity_class}">
                    {vuln.get('severity', 'Unknown')}
                </span>
            </div>
            
            <div class="vulnerability-details">
                {self.generate_vulnerability_details(vuln)}
            </div>
            
            {self.generate_ai_vulnerability_analysis(vuln)}
        </div>
        """
    
    def generate_vulnerability_details(self, vuln: Dict[str, Any]) -> str:
        """Generate vulnerability details"""
        details = ""
        
        if vuln.get('description'):
            details += f"""
            <div class="detail-item">
                <span class="detail-label"><i class="fas fa-info-circle"></i> Description</span>
                {vuln['description']}
            </div>
            """
        
        if vuln.get('evidence'):
            # HTML escape evidence to prevent XSS
            escaped_evidence = html.escape(str(vuln['evidence']))
            details += f"""
            <div class="detail-item">
                <span class="detail-label"><i class="fas fa-search"></i> Evidence</span>
                {escaped_evidence}
            </div>
            """
        
        if vuln.get('impact'):
            details += f"""
            <div class="detail-item">
                <span class="detail-label"><i class="fas fa-exclamation-triangle"></i> Impact</span>
                {vuln['impact']}
            </div>
            """
        
        if vuln.get('payload'):
            # HTML escape the payload to prevent XSS execution in report
            escaped_payload = html.escape(str(vuln['payload']))
            details += f"""
            <div class="detail-item">
                <span class="detail-label"><i class="fas fa-code"></i> Payload</span>
                <div class="code-block">{escaped_payload}</div>
            </div>
            """
        
        if vuln.get('url'):
            # HTML escape URL to prevent XSS
            escaped_url = html.escape(str(vuln['url']))
            details += f"""
            <div class="detail-item">
                <span class="detail-label"><i class="fas fa-link"></i> Affected URL</span>
                <code>{escaped_url}</code>
            </div>
            """
        
        if vuln.get('cwe'):
            details += f"""
            <div class="detail-item">
                <span class="detail-label"><i class="fas fa-tag"></i> CWE</span>
                {vuln['cwe']}
            </div>
            """
        
        if vuln.get('owasp'):
            details += f"""
            <div class="detail-item">
                <span class="detail-label"><i class="fas fa-shield-alt"></i> OWASP Category</span>
                {vuln['owasp']}
            </div>
            """
        
        return details
    
    def generate_ai_vulnerability_analysis(self, vuln: Dict[str, Any]) -> str:
        """Generate AI analysis for vulnerability"""
        ai_analysis = vuln.get('ai_analysis', {})
        if not ai_analysis:
            return ""
        
        # Format all text fields
        explanation = self.format_markdown_to_html(ai_analysis.get('explanation', 'Analysis not available'))
        impact = self.format_markdown_to_html(ai_analysis.get('impact', 'Impact analysis not available'))
        remediation = self.format_markdown_to_html(ai_analysis.get('remediation', 'Remediation steps not available'))
        prevention = self.format_markdown_to_html(ai_analysis.get('prevention', 'Prevention measures not available'))
        
        return f"""
        <div class="ai-analysis">
            <h4>AI Analysis & Recommendations</h4>
            <div class="row">
                <div class="col-md-6">
                    <h5>Technical Explanation</h5>
                    <p>{explanation}</p>
                    
                    <h5>Impact Assessment</h5>
                    <p>{impact}</p>
                </div>
                <div class="col-md-6">
                    <h5>Remediation Steps</h5>
                    <p>{remediation}</p>
                    
                    <h5>Prevention Measures</h5>
                    <p>{prevention}</p>
                </div>
            </div>
            {f'<p><strong>CVSS Score:</strong> {ai_analysis["cvss_score"]}</p>' if ai_analysis.get('cvss_score') != 'N/A' else ''}
        </div>
        """
    
    def generate_owasp_section(self, owasp_results: Dict[str, Any]) -> str:
        """Generate OWASP Top 10 section"""
        if not owasp_results:
            return ""
        
        content = """
        <div class="section">
            <h2 class="section-title">
                <i class="fas fa-shield-alt"></i> OWASP Top 10 2021 Assessment
            </h2>
        """
        
        for category_id, results in owasp_results.items():
            category_name = results.get('category', category_id)
            vulnerabilities = results.get('vulnerabilities', [])
            tests_performed = results.get('tests_performed', [])
            
            content += f"""
            <div class="owasp-category">
                <h3><i class="fas fa-bug"></i> {category_name}</h3>
                <p><strong>Tests Performed:</strong> {', '.join(tests_performed)}</p>
                <p><strong>Vulnerabilities Found:</strong> {len(vulnerabilities)}</p>
                
                {f'<div class="alert alert-success">No vulnerabilities found in this category.</div>' if not vulnerabilities else ''}
            </div>
            """
        
        content += "</div>"
        return content
    
    def generate_chain_attacks_section(self, chain_attacks: List[Dict[str, Any]]) -> str:
        """Generate chain attacks section"""
        if not chain_attacks:
            return ""
        
        content = f"""
        <div class="section">
            <h2 class="section-title">
                <i class="fas fa-link"></i> Chain Attack Analysis ({len(chain_attacks)})
            </h2>
        """
        
        for chain in chain_attacks[:5]:  # Show top 5 chains
            content += f"""
            <div class="chain-attack-card">
                <h4><i class="fas fa-crosshairs"></i> {chain.get('objective', 'Attack Chain')}</h4>
                <p><strong>Category:</strong> {chain.get('category', 'Unknown')}</p>
                <p><strong>Impact Score:</strong> {chain.get('impact_score', 0)}/100</p>
                <p><strong>Feasibility:</strong> {chain.get('feasibility', 'Unknown')}</p>
                <p><strong>Detection Difficulty:</strong> {chain.get('detection_difficulty', 'Unknown')}</p>
                
                <h5>Attack Steps:</h5>
                <div class="attack-steps">
            """
            
            for step in chain.get('attack_steps', []):
                content += f"""
                <div class="attack-step">
                    <strong>Step {step.get('step', 0)}:</strong> {step.get('action', 'Unknown action')}
                    <br><small>Target: {step.get('target', 'Unknown')}</small>
                    <br><small>Expected Result: {step.get('expected_result', 'Unknown')}</small>
                </div>
                """
            
            content += """
                </div>
            </div>
            """
        
        content += "</div>"
        return content
    
    def generate_recommendations_section(self, recommendations: List[str]) -> str:
        """Generate recommendations section"""
        content = """
        <div class="section">
            <h2 class="section-title">
                <i class="fas fa-lightbulb"></i> Security Recommendations
            </h2>
            
            <ul class="recommendations-list">
        """
        
        for recommendation in recommendations:
            content += f"<li>{recommendation}</li>"
        
        content += """
            </ul>
        </div>
        """
        
        return content
    
    def format_markdown_to_html(self, text: str) -> str:
        """Convert markdown formatting to HTML"""
        if not text:
            return ""
        
        # Convert **text** to <strong>text</strong>
        import re
        text = re.sub(r'\*\*([^\*]+)\*\*', r'<strong>\1</strong>', text)
        
        # Convert *text* to <em>text</em>
        text = re.sub(r'\*([^\*]+)\*', r'<em>\1</em>', text)
        
        # Convert line breaks to <br>
        text = text.replace('\n', '<br>')
        
        return text
    
    def generate_ai_analysis_section(self, ai_analysis: Dict[str, Any]) -> str:
        """Generate AI analysis section"""
        if not ai_analysis:
            return ""
        
        content = """
        <div class="section">
            <h2 class="section-title">
                <i class="fas fa-robot"></i> AI Security Analysis
            </h2>
        """
        
        if ai_analysis.get('reconnaissance'):
            # Format markdown to HTML
            formatted_text = self.format_markdown_to_html(ai_analysis['reconnaissance'])
            content += f"""
            <div class="ai-analysis">
                <h4>Reconnaissance Analysis</h4>
                <div style="white-space: normal; line-height: 1.8;">{formatted_text}</div>
            </div>
            """
        
        content += "</div>"
        return content
    
    async def generate_json_report(self, scan_results: Dict[str, Any]) -> str:
        """Generate JSON report"""
        self.logger.info("Generating JSON report...")
        
        # Generate filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        domain = urlparse(scan_results['target']).netloc.replace('.', '_')
        filename = f"Astrava_report_{domain}_{timestamp}.json"
        filepath = Path(self.config.output_dir) / filename
        
        # Write JSON report
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(scan_results, f, indent=2, default=str)
        
        self.logger.info(f"JSON report generated: {filepath}")
        return str(filepath)
    
    async def generate_pdf_report(self, scan_results: Dict[str, Any]) -> str:
        """Generate PDF report (requires additional dependencies)"""
        self.logger.info("PDF generation not implemented yet. Generating HTML report instead.")
        return await self.generate_html_report(scan_results)
