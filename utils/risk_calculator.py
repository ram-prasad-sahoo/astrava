"""
Risk Calculator for Astrava AI Security Scanner
Calculates comprehensive risk scores based on vulnerabilities and reconnaissance data
"""

from typing import Dict, List, Any
import math

class RiskCalculator:
    """Advanced risk calculation engine"""
    
    def __init__(self):
        # Severity weights
        self.severity_weights = {
            'Critical': 10,
            'High': 7,
            'Medium': 4,
            'Low': 2,
            'Info': 1
        }
        
        # OWASP category weights (some are more critical than others)
        self.owasp_weights = {
            'A01:2021 - Broken Access Control': 1.2,
            'A02:2021 - Cryptographic Failures': 1.1,
            'A03:2021 - Injection': 1.3,
            'A04:2021 - Insecure Design': 1.0,
            'A05:2021 - Security Misconfiguration': 1.0,
            'A06:2021 - Vulnerable and Outdated Components': 1.1,
            'A07:2021 - Identification and Authentication Failures': 1.2,
            'A08:2021 - Software and Data Integrity Failures': 1.1,
            'A09:2021 - Security Logging and Monitoring Failures': 0.8,
            'A10:2021 - Server-Side Request Forgery': 1.2
        }
        
        # Vulnerability type impact multipliers
        self.vuln_impact_multipliers = {
            'SQL Injection': 1.5,
            'Command Injection': 1.8,
            'Remote Code Execution': 2.0,
            'Authentication Bypass': 1.6,
            'Privilege Escalation': 1.7,
            'File Upload': 1.4,
            'SSRF': 1.3,
            'XXE': 1.2,
            'XSS': 1.1,
            'Path Traversal': 1.2,
            'Information Disclosure': 0.9,
            'Missing Security Headers': 0.8
        }
    
    def calculate_risk_score(self, vulnerabilities: List[Dict[str, Any]], 
                           reconnaissance_data: Dict[str, Any]) -> int:
        """Calculate comprehensive risk score"""
        
        if not vulnerabilities:
            return 0
        
        # Base vulnerability score
        vuln_score = self.calculate_vulnerability_score(vulnerabilities)
        
        # Environmental factors
        env_score = self.calculate_environmental_score(reconnaissance_data)
        
        # Attack surface score
        surface_score = self.calculate_attack_surface_score(reconnaissance_data)
        
        # Chain attack potential
        chain_score = self.calculate_chain_attack_potential(vulnerabilities)
        
        # Combine scores with weights
        total_score = (
            vuln_score * 0.5 +           # 50% - vulnerabilities are most important
            env_score * 0.2 +            # 20% - environmental factors
            surface_score * 0.2 +        # 20% - attack surface
            chain_score * 0.1            # 10% - chain attack potential
        )
        
        # Apply normalization and cap at 100
        final_score = min(int(total_score), 100)
        
        return final_score
    
    def calculate_vulnerability_score(self, vulnerabilities: List[Dict[str, Any]]) -> float:
        """Calculate score based on vulnerabilities found"""
        
        if not vulnerabilities:
            return 0
        
        total_score = 0
        severity_counts = {}
        vuln_types = set()
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Low')
            vuln_type = vuln.get('type', 'Unknown')
            owasp_category = vuln.get('owasp', '')
            
            # Base severity score
            base_score = self.severity_weights.get(severity, 1)
            
            # Apply vulnerability type multiplier
            type_multiplier = self.vuln_impact_multipliers.get(vuln_type, 1.0)
            
            # Apply OWASP category weight
            owasp_weight = self.owasp_weights.get(owasp_category, 1.0)
            
            # Calculate vulnerability score
            vuln_score = base_score * type_multiplier * owasp_weight
            total_score += vuln_score
            
            # Track for diversity calculations
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            vuln_types.add(vuln_type)
        
        # Apply diversity bonus (more diverse vulnerabilities = higher risk)
        diversity_bonus = len(vuln_types) * 0.5
        
        # Apply severity distribution penalty/bonus
        severity_distribution_factor = self.calculate_severity_distribution_factor(severity_counts)
        
        # Apply diminishing returns for large numbers of vulnerabilities
        count_factor = math.log(len(vulnerabilities) + 1) / math.log(10)
        
        final_score = (total_score + diversity_bonus) * severity_distribution_factor * count_factor
        
        return final_score
    
    def calculate_environmental_score(self, recon_data: Dict[str, Any]) -> float:
        """Calculate score based on environmental factors"""
        
        env_score = 0
        
        # Check passive reconnaissance data
        passive_data = recon_data.get('passive', {})
        if passive_data:
            # DNS information
            dns_info = passive_data.get('dns', {})
            if dns_info:
                # More DNS records = larger attack surface
                total_records = sum(len(records) for records in dns_info.values() if isinstance(records, list))
                env_score += min(total_records * 0.1, 5)
            
            # Subdomain count
            subdomains = passive_data.get('subdomains', [])
            env_score += min(len(subdomains) * 0.2, 10)
            
            # Certificate transparency findings
            ct_domains = passive_data.get('certificate_transparency', [])
            env_score += min(len(ct_domains) * 0.1, 5)
        
        # Check active reconnaissance data
        active_data = recon_data.get('active', {})
        if active_data:
            # Open ports
            open_ports = active_data.get('open_ports', [])
            env_score += min(len(open_ports) * 0.5, 15)
            
            # Services (handle both dict and list formats)
            services = active_data.get('services', {})
            if isinstance(services, dict):
                risky_services = ['FTP', 'Telnet', 'SMTP', 'MySQL', 'PostgreSQL', 'Redis', 'MongoDB']
                for port, service in services.items():
                    if service in risky_services:
                        env_score += 2
            elif isinstance(services, list):
                # Services is a list (basic mode with no port scan)
                pass
            
            # Technologies
            technologies = active_data.get('technologies', [])
            env_score += min(len(technologies) * 0.3, 8)
            
            # SSL/TLS issues
            ssl_info = active_data.get('ssl', {})
            if 'error' in ssl_info:
                env_score += 5
            if ssl_info.get('days_until_expiry', 365) < 30:
                env_score += 3
        
        return env_score
    
    def calculate_attack_surface_score(self, recon_data: Dict[str, Any]) -> float:
        """Calculate attack surface score"""
        
        surface_score = 0
        
        # Web application attack surface
        active_data = recon_data.get('active', {})
        if active_data:
            # HTTP analysis
            http_info = active_data.get('http', {})
            if http_info:
                # Forms increase attack surface
                forms = http_info.get('forms', [])
                surface_score += len(forms) * 1.5
                
                # Links increase attack surface
                links = http_info.get('links', [])
                surface_score += min(len(links) * 0.1, 10)
                
                # Comments might reveal information
                comments = http_info.get('comments', [])
                surface_score += len(comments) * 0.5
            
            # Directories found
            directories = active_data.get('directories', [])
            surface_score += len(directories) * 0.8
            
            # API endpoints
            api_endpoints = active_data.get('api_endpoints', [])
            surface_score += len(api_endpoints) * 2  # APIs are high-value targets
            
            # Virtual hosts
            vhosts = active_data.get('virtual_hosts', [])
            surface_score += len(vhosts) * 1.5
        
        return surface_score
    
    def calculate_chain_attack_potential(self, vulnerabilities: List[Dict[str, Any]]) -> float:
        """Calculate potential for chain attacks"""
        
        if len(vulnerabilities) < 2:
            return 0
        
        chain_score = 0
        
        # Group vulnerabilities by type
        vuln_types = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'Unknown')
            if vuln_type not in vuln_types:
                vuln_types[vuln_type] = []
            vuln_types[vuln_type].append(vuln)
        
        # Define chainable vulnerability combinations
        chainable_combinations = [
            ('SQL Injection', 'Authentication Bypass'),
            ('XSS', 'Session Hijacking'),
            ('File Upload', 'Command Injection'),
            ('SSRF', 'Internal Service Discovery'),
            ('Path Traversal', 'Information Disclosure'),
            ('XXE', 'File Disclosure'),
            ('Information Disclosure', 'Credential Theft')
        ]
        
        # Check for chainable combinations
        for combo in chainable_combinations:
            type1, type2 = combo
            has_type1 = any(type1.lower() in vt.lower() for vt in vuln_types.keys())
            has_type2 = any(type2.lower() in vt.lower() for vt in vuln_types.keys())
            
            if has_type1 and has_type2:
                chain_score += 5
        
        # Bonus for multiple vulnerabilities of different severities
        severities = set(v.get('severity', 'Low') for v in vulnerabilities)
        if len(severities) > 2:
            chain_score += 3
        
        # Bonus for vulnerabilities in same location/parameter
        locations = {}
        for vuln in vulnerabilities:
            location = vuln.get('url', '') + vuln.get('parameter', '')
            if location:
                locations[location] = locations.get(location, 0) + 1
        
        # Multiple vulnerabilities in same location = easier chaining
        for location, count in locations.items():
            if count > 1:
                chain_score += count * 1.5
        
        return chain_score
    
    def calculate_severity_distribution_factor(self, severity_counts: Dict[str, int]) -> float:
        """Calculate factor based on severity distribution"""
        
        total_vulns = sum(severity_counts.values())
        if total_vulns == 0:
            return 1.0
        
        # Calculate distribution score
        distribution_score = 0
        
        # Critical vulnerabilities have exponential impact
        critical_count = severity_counts.get('Critical', 0)
        if critical_count > 0:
            distribution_score += critical_count * 2.0
        
        # High vulnerabilities have significant impact
        high_count = severity_counts.get('High', 0)
        if high_count > 0:
            distribution_score += high_count * 1.5
        
        # Medium vulnerabilities add moderate impact
        medium_count = severity_counts.get('Medium', 0)
        if medium_count > 0:
            distribution_score += medium_count * 1.0
        
        # Low and Info vulnerabilities add minimal impact
        low_count = severity_counts.get('Low', 0) + severity_counts.get('Info', 0)
        if low_count > 0:
            distribution_score += low_count * 0.5
        
        # Normalize by total vulnerabilities
        factor = distribution_score / total_vulns
        
        # Ensure factor is at least 0.5 and at most 2.0
        return max(0.5, min(factor, 2.0))
    
    def get_risk_level(self, risk_score: int) -> str:
        """Get risk level description"""
        
        if risk_score >= 90:
            return "Critical"
        elif risk_score >= 70:
            return "High"
        elif risk_score >= 50:
            return "Medium"
        elif risk_score >= 30:
            return "Low"
        else:
            return "Minimal"
    
    def get_risk_description(self, risk_score: int) -> str:
        """Get detailed risk description"""
        
        descriptions = {
            "Critical": "Immediate action required. Multiple critical vulnerabilities present significant risk of complete system compromise.",
            "High": "Urgent attention needed. High-severity vulnerabilities could lead to significant data breach or system compromise.",
            "Medium": "Moderate risk present. Vulnerabilities should be addressed in next security update cycle.",
            "Low": "Low risk identified. Vulnerabilities present minimal threat but should be addressed during routine maintenance.",
            "Minimal": "Very low risk. Few or no significant vulnerabilities detected. Maintain current security posture."
        }
        
        risk_level = self.get_risk_level(risk_score)
        return descriptions.get(risk_level, "Risk assessment unavailable.")
    
    def calculate_business_impact(self, risk_score: int, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate business impact assessment"""
        
        impact = {
            'confidentiality': 'Low',
            'integrity': 'Low',
            'availability': 'Low',
            'financial_impact': 'Low',
            'regulatory_impact': 'Low',
            'reputation_impact': 'Low'
        }
        
        # Analyze vulnerability types for impact assessment
        vuln_types = [v.get('type', '').lower() for v in vulnerabilities]
        
        # Confidentiality impact
        if any(vt in ['sql injection', 'path traversal', 'information disclosure', 'ssrf'] for vt in vuln_types):
            if risk_score >= 70:
                impact['confidentiality'] = 'High'
            elif risk_score >= 40:
                impact['confidentiality'] = 'Medium'
        
        # Integrity impact
        if any(vt in ['sql injection', 'command injection', 'file upload', 'xss'] for vt in vuln_types):
            if risk_score >= 70:
                impact['integrity'] = 'High'
            elif risk_score >= 40:
                impact['integrity'] = 'Medium'
        
        # Availability impact
        if any(vt in ['command injection', 'denial of service', 'resource exhaustion'] for vt in vuln_types):
            if risk_score >= 70:
                impact['availability'] = 'High'
            elif risk_score >= 40:
                impact['availability'] = 'Medium'
        
        # Financial impact (based on overall risk)
        if risk_score >= 80:
            impact['financial_impact'] = 'High'
        elif risk_score >= 50:
            impact['financial_impact'] = 'Medium'
        
        # Regulatory impact (data protection vulnerabilities)
        data_protection_vulns = ['sql injection', 'information disclosure', 'authentication bypass']
        if any(vt in data_protection_vulns for vt in vuln_types):
            if risk_score >= 60:
                impact['regulatory_impact'] = 'High'
            elif risk_score >= 30:
                impact['regulatory_impact'] = 'Medium'
        
        # Reputation impact
        if risk_score >= 70:
            impact['reputation_impact'] = 'High'
        elif risk_score >= 40:
            impact['reputation_impact'] = 'Medium'
        
        return impact
    
    def generate_risk_recommendations(self, risk_score: int, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """Generate risk-based recommendations"""
        
        recommendations = []
        
        if risk_score >= 80:
            recommendations.extend([
                "[ALERT] IMMEDIATE ACTION REQUIRED",
                "Implement emergency security measures",
                "Consider taking affected systems offline until patched",
                "Engage incident response team",
                "Notify stakeholders and customers if data exposure is possible"
            ])
        
        elif risk_score >= 60:
            recommendations.extend([
                "[WARNING] URGENT SECURITY UPDATES NEEDED",
                "Prioritize patching critical and high-severity vulnerabilities",
                "Implement temporary mitigations where possible",
                "Increase security monitoring",
                "Schedule emergency security review"
            ])
        
        elif risk_score >= 40:
            recommendations.extend([
                " SCHEDULE SECURITY UPDATES",
                "Address vulnerabilities in next maintenance window",
                "Implement additional security controls",
                "Review and update security policies",
                "Consider penetration testing"
            ])
        
        elif risk_score >= 20:
            recommendations.extend([
                "[SEARCH] ROUTINE SECURITY MAINTENANCE",
                "Address low-priority vulnerabilities during regular updates",
                "Continue security monitoring",
                "Review security configurations",
                "Maintain current security practices"
            ])
        
        else:
            recommendations.extend([
                "[OK] MAINTAIN CURRENT SECURITY POSTURE",
                "Continue regular security assessments",
                "Keep security tools and processes up to date",
                "Monitor for new threats and vulnerabilities"
            ])
        
        # Add specific recommendations based on vulnerability types
        vuln_types = [v.get('type', '').lower() for v in vulnerabilities]
        
        if any('sql injection' in vt for vt in vuln_types):
            recommendations.append("[SHIELD] Implement parameterized queries and input validation")
        
        if any('xss' in vt for vt in vuln_types):
            recommendations.append("[SHIELD] Deploy Content Security Policy and output encoding")
        
        if any('command injection' in vt for vt in vuln_types):
            recommendations.append("[SHIELD] Avoid system command execution, use safe APIs")
        
        if any('file upload' in vt for vt in vuln_types):
            recommendations.append("[SHIELD] Implement strict file upload validation and sandboxing")
        
        return recommendations
