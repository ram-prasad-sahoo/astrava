"""
Chain Attack Module for Atlas AI Security Scanner
Analyzes vulnerabilities to identify potential attack chains
"""

import asyncio
from typing import Dict, List, Any, Optional, Tuple
import logging
from itertools import combinations

from core.config import Config, CHAIN_ATTACK_CONFIG
from core.ai_engine import AIEngine

class ChainAttackModule:
    """Module for analyzing and generating attack chains"""
    
    def __init__(self, config: Config, logger: logging.Logger, ai_engine: AIEngine):
        self.config = config
        self.logger = logger
        self.ai_engine = ai_engine
        self.target_url = config.target_url
        
        # Attack chain patterns
        self.chain_patterns = {
            'reconnaissance_to_exploitation': [
                ['Information Disclosure', 'SQL Injection'],
                ['Directory Traversal', 'File Upload'],
                ['Subdomain Discovery', 'SSRF']
            ],
            'privilege_escalation_chains': [
                ['SQL Injection', 'Authentication Bypass', 'Privilege Escalation'],
                ['XSS', 'Session Hijacking', 'Admin Access'],
                ['File Upload', 'Command Injection', 'System Compromise']
            ],
            'data_exfiltration_chains': [
                ['SSRF', 'Internal Service Discovery', 'Data Access'],
                ['Path Traversal', 'Sensitive File Access', 'Credential Theft'],
                ['XXE', 'File Disclosure', 'Configuration Exposure']
            ],
            'persistence_chains': [
                ['File Upload', 'Web Shell', 'Backdoor Installation'],
                ['Command Injection', 'User Creation', 'Persistent Access'],
                ['Deserialization', 'Code Execution', 'System Modification']
            ]
        }
    
    async def analyze_attack_chains(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze vulnerabilities to identify potential attack chains"""
        self.logger.info("Analyzing potential attack chains...")
        
        if not vulnerabilities:
            return []
        
        attack_chains = []
        
        # Generate AI-powered attack chains
        ai_chains = await self.ai_engine.generate_chain_attack(vulnerabilities)
        attack_chains.extend(ai_chains)
        
        # Generate pattern-based attack chains
        pattern_chains = self.generate_pattern_based_chains(vulnerabilities)
        attack_chains.extend(pattern_chains)
        
        # Generate severity-based chains
        severity_chains = self.generate_severity_based_chains(vulnerabilities)
        attack_chains.extend(severity_chains)
        
        # Generate location-based chains
        location_chains = self.generate_location_based_chains(vulnerabilities)
        attack_chains.extend(location_chains)
        
        # Remove duplicates and rank chains
        unique_chains = self.deduplicate_chains(attack_chains)
        ranked_chains = self.rank_attack_chains(unique_chains)
        
        self.logger.info(f"Identified {len(ranked_chains)} potential attack chains")
        return ranked_chains[:10]  # Return top 10 chains
    
    def generate_pattern_based_chains(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate attack chains based on predefined patterns"""
        chains = []
        
        # Group vulnerabilities by type
        vuln_by_type = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'Unknown')
            if vuln_type not in vuln_by_type:
                vuln_by_type[vuln_type] = []
            vuln_by_type[vuln_type].append(vuln)
        
        # Check each chain pattern
        for chain_category, patterns in self.chain_patterns.items():
            for pattern in patterns:
                matching_vulns = []
                
                # Find vulnerabilities that match the pattern
                for step in pattern:
                    matching_step_vulns = []
                    for vuln_type, vulns in vuln_by_type.items():
                        if step.lower() in vuln_type.lower() or vuln_type.lower() in step.lower():
                            matching_step_vulns.extend(vulns)
                    
                    if matching_step_vulns:
                        matching_vulns.append(matching_step_vulns[0])  # Take first match
                    else:
                        break  # Pattern incomplete
                
                # If we found vulnerabilities for all steps in the pattern
                if len(matching_vulns) == len(pattern):
                    chain = self.create_attack_chain(
                        chain_id=f"{chain_category}_{len(chains)}",
                        vulnerabilities=matching_vulns,
                        pattern=pattern,
                        category=chain_category
                    )
                    chains.append(chain)
        
        return chains
    
    def generate_severity_based_chains(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate attack chains based on vulnerability severity"""
        chains = []
        
        # Sort vulnerabilities by severity
        severity_order = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1, 'Info': 0}
        sorted_vulns = sorted(vulnerabilities, 
                            key=lambda v: severity_order.get(v.get('severity', 'Low'), 1), 
                            reverse=True)
        
        # Create chains starting with highest severity vulnerabilities
        for i, primary_vuln in enumerate(sorted_vulns[:5]):  # Top 5 severe vulnerabilities
            for secondary_vuln in sorted_vulns[i+1:i+4]:  # Next 3 vulnerabilities
                if self.can_chain_vulnerabilities(primary_vuln, secondary_vuln):
                    chain = self.create_severity_chain(primary_vuln, secondary_vuln)
                    chains.append(chain)
        
        return chains
    
    def generate_location_based_chains(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate attack chains based on vulnerability locations"""
        chains = []
        
        # Group vulnerabilities by URL/location
        vuln_by_location = {}
        for vuln in vulnerabilities:
            location = vuln.get('url', self.target_url)
            if location not in vuln_by_location:
                vuln_by_location[location] = []
            vuln_by_location[location].append(vuln)
        
        # Create chains for vulnerabilities in the same location
        for location, vulns in vuln_by_location.items():
            if len(vulns) >= 2:
                # Create combinations of vulnerabilities at the same location
                for combo in combinations(vulns, min(3, len(vulns))):
                    chain = self.create_location_chain(list(combo), location)
                    chains.append(chain)
        
        return chains
    
    def can_chain_vulnerabilities(self, vuln1: Dict[str, Any], vuln2: Dict[str, Any]) -> bool:
        """Determine if two vulnerabilities can be chained together"""
        
        # Define chainable vulnerability combinations
        chainable_combinations = [
            ('SQL Injection', 'Authentication Bypass'),
            ('XSS', 'Session Hijacking'),
            ('File Upload', 'Command Injection'),
            ('SSRF', 'Internal Service Discovery'),
            ('Path Traversal', 'Information Disclosure'),
            ('XXE', 'File Disclosure'),
            ('Deserialization', 'Remote Code Execution'),
            ('Information Disclosure', 'Credential Theft')
        ]
        
        vuln1_type = vuln1.get('type', '')
        vuln2_type = vuln2.get('type', '')
        
        # Check if the combination is in our chainable list
        for combo in chainable_combinations:
            if ((combo[0] in vuln1_type and combo[1] in vuln2_type) or
                (combo[1] in vuln1_type and combo[0] in vuln2_type)):
                return True
        
        # Check if vulnerabilities are in the same parameter/location
        if (vuln1.get('parameter') == vuln2.get('parameter') and 
            vuln1.get('parameter') is not None):
            return True
        
        # Check if one vulnerability can lead to another based on severity
        severity_order = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1, 'Info': 0}
        vuln1_severity = severity_order.get(vuln1.get('severity', 'Low'), 1)
        vuln2_severity = severity_order.get(vuln2.get('severity', 'Low'), 1)
        
        # Higher severity vulnerabilities can often be chained with lower ones
        return vuln1_severity >= vuln2_severity
    
    def create_attack_chain(self, chain_id: str, vulnerabilities: List[Dict[str, Any]], 
                          pattern: List[str], category: str) -> Dict[str, Any]:
        """Create an attack chain from vulnerabilities and pattern"""
        
        # Generate attack steps
        attack_steps = []
        for i, (vuln, step_name) in enumerate(zip(vulnerabilities, pattern)):
            attack_steps.append({
                'step': i + 1,
                'vulnerability': vuln.get('type', 'Unknown'),
                'action': step_name,
                'target': vuln.get('url', self.target_url),
                'payload': vuln.get('payload', 'N/A'),
                'expected_result': self.get_expected_result(vuln, step_name)
            })
        
        # Calculate overall impact
        impact_score = self.calculate_chain_impact(vulnerabilities)
        
        # Determine final objective
        objective = self.determine_chain_objective(category, vulnerabilities)
        
        return {
            'chain_id': chain_id,
            'category': category,
            'vulnerabilities_used': [v.get('type', 'Unknown') for v in vulnerabilities],
            'attack_steps': attack_steps,
            'objective': objective,
            'impact': self.get_chain_impact_description(impact_score),
            'impact_score': impact_score,
            'feasibility': self.assess_chain_feasibility(vulnerabilities),
            'detection_difficulty': self.assess_detection_difficulty(vulnerabilities),
            'prerequisites': self.get_chain_prerequisites(vulnerabilities),
            'mitigation': self.get_chain_mitigation(vulnerabilities)
        }
    
    def create_severity_chain(self, primary_vuln: Dict[str, Any], 
                            secondary_vuln: Dict[str, Any]) -> Dict[str, Any]:
        """Create an attack chain based on severity relationship"""
        
        chain_id = f"severity_chain_{primary_vuln.get('type', 'unknown')}_{secondary_vuln.get('type', 'unknown')}"
        
        attack_steps = [
            {
                'step': 1,
                'vulnerability': primary_vuln.get('type', 'Unknown'),
                'action': 'Initial Exploitation',
                'target': primary_vuln.get('url', self.target_url),
                'payload': primary_vuln.get('payload', 'N/A'),
                'expected_result': 'Gain initial foothold'
            },
            {
                'step': 2,
                'vulnerability': secondary_vuln.get('type', 'Unknown'),
                'action': 'Escalate Attack',
                'target': secondary_vuln.get('url', self.target_url),
                'payload': secondary_vuln.get('payload', 'N/A'),
                'expected_result': 'Expand access or capabilities'
            }
        ]
        
        vulnerabilities = [primary_vuln, secondary_vuln]
        impact_score = self.calculate_chain_impact(vulnerabilities)
        
        return {
            'chain_id': chain_id,
            'category': 'severity_based',
            'vulnerabilities_used': [v.get('type', 'Unknown') for v in vulnerabilities],
            'attack_steps': attack_steps,
            'objective': 'Escalate from initial vulnerability to broader system access',
            'impact': self.get_chain_impact_description(impact_score),
            'impact_score': impact_score,
            'feasibility': self.assess_chain_feasibility(vulnerabilities),
            'detection_difficulty': self.assess_detection_difficulty(vulnerabilities),
            'prerequisites': self.get_chain_prerequisites(vulnerabilities),
            'mitigation': self.get_chain_mitigation(vulnerabilities)
        }
    
    def create_location_chain(self, vulnerabilities: List[Dict[str, Any]], 
                            location: str) -> Dict[str, Any]:
        """Create an attack chain for vulnerabilities in the same location"""
        
        chain_id = f"location_chain_{hash(location) % 10000}"
        
        attack_steps = []
        for i, vuln in enumerate(vulnerabilities):
            attack_steps.append({
                'step': i + 1,
                'vulnerability': vuln.get('type', 'Unknown'),
                'action': f'Exploit {vuln.get("type", "vulnerability")}',
                'target': location,
                'payload': vuln.get('payload', 'N/A'),
                'expected_result': f'Leverage {vuln.get("type", "vulnerability")} for next step'
            })
        
        impact_score = self.calculate_chain_impact(vulnerabilities)
        
        return {
            'chain_id': chain_id,
            'category': 'location_based',
            'vulnerabilities_used': [v.get('type', 'Unknown') for v in vulnerabilities],
            'attack_steps': attack_steps,
            'objective': f'Comprehensive exploitation of vulnerabilities at {location}',
            'impact': self.get_chain_impact_description(impact_score),
            'impact_score': impact_score,
            'feasibility': self.assess_chain_feasibility(vulnerabilities),
            'detection_difficulty': self.assess_detection_difficulty(vulnerabilities),
            'prerequisites': self.get_chain_prerequisites(vulnerabilities),
            'mitigation': self.get_chain_mitigation(vulnerabilities)
        }
    
    def get_expected_result(self, vuln: Dict[str, Any], step_name: str) -> str:
        """Get expected result for a vulnerability in an attack chain"""
        
        vuln_type = vuln.get('type', '').lower()
        
        result_map = {
            'sql injection': 'Database access, authentication bypass',
            'xss': 'Session hijacking, credential theft',
            'command injection': 'Remote code execution, system access',
            'file upload': 'Web shell deployment, code execution',
            'ssrf': 'Internal network access, service discovery',
            'path traversal': 'File system access, sensitive data exposure',
            'xxe': 'File disclosure, SSRF capabilities',
            'authentication bypass': 'Unauthorized access, privilege escalation',
            'information disclosure': 'System reconnaissance, credential discovery'
        }
        
        for key, result in result_map.items():
            if key in vuln_type:
                return result
        
        return 'Exploit vulnerability for next attack step'
    
    def calculate_chain_impact(self, vulnerabilities: List[Dict[str, Any]]) -> int:
        """Calculate the overall impact score of an attack chain"""
        
        severity_scores = {'Critical': 10, 'High': 7, 'Medium': 4, 'Low': 2, 'Info': 1}
        
        total_score = 0
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Low')
            total_score += severity_scores.get(severity, 1)
        
        # Apply multiplier for chain length (longer chains are more impactful)
        chain_multiplier = 1 + (len(vulnerabilities) - 1) * 0.2
        
        # Apply multiplier for vulnerability diversity
        unique_types = len(set(v.get('type', 'Unknown') for v in vulnerabilities))
        diversity_multiplier = 1 + (unique_types - 1) * 0.1
        
        final_score = int(total_score * chain_multiplier * diversity_multiplier)
        return min(final_score, 100)  # Cap at 100
    
    def get_chain_impact_description(self, impact_score: int) -> str:
        """Get human-readable impact description"""
        
        if impact_score >= 80:
            return "Critical - Complete system compromise likely"
        elif impact_score >= 60:
            return "High - Significant system access and data exposure"
        elif impact_score >= 40:
            return "Medium - Moderate system access and information disclosure"
        elif impact_score >= 20:
            return "Low - Limited access and minor information disclosure"
        else:
            return "Minimal - Basic reconnaissance and limited impact"
    
    def determine_chain_objective(self, category: str, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Determine the final objective of an attack chain"""
        
        objective_map = {
            'reconnaissance_to_exploitation': 'Gain unauthorized access through information gathering',
            'privilege_escalation_chains': 'Escalate privileges to administrative level',
            'data_exfiltration_chains': 'Extract sensitive data from the system',
            'persistence_chains': 'Establish persistent access to the system'
        }
        
        if category in objective_map:
            return objective_map[category]
        
        # Determine objective based on vulnerability types
        vuln_types = [v.get('type', '').lower() for v in vulnerabilities]
        
        if any('command injection' in vt or 'code execution' in vt for vt in vuln_types):
            return 'Achieve remote code execution and system control'
        elif any('sql injection' in vt for vt in vuln_types):
            return 'Compromise database and extract sensitive information'
        elif any('xss' in vt for vt in vuln_types):
            return 'Hijack user sessions and steal credentials'
        elif any('file upload' in vt for vt in vuln_types):
            return 'Deploy malicious files and gain system access'
        else:
            return 'Exploit vulnerabilities for unauthorized access and data exposure'
    
    def assess_chain_feasibility(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Assess how feasible the attack chain is to execute"""
        
        # Factors affecting feasibility
        complexity_factors = 0
        
        # More vulnerabilities = more complex
        if len(vulnerabilities) > 3:
            complexity_factors += 1
        
        # Check for authentication requirements
        auth_required = any('auth' in v.get('description', '').lower() for v in vulnerabilities)
        if auth_required:
            complexity_factors += 1
        
        # Check for user interaction requirements
        user_interaction = any('xss' in v.get('type', '').lower() for v in vulnerabilities)
        if user_interaction:
            complexity_factors += 1
        
        # Check for timing requirements
        timing_sensitive = any('time-based' in v.get('type', '').lower() for v in vulnerabilities)
        if timing_sensitive:
            complexity_factors += 1
        
        if complexity_factors == 0:
            return "High - Simple to execute with basic tools"
        elif complexity_factors == 1:
            return "Medium - Requires some technical skill and preparation"
        elif complexity_factors == 2:
            return "Low - Requires advanced skills and specific conditions"
        else:
            return "Very Low - Highly complex, requires expert knowledge"
    
    def assess_detection_difficulty(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Assess how difficult the attack chain is to detect"""
        
        detection_factors = 0
        
        # Stealth factors
        if any('blind' in v.get('type', '').lower() for v in vulnerabilities):
            detection_factors += 1
        
        if any('time-based' in v.get('type', '').lower() for v in vulnerabilities):
            detection_factors += 1
        
        if len(vulnerabilities) > 2:  # Multi-step attacks are harder to detect
            detection_factors += 1
        
        if any('ssrf' in v.get('type', '').lower() for v in vulnerabilities):
            detection_factors += 1  # Internal network attacks
        
        if detection_factors >= 3:
            return "Very Difficult - Highly stealthy, minimal logging"
        elif detection_factors == 2:
            return "Difficult - Some stealth characteristics"
        elif detection_factors == 1:
            return "Moderate - May evade basic detection"
        else:
            return "Easy - Likely to trigger security alerts"
    
    def get_chain_prerequisites(self, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """Get prerequisites for executing the attack chain"""
        
        prerequisites = []
        
        # Network access
        prerequisites.append("Network access to target application")
        
        # Check for authentication requirements
        if any('auth' in v.get('description', '').lower() for v in vulnerabilities):
            prerequisites.append("Valid user credentials or session")
        
        # Check for specific tools needed
        vuln_types = [v.get('type', '').lower() for v in vulnerabilities]
        
        if any('sql injection' in vt for vt in vuln_types):
            prerequisites.append("SQL injection tools (sqlmap, custom scripts)")
        
        if any('xss' in vt for vt in vuln_types):
            prerequisites.append("XSS payload delivery mechanism")
        
        if any('command injection' in vt for vt in vuln_types):
            prerequisites.append("Command execution payloads")
        
        if any('file upload' in vt for vt in vuln_types):
            prerequisites.append("Malicious file preparation")
        
        # User interaction requirements
        if any('xss' in vt for vt in vuln_types):
            prerequisites.append("Target user interaction (for XSS)")
        
        return prerequisites
    
    def get_chain_mitigation(self, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """Get mitigation strategies for the attack chain"""
        
        mitigations = []
        vuln_types = [v.get('type', '').lower() for v in vulnerabilities]
        
        # General mitigations
        mitigations.append("Implement comprehensive input validation")
        mitigations.append("Deploy Web Application Firewall (WAF)")
        mitigations.append("Enable security logging and monitoring")
        
        # Specific mitigations based on vulnerability types
        if any('sql injection' in vt for vt in vuln_types):
            mitigations.append("Use parameterized queries and prepared statements")
            mitigations.append("Implement database access controls")
        
        if any('xss' in vt for vt in vuln_types):
            mitigations.append("Implement Content Security Policy (CSP)")
            mitigations.append("Use proper output encoding")
        
        if any('command injection' in vt for vt in vuln_types):
            mitigations.append("Avoid system command execution")
            mitigations.append("Use safe APIs instead of shell commands")
        
        if any('file upload' in vt for vt in vuln_types):
            mitigations.append("Implement strict file upload validation")
            mitigations.append("Store uploaded files outside web root")
        
        if any('ssrf' in vt for vt in vuln_types):
            mitigations.append("Implement URL validation and whitelisting")
            mitigations.append("Use network segmentation")
        
        # Authentication and authorization
        mitigations.append("Implement strong authentication mechanisms")
        mitigations.append("Use principle of least privilege")
        mitigations.append("Regular security assessments and penetration testing")
        
        return list(set(mitigations))  # Remove duplicates
    
    def deduplicate_chains(self, chains: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate attack chains"""
        
        unique_chains = []
        seen_signatures = set()
        
        for chain in chains:
            # Create a signature based on vulnerabilities used
            vulns = sorted(chain.get('vulnerabilities_used', []))
            signature = '|'.join(vulns)
            
            if signature not in seen_signatures:
                seen_signatures.add(signature)
                unique_chains.append(chain)
        
        return unique_chains
    
    def rank_attack_chains(self, chains: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Rank attack chains by impact and feasibility"""
        
        def chain_score(chain):
            impact_score = chain.get('impact_score', 0)
            
            # Feasibility scoring
            feasibility = chain.get('feasibility', '')
            feasibility_scores = {
                'High': 3,
                'Medium': 2,
                'Low': 1,
                'Very Low': 0
            }
            feasibility_score = 0
            for level, score in feasibility_scores.items():
                if level in feasibility:
                    feasibility_score = score
                    break
            
            # Detection difficulty scoring (higher is better for attacker)
            detection = chain.get('detection_difficulty', '')
            detection_scores = {
                'Very Difficult': 3,
                'Difficult': 2,
                'Moderate': 1,
                'Easy': 0
            }
            detection_score = 0
            for level, score in detection_scores.items():
                if level in detection:
                    detection_score = score
                    break
            
            # Combined score (impact is most important)
            return impact_score * 2 + feasibility_score * 1.5 + detection_score
        
        return sorted(chains, key=chain_score, reverse=True)