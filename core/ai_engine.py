"""
AI Engine for Astrava Security Scanner
Handles all AI-related operations using Ollama
"""

import aiohttp
import json
import asyncio
from typing import Dict, List, Optional, Any
import logging

class AIEngine:
    """AI Engine for generating payloads, analyzing results, and creating reports"""
    
    def __init__(self, model: str = "llama3.2:3b", ollama_url: str = "http://localhost:11434"):
        self.model = model
        self.ollama_url = ollama_url
        self.logger = logging.getLogger(__name__)
        self.session = None
    
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    async def validate_connection(self) -> bool:
        """Validate connection to Ollama"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{self.ollama_url}/api/tags", timeout=5) as response:
                    if response.status == 200:
                        data = await response.json()
                        models = [model['name'] for model in data.get('models', [])]
                        return self.model in models
            return False
        except Exception as e:
            self.logger.error(f"Failed to connect to Ollama: {e}")
            return False
    
    async def query_llama(self, prompt: str, system_prompt: str = "", temperature: float = 0.7) -> str:
        """Query Ollama with a prompt"""
        try:
            payload = {
                "model": self.model,
                "prompt": f"System: {system_prompt}\n\nUser: {prompt}",
                "stream": False,
                "options": {
                    "temperature": temperature,
                    "top_p": 0.9,
                    "top_k": 40
                }
            }
            
            if not self.session:
                self.session = aiohttp.ClientSession()
            
            async with self.session.post(f"{self.ollama_url}/api/generate", json=payload) as response:
                if response.status == 200:
                    result = await response.json()
                    return result.get('response', '').strip()
                else:
                    self.logger.error(f"Ollama API error: {response.status}")
                    return ""
        except Exception as e:
            self.logger.error(f"Error querying Ollama: {e}")
            return ""
    
    async def generate_sql_payloads(self, target_info: Dict[str, Any]) -> List[str]:
        """Generate SQL injection payloads using AI"""
        system_prompt = """You are a cybersecurity expert specializing in SQL injection testing. 
        Generate creative and effective SQL injection payloads for penetration testing purposes only."""
        
        prompt = f"""
        Generate 10 advanced SQL injection payloads for testing the following target:
        
        Target URL: {target_info.get('url', 'Unknown')}
        Database Type: {target_info.get('database', 'Unknown')}
        Technology Stack: {target_info.get('technologies', [])}
        
        Include payloads for:
        1. Union-based injection
        2. Boolean-based blind injection
        3. Time-based blind injection
        4. Error-based injection
        5. Second-order injection
        
        Return only the payloads, one per line, without explanations.
        """
        
        response = await self.query_llama(prompt, system_prompt, temperature=0.8)
        payloads = [line.strip() for line in response.split('\n') if line.strip()]
        return payloads[:10]  # Limit to 10 payloads
    
    async def generate_xss_payloads(self, target_info: Dict[str, Any]) -> List[str]:
        """Generate XSS payloads using AI"""
        system_prompt = """You are a cybersecurity expert specializing in XSS testing. 
        Generate creative XSS payloads that can bypass modern filters and WAFs."""
        
        prompt = f"""
        Generate 10 advanced XSS payloads for testing the following target:
        
        Target URL: {target_info.get('url', 'Unknown')}
        Content-Type: {target_info.get('content_type', 'text/html')}
        Security Headers: {target_info.get('security_headers', {})}
        
        Include payloads for:
        1. Filter bypass techniques
        2. DOM-based XSS
        3. Stored XSS
        4. Reflected XSS
        5. WAF evasion
        
        Return only the payloads, one per line, without explanations.
        """
        
        response = await self.query_llama(prompt, system_prompt, temperature=0.8)
        payloads = [line.strip() for line in response.split('\n') if line.strip()]
        return payloads[:10]
    
    async def generate_command_injection_payloads(self, target_info: Dict[str, Any]) -> List[str]:
        """Generate command injection payloads using AI"""
        system_prompt = """You are a cybersecurity expert specializing in command injection testing. 
        Generate effective command injection payloads for different operating systems."""
        
        prompt = f"""
        Generate 10 command injection payloads for testing the following target:
        
        Target URL: {target_info.get('url', 'Unknown')}
        Server OS: {target_info.get('os', 'Unknown')}
        Server Software: {target_info.get('server', 'Unknown')}
        
        Include payloads for:
        1. Linux/Unix systems
        2. Windows systems
        3. Blind command injection
        4. Time-based detection
        5. Output redirection
        
        Return only the payloads, one per line, without explanations.
        """
        
        response = await self.query_llama(prompt, system_prompt, temperature=0.8)
        payloads = [line.strip() for line in response.split('\n') if line.strip()]
        return payloads[:10]
    
    async def generate_ssrf_payloads(self, target_info: Dict[str, Any]) -> List[str]:
        """Generate SSRF payloads using AI"""
        system_prompt = """You are a cybersecurity expert specializing in SSRF testing. 
        Generate SSRF payloads that can access internal services and cloud metadata."""
        
        prompt = f"""
        Generate 10 SSRF payloads for testing the following target:
        
        Target URL: {target_info.get('url', 'Unknown')}
        Cloud Provider: {target_info.get('cloud_provider', 'Unknown')}
        Internal Networks: {target_info.get('internal_networks', [])}
        
        Include payloads for:
        1. AWS metadata access
        2. Azure metadata access
        3. GCP metadata access
        4. Internal service discovery
        5. Localhost bypass techniques
        
        Return only the payloads, one per line, without explanations.
        """
        
        response = await self.query_llama(prompt, system_prompt, temperature=0.8)
        payloads = [line.strip() for line in response.split('\n') if line.strip()]
        return payloads[:10]
    
    async def analyze_vulnerability(self, vuln_data: Dict[str, Any]) -> Dict[str, str]:
        """Analyze a vulnerability using AI (optimized for speed)"""
        system_prompt = """You are a cybersecurity expert. Provide concise vulnerability analysis."""
        
        # Shorter, more focused prompt
        prompt = f"""
        Vulnerability: {vuln_data.get('type', 'Unknown')} ({vuln_data.get('severity', 'Unknown')})
        Evidence: {vuln_data.get('evidence', 'None')}
        
        Provide brief analysis:
        1. Risk explanation (2 sentences)
        2. Impact (1 sentence) 
        3. Fix (1 sentence)
        4. CVSS score (number only)
        
        Keep response under 100 words total.
        """
        
        response = await self.query_llama(prompt, system_prompt, temperature=0.1)
        
        # Simple parsing instead of JSON
        lines = response.strip().split('\n')
        return {
            "explanation": lines[0] if len(lines) > 0 else "Vulnerability detected",
            "impact": lines[1] if len(lines) > 1 else "Potential security risk",
            "remediation": lines[2] if len(lines) > 2 else "Apply security patches",
            "prevention": "Follow security best practices",
            "cvss_score": "7.5"  # Default score
        }
    
    async def generate_chain_attack(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate chain attack scenarios using AI"""
        system_prompt = """You are a cybersecurity expert specializing in advanced persistent threats. 
        Analyze vulnerabilities and create realistic attack chain scenarios."""
        
        vuln_summary = "\n".join([
            f"- {v.get('type', 'Unknown')}: {v.get('severity', 'Unknown')} ({v.get('url', 'Unknown')})"
            for v in vulnerabilities
        ])
        
        prompt = f"""
        Given the following vulnerabilities, create realistic attack chain scenarios:
        
        {vuln_summary}
        
        For each attack chain:
        1. List the vulnerabilities used in order
        2. Describe the attack steps
        3. Explain the final objective
        4. Assess the overall impact
        
        Generate up to 3 attack chains. Format as JSON array with objects containing:
        chain_id, vulnerabilities_used, attack_steps, objective, impact
        """
        
        response = await self.query_llama(prompt, system_prompt, temperature=0.6)
        
        try:
            chains = json.loads(response)
            return chains if isinstance(chains, list) else []
        except json.JSONDecodeError:
            return []
    
    async def generate_reconnaissance_analysis(self, recon_data: Dict[str, Any]) -> str:
        """Generate reconnaissance analysis using AI"""
        system_prompt = """You are a cybersecurity expert analyzing reconnaissance data. 
        Provide insights about the target's security posture and potential attack vectors."""
        
        prompt = f"""
        Analyze the following reconnaissance data and provide security insights:
        
        Target: {recon_data.get('target', 'Unknown')}
        Technologies: {recon_data.get('technologies', [])}
        Open Ports: {recon_data.get('open_ports', [])}
        Subdomains: {recon_data.get('subdomains', [])}
        Security Headers: {recon_data.get('security_headers', {})}
        SSL/TLS Info: {recon_data.get('ssl_info', {})}
        
        Provide:
        1. Security posture assessment
        2. Potential attack vectors
        3. Technology-specific risks
        4. Recommendations for further testing
        5. Priority areas for security improvement
        
        Be specific and actionable in your analysis.
        """
        
        return await self.query_llama(prompt, system_prompt, temperature=0.4)
    
    async def generate_executive_summary(self, scan_results: Dict[str, Any]) -> str:
        """Generate executive summary using AI"""
        system_prompt = """You are a cybersecurity consultant writing an executive summary for C-level executives. 
        Focus on business impact, risk levels, and strategic recommendations."""
        
        vulnerabilities = scan_results.get('vulnerabilities', [])
        risk_score = scan_results.get('risk_score', 0)
        
        vuln_counts = {}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Unknown')
            vuln_counts[severity] = vuln_counts.get(severity, 0) + 1
        
        prompt = f"""
        Create an executive summary for a security assessment with the following results:
        
        Target: {scan_results.get('target', 'Unknown')}
        Risk Score: {risk_score}/100
        Total Vulnerabilities: {len(vulnerabilities)}
        Vulnerability Breakdown: {vuln_counts}
        Scan Duration: {scan_results.get('scan_duration', 0)} seconds
        
        Include:
        1. Executive overview (2-3 sentences)
        2. Key findings and business risks
        3. Immediate action items
        4. Strategic recommendations
        5. Compliance implications (if any)
        
        Keep it concise and business-focused.
        """
        
        return await self.query_llama(prompt, system_prompt, temperature=0.3)
