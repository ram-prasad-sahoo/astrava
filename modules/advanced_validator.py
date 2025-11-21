"""
Advanced Vulnerability Validator
Reduces false positives through intelligent response analysis
"""

import re
import difflib
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse
import hashlib


class AdvancedValidator:
    """Advanced vulnerability validation to reduce false positives"""
    
    def __init__(self, logger):
        self.logger = logger
        self.baseline_responses = {}
        
        # Known false positive patterns
        self.false_positive_patterns = {
            'echo_service': [
                r'httpbin\.org',
                r'"data":\s*"',
                r'"form":\s*{',
                r'"json":\s*',
            ],
            'test_sites': [
                r'testphp\.vulnweb\.com',
                r'demo\.testfire\.net',
            ]
        }
        
        # Real vulnerability indicators
        self.vulnerability_indicators = {
            'sql_injection': [
                r'SQL syntax.*?error',
                r'mysql_fetch',
                r'ORA-\d+',
                r'PostgreSQL.*?ERROR',
                r'SQLite.*?error',
                r'SQLSTATE\[\d+\]',
                r'Unclosed quotation mark',
                r'quoted string not properly terminated',
            ],
            'xss': [
                r'<script[^>]*>.*?</script>',
                r'onerror\s*=',
                r'onload\s*=',
                r'javascript:',
            ],
            'command_injection': [
                r'root:.*?:/bin/',  # /etc/passwd content
                r'uid=\d+\(.*?\)',  # id command output
                r'PING.*?bytes',  # ping command output
                r'Directory of',  # dir command output
            ],
            'lfi': [
                r'root:.*?:/bin/',
                r'\[boot loader\]',  # boot.ini
                r'\[extensions\]',  # win.ini
                r'<\?php',
            ],
            'ssrf': [
                r'169\.254\.169\.254',  # AWS metadata
                r'metadata\.google\.internal',
                r'169\.254\.',
            ]
        }
    
    def calculate_confidence(self, vuln_type: str, response: str, 
                            baseline: str, payload: str, 
                            status_code: int) -> Tuple[int, str]:
        """
        Calculate confidence score (0-100) for a vulnerability
        Returns: (confidence_score, reason)
        """
        confidence = 0
        reasons = []
        
        # Check if it's a known false positive source
        if self._is_false_positive_source(response):
            return (10, "Echo/test service detected - likely false positive")
        
        # Check for real vulnerability indicators
        indicator_found = False
        for pattern in self.vulnerability_indicators.get(vuln_type, []):
            if re.search(pattern, response, re.IGNORECASE):
                confidence += 30
                indicator_found = True
                reasons.append(f"Real {vuln_type} indicator found")
                break
        
        # Check HTTP status code
        if status_code >= 500:
            confidence += 20
            reasons.append("Server error (500+) indicates real issue")
        elif status_code == 200:
            confidence += 5
        
        # Compare with baseline
        if baseline:
            similarity = self._calculate_similarity(baseline, response)
            if similarity < 0.7:  # Significant difference
                confidence += 25
                reasons.append(f"Response differs significantly from baseline ({similarity:.0%})")
            elif similarity > 0.95:  # Almost identical
                confidence -= 20
                reasons.append("Response too similar to baseline")
        
        # Check if payload is simply echoed back
        if self._is_simple_echo(payload, response):
            confidence -= 30
            reasons.append("Payload simply echoed back - likely false positive")
        else:
            confidence += 15
            reasons.append("Payload processed/transformed")
        
        # Bonus for specific vulnerability types
        if vuln_type == 'sql_injection' and indicator_found:
            confidence += 10
        elif vuln_type == 'command_injection' and indicator_found:
            confidence += 15
        
        # Ensure confidence is between 0-100
        confidence = max(0, min(100, confidence))
        
        reason = "; ".join(reasons) if reasons else "Standard detection"
        return (confidence, reason)
    
    def _is_false_positive_source(self, response: str) -> bool:
        """Check if response is from a known echo/test service"""
        for category, patterns in self.false_positive_patterns.items():
            for pattern in patterns:
                if re.search(pattern, response, re.IGNORECASE):
                    return True
        return False
    
    def _is_simple_echo(self, payload: str, response: str) -> bool:
        """Check if payload is simply echoed back without processing"""
        # Remove common encoding
        clean_payload = payload.replace('<', '').replace('>', '').replace('"', '').replace("'", '')
        clean_response = response.replace('<', '').replace('>', '').replace('"', '').replace("'", '')
        
        # Check if payload appears verbatim in response
        if clean_payload in clean_response:
            # Check if it's in a data/form echo context
            if re.search(r'"(data|form|json|args)":\s*["\{].*?' + re.escape(clean_payload), response):
                return True
        
        return False
    
    def _calculate_similarity(self, text1: str, text2: str) -> float:
        """Calculate similarity ratio between two texts"""
        return difflib.SequenceMatcher(None, text1, text2).ratio()
    
    def store_baseline(self, url: str, response: str):
        """Store baseline response for comparison"""
        url_hash = hashlib.md5(url.encode()).hexdigest()
        self.baseline_responses[url_hash] = response
    
    def get_baseline(self, url: str) -> Optional[str]:
        """Get stored baseline response"""
        url_hash = hashlib.md5(url.encode()).hexdigest()
        return self.baseline_responses.get(url_hash)
    
    def validate_sql_injection(self, response: str, status_code: int, 
                               baseline: str = None) -> Tuple[bool, int, str]:
        """
        Validate SQL injection vulnerability
        Returns: (is_valid, confidence, reason)
        """
        # Check for SQL error messages
        for pattern in self.vulnerability_indicators['sql_injection']:
            if re.search(pattern, response, re.IGNORECASE):
                confidence, reason = self.calculate_confidence(
                    'sql_injection', response, baseline, '', status_code
                )
                return (True, confidence, f"SQL error detected: {reason}")
        
        # Check for boolean-based SQL injection
        if status_code == 200 and baseline:
            similarity = self._calculate_similarity(baseline, response)
            if similarity < 0.5:
                return (True, 60, "Boolean-based SQL injection detected")
        
        return (False, 0, "No SQL injection indicators found")
    
    def validate_xss(self, payload: str, response: str, status_code: int,
                     baseline: str = None) -> Tuple[bool, int, str]:
        """
        Validate XSS vulnerability
        Returns: (is_valid, confidence, reason)
        """
        # Check if payload is in response
        if payload not in response:
            return (False, 0, "Payload not reflected")
        
        # Check if it's just echoed in JSON/form data
        if self._is_simple_echo(payload, response):
            return (False, 15, "Payload only echoed in data field - false positive")
        
        # Check if payload is in executable context
        executable_contexts = [
            r'<script[^>]*>' + re.escape(payload),
            r'on\w+\s*=\s*["\']?' + re.escape(payload),
            r'<[^>]+\s+' + re.escape(payload),
        ]
        
        for pattern in executable_contexts:
            if re.search(pattern, response, re.IGNORECASE):
                confidence, reason = self.calculate_confidence(
                    'xss', response, baseline, payload, status_code
                )
                return (True, min(confidence + 20, 95), f"XSS in executable context: {reason}")
        
        # Payload reflected but not in dangerous context
        return (False, 25, "Payload reflected but not in executable context")
    
    def validate_command_injection(self, response: str, status_code: int,
                                   baseline: str = None) -> Tuple[bool, int, str]:
        """
        Validate command injection vulnerability
        Returns: (is_valid, confidence, reason)
        """
        # Check for command execution evidence
        for pattern in self.vulnerability_indicators['command_injection']:
            if re.search(pattern, response, re.IGNORECASE):
                confidence, reason = self.calculate_confidence(
                    'command_injection', response, baseline, '', status_code
                )
                return (True, min(confidence + 15, 95), f"Command execution evidence: {reason}")
        
        return (False, 0, "No command execution evidence found")
    
    def validate_lfi(self, response: str, status_code: int,
                     baseline: str = None) -> Tuple[bool, int, str]:
        """
        Validate LFI vulnerability
        Returns: (is_valid, confidence, reason)
        """
        # Check for file content indicators
        for pattern in self.vulnerability_indicators['lfi']:
            if re.search(pattern, response, re.IGNORECASE):
                confidence, reason = self.calculate_confidence(
                    'lfi', response, baseline, '', status_code
                )
                return (True, min(confidence + 20, 95), f"File content detected: {reason}")
        
        return (False, 0, "No file inclusion evidence found")
    
    def validate_ssrf(self, response: str, status_code: int,
                      baseline: str = None) -> Tuple[bool, int, str]:
        """
        Validate SSRF vulnerability
        Returns: (is_valid, confidence, reason)
        """
        # Check for SSRF indicators
        for pattern in self.vulnerability_indicators['ssrf']:
            if re.search(pattern, response, re.IGNORECASE):
                confidence, reason = self.calculate_confidence(
                    'ssrf', response, baseline, '', status_code
                )
                return (True, min(confidence + 10, 90), f"SSRF indicator: {reason}")
        
        return (False, 0, "No SSRF evidence found")
    
    def should_report_vulnerability(self, confidence: int, 
                                   min_confidence: int = 50) -> bool:
        """
        Determine if vulnerability should be reported based on confidence
        """
        return confidence >= min_confidence
