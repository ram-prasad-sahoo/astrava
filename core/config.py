"""
Configuration module for Astrava AI Security Scanner
"""

import os
from dataclasses import dataclass
from typing import List, Optional
from pathlib import Path

@dataclass
class Config:
    """Configuration class for the scanner"""
    
    # Target configuration
    target_url: str
    
    # Scan modes
    passive_only: bool = False
    active_only: bool = False
    owasp_all: bool = True
    chain_attacks: bool = False
    
    # File paths
    custom_payloads: Optional[str] = None
    output_dir: Optional[str] = None
    
    # Report settings
    report_format: str = 'html'
    
    # Performance settings
    max_threads: int = 10
    timeout: int = 30
    
    # Scan depth settings (for basic/fast mode)
    skip_port_scan: bool = False
    max_crawl_depth: int = 3
    
    # AI settings
    model: str = 'llama3.2:3b'  # Your downloaded model
    ollama_url: str = 'http://localhost:11434'
    
    def __post_init__(self):
        """Post-initialization setup"""
        if not self.output_dir:
            self.output_dir = str(Path.cwd() / "reports")
        
        # Create output directory
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)

# OWASP Top 10 2021 Configuration
OWASP_TOP_10 = {
    'A01_2021': {
        'name': 'Broken Access Control',
        'tests': ['idor', 'privilege_escalation', 'path_traversal', 'forced_browsing']
    },
    'A02_2021': {
        'name': 'Cryptographic Failures',
        'tests': ['weak_crypto', 'ssl_tls', 'sensitive_data_exposure']
    },
    'A03_2021': {
        'name': 'Injection',
        'tests': ['sql_injection', 'nosql_injection', 'command_injection', 'ldap_injection']
    },
    'A04_2021': {
        'name': 'Insecure Design',
        'tests': ['business_logic', 'design_flaws', 'threat_modeling']
    },
    'A05_2021': {
        'name': 'Security Misconfiguration',
        'tests': ['default_credentials', 'unnecessary_features', 'error_handling', 'security_headers']
    },
    'A06_2021': {
        'name': 'Vulnerable and Outdated Components',
        'tests': ['component_analysis', 'version_detection', 'cve_lookup']
    },
    'A07_2021': {
        'name': 'Identification and Authentication Failures',
        'tests': ['weak_passwords', 'session_management', 'brute_force', 'credential_stuffing']
    },
    'A08_2021': {
        'name': 'Software and Data Integrity Failures',
        'tests': ['deserialization', 'supply_chain', 'integrity_checks']
    },
    'A09_2021': {
        'name': 'Security Logging and Monitoring Failures',
        'tests': ['logging_analysis', 'monitoring_gaps', 'incident_response']
    },
    'A10_2021': {
        'name': 'Server-Side Request Forgery (SSRF)',
        'tests': ['ssrf_detection', 'internal_services', 'cloud_metadata']
    }
}

# Reconnaissance Configuration
RECON_CONFIG = {
    'passive': {
        'dns_enumeration': True,
        'subdomain_discovery': True,
        'certificate_transparency': True,
        'search_engines': True,
        'social_media': True,
        'code_repositories': True,
        'wayback_machine': True
    },
    'active': {
        'port_scanning': True,
        'service_detection': True,
        'technology_fingerprinting': True,
        'directory_bruteforce': True,
        'vhost_discovery': True,
        'api_discovery': True
    }
}

# Payload Generation Configuration
PAYLOAD_CONFIG = {
    'sql_injection': {
        'basic_payloads': True,
        'time_based': True,
        'union_based': True,
        'boolean_based': True,
        'error_based': True,
        'ai_generated': True
    },
    'xss': {
        'reflected': True,
        'stored': True,
        'dom_based': True,
        'filter_bypass': True,
        'ai_generated': True
    },
    'command_injection': {
        'basic_commands': True,
        'blind_injection': True,
        'time_based': True,
        'ai_generated': True
    }
}

# Chain Attack Configuration
CHAIN_ATTACK_CONFIG = {
    'enabled': False,
    'max_depth': 3,
    'attack_chains': [
        ['xss', 'csrf'],
        ['sql_injection', 'privilege_escalation'],
        ['file_upload', 'command_injection'],
        ['ssrf', 'internal_service_discovery']
    ]
}

# Common ports for scanning
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995,
    1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017
]

# User agents for requests
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0'
]

# Security headers to check
SECURITY_HEADERS = [
    'Content-Security-Policy',
    'X-Frame-Options',
    'X-XSS-Protection',
    'X-Content-Type-Options',
    'Strict-Transport-Security',
    'Referrer-Policy',
    'Feature-Policy',
    'Permissions-Policy',
    'X-Permitted-Cross-Domain-Policies'
]

# File extensions for discovery
INTERESTING_EXTENSIONS = [
    '.php', '.asp', '.aspx', '.jsp', '.py', '.rb', '.pl', '.cgi',
    '.bak', '.backup', '.old', '.tmp', '.swp', '.config', '.conf',
    '.sql', '.db', '.sqlite', '.log', '.txt', '.xml', '.json'
]

# Directory wordlist for brute force
COMMON_DIRECTORIES = [
    'admin', 'administrator', 'wp-admin', 'phpmyadmin', 'cpanel',
    'webmail', 'mail', 'email', 'user', 'users', 'member', 'members',
    'login', 'signin', 'signup', 'register', 'auth', 'authentication',
    'dashboard', 'panel', 'control', 'manager', 'management',
    'api', 'v1', 'v2', 'rest', 'graphql', 'soap',
    'backup', 'backups', 'old', 'archive', 'archives',
    'test', 'testing', 'dev', 'development', 'staging', 'prod',
    'config', 'configuration', 'settings', 'setup',
    'upload', 'uploads', 'files', 'documents', 'images', 'media'
]
