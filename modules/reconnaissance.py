"""
Reconnaissance Module for Atlas AI Security Scanner
Handles both passive and active reconnaissance
"""

import asyncio
import aiohttp
import socket
import ssl
import dns.resolver
import subprocess
import re
import json
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse, urljoin
import logging
from datetime import datetime

from core.config import Config, COMMON_PORTS, COMMON_DIRECTORIES

class ReconnaissanceModule:
    """Comprehensive reconnaissance module"""
    
    def __init__(self, config: Config, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.target_url = config.target_url
        self.parsed_url = urlparse(config.target_url)
        self.domain = self.parsed_url.netloc
        self.session = None
    
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
    
    async def passive_reconnaissance(self) -> Dict[str, Any]:
        """Perform passive reconnaissance"""
        self.logger.info("Starting passive reconnaissance...")
        
        recon_data = {
            'target': self.target_url,
            'domain': self.domain,
            'timestamp': datetime.now().isoformat()
        }
        
        async with self:
            # DNS enumeration
            dns_info = await self.dns_enumeration()
            recon_data['dns'] = dns_info
            
            # Subdomain discovery
            subdomains = await self.subdomain_discovery()
            recon_data['subdomains'] = subdomains
            
            # Certificate transparency logs
            ct_domains = await self.certificate_transparency()
            recon_data['certificate_transparency'] = ct_domains
            
            # Search engine reconnaissance
            search_results = await self.search_engine_recon()
            recon_data['search_engines'] = search_results
            
            # Wayback machine
            wayback_urls = await self.wayback_machine_recon()
            recon_data['wayback_machine'] = wayback_urls
            
            # Social media and code repositories
            social_intel = await self.social_intelligence()
            recon_data['social_intelligence'] = social_intel
        
        self.logger.info(f"Passive reconnaissance completed. Found {len(subdomains)} subdomains")
        return recon_data
    
    async def active_reconnaissance(self) -> Dict[str, Any]:
        """Perform active reconnaissance"""
        self.logger.info("Starting active reconnaissance...")
        
        recon_data = {
            'target': self.target_url,
            'domain': self.domain,
            'timestamp': datetime.now().isoformat()
        }
        
        async with self:
            # Port scanning
            open_ports = await self.port_scan()
            recon_data['open_ports'] = open_ports
            
            # Service detection
            services = await self.service_detection(open_ports)
            recon_data['services'] = services
            
            # HTTP analysis
            http_info = await self.http_analysis()
            recon_data['http'] = http_info
            
            # Technology fingerprinting
            technologies = await self.technology_fingerprinting()
            recon_data['technologies'] = technologies
            
            # SSL/TLS analysis
            if self.parsed_url.scheme == 'https':
                ssl_info = await self.ssl_analysis()
                recon_data['ssl'] = ssl_info
            
            # Directory and file discovery
            directories = await self.directory_discovery()
            recon_data['directories'] = directories
            
            # Virtual host discovery
            vhosts = await self.vhost_discovery()
            recon_data['virtual_hosts'] = vhosts
            
            # API endpoint discovery
            api_endpoints = await self.api_discovery()
            recon_data['api_endpoints'] = api_endpoints
        
        self.logger.info(f"Active reconnaissance completed. Found {len(open_ports)} open ports")
        return recon_data
    
    async def dns_enumeration(self) -> Dict[str, Any]:
        """Perform DNS enumeration"""
        dns_info = {}
        
        try:
            # A record
            a_records = []
            try:
                answers = dns.resolver.resolve(self.domain, 'A')
                a_records = [str(rdata) for rdata in answers]
            except:
                pass
            dns_info['A'] = a_records
            
            # AAAA record
            aaaa_records = []
            try:
                answers = dns.resolver.resolve(self.domain, 'AAAA')
                aaaa_records = [str(rdata) for rdata in answers]
            except:
                pass
            dns_info['AAAA'] = aaaa_records
            
            # MX records
            mx_records = []
            try:
                answers = dns.resolver.resolve(self.domain, 'MX')
                mx_records = [str(rdata) for rdata in answers]
            except:
                pass
            dns_info['MX'] = mx_records
            
            # NS records
            ns_records = []
            try:
                answers = dns.resolver.resolve(self.domain, 'NS')
                ns_records = [str(rdata) for rdata in answers]
            except:
                pass
            dns_info['NS'] = ns_records
            
            # TXT records
            txt_records = []
            try:
                answers = dns.resolver.resolve(self.domain, 'TXT')
                txt_records = [str(rdata) for rdata in answers]
            except:
                pass
            dns_info['TXT'] = txt_records
            
        except Exception as e:
            self.logger.error(f"DNS enumeration failed: {e}")
        
        return dns_info
    
    async def subdomain_discovery(self) -> List[str]:
        """Discover subdomains using various techniques"""
        subdomains = set()
        
        # Common subdomain wordlist
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'api',
            'app', 'blog', 'shop', 'store', 'support', 'help', 'docs',
            'portal', 'secure', 'vpn', 'remote', 'access', 'login',
            'dashboard', 'panel', 'cpanel', 'webmail', 'email',
            'cdn', 'static', 'assets', 'media', 'images', 'files'
        ]
        
        # DNS brute force
        tasks = []
        for subdomain in common_subdomains:
            tasks.append(self.check_subdomain(f"{subdomain}.{self.domain}"))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for i, result in enumerate(results):
            if result and not isinstance(result, Exception):
                subdomains.add(f"{common_subdomains[i]}.{self.domain}")
        
        return list(subdomains)
    
    async def check_subdomain(self, subdomain: str) -> bool:
        """Check if a subdomain exists"""
        try:
            socket.gethostbyname(subdomain)
            return True
        except:
            return False
    
    async def certificate_transparency(self) -> List[str]:
        """Search certificate transparency logs"""
        domains = []
        
        try:
            # Query crt.sh with proper headers and timeout
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            async with self.session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as response:
                if response.status == 200:
                    content_type = response.headers.get('Content-Type', '')
                    
                    # Check if response is actually JSON
                    if 'json' in content_type:
                        data = await response.json()
                        for entry in data:
                            name_value = entry.get('name_value', '')
                            for domain in name_value.split('\n'):
                                domain = domain.strip()
                                if domain and domain not in domains:
                                    domains.append(domain)
                    else:
                        self.logger.warning(f"Certificate transparency returned non-JSON response (skipping)")
                else:
                    self.logger.warning(f"Certificate transparency returned status {response.status} (skipping)")
                    
        except asyncio.TimeoutError:
            self.logger.warning("Certificate transparency search timed out (skipping)")
        except aiohttp.ClientError as e:
            self.logger.warning(f"Certificate transparency connection failed (skipping): {type(e).__name__}")
        except json.JSONDecodeError:
            self.logger.warning("Certificate transparency returned invalid JSON (skipping)")
        except Exception as e:
            self.logger.warning(f"Certificate transparency search failed (skipping): {type(e).__name__}")
        
        return domains[:50]  # Limit results
    
    async def search_engine_recon(self) -> Dict[str, List[str]]:
        """Perform search engine reconnaissance"""
        results = {
            'google_dorks': [],
            'interesting_files': [],
            'exposed_directories': []
        }
        
        # This would typically use search engine APIs
        # For demonstration, we'll return placeholder data
        results['google_dorks'] = [
            f'site:{self.domain} filetype:pdf',
            f'site:{self.domain} inurl:admin',
            f'site:{self.domain} intitle:"index of"'
        ]
        
        return results
    
    async def wayback_machine_recon(self) -> List[str]:
        """Search Wayback Machine for historical URLs"""
        urls = []
        
        try:
            # Query Wayback Machine CDX API (correct endpoint)
            api_url = f"http://web.archive.org/cdx/search/cdx?url={self.domain}/*&output=json&fl=original&collapse=urlkey&limit=100"
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            async with self.session.get(api_url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as response:
                if response.status == 200:
                    content_type = response.headers.get('Content-Type', '')
                    
                    # Check if response is actually JSON
                    if 'json' in content_type or 'application/json' in content_type:
                        data = await response.json()
                        # CDX API returns array of arrays
                        for entry in data:
                            if isinstance(entry, list) and len(entry) > 0:
                                url = entry[0]
                                if url and url not in urls and url.startswith('http'):
                                    urls.append(url)
                    else:
                        # Try parsing as text (CDX can return plain text)
                        text = await response.text()
                        if text and not text.startswith('<'):  # Not HTML
                            lines = text.strip().split('\n')
                            for line in lines[:100]:
                                if line and line.startswith('http'):
                                    url = line.split()[0] if ' ' in line else line
                                    if url not in urls:
                                        urls.append(url)
                        else:
                            self.logger.warning("Wayback Machine returned HTML instead of JSON (skipping)")
                else:
                    self.logger.warning(f"Wayback Machine returned status {response.status} (skipping)")
                    
        except asyncio.TimeoutError:
            self.logger.warning("Wayback Machine search timed out (skipping)")
        except aiohttp.ClientError as e:
            self.logger.warning(f"Wayback Machine connection failed (skipping): {type(e).__name__}")
        except json.JSONDecodeError:
            self.logger.warning("Wayback Machine returned invalid JSON (skipping)")
        except Exception as e:
            self.logger.warning(f"Wayback Machine search failed (skipping): {type(e).__name__}")
        
        return urls[:50]  # Limit results
    
    async def social_intelligence(self) -> Dict[str, Any]:
        """Gather social media and code repository intelligence"""
        intel = {
            'github_repos': [],
            'social_profiles': [],
            'email_addresses': [],
            'employees': []
        }
        
        # This would typically search GitHub, LinkedIn, etc.
        # For demonstration, we'll return placeholder data
        return intel
    
    async def port_scan(self) -> List[int]:
        """Perform port scanning"""
        open_ports = []
        
        async def scan_port(port: int) -> Optional[int]:
            try:
                future = asyncio.open_connection(self.domain, port)
                reader, writer = await asyncio.wait_for(future, timeout=3)
                writer.close()
                await writer.wait_closed()
                return port
            except:
                return None
        
        # Scan common ports
        tasks = [scan_port(port) for port in COMMON_PORTS]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if result and isinstance(result, int):
                open_ports.append(result)
        
        self.logger.info(f"Found {len(open_ports)} open ports: {open_ports}")
        return open_ports
    
    async def service_detection(self, open_ports: List[int]) -> Dict[int, str]:
        """Detect services running on open ports"""
        services = {}
        
        # Common service mappings
        service_map = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
            993: 'IMAPS', 995: 'POP3S', 3306: 'MySQL', 5432: 'PostgreSQL',
            6379: 'Redis', 27017: 'MongoDB'
        }
        
        for port in open_ports:
            services[port] = service_map.get(port, 'Unknown')
        
        return services
    
    async def http_analysis(self) -> Dict[str, Any]:
        """Analyze HTTP response and headers"""
        http_info = {}
        
        try:
            async with self.session.get(self.target_url) as response:
                http_info['status_code'] = response.status
                http_info['headers'] = dict(response.headers)
                http_info['content_type'] = response.headers.get('Content-Type', '')
                http_info['server'] = response.headers.get('Server', '')
                http_info['content_length'] = response.headers.get('Content-Length', '')
                
                # Get response body for analysis
                body = await response.text()
                http_info['body_length'] = len(body)
                
                # Extract interesting information from body
                http_info['title'] = self.extract_title(body)
                http_info['forms'] = self.extract_forms(body)
                http_info['links'] = self.extract_links(body)
                http_info['comments'] = self.extract_comments(body)
                
        except Exception as e:
            self.logger.error(f"HTTP analysis failed: {e}")
            http_info['error'] = str(e)
        
        return http_info
    
    def extract_title(self, html: str) -> str:
        """Extract page title"""
        match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
        return match.group(1).strip() if match else ''
    
    def extract_forms(self, html: str) -> List[Dict[str, Any]]:
        """Extract forms from HTML"""
        forms = []
        form_pattern = r'<form[^>]*>(.*?)</form>'
        
        for match in re.finditer(form_pattern, html, re.IGNORECASE | re.DOTALL):
            form_html = match.group(0)
            
            # Extract form attributes
            action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            
            # Extract input fields
            input_pattern = r'<input[^>]*>'
            inputs = []
            for input_match in re.finditer(input_pattern, form_html, re.IGNORECASE):
                input_html = input_match.group(0)
                name_match = re.search(r'name=["\']([^"\']*)["\']', input_html, re.IGNORECASE)
                type_match = re.search(r'type=["\']([^"\']*)["\']', input_html, re.IGNORECASE)
                
                inputs.append({
                    'name': name_match.group(1) if name_match else '',
                    'type': type_match.group(1) if type_match else 'text'
                })
            
            forms.append({
                'action': action_match.group(1) if action_match else '',
                'method': method_match.group(1) if method_match else 'GET',
                'inputs': inputs
            })
        
        return forms
    
    def extract_links(self, html: str) -> List[str]:
        """Extract links from HTML"""
        links = []
        link_pattern = r'<a[^>]*href=["\']([^"\']*)["\'][^>]*>'
        
        for match in re.finditer(link_pattern, html, re.IGNORECASE):
            link = match.group(1)
            if link and not link.startswith('#'):
                links.append(link)
        
        return list(set(links))[:50]  # Limit and deduplicate
    
    def extract_comments(self, html: str) -> List[str]:
        """Extract HTML comments"""
        comment_pattern = r'<!--(.*?)-->'
        comments = []
        
        for match in re.finditer(comment_pattern, html, re.DOTALL):
            comment = match.group(1).strip()
            if comment:
                comments.append(comment)
        
        return comments
    
    async def technology_fingerprinting(self) -> List[str]:
        """Fingerprint web technologies"""
        technologies = []
        
        try:
            async with self.session.get(self.target_url) as response:
                headers = response.headers
                body = await response.text()
                
                # Server header
                server = headers.get('Server', '').lower()
                if 'apache' in server:
                    technologies.append('Apache')
                if 'nginx' in server:
                    technologies.append('Nginx')
                if 'iis' in server:
                    technologies.append('Microsoft IIS')
                
                # X-Powered-By header
                powered_by = headers.get('X-Powered-By', '')
                if powered_by:
                    technologies.append(f"Powered by {powered_by}")
                
                # Technology detection from body
                body_lower = body.lower()
                
                # CMS Detection
                if 'wp-content' in body_lower or 'wordpress' in body_lower:
                    technologies.append('WordPress')
                if 'drupal' in body_lower:
                    technologies.append('Drupal')
                if 'joomla' in body_lower:
                    technologies.append('Joomla')
                
                # JavaScript frameworks
                if 'react' in body_lower:
                    technologies.append('React')
                if 'angular' in body_lower:
                    technologies.append('Angular')
                if 'vue' in body_lower:
                    technologies.append('Vue.js')
                if 'jquery' in body_lower:
                    technologies.append('jQuery')
                
                # Programming languages
                if '.php' in body_lower or 'php' in headers.get('X-Powered-By', '').lower():
                    technologies.append('PHP')
                if '.asp' in body_lower or 'asp.net' in headers.get('X-Powered-By', '').lower():
                    technologies.append('ASP.NET')
                if 'jsessionid' in body_lower:
                    technologies.append('Java')
                
        except Exception as e:
            self.logger.error(f"Technology fingerprinting failed: {e}")
        
        return technologies
    
    async def ssl_analysis(self) -> Dict[str, Any]:
        """Analyze SSL/TLS configuration"""
        ssl_info = {}
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    ssl_info = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serial_number': cert['serialNumber'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                        'cipher': ssock.cipher(),
                        'protocol': ssock.version(),
                        'san': cert.get('subjectAltName', [])
                    }
                    
                    # Check certificate validity
                    from datetime import datetime
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (not_after - datetime.now()).days
                    ssl_info['days_until_expiry'] = days_until_expiry
                    
        except Exception as e:
            ssl_info['error'] = str(e)
        
        return ssl_info
    
    async def directory_discovery(self) -> List[str]:
        """Discover directories and files"""
        found_directories = []
        
        async def check_directory(directory: str) -> Optional[str]:
            try:
                url = urljoin(self.target_url, directory)
                async with self.session.get(url) as response:
                    if response.status in [200, 301, 302, 403]:
                        return directory
            except:
                pass
            return None
        
        # Check common directories
        tasks = [check_directory(directory) for directory in COMMON_DIRECTORIES]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if result and not isinstance(result, Exception):
                found_directories.append(result)
        
        return found_directories
    
    async def vhost_discovery(self) -> List[str]:
        """Discover virtual hosts"""
        vhosts = []
        
        # This would typically involve testing different Host headers
        # For demonstration, we'll return placeholder data
        return vhosts
    
    async def api_discovery(self) -> List[str]:
        """Discover API endpoints"""
        api_endpoints = []
        
        # Common API paths
        api_paths = [
            '/api', '/api/v1', '/api/v2', '/rest', '/graphql',
            '/swagger', '/openapi', '/docs', '/api-docs'
        ]
        
        async def check_api_endpoint(path: str) -> Optional[str]:
            try:
                url = urljoin(self.target_url, path)
                async with self.session.get(url) as response:
                    if response.status == 200:
                        return path
            except:
                pass
            return None
        
        tasks = [check_api_endpoint(path) for path in api_paths]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if result and not isinstance(result, Exception):
                api_endpoints.append(result)
        
        return api_endpoints