"""
Advanced Web Crawler for Atlas AI Security Scanner
Discovers URLs, endpoints, parameters, and forms for comprehensive testing
"""

import asyncio
import aiohttp
import re
from urllib.parse import urljoin, urlparse, parse_qs, urlunparse
from bs4 import BeautifulSoup
from typing import Dict, List, Set, Any, Optional
import logging
from pathlib import Path

class WebCrawler:
    """Advanced web crawler for comprehensive endpoint discovery"""
    
    def __init__(self, config, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.target_url = config.target_url
        self.parsed_url = urlparse(config.target_url)
        self.domain = self.parsed_url.netloc
        self.session = None
        
        # Crawling data
        self.discovered_urls = set()
        self.crawled_urls = set()
        self.forms = []
        self.parameters = {}
        self.endpoints = []
        self.cookies = {}
        
        # Crawling limits (use config values for basic/fast mode)
        self.max_depth = getattr(config, 'max_crawl_depth', 3)
        self.max_urls = 50 if self.max_depth == 1 else 100  # Fewer URLs for basic mode
        self.current_depth = 0
        
        # Common file extensions to crawl
        self.crawlable_extensions = {'.php', '.asp', '.aspx', '.jsp', '.py', '.rb', '.pl', '.cgi', ''}
        
        # Common directories to check
        self.common_dirs = [
            '/admin/', '/administrator/', '/wp-admin/', '/phpmyadmin/',
            '/login/', '/signin/', '/signup/', '/register/', '/auth/',
            '/api/', '/v1/', '/v2/', '/rest/', '/graphql/',
            '/upload/', '/uploads/', '/files/', '/documents/',
            '/test/', '/testing/', '/dev/', '/development/',
            '/backup/', '/backups/', '/old/', '/archive/'
        ]
        
        # Common files to check
        self.common_files = [
            'index.php', 'login.php', 'admin.php', 'test.php',
            'search.php', 'contact.php', 'upload.php', 'file.php',
            'user.php', 'profile.php', 'settings.php', 'config.php'
        ]
    
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
    
    async def crawl_website(self) -> Dict[str, Any]:
        """Main crawling method - discovers all URLs, forms, and parameters"""
        self.logger.info("Starting comprehensive web crawling...")
        
        crawl_results = {
            'urls': [],
            'forms': [],
            'parameters': {},
            'endpoints': [],
            'cookies': {},
            'directories': [],
            'files': []
        }
        
        async with self:
            # Start with the main URL
            await self.crawl_url(self.target_url, 0)
            
            # Discover common directories and files
            await self.discover_common_paths()
            
            # Extract all discovered data
            crawl_results['urls'] = list(self.discovered_urls)
            crawl_results['forms'] = self.forms
            crawl_results['parameters'] = self.parameters
            crawl_results['endpoints'] = self.endpoints
            crawl_results['cookies'] = self.cookies
            
            self.logger.info(f"Crawling completed: {len(self.discovered_urls)} URLs, {len(self.forms)} forms, {len(self.parameters)} parameters")
            
            # Print real-time discovery (ASCII only)
            print(f"\nCRAWLING RESULTS:")
            print(f"   URLs Discovered: {len(self.discovered_urls)}")
            print(f"   Forms Found: {len(self.forms)}")
            print(f"   Parameters Found: {len(self.parameters)}")
            
            if self.forms:
                print(f"\nFORMS DISCOVERED:")
                for i, form in enumerate(self.forms[:5], 1):  # Show first 5
                    print(f"   {i}. {form['action']} ({form['method']}) - {len(form['inputs'])} inputs")
            
            if self.parameters:
                print(f"\nPARAMETERS DISCOVERED:")
                for url, params in list(self.parameters.items())[:5]:  # Show first 5
                    print(f"   {url} -> {list(params.keys())}")
        
        return crawl_results
    
    async def crawl_url(self, url: str, depth: int):
        """Crawl a single URL and extract links, forms, parameters"""
        
        if depth > self.max_depth or len(self.discovered_urls) > self.max_urls:
            self.logger.debug(f"Skipping {url}: depth={depth}, max_depth={self.max_depth}, urls={len(self.discovered_urls)}")
            return
        
        if url in self.crawled_urls:
            return
        
        # Only crawl URLs from the same domain
        parsed = urlparse(url)
        if parsed.netloc != self.domain:
            self.logger.debug(f"Skipping {url}: different domain")
            return
        
        try:
            self.logger.info(f"Crawling: {url} (depth: {depth})")
            print(f"   Crawling: {url}")
            
            async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as response:
                if response.status != 200:
                    self.logger.debug(f"Non-200 status: {response.status}")
                    return
                
                # Store cookies
                for cookie in response.cookies:
                    self.cookies[cookie.key] = cookie.value
                
                content = await response.text()
                content_type = response.headers.get('Content-Type', '').lower()
                
                # Only process HTML content
                if 'html' not in content_type:
                    return
                
                self.crawled_urls.add(url)
                self.discovered_urls.add(url)
                
                # Parse HTML content
                soup = BeautifulSoup(content, 'html.parser')
                
                # Extract links
                await self.extract_links(soup, url, depth)
                
                # Extract forms
                forms_found = await self.extract_forms(soup, url)
                if forms_found:
                    self.logger.info(f"Found {forms_found} forms on {url}")
                
                # Extract parameters from URL
                params_found = self.extract_url_parameters(url)
                if params_found:
                    self.logger.info(f"Found {params_found} parameters in {url}")
                
                # Extract JavaScript URLs and AJAX endpoints
                await self.extract_js_endpoints(content, url)
                
        except asyncio.TimeoutError:
            self.logger.warning(f"Timeout crawling {url}")
        except Exception as e:
            self.logger.warning(f"Error crawling {url}: {str(e)[:100]}")
    
    async def extract_links(self, soup: BeautifulSoup, base_url: str, depth: int):
        """Extract all links from the page"""
        
        links = soup.find_all('a', href=True)
        
        for link in links:
            href = link['href']
            full_url = urljoin(base_url, href)
            
            # Filter out non-crawlable URLs
            if self.is_crawlable_url(full_url):
                self.discovered_urls.add(full_url)
                
                # Recursively crawl if within depth limit
                if depth < self.max_depth:
                    await self.crawl_url(full_url, depth + 1)
    
    async def extract_forms(self, soup: BeautifulSoup, base_url: str):
        """Extract all forms and their parameters"""
        
        forms = soup.find_all('form')
        forms_count = 0
        
        for form in forms:
            forms_count += 1
            form_data = {
                'url': base_url,
                'action': urljoin(base_url, form.get('action', '')),
                'method': form.get('method', 'GET').upper(),
                'inputs': [],
                'has_file_upload': False
            }
            
            # Extract all input fields
            inputs = form.find_all(['input', 'textarea', 'select'])
            
            for input_field in inputs:
                input_data = {
                    'name': input_field.get('name', ''),
                    'type': input_field.get('type', 'text'),
                    'value': input_field.get('value', ''),
                    'required': input_field.has_attr('required')
                }
                
                if input_data['name']:  # Only add inputs with names
                    form_data['inputs'].append(input_data)
                    
                    # Check for file upload
                    if input_data['type'] == 'file':
                        form_data['has_file_upload'] = True
            
            if form_data['inputs']:  # Only add forms with inputs
                self.forms.append(form_data)
                
                # Store parameters for this form
                form_url = form_data['action'] or base_url
                if form_url not in self.parameters:
                    self.parameters[form_url] = {}
                
                for input_field in form_data['inputs']:
                    param_name = input_field['name']
                    if param_name:
                        self.parameters[form_url][param_name] = {
                            'type': input_field['type'],
                            'method': form_data['method'],
                            'form_action': form_data['action']
                        }
        
        return forms_count
    
    def extract_url_parameters(self, url: str):
        """Extract parameters from URL query string"""
        
        parsed = urlparse(url)
        params_count = 0
        
        if parsed.query:
            params = parse_qs(parsed.query)
            
            if url not in self.parameters:
                self.parameters[url] = {}
            
            for param, values in params.items():
                params_count += 1
                self.parameters[url][param] = {
                    'type': 'url_param',
                    'method': 'GET',
                    'values': values
                }
        
        return params_count
    
    async def extract_js_endpoints(self, content: str, base_url: str):
        """Extract AJAX endpoints and API calls from JavaScript"""
        
        # Common AJAX patterns
        ajax_patterns = [
            r'\.ajax\s*\(\s*["\']([^"\']+)["\']',
            r'fetch\s*\(\s*["\']([^"\']+)["\']',
            r'XMLHttpRequest.*open\s*\(\s*["\'][^"\']*["\']\s*,\s*["\']([^"\']+)["\']',
            r'axios\.[get|post|put|delete]+\s*\(\s*["\']([^"\']+)["\']',
            r'api["\']?\s*:\s*["\']([^"\']+)["\']',
            r'endpoint["\']?\s*:\s*["\']([^"\']+)["\']',
            r'url["\']?\s*:\s*["\']([^"\']+)["\']'
        ]
        
        for pattern in ajax_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                endpoint = urljoin(base_url, match)
                if self.is_crawlable_url(endpoint):
                    self.endpoints.append(endpoint)
                    self.discovered_urls.add(endpoint)
    
    async def discover_common_paths(self):
        """Discover common directories and files"""
        
        self.logger.info("Discovering common paths...")
        
        # Test common directories
        for directory in self.common_dirs:
            test_url = urljoin(self.target_url, directory)
            if await self.test_url_exists(test_url):
                self.discovered_urls.add(test_url)
                await self.crawl_url(test_url, 0)
        
        # Test common files
        for file_name in self.common_files:
            test_url = urljoin(self.target_url, file_name)
            if await self.test_url_exists(test_url):
                self.discovered_urls.add(test_url)
                await self.crawl_url(test_url, 0)
    
    async def test_url_exists(self, url: str) -> bool:
        """Test if a URL exists and is accessible"""
        try:
            async with self.session.head(url) as response:
                return response.status in [200, 301, 302, 403]  # Include forbidden as it exists
        except:
            return False
    
    def is_crawlable_url(self, url: str) -> bool:
        """Check if URL should be crawled"""
        
        parsed = urlparse(url)
        
        # Only crawl same domain
        if parsed.netloc and parsed.netloc != self.domain:
            return False
        
        # Skip certain file types
        path = parsed.path.lower()
        
        # Skip binary files
        skip_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.pdf', '.zip', '.rar', '.exe', '.dmg'}
        if any(path.endswith(ext) for ext in skip_extensions):
            return False
        
        # Skip fragments and mailto links
        if url.startswith('#') or url.startswith('mailto:') or url.startswith('javascript:'):
            return False
        
        return True
    
    def get_testable_parameters(self) -> List[Dict[str, Any]]:
        """Get all parameters that can be tested for vulnerabilities"""
        
        testable_params = []
        
        for url, params in self.parameters.items():
            for param_name, param_info in params.items():
                testable_params.append({
                    'url': url,
                    'parameter': param_name,
                    'type': param_info['type'],
                    'method': param_info['method'],
                    'form_action': param_info.get('form_action', url)
                })
        
        return testable_params
    
    def get_all_forms(self) -> List[Dict[str, Any]]:
        """Get all discovered forms"""
        return self.forms
    
    def get_all_urls(self) -> List[str]:
        """Get all discovered URLs"""
        return list(self.discovered_urls)