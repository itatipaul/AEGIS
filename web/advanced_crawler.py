# plugins/web/advanced_crawler.py
import asyncio
import aiohttp
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import json
import re
from collections import deque
import time
import hashlib

PRIORITY = 30
TYPE = "Web Analysis"
DESCRIPTION = "Advanced web crawler with JavaScript rendering and deep discovery"

class AdvancedCrawler:
    def __init__(self):
        self.visited = set()
        self.queue = deque()
        self.results = []
        self.session = None
        self.js_endpoints = set()
        self.forms = []
        self.api_endpoints = set()
        
        # Common file extensions to ignore for crawling
        self.ignore_extensions = {
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.ico',
            '.mp3', '.mp4', '.avi', '.mov', '.wmv',
            '.zip', '.rar', '.tar', '.gz', '.7z',
            '.exe', '.dll', '.msi', '.deb', '.rpm'
        }
        
        # Common API patterns
        self.api_patterns = [
            r'/api/', r'/v[0-9]/', r'/rest/', r'/json/',
            r'/graphql', r'/gql', r'/soap', r'/wsdl',
            r'\.json$', r'\.xml$', r'\.csv$'
        ]
        
        # Common JavaScript file patterns
        self.js_patterns = [
            r'\.js$', r'/static/', r'/js/', r'/scripts/',
            r'webpack', r'bundle', r'app\.js', r'main\.js'
        ]
        
    async def init_session(self):
        """Initialize aiohttp session"""
        self.session = aiohttp.ClientSession(
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive"
            }
        )
    
    async def close_session(self):
        """Close aiohttp session"""
        if self.session:
            await self.session.close()
    
    def should_crawl(self, url, base_domain):
        """Determine if a URL should be crawled"""
        parsed = urlparse(url)
        
        # Skip non-http(s) URLs
        if parsed.scheme not in ['http', 'https']:
            return False
        
        # Skip different domains (unless subdomain)
        if parsed.netloc != base_domain and not parsed.netloc.endswith('.' + base_domain):
            return False
        
        # Skip ignored extensions
        path = parsed.path.lower()
        if any(path.endswith(ext) for ext in self.ignore_extensions):
            return False
        
        # Skip common non-content URLs
        skip_patterns = ['logout', 'exit', 'signout', 'destroy']
        if any(pattern in path for pattern in skip_patterns):
            return False
        
        # Already visited
        if url in self.visited:
            return False
        
        return True
    
    def extract_links(self, html, base_url, base_domain):
        """Extract all links from HTML"""
        soup = BeautifulSoup(html, 'html.parser')
        links = set()
        
        # Extract from <a> tags
        for tag in soup.find_all('a', href=True):
            href = tag['href'].strip()
            full_url = urljoin(base_url, href)
            if self.should_crawl(full_url, base_domain):
                links.add(full_url)
        
        # Extract from <link> tags
        for tag in soup.find_all('link', href=True):
            href = tag['href'].strip()
            full_url = urljoin(base_url, href)
            if self.should_crawl(full_url, base_domain):
                links.add(full_url)
        
        # Extract from <script> tags
        for tag in soup.find_all('script', src=True):
            src = tag['src'].strip()
            full_url = urljoin(base_url, src)
            # Check if it's a JavaScript file
            if any(re.search(pattern, full_url, re.IGNORECASE) for pattern in self.js_patterns):
                self.js_endpoints.add(full_url)
            elif self.should_crawl(full_url, base_domain):
                links.add(full_url)
        
        # Extract from <img> tags
        for tag in soup.find_all('img', src=True):
            src = tag['src'].strip()
            full_url = urljoin(base_url, src)
            # Don't crawl images, but track them
            if any(re.search(pattern, full_url, re.IGNORECASE) for pattern in self.api_patterns):
                self.api_endpoints.add(full_url)
        
        # Extract from <form> actions
        for form in soup.find_all('form'):
            form_data = self.extract_form_data(form, base_url)
            self.forms.append(form_data)
            
            if form.get('action'):
                action = form['action'].strip()
                full_url = urljoin(base_url, action)
                if self.should_crawl(full_url, base_domain):
                    links.add(full_url)
        
        # Extract from inline JavaScript (basic extraction)
        for script in soup.find_all('script'):
            if script.string:
                # Look for URLs in JavaScript
                js_urls = re.findall(r'["\'](https?://[^"\']+)["\']', script.string)
                for js_url in js_urls:
                    if self.should_crawl(js_url, base_domain):
                        links.add(js_url)
                    
                    # Check for API endpoints
                    if any(re.search(pattern, js_url, re.IGNORECASE) for pattern in self.api_patterns):
                        self.api_endpoints.add(js_url)
        
        # Extract from CSS (style tags and inline styles)
        style_tags = soup.find_all('style')
        for style in style_tags:
            if style.string:
                css_urls = re.findall(r'url\(["\']?([^"\')]+)["\']?\)', style.string)
                for css_url in css_urls:
                    full_url = urljoin(base_url, css_url)
                    if self.should_crawl(full_url, base_domain):
                        links.add(full_url)
        
        return links
    
    def extract_form_data(self, form, base_url):
        """Extract detailed form information"""
        form_data = {
            'action': urljoin(base_url, form.get('action', '')),
            'method': form.get('method', 'get').upper(),
            'inputs': [],
            'attributes': dict(form.attrs)
        }
        
        # Extract all input fields
        for input_tag in form.find_all(['input', 'textarea', 'select']):
            input_info = {
                'type': input_tag.get('type', 'text'),
                'name': input_tag.get('name', ''),
                'value': input_tag.get('value', ''),
                'placeholder': input_tag.get('placeholder', ''),
                'required': 'required' in input_tag.attrs,
                'attributes': dict(input_tag.attrs)
            }
            
            # Handle select options
            if input_tag.name == 'select':
                options = []
                for option in input_tag.find_all('option'):
                    options.append({
                        'value': option.get('value', ''),
                        'text': option.get_text(strip=True)
                    })
                input_info['options'] = options
            
            form_data['inputs'].append(input_info)
        
        return form_data
    
    async def fetch_page(self, url):
        """Fetch a single page"""
        try:
            async with self.session.get(url, timeout=10, ssl=False) as response:
                if response.status == 200:
                    content = await response.text()
                    
                    # Get response headers
                    headers = dict(response.headers)
                    
                    # Get cookies
                    cookies = response.cookies
                    
                    return {
                        'url': url,
                        'status': response.status,
                        'content': content,
                        'headers': headers,
                        'cookies': dict(cookies),
                        'error': None
                    }
                else:
                    return {
                        'url': url,
                        'status': response.status,
                        'content': None,
                        'headers': dict(response.headers),
                        'cookies': {},
                        'error': f'HTTP {response.status}'
                    }
        except Exception as e:
            return {
                'url': url,
                'status': 0,
                'content': None,
                'headers': {},
                'cookies': {},
                'error': str(e)
            }
    
    def analyze_page_content(self, page_data):
        """Analyze page content for interesting patterns"""
        analysis = {
            'title': '',
            'meta_tags': [],
            'keywords': [],
            'description': '',
            'word_count': 0,
            'link_count': 0,
            'form_count': 0,
            'script_count': 0,
            'sensitive_patterns': [],
            'technology_hints': []
        }
        
        if not page_data['content']:
            return analysis
        
        soup = BeautifulSoup(page_data['content'], 'html.parser')
        
        # Extract title
        title_tag = soup.find('title')
        if title_tag:
            analysis['title'] = title_tag.get_text(strip=True)
        
        # Extract meta tags
        for meta in soup.find_all('meta'):
            meta_dict = dict(meta.attrs)
            analysis['meta_tags'].append(meta_dict)
            
            # Check for keywords and description
            if 'name' in meta_dict:
                if meta_dict['name'].lower() == 'keywords' and 'content' in meta_dict:
                    analysis['keywords'] = [k.strip() for k in meta_dict['content'].split(',')]
                elif meta_dict['name'].lower() == 'description' and 'content' in meta_dict:
                    analysis['description'] = meta_dict['content']
        
        # Word count (approximate)
        text = soup.get_text()
        analysis['word_count'] = len(text.split())
        
        # Count elements
        analysis['link_count'] = len(soup.find_all('a'))
        analysis['form_count'] = len(soup.find_all('form'))
        analysis['script_count'] = len(soup.find_all('script'))
        
        # Look for sensitive patterns
        sensitive_patterns = [
            (r'(api[_-]?key|access[_-]?key|secret[_-]?key)\s*[=:]\s*[\'"]([^\'"]{10,100})[\'"]', 'API Key'),
            (r'(password|passwd|pwd)\s*[=:]\s*[\'"]([^\'"]{3,50})[\'"]', 'Password'),
            (r'(token|auth[_-]?token)\s*[=:]\s*[\'"]([^\'"]{10,200})[\'"]', 'Token'),
            (r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----', 'Private Key'),
            (r'[\w\.-]+@[\w\.-]+\.\w+', 'Email Address'),
            (r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', 'Phone Number'),
            (r'\b\d{3}[-]?\d{2}[-]?\d{4}\b', 'SSN Pattern')
        ]
        
        for pattern, name in sensitive_patterns:
            matches = re.findall(pattern, page_data['content'], re.IGNORECASE)
            if matches:
                for match in matches:
                    if isinstance(match, tuple):
                        value = match[1] if len(match) > 1 else match[0]
                    else:
                        value = match
                    
                    # Truncate long values
                    if len(value) > 50:
                        value = value[:50] + "..."
                    
                    analysis['sensitive_patterns'].append({
                        'type': name,
                        'value': value,
                        'context': 'Found in page content'
                    })
        
        # Technology hints from headers and HTML
        headers = page_data.get('headers', {})
        if 'server' in headers:
            analysis['technology_hints'].append(f"Server: {headers['server']}")
        if 'x-powered-by' in headers:
            analysis['technology_hints'].append(f"Powered by: {headers['x-powered-by']}")
        
        # Check for common framework indicators
        framework_indicators = [
            ('React', r'__NEXT_DATA__|react|react-dom'),
            ('Vue.js', r'__vue__|vue|vue-router'),
            ('Angular', r'ng-|angular'),
            ('jQuery', r'jquery'),
            ('Bootstrap', r'bootstrap'),
            ('WordPress', r'wp-content|wp-includes|wordpress')
        ]
        
        for framework, pattern in framework_indicators:
            if re.search(pattern, page_data['content'], re.IGNORECASE):
                analysis['technology_hints'].append(framework)
        
        return analysis
    
    async def crawl(self, start_url, max_pages=100, max_depth=3):
        """Main crawling function"""
        parsed_start = urlparse(start_url)
        base_domain = parsed_start.netloc
        
        await self.init_session()
        
        # Add start URL to queue
        self.queue.append((start_url, 0))
        
        pages_crawled = 0
        
        while self.queue and pages_crawled < max_pages:
            url, depth = self.queue.popleft()
            
            if depth > max_depth:
                continue
            
            if url in self.visited:
                continue
            
            print(f"    ┃   ├ Crawling: {url} (depth: {depth})")
            
            # Fetch the page
            page_data = await self.fetch_page(url)
            self.visited.add(url)
            pages_crawled += 1
            
            if page_data['status'] == 200:
                # Analyze page content
                analysis = self.analyze_page_content(page_data)
                page_data['analysis'] = analysis
                
                # Extract links for further crawling
                new_links = self.extract_links(page_data['content'], url, base_domain)
                
                # Add new links to queue
                for link in new_links:
                    if link not in self.visited:
                        self.queue.append((link, depth + 1))
                
                # Store results
                self.results.append(page_data)
            
            # Add small delay to be polite
            await asyncio.sleep(0.1)
        
        await self.close_session()
        
        return self.results
    
    def generate_sitemap(self):
        """Generate a sitemap from crawled results"""
        sitemap = {
            'pages': [],
            'statistics': {
                'total_pages': len(self.results),
                'successful_pages': sum(1 for r in self.results if r['status'] == 200),
                'failed_pages': sum(1 for r in self.results if r['status'] != 200),
                'total_links': sum(r['analysis']['link_count'] for r in self.results if 'analysis' in r),
                'total_forms': sum(r['analysis']['form_count'] for r in self.results if 'analysis' in r),
                'js_endpoints': len(self.js_endpoints),
                'api_endpoints': len(self.api_endpoints),
                'forms_discovered': len(self.forms)
            },
            'structure': {},
            'interesting_findings': {
                'sensitive_data': [],
                'login_forms': [],
                'file_uploads': [],
                'admin_panels': []
            }
        }
        
        # Organize pages by directory structure
        for result in self.results:
            if result['status'] == 200:
                page_info = {
                    'url': result['url'],
                    'title': result['analysis']['title'] if 'analysis' in result else '',
                    'word_count': result['analysis']['word_count'] if 'analysis' in result else 0,
                    'link_count': result['analysis']['link_count'] if 'analysis' in result else 0,
                    'form_count': result['analysis']['form_count'] if 'analysis' in result else 0
                }
                sitemap['pages'].append(page_info)
                
                # Check for interesting pages
                url_lower = result['url'].lower()
                analysis = result.get('analysis', {})
                
                # Check for admin panels
                admin_keywords = ['admin', 'administrator', 'panel', 'dashboard', 'cp', 'manager']
                if any(keyword in url_lower for keyword in admin_keywords):
                    sitemap['interesting_findings']['admin_panels'].append(result['url'])
                
                # Check for login forms
                if analysis.get('form_count', 0) > 0:
                    # Look for password fields in forms
                    for form in self.forms:
                        if form['action'] == result['url']:
                            for input_field in form['inputs']:
                                if input_field['type'] == 'password':
                                    sitemap['interesting_findings']['login_forms'].append({
                                        'url': result['url'],
                                        'form_action': form['action'],
                                        'method': form['method']
                                    })
                                    break
                
                # Check for file upload forms
                for form in self.forms:
                    if form['action'] == result['url']:
                        for input_field in form['inputs']:
                            if input_field['type'] == 'file':
                                sitemap['interesting_findings']['file_uploads'].append({
                                    'url': result['url'],
                                    'form_action': form['action']
                                })
                                break
                
                # Collect sensitive data findings
                if analysis.get('sensitive_patterns'):
                    for pattern in analysis['sensitive_patterns']:
                        sitemap['interesting_findings']['sensitive_data'].append({
                            'url': result['url'],
                            'type': pattern['type'],
                            'value': pattern['value']
                        })
        
        # Add JavaScript and API endpoints
        sitemap['javascript_endpoints'] = list(self.js_endpoints)
        sitemap['api_endpoints'] = list(self.api_endpoints)
        sitemap['forms'] = self.forms
        
        return sitemap

async def run_crawler_async(kb, start_urls, max_pages=50, max_depth=2):
    """Async wrapper for crawler execution"""
    crawler = AdvancedCrawler()
    all_results = []
    
    for start_url in start_urls:
        print(f"    ╠ Starting crawl from: {start_url}")
        results = await crawler.crawl(start_url, max_pages=max_pages, max_depth=max_depth)
        all_results.extend(results)
    
    # Generate sitemap
    sitemap = crawler.generate_sitemap()
    
    return sitemap

def run(kb):
    """Plugin entry point for A.E.G.I.S framework"""
    print(f"\n[*] Running {DESCRIPTION}...")
    
    # Get starting URLs from KnowledgeBase
    start_urls = []
    
    # Get from web logic analysis
    web_analysis = kb.get("web_logic_analysis", {})
    if web_analysis and "results" in web_analysis:
        for result in web_analysis["results"]:
            if result.get("status_code") == 200:
                start_urls.append(result["target"])
    
    # Get from open ports
    open_ports = kb.get("open_ports", {})
    for target, ports in open_ports.items():
        for port_info in ports:
            port = port_info.get("port", 0)
            if port in [80, 443, 8080, 8443]:
                protocol = "https" if port in [443, 8443] else "http"
                start_urls.append(f"{protocol}://{target}:{port}")
    
    # Get from crawled URLs
    crawled_urls = kb.get("crawled_urls", [])
    start_urls.extend(crawled_urls[:5])  # Add first 5 crawled URLs
    
    # Remove duplicates
    start_urls = list(set(start_urls))
    
    if not start_urls:
        print("    ╚ No starting URLs found for crawling")
        return
    
    print(f"    ╠ Starting URLs: {len(start_urls)}")
    print(f"    ╠ Max pages per site: 50")
    print(f"    ╠ Max depth: 2")
    
    # Run async crawler
    import asyncio
    
    try:
        # Create new event loop for async execution
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        sitemap = loop.run_until_complete(
            run_crawler_async(kb, start_urls[:3], max_pages=50, max_depth=2)
        )
        
        # Save results to KnowledgeBase
        kb.update("advanced_crawl", sitemap)
        
        # Update crawled URLs with new discoveries
        existing_urls = kb.get("crawled_urls", [])
        new_urls = [page['url'] for page in sitemap['pages']]
        all_urls = list(set(existing_urls + new_urls))
        kb.update("crawled_urls", all_urls)
        
        # Report findings
        stats = sitemap['statistics']
        findings = sitemap['interesting_findings']
        
        print(f"\n    ╔═══════════════════════════════════════════════")
        print(f"    ║ ADVANCED CRAWLING COMPLETE")
        print(f"    ║ Pages crawled: {stats['total_pages']}")
        print(f"    ║ Successful: {stats['successful_pages']}")
        print(f"    ║ JavaScript endpoints: {stats['js_endpoints']}")
        print(f"    ║ API endpoints: {stats['api_endpoints']}")
        print(f"    ║ Forms discovered: {stats['forms_discovered']}")
        
        if findings['login_forms']:
            print(f"    ║")
            print(f"    ║ Login forms found: {len(findings['login_forms'])}")
            for form in findings['login_forms'][:3]:
                print(f"    ║   • {form['url']}")
        
        if findings['admin_panels']:
            print(f"    ║")
            print(f"    ║ Admin panels: {len(findings['admin_panels'])}")
            for panel in findings['admin_panels'][:3]:
                print(f"    ║   • {panel}")
        
        if findings['sensitive_data']:
            print(f"    ║")
            print(f"    ║ Sensitive data patterns: {len(findings['sensitive_data'])}")
            for data in findings['sensitive_data'][:3]:
                print(f"    ║   • {data['type']}: {data['value'][:30]}...")
        
        print(f"    ╚═══════════════════════════════════════════════")
        
    except Exception as e:
        print(f"    ╚ Crawling failed: {str(e)}")
