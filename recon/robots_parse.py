import requests
import re
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

PRIORITY = 21
TYPE = "Recon"
DESCRIPTION = "Advanced robots.txt parser with sitemap discovery and hidden path extraction"

def parse_robots_content(content, base_url):
    """Parse robots.txt content for disallowed paths and sitemaps"""
    disallowed_paths = []
    sitemap_urls = []
    user_agents = []
    current_agent = "global"
    
    lines = content.split('\n')
    for line in lines:
        line = line.strip()
        
        # Skip comments
        if line.startswith('#'):
            continue
            
        # User-agent directive
        if line.lower().startswith('user-agent:'):
            current_agent = line.split(':', 1)[1].strip()
            if current_agent not in user_agents:
                user_agents.append(current_agent)
                
        # Disallow directive
        elif line.lower().startswith('disallow:'):
            path = line.split(':', 1)[1].strip()
            if path and path != '/':
                full_path = urljoin(base_url, path)
                disallowed_paths.append({
                    "path": path,
                    "full_url": full_path,
                    "user_agent": current_agent,
                    "type": "disallowed"
                })
                
        # Allow directive (sometimes useful for bypass)
        elif line.lower().startswith('allow:'):
            path = line.split(':', 1)[1].strip()
            if path and path != '/':
                full_path = urljoin(base_url, path)
                disallowed_paths.append({
                    "path": path,
                    "full_url": full_path,
                    "user_agent": current_agent,
                    "type": "allowed"
                })
                
        # Sitemap directive
        elif line.lower().startswith('sitemap:'):
            sitemap_url = line.split(':', 1)[1].strip()
            sitemap_urls.append(sitemap_url)
    
    return {
        "disallowed_paths": disallowed_paths,
        "sitemap_urls": sitemap_urls,
        "user_agents": user_agents
    }

def fetch_sitemap(sitemap_url):
    """Fetch and parse sitemap content"""
    try:
        response = requests.get(sitemap_url, timeout=5)
        if response.status_code == 200:
            content = response.text
            
            # Parse URLs from sitemap (simple regex approach)
            urls = re.findall(r'<loc>(.*?)</loc>', content, re.IGNORECASE)
            
            # Also check for sitemap index files
            sitemap_indexes = re.findall(r'<sitemap>.*?<loc>(.*?)</loc>.*?</sitemap>', content, re.IGNORECASE | re.DOTALL)
            
            return {
                "url": sitemap_url,
                "urls_found": urls,
                "is_index": bool(sitemap_indexes),
                "child_sitemaps": sitemap_indexes
            }
    except Exception as e:
        pass
    return None

def analyze_disallowed_paths(paths):
    """Analyze disallowed paths for patterns and potential vulnerabilities"""
    analysis = {
        "admin_paths": [],
        "api_paths": [],
        "backup_files": [],
        "config_files": [],
        "development_paths": [],
        "other": []
    }
    
    file_extensions = {
        'backup': ['.bak', '.backup', '.old', '.orig', '.temp', '.tmp', '.swp'],
        'config': ['.conf', '.config', '.ini', '.yml', '.yaml', '.json', '.xml'],
        'database': ['.sql', '.db', '.sqlite', '.mdb', '.dump'],
        'log': ['.log', '.txt', '.out']
    }
    
    for path_info in paths:
        path = path_info["path"].lower()
        
        # Check for admin/management interfaces
        if any(keyword in path for keyword in ['admin', 'login', 'dashboard', 'panel', 'cp', 'manager', 'administrator']):
            analysis["admin_paths"].append(path_info)
            
        # Check for API endpoints
        elif any(keyword in path for keyword in ['api', 'rest', 'graphql', 'soap', 'wsdl', 'endpoint']):
            analysis["api_paths"].append(path_info)
            
        # Check for backup/config files
        elif any(ext in path for ext in file_extensions['backup']):
            analysis["backup_files"].append(path_info)
            
        elif any(ext in path for ext in file_extensions['config']):
            analysis["config_files"].append(path_info)
            
        # Check for development files
        elif any(keyword in path for keyword in ['dev', 'test', 'staging', 'debug', 'phpinfo', '.git', '.svn', '.env']):
            analysis["development_paths"].append(path_info)
            
        else:
            analysis["other"].append(path_info)
    
    return analysis

def run(kb):
    print(f"\n[*] Running {DESCRIPTION}...")
    
    target = kb.get("target_domain")
    if not target:
        print("    ╚ No target domain specified")
        return
    
    protocols = ['http', 'https']
    all_findings = {
        "robots_txt": [],
        "sitemaps": [],
        "disallowed_paths": [],
        "analysis": {}
    }
    
    print(f"    ╠ Target: {target}")
    
    # Try both HTTP and HTTPS
    for protocol in protocols:
        base_url = f"{protocol}://{target}"
        robots_url = f"{base_url}/robots.txt"
        
        print(f"    ╠ Checking: {robots_url}")
        
        try:
            response = requests.get(robots_url, timeout=5, allow_redirects=True)
            
            if response.status_code == 200:
                print(f"    ┃   ├ Found robots.txt ({len(response.text)} bytes)")
                
                # Parse robots.txt
                robots_data = parse_robots_content(response.text, base_url)
                
                all_findings["robots_txt"].append({
                    "url": robots_url,
                    "content_length": len(response.text),
                    "user_agents": robots_data["user_agents"]
                })
                
                # Analyze disallowed paths
                if robots_data["disallowed_paths"]:
                    print(f"    ┃   ├ Disallowed paths: {len(robots_data['disallowed_paths'])}")
                    
                    analysis = analyze_disallowed_paths(robots_data["disallowed_paths"])
                    all_findings["disallowed_paths"].extend(robots_data["disallowed_paths"])
                    
                    # Print interesting findings
                    for category, paths in analysis.items():
                        if paths:
                            print(f"    ┃   │   ├ {category.title()}: {len(paths)}")
                            for path_info in paths[:2]:
                                print(f"    ┃   │   │   └ {path_info['path'][:50]}...")
                
                # Process sitemaps
                if robots_data["sitemap_urls"]:
                    print(f"    ┃   ├ Sitemaps found: {len(robots_data['sitemap_urls'])}")
                    
                    # Fetch sitemaps in parallel
                    with ThreadPoolExecutor(max_workers=3) as executor:
                        future_to_sitemap = {
                            executor.submit(fetch_sitemap, sitemap_url): sitemap_url 
                            for sitemap_url in robots_data["sitemap_urls"][:5]  # Limit to 5
                        }
                        
                        for future in as_completed(future_to_sitemap):
                            sitemap_url = future_to_sitemap[future]
                            try:
                                sitemap_data = future.result(timeout=5)
                                if sitemap_data:
                                    all_findings["sitemaps"].append(sitemap_data)
                                    print(f"    ┃   │   ├ Sitemap: {sitemap_data['urls_found'][:3]} URLs")
                            except:
                                pass
                
                break  # Found robots.txt, no need to check other protocol
                
            elif response.status_code == 404:
                print(f"    ┃   ├ robots.txt not found")
            else:
                print(f"    ┃   ├ HTTP {response.status_code}")
                
        except requests.exceptions.RequestException as e:
            print(f"    ┃   ├ Connection failed: {str(e)[:40]}")
    
    # Also check common sitemap locations
    common_sitemaps = ['/sitemap.xml', '/sitemap_index.xml', '/sitemap1.xml', '/sitemap/sitemap.xml']
    
    print(f"    ╠ Checking common sitemap locations...")
    
    for sitemap_path in common_sitemaps:
        for protocol in protocols:
            sitemap_url = f"{protocol}://{target}{sitemap_path}"
            try:
                response = requests.head(sitemap_url, timeout=3)
                if response.status_code == 200:
                    sitemap_data = fetch_sitemap(sitemap_url)
                    if sitemap_data and sitemap_data not in all_findings["sitemaps"]:
                        all_findings["sitemaps"].append(sitemap_data)
                        print(f"    ┃   ├ Found sitemap at: {sitemap_path}")
                        break
            except:
                pass
    
    # Extract all discovered URLs
    discovered_urls = []
    
    # From disallowed paths
    for path_info in all_findings["disallowed_paths"]:
        if path_info["full_url"] not in discovered_urls:
            discovered_urls.append(path_info["full_url"])
    
    # From sitemaps
    for sitemap in all_findings["sitemaps"]:
        for url in sitemap.get("urls_found", []):
            if url not in discovered_urls:
                discovered_urls.append(url)
    
    # Update KnowledgeBase
    if discovered_urls:
        current_urls = kb.get("crawled_urls") or []
        updated_urls = list(set(current_urls + discovered_urls))
        kb.update("crawled_urls", updated_urls)
        
        all_findings["analysis"]["total_urls_discovered"] = len(discovered_urls)
        all_findings["analysis"]["added_to_crawl"] = len(updated_urls) - len(current_urls)
    
    # Save detailed findings
    kb.update("robots_analysis", all_findings)
    
    # Summary report
    print(f"\n    ╔═══════════════════════════════════════════════")
    print(f"    ║ ROBOTS.TXT ANALYSIS COMPLETE")
    print(f"    ║ Robots.txt files: {len(all_findings['robots_txt'])}")
    print(f"    ║ Disallowed paths: {len(all_findings['disallowed_paths'])}")
    print(f"    ║ Sitemaps found: {len(all_findings['sitemaps'])}")
    print(f"    ║ URLs added to crawl: {len(discovered_urls)}")
    print(f"    ╚═══════════════════════════════════════════════")
