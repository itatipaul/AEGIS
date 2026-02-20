import requests
import re
import ssl
import socket

PRIORITY = 20
TYPE = "Fingerprinting"
DESCRIPTION = "Detects technology stack and server information"

def run(kb):
    print(f"\n[*] Running {DESCRIPTION}...")
    
    domains = kb.get("scope_domains")
    if not domains:
        print("    ╚ No domains to analyze")
        return

    tech_findings = {}
    
    # Limit to first 20 domains for performance
    domains = domains[:20]
    
    print(f"    ╠ Analyzing {len(domains)} domains")
    
    for domain in domains:
        domain = domain.replace("*.", "")
        print(f"    ┣ Processing: {domain}")
        
        domain_info = {
            "server": "Unknown",
            "technologies": [],
            "ssl": {},
            "headers": {}
        }
        
        # Try HTTP and HTTPS
        for scheme in ['http', 'https']:
            url = f"{scheme}://{domain}"
            
            try:
                r = requests.head(url, timeout=3, allow_redirects=True)
                
                # Server header
                server_header = r.headers.get('Server', '')
                if server_header and domain_info["server"] == "Unknown":
                    domain_info["server"] = server_header
                
                # X-Powered-By header
                powered_by = r.headers.get('X-Powered-By', '')
                if powered_by:
                    domain_info["technologies"].append(f"X-Powered-By: {powered_by}")
                
                # Other technology indicators
                headers_str = str(r.headers).lower()
                
                tech_indicators = {
                    "ASP.NET": ["x-aspnet-version", "asp.net"],
                    "PHP": ["x-powered-by: php", "php/"],
                    "Node.js": ["x-powered-by: express", "node"],
                    "Nginx": ["nginx"],
                    "Apache": ["apache", "httpd"],
                    "IIS": ["microsoft-iis"],
                    "Cloudflare": ["cloudflare"],
                    "WordPress": ["wp-json", "wordpress"],
                    "Drupal": ["drupal"],
                    "Joomla": ["joomla"],
                    "Laravel": ["laravel"],
                    "Ruby on Rails": ["rails", "phusion passenger"],
                    "Django": ["django", "wsgiserver"],
                    "React": ["react", "next.js"],
                    "Vue.js": ["vue", "nuxt.js"]
                }
                
                for tech, indicators in tech_indicators.items():
                    for indicator in indicators:
                        if indicator in headers_str:
                            domain_info["technologies"].append(tech)
                            break
                
                # Check for common frameworks in response body (if we do GET)
                if len(domain_info["technologies"]) < 3:  # If not many found, try GET
                    try:
                        r_get = requests.get(url, timeout=3)
                        body = r_get.text.lower()
                        
                        # Check for framework signatures in HTML
                        if "wordpress" in body or "wp-content" in body:
                            domain_info["technologies"].append("WordPress")
                        if "joomla" in body:
                            domain_info["technologies"].append("Joomla")
                        if "drupal" in body:
                            domain_info["technologies"].append("Drupal")
                        if "laravel" in body:
                            domain_info["technologies"].append("Laravel")
                        if "react" in body or "reactdom" in body:
                            domain_info["technologies"].append("React")
                        if "vue" in body:
                            domain_info["technologies"].append("Vue.js")
                        if "angular" in body:
                            domain_info["technologies"].append("Angular")
                    except:
                        pass
                
                # SSL certificate information (for HTTPS)
                if scheme == 'https':
                    try:
                        cert = ssl.get_server_certificate((domain, 443))
                        # Parse certificate (simplified)
                        if "cloudflare" in cert.lower():
                            domain_info["technologies"].append("Cloudflare SSL")
                        domain_info["ssl"]["certificate"] = "Present"
                    except:
                        domain_info["ssl"]["certificate"] = "Error"
                
                # Store headers for analysis
                domain_info["headers"] = dict(r.headers)
                
                # If we got some info, break (no need to try both schemes)
                if domain_info["server"] != "Unknown" or domain_info["technologies"]:
                    break
                    
            except requests.exceptions.RequestException:
                continue
        
        # Remove duplicates
        domain_info["technologies"] = list(set(domain_info["technologies"]))
        
        # Store findings
        tech_findings[domain] = domain_info
        
        # Print summary for this domain
        if domain_info["server"] != "Unknown" or domain_info["technologies"]:
            print(f"    ┃   ├ Server: {domain_info['server']}")
            if domain_info["technologies"]:
                print(f"    ┃   ├ Technologies: {', '.join(domain_info['technologies'][:3])}")
                if len(domain_info["technologies"]) > 3:
                    print(f"    ┃   └ ... and {len(domain_info['technologies']) - 3} more")
        else:
            print(f"    ┃   └ No technology detected")
    
    # Save to KnowledgeBase
    kb.update("tech_stack", tech_findings)
    
    # Generate summary
    total_domains = len(tech_findings)
    servers = {}
    technologies = {}
    
    for domain, info in tech_findings.items():
        server = info["server"]
        if server in servers:
            servers[server] += 1
        else:
            servers[server] = 1
        
        for tech in info["technologies"]:
            if tech in technologies:
                technologies[tech] += 1
            else:
                technologies[tech] = 1
    
    print(f"\n    ╔═══════════════════════════════════════════════")
    print(f"    ║ TECHNOLOGY STACK ANALYSIS")
    print(f"    ║ Domains analyzed: {total_domains}")
    print(f"    ║ Top servers: {', '.join([f'{k}({v})' for k, v in list(servers.items())[:3]])}")
    print(f"    ║ Top technologies: {', '.join([f'{k}({v})' for k, v in list(technologies.items())[:5]])}")
    print(f"    ╚═══════════════════════════════════════════════")
