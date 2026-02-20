import requests
import json
from urllib.parse import urljoin

PRIORITY = 21 # Run after basic recon, before heavy attacks
TYPE = "Recon"
DESCRIPTION = "Hunts for Swagger/OpenAPI definitions and extracts endpoints"

COMMON_PATHS = [
    "/swagger.json",
    "/api/swagger.json",
    "/swagger/v1/swagger.json",
    "/openapi.json",
    "/api/openapi.json",
    "/api/docs",
    "/v2/api-docs",
    "/swagger-ui.html"
]

def run(kb):
    print(f"[*] Running {DESCRIPTION}...")
    
    target = kb.get("target_domain")
    if not target:
        return

    # Handle protocol
    base_url = f"https://{target}" if not target.startswith("http") else target
    found_endpoints = []
    
    # Get existing crawl results to see if we already found swagger
    crawled = kb.get("crawled_urls") or []
    
    paths_to_check = COMMON_PATHS + [u for u in crawled if "swagger" in u or "api-docs" in u]
    
    for path in set(paths_to_check):
        # If it's a full URL from crawler, use it, otherwise join
        target_url = path if path.startswith("http") else urljoin(base_url, path)
        
        try:
            print(f"    > Checking: {target_url}...", end="\r")
            r = requests.get(target_url, timeout=5, verify=False)
            
            if r.status_code == 200:
                # Check if it looks like Swagger JSON
                try:
                    data = r.json()
                    is_swagger = False
                    
                    if "swagger" in data or "openapi" in data:
                        is_swagger = True
                        print(f"      [+] FOUND SWAGGER DEFINITION: {target_url}")
                        
                        # Parse paths
                        paths = data.get("paths", {})
                        base_path = data.get("basePath", "")
                        
                        count = 0
                        for route, methods in paths.items():
                            full_route = f"{base_url}{base_path}{route}"
                            
                            # Identify required methods
                            for method in methods.keys():
                                found_endpoints.append({
                                    "url": full_route,
                                    "method": method.upper(),
                                    "source": "Swagger"
                                })
                                count += 1
                        
                        print(f"      [+] Extracted {count} API endpoints from definition.")
                        
                except:
                    # Not JSON, maybe HTML Swagger UI?
                    if "swagger-ui" in r.text.lower():
                         print(f"      [+] Found Swagger UI HTML: {target_url}")
                         
        except:
            pass

    if found_endpoints:
        # Save to KB for the attacks to use
        current_apis = kb.get("api_endpoints_list") or []
        kb.update("api_endpoints_list", current_apis + found_endpoints)
        
        # Also add URLs to general crawl list so XSS/SQLi scanners hit them
        new_urls = [e["url"] for e in found_endpoints]
        current_crawl = kb.get("crawled_urls") or []
        kb.update("crawled_urls", list(set(current_crawl + new_urls)))
