import requests
import re
from urllib.parse import urljoin, urlparse

PRIORITY = 22

def run(kb):
    print("[*] Running Web Spider...")
    
    start_url = kb.get("target_domain")
    if not start_url:
        return

    # Ensure protocol
    if not start_url.startswith("http"):
        start_url = f"http://{start_url}"

    visited = set()
    to_visit = [start_url]
    internal_urls = set()
    
    # Limit depth to prevent infinite loops in this demo
    max_pages = 15 
    count = 0

    while to_visit and count < max_pages:
        url = to_visit.pop(0)
        if url in visited:
            continue

        try:
            r = requests.get(url, timeout=3)
            visited.add(url)
            count += 1
            
            # Simple Regex to find href="..."
            links = re.findall(r'href=["\'](.*?)["\']', r.text)
            
            for link in links:
                # Make relative links absolute
                full_url = urljoin(url, link)
                
                # Only follow links inside the target domain
                if start_url in full_url:
                    internal_urls.add(full_url)
                    if full_url not in visited:
                        to_visit.append(full_url)
                        
        except:
            pass

    print(f"      [+] Spider crawled {count} pages.")
    print(f"      [+] Mapped {len(internal_urls)} internal endpoints.")
    
    # Save these for the Attack plugins to use later!
    kb.update("crawled_urls", list(internal_urls))
