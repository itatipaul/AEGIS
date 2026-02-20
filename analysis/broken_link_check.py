import requests
from urllib.parse import urlparse

PRIORITY = 27
TYPE = "Web Analysis"
DESCRIPTION = "Checks for broken external links (Hijacking Risk)"

def run(kb):
    print(f"[*] Running {DESCRIPTION}...")
    
    target_domain = kb.get("target_domain")
    # Get all links found by crawler
    all_pages = kb.get("advanced_crawl", {}).get("pages", [])
    
    external_links = set()
    
    # Extract external links
    for page in all_pages:
        # This assumes you might parse links from content again or rely on what you have
        # For this example, we assume we extract links fresh or have a list
        # Let's try to extract from the raw content if stored, or just use what we have
        pass 
        # (Simplified: assuming we rely on 'advanced_crawl' structure. 
        # If 'advanced_crawl' doesn't store external links list, we skip logic for now 
        # or just check the URL list itself if it contains externals).
    
    # Alternative: Scan the 'crawled_urls' list itself
    urls = kb.get("crawled_urls", [])
    
    broken_links = []
    
    for url in urls:
        try:
            parsed = urlparse(url)
            # If it's not our target domain
            if target_domain not in parsed.netloc and parsed.netloc != "":
                
                try:
                    r = requests.head(url, timeout=3, allow_redirects=True)
                    if r.status_code == 404:
                        print(f"      [HIGH] Broken External Link: {url}")
                        print(f"             (Potentially hijackable if domain expired)")
                        broken_links.append({"url": url, "status": 404})
                    elif r.status_code == 0: # Connection error (domain might be NXDOMAIN)
                         print(f"      [CRITICAL] Unresolvable External Domain: {parsed.netloc}")
                         broken_links.append({"url": url, "status": "NXDOMAIN"})
                except requests.exceptions.ConnectionError:
                     print(f"      [CRITICAL] Connection Failed (NXDOMAIN?): {url}")
                     broken_links.append({"url": url, "status": "NXDOMAIN"})
                except:
                    pass
        except:
            pass

    if broken_links:
        kb.update("broken_links", broken_links)
