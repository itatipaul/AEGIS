import requests
import urllib.parse

PRIORITY = 27
TYPE = "Vulnerability Scan"
DESCRIPTION = "Checks for broken external links (Social Media Hijacking)"

# Services we can check easily
SOCIAL_SIGS = {
    "twitter.com": "This account doesn’t exist",
    "instagram.com": "Sorry, this page isn't available",
    "facebook.com": "This content isn't available right now",
    "tiktok.com": "Couldn't find this account",
    "github.com": "404", # Github username takeover
    "medium.com": "404",
    "youtube.com": "404 Not Found"
}

def run(kb):
    urls = kb.get("external_links", []) # Assuming crawler extracts external links
    
    # If crawler didn't separate them, parse from all scraped data
    if not urls:
        # Quick parse of crawled pages is hard here without raw HTML, 
        # so we rely on what the spider found.
        # Fallback: Check if we have 'broken_links' from broken_link_check.py
        pass

    # Note: Ensure your spider/crawler saves external links to 'external_links' list in KB
    # If not, add this logic to your spider.py or run strictly on known broken links
    
    # Let's use broken links identified by the previous module if available
    broken_links = kb.get("broken_links", []) 
    
    if not broken_links: return

    print(f"[*] Checking {len(broken_links)} broken links for Hijacking potential...")
    
    hijackable = []

    for link in broken_links:
        url = link.get('url')
        if not url: continue
        
        domain = urllib.parse.urlparse(url).netloc
        
        # Check if it's a known social platform
        matched_sig = None
        for social, sig in SOCIAL_SIGS.items():
            if social in domain:
                matched_sig = sig
                break
        
        if matched_sig:
            # Re-check content to confirm "Available" status
            try:
                # We need a browser User-Agent to avoid getting blocked by social media
                headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
                r = requests.get(url, headers=headers, timeout=5)
                
                if r.status_code == 404 or matched_sig in r.text:
                    print(f"      [!] HIJACKABLE RESOURCE: {url} ({domain})")
                    hijackable.append({
                        "id": "SOCIAL-TAKEOVER",
                        "msg": f"Broken link to claimable {domain} account",
                        "url": url,
                        "severity": "MEDIUM"
                    })
            except: pass

    if hijackable:
        kb.update("nikto_vulns", hijackable)
