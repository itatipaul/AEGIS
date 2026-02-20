import requests
import urllib3

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PRIORITY = 26
TYPE = "Vulnerability Scan"
DESCRIPTION = "Checks for dangling CNAMEs (Subdomain Takeover)"

# Signatures of "dead" pages from cloud providers
SIGNATURES = {
    "GitHub Pages": "There isn't a GitHub Pages site here",
    "Heroku": "Heroku | No such app",
    "Amazon S3": "The specified bucket does not exist",
    "Shopify": "Sorry, this shop is currently unavailable",
    "Tumblr": "There's nothing here.",
    "Wix": "Error 404 - Webstation",
    "Azure": "The resource you are looking for has been removed",
    "Cloudfront": "Bad Request: ERROR: The request could not be satisfied",
    "Fastly": "Fastly error: unknown domain"
}

def run(kb):
    print(f"[*] Running {DESCRIPTION}...")
    
    domains = kb.get("scope_domains")
    if not domains:
        return

    takeovers = []

    for d in domains:
        # Clean wildcard domains if present
        d = d.replace("*.", "")
        
        # We try both HTTP and HTTPS
        protocols = ["http", "https"]
        
        for proto in protocols:
            url = f"{proto}://{d}"
            try:
                # verify=False is CRITICAL here for dead subdomains
                r = requests.get(url, timeout=3, verify=False)
                content = r.text
                
                for provider, sig in SIGNATURES.items():
                    if sig in content:
                        print(f"      [CRITICAL] POTENTIAL TAKEOVER: {d} ({provider})")
                        takeovers.append({
                            "domain": d, 
                            "provider": provider,
                            "url": url
                        })
                        break
            except:
                pass

    if takeovers:
        kb.update("takeovers", takeovers)
