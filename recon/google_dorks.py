import random
import time
import requests
from urllib.parse import quote

PRIORITY = 20
TYPE = "OSINT"
DESCRIPTION = "Automated Google Dorking for exposed documents and configs"

DORKS = [
    "ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ini | ext:env",
    "ext:sql | ext:dbf | ext:mdb",
    "ext:log",
    "ext:bkf | ext:bkp | ext:bak | ext:old | ext:backup",
    "inurl:login | inurl:signin | intitle:Login | intitle:\"sign in\"",
    "ext:doc | ext:docx | ext:odt | ext:pdf | ext:rtf | ext:sxw | ext:psw | ext:ppt | ext:pptx | ext:pps | ext:csv"
]

def run(kb):
    target = kb.get("target_domain")
    if not target: return

    print(f"[*] Running {DESCRIPTION}...")
    
    # We simply generate the links for the user to click, 
    # as automating this often triggers CAPTCHAs immediately.
    # However, we can try to fetch the first result if we have a proxy.
    
    print(f"    [i] Generated Dork Links for Manual Review (Anti-Captcha Safe Mode):")
    
    dork_results = []
    
    for dork in DORKS:
        query = f"site:{target} {dork}"
        encoded_query = quote(query)
        google_url = f"https://www.google.com/search?q={encoded_query}"
        
        # We categorize the dorks
        category = "Configs" if "ext:xml" in dork else "Database" if "ext:sql" in dork else "Documents"
        
        print(f"      - [{category}] {google_url}")
        
        dork_results.append({
            "url": google_url, 
            "msg": f"Google Dork: {category}",
            "id": "DORK"
        })

    # Add to report as "Sensitive Configs" so user sees the links
    kb.update("nikto_vulns", dork_results)
