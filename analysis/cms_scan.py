

import requests
import json

# TAGS
PRIORITY = 23
TYPE = "App Analysis"
DESCRIPTION = "Detects CMS (WordPress/Joomla) and enumerates users"

def run(kb):
    print(f"[*] Running {DESCRIPTION}...")
    
    domains = kb.get("scope_domains")
    if not domains:
        return

    cms_findings = []

    for d in domains:
        d = d.replace("*.", "")
        url = f"http://{d}"
        
        try:
            # 1. Check for WordPress
            # We check for the common login page and the readme
            r = requests.get(f"{url}/wp-login.php", timeout=5)
            if r.status_code == 200 and "wordpress" in r.text.lower():
                print(f"      [+] WordPress Detected: {d}")
                
                # 1a. Try to enumerate users via REST API
                try:
                    r_api = requests.get(f"{url}/wp-json/wp/v2/users", timeout=5)
                    if r_api.status_code == 200:
                        users = [u['slug'] for u in r_api.json()]
                        print(f"          [!] Enumerated Users: {', '.join(users)}")
                        cms_findings.append({"target": d, "cms": "WordPress", "users": users})
                except:
                    pass

                # 1b. Check for XML-RPC
                r_xml = requests.get(f"{url}/xmlrpc.php", timeout=5)
                if r_xml.status_code == 405: # 405 Method Not Allowed usually means it exists
                    print(f"          [!] XML-RPC Interface Exposed (Brute force risk)")
            
            # 2. Check for Joomla
            elif "joomla" in requests.get(f"{url}/administrator/", timeout=5).text.lower():
                 print(f"      [+] Joomla Detected: {d}")
                 cms_findings.append({"target": d, "cms": "Joomla", "users": []})

        except:
            pass

    kb.update("cms_findings", cms_findings)
