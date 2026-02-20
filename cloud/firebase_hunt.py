import requests

PRIORITY = 20
TYPE = "Cloud Recon"
DESCRIPTION = "Checks for open Firebase databases associated with the target"

def run(kb):
    target = kb.get("target_domain")
    if not target: return

    # Generate potential firebase names
    # e.g., company.com -> company, company-app, company-dev
    base = target.split('.')[0]
    variations = [
        base,
        f"{base}-app",
        f"{base}-dev",
        f"{base}-staging",
        f"{base}-prod",
        f"{base}app",
        target.replace('.', ''),
        target.replace('.', '-')
    ]
    
    print(f"[*] Checking {len(variations)} potential Firebase instances...")
    
    findings = []
    
    for name in variations:
        url = f"https://{name}.firebaseio.com/.json"
        try:
            r = requests.get(url, timeout=3, verify=False)
            
            if r.status_code == 200:
                print(f"      [!] CRITICAL: Open Firebase Found: {url}")
                # Analyze content size to guess impact
                size = len(r.content)
                findings.append({
                    "id": "FIREBASE-LEAK",
                    "msg": f"Open Firebase Database ({size} bytes)",
                    "url": url,
                    "severity": "CRITICAL"
                })
            elif r.status_code == 401:
                # Exists but secure
                # print(f"      [+] Found secure Firebase: {name}")
                pass
                
        except:
            pass

    if findings:
        kb.update("nikto_vulns", findings)
