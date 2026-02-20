import re
import requests

PRIORITY = 36
TYPE = "Web Analysis"
DESCRIPTION = "Scans for outdated/vulnerable JavaScript libraries"

# Simple signature database (Library -> (Regex, Vulnerable Version Limit))
JS_SIGNATURES = {
    "jQuery": (r"jquery[/-]([0-9]+\.[0-9]+\.[0-9]+)", "3.5.0"),
    "AngularJS": (r"angular[/-]([0-9]+\.[0-9]+\.[0-9]+)", "1.8.0"),
    "Bootstrap": (r"bootstrap[/-]([0-9]+\.[0-9]+\.[0-9]+)", "4.0.0"),
    "Vue": (r"vue[/-]([0-9]+\.[0-9]+\.[0-9]+)", "2.6.0"),
    "React": (r"react[/-]([0-9]+\.[0-9]+\.[0-9]+)", "16.8.0")
}

def version_compare(v1, v2):
    """Returns True if v1 < v2"""
    try:
        p1 = [int(x) for x in v1.split('.')]
        p2 = [int(x) for x in v2.split('.')]
        return p1 < p2
    except:
        return False

def run(kb):
    print(f"[*] Running {DESCRIPTION}...")
    
    # Get JS URLs found by crawler
    js_urls = kb.get("advanced_crawl", {}).get("javascript_endpoints", [])
    if not js_urls:
        return

    vuln_libs = []

    for js_url in js_urls[:15]: # Limit check
        try:
            # Check if filename itself has version (fast check)
            for lib, (regex, safe_ver) in JS_SIGNATURES.items():
                match = re.search(regex, js_url, re.IGNORECASE)
                version = None
                
                if match:
                    version = match.group(1)
                else:
                    # Slow check: download content
                    try:
                        content = requests.get(js_url, timeout=3).text[:1000] # Check header
                        match_content = re.search(regex, content, re.IGNORECASE)
                        if match_content:
                            version = match_content.group(1)
                    except:
                        pass
                
                if version:
                    if version_compare(version, safe_ver):
                        print(f"      [MEDIUM] Outdated {lib} found: v{version} (Safe: {safe_ver}+)")
                        print(f"               Source: {js_url}")
                        vuln_libs.append({
                            "library": lib,
                            "version": version,
                            "url": js_url,
                            "risk": "Client-Side XSS / Prototype Pollution"
                        })
                    else:
                        print(f"      [INFO] Found {lib} v{version} (Secure)")
        except:
            pass

    if vuln_libs:
        kb.update("js_vulnerabilities", vuln_libs)
