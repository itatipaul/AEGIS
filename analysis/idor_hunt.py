import re

PRIORITY = 45
TYPE = "Analysis"
DESCRIPTION = "Passive Heuristic Analysis for IDOR vulnerabilities"

# Regex patterns for interesting parameters
IDOR_PATTERNS = [
    r"user_?id=[0-9]+",
    r"account_?id=[0-9]+",
    r"order_?id=[0-9]+",
    r"doc_?id=[0-9]+",
    r"group_?id=[0-9]+",
    r"profile_?id=[0-9]+",
    r"invoice_?id=[0-9]+",
    r"id=[0-9]+",
    r"email=[\w\.-]+@[\w\.-]+"
]

def run(kb):
    urls = kb.get("crawled_urls", []) + [x[0] for x in kb.get("web_paths", [])]
    if not urls: return

    print(f"[*] Analyzing {len(urls)} URLs for IDOR candidates...")
    
    candidates = []
    
    for url in set(urls):
        for pattern in IDOR_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                candidates.append(url)
                break
    
    if candidates:
        print(f"    [i] Identified {len(candidates)} High-Probability IDOR Targets")
        
        # We store these differently to differentiate "Vulnerabilities" from "Leads"
        # Ideally, print the top 5 for the user to see immediately
        for c in candidates[:5]:
            print(f"      - {c}")
            
        findings = []
        for c in candidates:
            findings.append({
                "id": "IDOR-CANDIDATE",
                "msg": "Potential IDOR Parameter identified",
                "url": c,
                "severity": "LOW" # Low severity because it requires manual verification
            })
            
        kb.update("nikto_vulns", findings)
