import aiohttp
import asyncio
import re
import math
from urllib.parse import urljoin

PRIORITY = 25
TYPE = "Analysis"
DESCRIPTION = "Entropy-based Secret Hunter (Finds high-randomness API Keys)"

# Regex for finding string literals in JS
STRING_REGEX = r'["\']([a-zA-Z0-9_\-\.]{20,})["\']'

# Signatures for known keys (Regex is still useful for specific formats)
KNOWN_SIGS = {
    "AWS Key": r"AKIA[0-9A-Z]{16}",
    "Google API": r"AIza[0-9A-Za-z\\-_]{35}",
    "Slack Token": r"xox[baprs]-([0-9a-zA-Z]{10,48})",
    "Private Key": r"-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----"
}

def shannon_entropy(data):
    """Calculates the randomness of a string"""
    if not data: return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(chr(x))) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

async def scan_js(session, url):
    findings = []
    try:
        async with session.get(url, timeout=5) as r:
            text = await r.text()
            
            # 1. Check Known Signatures
            for name, pattern in KNOWN_SIGS.items():
                for match in re.findall(pattern, text):
                    findings.append({
                        "type": name,
                        "value": match if isinstance(match, str) else match[0],
                        "confidence": "HIGH"
                    })

            # 2. Check Entropy (The Secret Sauce)
            # Find all long strings
            potential_secrets = re.findall(STRING_REGEX, text)
            for secret in potential_secrets:
                # Filter out common false positives (like URLs or CSS classes)
                if "/" in secret or "." in secret or "-" in secret: continue
                
                # Calculate Entropy (Typical API keys are > 4.5)
                score = shannon_entropy(secret)
                if score > 4.5:
                    findings.append({
                        "type": "High Entropy String",
                        "value": secret,
                        "confidence": "MEDIUM",
                        "entropy": round(score, 2)
                    })
    except: pass
    
    return url, findings

async def run_async(kb):
    # Get JS files found by crawler/spider
    urls = kb.get("javascript_files", [])
    if not urls: 
        # Fallback to checking all crawled URLs ending in .js
        crawled = kb.get("crawled_urls", [])
        urls = [u for u in crawled if u.endswith(".js")]

    if not urls: return

    print(f"[*] Running {DESCRIPTION} on {len(urls)} JS files...")
    
    all_findings = []
    async with aiohttp.ClientSession() as session:
        tasks = [scan_js(session, u) for u in urls]
        results = await asyncio.gather(*tasks)
        
        for url, file_findings in results:
            if file_findings:
                print(f"    [!] Secrets in {url}:")
                for f in file_findings:
                    val_preview = f"{f['value'][:4]}...{f['value'][-4:]}"
                    print(f"        - {f['type']}: {val_preview}")
                    f['url'] = url
                    all_findings.append(f)

    if all_findings:
        kb.update("leaked_secrets", all_findings)
        
        # Security Alert
        kb.update("security_alerts", {
            "secrets_leak": {
                "status": "CRITICAL",
                "count": len(all_findings),
                "details": "Hardcoded secrets found in JavaScript. Revoke immediately."
            }
        })

def run(kb):
    asyncio.run(run_async(kb))
