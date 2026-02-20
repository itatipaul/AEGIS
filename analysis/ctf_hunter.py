import re

PRIORITY = 41
TYPE = "CTF"
DESCRIPTION = "Hunts for CTF flags, hidden comments, and secrets"

# Regex patterns for common flag formats
FLAG_PATTERNS = [
    r'flag\{[^}]+\}',       # flag{...}
    r'CTF\{[^}]+\}',        # CTF{...}
    r'aegis\{[^}]+\}',      # aegis{...}
    r'HTB\{[^}]+\}',        # HackTheBox style
    r'THM\{[^}]+\}',        # TryHackMe style
    r'[a-fA-F0-9]{32}',     # MD5 hash (common for flags)
]

def run(kb):
    print(f"[*] Running {DESCRIPTION}...")
    
    # Gather all text data we've seen
    pages = kb.get("advanced_crawl", {}).get("pages", [])
    if not pages:
        return

    findings = []
    
    for page in pages:
        url = page.get("url", "")
        content = page.get("content", "")
        
        if not content: continue

        # 1. Search for Flags
        for pattern in FLAG_PATTERNS:
            matches = re.findall(pattern, content)
            for match in matches:
                print(f"      [!!!] FLAG FOUND in {url}: {match}")
                findings.append({
                    "type": "CTF Flag",
                    "url": url,
                    "content": match,
                    "severity": "CRITICAL"
                })

        # 2. Search for HTML Comments (Developers hide hints here)
        comments = re.findall(r'', content, re.DOTALL)
        for comment in comments:
            comment = comment.strip()
            # Filter out boring comments
            if len(comment) > 3 and not comment.startswith(("<", "!", "[if")):
                # Heuristic for "interesting" comments
                if any(x in comment.lower() for x in ['todo', 'fix', 'password', 'key', 'admin', 'debug']):
                    print(f"      [INFO] Interesting Comment in {url}: {comment[:50]}...")
                    findings.append({
                        "type": "Hidden Comment",
                        "url": url,
                        "content": comment,
                        "severity": "INFO"
                    })

    if findings:
        kb.update("ctf_findings", findings)
