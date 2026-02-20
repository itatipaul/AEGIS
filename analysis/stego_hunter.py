import requests
import re

PRIORITY = 45
TYPE = "CTF Analysis"
DESCRIPTION = "Checks images for Steganography and hidden text"

def run(kb):
    print(f"[*] Running {DESCRIPTION}...")
    urls = kb.get("crawled_urls") or []
    image_extensions = (".jpg", ".jpeg", ".png", ".gif", ".bmp")
    images = [u for u in urls if u.lower().endswith(image_extensions)]
    
    if not images: return

    stego_findings = []
    for img_url in images[:10]:
        try:
            r = requests.get(img_url, timeout=5)
            content = r.content
            findings = []
            
            # 1. Check for appended strings (Strings after JPEG EOF)
            if img_url.endswith((".jpg", ".jpeg")):
                eof_index = content.rfind(b'\xff\xd9')
                if eof_index != -1 and len(content) > eof_index + 2:
                    findings.append(f"Data appended after EOF")

            # 2. Check for Plaintext Flags (Use rb for raw bytes regex)
            flag_match = re.search(rb'(flag\{|CTF\{|aegis\{)[^}]+\}', content)
            if flag_match:
                 findings.append(f"Plaintext Flag: {flag_match.group(0).decode('utf-8', 'ignore')}")

            if findings:
                print(f"      [!] Stego in {img_url}: {findings}")
                stego_findings.append({"url": img_url, "issues": findings})
        except: pass

    kb.update("stego_findings", stego_findings)
