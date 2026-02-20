import base64
import re
import binascii

PRIORITY = 42
TYPE = "CTF"
DESCRIPTION = "Attempts to decode suspicious strings (Base64, Hex)"

def try_base64(s):
    try:
        # Check if it looks like B64 (length multiple of 4, valid chars)
        if len(s) % 4 == 0 and re.match('^[A-Za-z0-9+/]+={0,2}$', s):
            decoded = base64.b64decode(s).decode('utf-8')
            # Check if result is readable text
            if decoded.isprintable() and len(decoded) > 3:
                return decoded
    except:
        pass
    return None

def try_hex(s):
    try:
        # Check if it is hex
        if re.match('^[0-9a-fA-F]+$', s) and len(s) % 2 == 0:
            decoded = bytes.fromhex(s).decode('utf-8')
            if decoded.isprintable() and len(decoded) > 3:
                return decoded
    except:
        pass
    return None

def run(kb):
    print(f"[*] Running {DESCRIPTION}...")
    
    # Look at comments and sensitive data found by other plugins
    findings = kb.get("ctf_findings", [])
    sensitive = kb.get("advanced_crawl", {}).get("interesting_findings", {}).get("sensitive_data", [])
    
    candidates = []
    
    # Extract candidate strings
    for f in findings:
        if f['type'] == "Hidden Comment":
            candidates.append(f['content'])
            
    for s in sensitive:
        candidates.append(s['value'])

    decoded_secrets = []

    for text in candidates:
        # Extract words that look like Base64 or Hex
        words = text.split()
        for word in words:
            # Clean it
            word = word.strip('",\'')
            if len(word) < 4: continue

            # Attempt Base64
            b64_res = try_base64(word)
            if b64_res:
                print(f"      [+] Decoded Base64: '{word}' -> '{b64_res}'")
                decoded_secrets.append({"original": word, "decoded": b64_res, "type": "Base64"})

            # Attempt Hex
            hex_res = try_hex(word)
            if hex_res:
                print(f"      [+] Decoded Hex: '{word}' -> '{hex_res}'")
                decoded_secrets.append({"original": word, "decoded": hex_res, "type": "Hex"})

    if decoded_secrets:
        kb.update("decoded_secrets", decoded_secrets)
