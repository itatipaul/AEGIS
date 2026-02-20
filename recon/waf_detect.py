import aiohttp
import asyncio
import re
import random

PRIORITY = 11
TYPE = "Security"
DESCRIPTION = "Async WAF detection with fingerprinting and bypass testing"

# Comprehensive WAF fingerprints
WAF_SIGNATURES = {
    "Cloudflare": {
        "headers": ["cf-ray", "cloudflare", "__cfduid", "__cf_bm"],
        "cookies": ["__cfduid", "__cf_bm"],
        "patterns": [r"cloudflare", r"attention required"]
    },
    "AWS WAF": {
        "headers": ["x-amzn-requestid", "x-amz-apigw-id", "x-amz-cf-id"],
        "patterns": [r"Request blocked", r"AWS"]
    },
    "Akamai": {
        "headers": ["x-akamai-transformed", "x-akamai-request-id"],
        "patterns": [r"akamai"]
    },
    "Imperva Incapsula": {
        "headers": ["x-iinfo", "incap_ses", "visid_incap"],
        "patterns": [r"incapsula"]
    },
    "F5 BIG-IP": {
        "headers": ["bigip", "x-wa-info"],
        "patterns": [r"bigip", r"f5"]
    }
}

TEST_PAYLOADS = [
    ("SQL Injection", "' OR '1'='1' --"),
    ("XSS", "<script>alert('XSS')</script>"),
    ("Path Traversal", "../../../etc/passwd"),
    ("Command Injection", "; ls -la"),
    ("SSI Injection", "")
]

async def detect_passive(session, url):
    """Passive detection via headers and response patterns"""
    detected = []
    try:
        async with session.get(url, timeout=10) as response:
            headers = {k.lower(): v.lower() for k, v in response.headers.items()}
            text = await response.text()
            cookies = response.cookies

            for waf, sigs in WAF_SIGNATURES.items():
                if any(h in headers for h in sigs.get("headers", [])):
                    detected.append((waf, "Header Match"))
                if any(re.search(p, text, re.IGNORECASE) for p in sigs.get("patterns", [])):
                    detected.append((waf, "Body Pattern"))
    except:
        pass
    return list(set(detected))

async def test_active(session, url, payload_info):
    """Active payload testing"""
    name, payload = payload_info
    target = f"{url}/?test={payload}"
    try:
        async with session.get(target, timeout=5) as response:
            if response.status in [403, 406, 429, 500]:
                return (name, response.status)
            
            # Check for generic block pages
            text = await response.text()
            if any(x in text.lower() for x in ["blocked", "forbidden", "access denied", "security policy"]):
                return (name, "BLOCK_PAGE")
    except:
        pass
    return None

async def run_async(kb):
    target = kb.get("target_domain")
    if not target: return

    print(f"[*] Running {DESCRIPTION} on {target}...")
    
    # Setup
    urls = [f"http://{target}", f"https://{target}"]
    detected_wafs = {}
    
    # 1. Passive Scan (Fast)
    async with aiohttp.ClientSession() as session:
        tasks = [detect_passive(session, u) for u in urls]
        results = await asyncio.gather(*tasks)
        
        for res in results:
            for waf, reason in res:
                if waf not in detected_wafs: detected_wafs[waf] = []
                detected_wafs[waf].append(reason)

        # 2. Active Scan (Only if nothing found passively)
        if not detected_wafs:
            print("    > No WAF signature found. Attempting active provocation...")
            active_tasks = []
            for url in urls:
                for payload in TEST_PAYLOADS:
                    active_tasks.append(test_active(session, url, payload))
            
            # Run probing in parallel
            probe_results = await asyncio.gather(*active_tasks)
            
            blocks = [r for r in probe_results if r]
            if blocks:
                detected_wafs["Generic WAF"] = [f"Blocked {name} ({code})" for name, code in blocks]

    # Reporting
    if detected_wafs:
        kb.update("waf_status", {"detected": True, "wafs": detected_wafs, "protection_level": "HIGH"})
        print(f"    [+] WAF DETECTED: {list(detected_wafs.keys())}")
        for waf, reasons in detected_wafs.items():
            print(f"        - {waf}: {reasons[0]}")
    else:
        kb.update("waf_status", {"detected": False, "protection_level": "LOW"})
        print("    [-] No WAF detected.")

def run(kb):
    asyncio.run(run_async(kb))
