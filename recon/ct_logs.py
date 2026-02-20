import aiohttp
import asyncio
import json
import random

PRIORITY = 3
TYPE = "Recon"
DESCRIPTION = "Extracts subdomains from Certificate Transparency Logs (crt.sh) [Keyless]"

async def fetch_crtsh(session, domain, proxy=None):
    # json output often fails on crt.sh, falling back to simple query if needed
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        # Pass the proxy specifically for this request
        async with session.get(url, timeout=30, proxy=proxy) as resp:
            if resp.status == 200:
                return await resp.json()
            else:
                print(f"    [-] crt.sh returned status {resp.status}")
    except Exception as e:
        # Suppress verbose errors unless debugging
        pass
    return []

def run(kb):
    asyncio.run(run_async(kb))

async def run_async(kb):
    target = kb.get("target_domain")
    if not target: return

    print(f"[*] Running {DESCRIPTION} on {target}...")
    
    # 1. Load Proxies from KB
    proxy_list = kb.get("swarm_proxies", [])
    # Filter for http proxies only (aiohttp doesn't support socks natively without extras)
    http_proxies = [p for p in proxy_list if p.startswith("http")]
    
    # Pick a random proxy if available
    active_proxy = random.choice(http_proxies) if http_proxies else None
    
    if active_proxy:
        print(f"    [i] Swarm Mode: Routing via {active_proxy}...")

    found_domains = set()
    
    async with aiohttp.ClientSession() as session:
        print(f"    > Querying Certificate Transparency logs...")
        data = await fetch_crtsh(session, target, proxy=active_proxy)
        
        if data:
            for entry in data:
                name_value = entry.get('name_value', '')
                subdomains = name_value.split('\n')
                for sub in subdomains:
                    sub = sub.replace('*.', '').strip()
                    if sub.endswith(target) and sub != target:
                        found_domains.add(sub)
        else:
            print("    [-] No data returned. Target might have no logs or crt.sh is timed out.")

    print(f"    [+] Found {len(found_domains)} unique subdomains from SSL logs.")
    
    if found_domains:
        current_scope = kb.get("scope_domains") or []
        new_scope = list(set(current_scope + list(found_domains)))
        kb.update("scope_domains", new_scope)
        
        for domain in list(found_domains)[:5]:
            print(f"      - {domain}")
        if len(found_domains) > 5:
            print(f"      ... and {len(found_domains)-5} more.")
