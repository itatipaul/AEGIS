import asyncio
import aiohttp
import re
import random
import os

PRIORITY = 5
TYPE = "Infrastructure"
DESCRIPTION = "Async Proxy Harvester (High-Speed & Low-Latency)"

# Configuration
DEFAULT_SOURCES = [
    "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt",
    "https://raw.githubusercontent.com/shiftytr/proxy-list/master/proxy.txt",
    "https://raw.githubusercontent.com/proxy4parsing/proxy-list/main/http.txt"
]

# Rotation targets to avoid rate-limiting specific validation services
VALIDATION_TARGETS = [
    "http://httpbin.org/ip",
    "http://ifconfig.me/ip",
    "http://api.ipify.org",
    "http://icanhazip.com",
    "http://checkip.amazonaws.com"
]

async def fetch_source(session, url):
    """Downloads a raw proxy list asynchronously."""
    try:
        async with session.get(url, timeout=5) as response:
            if response.status == 200:
                return await response.text()
    except:
        pass
    return ""

async def check_proxy(proxy, semaphore, valid_proxies):
    """Validates a single proxy with a strict timeout."""
    target = random.choice(VALIDATION_TARGETS)
    
    async with semaphore:
        try:
            # Short timeout (2s) to ensure we only keep FAST proxies
            timeout = aiohttp.ClientTimeout(total=2)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(target, proxy=proxy, allow_redirects=False) as response:
                    if response.status == 200:
                        valid_proxies.append(proxy)
                        print(f"      [+] Alive: {proxy} (Latency: Low)", end="\r")
        except:
            pass

async def run_async(kb):
    print(f"[*] Running {DESCRIPTION}...")
    
    sources = kb.get("config", {}).get("proxy_sources", DEFAULT_SOURCES)
    raw_proxies = set()

    # 1. Harvest Sources Asynchronously
    print(f"    [>] Harvesting from {len(sources)} sources...")
    
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_source(session, url) for url in sources]
        results = await asyncio.gather(*tasks)
        
        for content in results:
            # Regex to find IP:PORT patterns
            matches = re.findall(r'[0-9]+(?:\.[0-9]+){3}:[0-9]+', content)
            for m in matches:
                raw_proxies.add(f"http://{m}")

    total_found = len(raw_proxies)
    print(f"    [>] Harvested {total_found} potential proxies. Validating asynchronously...")

    # 2. High-Speed Validation
    # We use a Semaphore to limit concurrency to 500 simultaneous checks
    # This is much faster than the previous 50 threads.
    semaphore = asyncio.Semaphore(500)
    valid_proxies = []
    
    tasks = [check_proxy(p, semaphore, valid_proxies) for p in raw_proxies]
    await asyncio.gather(*tasks)

    print(f"\n    [+] Validation Complete. {len(valid_proxies)} high-speed proxies active.")

    # 3. Save to Swarm File
    if valid_proxies:
        with open("proxies.txt", "w") as f:
            for p in valid_proxies:
                f.write(f"{p}\n")
        
        print(f"    [+] Updated 'proxies.txt' and injected into Swarm.")
        kb.update("swarm_proxies", valid_proxies)
    else:
        print("    [-] No valid proxies found. Your network might be blocking raw connections.")

def run(kb):
    asyncio.run(run_async(kb))
