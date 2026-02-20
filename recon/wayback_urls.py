import aiohttp
import asyncio
import json
import re
from urllib.parse import urlparse

PRIORITY = 12
TYPE = "OSINT"
DESCRIPTION = "Async Archive Miner (Wayback & CommonCrawl)"

INTERESTING_EXT = r'\.(php|asp|aspx|jsp|json|xml|conf|config|bak|backup|sql|db|yaml|yml)$'
INTERESTING_KEY = r'(admin|login|api|dashboard|secret|token|password|upload)'

async def fetch_wayback(session, target):
    url = f"http://web.archive.org/cdx/search/cdx?url={target}/*&output=json&fl=original&collapse=urlkey&limit=3000"
    try:
        print("    > Querying Wayback Machine...")
        async with session.get(url, timeout=30) as resp:
            if resp.status == 200:
                data = await resp.json()
                if len(data) > 1:
                    return [row[0] for row in data[1:] if row[0]]
    except:
        pass
    return []

async def fetch_commoncrawl(session, target):
    # Simplified Common Crawl Index (latest)
    url = f"https://index.commoncrawl.org/CC-MAIN-2023-50-index?url={target}/*&output=json"
    try:
        print("    > Querying Common Crawl...")
        async with session.get(url, timeout=30) as resp:
            if resp.status == 200:
                text = await resp.text()
                urls = []
                for line in text.splitlines():
                    try:
                        entry = json.loads(line)
                        if 'url' in entry: urls.append(entry['url'])
                    except: pass
                return urls
    except:
        pass
    return []

async def run_async(kb):
    target = kb.get("target_domain")
    if not target: return

    print(f"[*] Running {DESCRIPTION}...")
    
    all_urls = set()
    
    async with aiohttp.ClientSession() as session:
        # Run both queries at the same time
        results = await asyncio.gather(
            fetch_wayback(session, target),
            fetch_commoncrawl(session, target)
        )
        
        for res in results:
            all_urls.update(res)

    if not all_urls:
        print("    [-] No historical data found.")
        return

    # Filtering
    interesting = []
    for url in all_urls:
        if re.search(INTERESTING_EXT, url, re.IGNORECASE) or re.search(INTERESTING_KEY, url, re.IGNORECASE):
            interesting.append(url)
    
    interesting = sorted(list(set(interesting)))
    
    if interesting:
        print(f"    [+] Found {len(interesting)} interesting historical URLs.")
        kb.update("historical_urls", interesting)
        
        # Display top 5
        for u in interesting[:5]:
            print(f"        - {u}")
    else:
        print(f"    [-] Found {len(all_urls)} URLs, but nothing looked sensitive.")

def run(kb):
    asyncio.run(run_async(kb))
