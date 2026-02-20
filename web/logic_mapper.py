import aiohttp
import asyncio
from urllib.parse import urlparse

PRIORITY = 25
TYPE = "Tier-3 Logic"
DESCRIPTION = "Async Business Logic Mapper (Auth & Payment Flows)"

# Keywords that indicate critical business logic
LOGIC_SIGNATURES = {
    "Authentication": ["login", "signin", "signup", "register", "auth", "oauth", "sso", "verify", "forgot-password"],
    "Financial": ["buy", "checkout", "cart", "payment", "transaction", "wallet", "transfer", "billing"],
    "Administrative": ["admin", "dashboard", "panel", "settings", "config", "upload", "import", "export"],
    "User Data": ["profile", "account", "settings", "history", "messages", "inbox"]
}

async def analyze_url(session, url, logic_map):
    parsed = urlparse(url)
    path = parsed.path.lower()
    
    # 1. Signature Matching
    for category, keywords in LOGIC_SIGNATURES.items():
        if any(k in path for k in keywords):
            if category not in logic_map: logic_map[category] = set()
            logic_map[category].add(url)
            return

    # 2. Heuristic: Deep Parameter Analysis
    # If a URL has parameters like 'id', 'user', 'amount', 'role', it's suspicious
    if parsed.query:
        critical_params = ["id", "uid", "user", "admin", "role", "amount", "price", "transfer"]
        if any(p in parsed.query.lower() for p in critical_params):
            if "Critical Params" not in logic_map: logic_map["Critical Params"] = set()
            logic_map["Critical Params"].add(url)

async def run_async(kb):
    urls = kb.get("crawled_urls", [])
    if not urls: return

    print(f"[*] Running {DESCRIPTION} on {len(urls)} URLs...")
    
    logic_map = {}
    
    # Analyze all URLs quickly
    async with aiohttp.ClientSession() as session:
        # We don't actually need to fetch the URLs again, just parse the strings we found
        # But if we wanted to check if they are active, we could.
        # For mapping, string analysis is usually sufficient and instant.
        for url in urls:
            await analyze_url(session, url, logic_map)

    if logic_map:
        kb.update("logic_map", logic_map)
        print(f"    [+] Logic Flows Mapped:")
        for cat, endpoints in logic_map.items():
            print(f"        - {cat}: {len(endpoints)} endpoints")
            # Show example
            if endpoints:
                print(f"          e.g. {list(endpoints)[0]}")
    else:
        print("    [-] No specific business logic flows identified.")

def run(kb):
    asyncio.run(run_async(kb))
