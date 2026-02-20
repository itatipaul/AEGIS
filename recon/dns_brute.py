import asyncio
import socket
import aiohttp

PRIORITY = 10
TYPE = "Heavy Recon"
DESCRIPTION = "High-speed Async DNS Brute Forcer (Wordlist based)"

# Small built-in list for demo; in production load from file
DEFAULT_WORDLIST = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "m", "shop", "ftp", "mail2", "test", "portal",
    "ns", "ww1", "host", "support", "dev", "web", "bbs", "ww42", "mx",
    "email", "cloud", "1", "mail1", "2", "forum", "owa", "www2", "gw",
    "admin", "store", "mx1", "cdn", "api", "exchange", "app", "gov",
    "2020", "gov", "private", "backend", "db", "staging", "prod", "dev-api"
]

async def resolve_domain(domain, resolver_ip="8.8.8.8"):
    # We use the system's default resolver via asyncio's loop
    loop = asyncio.get_running_loop()
    try:
        # This is non-blocking
        await loop.getaddrinfo(domain, None)
        return domain
    except socket.gaierror:
        return None
    except Exception:
        return None

async def run_async(kb):
    target = kb.get("target_domain")
    if not target: return

    print(f"[*] Running {DESCRIPTION}...")
    
    # Load wordlist from config or use default
    config = kb.get("config", {})
    # In a real heavy recon scenario, load a 10k line file here
    wordlist = DEFAULT_WORDLIST 
    
    print(f"    > Brute forcing {len(wordlist)} subdomains asynchronously...")
    
    tasks = []
    for word in wordlist:
        subdomain = f"{word}.{target}"
        tasks.append(resolve_domain(subdomain))
    
    # Execute all DNS queries concurrently
    results = await asyncio.gather(*tasks)
    
    # Filter valid domains (remove None)
    valid_subdomains = [r for r in results if r is not None]
    
    if valid_subdomains:
        print(f"    [+] Brute force successful: {len(valid_subdomains)} alive subdomains found.")
        
        # Update KnowledgeBase
        current_scope = kb.get("scope_domains") or []
        updated_scope = list(set(current_scope + valid_subdomains))
        kb.update("scope_domains", updated_scope)
        
        for sub in valid_subdomains[:3]:
             print(f"      - {sub}")
    else:
        print("    [-] No new subdomains found via brute force.")

def run(kb):
    asyncio.run(run_async(kb))
