import dns.resolver
from concurrent.futures import ThreadPoolExecutor

PRIORITY = 11 # Run after standard enum
TYPE = "Recon"
DESCRIPTION = "Generates and resolves subdomain permutations (Altdns style)"

PERMUTATIONS = [
    "dev", "staging", "test", "prod", "api", "admin", "corp", "vpn",
    "mail", "web", "internal", "sandbox", "beta", "v1", "v2", "secure"
]

def resolve(hostname):
    try:
        dns.resolver.resolve(hostname, 'A')
        return hostname
    except:
        return None

def run(kb):
    print(f"[*] Running {DESCRIPTION}...")
    
    domain = kb.get("target_domain")
    # Get subdomains found by previous plugins
    known_subs = kb.get("scope_domains", [])
    
    # Only keep subdomains that actually contain the target domain
    seeds = [s.replace(f".{domain}", "") for s in known_subs if domain in s and s != domain]
    
    potential_subs = set()
    
    for seed in seeds:
        for p in PERMUTATIONS:
            # Pattern 1: seed-permutation (api-dev.site.com)
            potential_subs.add(f"{seed}-{p}.{domain}")
            # Pattern 2: seedpermutation (apidev.site.com)
            potential_subs.add(f"{seed}{p}.{domain}")
            # Pattern 3: permutation-seed (dev-api.site.com)
            potential_subs.add(f"{p}-{seed}.{domain}")

    print(f"    > Generated {len(potential_subs)} permutations. Resolving...")
    
    confirmed = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(resolve, list(potential_subs))
        for r in results:
            if r:
                print(f"      [+] New Subdomain Found: {r}")
                confirmed.append(r)

    if confirmed:
        # Update scope
        current = kb.get("scope_domains")
        kb.update("scope_domains", list(set(current + confirmed)))
