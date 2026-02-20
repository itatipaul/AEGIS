import requests
import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

PRIORITY = 10
TYPE = "Recon"
DESCRIPTION = "Multi-Source Subdomain Enumeration (Turbo)"

def run(kb):
    print(f"\n[*] Running {DESCRIPTION}...")
    
    target = kb.get("target_domain")
    if not target: return

    config = kb.get("config", {})
    api_keys = config.get("settings", {}).get("api_keys", {})

    found_subdomains = set()
    
    # Sources Configuration
    sources = [
        {
            "name": "HackerTarget",
            "url": f"https://api.hackertarget.com/hostsearch/?q={target}",
            "parser": lambda data: [line.split(',')[0] for line in data.split('\n') if ',' in line]
        },
        {
            "name": "crt.sh",
            "url": f"https://crt.sh/?q=%.{target}&output=json",
            "parser": lambda data: [entry['name_value'] for entry in json.loads(data) if 'name_value' in entry]
        },
        {
            "name": "VirusTotal",
            "url": f"https://www.virustotal.com/ui/domains/{target}/subdomains?limit=100",
            "parser": lambda data: [item['id'] for item in json.loads(data).get('data', [])]
        },
        {
            "name": "AlienVault",
            "url": f"https://otx.alienvault.com/api/v1/indicators/domain/{target}/passive_dns",
            "parser": lambda data: [entry['hostname'] for entry in json.loads(data).get('passive_dns', [])]
        },
        {
            "name": "SecurityTrails",
            "url": f"https://api.securitytrails.com/v1/domain/{target}/subdomains",
            "headers": {"APIKEY": api_keys.get("securitytrails")},
            "parser": lambda data: [f"{sub}.{target}" for sub in json.loads(data).get('subdomains', [])],
            "requires_key": "securitytrails"
        }
    ]
    
    # [OPTIMIZATION] Increased workers from 5 to 20 for faster HTTP queries
    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_source = {}
        for source in sources:
            if source.get("requires_key") and not api_keys.get(source["requires_key"]):
                print(f"    [-] Skipping {source['name']} (Missing Key)")
                continue
                
            future = executor.submit(query_source, source)
            future_to_source[future] = source["name"]
        
        for future in as_completed(future_to_source):
            source_name = future_to_source[future]
            try:
                subs = future.result(timeout=20)
                if subs:
                    # Clean immediately to avoid memory bloat
                    clean_batch = set()
                    for s in subs:
                        s = s.replace('*.', '').strip().lower()
                        if s.endswith(f".{target}"):
                            clean_batch.add(s)
                    
                    if clean_batch:
                        count = len(clean_batch)
                        # Add to master list
                        found_subdomains.update(clean_batch)
                        print(f"    ┃   ├ {source_name}: Found {count} new subdomains")
            except Exception:
                pass

    # Final Sort & Save
    sorted_subs = sorted(list(found_subdomains))
    
    if sorted_subs:
        print(f"    ╠ Total Unique Subdomains: {len(sorted_subs)}")
        # Merge with existing scope if any
        current_scope = kb.get("scope_domains") or []
        # Ensure target itself is in the list
        if target not in sorted_subs: sorted_subs.insert(0, target)
        
        # Combine and Dedupe
        final_scope = list(set(current_scope + sorted_subs))
        kb.update("scope_domains", final_scope)
    else:
        print(f"    ╚ No subdomains found. Scope set to main target.")
        kb.update("scope_domains", [target])

def query_source(source):
    try:
        headers = source.get("headers", {
            "User-Agent": "Mozilla/5.0 (compatible; AegisBot/1.0)"
        })
        response = requests.get(source["url"], headers=headers, timeout=15)
        if response.status_code == 200:
            return source["parser"](response.text)
    except:
        pass
    return []
