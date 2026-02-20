import requests
import asyncio
from concurrent.futures import ThreadPoolExecutor

PRIORITY = 12
TYPE = "Recon"
DESCRIPTION = "Fuzzes Host headers to find hidden Virtual Hosts"

# VHost specific wordlist
VHOSTS = [
    "dev", "staging", "test", "prod", "beta", "admin", "internal",
    "corp", "jira", "wiki", "git", "api", "backend", "frontend",
    "uat", "sftp", "vpn", "mail", "webmail", "db", "sql"
]

def check_vhost(ip, domain, sub, baseline_len, baseline_status):
    vhost = f"{sub}.{domain}"
    try:
        # Request IP but with a custom Host header
        # We assume HTTP for speed, but HTTPS logic can be added
        r = requests.get(f"http://{ip}", headers={"Host": vhost}, timeout=3, verify=False, allow_redirects=False)
        
        # Filtering Logic:
        # If status code is different OR content length matches neither baseline nor error page
        if r.status_code != baseline_status or abs(len(r.text) - baseline_len) > 500:
            # Filter out 403s if baseline was 403 (unless size is wildly different)
            if r.status_code == 403 and baseline_status == 403 and abs(len(r.text) - baseline_len) < 50:
                return None
                
            return {
                "vhost": vhost, 
                "ip": ip, 
                "status": r.status_code, 
                "length": len(r.text)
            }
    except:
        pass
    return None

def run(kb):
    print(f"[*] Running {DESCRIPTION}...")
    
    target_domain = kb.get("target_domain")
    if not target_domain: return

    # Get IPs found during port scan or resolution
    # (Assuming we have a list of IPs in 'network_assets' or we resolve target)
    ips = kb.get("network_assets", [])
    if not ips:
        try:
            import socket
            ips = [socket.gethostbyname(target_domain)]
        except:
            return

    found_vhosts = []

    for ip in ips:
        print(f"    > Fuzzing VHosts on IP: {ip}")
        
        # 1. Establish Baseline (Request with random/IP host)
        try:
            baseline = requests.get(f"http://{ip}", headers={"Host": f"random-garbage.{target_domain}"}, timeout=5)
            base_len = len(baseline.text)
            base_status = baseline.status_code
        except:
            print(f"      [-] Could not connect to {ip}")
            continue

        print(f"      [i] Baseline: Status {base_status}, Len {base_len}")

        # 2. Fuzz
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(check_vhost, ip, target_domain, word, base_len, base_status) for word in VHOSTS]
            
            for future in futures:
                res = future.result()
                if res:
                    print(f"      [+] FOUND VHOST: {res['vhost']} (Status: {res['status']}, Size: {res['length']})")
                    found_vhosts.append(res['vhost'])

    if found_vhosts:
        # Add to scope so other plugins scan them!
        current_scope = kb.get("scope_domains") or []
        kb.update("scope_domains", list(set(current_scope + found_vhosts)))
        kb.update("vhosts_found", found_vhosts)
