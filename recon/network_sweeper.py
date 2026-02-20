import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor

PRIORITY = 5
TYPE = "Recon"
DESCRIPTION = "CIDR Network Sweeper (TCP Ping)"

def check_host(ip):
    # Check common ports to see if host is alive
    for port in [80, 443, 22, 445, 135]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((str(ip), port))
            sock.close()
            if result == 0:
                return str(ip)
        except: pass
    return None

def run(kb):
    target = kb.get("target_domain")
    if not target or "/" not in target:
        return

    try:
        network = ipaddress.ip_network(target, strict=False)
    except:
        return

    print(f"[*] Running {DESCRIPTION} on {target} ({network.num_addresses} hosts)...")
    
    live_hosts = []
    
    # 50 Threads for speed
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(check_host, ip): ip for ip in network}
        
        for future in futures:
            ip = future.result()
            if ip:
                print(f"    [+] Host Up: {ip}")
                live_hosts.append(ip)

    if live_hosts:
        print(f"    [=] Sweeper found {len(live_hosts)} live hosts.")
        
        # Update Scope
        current = kb.get("scope_domains") or []
        kb.update("scope_domains", list(set(current + live_hosts)))
