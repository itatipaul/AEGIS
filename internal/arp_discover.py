from scapy.all import ARP, Ether, srp, conf
import socket

# Suppress Scapy verbosity
conf.verb = 0

PRIORITY = 6
TYPE = "Internal Recon"
DESCRIPTION = "Layer 2 ARP Scanner (Finds local devices)"

def get_local_ip_and_cidr():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        # Guess /24 subnet
        return ".".join(local_ip.split('.')[:3]) + ".0/24"
    except:
        return None

def run(kb):
    # Only run if mode is 'network' or 'all'
    config = kb.get("config", {})
    if config.get("mode") not in ["network", "all"]:
        return

    target = kb.get("target_domain")
    
    # Check if target is a network range
    if "/" not in target:
        # If target is a single IP, we might want to scan its whole subnet
        # But for safety, we only auto-scan local subnet if target is missing
        return

    print(f"[*] Running {DESCRIPTION} on {target}...")
    
    try:
        # Broadcast ARP Request
        arp = ARP(pdst=target)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp

        result = srp(packet, timeout=2, verbose=0)[0]
        
        clients = []
        for sent, received in result:
            clients.append({'ip': received.psrc, 'mac': received.hwsrc})

        if clients:
            print(f"    [+] Found {len(clients)} live hosts via ARP:")
            for c in clients:
                print(f"        - {c['ip']} ({c['mac']})")
            
            # Save to KB
            kb.update("network_assets", clients)
            
            # Add IPs to scope for Port Scanning
            current_scope = kb.get("scope_domains") or []
            new_ips = [c['ip'] for c in clients]
            kb.update("scope_domains", list(set(current_scope + new_ips)))
            
    except Exception as e:
        print(f"    [!] ARP Scan failed (Requires Root): {e}")
