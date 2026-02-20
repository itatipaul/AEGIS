import socket
import requests
import dns.resolver

PRIORITY = 12
TYPE = "Recon"
DESCRIPTION = "Attempts to find origin IP to bypass Cloudflare/WAF"

def run(kb):
    target = kb.get("target_domain")
    if not target: return
    
    # Check if WAF was detected
    waf_data = kb.get("waf_status", {})
    if not waf_data.get("detected"):
        return

    print(f"[*] Running {DESCRIPTION} on {target}...")
    
    potential_ips = set()
    
    # 1. Check History via ViewDNS (Unauthenticated)
    try:
        r = requests.get(f"https://viewdns.info/iphistory/?domain={target}", 
                        headers={"User-Agent": "Mozilla/5.0"}, timeout=10)
        # Regex to find IPs in HTML
        import re
        ips = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', r.text)
        # Filter out obvious bad IPs (Cloudflare ranges)
        for ip in ips:
            if not ip.startswith("104.") and not ip.startswith("172."):
                potential_ips.add(ip)
    except:
        pass

    # 2. Check MX Records (Often expose real IP)
    try:
        mx_records = dns.resolver.resolve(target, 'MX')
        for mx in mx_records:
            mx_host = str(mx.exchange).rstrip('.')
            mx_ip = socket.gethostbyname(mx_host)
            potential_ips.add(mx_ip)
            print(f"    [+] MX Record Found: {mx_host} ({mx_ip})")
    except:
        pass

    # 3. Validation: Check if IP responds to Host header
    real_origins = []
    for ip in potential_ips:
        try:
            # Try to request the target domain on this specific IP
            # bypassing DNS
            r = requests.get(f"http://{ip}", headers={"Host": target}, timeout=3, verify=False)
            
            # If we get a 200 OK or the title matches, we found the origin
            if r.status_code < 400 or target in r.text:
                print(f"    [!!!] POTENTIAL ORIGIN FOUND: {ip}")
                real_origins.append(ip)
        except:
            pass

    if real_origins:
        kb.update("origin_ips", real_origins)
