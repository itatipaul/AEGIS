import requests
import re

PRIORITY = 4
TYPE = "Heavy Recon"
DESCRIPTION = "Maps ASN and CIDRs to find all IP ranges owned by the org"

def run(kb):
    target = kb.get("target_domain")
    if not target: return

    print(f"[*] Running {DESCRIPTION} on {target}...")
    
    asn_number = None
    asn_name = "Unknown"

    # Step 1: Get ASN
    try:
        url = f"http://ip-api.com/json/{target}?fields=status,message,query,as,asname"
        r = requests.get(url, timeout=15)
        if r.status_code == 200:
            data = r.json()
            if data.get("status") == "success":
                asn_string = data.get("as", "")
                if asn_string:
                    asn_number = asn_string.split(" ")[0].replace("AS", "")
                    asn_name = data.get("asname", "Unknown")
                    print(f"    [+] Target belongs to: AS{asn_number} ({asn_name})")
    except Exception as e:
        print(f"    [-] ASN lookup error: {e}")

    if not asn_number:
        return

    # Step 2: Get CIDRs (With Failover)
    cidrs = []
    
    # Attempt 1: BGPView
    try:
        bgp_url = f"https://api.bgpview.io/asn/{asn_number}/prefixes"
        r_bgp = requests.get(bgp_url, timeout=20)
        if r_bgp.status_code == 200:
            bgp_data = r_bgp.json()
            prefixes = bgp_data.get("data", {}).get("ipv4_prefixes", [])
            cidrs = [p['prefix'] for p in prefixes]
    except Exception:
        # Attempt 2: RADB Failover (if BGPView DNS fails)
        try:
            print("    [!] BGPView failed, trying RADB...")
            radb_url = f"https://www.radb.net/query?keywords=AS{asn_number}"
            r_radb = requests.get(radb_url, timeout=20, verify=False)
            # Simple regex to extract routes
            found = re.findall(r'route:\s+([0-9\./]+)', r_radb.text)
            cidrs = list(set(found))
        except:
            pass

    if cidrs:
        print(f"    [+] Found {len(cidrs)} CIDR blocks owned by {asn_name}.")
        # Update Scope
        current_scope = kb.get("scope_domains") or []
        for c in cidrs:
            if c not in current_scope:
                current_scope.append(c)
        
        kb.update("scope_domains", current_scope)
        kb.update("asn_data", {"asn": asn_number, "name": asn_name, "cidrs": cidrs})
    else:
        print("    [-] Could not retrieve CIDR blocks from any source.")
