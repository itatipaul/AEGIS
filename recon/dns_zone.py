import dns.resolver
import dns.query
import dns.zone
import dns.exception
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

PRIORITY = 9 
TYPE = "Recon"
DESCRIPTION = "Attempts DNS Zone Transfer (AXFR) with enhanced detection"

def check_nameserver(target, ns):
    """Check a single nameserver for zone transfer vulnerability"""
    try:
        ns_clean = ns.rstrip('.')
        
        # Try multiple IP resolution methods
        try:
            ns_ip = dns.resolver.resolve(ns_clean, 'A')[0].to_text()
        except:
            try:
                ns_ip = dns.resolver.resolve(ns_clean, 'AAAA')[0].to_text()
            except:
                return None
        
        print(f"    ┣ Testing: {ns_clean} ({ns_ip})")
        
        # Attempt Zone Transfer with multiple query types
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, target, timeout=3))
            if zone:
                hosts = [f"{n}.{target}" for n in zone.nodes.keys() if n != "@"]
                return {"server": ns_clean, "ip": ns_ip, "hosts": hosts, "count": len(hosts)}
        except dns.exception.FormError:
            # Try with TCP fallback
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, target, timeout=3, use_tcp=True))
                if zone:
                    hosts = [f"{n}.{target}" for n in zone.nodes.keys() if n != "@"]
                    return {"server": ns_clean, "ip": ns_ip, "hosts": hosts, "count": len(hosts)}
            except:
                pass
    except Exception as e:
        pass
    return None

def run(kb):
    print(f"\n[*] Running {DESCRIPTION}...")
    
    target = kb.get("target_domain")
    if not target:
        print("    ╚ No target domain specified")
        return

    print(f"    ╠ Target: {target}")
    
    try:
        # Find all name servers
        print("    ╠ Resolving name servers...")
        ns_records = dns.resolver.resolve(target, 'NS')
        nameservers = [str(r) for r in ns_records]
        
        if not nameservers:
            print("    ╚ No name servers found")
            return
            
        print(f"    ╠ Found {len(nameservers)} name servers")
        
        # Parallel testing of all name servers
        vulnerable_servers = []
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_ns = {executor.submit(check_nameserver, target, ns): ns for ns in nameservers}
            
            for future in as_completed(future_to_ns):
                ns = future_to_ns[future]
                try:
                    result = future.result(timeout=10)
                    if result:
                        print(f"    ┃   └ [CRITICAL] Zone transfer VULNERABLE on {result['server']}")
                        print(f"    ┃       ├ Hosts exposed: {result['count']}")
                        print(f"    ┃       └ Sample: {', '.join(result['hosts'][:3])}...")
                        vulnerable_servers.append(result)
                except Exception:
                    pass
        
        # Process results
        if vulnerable_servers:
            all_hosts = []
            for vs in vulnerable_servers:
                all_hosts.extend(vs["hosts"])
            
            # Add to KnowledgeBase
            current_scope = kb.get("scope_domains") or []
            updated_scope = list(set(current_scope + all_hosts))
            kb.update("scope_domains", updated_scope)
            kb.update("zone_transfer", {
                "status": "VULNERABLE",
                "vulnerable_servers": vulnerable_servers,
                "total_hosts_exposed": len(all_hosts),
                "severity": "CRITICAL"
            })
            
            print(f"    ╔═══════════════════════════════════════════════")
            print(f"    ║ ZONE TRANSFER VULNERABILITY DETECTED")
            print(f"    ║ Total hosts exposed: {len(all_hosts)}")
            print(f"    ║ Added to scope for further enumeration")
            print(f"    ╚═══════════════════════════════════════════════")
        else:
            print(f"    ╚ Zone transfer not vulnerable (good security)")
            kb.update("zone_transfer", {"status": "SECURE", "severity": "LOW"})
            
    except dns.resolver.NoAnswer:
        print("    ╚ No DNS records found")
    except Exception as e:
        print(f"    ╚ DNS resolution failed: {str(e)[:50]}")
