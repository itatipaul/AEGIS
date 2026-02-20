import nmap
import time

PRIORITY = 10
TYPE = "Active Recon"
DESCRIPTION = "Smart Nmap Wrapper (Service & Version Detection)"

class AegisScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        
    def smart_scan(self, target):
        print(f"[*] Starting Aegis Blitz Scan + Banner Grabbing on: {target}")
        start_time = time.time()

        # Optimized Nmap arguments
        scan_args = (
            "-sS -sV -T4 "
            "--version-intensity 5 "
            "--top-ports 1000 "
            "--min-rate 500 "
            "--max-retries 1 "
            "--max-rtt-timeout 500ms "
            "--host-timeout 5m"
        )

        results = []
        try:
            self.nm.scan(hosts=target, arguments=scan_args)
            
            if target not in self.nm.all_hosts():
                return None

            host_data = self.nm[target]
            
            if 'tcp' in host_data:
                for port in host_data['tcp']:
                    port_data = host_data['tcp'][port]
                    
                    # Normalize Data Structure
                    results.append({
                        "port": port,
                        "status": port_data['state'],
                        "service": port_data['name'],
                        "banner": port_data.get('product', '') + " " + port_data.get('version', '')
                    })
            
            return results
            
        except Exception as e:
            print(f"[ERROR] Scan failed: {e}")
            return None

def run(kb):
    target = kb.get("target_domain")
    if not target: return

    scanner = AegisScanner()
    scan_results = scanner.smart_scan(target)
    
    if scan_results:
        # Standardize Output: Keyed by Domain, List of Dicts
        # This matches fast_scan.py and nmap_integrator.py formats
        kb.update("open_ports", {target: scan_results})
        print(f"    [+] Smart Scan saved {len(scan_results)} ports to KB.")
