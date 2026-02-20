import requests
import socket

PRIORITY = 20
TYPE = "Infrastructure Recon"
DESCRIPTION = "Scans for exposed Docker, Kubernetes, and ETCD APIs"

TARGET_PORTS = {
    2375: "Docker API",
    2379: "etcd",
    6443: "Kubernetes API Server",
    10250: "Kubelet API",
    10255: "Kubelet Read-Only API"
}

def run(kb):
    target_domain = kb.get("target_domain")
    if not target_domain: return

    # Get IPs from KB or resolve
    ips = set()
    try:
        main_ip = socket.gethostbyname(target_domain)
        ips.add(main_ip)
    except: pass
    
    # Add IPs from subdomains if available
    # (Assuming subdomains have been resolved to IPs in knowledge base, if not, we stick to main)
    
    if not ips: return

    print(f"[*] Running Container Infrastructure Hunt on {len(ips)} hosts...")
    
    findings = []

    for ip in ips:
        for port, service in TARGET_PORTS.items():
            url = f"http://{ip}:{port}" if port != 6443 else f"https://{ip}:{port}"
            
            try:
                # Fast timeout check
                r = requests.get(url, timeout=3, verify=False)
                
                # Analyze Response
                is_vuln = False
                msg = ""
                
                # Docker Check
                if port == 2375 and "docker" in r.text.lower() and r.status_code == 200:
                    # Try listing containers
                    try:
                        r2 = requests.get(f"{url}/containers/json", timeout=3)
                        if r2.status_code == 200:
                            is_vuln = True
                            msg = "Exposed Docker API (Full Root Access Possible)"
                    except: pass

                # Kubernetes Check
                elif port in [6443, 10250] and ("kubernetes" in r.text.lower() or r.status_code == 403):
                    # 403 on K8s is still an "Exposure" (Active Service), 200 is a Critical Vuln
                    if r.status_code == 200:
                        is_vuln = True
                        msg = f"Unauthenticated {service} Access"
                    else:
                        print(f"    [i] Found {service} at {url} (Protected but exposed)")

                # Etcd Check
                elif port == 2379 and "etcd" in r.text.lower():
                     is_vuln = True
                     msg = "Exposed etcd keys (Kubernetes Secrets Risk)"

                if is_vuln:
                    print(f"      [!] CRITICAL: {msg} at {url}")
                    findings.append({
                        "id": "INFRA-EXPOSURE",
                        "msg": msg,
                        "url": url,
                        "service": service
                    })

            except:
                pass

    if findings:
        kb.update("nikto_vulns", findings)
