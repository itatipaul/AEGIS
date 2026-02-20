import socket
import ipaddress
import time

PRIORITY = 0  # Runs absolutely first
TYPE = "System"
DESCRIPTION = "Target Profiler (Detects Local/External & Web/Infra)"

def run(kb):
    target = kb.get("target_domain")
    if not target: return

    print(f"[*] Running {DESCRIPTION}...")
    
    profile = {
        "is_ip": False,
        "is_private": False,
        "has_web": False,
        "context": "unknown"
    }

    # 1. Check if Target is IP or Domain
    try:
        ip_obj = ipaddress.ip_address(target)
        profile["is_ip"] = True
        profile["is_private"] = ip_obj.is_private
        resolved_ip = str(ip_obj)
    except ValueError:
        # It's a domain
        profile["is_ip"] = False
        try:
            resolved_ip = socket.gethostbyname(target)
            # Check if the resolved IP is private (e.g. internal domain)
            if ipaddress.ip_address(resolved_ip).is_private:
                profile["is_private"] = True
        except:
            resolved_ip = None

    # 2. Check for Web Ports (Quick Connect)
    # We do this fast to decide if we should run Web Plugins
    for port in [80, 443, 8080, 8443]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            if s.connect_ex((target, port)) == 0:
                profile["has_web"] = True
                s.close()
                break
            s.close()
        except: pass

    # 3. Determine Context
    if profile["is_private"]:
        profile["context"] = "INTERNAL"
        print(f"    > Target identified as [bold yellow]INTERNAL INFRASTRUCTURE[/bold yellow]")
    else:
        profile["context"] = "EXTERNAL"
        print(f"    > Target identified as [bold cyan]EXTERNAL / INTERNET[/bold cyan]")

    if profile["has_web"]:
        print(f"    > Web services detected (HTTP/HTTPS enabled).")
    else:
        print(f"    > No web services detected. Skipping web plugins.")

    # Save to Brain
    kb.update("target_profile", profile)
