import shutil
import subprocess
import xml.etree.ElementTree as ET
import os
import re
import sys
try:
    from aegis.core.display import display
    from aegis.core.database import db
except ImportError:
    pass

PRIORITY = 10
TYPE = "Active Recon"
DESCRIPTION = "Adaptive Nmap Scanner (Network/Port/UDP/Script)"

def sanitize_path(path):
    return re.sub(r'[^a-zA-Z0-9_\-\.]', '_', path)

def run(kb):
    if not shutil.which("nmap"): return

    target = kb.get("target_domain")
    config = kb.get("config", {})
    mode = config.get("mode", "all")
    stealth = config.get("stealth", False)
    
    safe_target = sanitize_path(target)
    out_dir = f"scans/{safe_target}/nmap"
    os.makedirs(out_dir, exist_ok=True)
    
    display.log(f"Nmap engaging in [bold]{mode.upper()}[/bold] mode...", "INFO")

    # --- MODE SELECTION LOGIC ---
    scan_type = "-sS"
    ports = "--top-ports 1000" if stealth else "-p-"
    timing = "-T2" if stealth else "-T4"
    scripts = "--script=default"
    
    if mode == "network":
        cmd = ["nmap", "-sn", "-PE", target]
        run_nmap(cmd, "network_sweep", out_dir)
        return
    elif mode == "udp":
        scan_type = "-sU"
        ports = "--top-ports 100"
        timing = "-T4"
        scripts = ""
    elif mode == "script":
        p_list = get_kb_ports(kb, target)
        if p_list: ports = f"-p{','.join(p_list)}"
        else: ports = "--top-ports 100"
        scan_type = "-sV"
        scripts = "--script=vuln,default,safe"
    elif mode == "full":
        scan_type = "-sS"
        ports = "-p-"
        scripts = "--script=vulners,default"
    elif mode == "vulns":
        p_list = get_kb_ports(kb, target)
        if p_list: ports = f"-p{','.join(p_list)}"
        else: ports = "--top-ports 1000"
        scan_type = "-sV"
        scripts = "--script=vulners,vuln"

    final_cmd = [
        "nmap", scan_type, "-Pn", "-n",
        timing, ports, scripts,
        "-oX", f"{out_dir}/scan_{mode}.xml",
        target
    ]
    final_cmd = [x for x in final_cmd if x]
    
    display.log(f"Executing Nmap: {' '.join(final_cmd)}", "DEBUG")
    run_nmap(final_cmd, mode, out_dir, target)

def get_kb_ports(kb, target):
    ports = kb.get("open_ports", {}).get(target, [])
    return [str(p['port']) for p in ports if 'port' in p]

def run_nmap(cmd, mode, out_dir, target=""):
    try:
        # [FIX] Show output if verbose, otherwise show simple spinner
        # We assume standard run. If it hangs, the user sees nothing.
        # This forces a message.
        display.log(f"Nmap scan started. This may take time...", "WARNING")
        
        # If you want to see Nmap output live, remove capture_output=True
        # and use stdout=sys.stdout. But that breaks the progress bar layout.
        # Instead, we just wait.
        
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1800)
        
        parse_nmap_xml(f"{out_dir}/scan_{mode}.xml", target)
        display.log(f"Nmap {mode} scan finished.", "SUCCESS")
        
    except Exception as e:
        display.log(f"Nmap {mode} failed: {e}", "ERROR")

def parse_nmap_xml(xml_file, target):
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        count = 0
        for host in root.findall('host'):
            for port in host.findall('.//port'):
                if port.find('state').attrib['state'] == 'open':
                    port_id = port.attrib['portid']
                    service = port.find('service')
                    svc_name = service.attrib.get('name', 'unknown') if service is not None else 'unknown'
                    banner = service.attrib.get('product', '') if service is not None else ''
                    
                    db.add_port(target, port_id, svc_name, banner)
                    
                    for script in port.findall('script'):
                        if "vuln" in script.attrib['id']:
                            db.add_vuln(target, "HIGH", "Nmap Script", script.attrib['id'], script.attrib.get('output'))
                    count += 1
        if count > 0:
            display.log(f"Nmap found {count} open ports/services.", "SUCCESS")
    except: pass
