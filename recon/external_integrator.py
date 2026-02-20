import shutil
import subprocess
import os

PRIORITY = 12
TYPE = "External Recon"
DESCRIPTION = "Wrapper for DNSRecon, SSLScan, and ODAT"

def run(kb):
    target = kb.get("target_domain")
    if not target: return
    
    out_dir = f"scans/{target}/recon"
    os.makedirs(out_dir, exist_ok=True)
    
    # 1. DNSRecon (Zone Transfers, SRV, etc.)
    if shutil.which("dnsrecon"):
        print(f"[*] Running DNSRecon on {target}...")
        run_tool(["dnsrecon", "-d", target, "-j", f"{out_dir}/dnsrecon.json"])

    # 2. SSLScan (Port 443)
    # We assume 443 is open for most web targets
    if shutil.which("sslscan"):
        print(f"[*] Running SSLScan on {target}...")
        run_tool(["sslscan", "--no-failed", target], f"{out_dir}/sslscan.txt")

    # 3. ODAT (Oracle Database Attacking Tool) - Port 1521
    ports = kb.get("open_ports", {}).get(target, [])
    p_list = [int(p['port']) for p in ports if isinstance(p, dict)]
    
    if 1521 in p_list and shutil.which("odat"):
        print(f"[*] Oracle DB Port found! Running ODAT...")
        run_tool(["odat", "sidguesser", "-s", target], f"{out_dir}/odat_sid.txt")

def run_tool(cmd, outfile=None):
    try:
        if outfile:
            if outfile.endswith(".json"):
                subprocess.run(cmd, timeout=300) # Tools that handle their own output file
            else:
                with open(outfile, "w") as f:
                    subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, timeout=300)
        else:
             subprocess.run(cmd, timeout=300)
    except: pass
