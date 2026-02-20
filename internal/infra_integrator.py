import shutil
import subprocess
import os

PRIORITY = 15
TYPE = "Internal Infra"
DESCRIPTION = "Wrapper for SMBMap, Enum4linux, SNMP, LDAP, and SMTP tools"

def run(kb):
    target = kb.get("target_domain")
    # Get open ports from Nmap/Async Scanner
    ports = kb.get("open_ports", {}).get(target, [])
    # Flatten ports to a simple list of integers
    port_list = []
    for p in ports:
        if isinstance(p, dict): port_list.append(int(p.get('port', 0)))
        else: port_list.append(int(p))

    out_dir = f"scans/{target}/infra"
    os.makedirs(out_dir, exist_ok=True)

    # 1. SMB Tools (Port 445/139)
    if 445 in port_list or 139 in port_list:
        if shutil.which("enum4linux"):
            print(f"[*] SMB Found. Running enum4linux...")
            run_tool(["enum4linux", "-a", target], f"{out_dir}/enum4linux.txt")
        
        if shutil.which("smbmap"):
            print(f"[*] SMB Found. Running SMBMap...")
            run_tool(["smbmap", "-H", target], f"{out_dir}/smbmap.txt")

    # 2. SNMP (Port 161/162)
    if 161 in port_list:
        if shutil.which("snmpwalk"):
            print(f"[*] SNMP Found. Running snmpwalk...")
            run_tool(["snmpwalk", "-c", "public", "-v1", target], f"{out_dir}/snmpwalk.txt")
        
        if shutil.which("snmp-check"):
            print(f"[*] SNMP Found. Running snmp-check...")
            run_tool(["snmp-check", target], f"{out_dir}/snmp_check.txt")

    # 3. SMTP User Enum (Port 25)
    if 25 in port_list:
        if shutil.which("smtp-user-enum"):
            print(f"[*] SMTP Found. Running smtp-user-enum...")
            # Requires a userlist, using a default one or just skipping if not configured
            # run_tool(["smtp-user-enum", "-M", "VRFY", "-U", "users.txt", "-t", target], f"{out_dir}/smtp_enum.txt")
            pass

    # 4. LDAP (Port 389/636)
    if 389 in port_list:
        if shutil.which("ldapsearch"):
            print(f"[*] LDAP Found. Running ldapsearch (Naming Contexts)...")
            run_tool(["ldapsearch", "-x", "-h", target, "-s", "base", "namingContexts"], f"{out_dir}/ldap_naming.txt")

def run_tool(cmd, outfile):
    try:
        with open(outfile, "w") as f:
            subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, timeout=300)
        print(f"    [+] Saved output to {outfile}")
    except:
        print(f"    [-] Failed to run {' '.join(cmd[:1])}")
