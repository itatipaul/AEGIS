import paramiko
import time
import json

PRIORITY = 70
TYPE = "Audit"
DESCRIPTION = "Connects via SSH to perform authenticated security auditing (Gray Box)"

# Audit Commands
CHECKS = {
    "Kernel Version": "uname -a",
    "OS Release": "cat /etc/*release",
    "Listening Ports (Internal)": "netstat -tuln",
    "Running Processes": "ps aux --sort=-%cpu | head -10",
    "SUID Binaries (Privesc Risk)": "find / -perm -u=s -type f 2>/dev/null",
    "World Writable Files": "find / -xdev -type d \\( -perm -0002 -a ! -perm -1000 \\) -print 2>/dev/null",
    "Root Login Enabled": "grep '^PermitRootLogin' /etc/ssh/sshd_config",
    "Sudoers Config": "cat /etc/sudoers 2>/dev/null | grep -v '#'",
    "Installed Packages": "dpkg -l | head -10"  # Debian/Ubuntu specific
}

def run(kb):
    print(f"[*] Running {DESCRIPTION}...")
    
    # Check for credentials in KB
    creds = kb.get("cracked_creds", [])
    if not creds:
        # Fallback to config if manually provided
        config = kb.get("config", {})
        ssh_user = config.get("ssh_user")
        ssh_pass = config.get("ssh_pass")
        ssh_key = config.get("ssh_key")
        
        if ssh_user and (ssh_pass or ssh_key):
            creds = [{"url": kb.get("target_domain"), "creds": f"{ssh_user}:{ssh_pass or 'KEY'}"}]
        else:
            print("    [-] No SSH credentials available for authenticated audit.")
            return

    # Get SSH Port from Open Ports
    target_ip = None
    ports = kb.get("open_ports", {})
    for host, p_list in ports.items():
        for p in p_list:
            if p['port'] == 22:
                target_ip = host
                break
        if target_ip: break
    
    if not target_ip:
        target_ip = kb.get("target_domain")

    print(f"    > Initiating Audit on {target_ip}...")

    for c in creds:
        try:
            user, password = c.get("creds", "").split(":", 1)
            
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            print(f"      > Connecting as {user}...")
            client.connect(target_ip, username=user, password=password, timeout=10)
            
            audit_results = {}
            
            for check_name, cmd in CHECKS.items():
                stdin, stdout, stderr = client.exec_command(cmd)
                output = stdout.read().decode().strip()
                if output:
                    audit_results[check_name] = output
                    # Simple heuristic for High Risk findings
                    if check_name == "Root Login Enabled" and "yes" in output:
                        print(f"      [CRITICAL] SSH Root Login is ENABLED!")
                    elif check_name == "World Writable Files" and len(output) > 0:
                        print(f"      [HIGH] Found {len(output.splitlines())} world-writable directories.")

            client.close()
            
            # Save results
            kb.update("host_audit_results", audit_results)
            print("    [+] Audit Complete. Results saved to KnowledgeBase.")
            
            # Save detailed report to loot
            with open(f"loot/audit_{target_ip}.json", "w") as f:
                json.dump(audit_results, f, indent=4)
                
            return # Stop after first successful login

        except Exception as e:
            print(f"      [-] Connection failed: {e}")
