import shutil
import subprocess
import json
import requests
import time
import os

PRIORITY = 28
TYPE = "Vulnerability Scan"
DESCRIPTION = "Runs Nikto (if installed) or performs native common-vulnerability checks"

# Fallback signatures for Native Mode (Mini-Nikto)
NATIVE_SIGNATURES = [
    {"path": "/phpmyadmin/", "sig": "phpMyAdmin", "msg": "phpMyAdmin Interface found"},
    {"path": "/.env", "sig": "DB_PASSWORD", "msg": "Environment file (.env) exposed"},
    {"path": "/.git/HEAD", "sig": "ref: refs/", "msg": "Git repository exposed"},
    {"path": "/server-status", "sig": "Apache Status", "msg": "Apache Server Status exposed"},
    {"path": "/web.config", "sig": "<configuration>", "msg": "IIS Web Config exposed"},
    {"path": "/wp-config.php.bak", "sig": "<?php", "msg": "WordPress Config Backup found"},
    {"path": "/id_rsa", "sig": "PRIVATE KEY", "msg": "SSH Private Key exposed"},
    {"path": "/admin/login.php", "sig": "Login", "msg": "Admin Login Page found"},
    {"path": "/console", "sig": "Werkzeug", "msg": "Werkzeug Debug Console (RCE Risk)"},
    {"path": "/dashboard/", "sig": "Dashboard", "msg": "Kubernetes/Generic Dashboard found"},
    {"path": "/actuator/health", "sig": "status", "msg": "Spring Boot Actuator exposed"},
    {"path": "/trace.axd", "sig": "Trace", "msg": "ASP.NET Trace Viewer exposed"},
    {"path": "/.DS_Store", "sig": "Bud1", "msg": "macOS DS_Store file exposed"},
    {"path": "/info.php", "sig": "phpinfo", "msg": "PHP Info page exposed"},
    {"path": "/package.json", "sig": "dependencies", "msg": "Node.js package.json exposed"}
]

def run_native_scan(target, session, kb):
    """Fallback mode if Nikto is not installed"""
    print("    [!] Nikto binary not found in PATH.")
    print("    [*] Engaging Native Mode (Top 50 Common Checks)...")
    
    findings = []
    
    # Base URL construction
    protocol = "https" # Default to https, logic scanner might have found better
    base_url = f"{protocol}://{target}"
    
    # 1. Check Headers
    try:
        r = session.head(base_url, timeout=5, verify=False)
        headers = r.headers
        
        if 'X-AspNet-Version' in headers:
            findings.append({"id": "000001", "msg": f"ASP.NET Version Exposed: {headers['X-AspNet-Version']}"})
        if 'X-Powered-By' in headers:
            findings.append({"id": "000002", "msg": f"X-Powered-By Header: {headers['X-Powered-By']}"})
        if 'Server' in headers:
            findings.append({"id": "000003", "msg": f"Server Banner: {headers['Server']}"})
        if 'X-Frame-Options' not in headers:
            findings.append({"id": "000004", "msg": "Clickjacking protection (X-Frame-Options) missing"})
            
    except:
        pass

    # 2. Check Files
    for check in NATIVE_SIGNATURES:
        url = f"{base_url}{check['path']}"
        try:
            print(f"    > Checking: {check['path']}...", end="\r")
            r = session.get(url, timeout=3, verify=False, stream=True)
            
            # Read first 1kb to check signature
            content = r.raw.read(1024).decode('utf-8', errors='ignore')
            
            if r.status_code == 200 and check['sig'] in content:
                print(f"      [+] FOUND: {check['msg']}")
                findings.append({
                    "id": "999999",
                    "msg": f"{check['msg']} at {url}",
                    "url": url,
                    "method": "GET"
                })
        except:
            pass
            
    return findings

def run(kb):
    print(f"[*] Running {DESCRIPTION}...")
    
    target = kb.get("target_domain")
    if not target:
        return

    # Check for Nikto binary
    nikto_path = shutil.which("nikto")
    nikto_results = []
    
    # Get config for proxy/stealth
    config = kb.get("config", {})
    
    if nikto_path:
        print(f"    [+] Nikto found at: {nikto_path}")
        print("    > Launching Nikto (this may take a while)...")
        
        output_file = f"nikto_{target}.json"
        
        # Build Command
        cmd = [nikto_path, "-h", target, "-Format", "json", "-o", output_file]
        
        # Add Stealth / Tuning
        if config.get("stealth"):
            # T=x (Reverse Tuning options - skip some loud checks), -Pause for delay
            cmd.extend(["-Tuning", "x", "-Pause", "2"]) 
        else:
            # Default tuning (Interest, File Upload, Auth, XSS, SQLi)
            cmd.extend(["-Tuning", "123489"]) 
            
        # Add Proxy
        if config.get("proxy"):
            cmd.extend(["-useproxy", config.get("proxy")])
            
        try:
            # Run Nikto
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            
            # Parse Results
            if os.path.exists(output_file):
                try:
                    with open(output_file, 'r') as f:
                        data = json.load(f)
                        # Nikto JSON structure varies, usually in 'vulnerabilities'
                        if "vulnerabilities" in data:
                            for v in data["vulnerabilities"]:
                                nikto_results.append({
                                    "id": v.get("id"),
                                    "msg": v.get("msg"),
                                    "url": v.get("url"),
                                    "method": v.get("method")
                                })
                        # Cleanup
                        os.remove(output_file)
                except Exception as e:
                    print(f"    [!] Failed to parse Nikto JSON: {e}")
                    # Fallback to stdout parsing if JSON fails
                    print(f"    [i] Raw Output (truncated): {stdout.decode()[:500]}...")
            else:
                print("    [!] Nikto output file not found. Check permissions or installation.")
                
        except Exception as e:
            print(f"    [!] Error running Nikto: {e}")
            
    else:
        # Run Native Mode
        import requests
        session = requests.Session()
        
        # Configure session with stealth/proxy from KB
        session.headers = {"User-Agent": "Mozilla/5.0 (Aegis-Native-Scanner)"}
        if config.get("proxy"):
            session.proxies = {"http": config["proxy"], "https": config["proxy"]}
            session.verify = False
            
        nikto_results = run_native_scan(target, session, kb)

    if nikto_results:
        print(f"    [+] {len(nikto_results)} issues identified.")
        kb.update("nikto_vulns", nikto_results)
    else:
        print("    [-] No obvious vulnerabilities found by Nikto module.")
