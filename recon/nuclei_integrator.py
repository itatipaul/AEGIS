import shutil
import subprocess
import json
import os
import tempfile
try:
    from aegis.core.display import display
    from aegis.core.database import db   # <--- Link to The Brain
except ImportError:
    pass

PRIORITY = 20
TYPE = "Vulnerability Scan"
DESCRIPTION = "Nuclei Engine (Stealth-Enabled & DB-Linked)"

def run(kb):
    if not shutil.which("nuclei"):
        display.log("'nuclei' binary not found. Install it to enable Tier-1 scanning.", "WARNING")
        return

    target = kb.get("target_domain")
    if not target: return

    display.log(f"Initializing Nuclei Engine against {target}...", "INFO")
    
    # 1. Configuration
    config = kb.get("config", {})
    stealth = config.get("stealth", False)
    
    # 2. Proxy Injection (The Stealth Layer)
    # We pass the framework's proxy list to Nuclei
    proxy_args = []
    if os.path.exists("proxies.txt") and os.path.getsize("proxies.txt") > 0:
        display.log("Injecting Swarm Proxies into Nuclei...", "INFO")
        proxy_args = ["-proxy-list", "proxies.txt", "-proxy-rotate"]
    
    # 3. Rate Limiting
    rate_limit = ["-rate-limit", "150", "-bulk-size", "25"]
    if stealth:
        display.log("Stealth Mode: Throttling Nuclei scan speed.", "WARNING")
        rate_limit = ["-rate-limit", "30", "-bulk-size", "5"]

    # 4. Prepare Output
    fd, temp_path = tempfile.mkstemp(suffix=".json")
    os.close(fd)

    # 5. Build Command
    # Tags: exposure, misconfig, cve, tech, token, vulnerability
    cmd = [
        "nuclei", 
        "-u", target, 
        "-tags", "exposure,misconfig,tech,token,cve", 
        "-severity", "low,medium,high,critical",
        "-json-export", temp_path,
        "-silent",
        "-no-color"
    ] + rate_limit + proxy_args
    
    try:
        # Run Nuclei (Timeout: 10 minutes)
        process = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=600)
    except Exception as e:
        display.log(f"Nuclei execution failed: {e}", "ERROR")
        return

    # 6. Process & Store Findings
    if os.path.exists(temp_path):
        count = 0
        try:
            with open(temp_path, 'r') as f:
                # Nuclei JSON export is a list of JSON objects (one per line) or a JSON array
                # The flag -json-export produces a JSON array in newer versions, 
                # but -json (stdout) produces line-delimited. 
                # We handle line-delimited here which is standard for large outputs.
                try:
                    data = json.load(f) # Try parsing as array
                    entries = data if isinstance(data, list) else [data]
                except json.JSONDecodeError:
                    f.seek(0)
                    entries = [json.loads(line) for line in f if line.strip()]

                for entry in entries:
                    info = entry.get('info', {})
                    name = info.get('name', 'Unknown Issue')
                    severity = info.get('severity', 'info').upper()
                    matched_at = entry.get('matched-at', '')
                    matcher_name = entry.get('matcher-name', '')
                    
                    # Store Technologies separately
                    if "tech" in info.get("tags", []):
                        db.add_tech(target, "Nuclei", name, "Detected", "Fingerprint")
                        continue

                    # Filter out useless info
                    if severity == "INFO":
                        continue

                    # SAVE TO BRAIN
                    db.add_vuln(
                        domain=target,
                        risk=severity,
                        vtype="Nuclei Finding",
                        issue=name,
                        evidence=f"{matched_at} ({matcher_name})",
                        tool="Nuclei"
                    )
                    count += 1
                    
            if count > 0:
                display.log(f"Nuclei identified {count} valid vulnerabilities.", "SUCCESS")
            else:
                display.log("Nuclei scan completed. No significant vulnerabilities found.", "INFO")

        except Exception as e:
            display.log(f"Error parsing Nuclei results: {e}", "ERROR")
        finally:
            os.remove(temp_path)
