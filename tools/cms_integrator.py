import shutil
import subprocess
import os

PRIORITY = 20
TYPE = "CMS Analysis"
DESCRIPTION = "Wraps WPScan, JoomScan, and Droopescan"

def run(kb):
    target = kb.get("target_domain")
    if not target: return

    # Detect Tech from KnowledgeBase (populated by tech_detect.py or similar)
    tech_stack = kb.get("tech_stack", [])
    # Flatten tech stack for easy searching
    tech_names = []
    for t in tech_stack:
        if isinstance(t, dict): tech_names.append(t.get("NAME", "").lower())
        else: tech_names.append(str(t).lower())
    
    # 1. WPScan
    if "wordpress" in tech_names or os.path.exists(f"scans/{target}/wp-login.php"):
        if shutil.which("wpscan"):
            print(f"[*] CMS Detected: WordPress. Launching WPScan...")
            cmd = [
                "wpscan", "--url", target, 
                "--enumerate", "p,t,u", 
                "--format", "json",
                "--output", f"scans/{target}/wpscan.json"
            ]
            run_tool(cmd, "WPScan")
    
    # 2. JoomScan
    if "joomla" in tech_names:
        if shutil.which("joomscan"):
            print(f"[*] CMS Detected: Joomla. Launching JoomScan...")
            cmd = ["joomscan", "-u", target, "--ec"]
            run_tool(cmd, "JoomScan")

    # 3. DroopeScan (Drupal, Silverstripe)
    if "drupal" in tech_names or "silverstripe" in tech_names:
        if shutil.which("droopescan"):
            print(f"[*] CMS Detected: Drupal/Silverstripe. Launching Droopescan...")
            cmd = ["droopescan", "scan", "drupal", "-u", target]
            run_tool(cmd, "DroopeScan")

def run_tool(cmd, name):
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=600)
        print(f"    [+] {name} completed successfully.")
    except Exception as e:
        print(f"    [-] {name} failed: {e}")
