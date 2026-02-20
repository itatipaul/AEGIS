PRIORITY = 90 # Run near the end
TYPE = "Workflow"
DESCRIPTION = "Suggests Next-Step Attacks (Pivot Engine)"

def run(kb):
    print(f"[*] Running {DESCRIPTION}...")
    
    suggestions = []
    
    # Check 1: Git Exposure
    if kb.get("git_exposures"):
        suggestions.append({
            "trigger": "Exposed .git repo",
            "cmd": "git-dumper http://TARGET/.git/ output_folder",
            "desc": "Download the entire source code history."
        })

    # Check 2: AWS Keys
    secrets = kb.get("leaked_secrets", [])
    if any(s.get("type") == "AWS Key" for s in secrets):
        suggestions.append({
            "trigger": "Leaked AWS Key",
            "cmd": "aws sts get-caller-identity --profile [profilename]",
            "desc": "Verify the key permissions and attempt cloud pivoting."
        })

    # Check 3: SMB
    target = kb.get("target_domain")
    ports = kb.get("open_ports", {}).get(target, [])
    p_list = [int(p['port']) for p in ports if isinstance(p, dict)]
    
    if 445 in p_list:
        suggestions.append({
            "trigger": "Open SMB (445)",
            "cmd": f"crackmapexec smb {target} --shares",
            "desc": "Check for null sessions or writable shares."
        })

    if suggestions:
        print("\n    ╔═══════════════════════════════════════════════")
        print("    ║ ⛓️  CHAIN REACTION OPPORTUNITIES DETECTED")
        print("    ║ These commands can verify or exploit findings:")
        for s in suggestions:
            print(f"    ║")
            print(f"    ║ [Trigger: {s['trigger']}]")
            print(f"    ║ $ {s['cmd']}")
            print(f"    ║ -> {s['desc']}")
        print("    ╚═══════════════════════════════════════════════\n")
