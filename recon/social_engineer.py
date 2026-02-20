PRIORITY = 20
TYPE = "Recon"
DESCRIPTION = "Generates email permutations for Social Engineering targets"

def run(kb):
    print(f"[*] Running {DESCRIPTION}...")
    
    # Get raw emails found by other plugins
    emails = kb.get("emails_found", [])
    if not emails:
        return

    targets = set()
    domain = kb.get("target_domain", "")

    print(f"    > Analyzing {len(emails)} emails for patterns...")

    for email in emails:
        user, dom = email.split('@')
        if dom != domain: continue # Only target the main org
        
        # Heuristic: Try to extract First/Last name
        parts = user.replace('.', ' ').replace('_', ' ').split()
        
        if len(parts) == 2:
            first, last = parts[0], parts[1]
            # Generate common corporate permutations
            permutations = [
                f"{first}.{last}@{domain}",
                f"{first[0]}{last}@{domain}",
                f"{first}{last[0]}@{domain}",
                f"{first}@{domain}",
                f"{last}@{domain}",
                f"{first}_{last}@{domain}"
            ]
            for p in permutations:
                targets.add(p)

    print(f"    [+] Generated {len(targets)} high-probability phishing targets.")
    
    # Save to Loot
    with open(f"loot/phishing_targets_{domain}.txt", "w") as f:
        for t in sorted(targets):
            f.write(t + "\n")
            
    print(f"      > Saved list to loot/phishing_targets_{domain}.txt")
