import dns.resolver
import re
import ipaddress

PRIORITY = 15
TYPE = "Recon"
DESCRIPTION = "Checks SPF and DMARC records for Email Spoofing weakness"

def run(kb):
    domain = kb.get("target_domain")
    if not domain: return

    # [FIX] Logic Check: Is this an IP address?
    try:
        ipaddress.ip_address(domain)
        # If this succeeds, it IS an IP. We should skip email checks.
        return 
    except ValueError:
        pass # It is not an IP, so assume it is a domain and proceed.

    print(f"[*] Running {DESCRIPTION}...")
    print(f"    > Checking Email Security for: {domain}")
    
    findings = {
        "spf": "Missing",
        "dmarc": "Missing",
        "spoofable": False
    }

    # 1. Check SPF
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        spf_found = False
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if txt.startswith("v=spf1"):
                findings["spf"] = txt
                spf_found = True
                # Check for weak configuration
                if "+all" in txt or "?all" in txt:
                     print(f"      [HIGH] Weak SPF Record found: {txt}")
                     print(f"             (Allows softfail/pass for any IP)")
                else:
                     print(f"      [INFO] SPF Record found: {txt}")
                break
        
        if not spf_found:
             print(f"      [HIGH] No SPF Record found")

    except Exception:
        print(f"      [HIGH] No SPF Record found")

    # 2. Check DMARC
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        dmarc_found = False
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if txt.startswith("v=DMARC1"):
                findings["dmarc"] = txt
                dmarc_found = True
                # Check policy
                if "p=none" in txt:
                    print(f"      [HIGH] DMARC Policy is 'none': {txt}")
                elif "p=reject" in txt or "p=quarantine" in txt:
                    print(f"      [INFO] Strong DMARC Policy found: {txt}")
                break
        
        if not dmarc_found:
            print(f"      [HIGH] No DMARC Record found")

    except Exception:
        print(f"      [HIGH] No DMARC Record found")

    # 3. Verdict
    if findings["spf"] == "Missing" or "p=none" in findings.get("dmarc", "") or findings["dmarc"] == "Missing":
        findings["spoofable"] = True
        print(f"      [CRITICAL] Domain is vulnerable to EMAIL SPOOFING.")
    
    kb.update("email_security", findings)
