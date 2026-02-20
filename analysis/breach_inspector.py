import requests
import time

PRIORITY = 41
TYPE = "OSINT"
DESCRIPTION = "Checks emails against data breaches via XposedOrNot (Free) or HIBP"

def check_xposedornot(email):
    """
    Uses the free XposedOrNot API.
    Rate Limit: 1 request per second.
    """
    url = f"https://api.xposedornot.com/v1/check-email/{email}"
    try:
        # XposedOrNot is free and does not require a key for email checks
        r = requests.get(url, timeout=10)
        
        if r.status_code == 200:
            data = r.json()
            # If breaches are found, it returns a dict: {"Breaches": [["Name", ...], ...]}
            # or sometimes a list of names depending on the endpoint version.
            # The v1 endpoint usually returns: { "Breaches": [ [ "BreachName", ... ] ] }
            
            breaches = data.get("Breaches", [])
            if breaches:
                # Extract breach names (usually the first item in the list)
                breach_names = [b[0] for b in breaches]
                return breach_names
                
        elif r.status_code == 404:
            # 404 means "No Data Found" (Clean)
            return []
            
    except Exception as e:
        print(f"      [-] XposedOrNot Error: {e}")
    return []

def check_hibp(email, api_key):
    """
    Uses the paid HaveIBeenPwned API.
    """
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"
    headers = {
        "hibp-api-key": api_key,
        "user-agent": "Aegis-Framework"
    }
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            return [b['Name'] for b in r.json()]
        elif r.status_code == 401:
            print("      [-] HIBP API Key invalid/expired.")
    except:
        pass
    return None

def run(kb):
    emails = kb.get("found_emails", [])
    if not emails:
        return

    print(f"[*] Checking {len(emails)} emails against Breach Databases...")
    
    # Check for HIBP key (Optional)
    config = kb.get("config", {}).get("settings", {})
    hibp_key = config.get("hibp_api_key")
    
    provider = "XposedOrNot (Free)"
    if hibp_key:
        provider = "HaveIBeenPwned (Paid)"

    print(f"    > Using Provider: {provider}")
    
    breach_findings = []

    for email in emails:
        # Rate limit compliance (1.5s is safe for both)
        time.sleep(1.5)
        
        breaches = []
        if hibp_key:
            breaches = check_hibp(email, hibp_key)
            if breaches is None: # Fallback if key fails
                breaches = check_xposedornot(email)
        else:
            breaches = check_xposedornot(email)

        if breaches:
            print(f"      [!] LEAK CONFIRMED: {email} found in {len(breaches)} breaches!")
            print(f"          Sources: {', '.join(breaches[:5])}...")
            
            breach_findings.append({
                "email": email,
                "count": len(breaches),
                "sources": breaches
            })

    if breach_findings:
        kb.update("breach_data", breach_findings)
        
        # Inject into vulnerabilities for the report
        vulns = []
        for b in breach_findings:
            vulns.append({
                "id": "CREDENTIAL-LEAK",
                "msg": f"Email {b['email']} found in {b['count']} breaches",
                "url": "External Breach DB",
                "severity": "HIGH"
            })
        
        # Safely update existing vulns
        current_vulns = kb.get("nikto_vulns", [])
        kb.update("nikto_vulns", current_vulns + vulns)
