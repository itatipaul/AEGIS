import requests
import re

PRIORITY = 40
TYPE = "Post-Discovery"
DESCRIPTION = "Validates discovered API keys against provider endpoints"

def validate_google_api(key):
    # Test against Google Maps Static API (Low risk, clear response)
    url = f"https://maps.googleapis.com/maps/api/staticmap?center=40.714728,-73.998672&zoom=12&size=400x400&key={key}"
    try:
        r = requests.get(url, timeout=5, verify=False)
        if r.status_code == 200:
            return "VALID (Maps API Access)"
        elif r.status_code == 403:
            return "INVALID / RESTRICTED"
    except: pass
    return "Unknown"

def validate_aws_key(key):
    # AWS keys usually require a secret to verify fully, but we can detect format validity
    if re.match("AKIA[0-9A-Z]{16}", key):
        return "Format Valid (AWS Access Key ID)"
    return "Unknown"

def validate_stripe_key(key):
    # Stripe keys usually start with sk_live_ or pk_live_
    if key.startswith("sk_live_"):
        try:
            r = requests.get('https://api.stripe.com/v1/charges', auth=(key, ''), timeout=5)
            if r.status_code == 200:
                return "VALID (Stripe Live Secret Key - CRITICAL)"
            elif r.status_code == 401:
                return "Invalid Stripe Key"
        except: pass
    elif key.startswith("pk_live_"):
        return "Stripe Live Publishable Key (Low Risk)"
    return "Unknown"

def run(kb):
    secrets = kb.get("leaked_secrets", [])
    if not secrets: return

    print(f"[*] Validating {len(secrets)} leaked secrets...")
    
    validated_secrets = []
    
    for secret in secrets:
        key_type = secret.get("type", "Unknown")
        key_data = secret.get("data", "")
        status = "Unverified"

        if "Google" in key_type or key_data.startswith("AIza"):
            status = validate_google_api(key_data)
        elif "AWS" in key_type or key_data.startswith("AKIA"):
            status = validate_aws_key(key_data)
        elif "Stripe" in key_type or "sk_live" in key_data:
            status = validate_stripe_key(key_data)
            
        if "VALID" in status:
            print(f"      [!] CONFIRMED: {key_type} key is active! ({status})")
            # Update the finding with validation status
            secret['validation'] = status
            validated_secrets.append(secret)
        else:
            # print(f"      [-] {key_type} key appears inactive.")
            pass

    # Update KB with validated info
    if validated_secrets:
        kb.update("validated_secrets", validated_secrets)
