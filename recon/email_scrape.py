import requests
import re
from urllib.parse import urlparse

PRIORITY = 13
TYPE = "OSINT"
DESCRIPTION = "Harvests email addresses from web pages and related sources"

def run(kb):
    print(f"\n[*] Running {DESCRIPTION}...")
    
    target = kb.get("target_domain")
    if not target:
        print("    ╚ No target domain specified")
        return

    emails = set()
    
    # Get existing URLs from KnowledgeBase
    urls_to_scrape = kb.get("crawled_urls") or []
    
    # Add main domain if no URLs available
    if not urls_to_scrape:
        urls_to_scrape = [f"http://{target}", f"https://{target}"]
    
    print(f"    ╠ Scraping {len(urls_to_scrape)} URLs for emails")
    
    # Email regex pattern (more robust)
    email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
    
    # Social media patterns to exclude (if any)
    social_domains = ['facebook.com', 'twitter.com', 'linkedin.com', 'instagram.com']
    
    for url in urls_to_scrape[:20]:  # Limit to 20 URLs to avoid being too aggressive
        try:
            print(f"    ┃   ├ Checking: {url[:50]}...", end='\r')
            
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                # Find emails in the page content
                found_emails = email_pattern.findall(r.text)
                
                for email in found_emails:
                    # Filter out common false positives and social media emails
                    domain = email.split('@')[1].lower()
                    
                    # Check if the email domain is related to the target
                    if target in domain or domain.endswith('.' + target):
                        emails.add(email)
                    # Also include emails from non-social domains
                    elif not any(social in domain for social in social_domains):
                        # Additional filtering: exclude common placeholder emails
                        if not re.search(r'example|test|placeholder|domain|email', email, re.IGNORECASE):
                            emails.add(email)
            
            # Also check for mailto: links
            mailto_links = re.findall(r'mailto:([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', r.text, re.IGNORECASE)
            for email in mailto_links:
                emails.add(email)
                
        except Exception as e:
            continue
    
    # Remove any email addresses that are clearly not valid (like image names)
    filtered_emails = set()
    for email in emails:
        # Skip emails that are too long (likely false positives)
        if len(email) > 50:
            continue
        # Skip emails with consecutive dots
        if '..' in email:
            continue
        filtered_emails.add(email)
    
    emails = filtered_emails
    
    # Report findings
    if emails:
        print(f"\n    ╠ Found {len(emails)} email addresses:")
        for email in list(emails)[:10]:  # Show first 10
            print(f"    ┃   ├ {email}")
        if len(emails) > 10:
            print(f"    ┃   └ ... and {len(emails) - 10} more")
        
        print(f"    ╔═══════════════════════════════════════════════")
        print(f"    ║ EMAIL HARVESTING COMPLETE")
        print(f"    ║ Total unique emails: {len(emails)}")
        print(f"    ╚═══════════════════════════════════════════════")
        
        kb.update("emails_found", list(emails))
    else:
        print(f"\n    ╚ No email addresses found")
        kb.update("emails_found", [])
