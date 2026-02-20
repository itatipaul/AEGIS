import requests
import re
import os
from io import BytesIO
try:
    import PyPDF2 # pip install PyPDF2
except ImportError:
    PyPDF2 = None

PRIORITY = 42
TYPE = "OSINT"
DESCRIPTION = "Extracts users, software, and paths from PDF/Doc files (FOCA-lite)"

def extract_pdf_meta(content):
    findings = []
    try:
        if not PyPDF2: return ["PyPDF2 not installed"]
        
        pdf = PyPDF2.PdfReader(BytesIO(content))
        meta = pdf.metadata
        
        if not meta: return []

        if '/Author' in meta:
            findings.append(f"Author: {meta['/Author']}")
        if '/Creator' in meta:
            findings.append(f"Software: {meta['/Creator']}")
        if '/Producer' in meta:
            findings.append(f"Producer: {meta['/Producer']}")
        if '/CreationDate' in meta:
            findings.append(f"Created: {meta['/CreationDate']}")
            
    except Exception as e:
        pass
    return findings

def run(kb):
    # Get document URLs from crawler or dorks
    urls = kb.get("crawled_urls", []) + [x.get('url') for x in kb.get("nikto_vulns", []) if isinstance(x, dict)]
    
    # Filter for interesting extensions
    doc_urls = set()
    for u in urls:
        if u and u.lower().endswith(('.pdf', '.docx', '.xlsx', '.pptx')):
            doc_urls.add(u)
            
    if not doc_urls: return

    print(f"[*] Analyzing Metadata for {len(doc_urls)} documents...")
    
    metadata_intel = []
    users_found = set()
    software_found = set()

    for url in doc_urls:
        try:
            # Stream download to avoid memory issues with large files
            r = requests.get(url, timeout=10, stream=True, verify=False)
            
            # Limit size to 5MB analysis
            if int(r.headers.get('content-length', 0)) > 5 * 1024 * 1024:
                continue
                
            content = r.content
            meta_data = []

            # 1. PDF Analysis
            if url.lower().endswith('.pdf'):
                meta_data = extract_pdf_meta(content)

            # 2. Generic Regex (for Office docs if libraries missing)
            # Look for paths like C:\Users\xyz or /home/xyz
            paths = re.findall(rb'[a-zA-Z]:\\[\\\S| ]+|/home/[a-z0-9]+', content)
            for p in paths[:3]: # Limit noise
                try:
                    meta_data.append(f"Internal Path: {p.decode('utf-8', 'ignore')}")
                except: pass

            if meta_data:
                print(f"      [+] Metadata in {url.split('/')[-1]}: {meta_data}")
                
                # Extract intel for reporting
                for m in meta_data:
                    if "Author" in m: users_found.add(m.split(': ')[1])
                    if "Software" in m or "Producer" in m: software_found.add(m.split(': ')[1])

                metadata_intel.append({
                    "url": url,
                    "metadata": meta_data
                })

        except: pass

    # Update KB with Intelligence
    if metadata_intel:
        kb.update("document_metadata", metadata_intel)
        
    if users_found:
        print(f"    [i] Discovered Potential Usernames: {', '.join(users_found)}")
        # Merge with emails found earlier
        current_emails = set(kb.get("found_emails", []))
        for u in users_found: current_emails.add(u) # Add names as leads
        kb.update("found_emails", list(current_emails))
