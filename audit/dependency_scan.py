import asyncio
import aiohttp
import re

PRIORITY = 20
TYPE = "Audit"
DESCRIPTION = "Scans for exposed dependency files (Supply Chain Analysis)"

# Files that define a project's supply chain
DEPENDENCY_FILES = {
    "package.json": "Node.js (NPM)",
    "package-lock.json": "Node.js (NPM Locked)",
    "composer.json": "PHP (Composer)",
    "requirements.txt": "Python (Pip)",
    "Pipfile": "Python (Pipenv)",
    "Gemfile": "Ruby (Bundler)",
    "go.mod": "Go (Modules)",
    "pom.xml": "Java (Maven)",
    "build.gradle": "Java/Kotlin (Gradle)",
    "cargo.toml": "Rust (Cargo)"
}

async def check_file(session, url, file_name, tech, semaphore):
    target_url = f"{url}/{file_name}"
    async with semaphore:
        try:
            async with session.get(target_url, allow_redirects=False, timeout=10) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    # Simple heuristic validation to reduce false positives (404 pages returning 200)
                    if len(text) < 5000 and (
                        "dependencies" in text or 
                        "require" in text or 
                        "version" in text or 
                        "group" in text or
                        "module" in text
                    ):
                        print(f"    [CRITICAL] EXPOSED SUPPLY CHAIN: {target_url} ({tech})")
                        return {
                            "url": target_url,
                            "type": tech,
                            "file": file_name,
                            "content_snippet": text[:200]
                        }
        except:
            pass
    return None

async def run_async(kb):
    print(f"[*] Running {DESCRIPTION}...")
    
    # Get all web ports from previous Nmap/Scan
    targets = set()
    ports_data = kb.get("open_ports", {})
    
    # If no ports found yet, fallback to scope domains on standard ports
    if not ports_data:
        domains = kb.get("scope_domains", [])
        for d in domains:
            targets.add(f"https://{d}")
            targets.add(f"http://{d}")
    else:
        for host, ports in ports_data.items():
            for p in ports:
                # Check HTTP/HTTPS services
                if p['port'] in ['80', '443', '8080', '8443'] or 'http' in p.get('service', '').lower():
                    proto = "https" if p['port'] in ['443', '8443'] else "http"
                    targets.add(f"{proto}://{host}:{p['port']}")

    if not targets:
        print("    [-] No web targets to scan.")
        return

    print(f"    ╠ Scanning {len(targets)} targets for {len(DEPENDENCY_FILES)} dependency types...")
    
    semaphore = asyncio.Semaphore(20) # Limit concurrency
    tasks = []
    
    # Use the TrafficController's session logic if possible, otherwise raw aiohttp
    async with aiohttp.ClientSession() as session:
        for target in targets:
            for filename, tech in DEPENDENCY_FILES.items():
                tasks.append(check_file(session, target, filename, tech, semaphore))
        
        results = await asyncio.gather(*tasks)
    
    # Filter None results
    findings = [r for r in results if r]
    
    if findings:
        kb.update("supply_chain_exposures", findings)
        print(f"    ╚ Found {len(findings)} exposed dependency files.")
    else:
        print("    ╚ No supply chain exposures found.")

def run(kb):
    asyncio.run(run_async(kb))
