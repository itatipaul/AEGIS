import requests
import concurrent.futures

PRIORITY = 29
TYPE = "Recon"
DESCRIPTION = "Mines for hidden GET/POST parameters (e.g., debug, admin, test)"

# Top common hidden parameters
COMMON_PARAMS = [
    "debug", "admin", "test", "id", "user", "access", "dbg", "source",
    "backup", "system", "edit", "grant", "dashboard", "cmd", "exec",
    "redirect", "url", "proxy", "file", "path"
]

def run(kb):
    print(f"[*] Running {DESCRIPTION}...")
    
    # We only mine on pages that return 200 OK
    urls = kb.get("crawled_urls") or []
    targets = [u for u in urls if "?" not in u][:10] # Limit to 10 base URLs for speed
    
    if not targets:
        return

    found_params = []

    def check_param(url, param):
        try:
            # Baseline request (normal)
            r1 = requests.get(url, timeout=3)
            
            # Fuzzed request
            # We use a random value to see if it reflects or changes page size
            fuzzed_url = f"{url}?{param}=aegis_test"
            r2 = requests.get(fuzzed_url, timeout=3)
            
            # Heuristic: If content length differs significantly, the param might be doing something
            if len(r1.text) != len(r2.text):
                diff = abs(len(r1.text) - len(r2.text))
                if diff > 50: # Filters out tiny dynamic changes (timestamps)
                    return (url, param, f"Response size changed by {diff} bytes")
            
            # Heuristic: Reflection
            if "aegis_test" in r2.text and "aegis_test" not in r1.text:
                return (url, param, "Parameter value reflected in response")
                
        except:
            pass
        return None

    print(f"    > Mining parameters on {len(targets)} pages...")
    
    for url in targets:
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(check_param, url, p) for p in COMMON_PARAMS]
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    print(f"      [+] Hidden Param Found: {result[0]}?{result[1]} ({result[2]})")
                    found_params.append({
                        "url": result[0],
                        "parameter": result[1],
                        "details": result[2]
                    })

    if found_params:
        kb.update("hidden_parameters", found_params)
        
        # Add these new URLs to the crawl list so other plugins attack them!
        new_urls = [f"{x['url']}?{x['parameter']}=FUZZ" for x in found_params]
        current_crawl = kb.get("crawled_urls") or []
        kb.update("crawled_urls", list(set(current_crawl + new_urls)))
