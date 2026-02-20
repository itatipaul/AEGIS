import aiohttp
import asyncio

PRIORITY = 26
TYPE = "Web Analysis"
DESCRIPTION = "Async GraphQL Introspector & Console Hunter"

COMMON_ENDPOINTS = [
    "/graphql", "/api/graphql", "/v1/graphql", "/gql", "/query", "/api/query"
]

INTROSPECTION_QUERY = """
query {
  __schema {
    types {
      name
    }
  }
}
"""

async def check_endpoint(session, base_url, endpoint):
    url = f"{base_url}{endpoint}"
    # 1. Check for Console (GET)
    try:
        async with session.get(url, timeout=5) as r:
            text = await r.text()
            if "GraphiQL" in text or "graphql-playground" in text:
                return {"type": "Console", "url": url, "msg": "GraphiQL/Playground Exposed"}
    except: pass

    # 2. Check for Introspection (POST)
    try:
        async with session.post(url, json={"query": INTROSPECTION_QUERY}, timeout=5) as r:
            if r.status == 200:
                data = await r.json()
                if "data" in data and "__schema" in data["data"]:
                    return {"type": "Introspection", "url": url, "msg": "Introspection Enabled (Schema Leaked)"}
    except: pass

    return None

async def run_async(kb):
    target = kb.get("target_domain")
    if not target: return
    
    # Construct base URLs (http/https)
    base_urls = [f"https://{target}", f"http://{target}"]
    
    print(f"[*] Running {DESCRIPTION}...")
    
    findings = []
    
    async with aiohttp.ClientSession() as session:
        tasks = []
        for base in base_urls:
            for end in COMMON_ENDPOINTS:
                tasks.append(check_endpoint(session, base, end))
        
        results = await asyncio.gather(*tasks)
        
        for res in results:
            if res:
                print(f"    [!] FOUND: {res['msg']} at {res['url']}")
                findings.append(res)

    if findings:
        kb.update("graphql_findings", findings)
        # Add to vuln list
        current_vulns = kb.get("web_vulns", [])
        for f in findings:
            current_vulns.append({
                "RISK": "HIGH",
                "TYPE": "GraphQL",
                "ISSUE": f['msg'],
                "EVIDENCE": f['url']
            })
        kb.update("web_vulns", current_vulns)

def run(kb):
    asyncio.run(run_async(kb))
