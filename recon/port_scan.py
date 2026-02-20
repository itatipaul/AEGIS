import asyncio
import socket
import ssl
import ipaddress
import random
import base64
from urllib.parse import urlparse

PRIORITY = 15
TYPE = "Active Recon"
DESCRIPTION = "Async high-speed port scanner (Swarm-Enabled)"

# ... [Keep the AsyncProxyConnector class exactly as it was] ...
class AsyncProxyConnector:
    def __init__(self, proxies):
        self.proxies = proxies
    def get_random_proxy(self):
        if not self.proxies: return None
        return random.choice(self.proxies)
    async def open_connection(self, target_host, target_port):
        # ... [Same logic as previous upload] ...
        proxy_url = self.get_random_proxy()
        if not proxy_url:
            return await asyncio.open_connection(target_host, target_port)
        try:
            parsed = urlparse(proxy_url)
            proxy_host = parsed.hostname; proxy_port = parsed.port
            reader, writer = await asyncio.wait_for(asyncio.open_connection(proxy_host, proxy_port), timeout=2.0)
            connect_req = f"CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\nProxy-Connection: Keep-Alive\r\n\r\n"
            writer.write(connect_req.encode()); await writer.drain()
            await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=2.0)
            return reader, writer
        except: raise ConnectionError

async def check_port(ip, port, semaphore, open_ports, connector, stealth=False):
    async with semaphore:
        if stealth: await asyncio.sleep(random.uniform(0.5, 1.5))
        writer = None
        try:
            reader, writer = await connector.open_connection(ip, port)
            
            # Simple Banner Grab
            banner = ""
            try:
                writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                await writer.drain()
                data = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                banner = data.decode('utf-8', errors='ignore').split('\n')[0][:50]
            except: pass

            print(f"    [+] Open: {ip}:{port}")
            
            # [FIX] Use a flat list structure internally, aggregated later
            open_ports.append({"port": port, "banner": banner, "status": "OPEN", "ip": ip})
            
        except: pass
        finally:
            if writer:
                try: writer.close(); await writer.wait_closed()
                except: pass

async def run_async(kb):
    print(f"[*] Running {DESCRIPTION}...")
    target_domain = kb.get("target_domain") # Get the main key
    targets = kb.get("scope_domains") or []
    if not targets and target_domain: targets = [target_domain]

    settings = kb.get("settings", {})
    runtime_config = kb.get("config", {})
    stealth_mode = runtime_config.get("stealth", False)
    ports = settings.get("ports", {}).get("common", [80, 443, 22, 21, 25, 445, 3389, 8080, 8443])
    
    # ... [Proxy Loading Logic - Same as before] ...
    http_proxies = [] # assume empty or load from file logic here

    connector = AsyncProxyConnector(http_proxies)
    open_ports_list = [] # [FIX] Changed from dict to list
    semaphore = asyncio.Semaphore(200) 
    
    final_targets = []
    for t in targets: final_targets.append(t) # IP expansion logic omitted for brevity

    tasks = [check_port(t, p, semaphore, open_ports_list, connector, stealth_mode) for t in final_targets for p in ports]
    await asyncio.gather(*tasks)
    
    # [FIX] Save consistent structure: { "target_domain": [ {port:80}, {port:443} ] }
    if open_ports_list:
        kb.update("open_ports", {target_domain: open_ports_list})

def run(kb):
    asyncio.run(run_async(kb))
