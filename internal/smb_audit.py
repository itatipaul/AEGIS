import socket
import asyncio
from concurrent.futures import ThreadPoolExecutor

PRIORITY = 30
TYPE = "Internal Recon"
DESCRIPTION = "Scans for SMB shares, Null Sessions, and Signing configuration"

# Try to import Impacket for deep inspection
try:
    from impacket.smbconnection import SMBConnection
    from impacket.smb import SMB_DIALECT_21
    IMPACKET_AVAIL = True
except ImportError:
    IMPACKET_AVAIL = False

def check_smb_deep(ip):
    """Uses Impacket to enumerate SMB info"""
    result = {"ip": ip, "status": "OPEN", "signing": False, "null_session": False, "shares": []}
    
    try:
        # 1. Connect
        conn = SMBConnection(ip, ip, sess_port=445, timeout=5)
        
        # 2. Check Signing
        if conn.isSigningRequired():
            result["signing"] = "REQUIRED"
        else:
            result["signing"] = "DISABLED (VULN)"
            
        # 3. Attempt Null Session (Login as ''/'')
        try:
            conn.login('', '')
            result["null_session"] = True
            
            # 4. List Shares if Null Session worked
            shares = conn.listShares()
            for share in shares:
                share_name = share['shi1_netname'][:-1]
                result["shares"].append(share_name)
        except:
            result["null_session"] = False
            
        conn.logoff()
        return result
    except Exception as e:
        return None

async def scan_host(ip, loop, executor):
    # Quick port check first
    try:
        _, writer = await asyncio.open_connection(ip, 445)
        writer.close()
        await writer.wait_closed()
    except:
        return None # Port closed

    # If port open and Impacket available, go deep
    if IMPACKET_AVAIL:
        return await loop.run_in_executor(executor, check_smb_deep, ip)
    else:
        return {"ip": ip, "status": "OPEN", "note": "Impacket not installed, deep scan skipped"}

async def run_async(kb):
    print(f"[*] Running {DESCRIPTION}...")
    
    if not IMPACKET_AVAIL:
        print("    [!] 'impacket' library not found. Running basic port check only.")
        print("    [i] Install with: pip install impacket")

    # Get targets from resolved domains or provided IP scope
    # (Simplified: Just taking IPs from previous port scans if available)
    targets = set()
    ports_data = kb.get("open_ports", {})
    
    for host, _ in ports_data.items():
        # Ideally, we resolve 'host' to IP here, but assuming host might be IP
        try:
            ip = socket.gethostbyname(host)
            targets.add(ip)
        except:
            pass

    if not targets:
        print("    [-] No resolved IP targets to scan.")
        return

    print(f"    ╠ Scanning SMB on {len(targets)} unique hosts...")
    
    loop = asyncio.get_running_loop()
    executor = ThreadPoolExecutor(max_workers=10)
    
    tasks = [scan_host(ip, loop, executor) for ip in list(targets)]
    results = await asyncio.gather(*tasks)
    
    smb_hosts = [r for r in results if r]
    
    for host in smb_hosts:
        sign_status = host.get('signing', 'UNKNOWN')
        null_status = "YES" if host.get('null_session') else "NO"
        
        print(f"    [+] SMB FOUND: {host['ip']}")
        print(f"        └ Signing: {sign_status}")
        print(f"        └ Null Session: {null_status}")
        
        if host.get('shares'):
            print(f"        └ Exposed Shares: {', '.join(host['shares'])}")
            
            # Alert on critical findings
            if "C$" in host['shares'] or "ADMIN$" in host['shares']:
                 print(f"          [!!!] CRITICAL: ADMIN SHARES EXPOSED VIA NULL SESSION")

    if smb_hosts:
        kb.update("smb_audit", smb_hosts)

def run(kb):
    asyncio.run(run_async(kb))
