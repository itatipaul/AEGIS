# aegis/plugins/analysis/cve_check.py
import re

PRIORITY = 25
TYPE = "Analysis"
DESCRIPTION = "Analyzes service banners for known CVEs and critical vulnerabilities"

# Database of vulnerability signatures (Regex -> Vulnerability)
VULN_SIGNATURES = [
    # FTP
    (r"vsftpd 2\.3\.4", "CVE-2011-2523", "Critical", "Vsftpd Backdoor Command Execution"),
    (r"ProFTPD 1\.3\.[3-5]", "CVE-2015-3306", "High", "ProFTPD mod_copy Arbitrary File Copy"),
    
    # SSH
    (r"libssh 0\.([6-7]\.|8\.[0-3])", "CVE-2018-10933", "Critical", "LibSSH Authentication Bypass"),
    (r"OpenSSH 7\.2p2", "CVE-2016-6210", "Medium", "User Enumeration"),
    (r"OpenSSH ([1-6]\.|7\.[0-4])", "Legacy", "Medium", "Outdated SSH Version (Use v7.5+)"),
    
    # Web Servers
    (r"Apache/2\.4\.(49|50)", "CVE-2021-41773", "Critical", "Apache Path Traversal & RCE"),
    (r"Apache/2\.2\.", "Legacy", "Medium", "End of Life Apache Version"),
    (r"nginx/1\.[0-9]\.", "Legacy", "Low", "Old Nginx Version"),
    (r"Microsoft-IIS/6\.0", "CVE-2017-7269", "Critical", "IIS 6.0 WebDAV Buffer Overflow"),
    (r"Microsoft-IIS/7\.5", "Legacy", "Medium", "Windows Server 2008 R2 (EOL)"),
    (r"JBoss", "Multiple", "High", "JBoss Application Server (Often misconfigured)"),
    
    # Email
    (r"Exim 4\.(8[7-9]|9[0-1])", "CVE-2019-10149", "Critical", "The Return of the Wizard (RCE)"),
    
    # Databases
    (r"MySQL 5\.[0-5]\.", "Legacy", "Medium", "Old MySQL Version"),
    (r"PostgreSQL 9\.", "Legacy", "Low", "Old PostgreSQL Version"),
    
    # SMB / Windows
    (r"Windows 5\.1", "Legacy", "High", "Windows XP (End of Life)"),
    (r"Windows 6\.1", "Legacy", "Medium", "Windows 7 / Server 2008 R2 (End of Life)"),
    
    # Others
    (r"PHP/5\.", "Legacy", "High", "PHP 5.x is End of Life (Many vulnerabilities)"),
    (r"PHP/7\.[0-2]\.", "Legacy", "Medium", "Unsupported PHP Version")
]

def run(kb):
    print(f"[*] Running {DESCRIPTION}...")
    
    # Get open ports data from smart_scanner or port_scan
    ports_data = kb.get("open_ports")
    if not ports_data:
        return

    cve_findings = []

    for target, ports in ports_data.items():
        print(f"    ╠ Analyzing {len(ports)} services on {target}...")
        
        for p in ports:
            port = p.get('port')
            service = p.get('service', 'unknown')
            banner = p.get('banner', '')
            
            if not banner:
                continue
                
            # Normalize banner for matching
            banner_str = str(banner).strip()
            
            # Check against signatures
            matched = False
            for pattern, cve, risk, name in VULN_SIGNATURES:
                if re.search(pattern, banner_str, re.IGNORECASE):
                    print(f"      [{risk.upper()}] {target}:{port} - {name} ({cve})")
                    cve_findings.append({
                        "host": target,
                        "port": port,
                        "service": service,
                        "cve": cve,
                        "risk": risk,
                        "vulnerability": name,
                        "evidence": banner_str
                    })
                    matched = True
            
            # General checks if no specific CVE matched
            if not matched:
                if "telnet" in service.lower() or port == 23:
                    print(f"      [HIGH] {target}:{port} - Insecure Protocol (Telnet)")
                    cve_findings.append({"host": target, "port": port, "risk": "High", "vulnerability": "Cleartext Service (Telnet)", "cve": "N/A"})
                
                if "ftp" in service.lower() and "anonymous" in banner_str.lower():
                     print(f"      [MEDIUM] {target}:{port} - FTP Anonymous Login Allowed")
                     cve_findings.append({"host": target, "port": port, "risk": "Medium", "vulnerability": "FTP Anonymous Login", "cve": "N/A"})

    kb.update("cve_findings", cve_findings)
