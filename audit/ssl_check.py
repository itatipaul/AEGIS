import ssl
import socket
import datetime

# TAGS
PRIORITY = 16
TYPE = "Audit"
DESCRIPTION = "Checks SSL certificate validity and expiration"

def run(kb):
    print(f"[*] Running {DESCRIPTION}...")
    
    # Get open ports where port is 443 or 8443
    ports_data = kb.get("open_ports")
    if not ports_data:
        return

    ssl_issues = []

    for target, ports in ports_data.items():
        # Filter for HTTPS ports
        https_ports = [p['port'] for p in ports if p['port'] in [443, 8443]]
        
        for port in https_ports:
            try:
                context = ssl.create_default_context()
                # Wrap the socket
                with socket.create_connection((target, port), timeout=3) as sock:
                    with context.wrap_socket(sock, server_hostname=target) as ssock:
                        cert = ssock.getpeercert()
                        
                        # Check Expiration
                        not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        days_left = (not_after - datetime.datetime.utcnow()).days
                        
                        issuer = dict(x[0] for x in cert['issuer'])
                        org = issuer.get('organizationName', 'Unknown')

                        print(f"      [INFO] {target}:{port} | Issuer: {org} | Expires in: {days_left} days")
                        
                        if days_left < 30:
                            print(f"      [WARNING] Certificate expires soon! ({days_left} days)")
                            ssl_issues.append({"target": target, "issue": "Expiring Soon", "days": days_left})
            
            except ssl.SSLCertVerificationError:
                print(f"      [HIGH] {target}:{port} has a SELF-SIGNED or INVALID certificate.")
                ssl_issues.append({"target": target, "issue": "Invalid/Self-Signed Certificate"})
            except Exception as e:
                pass

    kb.update("ssl_issues", ssl_issues)
