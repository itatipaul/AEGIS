import random
import os
import logging

class ProxyRotator:
    def __init__(self, proxy_file="proxies.txt"):
        self.proxies = []
        self.logger = logging.getLogger("aegis.swarm")
        self.load_proxies(proxy_file)

    def load_proxies(self, file_path):
        """Loads a list of proxies from a text file."""
        # Check root directory first, then config/
        paths_to_check = [file_path, os.path.join("config", file_path), os.path.join("..", file_path)]
        
        valid_path = None
        for p in paths_to_check:
            if os.path.exists(p):
                valid_path = p
                break
        
        if not valid_path:
            self.logger.warning(f"[-] No 'proxies.txt' found. Swarm Mode disabled (Direct Connection).")
            return

        try:
            with open(valid_path, 'r') as f:
                lines = f.readlines()
                for line in lines:
                    line = line.strip()
                    if not line or line.startswith("#"): continue
                    
                    # Normalize format (add http:// if missing)
                    if "://" not in line:
                        line = f"http://{line}"
                    
                    self.proxies.append(line)
            
            if self.proxies:
                self.logger.info(f"[+] Swarm Activated: Loaded {len(self.proxies)} proxies.")
            else:
                self.logger.warning("[-] Proxy file is empty.")
                
        except Exception as e:
            self.logger.error(f"Error loading proxies: {e}")

    def get_random(self):
        """Returns a random proxy from the swarm to confuse WAFs."""
        if not self.proxies:
            return None
        
        proxy = random.choice(self.proxies)
        return {"http": proxy, "https": proxy}

    def get_rr(self):
        """Round-Robin rotation (Predictable but even load)."""
        if not self.proxies: return None
        proxy = self.proxies[0]
        self.proxies.append(self.proxies.pop(0)) # Rotate list
        return {"http": proxy, "https": proxy}
