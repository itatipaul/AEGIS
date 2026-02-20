import time
import random
import requests
import logging
from requests.exceptions import ProxyError, ConnectTimeout, ReadTimeout, ConnectionError
from aegis.core.proxy_rotator import ProxyRotator

class TrafficController:
    def __init__(self, config):
        self.config_data = config
        self.stealth = config.get("stealth", False)
        self.avg_latency = 0.5
        
        self.single_proxy = config.get("proxy")
        self.rotator = None
        
        if not self.single_proxy:
            # Load the list you provided
            self.rotator = ProxyRotator("proxies.txt")
        
        self.cookies = config.get("cookies", {})
        self.headers = config.get("headers", {})
        self.logger = logging.getLogger("aegis.traffic")
        
        # ... (User agents and bypass headers remain the same) ...
        self.user_agents = config.get("settings", {}).get("user_agents", ["Aegis/6.0"])
        self.bypass_headers = [{"X-Forwarded-For": "127.0.0.1"}] 

        self._orig_get = requests.get
        self._orig_post = requests.post
        self._orig_head = requests.head

    def _prepare_kwargs(self, kwargs):
        if self.stealth:
            delay = self.avg_latency * random.uniform(1.2, 2.8)
            time.sleep(delay)

        headers = kwargs.get("headers", {})
        if self.stealth:
            headers["User-Agent"] = random.choice(self.user_agents)
        
        headers.update(self.headers)
        kwargs["headers"] = headers
        
        # Inject Proxy
        if self.single_proxy:
            kwargs["proxies"] = {"http": self.single_proxy, "https": self.single_proxy}
            kwargs["verify"] = False
        elif self.rotator:
            # Pick a random proxy from your list
            proxy_dict = self.rotator.get_random()
            if proxy_dict:
                kwargs["proxies"] = proxy_dict
                kwargs["verify"] = False 

        return kwargs

    def _request_with_retry(self, method_func, url, **kwargs):
        """
        Attempts the request. If a ProxyError occurs, it picks a NEW proxy and retries.
        """
        max_retries = 3
        attempts = 0
        
        while attempts < max_retries:
            # Regenerate kwargs to pick a NEW random proxy if using rotator
            current_kwargs = self._prepare_kwargs(kwargs.copy())
            
            try:
                start_time = time.time()
                response = method_func(url, **current_kwargs)
                
                # Success: Update latency tracking
                self.avg_latency = (self.avg_latency * 0.7) + ((time.time() - start_time) * 0.3)
                return response

            except (ProxyError, ConnectTimeout, ReadTimeout, ConnectionError) as e:
                attempts += 1
                if self.rotator:
                    # Log the failure but keep it clean
                    # print(f"    [!] Proxy failed ({current_kwargs.get('proxies')}), retrying... ({attempts}/{max_retries})")
                    pass
                
                if attempts >= max_retries:
                    raise e # Give up after 3 failed proxies

    def patched_get(self, url, **kwargs):
        return self._request_with_retry(self._orig_get, url, **kwargs)

    def patched_post(self, url, **kwargs):
        return self._request_with_retry(self._orig_post, url, **kwargs)

    def patched_head(self, url, **kwargs):
        return self._request_with_retry(self._orig_head, url, **kwargs)

    def activate(self):
        requests.get = self.patched_get
        requests.post = self.patched_post
        requests.head = self.patched_head
