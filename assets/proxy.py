import requests
import threading
import queue
import socket
import time
import json
import os
import random
from typing import List, Optional
from .utilities import UI, Style

class ProxyManager:
    validated_proxies = []  # Class variable to store validated proxies
    already_validated = False  # Track if validation has been done
    
    def __init__(self, proxy_list: Optional[List[str]] = None, debug: bool = False):
        self.proxies = queue.Queue()
        self.valid_proxies = []
        self.debug = debug
        self.lock = threading.Lock()
        self.cache_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'cache')
        self.cache_file = os.path.join(self.cache_dir, 'proxy_cache.json')
        
        # Create cache directory if it doesn't exist
        if not os.path.exists(self.cache_dir):
            try:
                os.makedirs(self.cache_dir)
                if self.debug:
                    UI.print_info(f"Created cache directory: {self.cache_dir}")
            except Exception as e:
                if self.debug:
                    UI.print_error(f"Failed to create cache directory: {e}")
        
        self.load_cached_proxies()
        
        if proxy_list:
            for proxy in proxy_list:
                self.proxies.put(proxy)
                
        if ProxyManager.already_validated and ProxyManager.validated_proxies:
            UI.print_info(f"Using {len(ProxyManager.validated_proxies)} previously validated proxies")
            self.valid_proxies = ProxyManager.validated_proxies
            return

    def check_proxy_freshness(self) -> bool:
        """Check if proxies are still fresh (less than 1 hour old) and valid"""
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r') as f:
                    cache_data = json.load(f)
                    age = time.time() - cache_data.get('timestamp', 0)
                    
                    if age < 3600:  # Less than 1 hour old
                        # Test a sample of proxies (10% or at least 5)
                        proxies = cache_data.get('proxies', [])
                        sample_size = max(5, len(proxies) // 10)
                        test_proxies = random.sample(proxies, min(sample_size, len(proxies)))
                        
                        working = 0
                        for proxy in test_proxies:
                            if self.validate_proxy(proxy):
                                working += 1
                                
                        # If more than 70% of tested proxies work, consider cache fresh
                        if working / len(test_proxies) > 0.7:
                            if self.debug:
                                UI.print_info(f"Proxy cache is fresh ({working}/{len(test_proxies)} tested proxies working)")
                            return True
                        else:
                            if self.debug:
                                UI.print_warning(f"Too many dead proxies ({working}/{len(test_proxies)} working), updating cache")
                    else:
                        if self.debug:
                            UI.print_info(f"Proxy cache expired ({age/3600:.1f} hours old)")
        except Exception as e:
            if self.debug:
                UI.print_error(f"Error checking proxy freshness: {e}")
        return False

    def load_cached_proxies(self):
        """Load previously validated proxies from cache file"""
        try:
            if os.path.exists(self.cache_file):
                if self.check_proxy_freshness():
                    with open(self.cache_file, 'r') as f:
                        cache_data = json.load(f)
                        ProxyManager.validated_proxies = cache_data.get('proxies', [])
                        ProxyManager.already_validated = True
                        self.valid_proxies = ProxyManager.validated_proxies.copy()
                        UI.print_info(f"Using {len(self.valid_proxies)} cached proxies")
                        return True
        except Exception as e:
            if self.debug:
                UI.print_error(f"Failed to load proxy cache: {e}")
        return False

    def save_cache(self):
        """Save validated proxies to cache file"""
        try:
            cache_data = {
                'timestamp': time.time(),
                'proxies': self.valid_proxies,
                'source': 'TentroLink Proxy Cache'
            }
            with open(self.cache_file, 'w') as f:
                json.dump(cache_data, f, indent=2)
            if self.debug:
                UI.print_info(f"Saved {len(self.valid_proxies)} proxies to cache")
                UI.print_info(f"Cache location: {self.cache_file}")
        except Exception as e:
            if self.debug:
                UI.print_error(f"Failed to save proxy cache: {e}")

    def download_proxies(self, sources: List[str]) -> int:
        """Download proxies from multiple sources"""
        total_proxies = 0
        
        for source in sources:
            try:
                UI.print_info(f"Downloading proxies from: {source}")
                response = requests.get(source, timeout=10)
                proxies = response.text.strip().split('\n')
                
                for proxy in proxies:
                    proxy = proxy.strip()
                    if self._is_valid_proxy_format(proxy):
                        self.proxies.put(proxy)
                        total_proxies += 1
                        
                if self.debug:
                    UI.print_info(f"Found {len(proxies)} proxies from {source}")
                    
            except Exception as e:
                UI.print_error(f"Failed to download from {source}: {str(e)}")
                
        return total_proxies

    def _is_valid_proxy_format(self, proxy: str) -> bool:
        """Check if proxy string matches IP:PORT format"""
        try:
            ip, port = proxy.split(':')
            port = int(port)
            socket.inet_aton(ip)  # Validate IP format
            return 1 <= port <= 65535
        except:
            return False

    def validate_proxy(self, proxy: str) -> bool:
        """Test if a proxy is working"""
        try:
            ip, port = proxy.split(':')
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((ip, int(port)))
            sock.close()
            
            if self.debug:
                UI.print_success(f"Proxy validated: {proxy}")
                
            with self.lock:
                self.valid_proxies.append(proxy)
            return True
            
        except Exception as e:
            if self.debug:
                UI.print_error(f"Proxy failed: {proxy} - {str(e)}")
            return False
        
    def has_valid_proxies(self) -> bool:
        """Check if we already have validated proxies"""
        if ProxyManager.already_validated and ProxyManager.validated_proxies:
            self.valid_proxies = ProxyManager.validated_proxies.copy()
            if self.debug:
                UI.print_info(f"Reusing {len(self.valid_proxies)} previously validated proxies")
            return True
        return self.load_cached_proxies()  # Try loading from cache

    def validate_proxies(self, threads: int = 10) -> int:
        """Validate all proxies in the queue using multiple threads"""
        if self.has_valid_proxies():
            return len(self.valid_proxies)

        thread_list = []
        total_proxies = self.proxies.qsize()
        
        if total_proxies == 0:
            return 0

        UI.print_info(f"Validating {total_proxies} proxies using {threads} threads")
        
        def validator_worker():
            while True:
                try:
                    proxy = self.proxies.get_nowait()
                    self.validate_proxy(proxy)
                    self.proxies.task_done()
                except queue.Empty:
                    break

        # Start validator threads
        for _ in range(min(threads, total_proxies)):
            thread = threading.Thread(target=validator_worker)
            thread.daemon = True
            thread.start()
            thread_list.append(thread)

        # Show progress bar while validating
        while not self.proxies.empty():
            remaining = self.proxies.qsize()
            progress = ((total_proxies - remaining) / total_proxies) * 100
            UI.print_progress_bar(
                total_proxies - remaining,
                total_proxies,
                prefix="Validating proxies:",
                length=40
            )
            time.sleep(0.1)

        # Wait for validation to complete
        self.proxies.join()
        
        valid_count = len(self.valid_proxies)
        UI.print_info(f"Validation complete: {valid_count} valid proxies out of {total_proxies}")
        
        if self.debug and valid_count > 0:
            UI.print_info("Valid proxies:")
            for proxy in self.valid_proxies[:5]:
                print(f"  - {proxy}")
            if valid_count > 5:
                print(f"  ... and {valid_count - 5} more")
                
        if valid_count > 0:
            ProxyManager.validated_proxies = self.valid_proxies.copy()
            ProxyManager.already_validated = True
            self.save_cache()  # Save validated proxies to cache
            
        return valid_count

    def get_proxy(self) -> Optional[str]:
        """Get a random valid proxy"""
        with self.lock:
            if self.valid_proxies:
                return self.valid_proxies[int(time.time() * 1000) % len(self.valid_proxies)]
        return None
