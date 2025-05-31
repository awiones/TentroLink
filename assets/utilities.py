import sys
import time
import threading
import shutil
from typing import List
from urllib.parse import urlparse
import socket
import requests
from typing import Optional, Tuple

def get_banner():
    """Return the TentroLink banner ASCII art"""
    banner = r"""
__ __|             |               
   |   _ \  __ \   __|   _ \    __|
   |   __/  |   |  |    (   |  |   
  _| \___| _|  _| \__| \___/  _|   
  Tentor V0.6.6
  Made By github.com/awiones
"""
    return banner

class Style:
    # Color codes
    BLUE = '\033[0;34m'     # Add BLUE color code
    INFO = '\033[0;94m'      
    SUCCESS = '\033[0;92m'   
    WARNING = '\033[0;93m'   
    ERROR = '\033[0;91m'     
    BOLD = '\033[1m'         
    DIM = '\033[2m'          
    RESET = '\033[0m'        
    PROGRESS_BAR = '█'
    PROGRESS_EMPTY = '░'
    HEADER = '\033[1;95m'    
    SEPARATOR = '\033[2;37m'

    @staticmethod
    def disable_colors():
        Style.BLUE = ''      # Add BLUE to disable_colors
        Style.INFO = ''
        Style.SUCCESS = ''
        Style.WARNING = ''
        Style.ERROR = ''
        Style.BOLD = ''
        Style.DIM = ''
        Style.RESET = ''
        Style.HEADER = ''
        Style.SEPARATOR = ''

class UI:
    @staticmethod
    def print_banner():
        print(Style.BOLD + get_banner() + Style.RESET)
    
    @staticmethod
    def print_header(text):
        terminal_width = shutil.get_terminal_size().columns
        print(f"\n{Style.HEADER}{text}{Style.RESET}")
        print(f"{Style.SEPARATOR}{'-' * min(len(text), terminal_width)}{Style.RESET}")
    
    @staticmethod
    def print_info(text):
        print(f"{Style.INFO}[INFO]{Style.RESET} {text}")
    
    @staticmethod
    def print_warning(text):
        print(f"{Style.WARNING}[WARNING]{Style.RESET} {text}")
    
    @staticmethod
    def print_error(text):
        print(f"{Style.ERROR}[ERROR]{Style.RESET} {text}")
    
    @staticmethod
    def print_success(text):
        print(f"{Style.SUCCESS}[SUCCESS]{Style.RESET} {text}")
    
    @staticmethod
    def print_progress_bar(current, total, prefix='', suffix='', length=50):
        percent = float(current) * 100 / total
        filled_length = int(length * current // total)
        bar = Style.SUCCESS + Style.PROGRESS_BAR * filled_length + Style.RESET + Style.DIM + Style.PROGRESS_EMPTY * (length - filled_length) + Style.RESET
        print(f"\r{prefix} {bar} {percent:.1f}% {suffix}", end='\r')
        if current == total:
            print()

    @staticmethod
    def print_targets_summary(targets, ports):
        """Print a summary of targets and ports"""
        UI.print_header("Target Summary")
        
        # Calculate display limits based on terminal width
        terminal_width = shutil.get_terminal_size().columns
        max_targets_to_show = min(5, len(targets))
        max_ports_to_show = min(10, len(ports))
        
        print(f"Total targets: {Style.BOLD}{len(targets)}{Style.RESET}")
        if len(targets) > 0:
            target_display = ', '.join(targets[:max_targets_to_show])
            if len(targets) > max_targets_to_show:
                target_display += f", {Style.DIM}+{len(targets) - max_targets_to_show} more...{Style.RESET}"
            print(f"Targets: {target_display}")
        
        print(f"Total ports: {Style.BOLD}{len(ports)}{Style.RESET}")
        if len(ports) > 0:
            port_display = ', '.join(map(str, ports[:max_ports_to_show]))
            if len(ports) > max_ports_to_show:
                port_display += f", {Style.DIM}+{len(ports) - max_ports_to_show} more...{Style.RESET}"
            print(f"Ports: {port_display}")

    @staticmethod
    def clear_line():
        """Clear the current line in the terminal"""
        print('\r\033[K', end='')
    
    @staticmethod
    def print_status(message: str):
        """Print a status message that overwrites the previous line"""
        UI.clear_line()
        print(f"\r{Style.BLUE}[STATUS]{Style.RESET} {message}", end='', flush=True)

    @staticmethod
    def show_stats(stats, duration, method, target, port):
        """Display operation statistics in a different format"""
        last_packets = 0
        last_bytes = 0
        last_time = time.time()

        while True:
            current_time = time.time()
            elapsed = current_time - last_time

            if elapsed >= 1.0:
                current_pps = (stats["packets_sent"] - last_packets) / elapsed
                current_bps = (stats["bytes_sent"] - last_bytes) * 8 / elapsed

                last_packets = stats["packets_sent"]
                last_bytes = stats["bytes_sent"]
                last_time = current_time

                timestamp = time.strftime("%H:%M:%S", time.localtime(current_time))
                pps_display = f"{current_pps:.2f}"
                bps_display = f"{current_bps / (1024 * 1024):.2f} MB"

                print(f"[{timestamp}] {Style.BOLD}Target:{Style.RESET} {target} | {Style.BOLD}Port:{Style.RESET} {port} | {Style.BOLD}Method:{Style.RESET} {method.upper()} | {Style.BOLD}PPS:{Style.RESET} {pps_display} | {Style.BOLD}BPS:{Style.RESET} {bps_display} | {Style.BOLD}Success Rate:{Style.RESET} {stats['successful'] / stats['packets_sent'] * 100 if stats['packets_sent'] > 0 else 0:.0f}%")

            time.sleep(1.0)

class AttackModule:
    def __init__(self, targets: List[str], ports: List[int], skip_prompt: bool = False):
        self.targets = targets
        self.ports = ports
        self.running = False
        self.thread_list: List[threading.Thread] = []
        self.skip_prompt = skip_prompt
        self.stats = {
            "packets_sent": 0,
            "bytes_sent": 0,
            "failures": 0,
            "successful": 0
        }
        self.last_update_time = 0
        self.update_interval = 0.5
        self._stop_event = threading.Event()
        self.thread_list = []
        self._stats_thread = None
    
    def calculate_packet_size(self, threads: int, base_size: int = 1024) -> int:
        """Calculate packet size based on thread count"""
        # Scale packet size with thread count, but cap it at 65000
        scaled_size = base_size * (1 + (threads // 2))
        return min(scaled_size, 65000)
    
    def start(self):
        """Start the operation"""
        self.running = True
        self.start_time = time.time()
        self.last_update_time = time.time()
        self.stats = {"packets_sent": 0, "bytes_sent": 0, "failures": 0, "successful": 0}
        
    def stop(self):
        """Stop the operation gracefully with quick timeout"""
        if not self.running:
            return

        self.running = False
        self._stop_event.set()
        
        # Quick cleanup with 500ms total timeout
        cleanup_timeout = 0.5
        cleanup_start = time.time()
        
        # Stop all attack threads
        for thread in self.thread_list[:]:
            try:
                remaining = max(0, cleanup_timeout - (time.time() - cleanup_start))
                if remaining > 0:
                    thread.join(timeout=remaining)
            except:
                pass
        
        # Clear thread list
        self.thread_list.clear()
        
        # Stop stats thread if exists
        if self._stats_thread and self._stats_thread.is_alive():
            try:
                self._stats_thread.join(timeout=0.2)  # Short timeout for stats thread
            except:
                pass
        
        UI.print_success("Operation stopped successfully")

    def show_stats(self):
        """Show stats in a separate thread"""
        if self._stats_thread and self._stats_thread.is_alive():
            return
            
        self._stats_thread = threading.Thread(target=self._show_stats_loop)
        self._stats_thread.daemon = True
        self._stats_thread.start()

    def monitor_performance(self):
        """Base monitor_performance implementation"""
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
                    
                    # Calculate success rate
                    total = current_stats["packets_sent"]
                    success_rate = int((current_stats["successful"] / total * 100) 
                                     if total > 0 else 0)
                    
                    # Format and print status for each target/port
                    timestamp = time.strftime("%H:%M:%S", time.localtime())
                    for target in self.targets:
                        for port in self.ports:
                            status_line = (
                                f"[{timestamp}] Target: {target} | "
                                f"Port: {port} | PPS: {pps:.2f} | "
                                f"BPS: {mbps:.2f} MB | Success Rate: {success_rate}%"
                            )
                            print(status_line)
                    
                    # Update tracking values
                    last_stats = current_stats.copy()
                    last_update = current_time
                    
            except Exception as e:
                if hasattr(self, 'debug') and self.debug:
                    print(f"Error in performance monitoring: {e}")
                time.sleep(1)

def validate_target(target: str, skip_prompt: bool = False) -> Tuple[Optional[str], bool]:
    """
    Validates and converts URLs/hostnames to IP addresses.
    Returns tuple of (ip_address, is_valid).
    """
    # Remove any protocol prefix and path
    if '://' in target:
        parsed = urlparse(target)
        target = parsed.netloc or parsed.path
    
    # Remove port if present
    if ':' in target:
        target = target.split(':')[0]
    
    try:
        # Try to resolve hostname to IP
        ip = socket.gethostbyname(target)
        
        # Test connectivity
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((ip, 80))
        sock.close()
        
        # Always return True if skip_prompt is enabled
        if skip_prompt:
            return ip, True
            
        return ip, result == 0
            
    except socket.gaierror:
        return None, False
    except socket.error:
        return None, False
