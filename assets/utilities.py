import sys
import time
import threading
import shutil
from typing import List

def get_banner():
    """Return the TentroLink banner ASCII art"""
    banner = """
__ __|             |               
   |   _ \  __ \   __|   _ \    __|
   |   __/  |   |  |    (   |  |   
  _| \___| _|  _| \__| \___/  _|   
  Tentor V0.1
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

class AttackModule:
    def __init__(self, targets: List[str], ports: List[int], **kwargs):
        self.targets = targets
        self.ports = ports
        self.running = False
        self.start_time = 0
        self.thread_list: List[threading.Thread] = []
        self.stats = {
            "packets_sent": 0,
            "bytes_sent": 0,
            "failures": 0,
            "successful": 0  # Add success tracking
        }
        self.last_update_time = 0
        self.update_interval = 0.5

    def start(self):
        """Start the operation"""
        self.running = True
        self.start_time = time.time()
        self.last_update_time = time.time()
        self.stats = {"packets_sent": 0, "bytes_sent": 0, "failures": 0, "successful": 0}
        
    def stop(self):
        """Stop the operation"""
        self.running = False
        
        # Show a spinner while waiting for threads to finish
        spinner = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        i = 0
        
        for thread in self.thread_list:
            if thread.is_alive():
                sys.stdout.write(f"\r{Style.INFO}{spinner[i % len(spinner)]}{Style.RESET} Gracefully shutting down... ")
                sys.stdout.flush()
                i += 1
                thread.join(timeout=1)
        
        print(f"\r{Style.SUCCESS}✓{Style.RESET} Operation complete                      ")
            
    def show_stats(self):
        """Display operation statistics"""
        last_packets = 0
        last_bytes = 0
        last_time = time.time()
        
        terminal_width = shutil.get_terminal_size().columns
        bar_length = min(40, terminal_width - 40)  # Adjust based on terminal width
        
        while self.running:
            current_time = time.time()
            elapsed = current_time - self.start_time
            
            if current_time - self.last_update_time >= self.update_interval:
                self.last_update_time = current_time
                
                # Calculate current rates
                time_diff = current_time - last_time
                if time_diff > 0:
                    current_pps = (self.stats["packets_sent"] - last_packets) / time_diff
                    current_mbps = ((self.stats["bytes_sent"] - last_bytes) * 8) / (time_diff * 1000 * 1000)
                    
                    # Update last values
                    last_packets = self.stats["packets_sent"]
                    last_bytes = self.stats["bytes_sent"]
                    last_time = current_time
                    
                    # Overall statistics
                    total_mbps = (self.stats["bytes_sent"] * 8) / (elapsed * 1000 * 1000) if elapsed > 0 else 0
                    total_pps = self.stats["packets_sent"] / elapsed if elapsed > 0 else 0
                    
                    # Create a simple progress bar for duration
                    if hasattr(self, 'duration'):
                        progress = min(elapsed / self.duration, 1.0)
                        filled_length = int(bar_length * progress)
                        bar = Style.SUCCESS + Style.PROGRESS_BAR * filled_length + Style.RESET + Style.DIM + Style.PROGRESS_EMPTY * (bar_length - filled_length) + Style.RESET
                        duration_display = f" {bar} {progress*100:.1f}% "
                    else:
                        duration_display = ""
                    
                    # Calculate success rate
                    total_attempts = self.stats["packets_sent"]
                    success_rate = (self.stats["successful"] / total_attempts * 100) if total_attempts > 0 else 0
                    
                    status_line = (
                        f"\r{Style.BOLD}[Runtime: {elapsed:.1f}s]{Style.RESET}{duration_display}"
                        f"| {Style.INFO}Packets:{Style.RESET} {self.stats['packets_sent']:,} "
                        f"| {Style.INFO}Success Rate:{Style.RESET} {success_rate:.1f}% "
                        f"| {Style.INFO}Current:{Style.RESET} {current_mbps:.2f} Mbps ({current_pps:.0f} pps) "
                        f"| {Style.INFO}Avg:{Style.RESET} {total_mbps:.2f} Mbps"
                    )
                    
                    # Truncate status line if it's too long for the terminal
                    if len(status_line) > terminal_width:
                        status_line = status_line[:terminal_width-3] + "..."
                    
                    sys.stdout.write(status_line)
                    sys.stdout.flush()
            
            time.sleep(0.1)
