# TentroLink Documentation

<div align="center">
<img src="https://github.com/awiones/TentroLink/blob/main/assets/images/_Qbi9yCfTcG023xENbqkmA.jpg" alt="TentroLink Logo" width="250"/>

**Advanced Network Testing & Security Assessment Toolkit**

</div>

## 🚀 What's New in v0.6.4 (2025-05-15)

- DNS flood now uses randomized query types (A, AAAA, TXT, NS) and multi-level subdomains for better evasion.
- UDPFlooder generates DNS queries with advanced, randomized domain structures (multi-level, regional, service-like, long subdomains).
- The `get_optimized_payload` method fills these templates with random values for each DNS packet, increasing unpredictability.
- Improved warnings and guidance for DNS port 53 usage (now warns about filtering and low success rate).
- Enhanced proxy management and validation.
- See [updates/v0.6.4-update.md](updates/v0.6.4-update.md) for full details.

> **Warning:** Most providers heavily filter DNS (port 53) traffic. DNS floods on port 53 have a low chance of success. For higher impact, consider using port 80 or other less-filtered ports.

---

## Table of Contents

1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Core Concepts](#core-concepts)
4. [Command Line Interface](#command-line-interface)
5. [Attack Modules](#attack-modules)
   - [UDP Flooding](#udp-flooding)
   - [TCP Flooding](#tcp-flooding)
   - [HTTP Flooding](#http-flooding)
   - [TOR2WEB Flooding](#tor2web-flooding)
   - [SYN Flooding](#syn-flooding)
   - [Minecraft Flooding](#minecraft-flooding)
   - [Layer 7 OVH Bypass Flooding](#layer-7-ovh-bypass-flooding)
6. [Proxy Management](#proxy-management)
7. [Target Specification](#target-specification)
8. [Performance Metrics](#performance-metrics)
9. [Advanced Usage](#advanced-usage)
10. [Troubleshooting](#troubleshooting)
11. [Legal Considerations](#legal-considerations)
12. [Technical Reference](#technical-reference)

## Introduction

TentroLink is an advanced network testing toolkit designed for legitimate security testing and network resilience evaluation. The tool has evolved across multiple versions, with each release adding new testing capabilities.

### Purpose

TentroLink helps security professionals:

- Assess network infrastructure resilience
- Identify potential bottlenecks and vulnerabilities
- Test DDoS mitigation systems
- Evaluate network performance under stress

### Legal Disclaimer

**IMPORTANT**: TentroLink is designed and should be used ONLY for authorized network testing, security research, and educational purposes. Usage of this tool against targets without explicit permission is illegal and unethical. The developers of TentroLink assume no liability and are not responsible for any misuse or damage caused by this tool.

## Installation

### Prerequisites

- Python 3.6 or higher
- Administrative/root privileges (for certain operations)
- Network connectivity

### Step-by-Step Installation

```bash
# Clone the repository
git clone https://github.com/awiones/TentroLink.git

# Navigate to the TentroLink directory
cd TentroLink

# Install required packages
pip install -r requirements.txt

# Verify installation
python main.py --version
```

### Dependencies

TentroLink requires the following Python packages:

- `requests`: For HTTP operations and proxy validation
- `scapy`: For low-level packet manipulation (SYN flooding)
- Additional dependencies listed in `requirements.txt`

## Core Concepts

### Architecture

TentroLink is built on a modular architecture consisting of:

1. **Core Engine**: Manages resources and coordinates testing operations
2. **Attack Modules**: Specialized implementations for different testing methodologies
3. **Proxy Manager**: Handles proxy acquisition, validation, and rotation
4. **Metrics Collector**: Gathers and displays real-time performance data

### Design Philosophy

TentroLink follows these design principles:

- **Modularity**: Each attack type is implemented as a separate module
- **Efficiency**: Optimized resource usage for maximum performance
- **Flexibility**: Customizable parameters for different testing scenarios
- **Transparency**: Clear metrics and reporting

## Command Line Interface

TentroLink uses a command-line interface with subcommands for different attack types.

### Basic Syntax

```
python main.py [attack_method] -t [targets] [options]
```

### Global Options

| Option          | Description               | Default |
| --------------- | ------------------------- | ------- |
| `-h, --help`    | Show help message         | -       |
| `--version`     | Show version information  | -       |
| `--no-color`    | Disable colored output    | False   |
| `-y, --yes`     | Skip confirmation prompts | False   |
| `-v, --verbose` | Enable verbose output     | False   |

### Common Attack Options

| Option           | Description                               | Default         |
| ---------------- | ----------------------------------------- | --------------- |
| `-t, --targets`  | Target specification (IP, domain, CIDR)   | _Required_      |
| `-p, --ports`    | Port specification (single, range, named) | Method-specific |
| `-d, --duration` | Duration in seconds                       | 60              |
| `-T, --threads`  | Number of threads                         | Method-specific |

## Attack Modules

TentroLink includes several attack modules, each designed for specific testing methodologies.

### UDP Flooding

The UDP flooding module sends a high volume of UDP packets to target systems to test their ability to handle UDP traffic.

#### Command Syntax

```bash
python main.py udp -t [targets] [options]
```

#### Specific Options

| Option        | Description  | Default |
| ------------- | ------------ | ------- |
| `-p, --ports` | Target ports | 53      |

#### Examples

```bash
# Basic UDP test
python main.py udp -t 192.168.1.1 -p 53 -d 30

# Multiple ports with higher threads
python main.py udp -t 192.168.1.1 -p 53,67 -d 60 -T 5
```

#### Technical Details

The UDP module:

- Generates optimized payloads based on target port
- Uses socket pooling for efficient resource management
- Provides real-time statistics on packets sent and bandwidth

### TCP Flooding

The TCP flooding module establishes multiple TCP connections to target systems to test their connection handling capabilities.

#### Command Syntax

```bash
python main.py tcp -t [targets] [options]
```

#### Specific Options

| Option        | Description  | Default |
| ------------- | ------------ | ------- |
| `-p, --ports` | Target ports | 80,443  |

#### Examples

```bash
# Basic TCP test
python main.py tcp -t 192.168.1.1 -p 80 -d 30

# Testing multiple ports with increased threads
python main.py tcp -t 192.168.1.1 -p 80,443 -d 60 -T 10
```

#### Technical Details

The TCP module:

- Establishes and maintains multiple TCP connections
- Sends data through established connections
- Implements connection pooling for efficiency

### HTTP Flooding

The HTTP flooding module sends HTTP/HTTPS requests to web servers to test their request handling capabilities.

#### Command Syntax

```bash
python main.py http -t [targets] [options]
```

#### Specific Options

| Option        | Description                 | Default |
| ------------- | --------------------------- | ------- |
| `--method`    | HTTP method (GET/POST/HEAD) | GET     |
| `--path`      | Target URL path             | /       |
| `-p, --ports` | Target ports                | 80,443  |

#### Examples

```bash
# Basic HTTP flood test
python main.py http -t example.com -p 80 --method GET -d 60 -T 10

# HTTP POST flood with increased threads
python main.py http -t example.com -p 80 --method POST -d 60 -T 20

# Custom path with HTTPS
python main.py http -t example.com -p 443 --method GET --path /api/v1/test
```

#### Technical Details

The HTTP module:

- Supports GET, POST, and HEAD methods
- Handles both HTTP and HTTPS protocols
- Uses connection pooling for efficient resource usage
- Rotates user agents to avoid detection

### TOR2WEB Flooding

The TOR2WEB flooding module tests targets through TOR2WEB gateways, providing a way to test services anonymously.

#### Command Syntax

```bash
python main.py tor2web -t [targets] [options]
```

#### Specific Options

| Option           | Description         | Default |
| ---------------- | ------------------- | ------- |
| `-d, --duration` | Duration in seconds | 60      |
| `-T, --threads`  | Number of threads   | 5       |

#### Examples

```bash
# Basic TOR2WEB test
python main.py tor2web -t example.onion -d 30 -T 5
```

#### Technical Details

The TOR2WEB module:

- Uses multiple TOR2WEB gateways for request distribution
- Converts .onion addresses to TOR2WEB format
- Rotates user agents to avoid detection
- Provides anonymized testing capabilities

### SYN Flooding

The SYN flooding module tests target systems' ability to handle TCP SYN packet floods.

> **Note**: Currently there is a known issue where the BPS (bytes per second) throughput is lower than expected. This is being investigated and will be fixed in a future update.

#### Command Syntax

```bash
python main.py syn -t [targets] [options]
```

#### Specific Options

| Option           | Description            | Default |
| ---------------- | ---------------------- | ------- |
| `-p, --ports`    | Target ports           | 80      |
| `-T, --threads`  | Number of threads      | 5       |
| `-d, --duration` | Duration in seconds    | 60      |
| `-y, --yes`      | Skip target validation | False   |

#### Examples

```bash
# Basic SYN flood test
python main.py syn -t example.com -p 80 -d 60

# High intensity test with more threads
python main.py syn -t example.com -p 80 -T 100 -d 120

# Multiple ports
python main.py syn -t example.com -p 80,443 -T 50
```

#### Technical Details

The SYN flood module:

- Supports both raw sockets (with root/admin) and normal sockets
- Implements IP spoofing when using raw sockets
- Uses optimized packet generation and sending
- Provides real-time performance metrics
- Features socket pooling for better resource management

#### Current Limitations

1. **BPS Performance**: Currently experiencing lower than expected bytes-per-second throughput. Working on optimization.
2. **Raw Socket Requirements**: Full capabilities (IP spoofing, custom packets) require root/admin privileges
3. **Platform Specific**: Some features may be limited on certain operating systems

### Minecraft Flooding

The Minecraft flooding module tests servers by simulating multiple connection attempts using various protocol versions and ping requests.

#### Command Syntax

```bash
python main.py minecraft -t [targets] [options]
```

#### Specific Options

| Option           | Description         | Default |
| ---------------- | ------------------- | ------- |
| `-p, --ports`    | Target ports        | 25565   |
| `-T, --threads`  | Number of threads   | 5       |
| `-d, --duration` | Duration in seconds | 60      |

#### Technical Details

The Minecraft flood module:

- Supports multiple protocol versions (47-754)
- Simulates server list pings and handshakes
- Uses connection pooling for efficiency
- Provides real-time success rate monitoring

#### Performance Characteristics

- Optimal thread count: 5-10 per target
- Sockets per thread: 100 (configurable)
- Protocol versions: 1.8.x through 1.16.x

#### Examples

```bash
# Basic Minecraft flood test
python main.py minecraft -t mc.example.com -d 60

# High intensity test
python main.py minecraft -t mc.example.com -T 10 -d 120

# Custom port
python main.py minecraft -t mc.example.com -p 25566 -T 5
```

### Layer 7 OVH Bypass Flooding

The OVH bypass implementation features adaptive packet sizing and connection management for testing against systems with OVH protection.

#### Command Syntax

```bash
python main.py ovh -t [targets] [options]
```

#### Development History & Challenges

The OVH bypass implementation went through several iterations:

1. Initial Implementation (v0.5-alpha)

   - Basic functionality achieved
   - High packet sending capability
   - Very low success rate (~10-20%)

   <img src="https://github.com/awiones/TentroLink/blob/main/assets/images/ovh%20bypass.PNG" alt="TEST 1" width="1400"/>

   ```
   [17:49:34] Target: 51.195.234.56 | Port: 22 | Method: OVH | RPS: 28.00 | BPS: 2.73 MB | Success Rate: 20%
   ```

2. First Optimization (v0.5-beta)

   - Improved success rate with smaller packets
   - Thread count sensitivity discovered
   - Optimal performance at 10 threads

   <img src="https://github.com/awiones/TentroLink/blob/main/assets/images/ovh%20byp.PNG" alt="TEST 2" width="1400"/>

   ```
   [18:00:15] Target: 51.195.234.56 | Port: 22 | Method: OVH | RPS: 25.00 | BPS: 2.44 MB | Success Rate: 90%
   ```

3. Thread Scaling Issues
   - Performance degradation above 20 threads
   - Complete failure at 100 threads
   - Root cause: socket pool exhaustion

#### Specific Options

| Option           | Description           | Default  |
| ---------------- | --------------------- | -------- |
| `-t, --targets`  | Target specification  | Required |
| `-p, --ports`    | Target ports          | 80,443   |
| `-T, --threads`  | Number of threads     | 10       |
| `-d, --duration` | Duration in seconds   | 60       |
| `--path`         | URL path for requests | /        |

#### Performance Characteristics

- **Optimal Configuration**:

  - Threads: 10-15
  - Packet Size: Adaptive (8KB-65KB)
  - Connection Pool: 500 max

- **Thread Scaling Behavior**:
  ```
  5 threads:  Low performance (~10 RPS)
  10 threads: Optimal (~25-30 RPS)
  20 threads: Degraded (~15 RPS)
  100 threads: Connection failures (0 RPS)
  ```

#### Implementation Details

1. **Adaptive Packet Sizing**

   - Starting size: 8KB
   - Maximum size: 65KB
   - Dynamic adjustment based on success rate

2. **Connection Management**

   - Socket pooling with max 500 connections
   - Automatic backoff on failures
   - Connection reuse when possible

3. **Port-Specific Optimizations**
   ```python
   port_settings = {
       22: {  # SSH port
           "max_packet_size": 4096,
           "timeout": 1.5
       },
       80: {  # HTTP
           "max_packet_size": 65500,
           "timeout": 3.0
       }
   }
   ```

#### Known Limitations

1. **Thread Count Sensitivity**

   - Best performance: 10-15 threads
   - Fails with high thread counts (>50)
   - Requires manual thread count optimization

2. **Connection Management**

   - Socket pool exhaustion with high thread counts
   - Connection reuse limited by server timeouts

3. **Performance Bottlenecks**
   - Socket creation overhead
   - Connection establishment delays
   - Resource contention at high thread counts

#### Usage Examples

```bash
# Optimal configuration
python main.py ovh -t example.com -T 10 -d 60

# With custom path
python main.py ovh -t example.com -T 10 --path /api/v1

# Multiple ports
python main.py ovh -t example.com -p 80,443 -T 10
```

#### Best Practices

1. **Thread Count**

   - Start with 10 threads
   - Increase gradually if stable
   - Never exceed 50 threads

2. **Duration**

   - Test with short durations first (30s)
   - Increase duration after confirming stability

3. **Monitoring**
   - Watch success rate closely
   - Adjust thread count based on performance
   - Stop if success rate drops below 50%

## Proxy Management

TentroLink includes a sophisticated proxy management system that can acquire, validate, and rotate proxies during testing operations.

### Proxy Sources

- **File-based**: Load proxies from a text file
- **Automatic**: Fetch proxies from public proxy lists

### Usage

```bash
# Automatic proxy acquisition
python main.py udp -t 192.168.1.1 --proxy auto

# Using a proxy list file
python main.py udp -t 192.168.1.1 --proxy proxies.txt

# Adjusting proxy validation threads
python main.py udp -t 192.168.1.1 --proxy auto --proxy-threads 20
```

### Proxy File Format

Proxy files should contain one proxy per line in the following formats:

```
ip:port
http://username:password@ip:port
socks5://ip:port
```

## Target Specification

TentroLink supports flexible target specification formats:

### IP Addresses

- Single IP: `192.168.1.1`
- Multiple IPs: `192.168.1.1,192.168.1.2`
- CIDR notation: `192.168.1.0/24`
- IP ranges: `192.168.1.1-192.168.1.10`

### Domain Names

- Single domain: `example.com`
- Multiple domains: `example.com,example.org`
- Subdomains: `sub.example.com`

### Port Specification

- Single port: `80`
- Multiple ports: `80,443`
- Port ranges: `80-100`
- Named ports: `http,https,dns`

## Performance Metrics

TentroLink provides comprehensive real-time and summary metrics for all testing operations.

### Real-time Metrics

During operation, TentroLink displays:

- Packets/requests sent per second
- Bandwidth utilization (Mbps)
- Success/failure rates
- Progress indicators

### Summary Statistics

After completion, TentroLink provides a summary including:

- Total duration
- Total packets/requests sent
- Total data transferred
- Average and peak performance
- Failure statistics

## Advanced Usage

### Customizing Thread Count

For UDP and TCP flooding, you can adjust the thread count to control intensity:

```bash
python main.py udp -t 192.168.1.1 -p 53 -T 10
```

### Testing Multiple Targets

```bash
# Testing multiple specific targets
python main.py tcp -t 192.168.1.1,192.168.1.2 -p http,https -d 60 -T 20

# Testing a CIDR range
python main.py udp -t 192.168.1.0/24 -p 80-100 -d 120
```

### Combining Attack Methods

For comprehensive testing, you can run multiple attack methods in sequence:

```bash
# Sequential testing with different methods
python main.py udp -t 192.168.1.1 -d 30
python main.py tcp -t 192.168.1.1 -d 30
python main.py http -t 192.168.1.1 -d 30
```

## Troubleshooting

### Common Issues

1. **Permission errors**

   - **Symptom**: "Permission denied" errors
   - **Solution**: Run with administrator/root privileges

   ```bash
   sudo python main.py udp -t 192.168.1.1
   ```

2. **Proxy connection failures**

   - **Symptom**: "Failed to connect through proxy" errors
   - **Solution**: Check proxy validity or try automatic proxy acquisition

   ```bash
   python main.py udp -t 192.168.1.1 --proxy auto
   ```

3. **Performance issues**

   - **Symptom**: Low packets per second or bandwidth
   - **Solution**: Adjust thread count and packet size

   ```bash
   python main.py udp -t 192.168.1.1 -T 5 -s 1024
   ```

## Legal Considerations

### Authorized Testing Only

TentroLink should only be used for:

- Testing your own systems
- Systems you have explicit permission to test
- Educational environments with proper authorization

### Documentation

Always document:

- Written authorization before testing
- Testing scope and parameters
- Testing timeline
- Contact information for emergency stop

### Emergency Stop

All TentroLink operations can be immediately stopped with `Ctrl+C`.

## Technical Reference

### Style and Output

TentroLink uses ANSI color codes for terminal output:

- Blue: General information
- Green: Success messages
- Yellow: Warnings
- Red: Errors
- Bold: Important information
- Dim: Secondary information

To disable colored output:

```bash
python main.py udp -t 192.168.1.1 --no-color
```

### Attack Module Base Class

All attack modules inherit from the `AttackModule` base class, which provides:

- Target and port validation
- Thread management
- Statistics collection
- Graceful shutdown

### Payload Optimization

TentroLink dynamically optimizes payloads based on:

- Target service (port)
- Available system resources
- Network conditions

### Thread Management

Thread allocation is balanced based on:

- Number of targets
- Number of ports
- System capabilities
- Attack method requirements

---

<div align="center">
  <strong>Remember: With great power comes great responsibility. Use TentroLink ethically and legally.</strong>
</div>
