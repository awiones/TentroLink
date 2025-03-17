# TentroLink

<div align="center">  

<img src="https://github.com/awiones/TentroLink/blob/main/assets/images/_Qbi9yCfTcG023xENbqkmA.jpg" alt="TentroLink Logo" width="250"/>  

**Advanced Network Testing & Security Assessment Toolkit**  

<p>  
  <a href="https://github.com/awiones/TentroLink">
    <img src="https://img.shields.io/badge/version-0.1-blue?style=for-the-badge">
  </a>  
  <a href="LICENSE">
    <img src="https://img.shields.io/badge/license-MIT-green?style=for-the-badge">
  </a>  
  <a href="https://www.python.org/">
    <img src="https://img.shields.io/badge/python-3.6+-yellow?style=for-the-badge&logo=python">
  </a>  
</p>  

</div>

## 📋 Overview

TentroLink is an advanced network testing toolkit designed for legitimate security testing and network resilience evaluation. It provides a comprehensive set of tools for assessing network infrastructure through various methodologies, helping security professionals identify and address potential vulnerabilities.

## ⚠️ Legal Disclaimer

> **IMPORTANT**: TentroLink is designed and should be used ONLY for authorized network testing, security research, and educational purposes. Usage of this tool against targets without explicit permission is illegal and unethical. The developers of TentroLink assume no liability and are not responsible for any misuse or damage caused by this tool.
>
> **You are responsible for your actions. Use this tool responsibly and legally.**

## 🛠️ Key Features

| Feature | Description |
|---------|-------------|
| 🔹 UDP Flooding | Enhanced DNS attack techniques with optimized payloads |
| 🔹 TCP Flooding | Optimized connection handling with pool management |
| 🔹 TOR2WEB Flooding | Anonymous penetration testing capabilities |
| 🔹 SYN Flooding | Advanced SYN packet management *(coming soon)* |
| 🔹 HTTP Flooding | Customizable HTTP request crafting *(coming soon)* |


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

| Method | Description | Default Port |
|--------|-------------|--------------|
| `udp` | UDP flood operation with customizable packet sizes | 53 |
| `tcp` | TCP flood operation with connection pooling | 80 |
| `syn` | SYN flood operation *(coming soon)* | 80 |
| `http` | HTTP flood operation *(coming soon)* | 80 |

### Common Options

| Option | Description | Default |
|--------|-------------|---------|
| `-t, --targets` | Target specification (IP, domain, CIDR) | *Required* |
| `-p, --ports` | Port specification (single, range, named) | Method-specific |
| `-d, --duration` | Duration in seconds | 60 |
| `-T, --threads` | Number of threads | Method-specific |
| `-v, --verbose` | Enable verbose output | False |
| `--no-color` | Disable colored output | False |
| `--proxy` | Use proxies (file path or "auto") | None |
| `--proxy-threads` | Threads for proxy validation | 10 |

### Quick Examples

```bash
# Basic UDP test
python main.py udp -t 192.168.1.1 -p 53 -d 30

# TCP test with multiple ports
python main.py tcp -t 192.168.1.1 -p 80,443 -d 60 -T 10

# Test with automatic proxy acquisition
python main.py udp -t 192.168.1.1 --proxy auto
```

## 📊 Advanced Usage

### UDP Testing

```bash
# Custom packet size
python main.py udp -t 192.168.1.1 -p 53 -s 1024 -d 60 -T 5
```

**Additional options:**
- `-s, --size`: Size of each UDP packet in bytes (default: 1024)

### TCP Testing

```bash
# Testing multiple ports with increased threads
python main.py tcp -t 192.168.1.1 -p 80,443 -d 60 -T 10
```

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

## 📸 Screenshots

<div align="center">
  <img src="assets/images/test%20stat.PNG" alt="Test Statistics" width="80%"/>
  <p><em>Example of network test statistics output</em></p>
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

## 📝 Development Roadmap

| Feature | Status | Target Release |
|---------|--------|----------------|
| UDP Flooding | ✅ Completed | v0.1 |
| TCP Flooding | ✅ Completed | v0.1 |
| Proxy support | ✅ Completed | v0.1 |
| Performance monitoring | ✅ Completed | v0.1 |
| SYN Flooding | 🔄 In Progress | v0.2 |
| HTTP Flooding | 🔄 In Progress | v0.2 |
| HTTPS/SSL support | 📅 Planned | v0.3 |
| Layer 7 DDoS protection bypass | 📅 Planned | v0.3 |
| Distributed attack coordination | 📅 Planned | v0.4 |

## 🐛 Troubleshooting

### Common Issues

1. **Permission errors**: Run with administrator/root privileges for low-level network operations
2. **Proxy connection failures**: Check network connectivity and proxy validity
3. **Performance issues**: Reduce thread count on systems with limited resources

### Debugging

Enable verbose output for detailed logging:

```bash
python main.py udp -t 192.168.1.1 -v
```

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

- [Network Penetration Testing Methodology](https://example.com)
- [TCP/IP Protocol Suite RFC](https://www.rfc-editor.org/)
- [Python Socket Programming](https://docs.python.org/3/library/socket.html)

---

<div align="center">
  <strong>Remember: With great power comes great responsibility. Use TentroLink ethically and legally.</strong>
</div>
