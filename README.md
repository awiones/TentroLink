# TentroLink

![Version](https://img.shields.io/badge/version-0.1-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Python](https://img.shields.io/badge/python-3.6+-yellow)

TentroLink is an advanced network testing toolkit designed for legitimate security testing and network resilience evaluation. It provides a comprehensive set of tools for assessing network infrastructure through various methods.

## ⚠️ Legal Disclaimer

TentroLink is designed and should be used **ONLY** for authorized network testing, security research, and educational purposes. Usage of this tool against targets without explicit permission is illegal and unethical. The developers of TentroLink assume no liability and are not responsible for any misuse or damage caused by this tool.

**You are responsible for your actions. Use this tool responsibly and legally.**

## 🔧 Key Features

- **Methods**
  - UDP Flooding with enhanced DNS attack techniques
  - TCP Flooding with optimized connection handling
  - SYN Flooding (coming soon)
  - HTTP Flooding (coming soon)
  - TOR2WEB Flooding


## 🚀 Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/awiones/TentroLink.git

# 2. Navigate to the TentroLink directory
cd TentroLink

# 3. Install required packages
pip install -r requirements.txt

# 4. Run a basic test
python main.py udp -t 192.168.1.1 -p 53 -d 30
```

## 💻 Usage Guide

### Basic Syntax

```
python main.py [attack_method] -t [targets] [options]
```

### Available Testing Methods

Method | Description
------ | -----------
`udp`  | UDP flood operation
`tcp`  | TCP flood operation
`syn`  | SYN flood operation (coming soon)
`http` | HTTP flood operation (coming soon)
`tor2web` | TOR2WEB flood operation

### Common Options

Option | Description | Default
------ | ----------- | -------
`-t, --targets` | Target specification | *Required*
`-p, --ports` | Port specification | Method-specific
`-d, --duration` | Duration in seconds | 60
`-T, --threads` | Number of threads | Method-specific
`-v, --verbose` | Enable verbose output | False
`--no-color` | Disable colored output | False
`--proxy` | Use proxies (file path or "auto") | None
`--proxy-threads` | Threads for proxy validation | 10

### Method-Specific Examples

#### UDP Testing

```bash
python main.py udp -t 192.168.1.1 -p 53 -s 1024 -d 60 -T 5
```
Additional options:
- `-s, --size`: Size of each UDP packet in bytes (default: 1024)

#### TCP Testing

```bash
python main.py tcp -t 192.168.1.1 -p 80,443 -d 60 -T 10
```

#### Using Proxies

```bash
# Automatic proxy acquisition
python main.py udp -t 192.168.1.1 --proxy auto

# Using a proxy list file
python main.py udp -t 192.168.1.1 --proxy proxies.txt
```

## 📊 Example Scenarios

### Testing a Network Range

```bash
python main.py udp -t 192.168.1.0/24 -p 80-100 -d 120
```

### Multiple Targets with HTTP/HTTPS Ports

```bash
python main.py tcp -t 192.168.1.1,192.168.1.2 -p http,https -d 60 -T 20
```

## 📸 Screenshots

![Test Statistics](assets/images/test%20stat.PNG)
*Example of network test statistics output*

## 📝 Development Roadmap

- [x] UDP Flooding with optimized payloads
- [x] TCP Flooding with connection pool management
- [x] Proxy support with caching
- [x] Performance monitoring and statistics
- [ ] SYN Flooding implementation
- [ ] HTTP Flooding with customizable requests
- [ ] HTTPS/SSL support with certificate validation bypass
- [ ] Layer 7 DDoS protection bypass techniques
- [ ] Distributed attack coordination

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🤝 Contributing

Contributions, issues, and feature requests are welcome. Feel free to check the issues page if you want to contribute.

---

**Remember**: With great power comes great responsibility. Use TentroLink ethically and legally.
