# Advanced Penetration Testing Framework

A comprehensive, autonomous penetration testing framework designed for security research and authorized testing environments.

## ⚠️ Legal Notice

**This tool is for authorized penetration testing and security research only!**

- Ensure you have explicit written permission before scanning any network
- Only use on systems you own or have explicit authorization to test
- Unauthorized access to computer systems is illegal
- Users are responsible for complying with all applicable laws and regulations

## 🚀 Features

### Phase 1: Network Discovery & Scanning
- **CIDR Block Parsing**: Intelligent IP range handling with exclusion filters
- **Masscan Integration**: High-speed port discovery (up to 10M packets/sec)
- **Nmap Service Enumeration**: Detailed service detection and OS fingerprinting
- **Parallel Processing**: Multi-threaded scanning for maximum efficiency

### Phase 2: Vulnerability Intelligence
- **NVD Integration**: Real-time CVE database queries with CVSS scoring
- **Threat Intelligence**: Rapid7 and RiskIQ data correlation
- **Vulnerability Prioritization**: Custom risk scoring algorithms
- **Exploit Matching**: Automatic exploit-to-service correlation

### Phase 3: Exploit Development
- **ROP Chain Generation**: Automated with pwntools integration
- **Process Hollowing**: Cross-platform payload injection
- **Binary Analysis**: Radare2 and angr integration for vulnerability discovery
- **Shellcode Generation**: Multi-architecture with anti-detection features

### Phase 4: Multi-Protocol Exploitation
- **SSH Exploitation**: Brute force, key attacks, and tunneling
- **Shellshock Exploitation**: CVE-2014-6271 targeting
- **DNS Tunneling**: Command & control and data exfiltration
- **SMB Exploitation**: EternalBlue and lateral movement

### Phase 5: Persistence & Exfiltration
- **Windows Persistence**: Scheduled tasks, registry, services, WMI
- **Linux Persistence**: Systemd, cron, init scripts, kernel modules
- **Android Control**: ADB injection and root exploitation
- **Stealth Exfiltration**: DNS-over-TLS, HTTPS onion routing

## 📋 Requirements

### System Requirements
- Python 3.8+
- Linux/macOS (Windows support limited)
- Root/Administrator privileges for some features

### External Tools
- `masscan` - High-speed port scanner
- `nmap` - Network exploration and security auditing
- `radare2` - Reverse engineering framework
- Optional: `tor` for onion routing

## 🛠️ Installation

### 1. Clone Repository
```bash
git clone https://github.com/securitylab/advanced-pentest-framework.git
cd advanced-pentest-framework
```

### 2. Install Dependencies
```bash
# Install Python dependencies
pip install -r requirements.txt

# Install system dependencies (Ubuntu/Debian)
sudo apt update
sudo apt install masscan nmap radare2

# Install system dependencies (macOS)
brew install masscan nmap radare2
```

### 3. Configure Framework
```bash
# Edit configuration file
cp config/config.yaml config/config.yaml.local
nano config/config.yaml.local
```

### 4. Setup Environment
```bash
# Create necessary directories
mkdir -p logs data/wordlists

# Make main script executable
chmod +x main.py
```

## 🎯 Usage

### Basic Scanning
```bash
# Scan single IP
python main.py 192.168.1.100

# Scan CIDR block
python main.py 192.168.1.0/24

# Multiple targets
python main.py 192.168.1.0/24 10.0.0.0/16
```

### Advanced Usage
```bash
# Full exploitation chain
python main.py --mode full 192.168.1.0/24

# Scanning only
python main.py --mode scan --scan-type fast 192.168.1.0/24

# Verbose output
python main.py -v 192.168.1.100

# Custom configuration
python main.py --config custom-config.yaml 192.168.1.0/24
```

### Mode Options
- `scan`: Network discovery and service enumeration only
- `intelligence`: Vulnerability research and correlation
- `exploit`: Automated exploitation attempts
- `persistence`: Establish persistence on compromised hosts
- `full`: Complete exploitation chain (default)

## 📁 Project Structure

```
advanced-pentest-framework/
├── main.py                 # Main entry point
├── requirements.txt        # Python dependencies
├── setup.py               # Installation script
├── config/
│   └── config.yaml        # Framework configuration
├── src/
│   ├── core/              # Core framework components
│   ├── scanner/           # Network scanning modules
│   ├── intelligence/      # Vulnerability intelligence
│   ├── exploits/          # Exploitation modules
│   ├── persistence/       # Persistence mechanisms
│   └── utils/             # Utility functions
├── tests/                 # Unit tests
├── data/                  # Data storage
├── logs/                  # Log files
└── docs/                  # Documentation
```

## ⚙️ Configuration

The framework uses YAML configuration files. Key settings include:

```yaml
# Scanning configuration
scanning:
  masscan:
    rate: 10000              # Packets per second
    timeout: 30              # Scan timeout
  nmap:
    timing: 4                # Timing template (0-5)
    scripts: ["default", "vuln"]

# Database configuration
database:
  type: "sqlite"             # sqlite, postgresql
  sqlite:
    path: "data/pentest.db"

# Threading configuration
threading:
  max_workers: 50            # Maximum concurrent threads
  scanner_threads: 10        # Scanner thread pool size
```

## 🧪 Testing

```bash
# Run unit tests
python -m pytest tests/

# Run with coverage
python -m pytest --cov=src tests/

# Test specific module
python -m pytest tests/test_scanner.py
```

## 📊 Output

The framework generates multiple output formats:

- **Console**: Real-time progress and results
- **Logs**: Detailed execution logs in `logs/`
- **Database**: Structured data storage
- **Reports**: JSON/XML/HTML reports (optional)

## 🔧 Development

### Adding New Modules

1. Create module in appropriate `src/` subdirectory
2. Follow existing patterns and interfaces
3. Add configuration options to `config.yaml`
4. Write unit tests
5. Update documentation

### Contributing

1. Fork the repository
2. Create feature branch
3. Make changes with tests
4. Submit pull request

## 📚 Documentation

- [API Documentation](docs/api.md)
- [Module Development Guide](docs/development.md)
- [Configuration Reference](docs/configuration.md)
- [Troubleshooting Guide](docs/troubleshooting.md)

## 🛡️ Security Considerations

- Always run in isolated environments
- Use VPNs/proxies for operational security
- Implement proper access controls
- Regular security updates
- Monitor for detection/blocking

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Acknowledgments

- Masscan by Robert Graham
- Nmap by Gordon Lyon
- Pwntools by Gallopsled
- Radare2 by pancake
- All contributors and security researchers

---

**Remember: With great power comes great responsibility. Use this tool ethically and legally.**