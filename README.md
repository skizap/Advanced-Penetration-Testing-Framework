# Advanced Penetration Testing Framework

A comprehensive, autonomous penetration testing framework designed for security research and authorized testing environments.

## ⚠️ Legal Notice

**This tool is for authorized penetration testing and security research only!**

- Ensure you have explicit written permission before scanning any network
- Only use on systems you own or have explicit authorization to test
- Unauthorized access to computer systems is illegal
- Users are responsible for complying with all applicable laws and regulations

## 🚀 Features

- **Network Discovery**: Intelligent IP range scanning with CIDR block parsing
- **High-Speed Port Scanning**: Masscan integration for rapid port discovery
- **Service Enumeration**: Detailed service detection and OS fingerprinting with Nmap
- **Vulnerability Intelligence**: Real-time CVE database queries and threat correlation
- **Exploit Matching**: Automatic exploit-to-service correlation and prioritization
- **Multi-threaded Processing**: Parallel scanning for maximum efficiency
- **Comprehensive Reporting**: Multiple output formats with detailed analysis

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

### Quick Installation

```bash
# 1. Clone repository
git clone https://github.com/skizap/advanced-pentest-framework.git
cd advanced-pentest-framework

# 2. Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Install system dependencies
# Ubuntu/Debian:
sudo apt update && sudo apt install masscan nmap

# macOS:
brew install masscan nmap

# 5. Setup framework
mkdir -p logs data/wordlists
chmod +x main.py

# 6. Verify installation
python main.py --help
```

### Detailed Installation

For comprehensive installation instructions including troubleshooting, see:
📖 **[Installation Guide](docs/installation.md)**

## 🎯 Usage

### Quick Start

```bash
# Basic network scan
python main.py 192.168.1.0/24

# Fast discovery scan
python main.py --mode scan --scan-type fast 192.168.1.0/24

# Verbose output for debugging
python main.py --verbose 192.168.1.100
```

### Command Line Options

```
python main.py [OPTIONS] TARGETS...

Required:
  TARGETS                    Target IPs or CIDR blocks

Options:
  --mode {scan,intelligence,exploit,persistence,full}
                            Operation mode (default: full)
  --scan-type {fast,full,stealth}
                            Scan type (default: full)
  --config FILE             Configuration file path
  --output FILE             Output file for results
  --verbose, -v             Enable verbose logging
  --help, -h                Show help message
```

### Operation Modes

| Mode | Description |
|------|-------------|
| `scan` | Network discovery and service enumeration only |
| `intelligence` | Vulnerability research and correlation |
| `exploit` | Automated exploitation attempts |
| `persistence` | Establish persistence on compromised hosts |
| `full` | Complete exploitation chain (default) |

### Comprehensive Usage Guide

For detailed usage examples, configuration options, and advanced features:
📖 **[User Guide](docs/user-guide.md)**

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

The framework uses YAML configuration files for customization:

```yaml
# Basic configuration example
scanning:
  masscan:
    rate: 10000              # Packets per second
    timeout: 30              # Scan timeout
  nmap:
    timing: 4                # Timing template (0-5)

database:
  type: "sqlite"             # Database type
  sqlite:
    path: "data/pentest.db"  # Database file path

threading:
  max_workers: 50            # Maximum concurrent threads
```

### Configuration Files

- `config/config.yaml` - Main configuration file
- `config/config.yaml.local` - Local customizations (recommended)

For complete configuration reference and examples:
📖 **[Configuration Guide](docs/configuration.md)**

## 🧪 Testing

### Framework Testing

```bash
# Run unit tests
python -m pytest tests/

# Test with coverage
python -m pytest --cov=src tests/

# Test CLI functionality
python main.py --help
python main.py --mode intelligence 127.0.0.1
```

⚠️ **External Dependencies**: Requires `masscan` and `nmap` for full functionality

## 📊 Output & Results

### Output Formats

- **Console**: Real-time progress with colored output and progress indicators
- **Logs**: Detailed execution logs in `logs/framework.log`
- **Database**: Structured data storage in SQLite/PostgreSQL
- **Reports**: JSON/XML/HTML reports (configurable)

### Example Output

```
🎯 Penetration Testing Framework Demo
==================================================
1. 🗄️ Database System
   ✅ Database initialized (SQLite)

2. 📋 Creating Penetration Test Session
   ✅ Created scan session: 'Corporate Network Assessment'

3. 🔍 Network Discovery Results
   ✅ Discovered: 192.168.1.10 (web-server.corp.local) - Linux
   ✅ Discovered: 192.168.1.20 (db-server.corp.local) - Linux

4. 📊 Summary
   📈 Hosts Discovered: 4
   📈 Open Ports: 11
   📈 Services Identified: 8
   🚨 Vulnerabilities Found: 4 (1 critical)
```

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

### User Documentation
- 📖 **[User Guide](docs/user-guide.md)** - Comprehensive usage instructions
- 🛠️ **[Installation Guide](docs/installation.md)** - Detailed setup instructions
- ⚙️ **[Configuration Reference](docs/configuration.md)** - Complete configuration options
- 🔧 **[Troubleshooting Guide](docs/troubleshooting.md)** - Common issues and solutions

### Quick Reference
- **CLI Help**: `python main.py --help`
- **Configuration**: `config/config.yaml`
- **Logs**: `logs/framework.log`

## 🔧 Troubleshooting

### Common Issues

**"Masscan is required but not available"**
```bash
# Install masscan
sudo apt install masscan  # Ubuntu/Debian
brew install masscan      # macOS
```

**Permission denied errors**
```bash
# Set capabilities (recommended)
sudo setcap cap_net_raw+ep $(which masscan)

# Or run with sudo
sudo python main.py 192.168.1.0/24
```

**Module import errors**
```bash
# Verify virtual environment
source venv/bin/activate
pip install -r requirements.txt
```

For comprehensive troubleshooting:
📖 **[Troubleshooting Guide](docs/troubleshooting.md)**

## 🛡️ Security Considerations

- **Authorization**: Ensure explicit written permission before scanning
- **Isolation**: Always run in isolated/controlled environments
- **Stealth**: Use VPNs/proxies for operational security
- **Access Control**: Implement proper authentication and authorization
- **Updates**: Keep framework and dependencies updated
- **Monitoring**: Watch for detection and blocking mechanisms

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