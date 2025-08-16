# Advanced Penetration Testing Framework - User Guide

## Table of Contents
1. [Installation](#installation)
2. [Quick Start](#quick-start)
3. [Command Line Interface](#command-line-interface)
4. [Usage Examples](#usage-examples)
5. [Configuration](#configuration)
6. [Input/Output Formats](#inputoutput-formats)
7. [Troubleshooting](#troubleshooting)

## Installation

### Prerequisites

**System Requirements:**
- Python 3.8 or higher
- Linux or macOS (Windows support limited)
- Root/Administrator privileges for some features
- Minimum 4GB RAM, 10GB disk space

**External Dependencies:**
- `masscan` - High-speed port scanner
- `nmap` - Network exploration and security auditing
- `radare2` - Reverse engineering framework (optional)
- `tor` - For onion routing (optional)

### Step 1: Clone Repository

```bash
git clone https://github.com/securitylab/advanced-pentest-framework.git
cd advanced-pentest-framework
```

### Step 2: Install System Dependencies

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install masscan nmap radare2 tor
```

**CentOS/RHEL:**
```bash
sudo yum install epel-release
sudo yum install masscan nmap radare2 tor
```

**macOS:**
```bash
brew install masscan nmap radare2 tor
```

### Step 3: Install Python Dependencies

**Using pip:**
```bash
# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

**Using conda:**
```bash
conda create -n pentest python=3.9
conda activate pentest
pip install -r requirements.txt
```

### Step 4: Setup Framework

```bash
# Create necessary directories
mkdir -p logs data/wordlists

# Make main script executable
chmod +x main.py

# Copy and customize configuration
cp config/config.yaml config/config.yaml.local
```

### Step 5: Verify Installation

```bash
# Test basic functionality
python main.py --help

# Run demo to verify core components
python demo_working.py
```

## Quick Start

### Basic Network Scan

```bash
# Scan single IP
python main.py 192.168.1.100

# Scan CIDR block
python main.py 192.168.1.0/24

# Multiple targets
python main.py 192.168.1.0/24 10.0.0.0/16
```

### Scan with Specific Mode

```bash
# Fast scan only
python main.py --mode scan --scan-type fast 192.168.1.0/24

# Full exploitation chain
python main.py --mode full 192.168.1.0/24

# Verbose output
python main.py -v 192.168.1.100
```

## Command Line Interface

### Syntax

```
python main.py [OPTIONS] TARGETS...
```

### Required Arguments

- `TARGETS` - One or more target IPs or CIDR blocks to scan

### Optional Arguments

| Option | Choices | Default | Description |
|--------|---------|---------|-------------|
| `--mode` | scan, intelligence, exploit, persistence, full | full | Operation mode |
| `--scan-type` | fast, full, stealth | full | Scan type |
| `--config` | FILE | config/config.yaml | Configuration file path |
| `--output` | FILE | - | Output file for results |
| `--verbose, -v` | - | - | Enable verbose logging |
| `--help, -h` | - | - | Show help message |

### Operation Modes

**scan**: Network discovery and service enumeration only
- Performs CIDR parsing and IP enumeration
- Runs Masscan for fast port discovery
- Runs Nmap for detailed service detection
- Stores results in database

**intelligence**: Vulnerability research and correlation
- Loads previous scan results
- Queries NVD database for CVE information
- Correlates services with known vulnerabilities
- Generates risk assessment

**exploit**: Automated exploitation attempts
- Loads vulnerability data
- Attempts exploitation using available modules
- Documents successful compromises
- Maintains session information

**persistence**: Establish persistence on compromised hosts
- Loads compromised host information
- Deploys persistence mechanisms
- Configures backdoors and access methods
- Implements stealth techniques

**full**: Complete exploitation chain (default)
- Runs all phases sequentially
- Provides comprehensive assessment
- Generates complete report

### Scan Types

**fast**: Quick port discovery
- Uses Masscan with high packet rate
- Scans common ports only
- Minimal service enumeration

**full**: Comprehensive scanning (default)
- Complete port range scanning
- Detailed service detection
- OS fingerprinting
- Script scanning

**stealth**: Low-profile scanning
- Slow scan rates
- Randomized timing
- Minimal footprint

## Usage Examples

### Basic Examples

```bash
# Simple scan with default settings
python main.py 192.168.1.100

# Scan multiple targets
python main.py 192.168.1.0/24 10.0.0.1-10

# Fast scan for quick discovery
python main.py --scan-type fast 192.168.1.0/24
```

### Advanced Examples

```bash
# Full exploitation chain with verbose output
python main.py --mode full --verbose 192.168.1.0/24

# Stealth scan with custom config
python main.py --scan-type stealth --config stealth.yaml 192.168.1.0/24

# Intelligence gathering only
python main.py --mode intelligence 192.168.1.100

# Save results to file
python main.py --output results.json 192.168.1.0/24
```

### Target Formats

**Single IP:**
```bash
python main.py 192.168.1.100
python main.py 10.0.0.1
```

**CIDR Blocks:**
```bash
python main.py 192.168.1.0/24
python main.py 10.0.0.0/16
python main.py 172.16.0.0/12
```

**Multiple Targets:**
```bash
python main.py 192.168.1.0/24 10.0.0.0/16 172.16.1.100
```

## Configuration

### Configuration File Structure

The framework uses YAML configuration files located in `config/config.yaml`:

```yaml
# Scanning Configuration
scanning:
  masscan:
    rate: 10000              # Packets per second
    timeout: 30              # Scan timeout in seconds
    ports: "1-65535"         # Port range
  nmap:
    timing: 4                # Timing template (0-5)
    scripts: ["default", "vuln"]
    max_retries: 3

# Database Configuration
database:
  type: "sqlite"             # sqlite, postgresql, mysql
  sqlite:
    path: "data/pentest.db"
  postgresql:
    host: "localhost"
    port: 5432
    database: "pentest"
    username: "user"
    password: "pass"

# Threading Configuration
threading:
  max_workers: 50            # Maximum concurrent threads
  scanner_threads: 10        # Scanner thread pool size
  exploit_threads: 5         # Exploit thread pool size

# Logging Configuration
logging:
  level: "INFO"              # DEBUG, INFO, WARNING, ERROR
  file: "logs/framework.log"
  max_size: "100MB"
  backup_count: 5

# API Keys (optional)
api_keys:
  shodan: "your_shodan_key"
  virustotal: "your_vt_key"
  nvd: "your_nvd_key"
```

### Custom Configuration

```bash
# Create custom configuration
cp config/config.yaml config/custom.yaml

# Edit configuration
nano config/custom.yaml

# Use custom configuration
python main.py --config config/custom.yaml 192.168.1.0/24
```

## Input/Output Formats

### Input Formats

**Command Line Targets:**
- Single IP: `192.168.1.100`
- CIDR notation: `192.168.1.0/24`
- IP ranges: `192.168.1.1-254`
- Hostnames: `example.com`

**Configuration Files:**
- YAML format for framework configuration
- JSON format for custom scan profiles
- Text files for target lists

### Output Formats

**Console Output:**
- Real-time progress indicators
- Colored status messages
- Summary statistics
- Error messages and warnings

**Log Files:**
- Detailed execution logs in `logs/`
- Structured JSON logs for parsing
- Separate logs for each component

**Database Storage:**
- SQLite database by default
- PostgreSQL/MySQL support
- Structured data for analysis
- Historical scan data

**Report Generation:**
- JSON format for programmatic access
- XML format for integration
- HTML reports for presentation
- CSV exports for spreadsheets

### Database Schema

The framework stores data in the following main tables:

- `scan_sessions` - Scan metadata and configuration
- `hosts` - Discovered hosts and basic information
- `ports` - Open ports and service information
- `services` - Detailed service enumeration
- `vulnerabilities` - Identified vulnerabilities
- `exploits` - Exploitation attempts and results

## Troubleshooting

### Common Issues

**1. "Masscan is required but not available"**
```bash
# Install masscan
sudo apt install masscan  # Ubuntu/Debian
brew install masscan      # macOS

# Verify installation
masscan --version
```

**2. "Permission denied" errors**
```bash
# Run with sudo for privileged operations
sudo python main.py 192.168.1.0/24

# Or adjust capabilities
sudo setcap cap_net_raw+ep /usr/bin/masscan
```

**3. "Database connection failed"**
```bash
# Check database configuration
cat config/config.yaml

# Verify database file permissions
ls -la data/pentest.db

# Reset database
rm data/pentest.db
python demo_working.py
```

**4. "Import errors" or missing modules**
```bash
# Reinstall dependencies
pip install -r requirements.txt

# Check virtual environment
which python
pip list
```

**5. "Network unreachable" errors**
```bash
# Check network connectivity
ping 192.168.1.1

# Verify routing
ip route show

# Check firewall rules
sudo iptables -L
```

### Debug Mode

Enable verbose logging for detailed troubleshooting:

```bash
# Enable verbose output
python main.py --verbose 192.168.1.100

# Check log files
tail -f logs/framework.log

# Run demo for component testing
python demo_working.py
```

### Performance Tuning

**For large networks:**
```yaml
# Increase thread counts
threading:
  max_workers: 100
  scanner_threads: 20

# Adjust scan rates
scanning:
  masscan:
    rate: 50000
```

**For stealth operations:**
```yaml
# Reduce scan rates
scanning:
  masscan:
    rate: 1000
  nmap:
    timing: 1
```

### Getting Help

1. Check the troubleshooting section above
2. Review log files in `logs/` directory
3. Run demo scripts to isolate issues
4. Check GitHub issues for known problems
5. Contact support with detailed error messages

### System Requirements Check

```bash
# Check Python version
python --version

# Check available memory
free -h

# Check disk space
df -h

# Verify external tools
masscan --version
nmap --version
```
