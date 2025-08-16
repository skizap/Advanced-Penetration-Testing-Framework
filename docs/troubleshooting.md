# Troubleshooting Guide - Advanced Penetration Testing Framework

## Quick Diagnostic Commands

Before diving into specific issues, run these commands to gather system information:

```bash
# Framework status
python main.py --help
python demo_working.py

# System information
python --version
pip list | grep -E "(nmap|masscan|pwntools)"
which masscan nmap

# Configuration check
cat config/config.yaml | head -20
ls -la data/ logs/

# Recent logs
tail -50 logs/framework.log
```

## Common Issues and Solutions

### 1. Installation Issues

#### "Masscan is required but not available"

**Symptoms:**
```
ERROR | scanner.masscan_scanner:_verify_masscan:64 - Masscan verification failed
ERROR | Framework error: Masscan is required but not available
```

**Solutions:**

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install masscan

# If package not found, install from source:
git clone https://github.com/robertdavidgraham/masscan
cd masscan
make
sudo make install
```

**CentOS/RHEL:**
```bash
sudo yum install epel-release
sudo yum install masscan

# Alternative: compile from source
sudo yum groupinstall "Development Tools"
git clone https://github.com/robertdavidgraham/masscan
cd masscan
make
sudo make install
```

**macOS:**
```bash
brew install masscan

# If Homebrew not installed:
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
brew install masscan
```

#### "Permission denied" errors

**Symptoms:**
```
PermissionError: [Errno 13] Permission denied: '/usr/bin/masscan'
```

**Solutions:**
```bash
# Option 1: Set capabilities (recommended)
sudo setcap cap_net_raw+ep $(which masscan)
sudo setcap cap_net_raw+ep $(which nmap)

# Option 2: Run with sudo
sudo python main.py 192.168.1.0/24

# Option 3: Add user to appropriate groups
sudo usermod -a -G netdev $USER
newgrp netdev
```

#### Python module import errors

**Symptoms:**
```
ModuleNotFoundError: No module named 'python_nmap'
ImportError: cannot import name 'X' from 'Y'
```

**Solutions:**
```bash
# Verify virtual environment
source venv/bin/activate
which python

# Reinstall dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Force reinstall problematic packages
pip uninstall python-nmap
pip install python-nmap==1.5.1

# Check for conflicting packages
pip list | grep nmap
```

### 2. Runtime Issues

#### Database connection failures

**Symptoms:**
```
sqlalchemy.exc.OperationalError: (sqlite3.OperationalError) unable to open database file
DetachedInstanceError: Instance is not bound to a Session
```

**Solutions:**
```bash
# Check database file permissions
ls -la data/pentest.db
chmod 664 data/pentest.db

# Recreate database
rm data/pentest.db
python demo_working.py

# Check database configuration
grep -A 10 "database:" config/config.yaml

# Test database connectivity
python -c "
from src.core.database.manager import DatabaseManager
db = DatabaseManager()
print('Database connection successful')
"
```

#### Network connectivity issues

**Symptoms:**
```
Network is unreachable
Connection timed out
No route to host
```

**Solutions:**
```bash
# Check network connectivity
ping -c 3 8.8.8.8
ping -c 3 192.168.1.1

# Check routing table
ip route show
netstat -rn

# Check firewall rules
sudo iptables -L
sudo ufw status

# Test with simple target
python main.py --mode scan 127.0.0.1
```

#### Memory and performance issues

**Symptoms:**
```
MemoryError: Unable to allocate array
Process killed (OOM)
Scan taking extremely long time
```

**Solutions:**
```bash
# Check available memory
free -h
top -p $(pgrep -f python)

# Reduce thread counts in config
nano config/config.yaml
# Set lower values:
# threading:
#   max_workers: 10
#   scanner_threads: 5

# Use fast scan mode
python main.py --scan-type fast 192.168.1.0/24

# Scan smaller subnets
python main.py 192.168.1.0/28  # Instead of /24
```

### 3. Configuration Issues

#### Invalid configuration file

**Symptoms:**
```
yaml.scanner.ScannerError: while scanning for the next token
KeyError: 'scanning'
```

**Solutions:**
```bash
# Validate YAML syntax
python -c "import yaml; yaml.safe_load(open('config/config.yaml'))"

# Reset to default configuration
cp config/config.yaml.backup config/config.yaml

# Check for common YAML issues:
# - Incorrect indentation
# - Missing colons
# - Unquoted special characters

# Example fix:
sed -i 's/\t/  /g' config/config.yaml  # Replace tabs with spaces
```

#### API key issues

**Symptoms:**
```
HTTP 401: Unauthorized
API rate limit exceeded
Invalid API key format
```

**Solutions:**
```bash
# Check API key format
grep -A 5 "api_keys:" config/config.yaml

# Test API keys manually
curl -H "X-API-Key: YOUR_KEY" "https://api.shodan.io/shodan/host/8.8.8.8"

# Remove invalid keys temporarily
# Comment out problematic API keys in config.yaml
```

### 4. Scanning Issues

#### Masscan fails to start

**Symptoms:**
```
masscan: FAIL: failed to detect IP of interface
masscan: can't open adapter
```

**Solutions:**
```bash
# Check network interfaces
ip addr show
ifconfig

# Specify interface in config
nano config/config.yaml
# Add:
# scanning:
#   masscan:
#     interface: "eth0"

# Run with specific interface
sudo masscan -p80 192.168.1.0/24 --interface eth0
```

#### Nmap script errors

**Symptoms:**
```
NSE: failed to initialize the script engine
Script scan aborted due to host timeout
```

**Solutions:**
```bash
# Update Nmap scripts
sudo nmap --script-updatedb

# Disable problematic scripts
nano config/config.yaml
# Modify:
# scanning:
#   nmap:
#     scripts: ["default"]  # Remove "vuln"

# Test Nmap manually
nmap -sV -sC 127.0.0.1
```

#### False positive/negative results

**Symptoms:**
- Services detected incorrectly
- Missing open ports
- Incorrect OS detection

**Solutions:**
```bash
# Increase scan accuracy
nano config/config.yaml
# Modify:
# scanning:
#   nmap:
#     timing: 3  # Slower but more accurate
#     max_retries: 5

# Use different scan techniques
python main.py --scan-type full 192.168.1.100

# Verify manually
nmap -sS -sV -O 192.168.1.100
masscan -p1-65535 192.168.1.100 --rate=1000
```

### 5. Logging and Debug Issues

#### No log output

**Symptoms:**
- Empty log files
- Missing debug information
- Silent failures

**Solutions:**
```bash
# Enable verbose logging
python main.py --verbose 192.168.1.100

# Check log configuration
grep -A 10 "logging:" config/config.yaml

# Create log directory
mkdir -p logs
chmod 755 logs

# Test logging manually
python -c "
from src.utils.logger import setup_logging
from loguru import logger
setup_logging()
logger.info('Test log message')
"
```

#### Log file permissions

**Symptoms:**
```
PermissionError: [Errno 13] Permission denied: 'logs/framework.log'
```

**Solutions:**
```bash
# Fix log directory permissions
sudo chown -R $USER:$USER logs/
chmod -R 755 logs/

# Check disk space
df -h

# Rotate large log files
find logs/ -name "*.log" -size +100M -exec mv {} {}.old \;
```

### 6. Advanced Troubleshooting

#### Debug mode activation

```bash
# Enable maximum verbosity
export PYTHONPATH="$PWD/src"
python -c "
import logging
logging.basicConfig(level=logging.DEBUG)
from core.config import config_manager
print('Config loaded:', config_manager.config)
"

# Run with Python debugger
python -m pdb main.py --verbose 127.0.0.1
```

#### Component isolation testing

```bash
# Test individual components
python -c "from src.scanner.cidr_parser import CIDRParser; print('CIDR parser OK')"
python -c "from src.core.database.manager import DatabaseManager; print('Database OK')"
python -c "from src.scanner.masscan_scanner import MasscanScanner; print('Masscan OK')"

# Test with minimal configuration
cat > test_config.yaml << EOF
database:
  type: sqlite
  sqlite:
    path: test.db
scanning:
  masscan:
    rate: 1000
threading:
  max_workers: 5
EOF

python main.py --config test_config.yaml --mode scan 127.0.0.1
```

#### System resource monitoring

```bash
# Monitor during scan
# Terminal 1:
python main.py --verbose 192.168.1.0/28

# Terminal 2:
watch -n 1 'ps aux | grep python; free -h; netstat -i'

# Check for resource leaks
lsof -p $(pgrep -f "python main.py")
```

### 7. Environment-Specific Issues

#### Virtual environment problems

```bash
# Verify virtual environment
echo $VIRTUAL_ENV
which python pip

# Recreate virtual environment
deactivate
rm -rf venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

#### Docker-related issues

```bash
# Check Docker permissions
docker run hello-world

# Rebuild container
docker build --no-cache -t pentest-framework .

# Run with debugging
docker run -it --rm pentest-framework /bin/bash
```

## Getting Additional Help

### Diagnostic Information Collection

When reporting issues, include:

```bash
# System information
uname -a
python --version
pip --version

# Framework information
python main.py --help
ls -la config/ data/ logs/

# Error logs
tail -100 logs/framework.log

# Configuration (sanitized)
grep -v -E "(password|key|secret)" config/config.yaml
```

### Log Analysis

```bash
# Search for specific errors
grep -i error logs/framework.log
grep -i "failed\|exception\|traceback" logs/framework.log

# Check recent activity
tail -f logs/framework.log

# Analyze patterns
awk '/ERROR/ {print $0}' logs/framework.log | sort | uniq -c
```

### Performance Profiling

```bash
# Profile memory usage
python -m memory_profiler main.py 127.0.0.1

# Profile execution time
python -m cProfile -o profile.stats main.py 127.0.0.1
python -c "import pstats; pstats.Stats('profile.stats').sort_stats('cumulative').print_stats(10)"
```

### Community Resources

1. **GitHub Issues**: Check existing issues and solutions
2. **Documentation**: Review all documentation files
3. **Demo Scripts**: Use demo scripts to isolate problems
4. **Configuration Examples**: Reference working configurations
5. **Log Analysis**: Use provided log analysis commands

### Emergency Recovery

If the framework becomes completely unusable:

```bash
# Reset to clean state
git checkout -- .
rm -rf venv data/*.db logs/*.log
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python demo_working.py
```
