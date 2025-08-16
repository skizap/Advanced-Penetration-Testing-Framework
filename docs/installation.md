# Installation Guide - Advanced Penetration Testing Framework

## Overview

This guide provides detailed installation instructions for the Advanced Penetration Testing Framework across different operating systems and environments.

## System Requirements

### Minimum Requirements
- **OS**: Linux (Ubuntu 18.04+, CentOS 7+), macOS 10.14+
- **Python**: 3.8 or higher
- **RAM**: 4GB minimum, 8GB recommended
- **Storage**: 10GB free space
- **Network**: Internet connection for dependency installation

### Recommended Requirements
- **OS**: Ubuntu 20.04+ or CentOS 8+
- **Python**: 3.9 or 3.10
- **RAM**: 16GB for large network scans
- **Storage**: 50GB for extensive wordlists and data
- **CPU**: Multi-core processor for parallel scanning

## Pre-Installation Checklist

### 1. Verify Python Installation
```bash
python3 --version
# Should show Python 3.8 or higher
```

### 2. Check System Privileges
```bash
# Verify sudo access
sudo whoami
# Should return 'root'
```

### 3. Update System Packages
```bash
# Ubuntu/Debian
sudo apt update && sudo apt upgrade -y

# CentOS/RHEL
sudo yum update -y

# macOS
brew update && brew upgrade
```

## Installation Methods

### Method 1: Standard Installation (Recommended)

#### Step 1: Clone Repository
```bash
# Clone from GitHub
git clone https://github.com/securitylab/advanced-pentest-framework.git
cd advanced-pentest-framework

# Verify repository structure
ls -la
```

#### Step 2: Create Virtual Environment
```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Verify activation
which python
# Should show path to venv/bin/python
```

#### Step 3: Install Python Dependencies
```bash
# Upgrade pip
pip install --upgrade pip

# Install framework dependencies
pip install -r requirements.txt

# Verify installation
pip list | grep -E "(nmap|masscan|pwntools)"
```

#### Step 4: Install System Dependencies

**Ubuntu/Debian:**
```bash
# Update package list
sudo apt update

# Install core tools
sudo apt install -y masscan nmap

# Install optional tools
sudo apt install -y radare2 tor proxychains

# Install development tools
sudo apt install -y build-essential python3-dev
```

**CentOS/RHEL:**
```bash
# Enable EPEL repository
sudo yum install -y epel-release

# Install core tools
sudo yum install -y masscan nmap

# Install optional tools
sudo yum install -y radare2 tor

# Install development tools
sudo yum groupinstall -y "Development Tools"
sudo yum install -y python3-devel
```

**macOS:**
```bash
# Install Homebrew if not present
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install core tools
brew install masscan nmap

# Install optional tools
brew install radare2 tor

# Install development tools
xcode-select --install
```

#### Step 5: Framework Setup
```bash
# Create necessary directories
mkdir -p logs data/wordlists data/cache

# Set permissions
chmod +x main.py
chmod +x install.sh

# Copy configuration template
cp config/config.yaml config/config.yaml.local

# Initialize database
python demo_working.py
```

### Method 2: Automated Installation

#### Using Install Script
```bash
# Make install script executable
chmod +x install.sh

# Run automated installation
./install.sh

# Follow prompts for configuration
```

#### Install Script Features
- Automatic dependency detection
- Platform-specific package installation
- Virtual environment setup
- Configuration file generation
- Database initialization
- Permission configuration

### Method 3: Docker Installation

#### Prerequisites
```bash
# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Add user to docker group
sudo usermod -aG docker $USER
newgrp docker
```

#### Build and Run
```bash
# Build Docker image
docker build -t pentest-framework .

# Run container
docker run -it --rm \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/logs:/app/logs \
  pentest-framework
```

## Post-Installation Configuration

### 1. Verify Installation
```bash
# Test basic functionality
python main.py --help

# Run component tests
python demo_working.py

# Check external tools
masscan --version
nmap --version
```

### 2. Configure Framework
```bash
# Edit configuration file
nano config/config.yaml.local

# Key settings to review:
# - Database configuration
# - Scanning parameters
# - Thread limits
# - API keys
```

### 3. Set Up API Keys (Optional)
```yaml
# Add to config/config.yaml.local
api_keys:
  shodan: "your_shodan_api_key"
  virustotal: "your_virustotal_key"
  nvd: "your_nvd_api_key"
```

### 4. Configure Permissions
```bash
# Set capabilities for masscan (avoids sudo requirement)
sudo setcap cap_net_raw+ep $(which masscan)

# Verify capabilities
getcap $(which masscan)
```

## Platform-Specific Instructions

### Ubuntu 20.04/22.04
```bash
# Install additional dependencies
sudo apt install -y python3-pip python3-venv git

# Install security tools
sudo apt install -y nikto dirb gobuster

# Configure firewall (if needed)
sudo ufw allow out 53
sudo ufw allow out 80
sudo ufw allow out 443
```

### CentOS 8/Rocky Linux
```bash
# Enable PowerTools repository
sudo dnf config-manager --set-enabled powertools

# Install Python development
sudo dnf install -y python3-pip python3-devel

# Install additional tools
sudo dnf install -y git wget curl
```

### macOS Big Sur/Monterey
```bash
# Install Python via Homebrew
brew install python@3.9

# Link Python
brew link python@3.9

# Install additional tools
brew install wget curl git
```

### Kali Linux
```bash
# Update Kali repositories
sudo apt update

# Framework is compatible with Kali's tools
# Most dependencies already installed

# Install missing Python packages
pip3 install -r requirements.txt
```

## Troubleshooting Installation

### Common Issues

#### 1. Python Version Conflicts
```bash
# Check available Python versions
ls /usr/bin/python*

# Use specific Python version
python3.9 -m venv venv
```

#### 2. Permission Errors
```bash
# Fix ownership
sudo chown -R $USER:$USER advanced-pentest-framework/

# Fix permissions
chmod -R 755 advanced-pentest-framework/
```

#### 3. Package Installation Failures
```bash
# Update package manager
sudo apt update  # Ubuntu
sudo yum update   # CentOS

# Clear package cache
sudo apt clean   # Ubuntu
sudo yum clean all # CentOS
```

#### 4. Virtual Environment Issues
```bash
# Remove and recreate venv
rm -rf venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

#### 5. Masscan Installation Issues
```bash
# Ubuntu: Install from source if package fails
git clone https://github.com/robertdavidgraham/masscan
cd masscan
make
sudo make install
```

### Verification Commands
```bash
# Check Python environment
python --version
pip list

# Check system tools
which masscan nmap
masscan --version
nmap --version

# Check framework
python main.py --help
python demo_working.py
```

### Performance Optimization

#### 1. System Limits
```bash
# Increase file descriptor limits
echo "* soft nofile 65535" | sudo tee -a /etc/security/limits.conf
echo "* hard nofile 65535" | sudo tee -a /etc/security/limits.conf

# Increase network buffer sizes
echo "net.core.rmem_max = 134217728" | sudo tee -a /etc/sysctl.conf
echo "net.core.wmem_max = 134217728" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

#### 2. Framework Configuration
```yaml
# Optimize for performance in config.yaml
threading:
  max_workers: 100
  scanner_threads: 20

scanning:
  masscan:
    rate: 50000
    timeout: 60
```

## Uninstallation

### Remove Framework
```bash
# Deactivate virtual environment
deactivate

# Remove framework directory
rm -rf advanced-pentest-framework/

# Remove system packages (optional)
sudo apt remove masscan nmap radare2  # Ubuntu
sudo yum remove masscan nmap radare2  # CentOS
brew uninstall masscan nmap radare2   # macOS
```

### Clean Up
```bash
# Remove configuration files
rm -rf ~/.pentest-framework

# Remove logs (if stored globally)
sudo rm -rf /var/log/pentest-framework
```

## Next Steps

After successful installation:

1. **Read the User Guide**: `docs/user-guide.md`
2. **Review Configuration**: `docs/configuration.md`
3. **Run Basic Tests**: `python demo_working.py`
4. **Start with Simple Scans**: `python main.py --help`
5. **Check Troubleshooting**: `docs/troubleshooting.md`

## Support

If you encounter issues during installation:

1. Check the troubleshooting section above
2. Review system requirements
3. Verify all dependencies are installed
4. Check GitHub issues for known problems
5. Run diagnostic commands provided in this guide
