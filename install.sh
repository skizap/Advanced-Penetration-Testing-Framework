#!/bin/bash
# Advanced Penetration Testing Framework Installation Script

set -e

echo "🚀 Advanced Penetration Testing Framework - Installation Script"
echo "=============================================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root for system dependencies
check_root() {
    if [[ $EUID -eq 0 ]]; then
        print_warning "Running as root. This is not recommended for Python package installation."
        print_warning "Consider running without sudo and using --user flag for pip."
    fi
}

# Detect OS
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command -v apt-get &> /dev/null; then
            OS="ubuntu"
        elif command -v yum &> /dev/null; then
            OS="centos"
        elif command -v pacman &> /dev/null; then
            OS="arch"
        else
            OS="linux"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
    else
        OS="unknown"
    fi
    print_status "Detected OS: $OS"
}

# Install system dependencies
install_system_deps() {
    print_status "Installing system dependencies..."

    case $OS in
        "ubuntu")
            sudo apt update
            sudo apt install -y python3 python3-pip python3-venv masscan nmap radare2 git
            ;;
        "centos")
            sudo yum update -y
            sudo yum install -y python3 python3-pip masscan nmap radare2 git
            ;;
        "arch")
            sudo pacman -Sy --noconfirm python python-pip masscan nmap radare2 git
            ;;
        "macos")
            if ! command -v brew &> /dev/null; then
                print_error "Homebrew not found. Please install Homebrew first:"
                print_error "https://brew.sh/"
                exit 1
            fi
            brew install python masscan nmap radare2 git
            ;;
        *)
            print_warning "Unknown OS. Please install dependencies manually:"
            print_warning "- Python 3.8+"
            print_warning "- pip"
            print_warning "- masscan"
            print_warning "- nmap"
            print_warning "- radare2"
            ;;
    esac
}

# Create virtual environment
create_venv() {
    print_status "Creating Python virtual environment..."

    if [ ! -d "venv" ]; then
        python3 -m venv venv
        print_status "Virtual environment created"
    else
        print_status "Virtual environment already exists"
    fi

    # Activate virtual environment
    source venv/bin/activate
    print_status "Virtual environment activated"
}

# Install Python dependencies
install_python_deps() {
    print_status "Installing Python dependencies..."

    # Upgrade pip
    pip install --upgrade pip

    # Install requirements
    if [ -f "requirements.txt" ]; then
        pip install -r requirements.txt
        print_status "Python dependencies installed"
    else
        print_error "requirements.txt not found"
        exit 1
    fi
}

# Setup directories
setup_directories() {
    print_status "Setting up directories..."

    mkdir -p logs data/wordlists docs/reports

    # Create basic wordlists if they don't exist
    if [ ! -f "data/wordlists/users.txt" ]; then
        cat > data/wordlists/users.txt << EOF
admin
administrator
root
user
guest
test
demo
EOF
        print_status "Created basic users wordlist"
    fi

    if [ ! -f "data/wordlists/passwords.txt" ]; then
        cat > data/wordlists/passwords.txt << EOF
password
123456
admin
root
guest
test
demo
password123
admin123
EOF
        print_status "Created basic passwords wordlist"
    fi
}

# Set permissions
set_permissions() {
    print_status "Setting file permissions..."

    chmod +x main.py
    chmod +x install.sh

    # Make sure log directory is writable
    chmod 755 logs
    chmod 755 data
}

# Test installation
test_installation() {
    print_status "Testing installation..."

    # Test basic imports
    python3 -c "
import sys
sys.path.insert(0, 'src')
import yaml
from pathlib import Path
print('✅ Basic modules working')

# Test config loading
config_path = Path('config/config.yaml')
if config_path.exists():
    with open(config_path) as f:
        config = yaml.safe_load(f)
    print('✅ Configuration loaded')
else:
    print('❌ Configuration file missing')
    sys.exit(1)
"

    if [ $? -eq 0 ]; then
        print_status "✅ Installation test passed"
    else
        print_error "❌ Installation test failed"
        exit 1
    fi
}

# Main installation function
main() {
    echo
    print_status "Starting installation process..."
    echo

    check_root
    detect_os

    # Ask for confirmation
    read -p "Do you want to install system dependencies? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        install_system_deps
    else
        print_warning "Skipping system dependencies. Make sure you have:"
        print_warning "- Python 3.8+"
        print_warning "- masscan, nmap, radare2"
    fi

    create_venv
    install_python_deps
    setup_directories
    set_permissions
    test_installation

    echo
    print_status "🎉 Installation completed successfully!"
    echo
    print_status "To get started:"
    print_status "1. Activate virtual environment: source venv/bin/activate"
    print_status "2. Edit configuration: nano config/config.yaml"
    print_status "3. Run framework: python3 main.py --help"
    echo
    print_warning "⚠️  Remember: Only use on authorized networks!"
    echo
}

# Run main function
main "$@"