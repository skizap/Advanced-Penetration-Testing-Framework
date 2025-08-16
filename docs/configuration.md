# Configuration Reference - Advanced Penetration Testing Framework

## Overview

The framework uses YAML configuration files to control all aspects of operation. The main configuration file is located at `config/config.yaml`.

## Configuration File Structure

### Complete Configuration Template

```yaml
# =============================================================================
# Advanced Penetration Testing Framework Configuration
# =============================================================================

# Database Configuration
database:
  type: "sqlite"                    # Database type: sqlite, postgresql, mysql
  sqlite:
    path: "data/pentest.db"         # SQLite database file path
  postgresql:
    host: "localhost"               # PostgreSQL host
    port: 5432                      # PostgreSQL port
    database: "pentest"             # Database name
    username: "pentest_user"        # Database username
    password: "secure_password"     # Database password
    pool_size: 10                   # Connection pool size
  mysql:
    host: "localhost"               # MySQL host
    port: 3306                      # MySQL port
    database: "pentest"             # Database name
    username: "pentest_user"        # Database username
    password: "secure_password"     # Database password

# Scanning Configuration
scanning:
  masscan:
    rate: 10000                     # Packets per second (1000-100000)
    timeout: 30                     # Scan timeout in seconds
    ports: "1-65535"                # Port range to scan
    interface: "auto"               # Network interface (auto-detect)
    source_ip: "auto"               # Source IP address
    exclude_ranges:                 # IP ranges to exclude
      - "127.0.0.0/8"
      - "169.254.0.0/16"
      - "224.0.0.0/4"
    max_rate: 100000                # Maximum allowed rate
    retries: 3                      # Number of retries
  
  nmap:
    timing: 4                       # Timing template (0-5)
    scripts:                        # NSE scripts to run
      - "default"
      - "vuln"
    max_retries: 3                  # Maximum scan retries
    host_timeout: 300               # Host timeout in seconds
    script_timeout: 60              # Script timeout in seconds
    version_intensity: 7            # Version detection intensity (0-9)
    os_detection: true              # Enable OS detection
    service_detection: true         # Enable service detection
    aggressive: false               # Enable aggressive scanning
    
  cidr:
    max_hosts: 65536                # Maximum hosts per CIDR block
    exclude_private: false          # Exclude private IP ranges
    exclude_reserved: true          # Exclude reserved IP ranges

# Threading Configuration
threading:
  max_workers: 50                   # Maximum concurrent threads
  scanner_threads: 10               # Scanner thread pool size
  exploit_threads: 5                # Exploit thread pool size
  intelligence_threads: 3           # Intelligence gathering threads
  persistence_threads: 2           # Persistence establishment threads
  timeout: 300                      # Thread timeout in seconds

# Logging Configuration
logging:
  level: "INFO"                     # Log level: DEBUG, INFO, WARNING, ERROR
  file: "logs/framework.log"        # Log file path
  max_size: "100MB"                 # Maximum log file size
  backup_count: 5                   # Number of backup log files
  format: "detailed"                # Log format: simple, detailed, json
  console_output: true              # Enable console logging
  file_output: true                 # Enable file logging
  
# Intelligence Configuration
intelligence:
  nvd:
    api_key: ""                     # NVD API key (optional)
    rate_limit: 50                  # Requests per minute
    cache_duration: 86400           # Cache duration in seconds
    timeout: 30                     # Request timeout
  
  shodan:
    api_key: ""                     # Shodan API key
    rate_limit: 100                 # Requests per minute
    timeout: 30                     # Request timeout
  
  virustotal:
    api_key: ""                     # VirusTotal API key
    rate_limit: 4                   # Requests per minute (free tier)
    timeout: 30                     # Request timeout

# Exploitation Configuration
exploitation:
  timeout: 300                      # Exploit timeout in seconds
  max_attempts: 3                   # Maximum exploit attempts per target
  delay_between_attempts: 5         # Delay between attempts in seconds
  verify_success: true              # Verify successful exploitation
  cleanup_on_failure: true         # Clean up failed attempts
  
  ssh:
    username_list: "data/wordlists/usernames.txt"
    password_list: "data/wordlists/passwords.txt"
    key_files: "data/wordlists/ssh_keys/"
    timeout: 10                     # SSH connection timeout
    max_attempts: 100               # Maximum brute force attempts
  
  smb:
    username_list: "data/wordlists/usernames.txt"
    password_list: "data/wordlists/passwords.txt"
    share_enum: true                # Enumerate SMB shares
    timeout: 10                     # SMB connection timeout
  
  web:
    user_agent: "Mozilla/5.0 (compatible; PenTestFramework/1.0)"
    timeout: 30                     # HTTP request timeout
    follow_redirects: true          # Follow HTTP redirects
    verify_ssl: false               # Verify SSL certificates

# Persistence Configuration
persistence:
  windows:
    methods:                        # Enabled persistence methods
      - "scheduled_tasks"
      - "registry"
      - "services"
      - "wmi"
    cleanup_on_exit: true           # Clean up persistence on exit
    
  linux:
    methods:                        # Enabled persistence methods
      - "systemd"
      - "cron"
      - "init_scripts"
    cleanup_on_exit: true           # Clean up persistence on exit
    
  android:
    methods:                        # Enabled persistence methods
      - "adb_injection"
      - "root_exploit"
    cleanup_on_exit: true           # Clean up persistence on exit

# Data Exfiltration Configuration
exfiltration:
  dns:
    server: "8.8.8.8"               # DNS server for tunneling
    domain: "example.com"           # Domain for DNS tunneling
    chunk_size: 63                  # DNS label size limit
    
  http:
    endpoint: "https://example.com/upload"
    chunk_size: 1048576             # 1MB chunks
    encryption: true                # Encrypt data before exfiltration
    
  tor:
    enabled: false                  # Enable Tor routing
    socks_port: 9050                # Tor SOCKS port
    control_port: 9051              # Tor control port

# Output Configuration
output:
  formats:                          # Enabled output formats
    - "json"
    - "xml"
    - "html"
    - "csv"
  directory: "output/"              # Output directory
  timestamp: true                   # Include timestamp in filenames
  compress: true                    # Compress output files
  
# Cache Configuration
cache:
  enabled: true                     # Enable caching
  directory: "data/cache/"          # Cache directory
  max_size: "1GB"                   # Maximum cache size
  ttl: 86400                        # Time to live in seconds
  
# Security Configuration
security:
  encryption:
    algorithm: "AES-256-GCM"        # Encryption algorithm
    key_derivation: "PBKDF2"        # Key derivation function
  
  stealth:
    randomize_timing: true          # Randomize scan timing
    user_agent_rotation: true       # Rotate user agents
    proxy_rotation: false           # Rotate proxies (requires proxy list)
    
# Development Configuration
development:
  debug_mode: false                 # Enable debug mode
  profiling: false                  # Enable performance profiling
  test_mode: false                  # Enable test mode
  mock_external_tools: false        # Mock external tools for testing
```

## Configuration Sections

### Database Configuration

Controls how the framework stores and retrieves data.

**SQLite (Default):**
```yaml
database:
  type: "sqlite"
  sqlite:
    path: "data/pentest.db"
```

**PostgreSQL:**
```yaml
database:
  type: "postgresql"
  postgresql:
    host: "localhost"
    port: 5432
    database: "pentest"
    username: "pentest_user"
    password: "secure_password"
    pool_size: 10
```

### Scanning Configuration

Controls network scanning behavior.

**Performance Tuning:**
```yaml
scanning:
  masscan:
    rate: 50000          # High-speed scanning
    timeout: 60          # Longer timeout for large networks
  nmap:
    timing: 5            # Aggressive timing
    max_retries: 5       # More retries for accuracy
```

**Stealth Configuration:**
```yaml
scanning:
  masscan:
    rate: 1000           # Slow scanning
    timeout: 300         # Long timeout
  nmap:
    timing: 1            # Paranoid timing
    aggressive: false    # Disable aggressive scanning
```

### Threading Configuration

Controls parallel processing.

**High-Performance Setup:**
```yaml
threading:
  max_workers: 100
  scanner_threads: 20
  exploit_threads: 10
```

**Resource-Constrained Setup:**
```yaml
threading:
  max_workers: 10
  scanner_threads: 3
  exploit_threads: 2
```

## Environment-Specific Configurations

### Production Environment

```yaml
# production.yaml
logging:
  level: "WARNING"
  console_output: false
  
security:
  stealth:
    randomize_timing: true
    user_agent_rotation: true
    
scanning:
  masscan:
    rate: 5000
  nmap:
    timing: 2
```

### Development Environment

```yaml
# development.yaml
logging:
  level: "DEBUG"
  console_output: true
  
development:
  debug_mode: true
  profiling: true
  mock_external_tools: true
  
threading:
  max_workers: 5
```

### Testing Environment

```yaml
# testing.yaml
database:
  type: "sqlite"
  sqlite:
    path: ":memory:"
    
development:
  test_mode: true
  mock_external_tools: true
  
logging:
  level: "DEBUG"
```

## Configuration Management

### Using Multiple Configuration Files

```bash
# Use specific configuration
python main.py --config config/production.yaml 192.168.1.0/24

# Override with environment variables
export PENTEST_CONFIG="config/stealth.yaml"
python main.py 192.168.1.0/24
```

### Configuration Validation

```bash
# Validate configuration syntax
python -c "
import yaml
with open('config/config.yaml') as f:
    config = yaml.safe_load(f)
    print('Configuration is valid')
"

# Test configuration loading
python -c "
from src.core.config import config_manager
print('Configuration loaded successfully')
print(f'Database type: {config_manager.get(\"database.type\")}')
"
```

### Environment Variables

Override configuration values using environment variables:

```bash
# Database configuration
export PENTEST_DATABASE_TYPE="postgresql"
export PENTEST_DATABASE_POSTGRESQL_HOST="db.example.com"

# API keys
export PENTEST_SHODAN_API_KEY="your_shodan_key"
export PENTEST_NVD_API_KEY="your_nvd_key"

# Scanning parameters
export PENTEST_MASSCAN_RATE="25000"
export PENTEST_NMAP_TIMING="3"
```

## Security Considerations

### Sensitive Data Protection

```yaml
# Use environment variables for sensitive data
intelligence:
  shodan:
    api_key: "${SHODAN_API_KEY}"
  nvd:
    api_key: "${NVD_API_KEY}"

database:
  postgresql:
    password: "${DB_PASSWORD}"
```

### File Permissions

```bash
# Secure configuration files
chmod 600 config/config.yaml
chmod 600 config/production.yaml

# Secure API key files
chmod 600 config/api_keys.yaml
```

## Performance Optimization

### Large Network Scanning

```yaml
scanning:
  masscan:
    rate: 100000
    timeout: 120
  cidr:
    max_hosts: 1000000

threading:
  max_workers: 200
  scanner_threads: 50
```

### Memory Optimization

```yaml
cache:
  max_size: "500MB"
  ttl: 3600

database:
  postgresql:
    pool_size: 5

threading:
  max_workers: 20
```

## Troubleshooting Configuration

### Common Configuration Errors

1. **YAML Syntax Errors:**
   - Use spaces, not tabs for indentation
   - Quote strings containing special characters
   - Ensure proper nesting

2. **Invalid Values:**
   - Check numeric ranges (e.g., timing: 0-5)
   - Verify file paths exist
   - Validate API key formats

3. **Permission Issues:**
   - Ensure configuration files are readable
   - Check database file permissions
   - Verify log directory access

### Configuration Testing

```bash
# Test specific configuration sections
python -c "
from src.core.config import config_manager
print('Scanning config:', config_manager.get('scanning'))
print('Database config:', config_manager.get('database'))
"

# Validate all configuration paths
python -c "
import os
from src.core.config import config_manager

# Check file paths
paths = [
    config_manager.get('logging.file'),
    config_manager.get('database.sqlite.path'),
    config_manager.get('cache.directory')
]

for path in paths:
    if path and not os.path.exists(os.path.dirname(path)):
        print(f'Warning: Directory does not exist: {os.path.dirname(path)}')
"
```
