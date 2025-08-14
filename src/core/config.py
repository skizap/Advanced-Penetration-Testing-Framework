"""
Configuration Management Module
Handles loading and managing framework configuration
"""

import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass
from loguru import logger


@dataclass
class DatabaseConfig:
    """Database configuration settings"""
    type: str
    sqlite_path: Optional[str] = None
    host: Optional[str] = None
    port: Optional[int] = None
    database: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None


@dataclass
class ScanningConfig:
    """Scanning configuration settings"""
    masscan_rate: int
    masscan_timeout: int
    masscan_retries: int
    masscan_ports: str
    nmap_timing: int
    nmap_scripts: list
    nmap_max_parallel: int
    nmap_timeout: int
    cidr_max_hosts: int
    cidr_exclude_ranges: list


@dataclass
class ExploitationConfig:
    """Exploitation configuration settings"""
    max_concurrent: int
    timeout: int
    retry_attempts: int
    ssh_max_attempts: int
    smb_timeout: int
    web_timeout: int
    web_user_agent: str


class ConfigManager:
    """Manages framework configuration"""

    def __init__(self, config_path: str = "config/config.yaml"):
        self.config_path = Path(config_path)
        self.config: Dict[str, Any] = {}
        self._load_config()

    def _load_config(self) -> None:
        """Load configuration from YAML file"""
        try:
            if not self.config_path.exists():
                logger.error(f"Configuration file not found: {self.config_path}")
                raise FileNotFoundError(f"Configuration file not found: {self.config_path}")

            with open(self.config_path, 'r') as f:
                self.config = yaml.safe_load(f)

            logger.info(f"Configuration loaded from {self.config_path}")

        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            raise

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by key (supports dot notation)"""
        keys = key.split('.')
        value = self.config

        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default

        return value

    def get_database_config(self) -> DatabaseConfig:
        """Get database configuration"""
        db_config = self.get('database', {})
        db_type = db_config.get('type', 'sqlite')

        if db_type == 'sqlite':
            return DatabaseConfig(
                type=db_type,
                sqlite_path=db_config.get('sqlite', {}).get('path', 'data/pentest.db')
            )
        elif db_type == 'postgresql':
            pg_config = db_config.get('postgresql', {})
            return DatabaseConfig(
                type=db_type,
                host=pg_config.get('host', 'localhost'),
                port=pg_config.get('port', 5432),
                database=pg_config.get('database', 'pentest'),
                username=pg_config.get('username'),
                password=pg_config.get('password')
            )
        else:
            raise ValueError(f"Unsupported database type: {db_type}")

    def get_scanning_config(self) -> ScanningConfig:
        """Get scanning configuration"""
        scanning = self.get('scanning', {})
        masscan = scanning.get('masscan', {})
        nmap = scanning.get('nmap', {})
        cidr = scanning.get('cidr', {})

        return ScanningConfig(
            masscan_rate=masscan.get('rate', 10000),
            masscan_timeout=masscan.get('timeout', 30),
            masscan_retries=masscan.get('retries', 3),
            masscan_ports=masscan.get('ports', '1-65535'),
            nmap_timing=nmap.get('timing', 4),
            nmap_scripts=nmap.get('scripts', ['default']),
            nmap_max_parallel=nmap.get('max_parallel', 50),
            nmap_timeout=nmap.get('timeout', 300),
            cidr_max_hosts=cidr.get('max_hosts', 65536),
            cidr_exclude_ranges=cidr.get('exclude_ranges', [])
        )

    def get_exploitation_config(self) -> ExploitationConfig:
        """Get exploitation configuration"""
        exploitation = self.get('exploitation', {})
        ssh = exploitation.get('ssh', {})
        smb = exploitation.get('smb', {})
        web = exploitation.get('web', {})

        return ExploitationConfig(
            max_concurrent=exploitation.get('max_concurrent', 10),
            timeout=exploitation.get('timeout', 60),
            retry_attempts=exploitation.get('retry_attempts', 3),
            ssh_max_attempts=ssh.get('max_attempts', 100),
            smb_timeout=smb.get('timeout', 30),
            web_timeout=web.get('timeout', 30),
            web_user_agent=web.get('user_agent', 'Mozilla/5.0 (compatible; SecurityScanner/1.0)')
        )

    def update_config(self, key: str, value: Any) -> None:
        """Update configuration value"""
        keys = key.split('.')
        config = self.config

        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]

        config[keys[-1]] = value
        logger.info(f"Configuration updated: {key} = {value}")

    def save_config(self) -> None:
        """Save configuration to file"""
        try:
            with open(self.config_path, 'w') as f:
                yaml.dump(self.config, f, default_flow_style=False, indent=2)
            logger.info(f"Configuration saved to {self.config_path}")
        except Exception as e:
            logger.error(f"Failed to save configuration: {e}")
            raise


# Global configuration instance
config_manager = ConfigManager()