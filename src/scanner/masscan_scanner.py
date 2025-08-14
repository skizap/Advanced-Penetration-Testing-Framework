"""
Masscan Integration Module
High-speed port scanning using Masscan
"""

import asyncio
import json
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict, Set, Optional, Tuple, AsyncIterator
from dataclasses import dataclass, asdict
from loguru import logger
from core.config import config_manager


@dataclass
class PortResult:
    """Represents a discovered open port"""
    ip: str
    port: int
    protocol: str
    state: str
    timestamp: Optional[str] = None
    banner: Optional[str] = None


@dataclass
class ScanResult:
    """Represents scan results for a host"""
    ip: str
    ports: List[PortResult]
    scan_time: float
    total_ports_scanned: int


class MasscanScanner:
    """High-speed port scanner using Masscan"""

    def __init__(self):
        self.config = config_manager.get_scanning_config()
        self.rate = self.config.masscan_rate
        self.timeout = self.config.masscan_timeout
        self.retries = self.config.masscan_retries
        self.ports = self.config.masscan_ports

        # Verify masscan is installed
        self._verify_masscan()

        logger.info(f"Masscan scanner initialized - rate: {self.rate} pps, timeout: {self.timeout}s")

    def _verify_masscan(self) -> None:
        """Verify that masscan is installed and accessible"""
        try:
            result = subprocess.run(['masscan', '--version'],
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                version = result.stdout.strip().split('\n')[0]
                logger.info(f"Masscan found: {version}")
            else:
                raise FileNotFoundError("Masscan not found or not working")
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError) as e:
            logger.error(f"Masscan verification failed: {e}")
            raise RuntimeError("Masscan is required but not available. Install with: sudo apt install masscan")

    async def scan_ips(self, ip_list: List[str],
                      ports: Optional[str] = None,
                      rate: Optional[int] = None) -> List[ScanResult]:
        """
        Scan list of IPs for open ports

        Args:
            ip_list: List of IP addresses to scan
            ports: Port specification (default from config)
            rate: Scan rate in packets per second (default from config)

        Returns:
            List of scan results
        """
        if not ip_list:
            logger.warning("No IPs provided for scanning")
            return []

        ports = ports or self.ports
        rate = rate or self.rate

        logger.info(f"Starting Masscan on {len(ip_list)} IPs, ports: {ports}, rate: {rate} pps")

        # Split large IP lists into chunks for better performance
        chunk_size = min(1000, len(ip_list))  # Process up to 1000 IPs at once
        all_results = []

        for i in range(0, len(ip_list), chunk_size):
            chunk = ip_list[i:i + chunk_size]
            logger.info(f"Scanning chunk {i//chunk_size + 1}/{(len(ip_list)-1)//chunk_size + 1} ({len(chunk)} IPs)")

            chunk_results = await self._scan_chunk(chunk, ports, rate)
            all_results.extend(chunk_results)

        logger.info(f"Masscan completed. Found {sum(len(r.ports) for r in all_results)} open ports")
        return all_results