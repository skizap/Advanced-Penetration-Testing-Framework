"""
CIDR Block Parser Module
Handles CIDR notation parsing, IP range generation, and validation
"""

import ipaddress
import re
from typing import List, Set, Iterator, Union, Optional
from dataclasses import dataclass
from loguru import logger
from core.config import config_manager


@dataclass
class IPRange:
    """Represents an IP range with metadata"""
    network: Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
    start_ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
    end_ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
    total_hosts: int
    is_private: bool
    is_reserved: bool


class CIDRParser:
    """CIDR notation parser and IP range generator"""

    def __init__(self):
        self.config = config_manager.get_scanning_config()
        self.max_hosts = self.config.cidr_max_hosts
        self.exclude_ranges = self._parse_exclude_ranges()

        # Common private/reserved ranges
        self.private_ranges = [
            ipaddress.IPv4Network('10.0.0.0/8'),
            ipaddress.IPv4Network('172.16.0.0/12'),
            ipaddress.IPv4Network('192.168.0.0/16'),
            ipaddress.IPv4Network('127.0.0.0/8'),  # Loopback
            ipaddress.IPv4Network('169.254.0.0/16'),  # Link-local
            ipaddress.IPv4Network('224.0.0.0/4'),  # Multicast
            ipaddress.IPv4Network('240.0.0.0/4'),  # Reserved
        ]

        # IPv6 private/reserved ranges
        self.private_ranges_v6 = [
            ipaddress.IPv6Network('::1/128'),  # Loopback
            ipaddress.IPv6Network('fc00::/7'),  # Unique local
            ipaddress.IPv6Network('fe80::/10'),  # Link-local
            ipaddress.IPv6Network('ff00::/8'),  # Multicast
        ]

        logger.info(f"CIDR Parser initialized with max_hosts={self.max_hosts}")

    def _parse_exclude_ranges(self) -> List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]:
        """Parse exclude ranges from configuration"""
        exclude_ranges = []

        for range_str in self.config.cidr_exclude_ranges:
            try:
                network = ipaddress.ip_network(range_str, strict=False)
                exclude_ranges.append(network)
                logger.debug(f"Added exclude range: {network}")
            except ValueError as e:
                logger.warning(f"Invalid exclude range '{range_str}': {e}")

        return exclude_ranges