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

    def parse_cidr(self, cidr_string: str) -> List[str]:
        """
        Parse CIDR notation and return list of IP addresses

        Args:
            cidr_string: CIDR notation string (e.g., "192.168.1.0/24")

        Returns:
            List of IP addresses as strings
        """
        try:
            # Handle single IP addresses
            if '/' not in cidr_string:
                ip = ipaddress.ip_address(cidr_string)
                if self._is_ip_allowed(ip):
                    return [str(ip)]
                else:
                    logger.warning(f"IP {ip} is in exclude list or reserved range")
                    return []

            # Parse network
            network = ipaddress.ip_network(cidr_string, strict=False)

            # Check if network is too large
            if network.num_addresses > self.max_hosts:
                logger.error(f"Network {network} has {network.num_addresses} hosts, "
                           f"exceeds maximum of {self.max_hosts}")
                raise ValueError(f"Network too large: {network.num_addresses} > {self.max_hosts}")

            # Generate IP list
            ip_list = []
            for ip in network.hosts():
                if self._is_ip_allowed(ip):
                    ip_list.append(str(ip))

            logger.info(f"Generated {len(ip_list)} IPs from {cidr_string}")
            return ip_list

        except ValueError as e:
            logger.error(f"Invalid CIDR notation '{cidr_string}': {e}")
            raise

    def parse_multiple_cidrs(self, cidr_list: List[str]) -> List[str]:
        """
        Parse multiple CIDR blocks and return combined IP list

        Args:
            cidr_list: List of CIDR notation strings

        Returns:
            Combined list of unique IP addresses
        """
        all_ips = set()

        for cidr in cidr_list:
            try:
                ips = self.parse_cidr(cidr)
                all_ips.update(ips)
            except Exception as e:
                logger.error(f"Failed to parse CIDR '{cidr}': {e}")
                continue

        ip_list = sorted(list(all_ips), key=ipaddress.ip_address)
        logger.info(f"Combined {len(cidr_list)} CIDR blocks into {len(ip_list)} unique IPs")

        return ip_list

    def _is_ip_allowed(self, ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]) -> bool:
        """
        Check if IP address is allowed (not in exclude list or reserved ranges)

        Args:
            ip: IP address to check

        Returns:
            True if IP is allowed, False otherwise
        """
        # Check exclude ranges from config
        for exclude_range in self.exclude_ranges:
            if ip in exclude_range:
                return False

        # Check private/reserved ranges for IPv4
        if isinstance(ip, ipaddress.IPv4Address):
            for private_range in self.private_ranges:
                if ip in private_range:
                    # Allow private ranges unless specifically excluded
                    if private_range.network_address.compressed in ['127.0.0.0', '169.254.0.0', '224.0.0.0', '240.0.0.0']:
                        return False

        # Check private/reserved ranges for IPv6
        elif isinstance(ip, ipaddress.IPv6Address):
            for private_range in self.private_ranges_v6:
                if ip in private_range:
                    # Allow unique local addresses, block others
                    if not str(private_range).startswith('fc00:'):
                        return False

        return True

    def get_network_info(self, cidr_string: str) -> IPRange:
        """
        Get detailed information about a network range

        Args:
            cidr_string: CIDR notation string

        Returns:
            IPRange object with network metadata
        """
        try:
            network = ipaddress.ip_network(cidr_string, strict=False)

            # Determine if network is private/reserved
            is_private = network.is_private
            is_reserved = network.is_reserved or network.is_loopback or network.is_link_local

            return IPRange(
                network=network,
                start_ip=network.network_address,
                end_ip=network.broadcast_address,
                total_hosts=network.num_addresses,
                is_private=is_private,
                is_reserved=is_reserved
            )

        except ValueError as e:
            logger.error(f"Invalid CIDR notation '{cidr_string}': {e}")
            raise

    def validate_cidr(self, cidr_string: str) -> bool:
        """
        Validate CIDR notation format

        Args:
            cidr_string: CIDR notation string to validate

        Returns:
            True if valid, False otherwise
        """
        try:
            # Handle single IP
            if '/' not in cidr_string:
                ipaddress.ip_address(cidr_string)
                return True

            # Handle CIDR notation
            network = ipaddress.ip_network(cidr_string, strict=False)

            # Check size limits
            if network.num_addresses > self.max_hosts:
                logger.warning(f"Network {network} exceeds max hosts limit")
                return False

            return True

        except ValueError:
            return False

    def parse_ip_range(self, start_ip: str, end_ip: str) -> List[str]:
        """
        Parse IP range from start to end IP

        Args:
            start_ip: Starting IP address
            end_ip: Ending IP address

        Returns:
            List of IP addresses in range
        """
        try:
            start = ipaddress.ip_address(start_ip)
            end = ipaddress.ip_address(end_ip)

            # Ensure same IP version
            if type(start) != type(end):
                raise ValueError("Start and end IPs must be same version (IPv4 or IPv6)")

            # Calculate range size
            if isinstance(start, ipaddress.IPv4Address):
                range_size = int(end) - int(start) + 1
            else:
                range_size = int(end) - int(start) + 1

            if range_size > self.max_hosts:
                raise ValueError(f"IP range too large: {range_size} > {self.max_hosts}")

            # Generate IP list
            ip_list = []
            current = start

            while current <= end:
                if self._is_ip_allowed(current):
                    ip_list.append(str(current))
                current += 1

            logger.info(f"Generated {len(ip_list)} IPs from range {start_ip}-{end_ip}")
            return ip_list

        except ValueError as e:
            logger.error(f"Invalid IP range '{start_ip}-{end_ip}': {e}")
            raise

    def parse_mixed_input(self, input_string: str) -> List[str]:
        """
        Parse mixed input formats (CIDR, IP ranges, single IPs)

        Args:
            input_string: Input string in various formats

        Returns:
            List of IP addresses
        """
        input_string = input_string.strip()

        # CIDR notation
        if '/' in input_string:
            return self.parse_cidr(input_string)

        # IP range (e.g., 192.168.1.1-192.168.1.10)
        elif '-' in input_string and input_string.count('-') == 1:
            start_ip, end_ip = input_string.split('-')
            return self.parse_ip_range(start_ip.strip(), end_ip.strip())

        # Single IP
        else:
            try:
                ip = ipaddress.ip_address(input_string)
                if self._is_ip_allowed(ip):
                    return [str(ip)]
                else:
                    logger.warning(f"IP {ip} is not allowed")
                    return []
            except ValueError as e:
                logger.error(f"Invalid IP format '{input_string}': {e}")
                raise

    def get_subnet_info(self, cidr_string: str) -> dict:
        """
        Get comprehensive subnet information

        Args:
            cidr_string: CIDR notation string

        Returns:
            Dictionary with subnet details
        """
        try:
            network = ipaddress.ip_network(cidr_string, strict=False)

            info = {
                'network': str(network),
                'network_address': str(network.network_address),
                'broadcast_address': str(network.broadcast_address) if isinstance(network, ipaddress.IPv4Network) else None,
                'netmask': str(network.netmask),
                'prefix_length': network.prefixlen,
                'total_addresses': network.num_addresses,
                'usable_hosts': len(list(network.hosts())),
                'is_private': network.is_private,
                'is_reserved': network.is_reserved,
                'is_multicast': network.is_multicast,
                'version': network.version,
                'supernet': str(network.supernet()) if network.prefixlen > 0 else None,
            }

            # Add subnets for smaller networks
            if network.prefixlen < 30 and network.version == 4:  # IPv4
                try:
                    subnets = list(network.subnets(prefixlen_diff=1))[:5]  # First 5 subnets
                    info['example_subnets'] = [str(subnet) for subnet in subnets]
                except ValueError:
                    info['example_subnets'] = []
            elif network.prefixlen < 126 and network.version == 6:  # IPv6
                try:
                    subnets = list(network.subnets(prefixlen_diff=1))[:5]
                    info['example_subnets'] = [str(subnet) for subnet in subnets]
                except ValueError:
                    info['example_subnets'] = []
            else:
                info['example_subnets'] = []

            return info

        except ValueError as e:
            logger.error(f"Invalid CIDR notation '{cidr_string}': {e}")
            raise

    def filter_ips_by_criteria(self, ip_list: List[str],
                              include_private: bool = True,
                              include_reserved: bool = False,
                              version_filter: Optional[int] = None) -> List[str]:
        """
        Filter IP list based on criteria

        Args:
            ip_list: List of IP addresses
            include_private: Include private IP addresses
            include_reserved: Include reserved IP addresses
            version_filter: Filter by IP version (4 or 6)

        Returns:
            Filtered list of IP addresses
        """
        filtered_ips = []

        for ip_str in ip_list:
            try:
                ip = ipaddress.ip_address(ip_str)

                # Version filter
                if version_filter and ip.version != version_filter:
                    continue

                # Private IP filter
                if not include_private and ip.is_private:
                    continue

                # Reserved IP filter
                if not include_reserved and (ip.is_reserved or ip.is_loopback or ip.is_link_local):
                    continue

                filtered_ips.append(ip_str)

            except ValueError:
                logger.warning(f"Invalid IP address in list: {ip_str}")
                continue

        logger.info(f"Filtered {len(ip_list)} IPs to {len(filtered_ips)} IPs")
        return filtered_ips

    def chunk_ip_list(self, ip_list: List[str], chunk_size: int = 1000) -> Iterator[List[str]]:
        """
        Split IP list into chunks for processing

        Args:
            ip_list: List of IP addresses
            chunk_size: Size of each chunk

        Yields:
            Chunks of IP addresses
        """
        for i in range(0, len(ip_list), chunk_size):
            yield ip_list[i:i + chunk_size]

    def get_statistics(self, ip_list: List[str]) -> dict:
        """
        Get statistics about IP list

        Args:
            ip_list: List of IP addresses

        Returns:
            Dictionary with statistics
        """
        stats = {
            'total_ips': len(ip_list),
            'ipv4_count': 0,
            'ipv6_count': 0,
            'private_count': 0,
            'public_count': 0,
            'reserved_count': 0,
        }

        for ip_str in ip_list:
            try:
                ip = ipaddress.ip_address(ip_str)

                if ip.version == 4:
                    stats['ipv4_count'] += 1
                else:
                    stats['ipv6_count'] += 1

                if ip.is_private:
                    stats['private_count'] += 1
                else:
                    stats['public_count'] += 1

                if ip.is_reserved or ip.is_loopback or ip.is_link_local:
                    stats['reserved_count'] += 1

            except ValueError:
                continue

        return stats