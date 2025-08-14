"""
Test cases for CIDR Block Parser
"""

import pytest
import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from scanner.cidr_parser import CIDRParser, IPRange
import ipaddress


class TestCIDRParser:
    """Test cases for CIDRParser class"""

    def setup_method(self):
        """Setup test environment"""
        self.parser = CIDRParser()

    def test_single_ip_parsing(self):
        """Test parsing single IP addresses"""
        # Valid IPv4
        result = self.parser.parse_cidr("192.168.1.100")
        assert result == ["192.168.1.100"]

        # Valid IPv6
        result = self.parser.parse_cidr("2001:db8::1")
        assert result == ["2001:db8::1"]

    def test_cidr_parsing(self):
        """Test parsing CIDR notation"""
        # Small IPv4 network
        result = self.parser.parse_cidr("192.168.1.0/30")
        expected = ["192.168.1.1", "192.168.1.2"]  # .0 and .3 are network/broadcast
        assert result == expected

        # IPv6 network
        result = self.parser.parse_cidr("2001:db8::/127")
        assert len(result) == 2  # Two host addresses

    def test_invalid_cidr(self):
        """Test invalid CIDR notation handling"""
        with pytest.raises(ValueError):
            self.parser.parse_cidr("invalid.ip.address")

        with pytest.raises(ValueError):
            self.parser.parse_cidr("192.168.1.0/33")  # Invalid prefix

    def test_network_size_limit(self):
        """Test network size limitations"""
        # This should fail if max_hosts is set to default (65536)
        with pytest.raises(ValueError):
            self.parser.parse_cidr("10.0.0.0/8")  # 16M+ hosts

    def test_multiple_cidrs(self):
        """Test parsing multiple CIDR blocks"""
        cidrs = ["192.168.1.0/30", "10.0.0.1/32"]
        result = self.parser.parse_multiple_cidrs(cidrs)

        # Should contain IPs from both networks
        assert "192.168.1.1" in result
        assert "192.168.1.2" in result
        assert "10.0.0.1" in result

    def test_ip_range_parsing(self):
        """Test IP range parsing"""
        result = self.parser.parse_ip_range("192.168.1.1", "192.168.1.5")
        expected = ["192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.5"]
        assert result == expected

    def test_mixed_input_parsing(self):
        """Test mixed input format parsing"""
        # CIDR
        result = self.parser.parse_mixed_input("192.168.1.0/30")
        assert len(result) == 2

        # IP range
        result = self.parser.parse_mixed_input("192.168.1.1-192.168.1.3")
        assert result == ["192.168.1.1", "192.168.1.2", "192.168.1.3"]

        # Single IP
        result = self.parser.parse_mixed_input("192.168.1.100")
        assert result == ["192.168.1.100"]

    def test_cidr_validation(self):
        """Test CIDR validation"""
        assert self.parser.validate_cidr("192.168.1.0/24") == True
        assert self.parser.validate_cidr("192.168.1.100") == True
        assert self.parser.validate_cidr("2001:db8::/64") == True
        assert self.parser.validate_cidr("invalid") == False
        assert self.parser.validate_cidr("192.168.1.0/33") == False

    def test_network_info(self):
        """Test network information extraction"""
        info = self.parser.get_network_info("192.168.1.0/24")

        assert info.network == ipaddress.IPv4Network("192.168.1.0/24")
        assert info.total_hosts == 256
        assert info.is_private == True

    def test_subnet_info(self):
        """Test subnet information extraction"""
        info = self.parser.get_subnet_info("192.168.1.0/24")

        assert info['network'] == "192.168.1.0/24"
        assert info['network_address'] == "192.168.1.0"
        assert info['broadcast_address'] == "192.168.1.255"
        assert info['total_addresses'] == 256
        assert info['usable_hosts'] == 254
        assert info['is_private'] == True

    def test_ip_filtering(self):
        """Test IP filtering by criteria"""
        ip_list = ["192.168.1.1", "8.8.8.8", "127.0.0.1", "2001:db8::1"]

        # Filter private IPs
        result = self.parser.filter_ips_by_criteria(ip_list, include_private=False)
        assert "192.168.1.1" not in result
        assert "8.8.8.8" in result

        # Filter by version
        result = self.parser.filter_ips_by_criteria(ip_list, version_filter=4)
        assert "2001:db8::1" not in result
        assert "192.168.1.1" in result

    def test_ip_statistics(self):
        """Test IP list statistics"""
        ip_list = ["192.168.1.1", "8.8.8.8", "127.0.0.1", "2001:db8::1"]
        stats = self.parser.get_statistics(ip_list)

        assert stats['total_ips'] == 4
        assert stats['ipv4_count'] == 3
        assert stats['ipv6_count'] == 1
        assert stats['private_count'] >= 1  # At least 192.168.1.1

    def test_ip_chunking(self):
        """Test IP list chunking"""
        ip_list = [f"192.168.1.{i}" for i in range(1, 11)]  # 10 IPs
        chunks = list(self.parser.chunk_ip_list(ip_list, chunk_size=3))

        assert len(chunks) == 4  # 3 + 3 + 3 + 1
        assert len(chunks[0]) == 3
        assert len(chunks[-1]) == 1

    def test_exclude_ranges(self):
        """Test exclude range functionality"""
        # This test depends on configuration, so we'll test the logic
        ip = ipaddress.ip_address("127.0.0.1")
        assert not self.parser._is_ip_allowed(ip)  # Loopback should be excluded

        ip = ipaddress.ip_address("192.168.1.1")
        assert self.parser._is_ip_allowed(ip)  # Private IP should be allowed


if __name__ == "__main__":
    pytest.main([__file__])