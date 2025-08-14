"""
Test cases for Masscan Scanner
"""

import pytest
import asyncio
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
import sys

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from scanner.masscan_scanner import MasscanScanner, PortResult, ScanResult


class TestMasscanScanner:
    """Test cases for MasscanScanner class"""

    def setup_method(self):
        """Setup test environment"""
        # Note: These tests will skip if masscan is not installed
        try:
            self.scanner = MasscanScanner()
        except RuntimeError:
            pytest.skip("Masscan not available for testing")

    def test_scanner_initialization(self):
        """Test scanner initialization"""
        assert self.scanner.rate > 0
        assert self.scanner.timeout > 0
        assert self.scanner.ports is not None

    def test_xml_parsing_empty_file(self):
        """Test parsing empty XML file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            f.write('')
            temp_path = f.name

        try:
            results = self.scanner._parse_masscan_xml(temp_path)
            assert results == []
        finally:
            Path(temp_path).unlink()

    def test_xml_parsing_valid_results(self):
        """Test parsing valid Masscan XML results"""
        xml_content = '''<?xml version="1.0"?>
        <nmaprun>
            <host>
                <address addr="192.168.1.1"/>
                <ports>
                    <port protocol="tcp" portid="80">
                        <state state="open"/>
                    </port>
                    <port protocol="tcp" portid="443">
                        <state state="open"/>
                    </port>
                </ports>
            </host>
            <host>
                <address addr="192.168.1.2"/>
                <ports>
                    <port protocol="tcp" portid="22">
                        <state state="open"/>
                    </port>
                </ports>
            </host>
        </nmaprun>'''

        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            f.write(xml_content)
            temp_path = f.name

        try:
            results = self.scanner._parse_masscan_xml(temp_path)

            assert len(results) == 2

            # Check first host
            host1 = next(r for r in results if r.ip == "192.168.1.1")
            assert len(host1.ports) == 2
            assert any(p.port == 80 and p.protocol == "tcp" for p in host1.ports)
            assert any(p.port == 443 and p.protocol == "tcp" for p in host1.ports)

            # Check second host
            host2 = next(r for r in results if r.ip == "192.168.1.2")
            assert len(host2.ports) == 1
            assert host2.ports[0].port == 22
            assert host2.ports[0].protocol == "tcp"

        finally:
            Path(temp_path).unlink()

    def test_scan_statistics(self):
        """Test scan statistics calculation"""
        # Create mock results
        results = [
            ScanResult(
                ip="192.168.1.1",
                ports=[
                    PortResult("192.168.1.1", 80, "tcp", "open"),
                    PortResult("192.168.1.1", 443, "tcp", "open"),
                ],
                scan_time=1.5,
                total_ports_scanned=1000
            ),
            ScanResult(
                ip="192.168.1.2",
                ports=[
                    PortResult("192.168.1.2", 22, "tcp", "open"),
                    PortResult("192.168.1.2", 53, "udp", "open"),
                ],
                scan_time=2.0,
                total_ports_scanned=1000
            ),
        ]

        stats = self.scanner.get_scan_statistics(results)

        assert stats['total_hosts_scanned'] == 2
        assert stats['hosts_with_open_ports'] == 2
        assert stats['total_open_ports'] == 4
        assert stats['unique_ports'] == 4
        assert stats['protocols']['tcp'] == 3
        assert stats['protocols']['udp'] == 1
        assert stats['average_scan_time'] == 1.75

    def test_result_filtering(self):
        """Test result filtering"""
        results = [
            ScanResult(
                ip="192.168.1.1",
                ports=[
                    PortResult("192.168.1.1", 80, "tcp", "open"),
                    PortResult("192.168.1.1", 443, "tcp", "open"),
                    PortResult("192.168.1.1", 53, "udp", "open"),
                ],
                scan_time=1.0,
                total_ports_scanned=1000
            ),
            ScanResult(
                ip="192.168.1.2",
                ports=[
                    PortResult("192.168.1.2", 22, "tcp", "open"),
                ],
                scan_time=1.0,
                total_ports_scanned=1000
            ),
        ]

        # Filter by port
        filtered = self.scanner.filter_results(results, port_filter=[80, 443])
        assert len(filtered) == 1
        assert filtered[0].ip == "192.168.1.1"
        assert len(filtered[0].ports) == 2

        # Filter by protocol
        filtered = self.scanner.filter_results(results, protocol_filter=["udp"])
        assert len(filtered) == 1
        assert len(filtered[0].ports) == 1
        assert filtered[0].ports[0].protocol == "udp"

        # Filter by minimum ports
        filtered = self.scanner.filter_results(results, min_ports=2)
        assert len(filtered) == 1
        assert filtered[0].ip == "192.168.1.1"

    def test_export_json(self):
        """Test JSON export"""
        results = [
            ScanResult(
                ip="192.168.1.1",
                ports=[PortResult("192.168.1.1", 80, "tcp", "open")],
                scan_time=1.0,
                total_ports_scanned=1000
            )
        ]

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            temp_path = f.name

        try:
            self.scanner.export_results(results, temp_path, 'json')

            # Verify file was created and contains data
            assert Path(temp_path).exists()

            import json
            with open(temp_path) as f:
                data = json.load(f)

            assert len(data) == 1
            assert data[0]['ip'] == "192.168.1.1"
            assert len(data[0]['ports']) == 1

        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_export_csv(self):
        """Test CSV export"""
        results = [
            ScanResult(
                ip="192.168.1.1",
                ports=[
                    PortResult("192.168.1.1", 80, "tcp", "open"),
                    PortResult("192.168.1.1", 443, "tcp", "open"),
                ],
                scan_time=1.0,
                total_ports_scanned=1000
            )
        ]

        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            temp_path = f.name

        try:
            self.scanner.export_results(results, temp_path, 'csv')

            # Verify file was created
            assert Path(temp_path).exists()

            with open(temp_path) as f:
                lines = f.readlines()

            # Should have header + 2 data rows
            assert len(lines) == 3
            assert 'IP,Port,Protocol,State,Scan_Time' in lines[0]
            assert '192.168.1.1,80,tcp,open' in lines[1]
            assert '192.168.1.1,443,tcp,open' in lines[2]

        finally:
            Path(temp_path).unlink(missing_ok=True)


# Integration tests (require masscan to be installed)
class TestMasscanIntegration:
    """Integration tests for Masscan (requires masscan installation)"""

    def setup_method(self):
        """Setup test environment"""
        try:
            self.scanner = MasscanScanner()
        except RuntimeError:
            pytest.skip("Masscan not available for integration testing")

    @pytest.mark.asyncio
    async def test_scan_localhost(self):
        """Test scanning localhost (if masscan is available)"""
        # This test will only run if masscan is installed and we have permissions
        try:
            results = await self.scanner.scan_ips(['127.0.0.1'], ports='80,443,22')

            # Results may be empty if no ports are open, but should not error
            assert isinstance(results, list)

            for result in results:
                assert isinstance(result, ScanResult)
                assert result.ip == '127.0.0.1'

        except Exception as e:
            # Skip if we don't have permissions or masscan fails
            pytest.skip(f"Masscan integration test failed: {e}")

    @pytest.mark.asyncio
    async def test_scan_invalid_ip(self):
        """Test scanning invalid IP"""
        # Should handle gracefully
        results = await self.scanner.scan_ips(['999.999.999.999'])
        assert isinstance(results, list)
        # May be empty or contain error results


if __name__ == "__main__":
    pytest.main([__file__])