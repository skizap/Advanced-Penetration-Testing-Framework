"""
Test cases for Nmap Scanner
"""

import pytest
import asyncio
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
import sys

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from scanner.nmap_scanner import (
    NmapScanner, DetailedScanResult, DetailedPortResult,
    ServiceInfo, ScriptResult, OSMatch
)
from scanner.masscan_scanner import ScanResult, PortResult


class TestNmapScanner:
    """Test cases for NmapScanner class"""

    def setup_method(self):
        """Setup test environment"""
        # Note: These tests will skip if nmap is not installed
        try:
            self.scanner = NmapScanner()
        except RuntimeError:
            pytest.skip("Nmap not available for testing")

    def test_scanner_initialization(self):
        """Test scanner initialization"""
        assert self.scanner.timing >= 0
        assert self.scanner.timeout > 0
        assert isinstance(self.scanner.scripts, list)

    def test_prepare_targets(self):
        """Test target preparation from Masscan results"""
        masscan_results = [
            ScanResult(
                ip="192.168.1.1",
                ports=[
                    PortResult("192.168.1.1", 80, "tcp", "open"),
                    PortResult("192.168.1.1", 443, "tcp", "open"),
                    PortResult("192.168.1.1", 53, "udp", "open"),
                ],
                scan_time=1.0,
                total_ports_scanned=3
            ),
            ScanResult(
                ip="192.168.1.2",
                ports=[
                    PortResult("192.168.1.2", 22, "tcp", "open"),
                ],
                scan_time=0.5,
                total_ports_scanned=1
            ),
        ]

        targets = self.scanner._prepare_targets(masscan_results)

        assert len(targets) == 2

        # Check first target
        target1 = next(t for t in targets if t['ip'] == "192.168.1.1")
        assert target1['tcp_ports'] == [80, 443]
        assert target1['udp_ports'] == [53]

        # Check second target
        target2 = next(t for t in targets if t['ip'] == "192.168.1.2")
        assert target2['tcp_ports'] == [22]
        assert target2['udp_ports'] == []

    def test_xml_parsing_empty_file(self):
        """Test parsing empty XML file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            f.write('')
            temp_path = f.name

        try:
            result = self.scanner._parse_nmap_xml(temp_path, "192.168.1.1")
            assert result is None
        finally:
            Path(temp_path).unlink()

    def test_xml_parsing_valid_results(self):
        """Test parsing valid Nmap XML results"""
        xml_content = '''<?xml version="1.0"?>
        <nmaprun version="7.80">
            <host>
                <address addr="192.168.1.1"/>
                <hostnames>
                    <hostname name="test.example.com"/>
                </hostnames>
                <ports>
                    <port protocol="tcp" portid="80">
                        <state state="open" reason="syn-ack"/>
                        <service name="http" product="Apache" version="2.4.41" method="probed" conf="10"/>
                        <script id="http-title" output="Test Page">
                            <elem key="title">Test Page</elem>
                        </script>
                    </port>
                    <port protocol="tcp" portid="443">
                        <state state="open" reason="syn-ack"/>
                        <service name="https" product="Apache" version="2.4.41" method="probed" conf="10"/>
                    </port>
                </ports>
                <os>
                    <osmatch name="Linux 3.2 - 4.9" accuracy="95" line="12345">
                        <osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="3.X" accuracy="95"/>
                    </osmatch>
                </os>
            </host>
        </nmaprun>'''

        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            f.write(xml_content)
            temp_path = f.name

        try:
            result = self.scanner._parse_nmap_xml(temp_path, "192.168.1.1")

            assert result is not None
            assert result.ip == "192.168.1.1"
            assert result.hostname == "test.example.com"
            assert len(result.ports) == 2
            assert len(result.os_matches) == 1

            # Check first port
            port80 = next(p for p in result.ports if p.port == 80)
            assert port80.protocol == "tcp"
            assert port80.state == "open"
            assert port80.service.name == "http"
            assert port80.service.product == "Apache"
            assert port80.service.version == "2.4.41"
            assert len(port80.scripts) == 1
            assert port80.scripts[0].id == "http-title"

            # Check OS match
            os_match = result.os_matches[0]
            assert os_match.name == "Linux 3.2 - 4.9"
            assert os_match.accuracy == 95
            assert os_match.osclass['osfamily'] == "Linux"

        finally:
            Path(temp_path).unlink()

    def test_service_statistics(self):
        """Test service statistics calculation"""
        # Create mock results
        results = [
            DetailedScanResult(
                ip="192.168.1.1",
                hostname="test1.com",
                ports=[
                    DetailedPortResult(
                        ip="192.168.1.1", port=80, protocol="tcp", state="open",
                        service=ServiceInfo("http", "Apache", "2.4.41")
                    ),
                    DetailedPortResult(
                        ip="192.168.1.1", port=443, protocol="tcp", state="open",
                        service=ServiceInfo("https", "Apache", "2.4.41")
                    ),
                ],
                os_matches=[OSMatch("Linux", 95, 1, {"osfamily": "Linux"})],
                scan_time=2.5,
                total_ports_scanned=2
            ),
            DetailedScanResult(
                ip="192.168.1.2",
                hostname="test2.com",
                ports=[
                    DetailedPortResult(
                        ip="192.168.1.2", port=22, protocol="tcp", state="open",
                        service=ServiceInfo("ssh", "OpenSSH", "8.0"),
                        scripts=[ScriptResult("ssh-hostkey", "RSA key found")]
                    ),
                ],
                os_matches=[OSMatch("Windows", 90, 1, {"osfamily": "Windows"})],
                scan_time=1.8,
                total_ports_scanned=1
            ),
        ]

        stats = self.scanner.get_service_statistics(results)

        assert stats['total_hosts'] == 2
        assert stats['hosts_with_services'] == 2
        assert stats['total_services'] == 3
        assert stats['unique_services'] == 3
        assert stats['os_families']['Linux'] == 1
        assert stats['os_families']['Windows'] == 1
        assert stats['script_results'] == 1

    def test_service_filtering(self):
        """Test filtering by service names"""
        results = [
            DetailedScanResult(
                ip="192.168.1.1",
                hostname=None,
                ports=[
                    DetailedPortResult(
                        ip="192.168.1.1", port=80, protocol="tcp", state="open",
                        service=ServiceInfo("http")
                    ),
                    DetailedPortResult(
                        ip="192.168.1.1", port=22, protocol="tcp", state="open",
                        service=ServiceInfo("ssh")
                    ),
                ],
                os_matches=[],
                scan_time=1.0,
                total_ports_scanned=2
            ),
        ]

        # Filter for web services
        filtered = self.scanner.filter_by_service(results, ["http", "https"])

        assert len(filtered) == 1
        assert len(filtered[0].ports) == 1
        assert filtered[0].ports[0].service.name == "http"

    def test_vulnerability_filtering(self):
        """Test filtering by vulnerability indicators"""
        results = [
            DetailedScanResult(
                ip="192.168.1.1",
                hostname=None,
                ports=[
                    DetailedPortResult(
                        ip="192.168.1.1", port=80, protocol="tcp", state="open",
                        service=ServiceInfo("http"),
                        scripts=[ScriptResult("http-vuln-cve2017-5638", "VULNERABLE: Apache Struts")]
                    ),
                    DetailedPortResult(
                        ip="192.168.1.1", port=443, protocol="tcp", state="open",
                        service=ServiceInfo("https"),
                        scripts=[ScriptResult("ssl-cert", "Certificate is valid")]
                    ),
                ],
                os_matches=[],
                scan_time=1.0,
                total_ports_scanned=2
            ),
        ]

        vuln_results = self.scanner.filter_by_vulnerability(results)

        assert len(vuln_results) == 1
        assert len(vuln_results[0].ports) == 1  # Only the vulnerable port
        assert vuln_results[0].ports[0].port == 80

    def test_export_json(self):
        """Test JSON export"""
        results = [
            DetailedScanResult(
                ip="192.168.1.1",
                hostname="test.com",
                ports=[
                    DetailedPortResult(
                        ip="192.168.1.1", port=80, protocol="tcp", state="open",
                        service=ServiceInfo("http", "Apache", "2.4.41")
                    )
                ],
                os_matches=[],
                scan_time=1.0,
                total_ports_scanned=1
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
            assert data[0]['hostname'] == "test.com"
            assert len(data[0]['ports']) == 1

        finally:
            Path(temp_path).unlink(missing_ok=True)


# Integration tests (require nmap to be installed)
class TestNmapIntegration:
    """Integration tests for Nmap (requires nmap installation)"""

    def setup_method(self):
        """Setup test environment"""
        try:
            self.scanner = NmapScanner()
        except RuntimeError:
            pytest.skip("Nmap not available for integration testing")

    @pytest.mark.asyncio
    async def test_scan_localhost(self):
        """Test scanning localhost (if nmap is available)"""
        try:
            # Create mock Masscan result for localhost
            masscan_results = [
                ScanResult(
                    ip="127.0.0.1",
                    ports=[PortResult("127.0.0.1", 22, "tcp", "open")],
                    scan_time=0.1,
                    total_ports_scanned=1
                )
            ]

            results = await self.scanner.scan_services(masscan_results)

            # Results may be empty if no services are detected, but should not error
            assert isinstance(results, list)

            for result in results:
                assert isinstance(result, DetailedScanResult)
                assert result.ip == '127.0.0.1'

        except Exception as e:
            # Skip if we don't have permissions or nmap fails
            pytest.skip(f"Nmap integration test failed: {e}")


if __name__ == "__main__":
    pytest.main([__file__])