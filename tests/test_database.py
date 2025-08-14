"""
Test cases for Database System
"""

import pytest
import tempfile
import json
from datetime import datetime, timedelta
from pathlib import Path
import sys

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from core.database.manager import DatabaseManager
from core.database.queries import QueryBuilder
from core.database.importers import ScanResultImporter
from core.database.utils import DatabaseUtils
from core.database.models import ScanSession, Host, Port, Service, Script, Vulnerability
from scanner.masscan_scanner import ScanResult, PortResult
from scanner.nmap_scanner import (
    DetailedScanResult, DetailedPortResult, ServiceInfo,
    ScriptResult, OSMatch
)


class TestDatabaseManager:
    """Test cases for DatabaseManager"""

    def setup_method(self):
        """Setup test environment with in-memory SQLite"""
        # Use in-memory SQLite for testing
        import os
        os.environ['DATABASE_TYPE'] = 'sqlite'
        os.environ['DATABASE_SQLITE_PATH'] = ':memory:'

        from core.config import config_manager
        config_manager._config = None  # Reset config

        self.db_manager = DatabaseManager()

    def test_database_initialization(self):
        """Test database initialization"""
        assert self.db_manager.engine is not None
        assert self.db_manager.SessionLocal is not None

        # Test that tables were created
        with self.db_manager.get_session() as session:
            # Should not raise an error
            session.query(ScanSession).count()

    def test_scan_session_operations(self):
        """Test scan session CRUD operations"""
        # Create scan session
        session = self.db_manager.create_scan_session(
            name="Test Scan",
            scan_type="discovery",
            description="Test scan session",
            target_specification="192.168.1.0/24"
        )

        assert session.id is not None
        assert session.name == "Test Scan"
        assert session.scan_type == "discovery"
        assert session.status == "running"

        # Get scan session
        retrieved_session = self.db_manager.get_scan_session(session.id)
        assert retrieved_session.name == "Test Scan"

        # Update scan session
        updated_session = self.db_manager.update_scan_session(
            session.id,
            status="completed",
            total_hosts=10
        )
        assert updated_session.status == "completed"
        assert updated_session.total_hosts == 10

        # List scan sessions
        sessions = self.db_manager.list_scan_sessions()
        assert len(sessions) >= 1
        assert any(s.name == "Test Scan" for s in sessions)

        # Complete scan session
        completed_session = self.db_manager.complete_scan_session(session.id)
        assert completed_session.status == "completed"
        assert completed_session.end_time is not None

    def test_host_operations(self):
        """Test host CRUD operations"""
        # Create scan session first
        session = self.db_manager.create_scan_session("Host Test", "discovery")

        # Add host
        host = self.db_manager.add_host(
            ip_address="192.168.1.100",
            scan_session_id=session.id,
            hostname="test.local",
            os_name="Linux 5.4",
            os_family="Linux",
            os_accuracy=95
        )

        assert host.id is not None
        assert host.ip_address == "192.168.1.100"
        assert host.hostname == "test.local"
        assert host.os_family == "Linux"

        # Find host by IP
        found_host = self.db_manager.find_host_by_ip("192.168.1.100", session.id)
        assert found_host.id == host.id

        # List hosts
        hosts = self.db_manager.list_hosts(scan_session_id=session.id)
        assert len(hosts) == 1
        assert hosts[0].ip_address == "192.168.1.100"

        # Update host (add same IP again should update)
        updated_host = self.db_manager.add_host(
            ip_address="192.168.1.100",
            scan_session_id=session.id,
            hostname="updated.local"
        )
        assert updated_host.id == host.id
        assert updated_host.hostname == "updated.local"

    def test_port_operations(self):
        """Test port CRUD operations"""
        # Setup
        session = self.db_manager.create_scan_session("Port Test", "discovery")
        host = self.db_manager.add_host("192.168.1.100", session.id)

        # Add port
        port = self.db_manager.add_port(
            host_id=host.id,
            port_number=80,
            protocol="tcp",
            state="open",
            scan_session_id=session.id,
            reason="syn-ack"
        )

        assert port.id is not None
        assert port.port_number == 80
        assert port.protocol == "tcp"
        assert port.state == "open"

        # Find ports
        ports = self.db_manager.find_ports(host_id=host.id)
        assert len(ports) == 1
        assert ports[0].port_number == 80

        # Find by port number
        tcp_ports = self.db_manager.find_ports(port_number=80, protocol="tcp")
        assert len(tcp_ports) == 1

    def test_service_operations(self):
        """Test service CRUD operations"""
        # Setup
        session = self.db_manager.create_scan_session("Service Test", "service")
        host = self.db_manager.add_host("192.168.1.100", session.id)
        port = self.db_manager.add_port(host.id, 80, "tcp", "open", session.id)

        # Add service
        service = self.db_manager.add_service(
            port_id=port.id,
            name="http",
            product="Apache",
            version="2.4.41",
            confidence=10,
            scan_session_id=session.id
        )

        assert service.id is not None
        assert service.name == "http"
        assert service.product == "Apache"
        assert service.version == "2.4.41"

        # Find services
        services = self.db_manager.find_services(name="http")
        assert len(services) == 1
        assert services[0].product == "Apache"

        # Find by product
        apache_services = self.db_manager.find_services(product="Apache")
        assert len(apache_services) == 1

    def test_vulnerability_operations(self):
        """Test vulnerability CRUD operations"""
        # Setup
        session = self.db_manager.create_scan_session("Vuln Test", "vulnerability")
        host = self.db_manager.add_host("192.168.1.100", session.id)
        port = self.db_manager.add_port(host.id, 80, "tcp", "open", session.id)

        # Add vulnerability
        vuln = self.db_manager.add_vulnerability(
            host_id=host.id,
            port_id=port.id,
            title="Test Vulnerability",
            description="A test vulnerability",
            severity="high",
            cve_id="CVE-2021-1234",
            cvss_score=8.5,
            source="test_scanner",
            confidence=9,
            scan_session_id=session.id
        )

        assert vuln.id is not None
        assert vuln.cve_id == "CVE-2021-1234"
        assert vuln.severity == "high"
        assert vuln.cvss_score == 8.5

        # Find vulnerabilities
        vulns = self.db_manager.find_vulnerabilities(host_id=host.id)
        assert len(vulns) == 1
        assert vulns[0].cve_id == "CVE-2021-1234"

        # Find by severity
        high_vulns = self.db_manager.find_vulnerabilities(severity="high")
        assert len(high_vulns) == 1

        # Find by CVSS score
        critical_vulns = self.db_manager.find_vulnerabilities(min_cvss_score=8.0)
        assert len(critical_vulns) == 1


class TestQueryBuilder:
    """Test cases for QueryBuilder"""

    def setup_method(self):
        """Setup test environment"""
        import os
        os.environ['DATABASE_TYPE'] = 'sqlite'
        os.environ['DATABASE_SQLITE_PATH'] = ':memory:'

        from core.config import config_manager
        config_manager._config = None

        self.db_manager = DatabaseManager()
        self.query_builder = QueryBuilder(self.db_manager)

        # Create test data
        self.session = self.db_manager.create_scan_session("Query Test", "service")

        # Add test hosts with services
        self.host1 = self.db_manager.add_host("192.168.1.10", self.session.id,
                                             hostname="web.local", os_family="Linux")
        self.host2 = self.db_manager.add_host("192.168.1.20", self.session.id,
                                             hostname="db.local", os_family="Windows")

        # Add ports and services
        port1 = self.db_manager.add_port(self.host1.id, 80, "tcp", "open", self.session.id)
        port2 = self.db_manager.add_port(self.host1.id, 443, "tcp", "open", self.session.id)
        port3 = self.db_manager.add_port(self.host2.id, 3306, "tcp", "open", self.session.id)

        self.db_manager.add_service(port1.id, "http", "Apache", "2.4.41", 10, self.session.id)
        self.db_manager.add_service(port2.id, "https", "Apache", "2.4.41", 10, self.session.id)
        self.db_manager.add_service(port3.id, "mysql", "MySQL", "8.0.28", 10, self.session.id)

        # Add vulnerabilities
        self.db_manager.add_vulnerability(
            self.host1.id, port1.id, "HTTP Vulnerability", "Test vuln",
            "high", "CVE-2021-1234", 8.5, "test", 9, self.session.id
        )

    def test_get_hosts_with_service(self):
        """Test finding hosts with specific services"""
        # Find hosts with Apache
        apache_hosts = self.query_builder.get_hosts_with_service("Apache")
        assert len(apache_hosts) == 2  # Two Apache services on host1

        # Find hosts with MySQL
        mysql_hosts = self.query_builder.get_hosts_with_service("mysql")
        assert len(mysql_hosts) == 1
        assert mysql_hosts[0]['host']['ip_address'] == "192.168.1.20"

    def test_get_vulnerability_summary(self):
        """Test vulnerability summary"""
        summary = self.query_builder.get_vulnerability_summary(self.session.id)

        assert summary['total_vulnerabilities'] == 1
        assert summary['by_severity']['high'] == 1
        assert summary['affected_hosts'] == 1
        assert len(summary['critical_hosts']) == 1

    def test_search_hosts(self):
        """Test advanced host search"""
        # Search by IP pattern
        hosts = self.query_builder.search_hosts(ip_pattern="192.168.1")
        assert len(hosts) == 2

        # Search by OS family
        linux_hosts = self.query_builder.search_hosts(os_family="Linux")
        assert len(linux_hosts) == 1
        assert linux_hosts[0]['os_family'] == "Linux"

        # Search hosts with vulnerabilities
        vuln_hosts = self.query_builder.search_hosts(has_vulnerabilities=True)
        assert len(vuln_hosts) == 1
        assert vuln_hosts[0]['vulnerability_count'] == 1


class TestScanResultImporter:
    """Test cases for ScanResultImporter"""

    def setup_method(self):
        """Setup test environment"""
        import os
        os.environ['DATABASE_TYPE'] = 'sqlite'
        os.environ['DATABASE_SQLITE_PATH'] = ':memory:'

        from core.config import config_manager
        config_manager._config = None

        self.db_manager = DatabaseManager()
        self.importer = ScanResultImporter(self.db_manager)

        self.session = self.db_manager.create_scan_session("Import Test", "discovery")

    def test_import_masscan_results(self):
        """Test importing Masscan results"""
        # Create mock Masscan results
        masscan_results = [
            ScanResult(
                ip="192.168.1.10",
                ports=[
                    PortResult("192.168.1.10", 80, "tcp", "open"),
                    PortResult("192.168.1.10", 443, "tcp", "open"),
                ],
                scan_time=1.5,
                total_ports_scanned=2
            ),
            ScanResult(
                ip="192.168.1.20",
                ports=[
                    PortResult("192.168.1.20", 22, "tcp", "open"),
                ],
                scan_time=0.8,
                total_ports_scanned=1
            )
        ]

        # Import results
        stats = self.importer.import_masscan_results(masscan_results, self.session.id)

        assert stats['hosts_added'] == 2
        assert stats['ports_added'] == 3
        assert stats['errors'] == 0

        # Verify data was imported
        hosts = self.db_manager.list_hosts(scan_session_id=self.session.id)
        assert len(hosts) == 2

        # Check ports
        host1 = self.db_manager.find_host_by_ip("192.168.1.10", self.session.id)
        ports = self.db_manager.find_ports(host_id=host1.id)
        assert len(ports) == 2

    def test_import_nmap_results(self):
        """Test importing Nmap results"""
        # Create mock Nmap results
        nmap_results = [
            DetailedScanResult(
                ip="192.168.1.10",
                hostname="web.local",
                ports=[
                    DetailedPortResult(
                        ip="192.168.1.10",
                        port=80,
                        protocol="tcp",
                        state="open",
                        service=ServiceInfo("http", "Apache", "2.4.41"),
                        scripts=[
                            ScriptResult("http-title", "Welcome Page"),
                            ScriptResult("http-vuln-cve2021-44228", "VULNERABLE: Log4j RCE")
                        ]
                    )
                ],
                os_matches=[
                    OSMatch("Linux 5.4", 95, 1, {"osfamily": "Linux", "vendor": "Linux"})
                ],
                scan_time=15.2,
                total_ports_scanned=1
            )
        ]

        # Import results
        stats = self.importer.import_nmap_results(nmap_results, self.session.id)

        assert stats['hosts_added'] == 1
        assert stats['ports_added'] == 1
        assert stats['services_added'] == 1
        assert stats['scripts_added'] == 2
        assert stats['vulnerabilities_added'] == 1  # From vulnerable script

        # Verify data
        host = self.db_manager.find_host_by_ip("192.168.1.10", self.session.id)
        assert host.hostname == "web.local"
        assert host.os_name == "Linux 5.4"
        assert host.os_family == "Linux"

        # Check service
        services = self.db_manager.find_services(name="http")
        assert len(services) == 1
        assert services[0].product == "Apache"

        # Check vulnerability was detected
        vulns = self.db_manager.find_vulnerabilities(host_id=host.id)
        assert len(vulns) == 1


class TestDatabaseUtils:
    """Test cases for DatabaseUtils"""

    def setup_method(self):
        """Setup test environment"""
        import os
        os.environ['DATABASE_TYPE'] = 'sqlite'
        os.environ['DATABASE_SQLITE_PATH'] = ':memory:'

        from core.config import config_manager
        config_manager._config = None

        self.db_manager = DatabaseManager()
        self.db_utils = DatabaseUtils(self.db_manager)

        # Create test data
        self.session = self.db_manager.create_scan_session("Utils Test", "discovery")
        host = self.db_manager.add_host("192.168.1.10", self.session.id)
        port = self.db_manager.add_port(host.id, 80, "tcp", "open", self.session.id)
        self.db_manager.add_service(port.id, "http", "Apache", "2.4.41", 10, self.session.id)

    def test_backup_and_restore(self):
        """Test database backup and restore"""
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            backup_path = f.name

        try:
            # Create backup
            success = self.db_utils.backup_database(backup_path, compress=False)
            assert success == True

            # Verify backup file exists and has content
            backup_file = Path(backup_path)
            assert backup_file.exists()

            with open(backup_path) as f:
                backup_data = json.load(f)

            assert backup_data['metadata']['total_sessions'] == 1
            assert backup_data['metadata']['total_hosts'] == 1
            assert backup_data['metadata']['total_services'] == 1

            # Clear database
            self.db_utils.clear_all_data()

            # Verify data is cleared
            hosts = self.db_manager.list_hosts()
            assert len(hosts) == 0

            # Restore from backup
            success = self.db_utils.restore_database(backup_path)
            assert success == True

            # Verify data is restored
            hosts = self.db_manager.list_hosts()
            assert len(hosts) == 1
            assert hosts[0].ip_address == "192.168.1.10"

        finally:
            Path(backup_path).unlink(missing_ok=True)

    def test_database_statistics(self):
        """Test database statistics"""
        stats = self.db_utils.get_database_statistics()

        assert stats['scan_sessions'] == 1
        assert stats['hosts'] == 1
        assert stats['ports'] == 1
        assert stats['services'] == 1
        assert 'top_services' in stats

    def test_csv_export(self):
        """Test CSV export"""
        with tempfile.TemporaryDirectory() as temp_dir:
            success = self.db_utils.export_to_csv(temp_dir, self.session.id)
            assert success == True

            # Check files were created
            csv_dir = Path(temp_dir)
            assert (csv_dir / 'hosts.csv').exists()
            assert (csv_dir / 'services.csv').exists()
            assert (csv_dir / 'vulnerabilities.csv').exists()

            # Check content
            with open(csv_dir / 'hosts.csv') as f:
                content = f.read()
                assert '192.168.1.10' in content


if __name__ == "__main__":
    pytest.main([__file__])