#!/usr/bin/env python3
"""
Working Database Demo
Demonstrates the working functionality of the penetration testing framework
"""

import sys
import os
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

# Set up environment for SQLite
os.environ['DATABASE_TYPE'] = 'sqlite'
os.environ['DATABASE_SQLITE_PATH'] = 'data/pentest_demo.db'

def main():
    print("🎯 Penetration Testing Framework Demo")
    print("=" * 50)
    
    try:
        from core.database.manager import DatabaseManager
        from core.database.models import ScanSession, Host, Port, Service, Vulnerability
        
        # Initialize database
        print("1. 🗄️ Database System")
        db_manager = DatabaseManager()
        print("   ✅ Database initialized (SQLite)")
        
        # Create a penetration testing scan session
        print("\n2. 📋 Creating Penetration Test Session")
        with db_manager.get_session() as session:
            scan_session = ScanSession(
                name="Corporate Network Assessment",
                scan_type="comprehensive",
                description="Full penetration test of corporate network",
                target_specification="192.168.1.0/24",
                status="running"
            )
            session.add(scan_session)
            session.flush()
            session_id = scan_session.id
            print(f"   ✅ Created scan session: '{scan_session.name}' (ID: {session_id})")
        
        # Simulate network discovery results
        print("\n3. 🔍 Network Discovery Results")
        discovered_hosts = [
            ("192.168.1.10", "web-server.corp.local", "Linux"),
            ("192.168.1.20", "db-server.corp.local", "Linux"),
            ("192.168.1.30", "file-server.corp.local", "Windows"),
            ("192.168.1.100", "workstation-01.corp.local", "Windows")
        ]
        
        host_ids = {}
        for ip, hostname, os_family in discovered_hosts:
            with db_manager.get_session() as session:
                host = Host(
                    ip_address=ip,
                    hostname=hostname,
                    os_family=os_family,
                    scan_session_id=session_id
                )
                session.add(host)
                session.flush()
                host_ids[ip] = host.id
                print(f"   ✅ Discovered: {ip} ({hostname}) - {os_family}")
        
        # Simulate port scanning results
        print("\n4. 🔌 Port Scanning Results")
        port_data = [
            ("192.168.1.10", [(22, "tcp", "open"), (80, "tcp", "open"), (443, "tcp", "open")]),
            ("192.168.1.20", [(22, "tcp", "open"), (3306, "tcp", "open")]),
            ("192.168.1.30", [(21, "tcp", "open"), (135, "tcp", "open"), (445, "tcp", "open")]),
            ("192.168.1.100", [(135, "tcp", "open"), (445, "tcp", "open"), (3389, "tcp", "open")])
        ]
        
        port_ids = {}
        total_ports = 0
        for ip, ports in port_data:
            port_ids[ip] = []
            for port_num, protocol, state in ports:
                with db_manager.get_session() as session:
                    port = Port(
                        host_id=host_ids[ip],
                        port_number=port_num,
                        protocol=protocol,
                        state=state,
                        scan_session_id=session_id
                    )
                    session.add(port)
                    session.flush()
                    port_ids[ip].append(port.id)
                    total_ports += 1
            print(f"   ✅ {ip}: {len(ports)} open ports")
        
        # Simulate service enumeration
        print("\n5. 🔧 Service Enumeration Results")
        service_data = [
            ("192.168.1.10", 22, "ssh", "OpenSSH", "8.2p1"),
            ("192.168.1.10", 80, "http", "Apache", "2.4.41"),
            ("192.168.1.10", 443, "https", "Apache", "2.4.41"),
            ("192.168.1.20", 22, "ssh", "OpenSSH", "8.2p1"),
            ("192.168.1.20", 3306, "mysql", "MySQL", "8.0.28"),
            ("192.168.1.30", 21, "ftp", "Microsoft ftpd", "10.0"),
            ("192.168.1.30", 445, "microsoft-ds", "Windows Server", "2019"),
            ("192.168.1.100", 3389, "ms-wbt-server", "Microsoft Terminal Services", None)
        ]
        
        services_found = 0
        for ip, port_num, service_name, product, version in service_data:
            # Find the port ID
            with db_manager.get_session() as session:
                port = session.query(Port).filter_by(
                    host_id=host_ids[ip],
                    port_number=port_num,
                    scan_session_id=session_id
                ).first()
                
                if port:
                    service = Service(
                        port_id=port.id,
                        name=service_name,
                        product=product,
                        version=version,
                        confidence=10,
                        scan_session_id=session_id
                    )
                    session.add(service)
                    services_found += 1
        
        print(f"   ✅ Identified {services_found} services")
        
        return services_found, session_id, host_ids, total_ports
        
    except Exception as e:
        print(f"\n❌ Demo failed: {e}")
        import traceback
        traceback.print_exc()
        return 1

def continue_demo(services_found, session_id, host_ids, total_ports):
    """Continue the demo with vulnerability assessment"""
    try:
        from core.database.manager import DatabaseManager
        from core.database.models import Port, Vulnerability
        
        db_manager = DatabaseManager()
        
        # Simulate vulnerability findings
        print("\n6. 🚨 Vulnerability Assessment")
        vulnerability_data = [
            ("192.168.1.10", 80, "HTTP Server Vulnerability", "Apache version contains known vulnerabilities", "high", "CVE-2021-44228", 8.5),
            ("192.168.1.20", 3306, "MySQL Weak Configuration", "Root account has empty password", "critical", None, 9.1),
            ("192.168.1.30", 21, "FTP Anonymous Access", "Anonymous FTP access enabled", "medium", None, 5.3),
            ("192.168.1.30", 445, "SMB Signing Disabled", "SMB signing not required", "medium", "CVE-2019-1040", 6.5)
        ]
        
        vulnerabilities_found = 0
        for ip, port_num, title, description, severity, cve_id, cvss_score in vulnerability_data:
            with db_manager.get_session() as session:
                port = session.query(Port).filter_by(
                    host_id=host_ids[ip],
                    port_number=port_num,
                    scan_session_id=session_id
                ).first()
                
                if port:
                    vulnerability = Vulnerability(
                        host_id=host_ids[ip],
                        port_id=port.id,
                        title=title,
                        description=description,
                        severity=severity,
                        cve_id=cve_id,
                        cvss_score=cvss_score,
                        source="pentest_framework",
                        confidence=9,
                        scan_session_id=session_id
                    )
                    session.add(vulnerability)
                    vulnerabilities_found += 1
        
        print(f"   ✅ Found {vulnerabilities_found} vulnerabilities")
        
        # Generate summary report
        print("\n7. 📊 Penetration Test Summary")
        with db_manager.get_session() as session:
            from core.database.models import Host, Port, Service, Vulnerability
            
            # Count totals
            total_hosts = session.query(Host).filter_by(scan_session_id=session_id).count()
            total_ports_db = session.query(Port).filter_by(scan_session_id=session_id).count()
            total_services = session.query(Service).filter_by(scan_session_id=session_id).count()
            total_vulns = session.query(Vulnerability).filter_by(scan_session_id=session_id).count()
            
            # Count by severity
            critical_vulns = session.query(Vulnerability).filter_by(
                scan_session_id=session_id, severity="critical"
            ).count()
            high_vulns = session.query(Vulnerability).filter_by(
                scan_session_id=session_id, severity="high"
            ).count()
            medium_vulns = session.query(Vulnerability).filter_by(
                scan_session_id=session_id, severity="medium"
            ).count()
            
            print(f"   📈 Hosts Discovered: {total_hosts}")
            print(f"   📈 Open Ports: {total_ports_db}")
            print(f"   📈 Services Identified: {total_services}")
            print(f"   📈 Vulnerabilities Found: {total_vulns}")
            print(f"      • Critical: {critical_vulns}")
            print(f"      • High: {high_vulns}")
            print(f"      • Medium: {medium_vulns}")
        
        # Show database file info
        print(f"\n8. 💾 Data Storage")
        db_path = Path(os.environ['DATABASE_SQLITE_PATH'])
        if db_path.exists():
            size = db_path.stat().st_size
            print(f"   ✅ Database: {db_path}")
            print(f"   ✅ Size: {size:,} bytes")
        
        print(f"\n🎉 Penetration Testing Framework Demo Complete!")
        print(f"🔍 Discovered {total_hosts} hosts with {total_ports_db} open ports")
        print(f"🔧 Identified {total_services} services")
        print(f"🚨 Found {total_vulns} vulnerabilities ({critical_vulns} critical)")
        print(f"💾 All data stored in persistent database")
        
        return 0
        
    except Exception as e:
        print(f"\n❌ Demo failed: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    result = main()
    if isinstance(result, tuple):
        services_found, session_id, host_ids, total_ports = result
        sys.exit(continue_demo(services_found, session_id, host_ids, total_ports))
    else:
        sys.exit(result)
