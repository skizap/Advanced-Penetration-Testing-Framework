#!/usr/bin/env python3
"""
Basic Database Test
Tests core database functionality without complex object handling
"""

import sys
import os
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

# Set up environment for SQLite
os.environ['DATABASE_TYPE'] = 'sqlite'
os.environ['DATABASE_SQLITE_PATH'] = 'data/test.db'

def main():
    print("🧪 Basic Database Test")
    print("=" * 40)
    
    try:
        from core.database.manager import DatabaseManager
        from core.database.models import ScanSession, Host, Port, Service
        
        # Initialize database
        print("1. Database initialization...")
        db_manager = DatabaseManager()
        print("   ✅ Database initialized")
        
        # Test direct database operations
        print("\n2. Testing database operations...")
        
        with db_manager.get_session() as session:
            # Create scan session
            scan_session = ScanSession(
                name="Test Scan",
                scan_type="discovery",
                description="Basic test scan"
            )
            session.add(scan_session)
            session.flush()
            session_id = scan_session.id
            print(f"   ✅ Created scan session: {session_id}")
            
            # Create host
            host = Host(
                ip_address="192.168.1.100",
                hostname="test.local",
                os_family="Linux",
                scan_session_id=session_id
            )
            session.add(host)
            session.flush()
            host_id = host.id
            print(f"   ✅ Created host: {host.ip_address}")
            
            # Create port
            port = Port(
                host_id=host_id,
                port_number=80,
                protocol="tcp",
                state="open",
                scan_session_id=session_id
            )
            session.add(port)
            session.flush()
            port_id = port.id
            print(f"   ✅ Created port: {port.port_number}/{port.protocol}")
            
            # Create service
            service = Service(
                port_id=port_id,
                name="http",
                product="Apache",
                version="2.4.41",
                confidence=10,
                scan_session_id=session_id
            )
            session.add(service)
            session.flush()
            print(f"   ✅ Created service: {service.name}")
        
        # Test queries
        print("\n3. Testing queries...")
        
        with db_manager.get_session() as session:
            # Count records
            session_count = session.query(ScanSession).count()
            host_count = session.query(Host).count()
            port_count = session.query(Port).count()
            service_count = session.query(Service).count()
            
            print(f"   ✅ Sessions: {session_count}")
            print(f"   ✅ Hosts: {host_count}")
            print(f"   ✅ Ports: {port_count}")
            print(f"   ✅ Services: {service_count}")
            
            # Test joins with explicit FROM
            results = session.query(Host, Port, Service).select_from(Host).join(Port).join(Service).all()
            print(f"   ✅ Host-Port-Service joins: {len(results)}")

            if results:
                host, port, service = results[0]
                print(f"   • {host.ip_address}:{port.port_number} -> {service.name}")
        
        print("\n4. Testing advanced queries...")
        
        from core.database.queries import QueryBuilder
        query_builder = QueryBuilder(db_manager)
        
        # Test service search
        apache_hosts = query_builder.get_hosts_with_service("Apache")
        print(f"   ✅ Hosts with Apache: {len(apache_hosts)}")
        
        # Test statistics
        stats = query_builder.get_service_statistics()
        print(f"   ✅ Total services: {stats['total_services']}")
        print(f"   ✅ Unique services: {stats['unique_services']}")
        
        print("\n🎉 All tests passed!")
        print(f"📁 Database: {os.environ['DATABASE_SQLITE_PATH']}")
        
        # Show database file size
        db_path = Path(os.environ['DATABASE_SQLITE_PATH'])
        if db_path.exists():
            size = db_path.stat().st_size
            print(f"📊 Database size: {size} bytes")
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
