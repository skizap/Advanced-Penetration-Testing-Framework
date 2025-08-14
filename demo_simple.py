#!/usr/bin/env python3
"""
Simple Database Demo
Basic test of the database functionality
"""

import sys
import os
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

# Set up environment for SQLite
os.environ['DATABASE_TYPE'] = 'sqlite'
os.environ['DATABASE_SQLITE_PATH'] = 'data/demo.db'

def main():
    print("🗄️ Simple Database Demo")
    print("=" * 50)
    
    try:
        from core.database.manager import DatabaseManager
        
        # Initialize database
        print("1. Initializing database...")
        db_manager = DatabaseManager()
        print("   ✅ Database initialized successfully")
        
        # Create scan session
        print("\n2. Creating scan session...")
        with db_manager.get_session() as session:
            from core.database.models import ScanSession
            
            scan_session = ScanSession(
                name="Demo Scan",
                scan_type="discovery",
                description="Simple demo scan",
                status="running"
            )
            session.add(scan_session)
            session.flush()
            session_id = scan_session.id
            print(f"   ✅ Created scan session: {session_id}")
        
        # Add a host
        print("\n3. Adding host...")
        host = db_manager.add_host(
            ip_address="192.168.1.100",
            scan_session_id=session_id,
            hostname="demo.local",
            os_family="Linux"
        )
        print(f"   ✅ Added host: {host.ip_address}")
        
        # Add a port
        print("\n4. Adding port...")
        port = db_manager.add_port(
            host_id=host.id,
            port_number=80,
            protocol="tcp",
            state="open",
            scan_session_id=session_id
        )
        print(f"   ✅ Added port: {port.port_number}/{port.protocol}")
        
        # Add a service
        print("\n5. Adding service...")
        service = db_manager.add_service(
            port_id=port.id,
            name="http",
            product="Apache",
            version="2.4.41",
            confidence=10,
            scan_session_id=session_id
        )
        print(f"   ✅ Added service: {service.name} ({service.product} {service.version})")
        
        # Query data
        print("\n6. Querying data...")
        hosts = db_manager.list_hosts(scan_session_id=session_id)
        print(f"   ✅ Found {len(hosts)} hosts")
        
        ports = db_manager.find_ports(host_id=host.id)
        print(f"   ✅ Found {len(ports)} ports")
        
        services = db_manager.find_services(name="http")
        print(f"   ✅ Found {len(services)} HTTP services")
        
        # Show summary
        print("\n7. Summary:")
        print(f"   • Host: {hosts[0].ip_address} ({hosts[0].hostname})")
        print(f"   • Port: {ports[0].port_number}/{ports[0].protocol} ({ports[0].state})")
        print(f"   • Service: {services[0].name} - {services[0].product} {services[0].version}")
        
        print("\n🎉 Demo completed successfully!")
        print(f"📁 Database file: {os.environ['DATABASE_SQLITE_PATH']}")
        
    except Exception as e:
        print(f"\n❌ Demo failed: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
