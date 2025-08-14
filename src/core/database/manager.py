"""
Database Manager for Scan Results
Handles all database operations for the penetration testing framework
"""

from datetime import datetime
from typing import List, Dict, Optional, Any, Union
from contextlib import contextmanager
from sqlalchemy import create_engine, and_, or_, func, desc, asc
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.exc import SQLAlchemyError
from loguru import logger

from core.config import config_manager
from core.database.models import (
    Base, ScanSession, Host, Port, Service, Script,
    Vulnerability, ScanStatistics
)


class DatabaseManager:
    """Main database manager for scan results"""

    def __init__(self):
        self.config = config_manager.get_database_config()
        self.engine = None
        self.SessionLocal = None
        self._initialize_database()

    def _initialize_database(self):
        """Initialize database connection and create tables"""
        try:
            # Create database URL
            if self.config.type == 'sqlite':
                db_url = f"sqlite:///{self.config.sqlite_path}"
                # Ensure directory exists
                from pathlib import Path
                Path(self.config.sqlite_path).parent.mkdir(parents=True, exist_ok=True)
            elif self.config.type == 'postgresql':
                db_url = (f"postgresql://{self.config.username}:{self.config.password}"
                         f"@{self.config.host}:{self.config.port}/{self.config.database}")
            else:
                raise ValueError(f"Unsupported database type: {self.config.type}")

            # Create engine
            engine_kwargs = {
                'echo': False,  # Set to True for SQL debugging
                'pool_pre_ping': True,
            }

            if self.config.type == 'sqlite':
                engine_kwargs['connect_args'] = {'check_same_thread': False}

            self.engine = create_engine(db_url, **engine_kwargs)
            self.SessionLocal = sessionmaker(bind=self.engine)

            # Create all tables
            Base.metadata.create_all(bind=self.engine)

            logger.info(f"Database initialized: {self.config.type}")

        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            raise

    @contextmanager
    def get_session(self):
        """Get database session with automatic cleanup"""
        session = self.SessionLocal()
        try:
            yield session
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error(f"Database session error: {e}")
            raise
        finally:
            session.close()

    # Scan Session Operations
    def create_scan_session(self, name: str, scan_type: str,
                           description: str = None,
                           target_specification: str = None,
                           config_used: Dict = None) -> ScanSession:
        """Create a new scan session"""
        with self.get_session() as session:
            scan_session = ScanSession(
                name=name,
                description=description,
                scan_type=scan_type,
                target_specification=target_specification,
                config_used=config_used,
                status='running'
            )
            session.add(scan_session)
            session.flush()  # Get the ID

            logger.info(f"Created scan session: {scan_session.id} - {name}")
            return scan_session

    def update_scan_session(self, session_id: int, **kwargs) -> Optional[ScanSession]:
        """Update scan session"""
        with self.get_session() as session:
            scan_session = session.query(ScanSession).filter_by(id=session_id).first()
            if scan_session:
                for key, value in kwargs.items():
                    if hasattr(scan_session, key):
                        setattr(scan_session, key, value)

                logger.debug(f"Updated scan session {session_id}")
                return scan_session
            return None

    def complete_scan_session(self, session_id: int) -> Optional[ScanSession]:
        """Mark scan session as completed"""
        return self.update_scan_session(
            session_id,
            status='completed',
            end_time=datetime.utcnow()
        )

    def get_scan_session(self, session_id: int) -> Optional[ScanSession]:
        """Get scan session by ID"""
        with self.get_session() as session:
            return session.query(ScanSession).filter_by(id=session_id).first()

    def list_scan_sessions(self, limit: int = 50, scan_type: str = None) -> List[ScanSession]:
        """List recent scan sessions"""
        with self.get_session() as session:
            query = session.query(ScanSession).order_by(desc(ScanSession.start_time))

            if scan_type:
                query = query.filter_by(scan_type=scan_type)

            return query.limit(limit).all()

    def delete_scan_session(self, session_id: int) -> bool:
        """Delete scan session and all related data"""
        with self.get_session() as session:
            scan_session = session.query(ScanSession).filter_by(id=session_id).first()
            if scan_session:
                session.delete(scan_session)
                logger.info(f"Deleted scan session {session_id}")
                return True
            return False

    # Host Operations
    def add_host(self, ip_address: str, scan_session_id: int,
                hostname: str = None, os_name: str = None,
                os_family: str = None, os_accuracy: int = None,
                os_details: Dict = None, mac_address: str = None) -> Host:
        """Add or update a host"""
        with self.get_session() as session:
            # Check if host already exists in this session
            existing_host = session.query(Host).filter_by(
                ip_address=ip_address,
                scan_session_id=scan_session_id
            ).first()

            if existing_host:
                # Update existing host
                existing_host.last_seen = datetime.utcnow()
                if hostname:
                    existing_host.hostname = hostname
                if os_name:
                    existing_host.os_name = os_name
                if os_family:
                    existing_host.os_family = os_family
                if os_accuracy is not None:
                    existing_host.os_accuracy = os_accuracy
                if os_details:
                    existing_host.os_details = os_details
                if mac_address:
                    existing_host.mac_address = mac_address

                logger.debug(f"Updated host {ip_address}")
                return existing_host
            else:
                # Create new host
                host = Host(
                    ip_address=ip_address,
                    hostname=hostname,
                    os_name=os_name,
                    os_family=os_family,
                    os_accuracy=os_accuracy,
                    os_details=os_details,
                    mac_address=mac_address,
                    scan_session_id=scan_session_id
                )
                session.add(host)
                session.flush()

                logger.debug(f"Added host {ip_address}")
                return host

    def get_host(self, host_id: int) -> Optional[Host]:
        """Get host by ID"""
        with self.get_session() as session:
            return session.query(Host).filter_by(id=host_id).first()

    def find_host_by_ip(self, ip_address: str, scan_session_id: int = None) -> Optional[Host]:
        """Find host by IP address"""
        with self.get_session() as session:
            query = session.query(Host).filter_by(ip_address=ip_address)
            if scan_session_id:
                query = query.filter_by(scan_session_id=scan_session_id)
            return query.first()

    def list_hosts(self, scan_session_id: int = None,
                  os_family: str = None, limit: int = 100) -> List[Host]:
        """List hosts with optional filters"""
        with self.get_session() as session:
            query = session.query(Host)

            if scan_session_id:
                query = query.filter_by(scan_session_id=scan_session_id)
            if os_family:
                query = query.filter_by(os_family=os_family)

            return query.order_by(Host.ip_address).limit(limit).all()

    # Port Operations
    def add_port(self, host_id: int, port_number: int, protocol: str,
                state: str, scan_session_id: int, reason: str = None,
                reason_ttl: int = None) -> Port:
        """Add or update a port"""
        with self.get_session() as session:
            # Check if port already exists
            existing_port = session.query(Port).filter_by(
                host_id=host_id,
                port_number=port_number,
                protocol=protocol,
                scan_session_id=scan_session_id
            ).first()

            if existing_port:
                # Update existing port
                existing_port.state = state
                existing_port.reason = reason
                existing_port.reason_ttl = reason_ttl
                existing_port.last_seen = datetime.utcnow()

                logger.debug(f"Updated port {port_number}/{protocol}")
                return existing_port
            else:
                # Create new port
                port = Port(
                    host_id=host_id,
                    port_number=port_number,
                    protocol=protocol,
                    state=state,
                    reason=reason,
                    reason_ttl=reason_ttl,
                    scan_session_id=scan_session_id
                )
                session.add(port)
                session.flush()

                logger.debug(f"Added port {port_number}/{protocol}")
                return port

    def get_port(self, port_id: int) -> Optional[Port]:
        """Get port by ID"""
        with self.get_session() as session:
            return session.query(Port).filter_by(id=port_id).first()

    def find_ports(self, host_id: int = None, port_number: int = None,
                  protocol: str = None, state: str = None,
                  scan_session_id: int = None) -> List[Port]:
        """Find ports with filters"""
        with self.get_session() as session:
            query = session.query(Port)

            if host_id:
                query = query.filter_by(host_id=host_id)
            if port_number:
                query = query.filter_by(port_number=port_number)
            if protocol:
                query = query.filter_by(protocol=protocol)
            if state:
                query = query.filter_by(state=state)
            if scan_session_id:
                query = query.filter_by(scan_session_id=scan_session_id)

            return query.order_by(Port.port_number).all()

    # Service Operations
    def add_service(self, port_id: int, name: str, scan_session_id: int,
                   product: str = None, version: str = None,
                   extrainfo: str = None, method: str = None,
                   confidence: int = None, banner: str = None) -> Service:
        """Add or update a service"""
        with self.get_session() as session:
            # Check if service already exists
            existing_service = session.query(Service).filter_by(
                port_id=port_id,
                scan_session_id=scan_session_id
            ).first()

            if existing_service:
                # Update existing service
                existing_service.name = name
                existing_service.product = product
                existing_service.version = version
                existing_service.extrainfo = extrainfo
                existing_service.method = method
                existing_service.confidence = confidence
                existing_service.banner = banner
                existing_service.last_seen = datetime.utcnow()

                logger.debug(f"Updated service {name}")
                return existing_service
            else:
                # Create new service
                service = Service(
                    port_id=port_id,
                    name=name,
                    product=product,
                    version=version,
                    extrainfo=extrainfo,
                    method=method,
                    confidence=confidence,
                    banner=banner,
                    scan_session_id=scan_session_id
                )
                session.add(service)
                session.flush()

                logger.debug(f"Added service {name}")
                return service

    def find_services(self, name: str = None, product: str = None,
                     version: str = None, port_number: int = None,
                     scan_session_id: int = None) -> List[Service]:
        """Find services with filters"""
        with self.get_session() as session:
            query = session.query(Service)

            if name:
                query = query.filter(Service.name.ilike(f'%{name}%'))
            if product:
                query = query.filter(Service.product.ilike(f'%{product}%'))
            if version:
                query = query.filter(Service.version.ilike(f'%{version}%'))
            if port_number:
                query = query.join(Port).filter(Port.port_number == port_number)
            if scan_session_id:
                query = query.filter_by(scan_session_id=scan_session_id)

            return query.order_by(Service.name).all()

    # Script Operations
    def add_script_result(self, port_id: int, script_id: str, output: str,
                         scan_session_id: int, elements: Dict = None,
                         execution_time: float = None) -> Script:
        """Add script result"""
        with self.get_session() as session:
            script = Script(
                port_id=port_id,
                script_id=script_id,
                output=output,
                elements=elements,
                execution_time=execution_time,
                scan_session_id=scan_session_id
            )
            session.add(script)
            session.flush()

            logger.debug(f"Added script result {script_id}")
            return script

    def find_script_results(self, script_id: str = None, port_id: int = None,
                           scan_session_id: int = None,
                           contains_text: str = None) -> List[Script]:
        """Find script results with filters"""
        with self.get_session() as session:
            query = session.query(Script)

            if script_id:
                query = query.filter_by(script_id=script_id)
            if port_id:
                query = query.filter_by(port_id=port_id)
            if scan_session_id:
                query = query.filter_by(scan_session_id=scan_session_id)
            if contains_text:
                query = query.filter(Script.output.ilike(f'%{contains_text}%'))

            return query.order_by(Script.timestamp).all()

    # Vulnerability Operations
    def add_vulnerability(self, host_id: int, scan_session_id: int,
                         title: str, description: str = None,
                         severity: str = None, cve_id: str = None,
                         cvss_score: float = None, cvss_vector: str = None,
                         source: str = None, confidence: int = None,
                         port_id: int = None, references: Dict = None) -> Vulnerability:
        """Add vulnerability"""
        with self.get_session() as session:
            vulnerability = Vulnerability(
                host_id=host_id,
                port_id=port_id,
                cve_id=cve_id,
                title=title,
                description=description,
                severity=severity,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                source=source,
                confidence=confidence,
                references=references,
                scan_session_id=scan_session_id
            )
            session.add(vulnerability)
            session.flush()

            logger.debug(f"Added vulnerability {cve_id or title}")
            return vulnerability

    def find_vulnerabilities(self, host_id: int = None, severity: str = None,
                           cve_id: str = None, scan_session_id: int = None,
                           min_cvss_score: float = None) -> List[Vulnerability]:
        """Find vulnerabilities with filters"""
        with self.get_session() as session:
            query = session.query(Vulnerability)

            if host_id:
                query = query.filter_by(host_id=host_id)
            if severity:
                query = query.filter_by(severity=severity)
            if cve_id:
                query = query.filter_by(cve_id=cve_id)
            if scan_session_id:
                query = query.filter_by(scan_session_id=scan_session_id)
            if min_cvss_score:
                query = query.filter(Vulnerability.cvss_score >= min_cvss_score)

            return query.order_by(desc(Vulnerability.cvss_score)).all()