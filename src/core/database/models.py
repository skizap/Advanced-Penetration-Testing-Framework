"""
Database Models for Scan Results
SQLAlchemy models for storing penetration testing scan data
"""

from datetime import datetime
from typing import List, Optional
from sqlalchemy import (
    Column, Integer, String, DateTime, Text, Boolean, Float,
    ForeignKey, Index, JSON, UniqueConstraint
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, Session
from sqlalchemy.sql import func

Base = declarative_base()


class ScanSession(Base):
    """Represents a scan session/run"""
    __tablename__ = 'scan_sessions'

    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    scan_type = Column(String(50), nullable=False)  # 'discovery', 'service', 'vulnerability'
    status = Column(String(20), default='running')  # 'running', 'completed', 'failed'
    start_time = Column(DateTime, default=datetime.utcnow)
    end_time = Column(DateTime)
    config_used = Column(JSON)  # Store configuration used for this scan
    target_specification = Column(Text)  # CIDR blocks, IP ranges, etc.
    total_hosts = Column(Integer, default=0)
    total_ports = Column(Integer, default=0)
    total_services = Column(Integer, default=0)

    # Relationships
    hosts = relationship("Host", back_populates="scan_session", cascade="all, delete-orphan")
    ports = relationship("Port", back_populates="scan_session", cascade="all, delete-orphan")
    services = relationship("Service", back_populates="scan_session", cascade="all, delete-orphan")
    scripts = relationship("Script", back_populates="scan_session", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="scan_session", cascade="all, delete-orphan")

    # Indexes
    __table_args__ = (
        Index('idx_scan_sessions_start_time', 'start_time'),
        Index('idx_scan_sessions_scan_type', 'scan_type'),
        Index('idx_scan_sessions_status', 'status'),
    )

    def __repr__(self):
        return f"<ScanSession(id={self.id}, name='{self.name}', type='{self.scan_type}')>"


class Host(Base):
    """Represents a discovered host"""
    __tablename__ = 'hosts'

    id = Column(Integer, primary_key=True)
    ip_address = Column(String(45), nullable=False)  # IPv4/IPv6
    hostname = Column(String(255))
    mac_address = Column(String(17))  # MAC address if available
    os_name = Column(String(255))
    os_family = Column(String(100))
    os_accuracy = Column(Integer)  # OS detection confidence
    os_details = Column(JSON)  # Additional OS information
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    notes = Column(Text)

    # Foreign Keys
    scan_session_id = Column(Integer, ForeignKey('scan_sessions.id'), nullable=False)

    # Relationships
    scan_session = relationship("ScanSession", back_populates="hosts")
    ports = relationship("Port", back_populates="host", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="host", cascade="all, delete-orphan")

    # Indexes
    __table_args__ = (
        Index('idx_hosts_ip_address', 'ip_address'),
        Index('idx_hosts_hostname', 'hostname'),
        Index('idx_hosts_os_family', 'os_family'),
        Index('idx_hosts_scan_session', 'scan_session_id'),
        Index('idx_hosts_last_seen', 'last_seen'),
        UniqueConstraint('ip_address', 'scan_session_id', name='uq_host_ip_session'),
    )

    def __repr__(self):
        return f"<Host(id={self.id}, ip='{self.ip_address}', hostname='{self.hostname}')>"


class Port(Base):
    """Represents a discovered port on a host"""
    __tablename__ = 'ports'

    id = Column(Integer, primary_key=True)
    port_number = Column(Integer, nullable=False)
    protocol = Column(String(10), nullable=False)  # 'tcp', 'udp'
    state = Column(String(20), nullable=False)  # 'open', 'closed', 'filtered'
    reason = Column(String(50))  # Why port is in this state
    reason_ttl = Column(Integer)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)

    # Foreign Keys
    host_id = Column(Integer, ForeignKey('hosts.id'), nullable=False)
    scan_session_id = Column(Integer, ForeignKey('scan_sessions.id'), nullable=False)

    # Relationships
    host = relationship("Host", back_populates="ports")
    scan_session = relationship("ScanSession", back_populates="ports")
    services = relationship("Service", back_populates="port", cascade="all, delete-orphan")
    scripts = relationship("Script", back_populates="port", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="port", cascade="all, delete-orphan")

    # Indexes
    __table_args__ = (
        Index('idx_ports_number_protocol', 'port_number', 'protocol'),
        Index('idx_ports_state', 'state'),
        Index('idx_ports_host', 'host_id'),
        Index('idx_ports_scan_session', 'scan_session_id'),
        UniqueConstraint('host_id', 'port_number', 'protocol', 'scan_session_id',
                        name='uq_port_host_number_protocol_session'),
    )

    def __repr__(self):
        return f"<Port(id={self.id}, port={self.port_number}/{self.protocol}, state='{self.state}')>"


class Service(Base):
    """Represents a service running on a port"""
    __tablename__ = 'services'

    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    product = Column(String(255))
    version = Column(String(100))
    extrainfo = Column(Text)
    method = Column(String(50))  # Detection method
    confidence = Column(Integer)  # Detection confidence (0-10)
    banner = Column(Text)  # Service banner if available
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)

    # Foreign Keys
    port_id = Column(Integer, ForeignKey('ports.id'), nullable=False)
    scan_session_id = Column(Integer, ForeignKey('scan_sessions.id'), nullable=False)

    # Relationships
    port = relationship("Port", back_populates="services")
    scan_session = relationship("ScanSession", back_populates="services")

    # Indexes
    __table_args__ = (
        Index('idx_services_name', 'name'),
        Index('idx_services_product', 'product'),
        Index('idx_services_version', 'version'),
        Index('idx_services_port', 'port_id'),
        Index('idx_services_scan_session', 'scan_session_id'),
        Index('idx_services_name_version', 'name', 'version'),
    )

    def __repr__(self):
        return f"<Service(id={self.id}, name='{self.name}', product='{self.product}', version='{self.version}')>"


class Script(Base):
    """Represents Nmap script scan results"""
    __tablename__ = 'scripts'

    id = Column(Integer, primary_key=True)
    script_id = Column(String(100), nullable=False)  # Script name (e.g., 'http-title')
    output = Column(Text)
    elements = Column(JSON)  # Structured script output
    execution_time = Column(Float)
    timestamp = Column(DateTime, default=datetime.utcnow)

    # Foreign Keys
    port_id = Column(Integer, ForeignKey('ports.id'), nullable=False)
    scan_session_id = Column(Integer, ForeignKey('scan_sessions.id'), nullable=False)

    # Relationships
    port = relationship("Port", back_populates="scripts")
    scan_session = relationship("ScanSession", back_populates="scripts")

    # Indexes
    __table_args__ = (
        Index('idx_scripts_script_id', 'script_id'),
        Index('idx_scripts_port', 'port_id'),
        Index('idx_scripts_scan_session', 'scan_session_id'),
        Index('idx_scripts_timestamp', 'timestamp'),
    )

    def __repr__(self):
        return f"<Script(id={self.id}, script_id='{self.script_id}', port_id={self.port_id})>"


class Vulnerability(Base):
    """Represents discovered vulnerabilities"""
    __tablename__ = 'vulnerabilities'

    id = Column(Integer, primary_key=True)
    cve_id = Column(String(20))  # CVE identifier
    title = Column(String(500))
    description = Column(Text)
    severity = Column(String(20))  # 'critical', 'high', 'medium', 'low', 'info'
    cvss_score = Column(Float)
    cvss_vector = Column(String(200))
    source = Column(String(100))  # Where vulnerability was detected
    confidence = Column(Integer)  # Detection confidence
    exploit_available = Column(Boolean, default=False)
    patch_available = Column(Boolean, default=False)
    references = Column(JSON)  # URLs, advisories, etc.
    discovered_date = Column(DateTime, default=datetime.utcnow)

    # Foreign Keys
    host_id = Column(Integer, ForeignKey('hosts.id'), nullable=False)
    port_id = Column(Integer, ForeignKey('ports.id'))  # Optional - host-level vulns
    scan_session_id = Column(Integer, ForeignKey('scan_sessions.id'), nullable=False)

    # Relationships
    host = relationship("Host", back_populates="vulnerabilities")
    port = relationship("Port", back_populates="vulnerabilities")
    scan_session = relationship("ScanSession", back_populates="vulnerabilities")

    # Indexes
    __table_args__ = (
        Index('idx_vulnerabilities_cve_id', 'cve_id'),
        Index('idx_vulnerabilities_severity', 'severity'),
        Index('idx_vulnerabilities_cvss_score', 'cvss_score'),
        Index('idx_vulnerabilities_host', 'host_id'),
        Index('idx_vulnerabilities_port', 'port_id'),
        Index('idx_vulnerabilities_scan_session', 'scan_session_id'),
        Index('idx_vulnerabilities_discovered_date', 'discovered_date'),
    )

    def __repr__(self):
        return f"<Vulnerability(id={self.id}, cve_id='{self.cve_id}', severity='{self.severity}')>"


class ScanStatistics(Base):
    """Stores aggregated scan statistics for performance"""
    __tablename__ = 'scan_statistics'

    id = Column(Integer, primary_key=True)
    scan_session_id = Column(Integer, ForeignKey('scan_sessions.id'), nullable=False)
    metric_name = Column(String(100), nullable=False)
    metric_value = Column(String(500))
    numeric_value = Column(Float)
    calculated_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    scan_session = relationship("ScanSession")

    # Indexes
    __table_args__ = (
        Index('idx_scan_statistics_session', 'scan_session_id'),
        Index('idx_scan_statistics_metric', 'metric_name'),
        UniqueConstraint('scan_session_id', 'metric_name', name='uq_scan_statistics_session_metric'),
    )

    def __repr__(self):
        return f"<ScanStatistics(id={self.id}, metric='{self.metric_name}', value='{self.metric_value}')>"