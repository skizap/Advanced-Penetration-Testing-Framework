"""
Database Utilities
Backup, restore, migration, and maintenance utilities
"""

import json
import gzip
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
from sqlalchemy import text, func
from loguru import logger

from core.database.manager import DatabaseManager
from core.database.models import (
    ScanSession, Host, Port, Service, Script, Vulnerability, ScanStatistics
)


class DatabaseUtils:
    """Database maintenance and utility functions"""

    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager

    def backup_database(self, backup_path: str,
                       compress: bool = True,
                       include_sessions: List[int] = None) -> bool:
        """
        Create a backup of scan data

        Args:
            backup_path: Path for backup file
            compress: Whether to compress the backup
            include_sessions: List of session IDs to include (None for all)

        Returns:
            True if backup successful
        """
        try:
            backup_data = {
                'metadata': {
                    'created_at': datetime.utcnow().isoformat(),
                    'version': '1.0',
                    'total_sessions': 0,
                    'total_hosts': 0,
                    'total_ports': 0,
                    'total_services': 0,
                    'total_vulnerabilities': 0
                },
                'scan_sessions': [],
                'hosts': [],
                'ports': [],
                'services': [],
                'scripts': [],
                'vulnerabilities': []
            }

            with self.db_manager.get_session() as session:
                # Get scan sessions
                session_query = session.query(ScanSession)
                if include_sessions:
                    session_query = session_query.filter(ScanSession.id.in_(include_sessions))

                scan_sessions = session_query.all()
                session_ids = [s.id for s in scan_sessions]

                # Export scan sessions
                for scan_session in scan_sessions:
                    backup_data['scan_sessions'].append({
                        'id': scan_session.id,
                        'name': scan_session.name,
                        'description': scan_session.description,
                        'scan_type': scan_session.scan_type,
                        'status': scan_session.status,
                        'start_time': scan_session.start_time.isoformat() if scan_session.start_time else None,
                        'end_time': scan_session.end_time.isoformat() if scan_session.end_time else None,
                        'config_used': scan_session.config_used,
                        'target_specification': scan_session.target_specification,
                        'total_hosts': scan_session.total_hosts,
                        'total_ports': scan_session.total_ports,
                        'total_services': scan_session.total_services
                    })

                # Export hosts
                hosts = session.query(Host).filter(Host.scan_session_id.in_(session_ids)).all()
                for host in hosts:
                    backup_data['hosts'].append({
                        'id': host.id,
                        'ip_address': host.ip_address,
                        'hostname': host.hostname,
                        'mac_address': host.mac_address,
                        'os_name': host.os_name,
                        'os_family': host.os_family,
                        'os_accuracy': host.os_accuracy,
                        'os_details': host.os_details,
                        'first_seen': host.first_seen.isoformat() if host.first_seen else None,
                        'last_seen': host.last_seen.isoformat() if host.last_seen else None,
                        'is_active': host.is_active,
                        'notes': host.notes,
                        'scan_session_id': host.scan_session_id
                    })

                # Export ports
                ports = session.query(Port).filter(Port.scan_session_id.in_(session_ids)).all()
                for port in ports:
                    backup_data['ports'].append({
                        'id': port.id,
                        'port_number': port.port_number,
                        'protocol': port.protocol,
                        'state': port.state,
                        'reason': port.reason,
                        'reason_ttl': port.reason_ttl,
                        'first_seen': port.first_seen.isoformat() if port.first_seen else None,
                        'last_seen': port.last_seen.isoformat() if port.last_seen else None,
                        'host_id': port.host_id,
                        'scan_session_id': port.scan_session_id
                    })

                # Export services
                services = session.query(Service).filter(Service.scan_session_id.in_(session_ids)).all()
                for service in services:
                    backup_data['services'].append({
                        'id': service.id,
                        'name': service.name,
                        'product': service.product,
                        'version': service.version,
                        'extrainfo': service.extrainfo,
                        'method': service.method,
                        'confidence': service.confidence,
                        'banner': service.banner,
                        'first_seen': service.first_seen.isoformat() if service.first_seen else None,
                        'last_seen': service.last_seen.isoformat() if service.last_seen else None,
                        'port_id': service.port_id,
                        'scan_session_id': service.scan_session_id
                    })

                # Export scripts
                scripts = session.query(Script).filter(Script.scan_session_id.in_(session_ids)).all()
                for script in scripts:
                    backup_data['scripts'].append({
                        'id': script.id,
                        'script_id': script.script_id,
                        'output': script.output,
                        'elements': script.elements,
                        'execution_time': script.execution_time,
                        'timestamp': script.timestamp.isoformat() if script.timestamp else None,
                        'port_id': script.port_id,
                        'scan_session_id': script.scan_session_id
                    })

                # Export vulnerabilities
                vulnerabilities = session.query(Vulnerability).filter(Vulnerability.scan_session_id.in_(session_ids)).all()
                for vuln in vulnerabilities:
                    backup_data['vulnerabilities'].append({
                        'id': vuln.id,
                        'cve_id': vuln.cve_id,
                        'title': vuln.title,
                        'description': vuln.description,
                        'severity': vuln.severity,
                        'cvss_score': vuln.cvss_score,
                        'cvss_vector': vuln.cvss_vector,
                        'source': vuln.source,
                        'confidence': vuln.confidence,
                        'exploit_available': vuln.exploit_available,
                        'patch_available': vuln.patch_available,
                        'references': vuln.references,
                        'discovered_date': vuln.discovered_date.isoformat() if vuln.discovered_date else None,
                        'host_id': vuln.host_id,
                        'port_id': vuln.port_id,
                        'scan_session_id': vuln.scan_session_id
                    })

                # Update metadata
                backup_data['metadata'].update({
                    'total_sessions': len(backup_data['scan_sessions']),
                    'total_hosts': len(backup_data['hosts']),
                    'total_ports': len(backup_data['ports']),
                    'total_services': len(backup_data['services']),
                    'total_vulnerabilities': len(backup_data['vulnerabilities'])
                })

            # Write backup file
            backup_path_obj = Path(backup_path)
            backup_path_obj.parent.mkdir(parents=True, exist_ok=True)

            if compress:
                with gzip.open(backup_path, 'wt', encoding='utf-8') as f:
                    json.dump(backup_data, f, indent=2)
            else:
                with open(backup_path, 'w', encoding='utf-8') as f:
                    json.dump(backup_data, f, indent=2)

            logger.info(f"Database backup created: {backup_path}")
            logger.info(f"Backup contains: {backup_data['metadata']}")

            return True

        except Exception as e:
            logger.error(f"Database backup failed: {e}")
            return False

    def restore_database(self, backup_path: str,
                        clear_existing: bool = False) -> bool:
        """
        Restore database from backup

        Args:
            backup_path: Path to backup file
            clear_existing: Whether to clear existing data first

        Returns:
            True if restore successful
        """
        try:
            # Load backup data
            backup_path_obj = Path(backup_path)
            if not backup_path_obj.exists():
                logger.error(f"Backup file not found: {backup_path}")
                return False

            if backup_path.endswith('.gz'):
                with gzip.open(backup_path, 'rt', encoding='utf-8') as f:
                    backup_data = json.load(f)
            else:
                with open(backup_path, 'r', encoding='utf-8') as f:
                    backup_data = json.load(f)

            logger.info(f"Restoring database from: {backup_path}")
            logger.info(f"Backup metadata: {backup_data['metadata']}")

            # Clear existing data if requested
            if clear_existing:
                self.clear_all_data()

            # Restore data in correct order (respecting foreign keys)
            with self.db_manager.get_session() as session:
                # Restore scan sessions
                for session_data in backup_data['scan_sessions']:
                    scan_session = ScanSession(
                        name=session_data['name'],
                        description=session_data['description'],
                        scan_type=session_data['scan_type'],
                        status=session_data['status'],
                        start_time=datetime.fromisoformat(session_data['start_time']) if session_data['start_time'] else None,
                        end_time=datetime.fromisoformat(session_data['end_time']) if session_data['end_time'] else None,
                        config_used=session_data['config_used'],
                        target_specification=session_data['target_specification'],
                        total_hosts=session_data['total_hosts'],
                        total_ports=session_data['total_ports'],
                        total_services=session_data['total_services']
                    )
                    session.add(scan_session)

                session.flush()  # Get IDs

                # Create ID mapping for foreign keys
                session_id_map = {}
                for i, session_data in enumerate(backup_data['scan_sessions']):
                    new_session = session.query(ScanSession).order_by(ScanSession.id.desc()).offset(i).first()
                    session_id_map[session_data['id']] = new_session.id

                # Restore hosts
                host_id_map = {}
                for host_data in backup_data['hosts']:
                    host = Host(
                        ip_address=host_data['ip_address'],
                        hostname=host_data['hostname'],
                        mac_address=host_data['mac_address'],
                        os_name=host_data['os_name'],
                        os_family=host_data['os_family'],
                        os_accuracy=host_data['os_accuracy'],
                        os_details=host_data['os_details'],
                        first_seen=datetime.fromisoformat(host_data['first_seen']) if host_data['first_seen'] else None,
                        last_seen=datetime.fromisoformat(host_data['last_seen']) if host_data['last_seen'] else None,
                        is_active=host_data['is_active'],
                        notes=host_data['notes'],
                        scan_session_id=session_id_map[host_data['scan_session_id']]
                    )
                    session.add(host)
                    session.flush()
                    host_id_map[host_data['id']] = host.id

                # Restore ports
                port_id_map = {}
                for port_data in backup_data['ports']:
                    port = Port(
                        port_number=port_data['port_number'],
                        protocol=port_data['protocol'],
                        state=port_data['state'],
                        reason=port_data['reason'],
                        reason_ttl=port_data['reason_ttl'],
                        first_seen=datetime.fromisoformat(port_data['first_seen']) if port_data['first_seen'] else None,
                        last_seen=datetime.fromisoformat(port_data['last_seen']) if port_data['last_seen'] else None,
                        host_id=host_id_map[port_data['host_id']],
                        scan_session_id=session_id_map[port_data['scan_session_id']]
                    )
                    session.add(port)
                    session.flush()
                    port_id_map[port_data['id']] = port.id

                # Restore services
                for service_data in backup_data['services']:
                    service = Service(
                        name=service_data['name'],
                        product=service_data['product'],
                        version=service_data['version'],
                        extrainfo=service_data['extrainfo'],
                        method=service_data['method'],
                        confidence=service_data['confidence'],
                        banner=service_data['banner'],
                        first_seen=datetime.fromisoformat(service_data['first_seen']) if service_data['first_seen'] else None,
                        last_seen=datetime.fromisoformat(service_data['last_seen']) if service_data['last_seen'] else None,
                        port_id=port_id_map[service_data['port_id']],
                        scan_session_id=session_id_map[service_data['scan_session_id']]
                    )
                    session.add(service)

                # Restore scripts
                for script_data in backup_data['scripts']:
                    script = Script(
                        script_id=script_data['script_id'],
                        output=script_data['output'],
                        elements=script_data['elements'],
                        execution_time=script_data['execution_time'],
                        timestamp=datetime.fromisoformat(script_data['timestamp']) if script_data['timestamp'] else None,
                        port_id=port_id_map[script_data['port_id']],
                        scan_session_id=session_id_map[script_data['scan_session_id']]
                    )
                    session.add(script)

                # Restore vulnerabilities
                for vuln_data in backup_data['vulnerabilities']:
                    vulnerability = Vulnerability(
                        cve_id=vuln_data['cve_id'],
                        title=vuln_data['title'],
                        description=vuln_data['description'],
                        severity=vuln_data['severity'],
                        cvss_score=vuln_data['cvss_score'],
                        cvss_vector=vuln_data['cvss_vector'],
                        source=vuln_data['source'],
                        confidence=vuln_data['confidence'],
                        exploit_available=vuln_data['exploit_available'],
                        patch_available=vuln_data['patch_available'],
                        references=vuln_data['references'],
                        discovered_date=datetime.fromisoformat(vuln_data['discovered_date']) if vuln_data['discovered_date'] else None,
                        host_id=host_id_map[vuln_data['host_id']],
                        port_id=port_id_map.get(vuln_data['port_id']) if vuln_data['port_id'] else None,
                        scan_session_id=session_id_map[vuln_data['scan_session_id']]
                    )
                    session.add(vulnerability)

            logger.info("Database restore completed successfully")
            return True

        except Exception as e:
            logger.error(f"Database restore failed: {e}")
            return False

    def clear_all_data(self) -> bool:
        """Clear all scan data from database"""
        try:
            with self.db_manager.get_session() as session:
                # Delete in reverse order of dependencies
                session.query(Vulnerability).delete()
                session.query(Script).delete()
                session.query(Service).delete()
                session.query(Port).delete()
                session.query(Host).delete()
                session.query(ScanStatistics).delete()
                session.query(ScanSession).delete()

            logger.info("All scan data cleared from database")
            return True

        except Exception as e:
            logger.error(f"Failed to clear database: {e}")
            return False

    def cleanup_old_data(self, days_to_keep: int = 30) -> Dict[str, int]:
        """
        Clean up old scan data

        Args:
            days_to_keep: Number of days of data to keep

        Returns:
            Dictionary with cleanup statistics
        """
        cutoff_date = datetime.utcnow() - timedelta(days=days_to_keep)
        stats = {
            'sessions_deleted': 0,
            'hosts_deleted': 0,
            'ports_deleted': 0,
            'services_deleted': 0,
            'scripts_deleted': 0,
            'vulnerabilities_deleted': 0
        }

        try:
            with self.db_manager.get_session() as session:
                # Find old sessions
                old_sessions = session.query(ScanSession).filter(
                    ScanSession.start_time < cutoff_date
                ).all()

                for scan_session in old_sessions:
                    # Count related records before deletion
                    stats['hosts_deleted'] += len(scan_session.hosts)
                    stats['ports_deleted'] += len(scan_session.ports)
                    stats['services_deleted'] += len(scan_session.services)
                    stats['scripts_deleted'] += len(scan_session.scripts)
                    stats['vulnerabilities_deleted'] += len(scan_session.vulnerabilities)

                    # Delete session (cascades to related records)
                    session.delete(scan_session)
                    stats['sessions_deleted'] += 1

            logger.info(f"Cleanup completed: {stats}")
            return stats

        except Exception as e:
            logger.error(f"Cleanup failed: {e}")
            return stats

    def optimize_database(self) -> bool:
        """Optimize database performance"""
        try:
            with self.db_manager.get_session() as session:
                if self.db_manager.config.type == 'sqlite':
                    # SQLite optimization
                    session.execute(text("VACUUM"))
                    session.execute(text("ANALYZE"))
                    logger.info("SQLite database optimized")

                elif self.db_manager.config.type == 'postgresql':
                    # PostgreSQL optimization
                    session.execute(text("VACUUM ANALYZE"))
                    logger.info("PostgreSQL database optimized")

            return True

        except Exception as e:
            logger.error(f"Database optimization failed: {e}")
            return False

    def get_database_statistics(self) -> Dict[str, Any]:
        """Get comprehensive database statistics"""
        stats = {}

        try:
            with self.db_manager.get_session() as session:
                # Count records
                stats['scan_sessions'] = session.query(ScanSession).count()
                stats['hosts'] = session.query(Host).count()
                stats['ports'] = session.query(Port).count()
                stats['services'] = session.query(Service).count()
                stats['scripts'] = session.query(Script).count()
                stats['vulnerabilities'] = session.query(Vulnerability).count()

                # Recent activity
                recent_date = datetime.utcnow() - timedelta(days=7)
                stats['recent_sessions'] = session.query(ScanSession).filter(
                    ScanSession.start_time >= recent_date
                ).count()

                # Database size (approximate)
                if self.db_manager.config.type == 'sqlite':
                    db_path = Path(self.db_manager.config.sqlite_path)
                    if db_path.exists():
                        stats['database_size_mb'] = db_path.stat().st_size / (1024 * 1024)

                # Top scan types
                scan_type_counts = session.query(
                    ScanSession.scan_type,
                    func.count(ScanSession.id)
                ).group_by(ScanSession.scan_type).all()

                stats['scan_types'] = {scan_type: count for scan_type, count in scan_type_counts}

                # Top OS families
                os_family_counts = session.query(
                    Host.os_family,
                    func.count(Host.id)
                ).filter(Host.os_family.isnot(None)).group_by(Host.os_family).limit(10).all()

                stats['top_os_families'] = {os_family: count for os_family, count in os_family_counts}

                # Top services
                service_counts = session.query(
                    Service.name,
                    func.count(Service.id)
                ).group_by(Service.name).limit(10).all()

                stats['top_services'] = {service: count for service, count in service_counts}

                # Vulnerability severity distribution
                vuln_severity_counts = session.query(
                    Vulnerability.severity,
                    func.count(Vulnerability.id)
                ).filter(Vulnerability.severity.isnot(None)).group_by(Vulnerability.severity).all()

                stats['vulnerability_severity'] = {severity: count for severity, count in vuln_severity_counts}

            return stats

        except Exception as e:
            logger.error(f"Failed to get database statistics: {e}")
            return {}

    def export_to_csv(self, output_dir: str,
                     scan_session_id: int = None) -> bool:
        """
        Export data to CSV files

        Args:
            output_dir: Directory to save CSV files
            scan_session_id: Optional session ID to filter by

        Returns:
            True if export successful
        """
        try:
            import csv

            output_path = Path(output_dir)
            output_path.mkdir(parents=True, exist_ok=True)

            with self.db_manager.get_session() as session:
                # Export hosts
                hosts_query = session.query(Host)
                if scan_session_id:
                    hosts_query = hosts_query.filter_by(scan_session_id=scan_session_id)

                with open(output_path / 'hosts.csv', 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        'ID', 'IP_Address', 'Hostname', 'MAC_Address', 'OS_Name',
                        'OS_Family', 'OS_Accuracy', 'First_Seen', 'Last_Seen',
                        'Is_Active', 'Scan_Session_ID'
                    ])

                    for host in hosts_query.all():
                        writer.writerow([
                            host.id, host.ip_address, host.hostname, host.mac_address,
                            host.os_name, host.os_family, host.os_accuracy,
                            host.first_seen, host.last_seen, host.is_active,
                            host.scan_session_id
                        ])

                # Export services
                services_query = session.query(Service, Port, Host).join(Port).join(Host)
                if scan_session_id:
                    services_query = services_query.filter(Service.scan_session_id == scan_session_id)

                with open(output_path / 'services.csv', 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        'Host_IP', 'Port', 'Protocol', 'Service_Name', 'Product',
                        'Version', 'Confidence', 'Method', 'Scan_Session_ID'
                    ])

                    for service, port, host in services_query.all():
                        writer.writerow([
                            host.ip_address, port.port_number, port.protocol,
                            service.name, service.product, service.version,
                            service.confidence, service.method, service.scan_session_id
                        ])

                # Export vulnerabilities
                vulns_query = session.query(Vulnerability, Host).join(Host)
                if scan_session_id:
                    vulns_query = vulns_query.filter(Vulnerability.scan_session_id == scan_session_id)

                with open(output_path / 'vulnerabilities.csv', 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        'Host_IP', 'CVE_ID', 'Title', 'Severity', 'CVSS_Score',
                        'Source', 'Confidence', 'Discovered_Date', 'Scan_Session_ID'
                    ])

                    for vuln, host in vulns_query.all():
                        writer.writerow([
                            host.ip_address, vuln.cve_id, vuln.title, vuln.severity,
                            vuln.cvss_score, vuln.source, vuln.confidence,
                            vuln.discovered_date, vuln.scan_session_id
                        ])

            logger.info(f"CSV export completed to: {output_dir}")
            return True

        except Exception as e:
            logger.error(f"CSV export failed: {e}")
            return False