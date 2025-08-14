"""
Advanced Query Builder for Scan Results
Provides complex querying capabilities for analysis and reporting
"""

from typing import List, Dict, Optional, Any, Tuple
from datetime import datetime, timedelta
from sqlalchemy import and_, or_, func, desc, asc, text
from sqlalchemy.orm import Session, joinedload
from loguru import logger

from core.database.models import (
    ScanSession, Host, Port, Service, Script, Vulnerability, ScanStatistics
)


class QueryBuilder:
    """Advanced query builder for scan results"""

    def __init__(self, db_manager):
        self.db_manager = db_manager

    def get_hosts_with_service(self, service_name: str,
                              version_pattern: str = None,
                              scan_session_id: int = None) -> List[Dict]:
        """Find all hosts running a specific service"""
        with self.db_manager.get_session() as session:
            query = session.query(Host, Port, Service).join(Port).join(Service)
            query = query.filter(Service.name.ilike(f'%{service_name}%'))

            if version_pattern:
                query = query.filter(Service.version.ilike(f'%{version_pattern}%'))
            if scan_session_id:
                query = query.filter(Host.scan_session_id == scan_session_id)

            results = []
            for host, port, service in query.all():
                results.append({
                    'host': {
                        'id': host.id,
                        'ip_address': host.ip_address,
                        'hostname': host.hostname,
                        'os_name': host.os_name
                    },
                    'port': {
                        'number': port.port_number,
                        'protocol': port.protocol,
                        'state': port.state
                    },
                    'service': {
                        'name': service.name,
                        'product': service.product,
                        'version': service.version,
                        'confidence': service.confidence
                    }
                })

            logger.info(f"Found {len(results)} hosts with service {service_name}")
            return results

    def get_vulnerability_summary(self, scan_session_id: int = None,
                                 network_filter: str = None) -> Dict:
        """Get vulnerability summary statistics"""
        with self.db_manager.get_session() as session:
            query = session.query(Vulnerability)

            if scan_session_id:
                query = query.filter_by(scan_session_id=scan_session_id)
            if network_filter:
                # Filter by network (e.g., "192.168.1")
                query = query.join(Host).filter(Host.ip_address.like(f'{network_filter}%'))

            vulnerabilities = query.all()

            summary = {
                'total_vulnerabilities': len(vulnerabilities),
                'by_severity': {},
                'by_cvss_range': {'0-3': 0, '4-6': 0, '7-8': 0, '9-10': 0},
                'top_cves': {},
                'affected_hosts': set(),
                'critical_hosts': []
            }

            for vuln in vulnerabilities:
                # Count by severity
                severity = vuln.severity or 'unknown'
                summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1

                # Count by CVSS range
                if vuln.cvss_score:
                    if vuln.cvss_score <= 3:
                        summary['by_cvss_range']['0-3'] += 1
                    elif vuln.cvss_score <= 6:
                        summary['by_cvss_range']['4-6'] += 1
                    elif vuln.cvss_score <= 8:
                        summary['by_cvss_range']['7-8'] += 1
                    else:
                        summary['by_cvss_range']['9-10'] += 1

                # Track top CVEs
                if vuln.cve_id:
                    summary['top_cves'][vuln.cve_id] = summary['top_cves'].get(vuln.cve_id, 0) + 1

                # Track affected hosts
                summary['affected_hosts'].add(vuln.host_id)

                # Track critical hosts
                if vuln.severity in ['critical', 'high'] or (vuln.cvss_score and vuln.cvss_score >= 7):
                    summary['critical_hosts'].append({
                        'host_id': vuln.host_id,
                        'cve_id': vuln.cve_id,
                        'severity': vuln.severity,
                        'cvss_score': vuln.cvss_score
                    })

            summary['affected_hosts'] = len(summary['affected_hosts'])
            summary['top_cves'] = dict(sorted(summary['top_cves'].items(),
                                            key=lambda x: x[1], reverse=True)[:10])

            return summary

    def get_service_statistics(self, scan_session_id: int = None) -> Dict:
        """Get service statistics"""
        with self.db_manager.get_session() as session:
            query = session.query(Service)

            if scan_session_id:
                query = query.filter_by(scan_session_id=scan_session_id)

            services = query.all()

            stats = {
                'total_services': len(services),
                'unique_services': len(set(s.name for s in services)),
                'by_name': {},
                'by_product': {},
                'version_distribution': {},
                'confidence_distribution': {'high': 0, 'medium': 0, 'low': 0}
            }

            for service in services:
                # Count by name
                stats['by_name'][service.name] = stats['by_name'].get(service.name, 0) + 1

                # Count by product
                if service.product:
                    stats['by_product'][service.product] = stats['by_product'].get(service.product, 0) + 1

                # Version distribution
                if service.version:
                    key = f"{service.name} {service.version}"
                    stats['version_distribution'][key] = stats['version_distribution'].get(key, 0) + 1

                # Confidence distribution
                if service.confidence:
                    if service.confidence >= 8:
                        stats['confidence_distribution']['high'] += 1
                    elif service.confidence >= 5:
                        stats['confidence_distribution']['medium'] += 1
                    else:
                        stats['confidence_distribution']['low'] += 1

            # Sort by frequency
            stats['by_name'] = dict(sorted(stats['by_name'].items(),
                                         key=lambda x: x[1], reverse=True)[:20])
            stats['by_product'] = dict(sorted(stats['by_product'].items(),
                                            key=lambda x: x[1], reverse=True)[:20])

            return stats

    def get_port_statistics(self, scan_session_id: int = None) -> Dict:
        """Get port statistics"""
        with self.db_manager.get_session() as session:
            query = session.query(Port)

            if scan_session_id:
                query = query.filter_by(scan_session_id=scan_session_id)

            ports = query.all()

            stats = {
                'total_ports': len(ports),
                'by_state': {},
                'by_protocol': {},
                'top_ports': {},
                'port_ranges': {'1-1023': 0, '1024-49151': 0, '49152-65535': 0}
            }

            for port in ports:
                # Count by state
                stats['by_state'][port.state] = stats['by_state'].get(port.state, 0) + 1

                # Count by protocol
                stats['by_protocol'][port.protocol] = stats['by_protocol'].get(port.protocol, 0) + 1

                # Top ports
                port_key = f"{port.port_number}/{port.protocol}"
                stats['top_ports'][port_key] = stats['top_ports'].get(port_key, 0) + 1

                # Port ranges
                if port.port_number <= 1023:
                    stats['port_ranges']['1-1023'] += 1
                elif port.port_number <= 49151:
                    stats['port_ranges']['1024-49151'] += 1
                else:
                    stats['port_ranges']['49152-65535'] += 1

            # Sort top ports
            stats['top_ports'] = dict(sorted(stats['top_ports'].items(),
                                           key=lambda x: x[1], reverse=True)[:20])

            return stats

    def search_hosts(self, ip_pattern: str = None, hostname_pattern: str = None,
                    os_family: str = None, has_vulnerabilities: bool = None,
                    scan_session_id: int = None) -> List[Dict]:
        """Advanced host search"""
        with self.db_manager.get_session() as session:
            query = session.query(Host)

            if ip_pattern:
                query = query.filter(Host.ip_address.like(f'%{ip_pattern}%'))
            if hostname_pattern:
                query = query.filter(Host.hostname.ilike(f'%{hostname_pattern}%'))
            if os_family:
                query = query.filter(Host.os_family.ilike(f'%{os_family}%'))
            if scan_session_id:
                query = query.filter_by(scan_session_id=scan_session_id)

            if has_vulnerabilities is not None:
                if has_vulnerabilities:
                    query = query.filter(Host.vulnerabilities.any())
                else:
                    query = query.filter(~Host.vulnerabilities.any())

            hosts = query.order_by(Host.ip_address).all()

            results = []
            for host in hosts:
                # Get additional info
                port_count = len(host.ports)
                service_count = sum(len(port.services) for port in host.ports)
                vuln_count = len(host.vulnerabilities)

                results.append({
                    'id': host.id,
                    'ip_address': host.ip_address,
                    'hostname': host.hostname,
                    'os_name': host.os_name,
                    'os_family': host.os_family,
                    'os_accuracy': host.os_accuracy,
                    'port_count': port_count,
                    'service_count': service_count,
                    'vulnerability_count': vuln_count,
                    'first_seen': host.first_seen,
                    'last_seen': host.last_seen
                })

            return results

    def get_network_overview(self, network_prefix: str,
                           scan_session_id: int = None) -> Dict:
        """Get overview of a network (e.g., '192.168.1')"""
        with self.db_manager.get_session() as session:
            query = session.query(Host).filter(Host.ip_address.like(f'{network_prefix}%'))

            if scan_session_id:
                query = query.filter_by(scan_session_id=scan_session_id)

            hosts = query.all()

            overview = {
                'network': network_prefix,
                'total_hosts': len(hosts),
                'active_hosts': len([h for h in hosts if h.is_active]),
                'os_distribution': {},
                'total_ports': 0,
                'total_services': 0,
                'total_vulnerabilities': 0,
                'critical_vulnerabilities': 0,
                'top_services': {},
                'host_details': []
            }

            for host in hosts:
                # OS distribution
                if host.os_family:
                    overview['os_distribution'][host.os_family] = \
                        overview['os_distribution'].get(host.os_family, 0) + 1

                # Count ports and services
                overview['total_ports'] += len(host.ports)
                for port in host.ports:
                    overview['total_services'] += len(port.services)
                    for service in port.services:
                        overview['top_services'][service.name] = \
                            overview['top_services'].get(service.name, 0) + 1

                # Count vulnerabilities
                overview['total_vulnerabilities'] += len(host.vulnerabilities)
                for vuln in host.vulnerabilities:
                    if vuln.severity in ['critical', 'high'] or \
                       (vuln.cvss_score and vuln.cvss_score >= 7):
                        overview['critical_vulnerabilities'] += 1

                # Host summary
                overview['host_details'].append({
                    'ip_address': host.ip_address,
                    'hostname': host.hostname,
                    'os_name': host.os_name,
                    'port_count': len(host.ports),
                    'vulnerability_count': len(host.vulnerabilities)
                })

            # Sort top services
            overview['top_services'] = dict(sorted(overview['top_services'].items(),
                                                 key=lambda x: x[1], reverse=True)[:10])

            return overview

    def find_similar_hosts(self, reference_host_id: int,
                          similarity_criteria: List[str] = None) -> List[Dict]:
        """Find hosts similar to a reference host"""
        if not similarity_criteria:
            similarity_criteria = ['os_family', 'services', 'open_ports']

        with self.db_manager.get_session() as session:
            reference_host = session.query(Host).filter_by(id=reference_host_id).first()
            if not reference_host:
                return []

            # Get reference host characteristics
            ref_os_family = reference_host.os_family
            ref_services = set()
            ref_ports = set()

            for port in reference_host.ports:
                ref_ports.add(f"{port.port_number}/{port.protocol}")
                for service in port.services:
                    ref_services.add(service.name)

            # Find similar hosts
            query = session.query(Host).filter(Host.id != reference_host_id)
            all_hosts = query.all()

            similar_hosts = []
            for host in all_hosts:
                similarity_score = 0
                similarity_details = {}

                # OS family similarity
                if 'os_family' in similarity_criteria and ref_os_family and host.os_family:
                    if host.os_family == ref_os_family:
                        similarity_score += 30
                        similarity_details['os_match'] = True

                # Service similarity
                if 'services' in similarity_criteria:
                    host_services = set()
                    for port in host.ports:
                        for service in port.services:
                            host_services.add(service.name)

                    common_services = ref_services.intersection(host_services)
                    if ref_services:
                        service_similarity = len(common_services) / len(ref_services)
                        similarity_score += service_similarity * 40
                        similarity_details['common_services'] = list(common_services)
                        similarity_details['service_similarity'] = service_similarity

                # Port similarity
                if 'open_ports' in similarity_criteria:
                    host_ports = set()
                    for port in host.ports:
                        host_ports.add(f"{port.port_number}/{port.protocol}")

                    common_ports = ref_ports.intersection(host_ports)
                    if ref_ports:
                        port_similarity = len(common_ports) / len(ref_ports)
                        similarity_score += port_similarity * 30
                        similarity_details['common_ports'] = list(common_ports)
                        similarity_details['port_similarity'] = port_similarity

                # Only include hosts with reasonable similarity
                if similarity_score >= 20:
                    similar_hosts.append({
                        'host': {
                            'id': host.id,
                            'ip_address': host.ip_address,
                            'hostname': host.hostname,
                            'os_name': host.os_name,
                            'os_family': host.os_family
                        },
                        'similarity_score': similarity_score,
                        'similarity_details': similarity_details
                    })

            # Sort by similarity score
            similar_hosts.sort(key=lambda x: x['similarity_score'], reverse=True)

            return similar_hosts[:20]  # Return top 20 similar hosts