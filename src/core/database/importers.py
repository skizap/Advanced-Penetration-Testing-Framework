"""
Scanner Result Importers
Import scan results from various scanners into the database
"""

from typing import List, Dict, Optional
from datetime import datetime
from loguru import logger

from scanner.masscan_scanner import ScanResult as MasscanResult, PortResult
from scanner.nmap_scanner import DetailedScanResult as NmapResult, DetailedPortResult
from core.database.manager import DatabaseManager


class ScanResultImporter:
    """Import scan results into database"""

    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager

    def import_masscan_results(self, results: List[MasscanResult],
                              scan_session_id: int) -> Dict[str, int]:
        """
        Import Masscan results into database

        Args:
            results: List of Masscan scan results
            scan_session_id: ID of the scan session

        Returns:
            Dictionary with import statistics
        """
        stats = {
            'hosts_added': 0,
            'hosts_updated': 0,
            'ports_added': 0,
            'ports_updated': 0,
            'errors': 0
        }

        logger.info(f"Importing {len(results)} Masscan results to session {scan_session_id}")

        for result in results:
            try:
                # Add or update host
                existing_host = self.db_manager.find_host_by_ip(result.ip, scan_session_id)
                if existing_host:
                    stats['hosts_updated'] += 1
                    host = existing_host
                else:
                    host = self.db_manager.add_host(
                        ip_address=result.ip,
                        scan_session_id=scan_session_id
                    )
                    stats['hosts_added'] += 1

                # Add ports
                for port_result in result.ports:
                    try:
                        existing_ports = self.db_manager.find_ports(
                            host_id=host.id,
                            port_number=port_result.port,
                            protocol=port_result.protocol,
                            scan_session_id=scan_session_id
                        )

                        if existing_ports:
                            stats['ports_updated'] += 1
                        else:
                            self.db_manager.add_port(
                                host_id=host.id,
                                port_number=port_result.port,
                                protocol=port_result.protocol,
                                state=port_result.state,
                                scan_session_id=scan_session_id
                            )
                            stats['ports_added'] += 1

                    except Exception as e:
                        logger.error(f"Error importing port {port_result.port}: {e}")
                        stats['errors'] += 1

            except Exception as e:
                logger.error(f"Error importing host {result.ip}: {e}")
                stats['errors'] += 1

        logger.info(f"Masscan import completed: {stats}")
        return stats

    def import_nmap_results(self, results: List[NmapResult],
                           scan_session_id: int) -> Dict[str, int]:
        """
        Import Nmap results into database

        Args:
            results: List of Nmap detailed scan results
            scan_session_id: ID of the scan session

        Returns:
            Dictionary with import statistics
        """
        stats = {
            'hosts_added': 0,
            'hosts_updated': 0,
            'ports_added': 0,
            'ports_updated': 0,
            'services_added': 0,
            'services_updated': 0,
            'scripts_added': 0,
            'vulnerabilities_added': 0,
            'errors': 0
        }

        logger.info(f"Importing {len(results)} Nmap results to session {scan_session_id}")

        for result in results:
            try:
                # Add or update host with OS information
                os_details = None
                if result.os_matches:
                    os_details = {
                        'matches': [
                            {
                                'name': match.name,
                                'accuracy': match.accuracy,
                                'line': match.line,
                                'osclass': match.osclass
                            }
                            for match in result.os_matches
                        ]
                    }

                existing_host = self.db_manager.find_host_by_ip(result.ip, scan_session_id)
                if existing_host:
                    # Update with new information
                    host = self.db_manager.add_host(
                        ip_address=result.ip,
                        scan_session_id=scan_session_id,
                        hostname=result.hostname,
                        os_name=result.os_matches[0].name if result.os_matches else None,
                        os_family=result.os_matches[0].osclass.get('osfamily') if result.os_matches and result.os_matches[0].osclass else None,
                        os_accuracy=result.os_matches[0].accuracy if result.os_matches else None,
                        os_details=os_details
                    )
                    stats['hosts_updated'] += 1
                else:
                    host = self.db_manager.add_host(
                        ip_address=result.ip,
                        scan_session_id=scan_session_id,
                        hostname=result.hostname,
                        os_name=result.os_matches[0].name if result.os_matches else None,
                        os_family=result.os_matches[0].osclass.get('osfamily') if result.os_matches and result.os_matches[0].osclass else None,
                        os_accuracy=result.os_matches[0].accuracy if result.os_matches else None,
                        os_details=os_details
                    )
                    stats['hosts_added'] += 1

                # Process ports with detailed information
                for port_result in result.ports:
                    try:
                        # Add or update port
                        existing_ports = self.db_manager.find_ports(
                            host_id=host.id,
                            port_number=port_result.port,
                            protocol=port_result.protocol,
                            scan_session_id=scan_session_id
                        )

                        if existing_ports:
                            port = existing_ports[0]
                            stats['ports_updated'] += 1
                        else:
                            port = self.db_manager.add_port(
                                host_id=host.id,
                                port_number=port_result.port,
                                protocol=port_result.protocol,
                                state=port_result.state,
                                reason=port_result.reason,
                                reason_ttl=port_result.reason_ttl,
                                scan_session_id=scan_session_id
                            )
                            stats['ports_added'] += 1

                        # Add service information
                        if port_result.service:
                            service = self.db_manager.add_service(
                                port_id=port.id,
                                name=port_result.service.name,
                                product=port_result.service.product,
                                version=port_result.service.version,
                                extrainfo=port_result.service.extrainfo,
                                method=port_result.service.method,
                                confidence=port_result.service.conf,
                                scan_session_id=scan_session_id
                            )
                            stats['services_added'] += 1

                        # Add script results
                        if port_result.scripts:
                            for script_result in port_result.scripts:
                                self.db_manager.add_script_result(
                                    port_id=port.id,
                                    script_id=script_result.id,
                                    output=script_result.output,
                                    elements=script_result.elements,
                                    scan_session_id=scan_session_id
                                )
                                stats['scripts_added'] += 1

                                # Check for vulnerabilities in script output
                                if self._is_vulnerability_script(script_result):
                                    vuln_info = self._extract_vulnerability_info(script_result)
                                    if vuln_info:
                                        self.db_manager.add_vulnerability(
                                            host_id=host.id,
                                            port_id=port.id,
                                            title=vuln_info.get('title', script_result.id),
                                            description=script_result.output,
                                            severity=vuln_info.get('severity'),
                                            cve_id=vuln_info.get('cve_id'),
                                            cvss_score=vuln_info.get('cvss_score'),
                                            source=f"nmap_script_{script_result.id}",
                                            confidence=8,  # High confidence for script-detected vulns
                                            scan_session_id=scan_session_id
                                        )
                                        stats['vulnerabilities_added'] += 1

                    except Exception as e:
                        logger.error(f"Error importing port {port_result.port}: {e}")
                        stats['errors'] += 1

            except Exception as e:
                logger.error(f"Error importing host {result.ip}: {e}")
                stats['errors'] += 1

        logger.info(f"Nmap import completed: {stats}")
        return stats

    def _is_vulnerability_script(self, script_result) -> bool:
        """Check if script result indicates a vulnerability"""
        vuln_indicators = [
            'vuln', 'cve-', 'exploit', 'vulnerable', 'security',
            'weakness', 'flaw', 'backdoor', 'malware', 'dos'
        ]

        script_id_lower = script_result.id.lower()
        output_lower = script_result.output.lower()

        return (any(indicator in script_id_lower for indicator in vuln_indicators) or
                any(indicator in output_lower for indicator in vuln_indicators))

    def _extract_vulnerability_info(self, script_result) -> Optional[Dict]:
        """Extract vulnerability information from script result"""
        import re

        output = script_result.output
        vuln_info = {}

        # Extract CVE IDs
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        cve_matches = re.findall(cve_pattern, output, re.IGNORECASE)
        if cve_matches:
            vuln_info['cve_id'] = cve_matches[0]

        # Extract CVSS scores
        cvss_pattern = r'CVSS:?\s*(\d+\.?\d*)'
        cvss_matches = re.findall(cvss_pattern, output, re.IGNORECASE)
        if cvss_matches:
            try:
                vuln_info['cvss_score'] = float(cvss_matches[0])
            except ValueError:
                pass

        # Determine severity based on keywords and CVSS
        severity_keywords = {
            'critical': ['critical', 'severe'],
            'high': ['high', 'dangerous', 'exploit'],
            'medium': ['medium', 'moderate'],
            'low': ['low', 'minor', 'info']
        }

        output_lower = output.lower()
        for severity, keywords in severity_keywords.items():
            if any(keyword in output_lower for keyword in keywords):
                vuln_info['severity'] = severity
                break

        # If no severity found but CVSS available, determine from score
        if 'severity' not in vuln_info and 'cvss_score' in vuln_info:
            score = vuln_info['cvss_score']
            if score >= 9.0:
                vuln_info['severity'] = 'critical'
            elif score >= 7.0:
                vuln_info['severity'] = 'high'
            elif score >= 4.0:
                vuln_info['severity'] = 'medium'
            else:
                vuln_info['severity'] = 'low'

        # Extract title from script output
        lines = output.split('\n')
        if lines:
            # Use first non-empty line as title
            for line in lines:
                line = line.strip()
                if line and not line.startswith('|'):
                    vuln_info['title'] = line[:200]  # Limit title length
                    break

        return vuln_info if vuln_info else None

    def import_vulnerability_data(self, vulnerability_data: List[Dict],
                                 scan_session_id: int) -> Dict[str, int]:
        """
        Import external vulnerability data

        Args:
            vulnerability_data: List of vulnerability dictionaries
            scan_session_id: ID of the scan session

        Returns:
            Dictionary with import statistics
        """
        stats = {
            'vulnerabilities_added': 0,
            'vulnerabilities_updated': 0,
            'errors': 0
        }

        logger.info(f"Importing {len(vulnerability_data)} vulnerabilities to session {scan_session_id}")

        for vuln_data in vulnerability_data:
            try:
                # Find the host
                host = self.db_manager.find_host_by_ip(
                    vuln_data['ip_address'],
                    scan_session_id
                )

                if not host:
                    logger.warning(f"Host {vuln_data['ip_address']} not found, skipping vulnerability")
                    continue

                # Find the port if specified
                port_id = None
                if 'port_number' in vuln_data and 'protocol' in vuln_data:
                    ports = self.db_manager.find_ports(
                        host_id=host.id,
                        port_number=vuln_data['port_number'],
                        protocol=vuln_data['protocol'],
                        scan_session_id=scan_session_id
                    )
                    if ports:
                        port_id = ports[0].id

                # Add vulnerability
                self.db_manager.add_vulnerability(
                    host_id=host.id,
                    port_id=port_id,
                    cve_id=vuln_data.get('cve_id'),
                    title=vuln_data.get('title', 'Unknown Vulnerability'),
                    description=vuln_data.get('description'),
                    severity=vuln_data.get('severity'),
                    cvss_score=vuln_data.get('cvss_score'),
                    cvss_vector=vuln_data.get('cvss_vector'),
                    source=vuln_data.get('source', 'external'),
                    confidence=vuln_data.get('confidence', 5),
                    references=vuln_data.get('references'),
                    scan_session_id=scan_session_id
                )

                stats['vulnerabilities_added'] += 1

            except Exception as e:
                logger.error(f"Error importing vulnerability: {e}")
                stats['errors'] += 1

        logger.info(f"Vulnerability import completed: {stats}")
        return stats

    def bulk_import_hosts(self, host_data: List[Dict],
                         scan_session_id: int) -> Dict[str, int]:
        """
        Bulk import host data for performance

        Args:
            host_data: List of host dictionaries
            scan_session_id: ID of the scan session

        Returns:
            Dictionary with import statistics
        """
        stats = {
            'hosts_added': 0,
            'hosts_updated': 0,
            'errors': 0
        }

        logger.info(f"Bulk importing {len(host_data)} hosts to session {scan_session_id}")

        # Process in batches for better performance
        batch_size = 100
        for i in range(0, len(host_data), batch_size):
            batch = host_data[i:i + batch_size]

            try:
                with self.db_manager.get_session() as session:
                    for host_info in batch:
                        try:
                            host = self.db_manager.add_host(
                                ip_address=host_info['ip_address'],
                                scan_session_id=scan_session_id,
                                hostname=host_info.get('hostname'),
                                os_name=host_info.get('os_name'),
                                os_family=host_info.get('os_family'),
                                os_accuracy=host_info.get('os_accuracy'),
                                mac_address=host_info.get('mac_address')
                            )
                            stats['hosts_added'] += 1

                        except Exception as e:
                            logger.error(f"Error in bulk import for host {host_info.get('ip_address')}: {e}")
                            stats['errors'] += 1

            except Exception as e:
                logger.error(f"Error in bulk import batch: {e}")
                stats['errors'] += len(batch)

        logger.info(f"Bulk import completed: {stats}")
        return stats