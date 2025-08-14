"""
Nmap Service Enumeration Module
Detailed service detection and OS fingerprinting using Nmap
"""

import asyncio
import json
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict, Set, Optional, Tuple, AsyncIterator
from dataclasses import dataclass, asdict
from loguru import logger
from core.config import config_manager
from scanner.masscan_scanner import ScanResult, PortResult


@dataclass
class ServiceInfo:
    """Detailed service information"""
    name: str
    product: Optional[str] = None
    version: Optional[str] = None
    extrainfo: Optional[str] = None
    method: Optional[str] = None
    conf: Optional[int] = None


@dataclass
class ScriptResult:
    """Nmap script scan result"""
    id: str
    output: str
    elements: Optional[Dict] = None


@dataclass
class OSMatch:
    """OS detection match"""
    name: str
    accuracy: int
    line: int
    osclass: Optional[Dict] = None


@dataclass
class DetailedPortResult:
    """Enhanced port result with service details"""
    ip: str
    port: int
    protocol: str
    state: str
    service: Optional[ServiceInfo] = None
    scripts: List[ScriptResult] = None
    timestamp: Optional[str] = None
    reason: Optional[str] = None
    reason_ttl: Optional[int] = None


@dataclass
class DetailedScanResult:
    """Enhanced scan result with OS detection and service details"""
    ip: str
    hostname: Optional[str]
    ports: List[DetailedPortResult]
    os_matches: List[OSMatch]
    scan_time: float
    total_ports_scanned: int
    nmap_version: Optional[str] = None
    scan_type: Optional[str] = None


class NmapScanner:
    """Detailed service scanner using Nmap"""

    def __init__(self):
        self.config = config_manager.get_scanning_config()
        self.timing = self.config.nmap_timing
        self.scripts = self.config.nmap_scripts
        self.max_parallel = self.config.nmap_max_parallel
        self.timeout = self.config.nmap_timeout

        # Verify nmap is installed
        self._verify_nmap()

        logger.info(f"Nmap scanner initialized - timing: T{self.timing}, scripts: {self.scripts}")

    def _verify_nmap(self) -> None:
        """Verify that nmap is installed and accessible"""
        try:
            result = subprocess.run(['nmap', '--version'],
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                version_line = result.stdout.strip().split('\n')[0]
                logger.info(f"Nmap found: {version_line}")
            else:
                raise FileNotFoundError("Nmap not found or not working")
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError) as e:
            logger.error(f"Nmap verification failed: {e}")
            raise RuntimeError("Nmap is required but not available. Install with: sudo apt install nmap")

    async def scan_services(self, masscan_results: List[ScanResult]) -> List[DetailedScanResult]:
        """
        Perform detailed service enumeration on Masscan results

        Args:
            masscan_results: Results from Masscan port discovery

        Returns:
            List of detailed scan results with service information
        """
        if not masscan_results:
            logger.warning("No Masscan results provided for service enumeration")
            return []

        logger.info(f"Starting Nmap service enumeration on {len(masscan_results)} hosts")

        # Convert Masscan results to target specifications
        targets = self._prepare_targets(masscan_results)

        # Process targets in parallel batches
        all_results = []
        batch_size = min(self.max_parallel, len(targets))

        for i in range(0, len(targets), batch_size):
            batch = targets[i:i + batch_size]
            logger.info(f"Processing batch {i//batch_size + 1}/{(len(targets)-1)//batch_size + 1} ({len(batch)} targets)")

            batch_tasks = [self._scan_target(target) for target in batch]
            batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)

            # Filter out exceptions and None results
            valid_results = [r for r in batch_results if isinstance(r, DetailedScanResult)]
            all_results.extend(valid_results)

            # Log any exceptions
            for i, result in enumerate(batch_results):
                if isinstance(result, Exception):
                    logger.error(f"Batch target {i} failed: {result}")

        logger.info(f"Nmap service enumeration completed. Processed {len(all_results)} hosts")
        return all_results

    def _prepare_targets(self, masscan_results: List[ScanResult]) -> List[Dict]:
        """
        Convert Masscan results to Nmap target specifications

        Args:
            masscan_results: Results from Masscan

        Returns:
            List of target dictionaries with IP and ports
        """
        targets = []

        for result in masscan_results:
            if not result.ports:
                continue

            # Group ports by protocol
            tcp_ports = []
            udp_ports = []

            for port in result.ports:
                if port.protocol.lower() == 'tcp':
                    tcp_ports.append(port.port)
                elif port.protocol.lower() == 'udp':
                    udp_ports.append(port.port)

            target = {
                'ip': result.ip,
                'tcp_ports': tcp_ports,
                'udp_ports': udp_ports,
                'scan_time': result.scan_time
            }

            targets.append(target)

        logger.debug(f"Prepared {len(targets)} targets for Nmap scanning")
        return targets

    async def _scan_target(self, target: Dict) -> Optional[DetailedScanResult]:
        """
        Scan a single target with Nmap

        Args:
            target: Target specification dictionary

        Returns:
            Detailed scan result or None if scan failed
        """
        import time
        start_time = time.time()

        ip = target['ip']
        tcp_ports = target['tcp_ports']
        udp_ports = target['udp_ports']

        logger.debug(f"Scanning {ip} - TCP ports: {len(tcp_ports)}, UDP ports: {len(udp_ports)}")

        # Create temporary output file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as output_file:
            output_file_path = output_file.name

        try:
            # Build Nmap command
            cmd = ['nmap']

            # Add timing template
            cmd.extend(['-T', str(self.timing)])

            # Add service detection
            cmd.extend(['-sV'])  # Version detection

            # Add OS detection (requires root privileges)
            try:
                # Test if we can run OS detection
                test_result = subprocess.run(['id', '-u'], capture_output=True, text=True)
                if test_result.returncode == 0 and test_result.stdout.strip() == '0':
                    cmd.extend(['-O'])  # OS detection
                    logger.debug("Added OS detection (running as root)")
            except:
                pass  # Skip OS detection if we can't determine privileges

            # Add script scanning
            if self.scripts:
                script_args = ','.join(self.scripts)
                cmd.extend(['--script', script_args])

            # Add port specifications
            if tcp_ports:
                tcp_port_str = ','.join(map(str, tcp_ports))
                cmd.extend(['-p', f"T:{tcp_port_str}"])

            if udp_ports:
                udp_port_str = ','.join(map(str, udp_ports))
                if tcp_ports:
                    # Combine with TCP ports
                    cmd[-1] += f",U:{udp_port_str}"
                else:
                    cmd.extend(['-p', f"U:{udp_port_str}"])

            # Add output format
            cmd.extend(['-oX', output_file_path])

            # Add target IP
            cmd.append(ip)

            logger.debug(f"Executing: {' '.join(cmd)}")

            # Execute Nmap
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self.timeout
                )
            except asyncio.TimeoutError:
                logger.warning(f"Nmap scan of {ip} timed out after {self.timeout}s")
                process.kill()
                return None

            if process.returncode != 0:
                logger.warning(f"Nmap scan of {ip} failed with return code {process.returncode}")
                logger.debug(f"Stderr: {stderr.decode()}")
                return None

            # Parse results
            result = self._parse_nmap_xml(output_file_path, ip)

            if result:
                result.scan_time = time.time() - start_time
                logger.debug(f"Completed scan of {ip} in {result.scan_time:.2f}s")

            return result

        finally:
            # Clean up temporary file
            Path(output_file_path).unlink(missing_ok=True)

    def _parse_nmap_xml(self, xml_file_path: str, target_ip: str) -> Optional[DetailedScanResult]:
        """
        Parse Nmap XML output

        Args:
            xml_file_path: Path to Nmap XML output file
            target_ip: Target IP address

        Returns:
            Detailed scan result or None if parsing failed
        """
        try:
            if not Path(xml_file_path).exists() or Path(xml_file_path).stat().st_size == 0:
                logger.warning(f"Nmap XML output file for {target_ip} is empty or missing")
                return None

            tree = ET.parse(xml_file_path)
            root = tree.getroot()

            # Get Nmap version
            nmap_version = root.get('version', 'unknown')

            # Find the host element
            host_elem = root.find('host')
            if host_elem is None:
                logger.warning(f"No host element found in Nmap XML for {target_ip}")
                return None

            # Parse hostname
            hostname = None
            hostnames_elem = host_elem.find('hostnames')
            if hostnames_elem is not None:
                hostname_elem = hostnames_elem.find('hostname')
                if hostname_elem is not None:
                    hostname = hostname_elem.get('name')

            # Parse ports
            ports = []
            ports_elem = host_elem.find('ports')
            if ports_elem is not None:
                for port_elem in ports_elem.findall('port'):
                    port_result = self._parse_port_element(port_elem, target_ip)
                    if port_result:
                        ports.append(port_result)

            # Parse OS detection
            os_matches = []
            os_elem = host_elem.find('os')
            if os_elem is not None:
                for osmatch_elem in os_elem.findall('osmatch'):
                    os_match = self._parse_os_match(osmatch_elem)
                    if os_match:
                        os_matches.append(os_match)

            result = DetailedScanResult(
                ip=target_ip,
                hostname=hostname,
                ports=ports,
                os_matches=os_matches,
                scan_time=0.0,  # Will be set by caller
                total_ports_scanned=len(ports),
                nmap_version=nmap_version,
                scan_type="service_detection"
            )

            logger.debug(f"Parsed Nmap results for {target_ip}: {len(ports)} ports, {len(os_matches)} OS matches")
            return result

        except ET.ParseError as e:
            logger.error(f"Failed to parse Nmap XML for {target_ip}: {e}")
            return None
        except Exception as e:
            logger.error(f"Error parsing Nmap results for {target_ip}: {e}")
            return None

    def _parse_port_element(self, port_elem: ET.Element, ip: str) -> Optional[DetailedPortResult]:
        """Parse a port element from Nmap XML"""
        try:
            port_num = int(port_elem.get('portid'))
            protocol = port_elem.get('protocol', 'tcp')

            # Parse state
            state_elem = port_elem.find('state')
            if state_elem is None:
                return None

            state = state_elem.get('state', 'unknown')
            reason = state_elem.get('reason')
            reason_ttl = state_elem.get('reason_ttl')
            if reason_ttl:
                reason_ttl = int(reason_ttl)

            # Parse service information
            service = None
            service_elem = port_elem.find('service')
            if service_elem is not None:
                service = ServiceInfo(
                    name=service_elem.get('name', 'unknown'),
                    product=service_elem.get('product'),
                    version=service_elem.get('version'),
                    extrainfo=service_elem.get('extrainfo'),
                    method=service_elem.get('method'),
                    conf=int(service_elem.get('conf', 0)) if service_elem.get('conf') else None
                )

            # Parse script results
            scripts = []
            for script_elem in port_elem.findall('script'):
                script_result = self._parse_script_element(script_elem)
                if script_result:
                    scripts.append(script_result)

            return DetailedPortResult(
                ip=ip,
                port=port_num,
                protocol=protocol,
                state=state,
                service=service,
                scripts=scripts if scripts else None,
                reason=reason,
                reason_ttl=reason_ttl
            )

        except (ValueError, TypeError) as e:
            logger.warning(f"Failed to parse port element: {e}")
            return None

    def _parse_script_element(self, script_elem: ET.Element) -> Optional[ScriptResult]:
        """Parse a script element from Nmap XML"""
        try:
            script_id = script_elem.get('id')
            script_output = script_elem.get('output', '')

            # Parse script elements (structured data)
            elements = {}
            for elem in script_elem.findall('.//elem'):
                key = elem.get('key')
                if key:
                    elements[key] = elem.text or elem.get('value', '')

            return ScriptResult(
                id=script_id,
                output=script_output,
                elements=elements if elements else None
            )

        except Exception as e:
            logger.warning(f"Failed to parse script element: {e}")
            return None

    def _parse_os_match(self, osmatch_elem: ET.Element) -> Optional[OSMatch]:
        """Parse an OS match element from Nmap XML"""
        try:
            name = osmatch_elem.get('name', 'Unknown')
            accuracy = int(osmatch_elem.get('accuracy', 0))
            line = int(osmatch_elem.get('line', 0))

            # Parse OS class information
            osclass = None
            osclass_elem = osmatch_elem.find('osclass')
            if osclass_elem is not None:
                osclass = {
                    'type': osclass_elem.get('type'),
                    'vendor': osclass_elem.get('vendor'),
                    'osfamily': osclass_elem.get('osfamily'),
                    'osgen': osclass_elem.get('osgen'),
                    'accuracy': int(osclass_elem.get('accuracy', 0))
                }

            return OSMatch(
                name=name,
                accuracy=accuracy,
                line=line,
                osclass=osclass
            )

        except (ValueError, TypeError) as e:
            logger.warning(f"Failed to parse OS match element: {e}")
            return None

    async def scan_single_host(self, ip: str, ports: List[int],
                              protocols: List[str] = None) -> Optional[DetailedScanResult]:
        """
        Perform detailed scan on a single host

        Args:
            ip: Target IP address
            ports: List of ports to scan
            protocols: List of protocols ('tcp', 'udp')

        Returns:
            Detailed scan result or None
        """
        protocols = protocols or ['tcp']

        # Create mock Masscan result
        port_results = []
        for port in ports:
            for protocol in protocols:
                port_results.append(PortResult(ip, port, protocol, 'open'))

        masscan_result = ScanResult(ip, port_results, 0.0, len(ports))

        results = await self.scan_services([masscan_result])
        return results[0] if results else None

    async def vulnerability_scan(self, targets: List[Dict],
                                vuln_scripts: List[str] = None) -> List[DetailedScanResult]:
        """
        Perform vulnerability scanning with specific scripts

        Args:
            targets: List of target specifications
            vuln_scripts: List of vulnerability scripts to run

        Returns:
            List of detailed scan results
        """
        if not vuln_scripts:
            vuln_scripts = [
                'vuln',
                'exploit',
                'dos',
                'malware',
                'safe'
            ]

        # Temporarily override scripts
        original_scripts = self.scripts
        self.scripts = vuln_scripts

        try:
            # Convert targets to Masscan-like results
            masscan_results = []
            for target in targets:
                port_results = []
                for port in target.get('tcp_ports', []):
                    port_results.append(PortResult(target['ip'], port, 'tcp', 'open'))
                for port in target.get('udp_ports', []):
                    port_results.append(PortResult(target['ip'], port, 'udp', 'open'))

                if port_results:
                    masscan_results.append(ScanResult(target['ip'], port_results, 0.0, len(port_results)))

            results = await self.scan_services(masscan_results)

            # Filter results to only include hosts with vulnerability findings
            vuln_results = []
            for result in results:
                has_vulns = False
                for port in result.ports:
                    if port.scripts:
                        for script in port.scripts:
                            if any(keyword in script.output.lower()
                                  for keyword in ['vulnerable', 'exploit', 'cve-', 'security']):
                                has_vulns = True
                                break
                    if has_vulns:
                        break

                if has_vulns:
                    vuln_results.append(result)

            logger.info(f"Vulnerability scan found issues on {len(vuln_results)} hosts")
            return vuln_results

        finally:
            # Restore original scripts
            self.scripts = original_scripts

    async def os_detection_scan(self, ip_list: List[str]) -> List[DetailedScanResult]:
        """
        Perform OS detection scan on list of IPs

        Args:
            ip_list: List of IP addresses

        Returns:
            List of scan results with OS information
        """
        logger.info(f"Starting OS detection scan on {len(ip_list)} hosts")

        results = []
        for ip in ip_list:
            result = await self._os_detection_single(ip)
            if result:
                results.append(result)

        return results

    async def _os_detection_single(self, ip: str) -> Optional[DetailedScanResult]:
        """Perform OS detection on a single host"""
        import time
        start_time = time.time()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as output_file:
            output_file_path = output_file.name

        try:
            # Build OS detection command
            cmd = [
                'nmap',
                '-O',  # OS detection
                '-T', str(self.timing),
                '--osscan-guess',  # Guess OS more aggressively
                '-oX', output_file_path,
                ip
            ]

            logger.debug(f"OS detection: {' '.join(cmd)}")

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self.timeout
                )
            except asyncio.TimeoutError:
                logger.warning(f"OS detection of {ip} timed out")
                process.kill()
                return None

            if process.returncode != 0:
                logger.debug(f"OS detection of {ip} failed: {stderr.decode()}")
                return None

            result = self._parse_nmap_xml(output_file_path, ip)
            if result:
                result.scan_time = time.time() - start_time
                result.scan_type = "os_detection"

            return result

        finally:
            Path(output_file_path).unlink(missing_ok=True)

    def get_service_statistics(self, results: List[DetailedScanResult]) -> Dict:
        """
        Get statistics about discovered services

        Args:
            results: List of detailed scan results

        Returns:
            Dictionary with service statistics
        """
        stats = {
            'total_hosts': len(results),
            'hosts_with_services': 0,
            'total_services': 0,
            'unique_services': set(),
            'service_versions': {},
            'os_families': {},
            'vulnerability_count': 0,
            'script_results': 0
        }

        for result in results:
            has_services = False

            for port in result.ports:
                if port.service and port.service.name != 'unknown':
                    has_services = True
                    stats['total_services'] += 1
                    stats['unique_services'].add(port.service.name)

                    # Track service versions
                    if port.service.product:
                        service_key = f"{port.service.name} ({port.service.product})"
                        if port.service.version:
                            service_key += f" {port.service.version}"
                        stats['service_versions'][service_key] = stats['service_versions'].get(service_key, 0) + 1

                # Count script results
                if port.scripts:
                    stats['script_results'] += len(port.scripts)

                    # Count potential vulnerabilities
                    for script in port.scripts:
                        if any(keyword in script.output.lower()
                              for keyword in ['vulnerable', 'cve-', 'exploit']):
                            stats['vulnerability_count'] += 1

            if has_services:
                stats['hosts_with_services'] += 1

            # Track OS families
            for os_match in result.os_matches:
                if os_match.osclass and os_match.osclass.get('osfamily'):
                    family = os_match.osclass['osfamily']
                    stats['os_families'][family] = stats['os_families'].get(family, 0) + 1

        # Convert set to count
        stats['unique_services'] = len(stats['unique_services'])

        # Sort service versions by frequency
        stats['service_versions'] = dict(sorted(stats['service_versions'].items(),
                                               key=lambda x: x[1], reverse=True)[:20])

        return stats

    def filter_by_service(self, results: List[DetailedScanResult],
                         service_names: List[str]) -> List[DetailedScanResult]:
        """
        Filter results by specific service names

        Args:
            results: List of scan results
            service_names: List of service names to filter by

        Returns:
            Filtered scan results
        """
        filtered_results = []

        for result in results:
            filtered_ports = []

            for port in result.ports:
                if (port.service and
                    port.service.name and
                    port.service.name.lower() in [s.lower() for s in service_names]):
                    filtered_ports.append(port)

            if filtered_ports:
                filtered_result = DetailedScanResult(
                    ip=result.ip,
                    hostname=result.hostname,
                    ports=filtered_ports,
                    os_matches=result.os_matches,
                    scan_time=result.scan_time,
                    total_ports_scanned=len(filtered_ports),
                    nmap_version=result.nmap_version,
                    scan_type=result.scan_type
                )
                filtered_results.append(filtered_result)

        logger.info(f"Filtered {len(results)} results to {len(filtered_results)} with services: {service_names}")
        return filtered_results

    def filter_by_vulnerability(self, results: List[DetailedScanResult]) -> List[DetailedScanResult]:
        """
        Filter results to only include hosts with potential vulnerabilities

        Args:
            results: List of scan results

        Returns:
            Results with potential vulnerabilities
        """
        vuln_results = []
        vuln_keywords = ['vulnerable', 'cve-', 'exploit', 'security', 'weakness', 'flaw']

        for result in results:
            has_vulns = False
            vuln_ports = []

            for port in result.ports:
                port_has_vulns = False

                if port.scripts:
                    for script in port.scripts:
                        if any(keyword in script.output.lower() for keyword in vuln_keywords):
                            port_has_vulns = True
                            has_vulns = True
                            break

                if port_has_vulns:
                    vuln_ports.append(port)

            if has_vulns:
                filtered_result = DetailedScanResult(
                    ip=result.ip,
                    hostname=result.hostname,
                    ports=vuln_ports,
                    os_matches=result.os_matches,
                    scan_time=result.scan_time,
                    total_ports_scanned=len(vuln_ports),
                    nmap_version=result.nmap_version,
                    scan_type=result.scan_type
                )
                vuln_results.append(filtered_result)

        logger.info(f"Found {len(vuln_results)} hosts with potential vulnerabilities")
        return vuln_results

    def export_results(self, results: List[DetailedScanResult],
                      output_file: str, format: str = 'json') -> None:
        """
        Export detailed scan results to file

        Args:
            results: List of detailed scan results
            output_file: Output file path
            format: Export format ('json', 'csv', 'xml', 'html')
        """
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if format.lower() == 'json':
            self._export_json(results, output_path)
        elif format.lower() == 'csv':
            self._export_csv(results, output_path)
        elif format.lower() == 'xml':
            self._export_xml(results, output_path)
        elif format.lower() == 'html':
            self._export_html(results, output_path)
        else:
            raise ValueError(f"Unsupported export format: {format}")

        logger.info(f"Nmap results exported to {output_path} in {format.upper()} format")

    def _export_json(self, results: List[DetailedScanResult], output_path: Path) -> None:
        """Export results as JSON"""
        # Convert dataclasses to dictionaries
        data = []
        for result in results:
            result_dict = asdict(result)
            data.append(result_dict)

        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2, default=str)

    def _export_csv(self, results: List[DetailedScanResult], output_path: Path) -> None:
        """Export results as CSV"""
        import csv

        with open(output_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'IP', 'Hostname', 'Port', 'Protocol', 'State', 'Service',
                'Product', 'Version', 'OS_Match', 'Scripts', 'Scan_Time'
            ])

            for result in results:
                for port in result.ports:
                    service_name = port.service.name if port.service else ''
                    product = port.service.product if port.service else ''
                    version = port.service.version if port.service else ''

                    os_match = result.os_matches[0].name if result.os_matches else ''

                    scripts = '; '.join([s.id for s in port.scripts]) if port.scripts else ''

                    writer.writerow([
                        result.ip, result.hostname or '', port.port, port.protocol,
                        port.state, service_name, product, version, os_match,
                        scripts, result.scan_time
                    ])

    def _export_xml(self, results: List[DetailedScanResult], output_path: Path) -> None:
        """Export results as XML"""
        root = ET.Element('nmap_results')

        for result in results:
            host_elem = ET.SubElement(root, 'host')
            host_elem.set('ip', result.ip)
            if result.hostname:
                host_elem.set('hostname', result.hostname)
            host_elem.set('scan_time', str(result.scan_time))

            # Add OS matches
            if result.os_matches:
                os_elem = ET.SubElement(host_elem, 'os_detection')
                for os_match in result.os_matches:
                    match_elem = ET.SubElement(os_elem, 'os_match')
                    match_elem.set('name', os_match.name)
                    match_elem.set('accuracy', str(os_match.accuracy))

            # Add ports
            ports_elem = ET.SubElement(host_elem, 'ports')
            for port in result.ports:
                port_elem = ET.SubElement(ports_elem, 'port')
                port_elem.set('number', str(port.port))
                port_elem.set('protocol', port.protocol)
                port_elem.set('state', port.state)

                if port.service:
                    service_elem = ET.SubElement(port_elem, 'service')
                    service_elem.set('name', port.service.name)
                    if port.service.product:
                        service_elem.set('product', port.service.product)
                    if port.service.version:
                        service_elem.set('version', port.service.version)

                if port.scripts:
                    scripts_elem = ET.SubElement(port_elem, 'scripts')
                    for script in port.scripts:
                        script_elem = ET.SubElement(scripts_elem, 'script')
                        script_elem.set('id', script.id)
                        script_elem.text = script.output

        tree = ET.ElementTree(root)
        tree.write(output_path, encoding='utf-8', xml_declaration=True)

    def _export_html(self, results: List[DetailedScanResult], output_path: Path) -> None:
        """Export results as HTML report"""
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Nmap Service Enumeration Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .host {{ border: 1px solid #ccc; margin: 10px 0; padding: 15px; }}
                .host-header {{ background: #f0f0f0; padding: 10px; margin: -15px -15px 10px -15px; }}
                .port {{ margin: 5px 0; padding: 5px; background: #f9f9f9; }}
                .service {{ color: #0066cc; font-weight: bold; }}
                .os {{ color: #cc6600; font-style: italic; }}
                .script {{ margin: 5px 0; padding: 5px; background: #fff3cd; font-size: 0.9em; }}
                .vuln {{ background: #f8d7da; color: #721c24; }}
            </style>
        </head>
        <body>
            <h1>Nmap Service Enumeration Report</h1>
            <p>Generated on: {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>Total hosts scanned: {len(results)}</p>
        """

        for result in results:
            html_content += f"""
            <div class="host">
                <div class="host-header">
                    <h3>{result.ip}</h3>
                    {f'<p>Hostname: {result.hostname}</p>' if result.hostname else ''}
                    {f'<p class="os">OS: {result.os_matches[0].name} ({result.os_matches[0].accuracy}% confidence)</p>' if result.os_matches else ''}
                    <p>Scan time: {result.scan_time:.2f}s</p>
                </div>
            """

            for port in result.ports:
                service_info = ""
                if port.service:
                    service_info = f'<span class="service">{port.service.name}</span>'
                    if port.service.product:
                        service_info += f' ({port.service.product}'
                        if port.service.version:
                            service_info += f' {port.service.version}'
                        service_info += ')'

                html_content += f"""
                <div class="port">
                    <strong>{port.port}/{port.protocol}</strong> - {port.state} {service_info}
                """

                if port.scripts:
                    for script in port.scripts:
                        script_class = "script vuln" if any(kw in script.output.lower()
                                                          for kw in ['vulnerable', 'cve-']) else "script"
                        html_content += f'<div class="{script_class}"><strong>{script.id}:</strong> {script.output[:200]}...</div>'

                html_content += "</div>"

            html_content += "</div>"

        html_content += """
        </body>
        </html>
        """

        with open(output_path, 'w') as f:
            f.write(html_content)