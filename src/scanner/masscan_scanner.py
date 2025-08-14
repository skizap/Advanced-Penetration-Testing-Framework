"""
Masscan Integration Module
High-speed port scanning using Masscan
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


@dataclass
class PortResult:
    """Represents a discovered open port"""
    ip: str
    port: int
    protocol: str
    state: str
    timestamp: Optional[str] = None
    banner: Optional[str] = None


@dataclass
class ScanResult:
    """Represents scan results for a host"""
    ip: str
    ports: List[PortResult]
    scan_time: float
    total_ports_scanned: int


class MasscanScanner:
    """High-speed port scanner using Masscan"""

    def __init__(self):
        self.config = config_manager.get_scanning_config()
        self.rate = self.config.masscan_rate
        self.timeout = self.config.masscan_timeout
        self.retries = self.config.masscan_retries
        self.ports = self.config.masscan_ports

        # Verify masscan is installed
        self._verify_masscan()

        logger.info(f"Masscan scanner initialized - rate: {self.rate} pps, timeout: {self.timeout}s")

    def _verify_masscan(self) -> None:
        """Verify that masscan is installed and accessible"""
        try:
            result = subprocess.run(['masscan', '--version'],
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                version = result.stdout.strip().split('\n')[0]
                logger.info(f"Masscan found: {version}")
            else:
                raise FileNotFoundError("Masscan not found or not working")
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError) as e:
            logger.error(f"Masscan verification failed: {e}")
            raise RuntimeError("Masscan is required but not available. Install with: sudo apt install masscan")

    async def scan_ips(self, ip_list: List[str],
                      ports: Optional[str] = None,
                      rate: Optional[int] = None) -> List[ScanResult]:
        """
        Scan list of IPs for open ports

        Args:
            ip_list: List of IP addresses to scan
            ports: Port specification (default from config)
            rate: Scan rate in packets per second (default from config)

        Returns:
            List of scan results
        """
        if not ip_list:
            logger.warning("No IPs provided for scanning")
            return []

        ports = ports or self.ports
        rate = rate or self.rate

        logger.info(f"Starting Masscan on {len(ip_list)} IPs, ports: {ports}, rate: {rate} pps")

        # Split large IP lists into chunks for better performance
        chunk_size = min(1000, len(ip_list))  # Process up to 1000 IPs at once
        all_results = []

        for i in range(0, len(ip_list), chunk_size):
            chunk = ip_list[i:i + chunk_size]
            logger.info(f"Scanning chunk {i//chunk_size + 1}/{(len(ip_list)-1)//chunk_size + 1} ({len(chunk)} IPs)")

            chunk_results = await self._scan_chunk(chunk, ports, rate)
            all_results.extend(chunk_results)

        logger.info(f"Masscan completed. Found {sum(len(r.ports) for r in all_results)} open ports")
        return all_results

    async def _scan_chunk(self, ip_list: List[str], ports: str, rate: int) -> List[ScanResult]:
        """Scan a chunk of IPs"""
        import time
        start_time = time.time()

        # Create temporary files for input and output
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as ip_file:
            ip_file.write('\n'.join(ip_list))
            ip_file_path = ip_file.name

        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as output_file:
            output_file_path = output_file.name

        try:
            # Build masscan command
            cmd = [
                'masscan',
                '-iL', ip_file_path,  # Input file with IPs
                '-p', ports,          # Port specification
                '--rate', str(rate),  # Scan rate
                '--wait', str(self.timeout),  # Wait time
                '-oX', output_file_path,      # XML output
                '--open-only',        # Only report open ports
            ]

            # Add additional options for stealth and performance
            cmd.extend([
                '--randomize-hosts',  # Randomize host order
                '--seed', str(hash(' '.join(ip_list)) % 2**32),  # Deterministic randomization
            ])

            logger.debug(f"Executing: {' '.join(cmd)}")

            # Execute masscan
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                logger.error(f"Masscan failed with return code {process.returncode}")
                logger.error(f"Stderr: {stderr.decode()}")
                return []

            # Parse results
            results = self._parse_masscan_xml(output_file_path)

            scan_time = time.time() - start_time
            logger.info(f"Chunk scan completed in {scan_time:.2f}s")

            return results

        finally:
            # Clean up temporary files
            Path(ip_file_path).unlink(missing_ok=True)
            Path(output_file_path).unlink(missing_ok=True)

    def _parse_masscan_xml(self, xml_file_path: str) -> List[ScanResult]:
        """Parse Masscan XML output"""
        results = {}  # ip -> ScanResult

        try:
            if not Path(xml_file_path).exists() or Path(xml_file_path).stat().st_size == 0:
                logger.warning("Masscan XML output file is empty or missing")
                return []

            tree = ET.parse(xml_file_path)
            root = tree.getroot()

            for host in root.findall('host'):
                ip = host.find('address').get('addr')

                if ip not in results:
                    results[ip] = ScanResult(
                        ip=ip,
                        ports=[],
                        scan_time=0.0,
                        total_ports_scanned=0
                    )

                # Parse ports
                ports_elem = host.find('ports')
                if ports_elem is not None:
                    for port in ports_elem.findall('port'):
                        port_num = int(port.get('portid'))
                        protocol = port.get('protocol', 'tcp')

                        state_elem = port.find('state')
                        state = state_elem.get('state') if state_elem is not None else 'open'

                        port_result = PortResult(
                            ip=ip,
                            port=port_num,
                            protocol=protocol,
                            state=state,
                            timestamp=None,  # Masscan doesn't provide timestamps in XML
                            banner=None      # Masscan doesn't do banner grabbing
                        )

                        results[ip].ports.append(port_result)

            logger.info(f"Parsed {len(results)} hosts with open ports from Masscan XML")
            return list(results.values())

        except ET.ParseError as e:
            logger.error(f"Failed to parse Masscan XML: {e}")
            return []
        except Exception as e:
            logger.error(f"Error parsing Masscan results: {e}")
            return []

    async def scan_single_host(self, ip: str, ports: Optional[str] = None) -> Optional[ScanResult]:
        """
        Scan a single host

        Args:
            ip: IP address to scan
            ports: Port specification

        Returns:
            Scan result or None if no ports found
        """
        results = await self.scan_ips([ip], ports)
        return results[0] if results else None

    async def scan_top_ports(self, ip_list: List[str], top_ports: int = 1000) -> List[ScanResult]:
        """
        Scan top N most common ports

        Args:
            ip_list: List of IP addresses
            top_ports: Number of top ports to scan

        Returns:
            List of scan results
        """
        # Common ports mapping
        common_ports = {
            100: "21,22,23,25,53,80,110,111,135,139,143,443,993,995",
            1000: "1-1000",
            5000: "1-5000",
            10000: "1-10000"
        }

        if top_ports in common_ports:
            ports = common_ports[top_ports]
        else:
            ports = f"1-{top_ports}"

        logger.info(f"Scanning top {top_ports} ports on {len(ip_list)} hosts")
        return await self.scan_ips(ip_list, ports)

    async def scan_specific_ports(self, ip_list: List[str], port_list: List[int]) -> List[ScanResult]:
        """
        Scan specific ports

        Args:
            ip_list: List of IP addresses
            port_list: List of specific ports to scan

        Returns:
            List of scan results
        """
        ports = ','.join(map(str, port_list))
        logger.info(f"Scanning specific ports {ports} on {len(ip_list)} hosts")
        return await self.scan_ips(ip_list, ports)

    def get_scan_statistics(self, results: List[ScanResult]) -> Dict:
        """
        Get statistics from scan results

        Args:
            results: List of scan results

        Returns:
            Dictionary with statistics
        """
        stats = {
            'total_hosts_scanned': len(results),
            'hosts_with_open_ports': len([r for r in results if r.ports]),
            'total_open_ports': sum(len(r.ports) for r in results),
            'unique_ports': len(set(p.port for r in results for p in r.ports)),
            'protocols': {},
            'top_ports': {},
            'average_scan_time': sum(r.scan_time for r in results) / len(results) if results else 0
        }

        # Protocol statistics
        for result in results:
            for port in result.ports:
                protocol = port.protocol
                stats['protocols'][protocol] = stats['protocols'].get(protocol, 0) + 1

                # Top ports
                port_key = f"{port.port}/{protocol}"
                stats['top_ports'][port_key] = stats['top_ports'].get(port_key, 0) + 1

        # Sort top ports
        stats['top_ports'] = dict(sorted(stats['top_ports'].items(),
                                       key=lambda x: x[1], reverse=True)[:20])

        return stats

    async def scan_with_stealth(self, ip_list: List[str],
                               ports: Optional[str] = None,
                               stealth_level: int = 1) -> List[ScanResult]:
        """
        Perform stealth scanning with various evasion techniques

        Args:
            ip_list: List of IP addresses
            ports: Port specification
            stealth_level: Stealth level (1-3, higher = more stealthy)

        Returns:
            List of scan results
        """
        ports = ports or self.ports

        # Adjust scan parameters based on stealth level
        if stealth_level == 1:
            # Light stealth - reduce rate slightly
            rate = max(100, self.rate // 2)
            timeout = self.timeout * 2
        elif stealth_level == 2:
            # Medium stealth - significant rate reduction
            rate = max(50, self.rate // 10)
            timeout = self.timeout * 4
        else:  # stealth_level >= 3
            # High stealth - very slow scan
            rate = max(10, self.rate // 100)
            timeout = self.timeout * 8

        logger.info(f"Stealth scan level {stealth_level}: rate={rate} pps, timeout={timeout}s")

        # Split into smaller chunks for stealth
        chunk_size = max(10, 100 // stealth_level)
        all_results = []

        for i in range(0, len(ip_list), chunk_size):
            chunk = ip_list[i:i + chunk_size]

            # Add delay between chunks for stealth
            if i > 0:
                delay = stealth_level * 5  # 5-15 second delays
                logger.debug(f"Stealth delay: {delay}s")
                await asyncio.sleep(delay)

            chunk_results = await self._scan_chunk_stealth(chunk, ports, rate, timeout)
            all_results.extend(chunk_results)

        return all_results

    async def _scan_chunk_stealth(self, ip_list: List[str], ports: str,
                                 rate: int, timeout: int) -> List[ScanResult]:
        """Scan chunk with stealth options"""
        import time
        start_time = time.time()

        # Create temporary files
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as ip_file:
            ip_file.write('\n'.join(ip_list))
            ip_file_path = ip_file.name

        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as output_file:
            output_file_path = output_file.name

        try:
            # Build stealth masscan command
            cmd = [
                'masscan',
                '-iL', ip_file_path,
                '-p', ports,
                '--rate', str(rate),
                '--wait', str(timeout),
                '-oX', output_file_path,
                '--open-only',
                '--randomize-hosts',
                '--seed', str(hash(' '.join(ip_list)) % 2**32),
                # Stealth options
                '--source-port', '53',  # Use DNS source port
                '--ttl', '64',          # Set TTL
            ]

            logger.debug(f"Stealth scan: {' '.join(cmd)}")

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                logger.error(f"Stealth scan failed: {stderr.decode()}")
                return []

            results = self._parse_masscan_xml(output_file_path)
            scan_time = time.time() - start_time

            for result in results:
                result.scan_time = scan_time

            return results

        finally:
            Path(ip_file_path).unlink(missing_ok=True)
            Path(output_file_path).unlink(missing_ok=True)

    async def scan_with_retry(self, ip_list: List[str],
                             ports: Optional[str] = None,
                             max_retries: Optional[int] = None) -> List[ScanResult]:
        """
        Scan with automatic retry on failure

        Args:
            ip_list: List of IP addresses
            ports: Port specification
            max_retries: Maximum retry attempts

        Returns:
            List of scan results
        """
        max_retries = max_retries or self.retries
        ports = ports or self.ports

        for attempt in range(max_retries + 1):
            try:
                logger.info(f"Scan attempt {attempt + 1}/{max_retries + 1}")
                results = await self.scan_ips(ip_list, ports)

                if results or attempt == max_retries:
                    return results

            except Exception as e:
                logger.warning(f"Scan attempt {attempt + 1} failed: {e}")
                if attempt < max_retries:
                    delay = 2 ** attempt  # Exponential backoff
                    logger.info(f"Retrying in {delay} seconds...")
                    await asyncio.sleep(delay)
                else:
                    logger.error("All scan attempts failed")
                    raise

        return []

    def filter_results(self, results: List[ScanResult],
                      port_filter: Optional[List[int]] = None,
                      protocol_filter: Optional[List[str]] = None,
                      min_ports: int = 1) -> List[ScanResult]:
        """
        Filter scan results based on criteria

        Args:
            results: List of scan results
            port_filter: Only include specific ports
            protocol_filter: Only include specific protocols
            min_ports: Minimum number of open ports per host

        Returns:
            Filtered scan results
        """
        filtered_results = []

        for result in results:
            filtered_ports = result.ports

            # Filter by port
            if port_filter:
                filtered_ports = [p for p in filtered_ports if p.port in port_filter]

            # Filter by protocol
            if protocol_filter:
                filtered_ports = [p for p in filtered_ports if p.protocol in protocol_filter]

            # Check minimum ports requirement
            if len(filtered_ports) >= min_ports:
                filtered_result = ScanResult(
                    ip=result.ip,
                    ports=filtered_ports,
                    scan_time=result.scan_time,
                    total_ports_scanned=result.total_ports_scanned
                )
                filtered_results.append(filtered_result)

        logger.info(f"Filtered {len(results)} results to {len(filtered_results)} results")
        return filtered_results

    def export_results(self, results: List[ScanResult],
                      output_file: str, format: str = 'json') -> None:
        """
        Export scan results to file

        Args:
            results: List of scan results
            output_file: Output file path
            format: Export format ('json', 'csv', 'xml')
        """
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if format.lower() == 'json':
            self._export_json(results, output_path)
        elif format.lower() == 'csv':
            self._export_csv(results, output_path)
        elif format.lower() == 'xml':
            self._export_xml(results, output_path)
        else:
            raise ValueError(f"Unsupported export format: {format}")

        logger.info(f"Results exported to {output_path} in {format.upper()} format")

    def _export_json(self, results: List[ScanResult], output_path: Path) -> None:
        """Export results as JSON"""
        data = [asdict(result) for result in results]
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)

    def _export_csv(self, results: List[ScanResult], output_path: Path) -> None:
        """Export results as CSV"""
        import csv

        with open(output_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['IP', 'Port', 'Protocol', 'State', 'Scan_Time'])

            for result in results:
                for port in result.ports:
                    writer.writerow([
                        result.ip, port.port, port.protocol,
                        port.state, result.scan_time
                    ])

    def _export_xml(self, results: List[ScanResult], output_path: Path) -> None:
        """Export results as XML"""
        root = ET.Element('masscan_results')

        for result in results:
            host_elem = ET.SubElement(root, 'host')
            host_elem.set('ip', result.ip)
            host_elem.set('scan_time', str(result.scan_time))

            ports_elem = ET.SubElement(host_elem, 'ports')
            for port in result.ports:
                port_elem = ET.SubElement(ports_elem, 'port')
                port_elem.set('number', str(port.port))
                port_elem.set('protocol', port.protocol)
                port_elem.set('state', port.state)

        tree = ET.ElementTree(root)
        tree.write(output_path, encoding='utf-8', xml_declaration=True)