#!/usr/bin/env python3
"""
Advanced Penetration Testing Framework
Main entry point for the framework
"""

import sys
import asyncio
import argparse
from pathlib import Path
from typing import List, Optional

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

from core.config import config_manager
from utils.logger import setup_logging
from utils.banner import print_banner
from loguru import logger


class PenTestFramework:
    """Main framework class"""

    def __init__(self):
        self.config = config_manager
        setup_logging()

    async def run_scan(self, targets: List[str], scan_type: str = "full") -> None:
        """Run scanning phase"""
        logger.info(f"Starting {scan_type} scan on targets: {targets}")

        # Import scanner modules
        from scanner.cidr_parser import CIDRParser
        from scanner.masscan_scanner import MasscanScanner
        from scanner.nmap_scanner import NmapScanner

        # Initialize components
        cidr_parser = CIDRParser()
        masscan = MasscanScanner()
        nmap = NmapScanner()

        # Parse targets and generate IP list
        all_ips = []
        for target in targets:
            if '/' in target:  # CIDR notation
                ips = cidr_parser.parse_cidr(target)
                all_ips.extend(ips)
            else:  # Single IP
                all_ips.append(target)

        logger.info(f"Total IPs to scan: {len(all_ips)}")

        # Phase 1: Fast port discovery with Masscan
        if scan_type in ["full", "fast"]:
            logger.info("Phase 1: Fast port discovery with Masscan")
            masscan_results = await masscan.scan_ips(all_ips)

            # Phase 2: Detailed service enumeration with Nmap
            logger.info("Phase 2: Detailed service enumeration with Nmap")
            nmap_results = await nmap.scan_services(masscan_results)

            return nmap_results

    async def run_intelligence(self, scan_results) -> None:
        """Run vulnerability intelligence gathering"""
        logger.info("Starting vulnerability intelligence gathering")

        from intelligence.nvd_client import NVDClient
        from intelligence.vulnerability_matcher import VulnerabilityMatcher

        nvd_client = NVDClient()
        vuln_matcher = VulnerabilityMatcher()

        # Match services to vulnerabilities
        vulnerabilities = await vuln_matcher.match_vulnerabilities(scan_results)

        return vulnerabilities

    async def run_exploitation(self, vulnerabilities) -> None:
        """Run exploitation phase"""
        logger.info("Starting exploitation phase")

        from exploits.exploit_engine import ExploitEngine

        exploit_engine = ExploitEngine()
        results = await exploit_engine.run_exploits(vulnerabilities)

        return results

    async def run_persistence(self, compromised_hosts) -> None:
        """Run persistence establishment"""
        logger.info("Starting persistence establishment")

        from persistence.persistence_manager import PersistenceManager

        persistence_manager = PersistenceManager()
        await persistence_manager.establish_persistence(compromised_hosts)

    async def run_full_chain(self, targets: List[str]) -> None:
        """Run the complete exploitation chain"""
        logger.info("Starting full exploitation chain")

        try:
            # Phase 1: Scanning
            scan_results = await self.run_scan(targets, "full")

            # Phase 2: Intelligence
            vulnerabilities = await self.run_intelligence(scan_results)

            # Phase 3: Exploitation
            compromised_hosts = await self.run_exploitation(vulnerabilities)

            # Phase 4: Persistence
            if compromised_hosts:
                await self.run_persistence(compromised_hosts)

            logger.info("Full exploitation chain completed")

        except Exception as e:
            logger.error(f"Error in exploitation chain: {e}")
            raise


def create_parser() -> argparse.ArgumentParser:
    """Create command line argument parser"""
    parser = argparse.ArgumentParser(
        description="Advanced Penetration Testing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        "targets",
        nargs="+",
        help="Target IPs or CIDR blocks to scan"
    )

    parser.add_argument(
        "--mode",
        choices=["scan", "intelligence", "exploit", "persistence", "full"],
        default="full",
        help="Operation mode (default: full)"
    )

    parser.add_argument(
        "--scan-type",
        choices=["fast", "full", "stealth"],
        default="full",
        help="Scan type (default: full)"
    )

    parser.add_argument(
        "--config",
        default="config/config.yaml",
        help="Configuration file path"
    )

    parser.add_argument(
        "--output",
        help="Output file for results"
    )

    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )

    return parser


async def main():
    """Main entry point"""
    parser = create_parser()
    args = parser.parse_args()

    # Print banner
    print_banner()

    # Initialize framework
    framework = PenTestFramework()

    # Set verbose logging if requested
    if args.verbose:
        logger.remove()
        logger.add(sys.stderr, level="DEBUG")

    try:
        if args.mode == "full":
            await framework.run_full_chain(args.targets)
        elif args.mode == "scan":
            results = await framework.run_scan(args.targets, args.scan_type)
            logger.info(f"Scan completed. Found {len(results)} services")
        elif args.mode == "intelligence":
            # Load previous scan results and run intelligence
            logger.info("Intelligence mode - implement result loading")
        elif args.mode == "exploit":
            # Load vulnerabilities and run exploitation
            logger.info("Exploit mode - implement vulnerability loading")
        elif args.mode == "persistence":
            # Load compromised hosts and establish persistence
            logger.info("Persistence mode - implement host loading")

    except KeyboardInterrupt:
        logger.info("Operation cancelled by user")
    except Exception as e:
        logger.error(f"Framework error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())