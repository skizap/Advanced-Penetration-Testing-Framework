#!/usr/bin/env python3
"""
Database System Demo Script
Demonstrates the functionality of the scan results database
"""

import sys
import asyncio
import tempfile
from pathlib import Path
from datetime import datetime

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

from core.database.manager import DatabaseManager
from core.database.queries import QueryBuilder
from core.database.importers import ScanResultImporter
from core.database.utils import DatabaseUtils
from scanner.masscan_scanner import ScanResult, PortResult
from scanner.nmap_scanner import (
    DetailedScanResult, DetailedPortResult, ServiceInfo,
    ScriptResult, OSMatch
)
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.tree import Tree

console = Console()


def demo_database_setup():
    """Demonstrate database setup and initialization"""
    console.print("\n[bold cyan]🗄️ Database Setup Demo[/bold cyan]")

    try:
        # Initialize database manager
        db_manager = DatabaseManager()
        console.print("[green]✅ Database initialized successfully[/green]")

        # Show database configuration
        config = db_manager.config
        console.print(f"[dim]Database type: {config.type}[/dim]")
        if config.type == 'sqlite':
            console.print(f"[dim]Database path: {config.sqlite_path}[/dim]")

        return db_manager

    except Exception as e:
        console.print(f"[red]❌ Database setup failed: {e}[/red]")
        return None


def demo_scan_session_management(db_manager: DatabaseManager):
    """Demonstrate scan session management"""
    console.print("\n[bold cyan]📋 Scan Session Management Demo[/bold cyan]")

    # Create scan sessions
    sessions = []

    # Discovery scan session
    discovery_session = db_manager.create_scan_session(
        name="Network Discovery Scan",
        scan_type="discovery",
        description="Initial network discovery using Masscan",
        target_specification="192.168.1.0/24",
        config_used={"rate": 1000, "ports": "1-1000"}
    )
    sessions.append(discovery_session)
    console.print(f"[green]Created discovery session:[/green] {discovery_session.id}")

    # Service enumeration session
    service_session = db_manager.create_scan_session(
        name="Service Enumeration",
        scan_type="service",
        description="Detailed service enumeration using Nmap",
        target_specification="Discovered hosts from session 1"
    )
    sessions.append(service_session)
    console.print(f"[green]Created service session:[/green] {service_session.id}")

    # Vulnerability scan session
    vuln_session = db_manager.create_scan_session(
        name="Vulnerability Assessment",
        scan_type="vulnerability",
        description="Vulnerability scanning and assessment"
    )
    sessions.append(vuln_session)
    console.print(f"[green]Created vulnerability session:[/green] {vuln_session.id}")

    # Display sessions table
    table = Table(title="Scan Sessions")
    table.add_column("ID", style="cyan")
    table.add_column("Name", style="yellow")
    table.add_column("Type", style="green")
    table.add_column("Status", style="white")
    table.add_column("Created", style="dim")

    for session in sessions:
        table.add_row(
            str(session.id),
            session.name,
            session.scan_type,
            session.status,
            session.start_time.strftime("%Y-%m-%d %H:%M") if session.start_time else "N/A"
        )

    console.print(table)
    return sessions


def demo_data_import(db_manager: DatabaseManager, sessions):
    """Demonstrate importing scan results"""
    console.print("\n[bold cyan]📥 Data Import Demo[/bold cyan]")

    importer = ScanResultImporter(db_manager)

    # Create mock Masscan results
    masscan_results = [
        ScanResult(
            ip="192.168.1.10",
            ports=[
                PortResult("192.168.1.10", 22, "tcp", "open"),
                PortResult("192.168.1.10", 80, "tcp", "open"),
                PortResult("192.168.1.10", 443, "tcp", "open"),
            ],
            scan_time=2.1,
            total_ports_scanned=3
        ),
        ScanResult(
            ip="192.168.1.20",
            ports=[
                PortResult("192.168.1.20", 22, "tcp", "open"),
                PortResult("192.168.1.20", 3306, "tcp", "open"),
            ],
            scan_time=1.8,
            total_ports_scanned=2
        ),
        ScanResult(
            ip="192.168.1.30",
            ports=[
                PortResult("192.168.1.30", 21, "tcp", "open"),
                PortResult("192.168.1.30", 80, "tcp", "open"),
                PortResult("192.168.1.30", 135, "tcp", "open"),
            ],
            scan_time=2.5,
            total_ports_scanned=3
        )
    ]

    # Import Masscan results
    console.print("[yellow]Importing Masscan results...[/yellow]")
    masscan_stats = importer.import_masscan_results(masscan_results, sessions[0].id)

    stats_table = Table(title="Masscan Import Statistics")
    stats_table.add_column("Metric", style="cyan")
    stats_table.add_column("Count", style="white")

    for key, value in masscan_stats.items():
        stats_table.add_row(key.replace('_', ' ').title(), str(value))

    console.print(stats_table)

    # Create mock Nmap results
    nmap_results = [
        DetailedScanResult(
            ip="192.168.1.10",
            hostname="web-server.local",
            ports=[
                DetailedPortResult(
                    ip="192.168.1.10",
                    port=80,
                    protocol="tcp",
                    state="open",
                    service=ServiceInfo("http", "Apache", "2.4.41", "Ubuntu", "probed", 10),
                    scripts=[
                        ScriptResult("http-title", "Welcome to Apache"),
                        ScriptResult("http-server-header", "Apache/2.4.41 (Ubuntu)")
                    ]
                ),
                DetailedPortResult(
                    ip="192.168.1.10",
                    port=443,
                    protocol="tcp",
                    state="open",
                    service=ServiceInfo("https", "Apache", "2.4.41", "Ubuntu SSL", "probed", 10),
                    scripts=[
                        ScriptResult("ssl-cert", "Certificate valid until 2025"),
                        ScriptResult("http-vuln-cve2021-44228", "VULNERABLE: Apache Log4j RCE")
                    ]
                )
            ],
            os_matches=[
                OSMatch("Linux 5.4", 95, 1, {
                    "type": "general purpose",
                    "vendor": "Linux",
                    "osfamily": "Linux",
                    "osgen": "5.X",
                    "accuracy": 95
                })
            ],
            scan_time=18.7,
            total_ports_scanned=2
        ),
        DetailedScanResult(
            ip="192.168.1.20",
            hostname="db-server.local",
            ports=[
                DetailedPortResult(
                    ip="192.168.1.20",
                    port=3306,
                    protocol="tcp",
                    state="open",
                    service=ServiceInfo("mysql", "MySQL", "8.0.28", None, "probed", 10),
                    scripts=[
                        ScriptResult("mysql-info", "MySQL 8.0.28 Community Server"),
                        ScriptResult("mysql-empty-password", "Root account has empty password")
                    ]
                )
            ],
            os_matches=[
                OSMatch("Linux 5.4", 90, 1, {
                    "type": "general purpose",
                    "vendor": "Linux",
                    "osfamily": "Linux",
                    "osgen": "5.X",
                    "accuracy": 90
                })
            ],
            scan_time=12.3,
            total_ports_scanned=1
        )
    ]

    # Import Nmap results
    console.print("\n[yellow]Importing Nmap results...[/yellow]")
    nmap_stats = importer.import_nmap_results(nmap_results, sessions[1].id)

    nmap_stats_table = Table(title="Nmap Import Statistics")
    nmap_stats_table.add_column("Metric", style="cyan")
    nmap_stats_table.add_column("Count", style="white")

    for key, value in nmap_stats.items():
        nmap_stats_table.add_row(key.replace('_', ' ').title(), str(value))

    console.print(nmap_stats_table)

    return masscan_stats, nmap_stats


def demo_advanced_queries(db_manager: DatabaseManager):
    """Demonstrate advanced querying capabilities"""
    console.print("\n[bold cyan]🔍 Advanced Queries Demo[/bold cyan]")

    query_builder = QueryBuilder(db_manager)

    # Find hosts with specific services
    console.print("[yellow]Finding hosts with Apache services...[/yellow]")
    apache_hosts = query_builder.get_hosts_with_service("Apache")

    if apache_hosts:
        apache_table = Table(title="Hosts with Apache Services")
        apache_table.add_column("IP Address", style="cyan")
        apache_table.add_column("Hostname", style="yellow")
        apache_table.add_column("Port", style="green")
        apache_table.add_column("Service", style="white")
        apache_table.add_column("Version", style="dim")

        for host_info in apache_hosts:
            apache_table.add_row(
                host_info['host']['ip_address'],
                host_info['host']['hostname'] or "N/A",
                f"{host_info['port']['number']}/{host_info['port']['protocol']}",
                host_info['service']['name'],
                host_info['service']['version'] or "N/A"
            )

        console.print(apache_table)
    else:
        console.print("[dim]No Apache services found[/dim]")

    # Get vulnerability summary
    console.print("\n[yellow]Getting vulnerability summary...[/yellow]")
    vuln_summary = query_builder.get_vulnerability_summary()

    vuln_table = Table(title="Vulnerability Summary")
    vuln_table.add_column("Metric", style="cyan")
    vuln_table.add_column("Value", style="white")

    vuln_table.add_row("Total Vulnerabilities", str(vuln_summary['total_vulnerabilities']))
    vuln_table.add_row("Affected Hosts", str(vuln_summary['affected_hosts']))

    # Show severity breakdown
    for severity, count in vuln_summary['by_severity'].items():
        vuln_table.add_row(f"{severity.title()} Severity", str(count))

    console.print(vuln_table)

    # Search hosts
    console.print("\n[yellow]Searching hosts in 192.168.1.x network...[/yellow]")
    network_hosts = query_builder.search_hosts(ip_pattern="192.168.1")

    if network_hosts:
        hosts_table = Table(title="Network Hosts")
        hosts_table.add_column("IP Address", style="cyan")
        hosts_table.add_column("Hostname", style="yellow")
        hosts_table.add_column("OS", style="green")
        hosts_table.add_column("Ports", style="white")
        hosts_table.add_column("Services", style="white")
        hosts_table.add_column("Vulnerabilities", style="red")

        for host in network_hosts:
            hosts_table.add_row(
                host['ip_address'],
                host['hostname'] or "N/A",
                host['os_name'] or "Unknown",
                str(host['port_count']),
                str(host['service_count']),
                str(host['vulnerability_count'])
            )

        console.print(hosts_table)

    # Get network overview
    console.print("\n[yellow]Getting network overview for 192.168.1.x...[/yellow]")
    network_overview = query_builder.get_network_overview("192.168.1")

    overview_table = Table(title="Network Overview")
    overview_table.add_column("Metric", style="cyan")
    overview_table.add_column("Value", style="white")

    overview_table.add_row("Total Hosts", str(network_overview['total_hosts']))
    overview_table.add_row("Active Hosts", str(network_overview['active_hosts']))
    overview_table.add_row("Total Ports", str(network_overview['total_ports']))
    overview_table.add_row("Total Services", str(network_overview['total_services']))
    overview_table.add_row("Total Vulnerabilities", str(network_overview['total_vulnerabilities']))
    overview_table.add_row("Critical Vulnerabilities", str(network_overview['critical_vulnerabilities']))

    console.print(overview_table)

    # Show top services
    if network_overview['top_services']:
        console.print("\n[yellow]Top Services in Network:[/yellow]")
        for service, count in list(network_overview['top_services'].items())[:5]:
            console.print(f"  • {service}: {count} instances")


def demo_database_utilities(db_manager: DatabaseManager):
    """Demonstrate database utilities"""
    console.print("\n[bold cyan]🛠️ Database Utilities Demo[/bold cyan]")

    db_utils = DatabaseUtils(db_manager)

    # Get database statistics
    console.print("[yellow]Getting database statistics...[/yellow]")
    stats = db_utils.get_database_statistics()

    db_stats_table = Table(title="Database Statistics")
    db_stats_table.add_column("Metric", style="cyan")
    db_stats_table.add_column("Count", style="white")

    basic_stats = ['scan_sessions', 'hosts', 'ports', 'services', 'scripts', 'vulnerabilities']
    for stat in basic_stats:
        if stat in stats:
            db_stats_table.add_row(stat.replace('_', ' ').title(), str(stats[stat]))

    if 'database_size_mb' in stats:
        db_stats_table.add_row("Database Size (MB)", f"{stats['database_size_mb']:.2f}")

    console.print(db_stats_table)

    # Show top OS families
    if stats.get('top_os_families'):
        console.print("\n[yellow]Top OS Families:[/yellow]")
        for os_family, count in stats['top_os_families'].items():
            console.print(f"  • {os_family}: {count} hosts")

    # Show top services
    if stats.get('top_services'):
        console.print("\n[yellow]Top Services:[/yellow]")
        for service, count in stats['top_services'].items():
            console.print(f"  • {service}: {count} instances")

    # Demonstrate backup
    console.print("\n[yellow]Creating database backup...[/yellow]")
    with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
        backup_path = f.name

    try:
        success = db_utils.backup_database(backup_path, compress=False)
        if success:
            console.print(f"[green]✅ Backup created:[/green] {backup_path}")

            # Show backup size
            backup_size = Path(backup_path).stat().st_size
            console.print(f"[dim]Backup size: {backup_size} bytes[/dim]")
        else:
            console.print("[red]❌ Backup failed[/red]")

    finally:
        # Clean up backup file
        Path(backup_path).unlink(missing_ok=True)

    # Demonstrate CSV export
    console.print("\n[yellow]Exporting data to CSV...[/yellow]")
    with tempfile.TemporaryDirectory() as temp_dir:
        success = db_utils.export_to_csv(temp_dir)
        if success:
            console.print(f"[green]✅ CSV export completed:[/green] {temp_dir}")

            # List exported files
            csv_files = list(Path(temp_dir).glob('*.csv'))
            for csv_file in csv_files:
                size = csv_file.stat().st_size
                console.print(f"[dim]  • {csv_file.name}: {size} bytes[/dim]")
        else:
            console.print("[red]❌ CSV export failed[/red]")


async def main():
    """Main demo function"""
    console.print(Panel.fit(
        "[bold red]Scan Results Database Demo[/bold red]\n"
        "[yellow]Persistent storage and analysis for penetration testing data[/yellow]",
        border_style="red"
    ))

    try:
        # Setup database
        db_manager = demo_database_setup()
        if not db_manager:
            return

        # Demonstrate scan session management
        sessions = demo_scan_session_management(db_manager)

        # Import scan data
        demo_data_import(db_manager, sessions)

        # Advanced queries
        demo_advanced_queries(db_manager)

        # Database utilities
        demo_database_utilities(db_manager)

        console.print("\n[bold green]✅ All database demos completed![/bold green]")
        console.print("[dim]Database contains persistent scan data ready for analysis[/dim]")

    except Exception as e:
        console.print(f"\n[bold red]❌ Demo failed:[/bold red] {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())