#!/usr/bin/env python3
"""
Nmap Service Enumeration Demo Script
Demonstrates the functionality of the Nmap integration
"""

import sys
import asyncio
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

from scanner.nmap_scanner import (
    NmapScanner, DetailedScanResult, DetailedPortResult,
    ServiceInfo, ScriptResult, OSMatch
)
from scanner.masscan_scanner import MasscanScanner, ScanResult, PortResult
from scanner.cidr_parser import CIDRParser
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.tree import Tree

console = Console()


async def demo_service_enumeration():
    """Demonstrate service enumeration on mock Masscan results"""
    console.print("\n[bold cyan]🔍 Service Enumeration Demo[/bold cyan]")

    try:
        scanner = NmapScanner()
        console.print(f"[green]✅ Nmap scanner initialized[/green]")
        console.print(f"[dim]Timing: T{scanner.timing}, Scripts: {', '.join(scanner.scripts)}[/dim]")

        # Create mock Masscan results (simulating discovered open ports)
        mock_masscan_results = [
            ScanResult(
                ip="127.0.0.1",
                ports=[
                    PortResult("127.0.0.1", 22, "tcp", "open"),
                    PortResult("127.0.0.1", 80, "tcp", "open"),
                    PortResult("127.0.0.1", 443, "tcp", "open"),
                ],
                scan_time=1.5,
                total_ports_scanned=3
            )
        ]

        console.print(f"\n[yellow]Processing Masscan results for service enumeration...[/yellow]")
        console.print(f"[dim]Target: {mock_masscan_results[0].ip} with {len(mock_masscan_results[0].ports)} open ports[/dim]")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Enumerating services...", total=None)

            results = await scanner.scan_services(mock_masscan_results)
            progress.update(task, completed=True)

        if results:
            console.print(f"[green]Service enumeration completed on {len(results)} hosts[/green]")

            for result in results:
                display_detailed_result(result)
        else:
            console.print("[yellow]No detailed results (this is normal for localhost without services)[/yellow]")

    except RuntimeError as e:
        console.print(f"[red]❌ Nmap not available: {e}[/red]")
        console.print("[yellow]Install nmap with: sudo apt install nmap[/yellow]")
    except Exception as e:
        console.print(f"[red]❌ Service enumeration failed: {e}[/red]")


def demo_result_processing():
    """Demonstrate result processing with mock data"""
    console.print("\n[bold cyan]📊 Result Processing Demo[/bold cyan]")

    # Create comprehensive mock results
    mock_results = [
        DetailedScanResult(
            ip="192.168.1.10",
            hostname="web-server.local",
            ports=[
                DetailedPortResult(
                    ip="192.168.1.10", port=80, protocol="tcp", state="open",
                    service=ServiceInfo("http", "Apache", "2.4.41", "Ubuntu", "probed", 10),
                    scripts=[
                        ScriptResult("http-title", "Welcome to Apache", {"title": "Welcome"}),
                        ScriptResult("http-server-header", "Apache/2.4.41 (Ubuntu)")
                    ]
                ),
                DetailedPortResult(
                    ip="192.168.1.10", port=443, protocol="tcp", state="open",
                    service=ServiceInfo("https", "Apache", "2.4.41", "Ubuntu SSL", "probed", 10),
                    scripts=[
                        ScriptResult("ssl-cert", "Certificate valid until 2025"),
                        ScriptResult("http-vuln-cve2021-44228", "VULNERABLE: Log4j RCE")
                    ]
                ),
                DetailedPortResult(
                    ip="192.168.1.10", port=22, protocol="tcp", state="open",
                    service=ServiceInfo("ssh", "OpenSSH", "8.2p1", "Ubuntu-4ubuntu0.5", "probed", 10)
                ),
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
            scan_time=15.3,
            total_ports_scanned=3,
            nmap_version="7.80",
            scan_type="service_detection"
        ),
        DetailedScanResult(
            ip="192.168.1.20",
            hostname="db-server.local",
            ports=[
                DetailedPortResult(
                    ip="192.168.1.20", port=3306, protocol="tcp", state="open",
                    service=ServiceInfo("mysql", "MySQL", "8.0.28", None, "probed", 10),
                    scripts=[
                        ScriptResult("mysql-info", "MySQL 8.0.28 Community Server"),
                        ScriptResult("mysql-empty-password", "Root account has empty password")
                    ]
                ),
                DetailedPortResult(
                    ip="192.168.1.20", port=22, protocol="tcp", state="open",
                    service=ServiceInfo("ssh", "OpenSSH", "8.2p1", "Ubuntu-4ubuntu0.5", "probed", 10)
                ),
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
            scan_time=8.7,
            total_ports_scanned=2,
            nmap_version="7.80",
            scan_type="service_detection"
        ),
    ]

    scanner = NmapScanner()

    # Display comprehensive results
    for result in mock_results:
        display_detailed_result(result)

    # Show statistics
    stats = scanner.get_service_statistics(mock_results)
    display_statistics(stats)

    # Demonstrate filtering
    console.print("\n[yellow]🔧 Filtering Examples:[/yellow]")

    # Filter by web services
    web_results = scanner.filter_by_service(mock_results, ["http", "https"])
    console.print(f"[green]Web services:[/green] {len(web_results)} hosts")

    # Filter by vulnerabilities
    vuln_results = scanner.filter_by_vulnerability(mock_results)
    console.print(f"[red]Vulnerable hosts:[/red] {len(vuln_results)} hosts")

    if vuln_results:
        for result in vuln_results:
            for port in result.ports:
                if port.scripts:
                    for script in port.scripts:
                        if "vulnerable" in script.output.lower():
                            console.print(f"[red]  • {result.ip}:{port.port} - {script.id}[/red]")


def display_detailed_result(result: DetailedScanResult):
    """Display a detailed scan result in a formatted way"""
    # Create host header
    host_info = f"[bold cyan]{result.ip}[/bold cyan]"
    if result.hostname:
        host_info += f" ([dim]{result.hostname}[/dim])"

    console.print(f"\n{host_info}")

    # OS Information
    if result.os_matches:
        os_match = result.os_matches[0]
        console.print(f"[yellow]OS:[/yellow] {os_match.name} ({os_match.accuracy}% confidence)")

    # Create ports table
    if result.ports:
        table = Table(title=f"Services on {result.ip}")
        table.add_column("Port", style="cyan", width=8)
        table.add_column("State", style="green", width=8)
        table.add_column("Service", style="yellow", width=12)
        table.add_column("Version", style="white", width=25)
        table.add_column("Scripts", style="dim", width=30)

        for port in result.ports:
            service_info = port.service.name if port.service else "unknown"

            version_info = ""
            if port.service and port.service.product:
                version_info = port.service.product
                if port.service.version:
                    version_info += f" {port.service.version}"

            script_info = ""
            if port.scripts:
                script_names = [s.id for s in port.scripts]
                script_info = ", ".join(script_names[:2])  # Show first 2 scripts
                if len(port.scripts) > 2:
                    script_info += f" (+{len(port.scripts)-2} more)"

            table.add_row(
                f"{port.port}/{port.protocol}",
                port.state,
                service_info,
                version_info,
                script_info
            )

        console.print(table)

        # Show script details for interesting findings
        for port in result.ports:
            if port.scripts:
                for script in port.scripts:
                    if any(keyword in script.output.lower()
                          for keyword in ['vulnerable', 'cve-', 'error', 'warning']):
                        console.print(f"[red]⚠️  {port.port}/{port.protocol} - {script.id}:[/red] {script.output[:100]}...")

    console.print(f"[dim]Scan completed in {result.scan_time:.2f}s[/dim]")


def display_statistics(stats: dict):
    """Display service statistics"""
    console.print("\n[bold cyan]📈 Service Statistics[/bold cyan]")

    stats_table = Table(title="Scan Summary")
    stats_table.add_column("Metric", style="cyan")
    stats_table.add_column("Value", style="white")

    # Basic stats
    stats_table.add_row("Total Hosts", str(stats['total_hosts']))
    stats_table.add_row("Hosts with Services", str(stats['hosts_with_services']))
    stats_table.add_row("Total Services", str(stats['total_services']))
    stats_table.add_row("Unique Services", str(stats['unique_services']))
    stats_table.add_row("Script Results", str(stats['script_results']))
    stats_table.add_row("Potential Vulnerabilities", str(stats['vulnerability_count']))

    console.print(stats_table)

    # OS Families
    if stats['os_families']:
        console.print("\n[yellow]Operating Systems:[/yellow]")
        for os_family, count in stats['os_families'].items():
            console.print(f"  • {os_family}: {count} hosts")

    # Top Services
    if stats['service_versions']:
        console.print("\n[yellow]Top Services:[/yellow]")
        for service, count in list(stats['service_versions'].items())[:5]:
            console.print(f"  • {service}: {count} instances")


def demo_export_formats():
    """Demonstrate different export formats"""
    console.print("\n[bold cyan]💾 Export Formats Demo[/bold cyan]")

    # Create sample results
    sample_results = [
        DetailedScanResult(
            ip="192.168.1.100",
            hostname="demo.local",
            ports=[
                DetailedPortResult(
                    ip="192.168.1.100", port=80, protocol="tcp", state="open",
                    service=ServiceInfo("http", "nginx", "1.18.0")
                ),
                DetailedPortResult(
                    ip="192.168.1.100", port=22, protocol="tcp", state="open",
                    service=ServiceInfo("ssh", "OpenSSH", "8.2p1")
                ),
            ],
            os_matches=[],
            scan_time=5.2,
            total_ports_scanned=2
        )
    ]

    scanner = NmapScanner()

    # Export to different formats
    formats = ['json', 'csv', 'xml', 'html']

    for fmt in formats:
        try:
            output_file = f"demo_nmap_results.{fmt}"
            scanner.export_results(sample_results, output_file, fmt)

            # Check if file was created
            if Path(output_file).exists():
                size = Path(output_file).stat().st_size
                console.print(f"[green]✅ {fmt.upper()} export:[/green] {output_file} ({size} bytes)")

                # Show preview for small files
                if fmt in ['json', 'csv'] and size < 1000:
                    with open(output_file) as f:
                        preview = f.read()[:300]
                    console.print(f"[dim]Preview: {preview}...[/dim]")

                # Clean up demo file
                Path(output_file).unlink()
            else:
                console.print(f"[red]❌ {fmt.upper()} export failed[/red]")

        except Exception as e:
            console.print(f"[red]❌ {fmt.upper()} export error: {e}[/red]")


async def main():
    """Main demo function"""
    console.print(Panel.fit(
        "[bold red]Nmap Service Enumeration Demo[/bold red]\n"
        "[yellow]Detailed service detection and OS fingerprinting[/yellow]",
        border_style="red"
    ))

    try:
        await demo_service_enumeration()
        demo_result_processing()
        demo_export_formats()

        console.print("\n[bold green]✅ All Nmap demos completed![/bold green]")

    except Exception as e:
        console.print(f"\n[bold red]❌ Demo failed:[/bold red] {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())