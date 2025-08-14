#!/usr/bin/env python3
"""
Masscan Scanner Demo Script
Demonstrates the functionality of the Masscan integration
"""

import sys
import asyncio
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

from scanner.masscan_scanner import MasscanScanner, PortResult, ScanResult
from scanner.cidr_parser import CIDRParser
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()


async def demo_basic_scanning():
    """Demonstrate basic Masscan scanning"""
    console.print("\n[bold cyan]🔍 Basic Masscan Scanning Demo[/bold cyan]")

    try:
        scanner = MasscanScanner()
        console.print(f"[green]✅ Masscan scanner initialized[/green]")
        console.print(f"[dim]Rate: {scanner.rate} pps, Timeout: {scanner.timeout}s[/dim]")

        # Test with localhost (safe for demo)
        test_ips = ['127.0.0.1']
        test_ports = '22,80,443,8080'

        console.print(f"\n[yellow]Scanning {', '.join(test_ips)} on ports {test_ports}[/yellow]")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Scanning...", total=None)

            results = await scanner.scan_ips(test_ips, ports=test_ports)
            progress.update(task, completed=True)

        if results:
            console.print(f"[green]Found {len(results)} hosts with open ports[/green]")

            for result in results:
                table = Table(title=f"Host: {result.ip}")
                table.add_column("Port", style="cyan")
                table.add_column("Protocol", style="yellow")
                table.add_column("State", style="green")

                for port in result.ports:
                    table.add_row(str(port.port), port.protocol, port.state)

                console.print(table)
        else:
            console.print("[yellow]No open ports found (this is normal for localhost)[/yellow]")

    except RuntimeError as e:
        console.print(f"[red]❌ Masscan not available: {e}[/red]")
        console.print("[yellow]Install masscan with: sudo apt install masscan[/yellow]")
    except Exception as e:
        console.print(f"[red]❌ Scan failed: {e}[/red]")


async def demo_stealth_scanning():
    """Demonstrate stealth scanning capabilities"""
    console.print("\n[bold cyan]🥷 Stealth Scanning Demo[/bold cyan]")

    try:
        scanner = MasscanScanner()

        # Demo different stealth levels
        stealth_levels = [1, 2, 3]
        test_ip = '127.0.0.1'

        for level in stealth_levels:
            console.print(f"\n[yellow]Stealth Level {level} scan on {test_ip}[/yellow]")

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task(f"Stealth scan level {level}...", total=None)

                results = await scanner.scan_with_stealth([test_ip], ports='80,443', stealth_level=level)
                progress.update(task, completed=True)

            console.print(f"[dim]Level {level}: Found {sum(len(r.ports) for r in results)} open ports[/dim]")

    except RuntimeError:
        console.print("[yellow]Masscan not available - skipping stealth demo[/yellow]")
    except Exception as e:
        console.print(f"[red]Stealth scan demo failed: {e}[/red]")


def demo_result_processing():
    """Demonstrate result processing and filtering"""
    console.print("\n[bold cyan]📊 Result Processing Demo[/bold cyan]")

    # Create mock results for demonstration
    mock_results = [
        ScanResult(
            ip="192.168.1.1",
            ports=[
                PortResult("192.168.1.1", 22, "tcp", "open"),
                PortResult("192.168.1.1", 80, "tcp", "open"),
                PortResult("192.168.1.1", 443, "tcp", "open"),
                PortResult("192.168.1.1", 53, "udp", "open"),
            ],
            scan_time=2.5,
            total_ports_scanned=1000
        ),
        ScanResult(
            ip="192.168.1.2",
            ports=[
                PortResult("192.168.1.2", 21, "tcp", "open"),
                PortResult("192.168.1.2", 22, "tcp", "open"),
            ],
            scan_time=1.8,
            total_ports_scanned=1000
        ),
        ScanResult(
            ip="192.168.1.3",
            ports=[
                PortResult("192.168.1.3", 3389, "tcp", "open"),
            ],
            scan_time=1.2,
            total_ports_scanned=1000
        ),
    ]

    scanner = MasscanScanner()

    # Show statistics
    stats = scanner.get_scan_statistics(mock_results)

    stats_table = Table(title="Scan Statistics")
    stats_table.add_column("Metric", style="cyan")
    stats_table.add_column("Value", style="white")

    for key, value in stats.items():
        if key == 'top_ports':
            # Show top 3 ports
            top_ports = list(value.items())[:3]
            value_str = ', '.join([f"{port}({count})" for port, count in top_ports])
        elif isinstance(value, dict):
            value_str = ', '.join([f"{k}:{v}" for k, v in value.items()])
        else:
            value_str = str(value)

        stats_table.add_row(key.replace('_', ' ').title(), value_str)

    console.print(stats_table)

    # Demonstrate filtering
    console.print("\n[yellow]Filtering Examples:[/yellow]")

    # Filter by specific ports
    web_ports = scanner.filter_results(mock_results, port_filter=[80, 443, 8080])
    console.print(f"[green]Web ports (80,443,8080):[/green] {len(web_ports)} hosts")

    # Filter by protocol
    tcp_only = scanner.filter_results(mock_results, protocol_filter=["tcp"])
    console.print(f"[green]TCP only:[/green] {sum(len(r.ports) for r in tcp_only)} ports")

    # Filter by minimum ports
    multi_port = scanner.filter_results(mock_results, min_ports=2)
    console.print(f"[green]Hosts with 2+ ports:[/green] {len(multi_port)} hosts")


def demo_export_formats():
    """Demonstrate different export formats"""
    console.print("\n[bold cyan]💾 Export Formats Demo[/bold cyan]")

    # Create sample results
    sample_results = [
        ScanResult(
            ip="192.168.1.100",
            ports=[
                PortResult("192.168.1.100", 22, "tcp", "open"),
                PortResult("192.168.1.100", 80, "tcp", "open"),
            ],
            scan_time=1.5,
            total_ports_scanned=1000
        )
    ]

    scanner = MasscanScanner()

    # Export to different formats
    formats = ['json', 'csv', 'xml']

    for fmt in formats:
        try:
            output_file = f"demo_results.{fmt}"
            scanner.export_results(sample_results, output_file, fmt)

            # Check if file was created
            if Path(output_file).exists():
                size = Path(output_file).stat().st_size
                console.print(f"[green]✅ {fmt.upper()} export:[/green] {output_file} ({size} bytes)")

                # Show preview for small files
                if size < 500:
                    with open(output_file) as f:
                        preview = f.read()[:200]
                    console.print(f"[dim]Preview: {preview}...[/dim]")

                # Clean up demo file
                Path(output_file).unlink()
            else:
                console.print(f"[red]❌ {fmt.upper()} export failed[/red]")

        except Exception as e:
            console.print(f"[red]❌ {fmt.upper()} export error: {e}[/red]")


async def demo_integration_with_cidr():
    """Demonstrate integration with CIDR parser"""
    console.print("\n[bold cyan]🔗 CIDR Integration Demo[/bold cyan]")

    try:
        # Initialize both components
        cidr_parser = CIDRParser()
        scanner = MasscanScanner()

        # Parse a small CIDR block
        cidr_block = "127.0.0.0/30"  # Just 4 IPs including network/broadcast
        console.print(f"[yellow]Parsing CIDR block: {cidr_block}[/yellow]")

        ip_list = cidr_parser.parse_cidr(cidr_block)
        console.print(f"[green]Generated {len(ip_list)} IPs: {', '.join(ip_list)}[/green]")

        # Scan the parsed IPs
        console.print("[yellow]Scanning parsed IPs...[/yellow]")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Integrated scan...", total=None)

            results = await scanner.scan_ips(ip_list, ports='22,80,443')
            progress.update(task, completed=True)

        console.print(f"[green]Integration complete: {len(results)} hosts scanned[/green]")

        if results:
            for result in results:
                console.print(f"[dim]{result.ip}: {len(result.ports)} open ports[/dim]")
        else:
            console.print("[dim]No open ports found (expected for localhost range)[/dim]")

    except RuntimeError:
        console.print("[yellow]Masscan not available - skipping integration demo[/yellow]")
    except Exception as e:
        console.print(f"[red]Integration demo failed: {e}[/red]")


async def main():
    """Main demo function"""
    console.print(Panel.fit(
        "[bold red]Masscan Scanner Demo[/bold red]\n"
        "[yellow]High-speed port scanning with Masscan integration[/yellow]",
        border_style="red"
    ))

    try:
        await demo_basic_scanning()
        await demo_stealth_scanning()
        demo_result_processing()
        demo_export_formats()
        await demo_integration_with_cidr()

        console.print("\n[bold green]✅ All Masscan demos completed![/bold green]")

    except Exception as e:
        console.print(f"\n[bold red]❌ Demo failed:[/bold red] {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())