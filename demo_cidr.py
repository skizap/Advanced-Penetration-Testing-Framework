#!/usr/bin/env python3
"""
CIDR Parser Demo Script
Demonstrates the functionality of the CIDR Block Parser
"""

import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

from scanner.cidr_parser import CIDRParser
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


def demo_basic_parsing():
    """Demonstrate basic CIDR parsing"""
    console.print("\n[bold cyan]🔍 Basic CIDR Parsing Demo[/bold cyan]")

    parser = CIDRParser()

    test_cases = [
        "192.168.1.100",           # Single IP
        "192.168.1.0/30",          # Small network
        "10.0.0.1-10.0.0.5",       # IP range
        "2001:db8::1",             # IPv6 single
        "2001:db8::/127",          # IPv6 network
    ]

    for test_case in test_cases:
        try:
            console.print(f"\n[yellow]Input:[/yellow] {test_case}")

            if '-' in test_case and '/' not in test_case:
                start_ip, end_ip = test_case.split('-')
                result = parser.parse_ip_range(start_ip.strip(), end_ip.strip())
            else:
                result = parser.parse_cidr(test_case)

            console.print(f"[green]Result:[/green] {len(result)} IPs")
            if len(result) <= 10:
                console.print(f"[dim]IPs: {', '.join(result)}[/dim]")
            else:
                console.print(f"[dim]First 5: {', '.join(result[:5])}...[/dim]")

        except Exception as e:
            console.print(f"[red]Error:[/red] {e}")


def demo_network_info():
    """Demonstrate network information extraction"""
    console.print("\n[bold cyan]📊 Network Information Demo[/bold cyan]")

    parser = CIDRParser()

    networks = [
        "192.168.1.0/24",
        "10.0.0.0/16",
        "2001:db8::/64",
    ]

    for network in networks:
        try:
            info = parser.get_subnet_info(network)

            table = Table(title=f"Network: {network}")
            table.add_column("Property", style="cyan")
            table.add_column("Value", style="white")

            table.add_row("Network Address", info['network_address'])
            if info['broadcast_address']:
                table.add_row("Broadcast Address", info['broadcast_address'])
            table.add_row("Netmask", info['netmask'])
            table.add_row("Prefix Length", str(info['prefix_length']))
            table.add_row("Total Addresses", str(info['total_addresses']))
            table.add_row("Usable Hosts", str(info['usable_hosts']))
            table.add_row("Is Private", str(info['is_private']))
            table.add_row("IP Version", str(info['version']))

            console.print(table)
            console.print()

        except Exception as e:
            console.print(f"[red]Error processing {network}:[/red] {e}")


def demo_filtering():
    """Demonstrate IP filtering capabilities"""
    console.print("\n[bold cyan]🔧 IP Filtering Demo[/bold cyan]")

    parser = CIDRParser()

    # Generate mixed IP list
    ip_list = [
        "192.168.1.1",    # Private IPv4
        "8.8.8.8",        # Public IPv4
        "127.0.0.1",      # Loopback IPv4
        "10.0.0.1",       # Private IPv4
        "2001:db8::1",    # IPv6
        "::1",            # IPv6 loopback
    ]

    console.print(f"[yellow]Original IP list:[/yellow] {', '.join(ip_list)}")

    # Filter examples
    filters = [
        ("Public IPs only", {"include_private": False, "include_reserved": False}),
        ("IPv4 only", {"version_filter": 4}),
        ("IPv6 only", {"version_filter": 6}),
        ("No reserved IPs", {"include_reserved": False}),
    ]

    for filter_name, filter_args in filters:
        try:
            filtered = parser.filter_ips_by_criteria(ip_list, **filter_args)
            console.print(f"[green]{filter_name}:[/green] {', '.join(filtered) if filtered else 'None'}")
        except Exception as e:
            console.print(f"[red]Error with {filter_name}:[/red] {e}")


def demo_statistics():
    """Demonstrate IP statistics"""
    console.print("\n[bold cyan]📈 IP Statistics Demo[/bold cyan]")

    parser = CIDRParser()

    # Generate IP list from multiple networks
    networks = ["192.168.1.0/28", "10.0.0.0/30"]
    all_ips = []

    for network in networks:
        ips = parser.parse_cidr(network)
        all_ips.extend(ips)

    # Add some IPv6 and special IPs
    all_ips.extend(["2001:db8::1", "2001:db8::2", "8.8.8.8"])

    stats = parser.get_statistics(all_ips)

    table = Table(title="IP Statistics")
    table.add_column("Metric", style="cyan")
    table.add_column("Count", style="white")

    for key, value in stats.items():
        table.add_row(key.replace('_', ' ').title(), str(value))

    console.print(table)


def demo_validation():
    """Demonstrate CIDR validation"""
    console.print("\n[bold cyan]✅ CIDR Validation Demo[/bold cyan]")

    parser = CIDRParser()

    test_cases = [
        ("192.168.1.0/24", True),
        ("192.168.1.100", True),
        ("2001:db8::/64", True),
        ("invalid.ip", False),
        ("192.168.1.0/33", False),
        ("256.256.256.256", False),
    ]

    table = Table(title="CIDR Validation Results")
    table.add_column("Input", style="yellow")
    table.add_column("Expected", style="cyan")
    table.add_column("Result", style="white")
    table.add_column("Status", style="white")

    for test_input, expected in test_cases:
        result = parser.validate_cidr(test_input)
        status = "✅" if result == expected else "❌"
        table.add_row(test_input, str(expected), str(result), status)

    console.print(table)


def main():
    """Main demo function"""
    console.print(Panel.fit(
        "[bold red]CIDR Block Parser Demo[/bold red]\n"
        "[yellow]Testing CIDR notation parsing, IP range generation, and validation[/yellow]",
        border_style="red"
    ))

    try:
        demo_basic_parsing()
        demo_network_info()
        demo_filtering()
        demo_statistics()
        demo_validation()

        console.print("\n[bold green]✅ All demos completed successfully![/bold green]")

    except Exception as e:
        console.print(f"\n[bold red]❌ Demo failed:[/bold red] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()