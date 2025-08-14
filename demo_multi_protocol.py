#!/usr/bin/env python3
"""
Multi-Protocol Exploitation Engine Demo
Demonstrates the complete multi-protocol exploitation capabilities
"""

import sys
import asyncio
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

from exploits import (
    MultiProtocolExploiter, ExploitTarget, ExploitationConfig,
    ProtocolType, ExploitationMode
)
from core.config import ConfigManager
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.tree import Tree

console = Console()


async def demo_ssh_exploitation():
    """Demonstrate SSH exploitation capabilities"""
    console.print(Panel.fit("🔐 SSH Exploitation Demo", style="bold blue"))
    
    # Initialize exploiter
    config_manager = ConfigManager()
    exploiter = MultiProtocolExploiter(config_manager)
    
    # Create SSH targets
    targets = [
        ExploitTarget(
            host="192.168.1.100",
            port=22,
            protocol=ProtocolType.SSH,
            service_name="ssh"
        ),
        ExploitTarget(
            host="10.0.0.50",
            port=2222,
            protocol=ProtocolType.SSH,
            service_name="ssh"
        )
    ]
    
    # Configure exploitation
    config = ExploitationConfig(
        mode=ExploitationMode.STEALTH,
        max_concurrent=2,
        timeout=30,
        stealth_delay=2.0
    )
    
    console.print(f"Testing SSH exploitation on {len(targets)} targets...")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Exploiting SSH targets...", total=None)
        
        # Perform exploitation
        results = await exploiter.exploit_targets(targets, config)
        
        progress.update(task, completed=True)
    
    # Display results
    table = Table(title="SSH Exploitation Results")
    table.add_column("Target", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Method", style="yellow")
    table.add_column("Credentials", style="magenta")
    
    for result in results:
        status = "✅ Success" if result.success else "❌ Failed"
        credentials = ""
        if result.credentials:
            credentials = f"{result.credentials.get('username', '')}:{result.credentials.get('password', 'key')}"
        
        table.add_row(
            f"{result.target.host}:{result.target.port}",
            status,
            result.exploit_type,
            credentials
        )
    
    console.print(table)
    
    # Show active sessions
    ssh_sessions = exploiter.ssh_exploiter.get_active_sessions()
    if ssh_sessions:
        console.print(f"\n🔗 Active SSH Sessions: {len(ssh_sessions)}")
        for session_key, session_info in ssh_sessions.items():
            console.print(f"  • {session_key} - {session_info['credentials']['username']}")


async def demo_shellshock_exploitation():
    """Demonstrate Shellshock exploitation capabilities"""
    console.print(Panel.fit("💥 Shellshock Exploitation Demo", style="bold red"))
    
    # Initialize exploiter
    config_manager = ConfigManager()
    exploiter = MultiProtocolExploiter(config_manager)
    
    # Create web targets
    targets = [
        ExploitTarget(
            host="192.168.1.200",
            port=80,
            protocol=ProtocolType.HTTP,
            service_name="http"
        ),
        ExploitTarget(
            host="10.0.0.100",
            port=443,
            protocol=ProtocolType.HTTPS,
            service_name="https"
        )
    ]
    
    config = ExploitationConfig(
        mode=ExploitationMode.AUTOMATED,
        max_concurrent=5,
        timeout=15
    )
    
    console.print(f"Testing Shellshock exploitation on {len(targets)} web targets...")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Exploiting web targets...", total=None)
        
        results = await exploiter.exploit_targets(targets, config)
        
        progress.update(task, completed=True)
    
    # Display results
    table = Table(title="Shellshock Exploitation Results")
    table.add_column("Target", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Method", style="yellow")
    table.add_column("Vulnerable Path", style="magenta")
    
    for result in results:
        status = "✅ Vulnerable" if result.success else "❌ Not Vulnerable"
        vulnerable_path = ""
        if result.additional_data and 'url' in result.additional_data:
            vulnerable_path = result.additional_data['url']
        
        table.add_row(
            f"{result.target.host}:{result.target.port}",
            status,
            result.exploit_type,
            vulnerable_path
        )
    
    console.print(table)


async def demo_dns_tunneling():
    """Demonstrate DNS tunneling capabilities"""
    console.print(Panel.fit("🌐 DNS Tunneling Demo", style="bold green"))
    
    # Initialize exploiter
    config_manager = ConfigManager()
    exploiter = MultiProtocolExploiter(config_manager)
    
    # Create DNS targets
    targets = [
        ExploitTarget(
            host="8.8.8.8",
            port=53,
            protocol=ProtocolType.DNS,
            service_name="domain"
        ),
        ExploitTarget(
            host="1.1.1.1",
            port=53,
            protocol=ProtocolType.DNS,
            service_name="domain"
        )
    ]
    
    config = ExploitationConfig(
        mode=ExploitationMode.STEALTH,
        max_concurrent=2,
        timeout=10
    )
    
    console.print(f"Testing DNS tunneling on {len(targets)} DNS servers...")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Testing DNS tunneling...", total=None)
        
        results = await exploiter.exploit_targets(targets, config)
        
        progress.update(task, completed=True)
    
    # Display results
    table = Table(title="DNS Tunneling Test Results")
    table.add_column("DNS Server", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Supported Methods", style="yellow")
    
    for result in results:
        status = "✅ Tunneling Possible" if result.success else "❌ No Tunneling"
        methods = ""
        if result.additional_data and 'supported_record_types' in result.additional_data:
            methods = ", ".join(result.additional_data['supported_record_types'])
        
        table.add_row(
            f"{result.target.host}:{result.target.port}",
            status,
            methods
        )
    
    console.print(table)


async def demo_smb_exploitation():
    """Demonstrate SMB exploitation capabilities"""
    console.print(Panel.fit("🗂️ SMB Exploitation Demo", style="bold yellow"))
    
    # Initialize exploiter
    config_manager = ConfigManager()
    exploiter = MultiProtocolExploiter(config_manager)
    
    # Create SMB targets
    targets = [
        ExploitTarget(
            host="192.168.1.150",
            port=445,
            protocol=ProtocolType.SMB,
            service_name="microsoft-ds"
        ),
        ExploitTarget(
            host="10.0.0.75",
            port=139,
            protocol=ProtocolType.SMB,
            service_name="netbios-ssn"
        )
    ]
    
    config = ExploitationConfig(
        mode=ExploitationMode.AUTOMATED,
        max_concurrent=3,
        timeout=20
    )
    
    console.print(f"Testing SMB exploitation on {len(targets)} targets...")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Exploiting SMB targets...", total=None)
        
        results = await exploiter.exploit_targets(targets, config)
        
        progress.update(task, completed=True)
    
    # Display results
    table = Table(title="SMB Exploitation Results")
    table.add_column("Target", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Method", style="yellow")
    table.add_column("Shares", style="magenta")
    
    for result in results:
        status = "✅ Exploited" if result.success else "❌ Failed"
        shares = ""
        if result.additional_data and 'shares' in result.additional_data:
            shares = ", ".join(result.additional_data['shares'][:3])  # Show first 3 shares
        
        table.add_row(
            f"{result.target.host}:{result.target.port}",
            status,
            result.exploit_type,
            shares
        )
    
    console.print(table)


async def demo_comprehensive_exploitation():
    """Demonstrate comprehensive multi-protocol exploitation"""
    console.print(Panel.fit("🎯 Comprehensive Multi-Protocol Exploitation", style="bold magenta"))
    
    # Initialize exploiter
    config_manager = ConfigManager()
    exploiter = MultiProtocolExploiter(config_manager)
    
    # Create mixed targets
    targets = [
        ExploitTarget(host="192.168.1.100", port=22, protocol=ProtocolType.SSH, service_name="ssh"),
        ExploitTarget(host="192.168.1.200", port=80, protocol=ProtocolType.HTTP, service_name="http"),
        ExploitTarget(host="192.168.1.150", port=445, protocol=ProtocolType.SMB, service_name="microsoft-ds"),
        ExploitTarget(host="8.8.8.8", port=53, protocol=ProtocolType.DNS, service_name="domain"),
    ]
    
    config = ExploitationConfig(
        mode=ExploitationMode.AUTOMATED,
        max_concurrent=4,
        timeout=30
    )
    
    console.print(f"Performing comprehensive exploitation on {len(targets)} targets...")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Multi-protocol exploitation...", total=None)
        
        results = await exploiter.exploit_targets(targets, config)
        
        progress.update(task, completed=True)
    
    # Display comprehensive results
    table = Table(title="Multi-Protocol Exploitation Results")
    table.add_column("Target", style="cyan")
    table.add_column("Protocol", style="blue")
    table.add_column("Status", style="green")
    table.add_column("Method", style="yellow")
    table.add_column("Details", style="magenta")
    
    for result in results:
        status = "✅ Success" if result.success else "❌ Failed"
        details = ""
        
        if result.success:
            if result.credentials:
                details = f"Creds: {result.credentials.get('username', 'N/A')}"
            elif result.additional_data:
                if 'shares' in result.additional_data:
                    details = f"Shares: {len(result.additional_data['shares'])}"
                elif 'supported_record_types' in result.additional_data:
                    details = f"DNS: {len(result.additional_data['supported_record_types'])} methods"
                elif 'url' in result.additional_data:
                    details = f"CGI: {result.additional_data['url'].split('/')[-1]}"
        
        table.add_row(
            f"{result.target.host}:{result.target.port}",
            result.target.protocol.value.upper(),
            status,
            result.exploit_type,
            details
        )
    
    console.print(table)
    
    # Show exploitation statistics
    stats = exploiter.get_exploitation_statistics()
    
    stats_table = Table(title="Exploitation Statistics")
    stats_table.add_column("Metric", style="cyan")
    stats_table.add_column("Value", style="green")
    
    stats_table.add_row("Total Attempts", str(stats.get('total_attempts', 0)))
    stats_table.add_row("Successful", str(stats.get('successful', 0)))
    stats_table.add_row("Failed", str(stats.get('failed', 0)))
    stats_table.add_row("Success Rate", f"{stats.get('success_rate', 0):.1f}%")
    stats_table.add_row("Active Sessions", str(stats.get('active_sessions', 0)))
    
    console.print(stats_table)
    
    # Show protocol breakdown
    if stats.get('protocol_breakdown'):
        protocol_tree = Tree("📊 Protocol Breakdown")
        
        for protocol, protocol_stats in stats['protocol_breakdown'].items():
            success_rate = (protocol_stats['successful'] / protocol_stats['total']) * 100
            protocol_tree.add(
                f"{protocol.upper()}: {protocol_stats['successful']}/{protocol_stats['total']} "
                f"({success_rate:.1f}% success)"
            )
        
        console.print(protocol_tree)


async def main():
    """Main demo function"""
    console.print(Panel.fit(
        "🚀 Multi-Protocol Exploitation Engine Demo\n"
        "Comprehensive demonstration of protocol-specific exploitation capabilities",
        style="bold white on blue"
    ))
    
    try:
        # Run individual protocol demos
        await demo_ssh_exploitation()
        console.print()
        
        await demo_shellshock_exploitation()
        console.print()
        
        await demo_dns_tunneling()
        console.print()
        
        await demo_smb_exploitation()
        console.print()
        
        # Run comprehensive demo
        await demo_comprehensive_exploitation()
        
        console.print(Panel.fit(
            "✅ Multi-Protocol Exploitation Demo Completed\n"
            "All protocol exploitation modules demonstrated successfully",
            style="bold green"
        ))
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Demo interrupted by user[/yellow]")
    except Exception as e:
        console.print(f"\n[red]Demo failed: {e}[/red]")
        raise


if __name__ == "__main__":
    asyncio.run(main())
