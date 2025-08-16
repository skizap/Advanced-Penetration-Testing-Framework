#!/usr/bin/env python3
"""
Post-Exploitation & Persistence Framework Demo
Demonstrates the complete persistence pipeline across multiple platforms
"""

import sys
import asyncio
import tempfile
from pathlib import Path
from datetime import datetime

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

from persistence import (
    PersistenceManager, CompromisedHost, PlatformType, PersistenceMethod,
    BackdoorType, CommunicationProtocol
)
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.tree import Tree

console = Console()


def demo_header():
    """Display demo header"""
    console.print(Panel.fit(
        "[bold blue]Post-Exploitation & Persistence Framework Demo[/bold blue]\n"
        "[dim]Comprehensive persistence across Windows, Linux, and Android platforms[/dim]",
        border_style="blue"
    ))


async def demo_windows_persistence():
    """Demonstrate Windows persistence methods"""
    console.print("\n[bold green]🪟 Windows Persistence Demo[/bold green]")
    
    # Create mock Windows host
    windows_host = {
        'ip_address': '192.168.1.100',
        'hostname': 'WIN-DESKTOP-01',
        'platform': 'windows',
        'os_version': 'Windows 10 Pro',
        'architecture': 'x64',
        'privileges': 'admin',
        'access_method': 'SMB exploit',
        'credentials': {'username': 'administrator', 'password': 'P@ssw0rd123'},
        'network_info': {'domain': 'CORP.LOCAL'}
    }
    
    # Initialize persistence manager
    manager = PersistenceManager()
    
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
        task = progress.add_task("Establishing Windows persistence...", total=None)
        
        # Establish persistence
        results = await manager.establish_persistence([windows_host])
        
        progress.update(task, description="✅ Windows persistence established")
    
    # Display results
    table = Table(title="Windows Persistence Results")
    table.add_column("Method", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Artifacts", style="yellow")
    
    for result in results:
        status = "✅ Success" if result.success else "❌ Failed"
        artifacts = ", ".join(result.artifacts_created) if result.artifacts_created else "None"
        table.add_row(result.method.value, status, artifacts)
    
    console.print(table)
    return results


async def demo_linux_persistence():
    """Demonstrate Linux persistence methods"""
    console.print("\n[bold green]🐧 Linux Persistence Demo[/bold green]")
    
    # Create mock Linux host
    linux_host = {
        'ip_address': '192.168.1.101',
        'hostname': 'ubuntu-server',
        'platform': 'linux',
        'os_version': 'Ubuntu 20.04 LTS',
        'architecture': 'x64',
        'privileges': 'root',
        'access_method': 'SSH brute force',
        'credentials': {'username': 'root', 'password': 'toor'},
        'network_info': {'interfaces': ['eth0', 'lo']}
    }
    
    manager = PersistenceManager()
    
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
        task = progress.add_task("Establishing Linux persistence...", total=None)
        
        results = await manager.establish_persistence([linux_host])
        
        progress.update(task, description="✅ Linux persistence established")
    
    # Display results
    table = Table(title="Linux Persistence Results")
    table.add_column("Method", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Stealth Features", style="magenta")
    
    for result in results:
        status = "✅ Success" if result.success else "❌ Failed"
        stealth = ", ".join(result.backdoor_info.stealth_features) if result.backdoor_info else "None"
        table.add_row(result.method.value, status, stealth)
    
    console.print(table)
    return results


async def demo_android_persistence():
    """Demonstrate Android persistence methods"""
    console.print("\n[bold green]🤖 Android Persistence Demo[/bold green]")
    
    # Create mock Android device
    android_device = {
        'ip_address': '192.168.1.102',
        'hostname': 'android-device',
        'platform': 'android',
        'os_version': 'Android 10',
        'architecture': 'arm64',
        'privileges': 'user',
        'access_method': 'ADB debug',
        'credentials': {},
        'network_info': {'wifi_connected': True}
    }
    
    manager = PersistenceManager()
    
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
        task = progress.add_task("Establishing Android persistence...", total=None)
        
        results = await manager.establish_persistence([android_device])
        
        progress.update(task, description="✅ Android persistence established")
    
    # Display results
    table = Table(title="Android Persistence Results")
    table.add_column("Method", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Requirements", style="yellow")
    
    for result in results:
        status = "✅ Success" if result.success else "❌ Failed"
        requirements = result.additional_data.get('requires_adb', False) or result.additional_data.get('requires_root', False)
        req_text = "ADB/Root" if requirements else "Standard"
        table.add_row(result.method.value, status, req_text)
    
    console.print(table)
    return results


def demo_persistence_methods():
    """Display available persistence methods"""
    console.print("\n[bold blue]📋 Available Persistence Methods[/bold blue]")
    
    tree = Tree("🎯 Persistence Methods")
    
    # Windows methods
    windows_branch = tree.add("🪟 Windows")
    windows_branch.add("📅 Scheduled Tasks")
    windows_branch.add("🗃️ Registry Modifications")
    windows_branch.add("⚙️ Windows Services")
    windows_branch.add("🔧 WMI Event Subscriptions")
    windows_branch.add("📁 Startup Folder")
    windows_branch.add("📚 DLL Hijacking")
    
    # Linux methods
    linux_branch = tree.add("🐧 Linux")
    linux_branch.add("🔧 Systemd Services")
    linux_branch.add("⏰ Cron Jobs")
    linux_branch.add("🚀 Init Scripts")
    linux_branch.add("💻 Bashrc/Profile")
    linux_branch.add("🔩 Kernel Modules")
    linux_branch.add("📚 Library Hijacking")
    
    # Android methods
    android_branch = tree.add("🤖 Android")
    android_branch.add("🔌 ADB Injection")
    android_branch.add("👑 Root Exploits")
    android_branch.add("📱 App Persistence")
    
    # Cross-platform
    cross_branch = tree.add("🌐 Cross-Platform")
    cross_branch.add("🔑 SSH Keys")
    cross_branch.add("🕸️ Web Shells")
    cross_branch.add("🔄 Reverse Shells")
    
    console.print(tree)


def demo_stealth_features():
    """Display stealth and evasion features"""
    console.print("\n[bold magenta]🥷 Stealth & Evasion Features[/bold magenta]")
    
    features_table = Table(title="Stealth Capabilities")
    features_table.add_column("Category", style="cyan")
    features_table.add_column("Features", style="green")
    
    features_table.add_row(
        "Process Hiding",
        "• Hidden processes\n• Process name spoofing\n• Parent process injection"
    )
    features_table.add_row(
        "File Hiding", 
        "• Hidden files/directories\n• System directory placement\n• Attribute manipulation"
    )
    features_table.add_row(
        "Network Hiding",
        "• Encrypted communications\n• DNS tunneling\n• Tor onion routing"
    )
    features_table.add_row(
        "Anti-Forensics",
        "• Log clearing\n• Artifact removal\n• Secure deletion"
    )
    features_table.add_row(
        "Evasion",
        "• Anti-debugging\n• VM detection\n• Sandbox evasion"
    )
    
    console.print(features_table)


async def demo_cleanup():
    """Demonstrate enhanced cleanup and anti-forensics capabilities"""
    console.print("\n[bold red]🧹 Enhanced Cleanup & Anti-Forensics Demo[/bold red]")

    manager = PersistenceManager()

    # Get active sessions (mock)
    sessions = manager.get_active_sessions()

    if sessions:
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
            task = progress.add_task("Performing enhanced cleanup operations...", total=None)

            # Simulate cleanup
            await asyncio.sleep(1)
            success = await manager.cleanup_all_sessions()

            status = "✅ Completed" if success else "❌ Failed"
            progress.update(task, description=f"{status} enhanced cleanup operations")
    else:
        console.print("[yellow]ℹ️ No active sessions to clean up[/yellow]")

    # Display enhanced cleanup features
    cleanup_table = Table(title="Enhanced Cleanup & Anti-Forensics Capabilities")
    cleanup_table.add_column("Platform", style="cyan")
    cleanup_table.add_column("Standard Cleanup", style="green")
    cleanup_table.add_column("Anti-Forensics", style="red")

    cleanup_table.add_row(
        "Windows",
        "• Event log clearing\n• PowerShell history\n• Prefetch files\n• Registry cleanup\n• USN journal\n• Shadow copies\n• Recycle bin",
        "• Timestomping\n• Memory artifacts\n• Browser cleanup\n• Network traces\n• Swap file clearing\n• Selective log editing"
    )
    cleanup_table.add_row(
        "Linux",
        "• Multiple shell histories\n• System logs\n• Systemd journal\n• Package manager logs\n• Kernel ring buffer\n• Mail logs",
        "• File timestamp modification\n• Memory cleanup\n• Network artifact removal\n• Browser data clearing\n• Swap file overwriting"
    )
    cleanup_table.add_row(
        "Android",
        "• ADB logs\n• App caches\n• Development settings\n• Temporary files",
        "• File timestomping\n• Memory clearing\n• Network cleanup\n• Browser artifacts"
    )

    console.print(cleanup_table)

    # Display anti-forensics techniques
    console.print("\n[bold yellow]🔒 Advanced Anti-Forensics Techniques[/bold yellow]")

    techniques_table = Table(title="Anti-Forensics Techniques")
    techniques_table.add_column("Technique", style="cyan")
    techniques_table.add_column("Description", style="white")
    techniques_table.add_column("Platforms", style="green")

    techniques_table.add_row(
        "Timestomping",
        "Modify file creation, modification, and access times to avoid detection",
        "Windows, Linux, Android"
    )
    techniques_table.add_row(
        "Memory Cleanup",
        "Clear sensitive data from RAM, clipboard, and environment variables",
        "Windows, Linux"
    )
    techniques_table.add_row(
        "Network Artifact Removal",
        "Clear DNS cache, ARP tables, connection tracking, and network statistics",
        "Windows, Linux"
    )
    techniques_table.add_row(
        "Browser Data Clearing",
        "Remove browser history, cache, cookies from Chrome, Firefox, Edge",
        "Windows, Linux"
    )
    techniques_table.add_row(
        "Swap File Clearing",
        "Securely overwrite hibernation files and swap partitions",
        "Windows, Linux"
    )
    techniques_table.add_row(
        "Selective Log Editing",
        "Remove specific log entries instead of clearing entire logs",
        "Windows, Linux"
    )

    console.print(techniques_table)


async def main():
    """Main demo function"""
    try:
        demo_header()
        
        # Display available methods
        demo_persistence_methods()
        
        # Display stealth features
        demo_stealth_features()
        
        # Run platform demos
        await demo_windows_persistence()
        await demo_linux_persistence()
        await demo_android_persistence()
        
        # Demonstrate cleanup
        await demo_cleanup()
        
        # Summary
        console.print("\n" + "="*60)
        console.print(Panel.fit(
            "[bold green]✅ Post-Exploitation & Persistence Framework Demo Complete![/bold green]\n\n"
            "[blue]Key Features Demonstrated:[/blue]\n"
            "• Multi-platform persistence (Windows, Linux, Android)\n"
            "• Advanced stealth and evasion techniques\n"
            "• Comprehensive cleanup and anti-forensics\n"
            "• Multiple communication channels (HTTPS, DNS, Tor, ICMP)\n"
            "• Automated payload generation and deployment\n\n"
            "[yellow]⚠️ This framework is for authorized security testing only![/yellow]",
            border_style="green"
        ))
        
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️ Demo interrupted by user[/yellow]")
    except Exception as e:
        console.print(f"\n[red]❌ Demo failed: {e}[/red]")
        import traceback
        console.print(f"[red]{traceback.format_exc()}[/red]")


if __name__ == "__main__":
    asyncio.run(main())
