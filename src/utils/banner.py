"""
Banner Module
Displays framework banner and information
"""

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from core.config import config_manager

console = Console()


def print_banner():
    """Print the framework banner"""

    banner_text = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║     █████╗ ██████╗ ██╗   ██╗ █████╗ ███╗   ██╗ ██████╗███████╗║
    ║    ██╔══██╗██╔══██╗██║   ██║██╔══██╗████╗  ██║██╔════╝██╔════╝║
    ║    ███████║██║  ██║██║   ██║███████║██╔██╗ ██║██║     █████╗  ║
    ║    ██╔══██║██║  ██║╚██╗ ██╔╝██╔══██║██║╚██╗██║██║     ██╔══╝  ║
    ║    ██║  ██║██████╔╝ ╚████╔╝ ██║  ██║██║ ╚████║╚██████╗███████╗║
    ║    ╚═╝  ╚═╝╚═════╝   ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝╚══════╝║
    ║                                                               ║
    ║           PENETRATION TESTING FRAMEWORK v1.0.0                ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    """

    # Get framework info from config
    framework_name = config_manager.get('framework.name', 'AdvancedPenTestFramework')
    framework_version = config_manager.get('framework.version', '1.0.0')
    framework_author = config_manager.get('framework.author', 'Security Research Lab')

    # Create info text
    info_text = Text()
    info_text.append(f"Framework: ", style="bold cyan")
    info_text.append(f"{framework_name}\n", style="white")
    info_text.append(f"Version: ", style="bold cyan")
    info_text.append(f"{framework_version}\n", style="white")
    info_text.append(f"Author: ", style="bold cyan")
    info_text.append(f"{framework_author}\n", style="white")
    info_text.append(f"\nCapabilities:\n", style="bold yellow")
    info_text.append(f"• Network Discovery & Scanning (Masscan + Nmap)\n", style="green")
    info_text.append(f"• Vulnerability Intelligence (NVD, Shodan, Rapid7)\n", style="green")
    info_text.append(f"• Automated Exploit Generation (ROP, Process Hollowing)\n", style="green")
    info_text.append(f"• Multi-Protocol Exploitation (SSH, SMB, Web, DNS)\n", style="green")
    info_text.append(f"• Cross-Platform Persistence (Windows, Linux, Android)\n", style="green")
    info_text.append(f"• Stealth Exfiltration (DNS-over-TLS, Tor)\n", style="green")

    # Print banner
    console.print(banner_text, style="bold red")
    console.print(Panel(info_text, title="[bold red]Framework Information[/bold red]", border_style="red"))
    console.print()

    # Warning message
    warning_text = Text()
    warning_text.append("⚠️  WARNING: ", style="bold red")
    warning_text.append("This tool is for authorized penetration testing only!\n", style="yellow")
    warning_text.append("   Ensure you have explicit written permission before scanning any network.\n", style="yellow")
    warning_text.append("   Unauthorized access to computer systems is illegal.", style="yellow")

    console.print(Panel(warning_text, title="[bold red]Legal Notice[/bold red]", border_style="red"))
    console.print()


def print_phase_banner(phase_name: str, description: str):
    """Print a phase banner"""
    phase_text = Text()
    phase_text.append(f"🚀 {phase_name}\n", style="bold cyan")
    phase_text.append(f"{description}", style="white")

    console.print(Panel(phase_text, title=f"[bold cyan]Phase: {phase_name}[/bold cyan]", border_style="cyan"))
    console.print()


def print_results_summary(results: dict):
    """Print results summary"""
    summary_text = Text()

    for key, value in results.items():
        summary_text.append(f"{key}: ", style="bold cyan")
        summary_text.append(f"{value}\n", style="white")

    console.print(Panel(summary_text, title="[bold green]Results Summary[/bold green]", border_style="green"))
    console.print()