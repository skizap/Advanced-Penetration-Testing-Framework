#!/usr/bin/env python3
"""
Vulnerability Research & Intelligence Demo
Demonstrates the complete vulnerability intelligence pipeline
"""

import sys
import asyncio
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

from intelligence.nvd_client import NVDClient
from intelligence.vulnerability_matcher import VulnerabilityMatcher, ServiceFingerprint
from intelligence.threat_intel import ThreatIntelClient
from intelligence.prioritization import VulnerabilityPrioritizer
from intelligence.exploit_db import ExploitDatabase
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.tree import Tree

console = Console()

async def demo_nvd_client():
    """Demonstrate NVD API client functionality"""
    console.print("\n[bold blue]🔍 NVD API Client Demo[/bold blue]")

    async with NVDClient() as nvd_client:
        # Test CVE lookup
        console.print("Testing CVE lookup...")
        cve_data = await nvd_client.get_cve_by_id("CVE-2021-44228")  # Log4j

        if cve_data:
            table = Table(title="CVE-2021-44228 (Log4j)")
            table.add_column("Field", style="cyan")
            table.add_column("Value", style="white")

            table.add_row("CVE ID", cve_data.cve_id)
            table.add_row("CVSS v3 Score", str(cve_data.cvss_v3_score))
            table.add_row("Severity", cve_data.cvss_v3_severity or "N/A")
            table.add_row("Description", cve_data.description[:100] + "..." if len(cve_data.description) > 100 else cve_data.description)
            table.add_row("Published", cve_data.published_date)

            console.print(table)
        else:
            console.print("[red]❌ Failed to retrieve CVE data[/red]")

        # Test keyword search
        console.print("\nTesting keyword search for 'apache'...")
        apache_cves = await nvd_client.search_cves_by_keyword("apache", limit=5)

        if apache_cves:
            console.print(f"[green]✅ Found {len(apache_cves)} Apache-related CVEs[/green]")
            for cve in apache_cves[:3]:
                console.print(f"  • {cve.cve_id}: {cve.cvss_v3_score or cve.cvss_v2_score or 'N/A'} - {cve.cvss_v3_severity or cve.cvss_v2_severity or 'Unknown'}")
        else:
            console.print("[red]❌ No Apache CVEs found[/red]")

async def demo_vulnerability_matcher():
    """Demonstrate vulnerability matching functionality"""
    console.print("\n[bold blue]🎯 Vulnerability Matcher Demo[/bold blue]")

    # Create mock service fingerprints
    services = [
        ServiceFingerprint(
            name="apache",
            version="2.4.41",
            port=80,
            protocol="tcp",
            banner="Apache/2.4.41 (Ubuntu)",
            cpe="cpe:2.3:a:apache:http_server:2.4.41"
        ),
        ServiceFingerprint(
            name="openssh",
            version="7.6",
            port=22,
            protocol="tcp",
            banner="OpenSSH_7.6p1 Ubuntu-4ubuntu0.3",
            cpe="cpe:2.3:a:openbsd:openssh:7.6"
        ),
        ServiceFingerprint(
            name="mysql",
            version="5.7.30",
            port=3306,
            protocol="tcp",
            banner="MySQL 5.7.30-0ubuntu0.18.04.1",
            cpe="cpe:2.3:a:mysql:mysql:5.7.30"
        )
    ]

    matcher = VulnerabilityMatcher()

    # Test single service matching
    console.print("Testing single service vulnerability matching...")

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
        task = progress.add_task("Searching vulnerabilities...", total=None)

        result = await matcher.match_single_service("apache", "2.4.41", 80, "tcp")

        progress.update(task, completed=True)

    if result.vulnerabilities:
        table = Table(title=f"Vulnerabilities for Apache 2.4.41")
        table.add_column("CVE ID", style="red")
        table.add_column("CVSS Score", style="yellow")
        table.add_column("Severity", style="magenta")
        table.add_column("Confidence", style="green")

        for vuln in result.vulnerabilities[:5]:
            table.add_row(
                vuln.cve_data.cve_id,
                str(vuln.cve_data.cvss_v3_score or vuln.cve_data.cvss_v2_score or "N/A"),
                vuln.cve_data.cvss_v3_severity or vuln.cve_data.cvss_v2_severity or "Unknown",
                f"{vuln.confidence:.2f}"
            )

        console.print(table)
        console.print(f"[green]✅ Risk Score: {result.risk_score:.1f}/10.0[/green]")

        # Show severity breakdown
        severity_text = ", ".join([f"{k}: {v}" for k, v in result.severity_breakdown.items() if v > 0])
        console.print(f"[blue]📊 Severity Breakdown: {severity_text}[/blue]")
    else:
        console.print("[yellow]⚠️ No vulnerabilities found for Apache 2.4.41[/yellow]")

async def demo_threat_intelligence():
    """Demonstrate threat intelligence functionality"""
    console.print("\n[bold blue]🕵️ Threat Intelligence Demo[/bold blue]")

    # Mock configuration (no real API keys for demo)
    config = {
        'shodan_api_key': '',
        'virustotal_api_key': '',
        'rapid7_api_key': ''
    }

    async with ThreatIntelClient(config) as threat_client:
        # Test reputation scoring (will use cached/mock data)
        console.print("Testing reputation scoring...")

        test_indicators = [
            ("8.8.8.8", "ip"),
            ("google.com", "domain"),
            ("192.168.1.1", "ip")
        ]

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
            task = progress.add_task("Analyzing reputation...", total=None)

            # This will mostly return empty results without real API keys
            reputation_scores = await threat_client.bulk_reputation_check(test_indicators)

            progress.update(task, completed=True)

        if reputation_scores:
            table = Table(title="Reputation Analysis")
            table.add_column("Indicator", style="cyan")
            table.add_column("Type", style="blue")
            table.add_column("Score", style="red")
            table.add_column("Confidence", style="green")

            for score in reputation_scores:
                table.add_row(
                    score.indicator,
                    score.indicator_type,
                    f"{score.overall_score:.1f}/100",
                    f"{score.confidence:.2f}"
                )

            console.print(table)
        else:
            console.print("[yellow]⚠️ No reputation data available (API keys required)[/yellow]")

async def demo_vulnerability_prioritization():
    """Demonstrate vulnerability prioritization"""
    console.print("\n[bold blue]📊 Vulnerability Prioritization Demo[/bold blue]")

    # Create mock vulnerability results for demonstration
    from intelligence.nvd_client import CVEData, VulnerabilityMatch
    from intelligence.vulnerability_matcher import VulnerabilityResult, ServiceFingerprint

    # Mock CVE data
    mock_cve = CVEData(
        cve_id="CVE-2021-44228",
        description="Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints.",
        published_date="2021-12-10T10:15:09.000",
        modified_date="2021-12-10T10:15:09.000",
        cvss_v3_score=10.0,
        cvss_v3_severity="CRITICAL",
        cvss_v2_score=9.3,
        cvss_v2_severity="HIGH",
        cpe_matches=["cpe:2.3:a:apache:log4j:2.14.1"],
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
        weaknesses=["CWE-502"],
        configurations=[]
    )

    mock_vuln_match = VulnerabilityMatch(
        service_name="apache",
        service_version="2.4.41",
        port=80,
        protocol="tcp",
        cve_data=mock_cve,
        confidence=0.9,
        match_reason="Service and version match"
    )

    mock_service = ServiceFingerprint(
        name="apache",
        version="2.4.41",
        port=80,
        protocol="tcp",
        banner="Apache/2.4.41 (Ubuntu)"
    )

    mock_vuln_result = VulnerabilityResult(
        service=mock_service,
        vulnerabilities=[mock_vuln_match],
        risk_score=9.5,
        severity_breakdown={"critical": 1, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    )

    # Test prioritization
    prioritizer = VulnerabilityPrioritizer()

    console.print("Prioritizing vulnerabilities...")
    prioritized = await prioritizer.prioritize_vulnerabilities([mock_vuln_result])

    if prioritized:
        table = Table(title="Prioritized Vulnerabilities")
        table.add_column("CVE ID", style="red")
        table.add_column("Priority Score", style="yellow")
        table.add_column("Business Impact", style="magenta")
        table.add_column("Risk Factors", style="cyan")

        for vuln in prioritized[:5]:
            risk_factors = ", ".join(vuln.risk_factors[:3])  # Show first 3 factors
            table.add_row(
                vuln.vulnerability_match.cve_data.cve_id,
                f"{vuln.priority_score:.1f}/100",
                vuln.business_impact,
                risk_factors
            )

        console.print(table)

        # Show summary
        summary = prioritizer.get_prioritization_summary(prioritized)
        console.print(f"\n[green]📈 Summary:[/green]")
        console.print(f"  • Total vulnerabilities: {summary['total_vulnerabilities']}")
        console.print(f"  • Average priority score: {summary['average_priority_score']:.1f}")
        console.print(f"  • Critical: {summary['priority_breakdown']['critical']}")
        console.print(f"  • High: {summary['priority_breakdown']['high']}")
    else:
        console.print("[red]❌ No vulnerabilities to prioritize[/red]")

async def demo_exploit_database():
    """Demonstrate exploit database functionality"""
    console.print("\n[bold blue]💥 Exploit Database Demo[/bold blue]")

    async with ExploitDatabase() as exploit_db:
        console.print("Searching for Apache exploits...")

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
            task = progress.add_task("Searching exploits...", total=None)

            # Search for exploits
            search_result = await exploit_db.comprehensive_exploit_search(
                service_name="apache",
                service_version="2.4.41",
                cve_id="CVE-2021-44228"
            )

            progress.update(task, completed=True)

        if search_result.total_exploits > 0:
            console.print(f"[green]✅ Found {search_result.total_exploits} exploits[/green]")

            # Show search summary
            summary = search_result.search_summary
            console.print(f"  • ExploitDB results: {summary['exploitdb_results']}")
            console.print(f"  • GitHub results: {summary['github_results']}")
            console.print(f"  • Highest confidence: {summary['highest_confidence']:.2f}")

            # Show best exploits
            best_exploits = exploit_db.select_best_exploits(search_result, max_exploits=3)

            if best_exploits:
                table = Table(title="Best Exploit Matches")
                table.add_column("Source", style="blue")
                table.add_column("Exploit ID", style="cyan")
                table.add_column("Availability", style="yellow")
                table.add_column("Confidence", style="green")
                table.add_column("Complexity", style="magenta")

                for exploit in best_exploits:
                    table.add_row(
                        exploit.exploit_info.source,
                        exploit.exploit_info.exploit_id,
                        exploit.exploit_info.availability.value,
                        f"{exploit.confidence:.2f}",
                        exploit.exploit_info.complexity
                    )

                console.print(table)
        else:
            console.print("[yellow]⚠️ No exploits found (requires internet connection)[/yellow]")

async def main():
    """Main demo function"""
    console.print(Panel.fit(
        "[bold green]🔬 Vulnerability Research & Intelligence System Demo[/bold green]\n"
        "This demo showcases the complete vulnerability intelligence pipeline:\n"
        "• NVD API integration for CVE data\n"
        "• Vulnerability matching and scoring\n"
        "• Threat intelligence correlation\n"
        "• Risk-based prioritization\n"
        "• Exploit database integration",
        title="Intelligence Demo",
        border_style="blue"
    ))

    try:
        # Run all demos
        await demo_nvd_client()
        await demo_vulnerability_matcher()
        await demo_threat_intelligence()
        await demo_vulnerability_prioritization()
        await demo_exploit_database()

        console.print("\n[bold green]✅ Demo completed successfully![/bold green]")
        console.print("\n[blue]💡 Note: Some features require API keys for full functionality:[/blue]")
        console.print("  • NVD API key for higher rate limits")
        console.print("  • Shodan API key for IP intelligence")
        console.print("  • VirusTotal API key for reputation data")
        console.print("  • Rapid7 API key for threat intelligence")

    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️ Demo interrupted by user[/yellow]")
    except Exception as e:
        console.print(f"\n[red]❌ Demo failed: {e}[/red]")
        import traceback
        console.print(f"[red]{traceback.format_exc()}[/red]")

if __name__ == "__main__":
    asyncio.run(main())