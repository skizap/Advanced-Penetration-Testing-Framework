"""
Tests for Anti-Forensics Manager
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, AsyncMock

from src.persistence.anti_forensics import AntiForensicsManager
from src.persistence.models import (
    CompromisedHost, PlatformType, CleanupConfig
)


class TestAntiForensicsManager:
    """Test suite for AntiForensicsManager"""
    
    @pytest.fixture
    def cleanup_config(self):
        """Create test cleanup configuration"""
        return CleanupConfig(
            auto_cleanup=True,
            cleanup_on_exit=True,
            secure_delete=True,
            preserve_logs=False
        )
    
    @pytest.fixture
    def anti_forensics_manager(self, cleanup_config):
        """Create AntiForensicsManager instance"""
        return AntiForensicsManager(cleanup_config)
    
    @pytest.fixture
    def windows_host(self):
        """Create Windows test host"""
        return CompromisedHost(
            host_id="test-windows-host",
            ip_address="192.168.1.100",
            hostname="WIN-TEST",
            platform=PlatformType.WINDOWS,
            os_version="Windows 10",
            architecture="x64"
        )
    
    @pytest.fixture
    def linux_host(self):
        """Create Linux test host"""
        return CompromisedHost(
            host_id="test-linux-host",
            ip_address="192.168.1.101",
            hostname="linux-test",
            platform=PlatformType.LINUX,
            os_version="Ubuntu 20.04",
            architecture="x64"
        )
    
    @pytest.mark.asyncio
    async def test_timestomp_files_windows(self, anti_forensics_manager, windows_host):
        """Test timestomping files on Windows"""
        file_paths = [
            "C:\\temp\\test1.exe",
            "C:\\temp\\test2.dll"
        ]
        
        target_timestamp = datetime.now() - timedelta(days=30)
        
        with patch.object(anti_forensics_manager, '_execute_with_retry', new_callable=AsyncMock) as mock_execute:
            mock_execute.return_value = True
            
            result = await anti_forensics_manager.timestomp_files(
                windows_host, file_paths, target_timestamp
            )
            
            assert result is True
            # Should call execute for each file and each timestamp type (3 per file)
            assert mock_execute.call_count == len(file_paths) * 3
    
    @pytest.mark.asyncio
    async def test_timestomp_files_linux(self, anti_forensics_manager, linux_host):
        """Test timestomping files on Linux"""
        file_paths = [
            "/tmp/test1",
            "/tmp/test2"
        ]
        
        with patch.object(anti_forensics_manager, '_execute_with_retry', new_callable=AsyncMock) as mock_execute:
            mock_execute.return_value = True
            
            result = await anti_forensics_manager.timestomp_files(
                linux_host, file_paths
            )
            
            assert result is True
            # Should call execute for each file (1 per file on Linux)
            assert mock_execute.call_count == len(file_paths)
    
    @pytest.mark.asyncio
    async def test_clear_memory_artifacts_windows(self, anti_forensics_manager, windows_host):
        """Test clearing memory artifacts on Windows"""
        with patch.object(anti_forensics_manager, '_execute_with_retry', new_callable=AsyncMock) as mock_execute:
            mock_execute.return_value = True
            
            result = await anti_forensics_manager.clear_memory_artifacts(windows_host)
            
            assert result is True
            assert mock_execute.call_count > 0
            
            # Check that Windows-specific commands were called
            calls = [call[0][1] for call in mock_execute.call_args_list]
            assert any('clip' in call for call in calls)
            assert any('GC' in call for call in calls)
    
    @pytest.mark.asyncio
    async def test_clear_memory_artifacts_linux(self, anti_forensics_manager, linux_host):
        """Test clearing memory artifacts on Linux"""
        with patch.object(anti_forensics_manager, '_execute_with_retry', new_callable=AsyncMock) as mock_execute:
            mock_execute.return_value = True
            
            result = await anti_forensics_manager.clear_memory_artifacts(linux_host)
            
            assert result is True
            assert mock_execute.call_count > 0
            
            # Check that Linux-specific commands were called
            calls = [call[0][1] for call in mock_execute.call_args_list]
            assert any('swapoff' in call for call in calls)
            assert any('drop_caches' in call for call in calls)
    
    @pytest.mark.asyncio
    async def test_clear_network_artifacts_windows(self, anti_forensics_manager, windows_host):
        """Test clearing network artifacts on Windows"""
        with patch.object(anti_forensics_manager, '_execute_with_retry', new_callable=AsyncMock) as mock_execute:
            mock_execute.return_value = True
            
            result = await anti_forensics_manager.clear_network_artifacts(windows_host)
            
            assert result is True
            assert mock_execute.call_count > 0
            
            # Check that Windows-specific commands were called
            calls = [call[0][1] for call in mock_execute.call_args_list]
            assert any('ipconfig /flushdns' in call for call in calls)
            assert any('arp -d' in call for call in calls)
    
    @pytest.mark.asyncio
    async def test_clear_network_artifacts_linux(self, anti_forensics_manager, linux_host):
        """Test clearing network artifacts on Linux"""
        with patch.object(anti_forensics_manager, '_execute_with_retry', new_callable=AsyncMock) as mock_execute:
            mock_execute.return_value = True
            
            result = await anti_forensics_manager.clear_network_artifacts(linux_host)
            
            assert result is True
            assert mock_execute.call_count > 0
            
            # Check that Linux-specific commands were called
            calls = [call[0][1] for call in mock_execute.call_args_list]
            assert any('ip neigh flush' in call for call in calls)
            assert any('conntrack' in call for call in calls)
    
    @pytest.mark.asyncio
    async def test_clear_browser_artifacts_windows(self, anti_forensics_manager, windows_host):
        """Test clearing browser artifacts on Windows"""
        with patch.object(anti_forensics_manager, '_execute_with_retry', new_callable=AsyncMock) as mock_execute:
            mock_execute.return_value = True
            
            result = await anti_forensics_manager.clear_browser_artifacts(windows_host)
            
            assert result is True
            assert mock_execute.call_count > 0
            
            # Check that browser paths are targeted
            calls = [call[0][1] for call in mock_execute.call_args_list]
            assert any('Chrome' in call for call in calls)
            assert any('Firefox' in call for call in calls)
    
    @pytest.mark.asyncio
    async def test_clear_browser_artifacts_linux(self, anti_forensics_manager, linux_host):
        """Test clearing browser artifacts on Linux"""
        with patch.object(anti_forensics_manager, '_execute_with_retry', new_callable=AsyncMock) as mock_execute:
            mock_execute.return_value = True
            
            result = await anti_forensics_manager.clear_browser_artifacts(linux_host)
            
            assert result is True
            assert mock_execute.call_count > 0
            
            # Check that Linux browser paths are targeted
            calls = [call[0][1] for call in mock_execute.call_args_list]
            assert any('.config/google-chrome' in call for call in calls)
            assert any('.mozilla/firefox' in call for call in calls)
    
    @pytest.mark.asyncio
    async def test_clear_swap_files_windows(self, anti_forensics_manager, windows_host):
        """Test clearing swap files on Windows"""
        with patch.object(anti_forensics_manager, '_execute_with_retry', new_callable=AsyncMock) as mock_execute:
            mock_execute.return_value = True
            
            result = await anti_forensics_manager.clear_swap_files(windows_host)
            
            assert result is True
            assert mock_execute.call_count > 0
            
            # Check that hibernation and page file commands were called
            calls = [call[0][1] for call in mock_execute.call_args_list]
            assert any('powercfg -h off' in call for call in calls)
            assert any('hiberfil.sys' in call for call in calls)
    
    @pytest.mark.asyncio
    async def test_clear_swap_files_linux(self, anti_forensics_manager, linux_host):
        """Test clearing swap files on Linux"""
        with patch.object(anti_forensics_manager, '_execute_with_retry', new_callable=AsyncMock) as mock_execute:
            mock_execute.return_value = True
            
            result = await anti_forensics_manager.clear_swap_files(linux_host)
            
            assert result is True
            assert mock_execute.call_count > 0
            
            # Check that swap commands were called
            calls = [call[0][1] for call in mock_execute.call_args_list]
            assert any('swapoff' in call for call in calls)
            assert any('mkswap' in call for call in calls)
    
    @pytest.mark.asyncio
    async def test_selective_log_editing_windows(self, anti_forensics_manager, windows_host):
        """Test selective log editing on Windows"""
        log_patterns = ["suspicious_activity", "malware"]
        
        with patch.object(anti_forensics_manager, '_execute_with_retry', new_callable=AsyncMock) as mock_execute:
            mock_execute.return_value = True
            
            result = await anti_forensics_manager.selective_log_editing(
                windows_host, log_patterns
            )
            
            assert result is True
            assert mock_execute.call_count > 0
    
    @pytest.mark.asyncio
    async def test_selective_log_editing_linux(self, anti_forensics_manager, linux_host):
        """Test selective log editing on Linux"""
        log_patterns = ["suspicious_activity", "malware"]
        
        with patch.object(anti_forensics_manager, '_execute_with_retry', new_callable=AsyncMock) as mock_execute:
            mock_execute.return_value = True
            
            result = await anti_forensics_manager.selective_log_editing(
                linux_host, log_patterns
            )
            
            assert result is True
            assert mock_execute.call_count > 0
            
            # Check that sed commands were used
            calls = [call[0][1] for call in mock_execute.call_args_list]
            assert any('sed -i' in call for call in calls)
    
    @pytest.mark.asyncio
    async def test_execute_with_retry_success(self, anti_forensics_manager, windows_host):
        """Test successful command execution with retry"""
        command = "test command"
        
        with patch('random.random', return_value=0.5):  # Ensure success
            result = await anti_forensics_manager._execute_with_retry(windows_host, command)
            assert result is True
    
    @pytest.mark.asyncio
    async def test_execute_with_retry_failure(self, anti_forensics_manager, windows_host):
        """Test failed command execution with retry"""
        command = "test command"
        
        with patch('random.random', return_value=0.95):  # Ensure failure
            result = await anti_forensics_manager._execute_with_retry(windows_host, command)
            assert result is False
    
    @pytest.mark.asyncio
    async def test_error_handling(self, anti_forensics_manager, windows_host):
        """Test error handling in anti-forensics operations"""
        with patch.object(anti_forensics_manager, '_execute_with_retry', side_effect=Exception("Test error")):
            result = await anti_forensics_manager.clear_memory_artifacts(windows_host)
            assert result is False
