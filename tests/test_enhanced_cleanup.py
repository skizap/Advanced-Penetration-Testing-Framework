"""
Tests for Enhanced Cleanup Manager
"""

import pytest
import asyncio
from datetime import datetime
from unittest.mock import Mock, patch, AsyncMock

from src.persistence.cleanup_manager import CleanupManager
from src.persistence.models import (
    PersistenceSession, CompromisedHost, PlatformType, 
    CleanupConfig, PersistenceConfig, BackdoorInfo,
    PersistenceMethod, BackdoorType
)


class TestEnhancedCleanupManager:
    """Test suite for enhanced CleanupManager functionality"""
    
    @pytest.fixture
    def persistence_config(self):
        """Create test persistence configuration"""
        cleanup_config = CleanupConfig(
            auto_cleanup=True,
            cleanup_on_exit=True,
            secure_delete=True,
            preserve_logs=False
        )
        return PersistenceConfig(cleanup_config=cleanup_config)
    
    @pytest.fixture
    def cleanup_manager(self, persistence_config):
        """Create CleanupManager instance"""
        return CleanupManager(persistence_config)
    
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
    
    @pytest.fixture
    def windows_session(self, windows_host):
        """Create Windows persistence session"""
        backdoor = BackdoorInfo(
            backdoor_id="test-backdoor-1",
            host_id=windows_host.host_id,
            backdoor_type=BackdoorType.REVERSE_SHELL,
            persistence_method=PersistenceMethod.WINDOWS_SCHEDULED_TASK,
            installation_path="C:\\temp\\backdoor.exe",
            process_name="backdoor.exe",
            service_name="TestService",
            registry_key="HKLM\\Software\\Test",
            cleanup_commands=["sc stop TestService", "sc delete TestService"]
        )
        
        return PersistenceSession(
            session_id="test-session-1",
            host=windows_host,
            backdoors=[backdoor],
            session_data={
                'created_files': ['C:\\temp\\backdoor.exe', 'C:\\temp\\config.ini'],
                'temp_files': ['C:\\temp\\temp1.tmp', 'C:\\temp\\temp2.tmp']
            }
        )
    
    @pytest.fixture
    def linux_session(self, linux_host):
        """Create Linux persistence session"""
        backdoor = BackdoorInfo(
            backdoor_id="test-backdoor-2",
            host_id=linux_host.host_id,
            backdoor_type=BackdoorType.REVERSE_SHELL,
            persistence_method=PersistenceMethod.LINUX_SYSTEMD,
            installation_path="/tmp/backdoor",
            process_name="backdoor",
            service_name="test-service",
            cron_expression="*/5 * * * * /tmp/backdoor",
            cleanup_commands=["systemctl stop test-service", "rm -f /tmp/backdoor"]
        )
        
        return PersistenceSession(
            session_id="test-session-2",
            host=linux_host,
            backdoors=[backdoor],
            session_data={
                'created_files': ['/tmp/backdoor', '/tmp/config'],
                'temp_files': ['/tmp/temp1', '/tmp/temp2']
            }
        )
    
    @pytest.mark.asyncio
    async def test_enhanced_windows_cleanup(self, cleanup_manager, windows_session):
        """Test enhanced Windows cleanup operations"""
        with patch.object(cleanup_manager, '_execute_cleanup_command', new_callable=AsyncMock) as mock_execute:
            mock_execute.return_value = True
            
            result = await cleanup_manager._windows_cleanup(windows_session)
            
            assert result is True
            assert mock_execute.call_count > 0
            
            # Check that enhanced commands were called
            calls = [call[0][1] for call in mock_execute.call_args_list]
            
            # Verify enhanced Windows cleanup commands
            assert any('wevtutil cl "Windows PowerShell"' in call for call in calls)
            assert any('wevtutil cl "Microsoft-Windows-PowerShell/Operational"' in call for call in calls)
            assert any('fsutil usn deletejournal' in call for call in calls)
            assert any('vssadmin delete shadows' in call for call in calls)
            assert any('$Recycle.Bin' in call for call in calls)
            assert any('Windows Defender' in call for call in calls)
            assert any('RecentDocs' in call for call in calls)
            assert any('RunMRU' in call for call in calls)
    
    @pytest.mark.asyncio
    async def test_enhanced_linux_cleanup(self, cleanup_manager, linux_session):
        """Test enhanced Linux cleanup operations"""
        with patch.object(cleanup_manager, '_execute_cleanup_command', new_callable=AsyncMock) as mock_execute:
            mock_execute.return_value = True
            
            result = await cleanup_manager._linux_cleanup(linux_session)
            
            assert result is True
            assert mock_execute.call_count > 0
            
            # Check that enhanced commands were called
            calls = [call[0][1] for call in mock_execute.call_args_list]
            
            # Verify enhanced Linux cleanup commands
            assert any('.zsh_history' in call for call in calls)
            assert any('.fish_history' in call for call in calls)
            assert any('.python_history' in call for call in calls)
            assert any('journalctl --vacuum-time' in call for call in calls)
            assert any('/dev/shm' in call for call in calls)
            assert any('dpkg.log' in call for call in calls)
            assert any('yum.log' in call for call in calls)
            assert any('dmesg -c' in call for call in calls)
            assert any('mail.log' in call for call in calls)
    
    @pytest.mark.asyncio
    async def test_advanced_anti_forensics_integration(self, cleanup_manager, windows_session):
        """Test integration of advanced anti-forensics in cleanup session"""
        with patch.object(cleanup_manager, '_execute_cleanup_command', new_callable=AsyncMock) as mock_execute:
            with patch.object(cleanup_manager.anti_forensics, 'timestomp_files', new_callable=AsyncMock) as mock_timestomp:
                with patch.object(cleanup_manager.anti_forensics, 'clear_memory_artifacts', new_callable=AsyncMock) as mock_memory:
                    with patch.object(cleanup_manager.anti_forensics, 'clear_network_artifacts', new_callable=AsyncMock) as mock_network:
                        with patch.object(cleanup_manager.anti_forensics, 'clear_browser_artifacts', new_callable=AsyncMock) as mock_browser:
                            with patch.object(cleanup_manager.anti_forensics, 'clear_swap_files', new_callable=AsyncMock) as mock_swap:
                                
                                # Set all mocks to return True
                                mock_execute.return_value = True
                                mock_timestomp.return_value = True
                                mock_memory.return_value = True
                                mock_network.return_value = True
                                mock_browser.return_value = True
                                mock_swap.return_value = True
                                
                                result = await cleanup_manager.cleanup_session(windows_session)
                                
                                assert result is True
                                
                                # Verify anti-forensics methods were called
                                mock_timestomp.assert_called_once()
                                mock_memory.assert_called_once()
                                mock_network.assert_called_once()
                                mock_browser.assert_called_once()
                                mock_swap.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_advanced_anti_forensics_with_log_patterns(self, cleanup_manager, windows_session):
        """Test advanced anti-forensics with log patterns"""
        # Add log patterns to session
        windows_session.log_patterns = ["suspicious_activity", "malware_detected"]
        
        with patch.object(cleanup_manager, '_execute_cleanup_command', new_callable=AsyncMock) as mock_execute:
            with patch.object(cleanup_manager.anti_forensics, 'timestomp_files', new_callable=AsyncMock) as mock_timestomp:
                with patch.object(cleanup_manager.anti_forensics, 'clear_memory_artifacts', new_callable=AsyncMock) as mock_memory:
                    with patch.object(cleanup_manager.anti_forensics, 'clear_network_artifacts', new_callable=AsyncMock) as mock_network:
                        with patch.object(cleanup_manager.anti_forensics, 'clear_browser_artifacts', new_callable=AsyncMock) as mock_browser:
                            with patch.object(cleanup_manager.anti_forensics, 'clear_swap_files', new_callable=AsyncMock) as mock_swap:
                                with patch.object(cleanup_manager.anti_forensics, 'selective_log_editing', new_callable=AsyncMock) as mock_log_edit:
                                    
                                    # Set all mocks to return True
                                    mock_execute.return_value = True
                                    mock_timestomp.return_value = True
                                    mock_memory.return_value = True
                                    mock_network.return_value = True
                                    mock_browser.return_value = True
                                    mock_swap.return_value = True
                                    mock_log_edit.return_value = True
                                    
                                    result = await cleanup_manager._advanced_anti_forensics(windows_session)
                                    
                                    assert result is True
                                    
                                    # Verify selective log editing was called with patterns
                                    mock_log_edit.assert_called_once_with(
                                        windows_session.host,
                                        windows_session.log_patterns
                                    )
    
    @pytest.mark.asyncio
    async def test_cleanup_session_success_rate_calculation(self, cleanup_manager, windows_session):
        """Test cleanup session success rate calculation"""
        with patch.object(cleanup_manager, '_cleanup_backdoor', new_callable=AsyncMock) as mock_backdoor:
            with patch.object(cleanup_manager, '_platform_specific_cleanup', new_callable=AsyncMock) as mock_platform:
                with patch.object(cleanup_manager, '_cleanup_session_artifacts', new_callable=AsyncMock) as mock_artifacts:
                    with patch.object(cleanup_manager, '_secure_delete_temp_files', new_callable=AsyncMock) as mock_secure:
                        with patch.object(cleanup_manager, '_clear_logs', new_callable=AsyncMock) as mock_logs:
                            with patch.object(cleanup_manager, '_advanced_anti_forensics', new_callable=AsyncMock) as mock_anti_forensics:
                                
                                # Set some operations to fail
                                mock_backdoor.return_value = True
                                mock_platform.return_value = False  # Fail this one
                                mock_artifacts.return_value = True
                                mock_secure.return_value = True
                                mock_logs.return_value = True
                                mock_anti_forensics.return_value = True
                                
                                result = await cleanup_manager.cleanup_session(windows_session)
                                
                                # Should still succeed with 5/6 operations successful (83%)
                                assert result is True
    
    @pytest.mark.asyncio
    async def test_cleanup_session_failure_threshold(self, cleanup_manager, windows_session):
        """Test cleanup session failure when below success threshold"""
        with patch.object(cleanup_manager, '_cleanup_backdoor', new_callable=AsyncMock) as mock_backdoor:
            with patch.object(cleanup_manager, '_platform_specific_cleanup', new_callable=AsyncMock) as mock_platform:
                with patch.object(cleanup_manager, '_cleanup_session_artifacts', new_callable=AsyncMock) as mock_artifacts:
                    with patch.object(cleanup_manager, '_secure_delete_temp_files', new_callable=AsyncMock) as mock_secure:
                        with patch.object(cleanup_manager, '_clear_logs', new_callable=AsyncMock) as mock_logs:
                            with patch.object(cleanup_manager, '_advanced_anti_forensics', new_callable=AsyncMock) as mock_anti_forensics:
                                
                                # Set most operations to fail
                                mock_backdoor.return_value = False
                                mock_platform.return_value = False
                                mock_artifacts.return_value = False
                                mock_secure.return_value = False
                                mock_logs.return_value = True
                                mock_anti_forensics.return_value = True
                                
                                result = await cleanup_manager.cleanup_session(windows_session)
                                
                                # Should fail with only 2/6 operations successful (33%)
                                assert result is False
    
    @pytest.mark.asyncio
    async def test_cleanup_manager_initialization(self, persistence_config):
        """Test CleanupManager initialization with anti-forensics"""
        manager = CleanupManager(persistence_config)
        
        assert manager.config == persistence_config
        assert manager.cleanup_config == persistence_config.cleanup_config
        assert manager.anti_forensics is not None
        assert hasattr(manager.anti_forensics, 'timestomp_files')
        assert hasattr(manager.anti_forensics, 'clear_memory_artifacts')
    
    @pytest.mark.asyncio
    async def test_error_handling_in_advanced_anti_forensics(self, cleanup_manager, windows_session):
        """Test error handling in advanced anti-forensics"""
        with patch.object(cleanup_manager.anti_forensics, 'timestomp_files', side_effect=Exception("Test error")):
            result = await cleanup_manager._advanced_anti_forensics(windows_session)
            assert result is False
