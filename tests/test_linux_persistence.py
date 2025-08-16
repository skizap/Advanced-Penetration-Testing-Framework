"""
Test cases for Linux Persistence Module
"""

import pytest
import asyncio
import uuid
from unittest.mock import Mock, patch
from pathlib import Path
import sys

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from persistence.linux_persistence import LinuxPersistence
from persistence.models import (
    CompromisedHost, PersistenceSession, PersistenceResult, BackdoorInfo,
    PersistenceMethod, BackdoorType, PlatformType, PersistenceConfig
)


class TestLinuxPersistence:
    """Test cases for LinuxPersistence"""

    def setup_method(self):
        """Setup test environment"""
        self.config = PersistenceConfig()
        self.linux_persistence = LinuxPersistence(self.config)
        
        # Create mock host
        self.mock_host = CompromisedHost(
            ip_address="192.168.1.100",
            hostname="test-linux",
            platform=PlatformType.LINUX,
            os_version="Ubuntu 20.04 LTS",
            architecture="x64",
            privileges="root",
            credentials={"username": "root", "password": "toor"}
        )
        
        # Create mock session
        self.mock_session = PersistenceSession(
            host=self.mock_host,
            c2_servers=["192.168.1.10:4444"],
            stealth_mode=True
        )

    @pytest.mark.asyncio
    async def test_systemd_persistence(self):
        """Test systemd service persistence"""
        result = await self.linux_persistence._create_systemd_service(
            self.mock_host, self.mock_session
        )
        
        assert result.success is True
        assert result.method == PersistenceMethod.LINUX_SYSTEMD
        assert result.backdoor_info is not None
        assert result.backdoor_info.backdoor_type == BackdoorType.CUSTOM_IMPLANT
        assert result.backdoor_info.persistence_method == PersistenceMethod.LINUX_SYSTEMD
        assert "systemd_service" in result.backdoor_info.stealth_features
        assert len(result.cleanup_commands) > 0
        assert "systemctl stop" in result.cleanup_commands[0]
        
        # Check artifacts
        assert len(result.artifacts_created) == 3  # Service, File, Unit
        assert any("Service:" in artifact for artifact in result.artifacts_created)
        
        # Check additional data
        assert "service_name" in result.additional_data
        assert "commands" in result.additional_data

    @pytest.mark.asyncio
    async def test_cron_persistence(self):
        """Test cron job persistence"""
        result = await self.linux_persistence._create_cron_persistence(
            self.mock_host, self.mock_session
        )
        
        assert result.success is True
        assert result.method == PersistenceMethod.LINUX_CRON
        assert result.backdoor_info is not None
        assert result.backdoor_info.backdoor_type == BackdoorType.CUSTOM_IMPLANT
        assert result.backdoor_info.persistence_method == PersistenceMethod.LINUX_CRON
        assert "cron_job" in result.backdoor_info.stealth_features
        assert "hidden_file" in result.backdoor_info.stealth_features
        
        # Check cron expression
        assert result.backdoor_info.cron_expression is not None
        assert "*/15 * * * *" in result.backdoor_info.cron_expression
        
        # Check cleanup commands
        assert len(result.cleanup_commands) == 2
        assert "crontab -l" in result.cleanup_commands[0]
        assert "rm -f" in result.cleanup_commands[1]

    @pytest.mark.asyncio
    async def test_init_script_persistence(self):
        """Test init script persistence"""
        result = await self.linux_persistence._create_init_script(
            self.mock_host, self.mock_session
        )
        
        assert result.success is True
        assert result.method == PersistenceMethod.LINUX_INIT
        assert result.backdoor_info is not None
        assert result.backdoor_info.backdoor_type == BackdoorType.CUSTOM_IMPLANT
        assert result.backdoor_info.persistence_method == PersistenceMethod.LINUX_INIT
        assert "init_script" in result.backdoor_info.stealth_features
        assert "system_service" in result.backdoor_info.stealth_features
        
        # Check service name
        assert result.backdoor_info.service_name is not None
        assert "system-monitor-" in result.backdoor_info.service_name
        
        # Check installation path
        assert "/etc/init.d/" in result.backdoor_info.installation_path
        
        # Check cleanup commands
        assert len(result.cleanup_commands) == 3
        assert "service" in result.cleanup_commands[0]
        assert "update-rc.d" in result.cleanup_commands[1]
        assert "rm -f" in result.cleanup_commands[2]

    @pytest.mark.asyncio
    async def test_bashrc_persistence(self):
        """Test bashrc persistence"""
        result = await self.linux_persistence._create_bashrc_persistence(
            self.mock_host, self.mock_session
        )
        
        assert result.success is True
        assert result.method == PersistenceMethod.LINUX_BASHRC
        assert result.backdoor_info is not None
        assert result.backdoor_info.backdoor_type == BackdoorType.CUSTOM_IMPLANT
        assert result.backdoor_info.persistence_method == PersistenceMethod.LINUX_BASHRC
        assert "bashrc_persistence" in result.backdoor_info.stealth_features
        assert "hidden_file" in result.backdoor_info.stealth_features
        assert "function_disguise" in result.backdoor_info.stealth_features
        
        # Check installation path (should be hidden file in /tmp)
        assert "/tmp/." in result.backdoor_info.installation_path
        
        # Check cleanup commands
        assert len(result.cleanup_commands) == 2
        assert "sed -i" in result.cleanup_commands[0]
        assert "rm -f" in result.cleanup_commands[1]

    @pytest.mark.asyncio
    async def test_kernel_module_persistence(self):
        """Test kernel module persistence"""
        result = await self.linux_persistence._create_kernel_module(
            self.mock_host, self.mock_session
        )
        
        assert result.success is True
        assert result.method == PersistenceMethod.LINUX_KERNEL_MODULE
        assert result.backdoor_info is not None
        assert result.backdoor_info.backdoor_type == BackdoorType.CUSTOM_IMPLANT
        assert result.backdoor_info.persistence_method == PersistenceMethod.LINUX_KERNEL_MODULE
        assert "kernel_module" in result.backdoor_info.stealth_features
        assert "rootkit_level" in result.backdoor_info.stealth_features
        assert "deep_hiding" in result.backdoor_info.stealth_features
        
        # Check module path
        assert "/lib/modules/" in result.backdoor_info.installation_path
        assert ".ko" in result.backdoor_info.installation_path
        
        # Check cleanup commands
        assert len(result.cleanup_commands) == 3
        assert "rmmod" in result.cleanup_commands[0]
        assert "rm -f" in result.cleanup_commands[1]
        assert "depmod -a" in result.cleanup_commands[2]
        
        # Check additional data
        assert "note" in result.additional_data
        assert "compilation" in result.additional_data["note"]

    @pytest.mark.asyncio
    async def test_library_hijacking_persistence(self):
        """Test library hijacking persistence"""
        result = await self.linux_persistence._create_library_hijacking(
            self.mock_host, self.mock_session
        )
        
        assert result.success is True
        assert result.method == PersistenceMethod.LINUX_LIBRARY_HIJACKING
        assert result.backdoor_info is not None
        assert result.backdoor_info.backdoor_type == BackdoorType.CUSTOM_IMPLANT
        assert result.backdoor_info.persistence_method == PersistenceMethod.LINUX_LIBRARY_HIJACKING
        assert "library_hijacking" in result.backdoor_info.stealth_features
        assert "ld_preload" in result.backdoor_info.stealth_features
        
        # Check installation path
        assert "/usr/local/lib/" in result.backdoor_info.installation_path
        assert ".so" in result.backdoor_info.installation_path
        
        # Check cleanup commands
        assert len(result.cleanup_commands) == 1
        assert "rm -f" in result.cleanup_commands[0]

    @pytest.mark.asyncio
    async def test_apply_persistence_all_methods(self):
        """Test apply_persistence with all Linux methods"""
        methods = [
            PersistenceMethod.LINUX_SYSTEMD,
            PersistenceMethod.LINUX_CRON,
            PersistenceMethod.LINUX_INIT,
            PersistenceMethod.LINUX_BASHRC,
            PersistenceMethod.LINUX_KERNEL_MODULE,
            PersistenceMethod.LINUX_LIBRARY_HIJACKING
        ]
        
        for method in methods:
            result = await self.linux_persistence.apply_persistence(
                self.mock_host, method, self.mock_session
            )
            assert result.success is True
            assert result.method == method
            assert result.host_id == self.mock_host.host_id

    @pytest.mark.asyncio
    async def test_apply_persistence_unsupported_method(self):
        """Test apply_persistence with unsupported method"""
        result = await self.linux_persistence.apply_persistence(
            self.mock_host, PersistenceMethod.WINDOWS_REGISTRY, self.mock_session
        )
        
        assert result.success is False
        assert "Unsupported Linux method" in result.error_message

    @pytest.mark.asyncio
    async def test_apply_persistence_exception_handling(self):
        """Test exception handling in apply_persistence"""
        # Mock an exception in one of the methods
        with patch.object(self.linux_persistence, '_create_systemd_service', 
                         side_effect=Exception("Test exception")):
            result = await self.linux_persistence.apply_persistence(
                self.mock_host, PersistenceMethod.LINUX_SYSTEMD, self.mock_session
            )
            
            assert result.success is False
            assert "Test exception" in result.error_message

    def test_generate_bash_payload(self):
        """Test bash payload generation"""
        payload = self.linux_persistence._generate_bash_payload(
            self.mock_host, self.mock_session
        )
        
        assert "#!/bin/bash" in payload
        assert "192.168.1.10" in payload  # C2 server IP
        assert "4444" in payload  # C2 server port
        assert "while true" in payload
        assert "/dev/tcp/" in payload or "nc -e" in payload

    def test_create_systemd_unit(self):
        """Test systemd unit file creation"""
        service_name = "test-service"
        script_path = "/usr/local/bin/test-service"
        
        unit_content = self.linux_persistence._create_systemd_unit(service_name, script_path)
        
        assert "[Unit]" in unit_content
        assert "[Service]" in unit_content
        assert "[Install]" in unit_content
        assert script_path in unit_content
        assert "network.target" in unit_content
        assert "multi-user.target" in unit_content

    def test_create_init_script_content(self):
        """Test init script content creation"""
        script_name = "test-script"
        payload = "echo 'test payload'"
        
        init_script = self.linux_persistence._create_init_script_content(script_name, payload)
        
        assert "#!/bin/bash" in init_script
        assert "### BEGIN INIT INFO" in init_script
        assert script_name in init_script
        assert payload in init_script
        assert "start)" in init_script
        assert "stop)" in init_script
        assert "restart)" in init_script

    def test_generate_kernel_module_source(self):
        """Test kernel module source generation"""
        module_name = "test_module"
        
        source = self.linux_persistence._generate_kernel_module_source(
            self.mock_host, self.mock_session, module_name
        )
        
        assert module_name in source
        assert "/*" in source  # Comment marker
        assert "*/" in source  # Comment marker

    def test_generate_malicious_library(self):
        """Test malicious library generation"""
        lib_content = self.linux_persistence._generate_malicious_library(
            self.mock_host, self.mock_session
        )
        
        assert isinstance(lib_content, bytes)
        assert b"LIBRARY_PLACEHOLDER" in lib_content
