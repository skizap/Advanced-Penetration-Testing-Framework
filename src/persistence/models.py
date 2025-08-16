"""
Data Models for Post-Exploitation & Persistence Framework
Defines data structures for persistence operations and session management
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any, Union
import uuid


class PlatformType(Enum):
    """Supported platforms for persistence"""
    WINDOWS = "windows"
    LINUX = "linux"
    ANDROID = "android"
    MACOS = "macos"
    UNKNOWN = "unknown"


class PersistenceMethod(Enum):
    """Available persistence methods"""
    # Windows methods
    WINDOWS_SCHEDULED_TASK = "windows_scheduled_task"
    WINDOWS_REGISTRY = "windows_registry"
    WINDOWS_SERVICE = "windows_service"
    WINDOWS_WMI = "windows_wmi"
    WINDOWS_STARTUP_FOLDER = "windows_startup_folder"
    WINDOWS_DLL_HIJACKING = "windows_dll_hijacking"

    # Windows UAC bypass methods
    WINDOWS_UAC_FODHELPER = "windows_uac_fodhelper"
    WINDOWS_UAC_EVENTVWR = "windows_uac_eventvwr"
    WINDOWS_UAC_COMPUTERDEFAULTS = "windows_uac_computerdefaults"
    WINDOWS_UAC_SDCLT = "windows_uac_sdclt"

    # Windows privilege escalation methods
    WINDOWS_PRIVESC_TOKEN = "windows_privesc_token"
    WINDOWS_PRIVESC_SERVICE = "windows_privesc_service"
    WINDOWS_PRIVESC_UNQUOTED_PATH = "windows_privesc_unquoted_path"
    WINDOWS_PRIVESC_REGISTRY = "windows_privesc_registry"
    
    # Linux methods
    LINUX_SYSTEMD = "linux_systemd"
    LINUX_CRON = "linux_cron"
    LINUX_INIT = "linux_init"
    LINUX_BASHRC = "linux_bashrc"
    LINUX_KERNEL_MODULE = "linux_kernel_module"
    LINUX_LIBRARY_HIJACKING = "linux_library_hijacking"
    
    # Android methods
    ANDROID_ADB = "android_adb"
    ANDROID_ROOT_EXPLOIT = "android_root_exploit"
    ANDROID_APP_PERSISTENCE = "android_app_persistence"
    
    # Cross-platform methods
    SSH_KEY = "ssh_key"
    WEB_SHELL = "web_shell"
    REVERSE_SHELL = "reverse_shell"


class BackdoorType(Enum):
    """Types of backdoors"""
    REVERSE_SHELL = "reverse_shell"
    BIND_SHELL = "bind_shell"
    WEB_SHELL = "web_shell"
    METERPRETER = "meterpreter"
    CUSTOM_IMPLANT = "custom_implant"
    FILELESS = "fileless"


class CommunicationProtocol(Enum):
    """Communication protocols for C2"""
    HTTP = "http"
    HTTPS = "https"
    DNS = "dns"
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    TOR_ONION = "tor_onion"


@dataclass
class CompromisedHost:
    """Information about a compromised host"""
    host_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    ip_address: str = ""
    hostname: str = ""
    platform: PlatformType = PlatformType.UNKNOWN
    os_version: str = ""
    architecture: str = ""
    privileges: str = "user"  # user, admin, root, system
    access_method: str = ""  # how we gained access
    credentials: Dict[str, str] = field(default_factory=dict)
    network_info: Dict[str, Any] = field(default_factory=dict)
    discovered_at: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    is_active: bool = True
    notes: str = ""


@dataclass
class BackdoorInfo:
    """Information about an installed backdoor"""
    backdoor_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    host_id: str = ""
    backdoor_type: BackdoorType = BackdoorType.REVERSE_SHELL
    persistence_method: PersistenceMethod = PersistenceMethod.REVERSE_SHELL
    payload_path: str = ""
    payload_hash: str = ""
    listen_address: str = ""
    listen_port: int = 0
    protocol: CommunicationProtocol = CommunicationProtocol.TCP
    encryption_key: str = ""
    installation_path: str = ""
    process_name: str = ""
    service_name: str = ""
    registry_key: str = ""
    cron_expression: str = ""
    startup_command: str = ""
    installed_at: datetime = field(default_factory=datetime.utcnow)
    last_callback: Optional[datetime] = None
    is_active: bool = True
    stealth_features: List[str] = field(default_factory=list)
    cleanup_commands: List[str] = field(default_factory=list)


@dataclass
class PersistenceSession:
    """Represents a persistence session on a compromised host"""
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    host: CompromisedHost = field(default_factory=CompromisedHost)
    backdoors: List[BackdoorInfo] = field(default_factory=list)
    persistence_methods: List[PersistenceMethod] = field(default_factory=list)
    c2_servers: List[str] = field(default_factory=list)
    exfiltration_channels: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    last_activity: datetime = field(default_factory=datetime.utcnow)
    is_active: bool = True
    stealth_mode: bool = True
    auto_cleanup: bool = True
    session_data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PersistenceResult:
    """Result of a persistence operation"""
    success: bool = False
    host_id: str = ""
    method: PersistenceMethod = PersistenceMethod.REVERSE_SHELL
    backdoor_info: Optional[BackdoorInfo] = None
    error_message: str = ""
    execution_time: float = 0.0
    artifacts_created: List[str] = field(default_factory=list)
    cleanup_commands: List[str] = field(default_factory=list)
    stealth_applied: bool = False
    additional_data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ExfiltrationChannel:
    """Information about data exfiltration channels"""
    channel_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    host_id: str = ""
    channel_type: str = ""  # dns, https, tor, etc.
    endpoint: str = ""
    encryption: str = ""
    compression: bool = False
    max_bandwidth: int = 0  # bytes per second
    schedule: str = ""  # when to exfiltrate
    file_patterns: List[str] = field(default_factory=list)
    exclude_patterns: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    last_used: Optional[datetime] = None
    bytes_transferred: int = 0
    is_active: bool = True


@dataclass
class StealthConfig:
    """Configuration for stealth and evasion techniques"""
    process_hiding: bool = True
    file_hiding: bool = True
    network_hiding: bool = True
    anti_debugging: bool = True
    anti_vm: bool = True
    anti_sandbox: bool = True
    memory_encryption: bool = True
    api_hooking_evasion: bool = True
    timing_evasion: bool = True
    polymorphic_payloads: bool = False
    custom_packers: List[str] = field(default_factory=list)
    evasion_techniques: List[str] = field(default_factory=list)


@dataclass
class CleanupConfig:
    """Configuration for cleanup operations"""
    auto_cleanup: bool = True
    cleanup_on_exit: bool = True
    cleanup_on_detection: bool = True
    preserve_logs: bool = False
    secure_delete: bool = True
    cleanup_delay: int = 0  # seconds
    cleanup_commands: List[str] = field(default_factory=list)
    artifacts_to_remove: List[str] = field(default_factory=list)


@dataclass
class PersistenceConfig:
    """Overall configuration for persistence operations"""
    max_concurrent_sessions: int = 10
    session_timeout: int = 3600  # seconds
    heartbeat_interval: int = 300  # seconds
    retry_attempts: int = 3
    retry_delay: int = 60  # seconds
    stealth_config: StealthConfig = field(default_factory=StealthConfig)
    cleanup_config: CleanupConfig = field(default_factory=CleanupConfig)
    default_methods: Dict[PlatformType, List[PersistenceMethod]] = field(default_factory=dict)
    c2_servers: List[str] = field(default_factory=list)
    encryption_keys: Dict[str, str] = field(default_factory=dict)
