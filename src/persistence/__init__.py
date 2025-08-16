"""
Post-Exploitation & Persistence Framework
Comprehensive persistence and backdoor management across multiple platforms
"""

from .persistence_manager import PersistenceManager
from .cleanup_manager import CleanupManager
from .anti_forensics import AntiForensicsManager
from .models import (
    CompromisedHost, PersistenceSession, PersistenceResult, BackdoorInfo,
    ExfiltrationChannel, StealthConfig, CleanupConfig, PersistenceConfig,
    PlatformType, PersistenceMethod, BackdoorType, CommunicationProtocol
)
from .data_exfiltration import (
    DataExfiltrationManager, ExfiltrationMethod, ChannelStatus, ExfiltrationConfig,
    ExfiltrationResult, DNSOverTLSExfiltrator, HTTPSOnionExfiltrator,
    SteganographicExfiltrator, EncryptedChannelExfiltrator
)

__all__ = [
    'PersistenceManager',
    'CompromisedHost',
    'PersistenceSession',
    'PersistenceResult',
    'BackdoorInfo',
    'ExfiltrationChannel',
    'StealthConfig',
    'CleanupConfig',
    'PersistenceConfig',
    'PlatformType',
    'PersistenceMethod',
    'BackdoorType',
    'CommunicationProtocol',
    'DataExfiltrationManager',
    'ExfiltrationMethod',
    'ChannelStatus',
    'ExfiltrationConfig',
    'ExfiltrationResult',
    'DNSOverTLSExfiltrator',
    'HTTPSOnionExfiltrator',
    'SteganographicExfiltrator',
    'EncryptedChannelExfiltrator'
]