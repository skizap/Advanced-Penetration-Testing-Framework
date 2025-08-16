"""
Post-Exploitation & Persistence Framework
Comprehensive persistence and backdoor management across multiple platforms
"""

from .persistence_manager import PersistenceManager
from .models import (
    CompromisedHost, PersistenceSession, PersistenceResult, BackdoorInfo,
    ExfiltrationChannel, StealthConfig, CleanupConfig, PersistenceConfig,
    PlatformType, PersistenceMethod, BackdoorType, CommunicationProtocol
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
    'CommunicationProtocol'
]