"""
Post-Exploitation & Persistence Manager
Main orchestrator for persistence operations across different platforms
"""

import asyncio
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from loguru import logger

from src.core.config import config_manager
from .models import (
    CompromisedHost, PersistenceSession, PersistenceResult, BackdoorInfo,
    PlatformType, PersistenceMethod, PersistenceConfig, StealthConfig, CleanupConfig
)


class PersistenceManager:
    """
    Main persistence manager that coordinates all persistence operations
    """
    
    def __init__(self):
        self.config = self._load_config()
        self.sessions: Dict[str, PersistenceSession] = {}
        self.active_hosts: Dict[str, CompromisedHost] = {}
        
        # Platform-specific modules (will be imported lazily)
        self._windows_module = None
        self._linux_module = None
        self._android_module = None
        
        # Support modules
        self._backdoor_manager = None
        self._stealth_manager = None
        self._cleanup_manager = None
        self._communication_manager = None
        self._exfiltration_manager = None
        
        logger.info("Persistence Manager initialized")
    
    def _load_config(self) -> PersistenceConfig:
        """Load persistence configuration from config manager"""
        try:
            persistence_config = config_manager.get('persistence', {})
            
            # Create default configuration
            config = PersistenceConfig()
            
            # Load stealth configuration
            stealth_config = StealthConfig()
            stealth_config.process_hiding = persistence_config.get('stealth_mode', True)
            stealth_config.file_hiding = persistence_config.get('stealth_mode', True)
            stealth_config.network_hiding = persistence_config.get('stealth_mode', True)
            
            # Load cleanup configuration
            cleanup_config = CleanupConfig()
            cleanup_config.auto_cleanup = persistence_config.get('cleanup_on_exit', True)
            cleanup_config.cleanup_on_exit = persistence_config.get('cleanup_on_exit', True)
            
            config.stealth_config = stealth_config
            config.cleanup_config = cleanup_config
            
            # Load platform-specific methods
            windows_methods = persistence_config.get('windows', {}).get('methods', [])
            linux_methods = persistence_config.get('linux', {}).get('methods', [])
            android_methods = persistence_config.get('android', {}).get('methods', [])
            
            config.default_methods = {
                PlatformType.WINDOWS: [self._method_name_to_enum(m, 'windows') for m in windows_methods],
                PlatformType.LINUX: [self._method_name_to_enum(m, 'linux') for m in linux_methods],
                PlatformType.ANDROID: [self._method_name_to_enum(m, 'android') for m in android_methods],
            }
            
            logger.info("Persistence configuration loaded successfully")
            return config
            
        except Exception as e:
            logger.error(f"Failed to load persistence configuration: {e}")
            return PersistenceConfig()
    
    def _method_name_to_enum(self, method_name: str, platform: str) -> PersistenceMethod:
        """Convert method name from config to enum"""
        method_map = {
            'windows': {
                'scheduled_task': PersistenceMethod.WINDOWS_SCHEDULED_TASK,
                'registry': PersistenceMethod.WINDOWS_REGISTRY,
                'service': PersistenceMethod.WINDOWS_SERVICE,
                'wmi': PersistenceMethod.WINDOWS_WMI,
                'startup_folder': PersistenceMethod.WINDOWS_STARTUP_FOLDER,
                'dll_hijacking': PersistenceMethod.WINDOWS_DLL_HIJACKING,
                'uac_fodhelper': PersistenceMethod.WINDOWS_UAC_FODHELPER,
                'uac_eventvwr': PersistenceMethod.WINDOWS_UAC_EVENTVWR,
                'uac_computerdefaults': PersistenceMethod.WINDOWS_UAC_COMPUTERDEFAULTS,
                'uac_sdclt': PersistenceMethod.WINDOWS_UAC_SDCLT,
                'privesc_token': PersistenceMethod.WINDOWS_PRIVESC_TOKEN,
                'privesc_service': PersistenceMethod.WINDOWS_PRIVESC_SERVICE,
                'privesc_unquoted_path': PersistenceMethod.WINDOWS_PRIVESC_UNQUOTED_PATH,
                'privesc_registry': PersistenceMethod.WINDOWS_PRIVESC_REGISTRY,
            },
            'linux': {
                'systemd': PersistenceMethod.LINUX_SYSTEMD,
                'cron': PersistenceMethod.LINUX_CRON,
                'init': PersistenceMethod.LINUX_INIT,
                'bashrc': PersistenceMethod.LINUX_BASHRC,
                'kernel_module': PersistenceMethod.LINUX_KERNEL_MODULE,
                'library_hijacking': PersistenceMethod.LINUX_LIBRARY_HIJACKING,
            },
            'android': {
                'adb': PersistenceMethod.ANDROID_ADB,
                'root_exploit': PersistenceMethod.ANDROID_ROOT_EXPLOIT,
                'app_persistence': PersistenceMethod.ANDROID_APP_PERSISTENCE,
            }
        }
        
        return method_map.get(platform, {}).get(method_name, PersistenceMethod.REVERSE_SHELL)
    
    async def establish_persistence(self, compromised_hosts: List[Dict[str, Any]]) -> List[PersistenceResult]:
        """
        Establish persistence on compromised hosts
        
        Args:
            compromised_hosts: List of compromised host information
            
        Returns:
            List of persistence results
        """
        logger.info(f"Establishing persistence on {len(compromised_hosts)} hosts")
        
        results = []
        
        # Process hosts concurrently but limit concurrency
        semaphore = asyncio.Semaphore(self.config.max_concurrent_sessions)
        
        tasks = []
        for host_data in compromised_hosts:
            task = self._establish_host_persistence(semaphore, host_data)
            tasks.append(task)
        
        # Wait for all tasks to complete
        host_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in host_results:
            if isinstance(result, Exception):
                logger.error(f"Host persistence failed: {result}")
                results.append(PersistenceResult(
                    success=False,
                    error_message=str(result)
                ))
            else:
                results.extend(result)
        
        logger.info(f"Persistence establishment completed: {len(results)} results")
        return results
    
    async def _establish_host_persistence(self, semaphore: asyncio.Semaphore, 
                                        host_data: Dict[str, Any]) -> List[PersistenceResult]:
        """Establish persistence on a single host"""
        async with semaphore:
            try:
                # Create compromised host object
                host = self._create_host_from_data(host_data)
                
                # Determine platform and methods
                platform = self._detect_platform(host)
                methods = self.config.default_methods.get(platform, [PersistenceMethod.REVERSE_SHELL])
                
                logger.info(f"Establishing persistence on {host.ip_address} ({platform.value}) using {len(methods)} methods")
                
                # Create persistence session
                session = PersistenceSession(
                    host=host,
                    persistence_methods=methods,
                    stealth_mode=self.config.stealth_config.process_hiding,
                    auto_cleanup=self.config.cleanup_config.auto_cleanup
                )
                
                # Store session
                self.sessions[session.session_id] = session
                self.active_hosts[host.host_id] = host
                
                # Establish persistence using platform-specific methods
                results = []
                for method in methods:
                    try:
                        result = await self._apply_persistence_method(host, method, session)
                        results.append(result)
                        
                        if result.success and result.backdoor_info:
                            session.backdoors.append(result.backdoor_info)
                            
                    except Exception as e:
                        logger.error(f"Failed to apply {method.value} on {host.ip_address}: {e}")
                        results.append(PersistenceResult(
                            success=False,
                            host_id=host.host_id,
                            method=method,
                            error_message=str(e)
                        ))
                
                # Update session activity
                session.last_activity = datetime.utcnow()
                
                return results
                
            except Exception as e:
                logger.error(f"Host persistence establishment failed: {e}")
                return [PersistenceResult(
                    success=False,
                    error_message=str(e)
                )]
    
    def _create_host_from_data(self, host_data: Dict[str, Any]) -> CompromisedHost:
        """Create CompromisedHost object from data"""
        return CompromisedHost(
            ip_address=host_data.get('ip_address', ''),
            hostname=host_data.get('hostname', ''),
            platform=PlatformType(host_data.get('platform', 'unknown')),
            os_version=host_data.get('os_version', ''),
            architecture=host_data.get('architecture', ''),
            privileges=host_data.get('privileges', 'user'),
            access_method=host_data.get('access_method', ''),
            credentials=host_data.get('credentials', {}),
            network_info=host_data.get('network_info', {})
        )
    
    def _detect_platform(self, host: CompromisedHost) -> PlatformType:
        """Detect platform type from host information"""
        if host.platform != PlatformType.UNKNOWN:
            return host.platform
        
        # Try to detect from OS version or other indicators
        os_version = host.os_version.lower()
        if 'windows' in os_version:
            return PlatformType.WINDOWS
        elif 'linux' in os_version or 'ubuntu' in os_version or 'debian' in os_version:
            return PlatformType.LINUX
        elif 'android' in os_version:
            return PlatformType.ANDROID
        elif 'macos' in os_version or 'darwin' in os_version:
            return PlatformType.MACOS
        
        return PlatformType.UNKNOWN
    
    async def _apply_persistence_method(self, host: CompromisedHost, 
                                      method: PersistenceMethod,
                                      session: PersistenceSession) -> PersistenceResult:
        """Apply a specific persistence method"""
        start_time = time.time()
        
        try:
            # Get appropriate platform module
            if method.value.startswith('windows_'):
                module = await self._get_windows_module()
                result = await module.apply_persistence(host, method, session)
            elif method.value.startswith('linux_'):
                module = await self._get_linux_module()
                result = await module.apply_persistence(host, method, session)
            elif method.value.startswith('android_'):
                module = await self._get_android_module()
                result = await module.apply_persistence(host, method, session)
            else:
                # Cross-platform methods
                result = await self._apply_generic_method(host, method, session)
            
            result.execution_time = time.time() - start_time
            return result
            
        except Exception as e:
            logger.error(f"Failed to apply {method.value}: {e}")
            return PersistenceResult(
                success=False,
                host_id=host.host_id,
                method=method,
                error_message=str(e),
                execution_time=time.time() - start_time
            )
    
    async def _get_windows_module(self):
        """Lazy load Windows persistence module"""
        if self._windows_module is None:
            from .windows_persistence import WindowsPersistence
            self._windows_module = WindowsPersistence(self.config)
        return self._windows_module
    
    async def _get_linux_module(self):
        """Lazy load Linux persistence module"""
        if self._linux_module is None:
            from .linux_persistence import LinuxPersistence
            self._linux_module = LinuxPersistence(self.config)
        return self._linux_module
    
    async def _get_android_module(self):
        """Lazy load Android persistence module"""
        if self._android_module is None:
            from .android_persistence import AndroidPersistence
            self._android_module = AndroidPersistence(self.config)
        return self._android_module
    
    async def _apply_generic_method(self, host: CompromisedHost, 
                                  method: PersistenceMethod,
                                  session: PersistenceSession) -> PersistenceResult:
        """Apply generic cross-platform persistence methods"""
        # Placeholder for generic methods like SSH keys, web shells, etc.
        logger.info(f"Applying generic method {method.value} on {host.ip_address}")
        
        return PersistenceResult(
            success=True,
            host_id=host.host_id,
            method=method,
            additional_data={'message': f'Generic method {method.value} applied'}
        )
    
    async def cleanup_session(self, session_id: str) -> bool:
        """Clean up a persistence session"""
        if session_id not in self.sessions:
            logger.warning(f"Session {session_id} not found for cleanup")
            return False
        
        session = self.sessions[session_id]
        logger.info(f"Cleaning up session {session_id} on {session.host.ip_address}")
        
        try:
            # Get cleanup manager
            if self._cleanup_manager is None:
                from .cleanup_manager import CleanupManager
                self._cleanup_manager = CleanupManager(self.config)
            
            # Perform cleanup
            success = await self._cleanup_manager.cleanup_session(session)
            
            if success:
                # Remove session
                del self.sessions[session_id]
                if session.host.host_id in self.active_hosts:
                    del self.active_hosts[session.host.host_id]
                
                logger.info(f"Session {session_id} cleaned up successfully")
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to cleanup session {session_id}: {e}")
            return False
    
    async def cleanup_all_sessions(self) -> bool:
        """Clean up all active sessions"""
        logger.info(f"Cleaning up all {len(self.sessions)} active sessions")
        
        cleanup_tasks = []
        for session_id in list(self.sessions.keys()):
            task = self.cleanup_session(session_id)
            cleanup_tasks.append(task)
        
        results = await asyncio.gather(*cleanup_tasks, return_exceptions=True)
        
        success_count = sum(1 for r in results if r is True)
        logger.info(f"Cleaned up {success_count}/{len(results)} sessions successfully")
        
        return success_count == len(results)
    
    def get_active_sessions(self) -> List[PersistenceSession]:
        """Get all active persistence sessions"""
        return list(self.sessions.values())
    
    def get_session(self, session_id: str) -> Optional[PersistenceSession]:
        """Get a specific persistence session"""
        return self.sessions.get(session_id)
    
    def get_host_sessions(self, host_id: str) -> List[PersistenceSession]:
        """Get all sessions for a specific host"""
        return [s for s in self.sessions.values() if s.host.host_id == host_id]
