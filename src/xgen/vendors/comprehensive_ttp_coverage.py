"""
Comprehensive TTP Coverage Library

This module provides extensive MITRE ATT&CK TTP coverage across all major security vendors,
with multiple log types per TTP showing complete attack chains. Each vendor generates
logs that demonstrate the full spectrum of threat actor behaviors.
"""

import random
import json
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any
from faker import Faker

from ..core.models import BaseEvent, EndpointEvent, NetworkEvent, IdentityEvent, CloudEvent
from ..core.models import NICECategory, SeverityLevel
from .authentic_log_library import AuthenticLogGenerator

fake = Faker()


# === EXTENDED PALO ALTO NETWORKS COVERAGE ===

class PaloAltoExtendedGenerator(AuthenticLogGenerator):
    """Extended Palo Alto PAN-OS coverage for comprehensive TTP mapping."""
    
    def __init__(self):
        super().__init__("Palo Alto Networks", "PAN-OS", NICECategory.NETWORK)
    
    # T1071.001 - Application Layer Protocol: Web Protocols
    def generate_web_tunnel_log(self) -> NetworkEvent:
        """Web-based tunneling for C2 communications."""
        return NetworkEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="TRAFFIC",
            event_code="1",
            severity=SeverityLevel.WARNING,
            message=f"1,{datetime.now().strftime('%Y/%m/%d %H:%M:%S')},01234567890,TRAFFIC,end,2305,"
                   f"{datetime.now().strftime('%Y/%m/%d %H:%M:%S')},{fake.ipv4_private()},{fake.ipv4()},"
                   f"{fake.ipv4_private()},{fake.ipv4()},Web-Tunneling-Rule,{fake.user_name()},,web-browsing,vsys1,"
                   f"Internal,External,ethernet1/1,ethernet1/2,LOG-Default,{datetime.now().strftime('%Y/%m/%d %H:%M:%S')},"
                   f"{random.randint(100000, 999999)},1,{random.randint(50000, 60000)},443,0,0,0x19,tcp,allow,"
                   f"{random.randint(50000, 100000)},{random.randint(10000, 50000)},100,50,{datetime.now().strftime('%Y/%m/%d %H:%M:%S')},"
                   f"300,tunnel-other,0,{random.randint(1000000, 9999999)},0x8000,US,Reserved,0,1,0,policy-allow",
            source_ip=fake.ipv4_private(),
            destination_ip=fake.ipv4(),
            protocol="tcp",
            direction="outbound",
            labels={"action": "allow", "application": "tunnel-other", "suspicious": "true"},
            pattern_id="T1071.001_WEB_PROTOCOLS"
        )
    
    def generate_dns_tunneling_log(self) -> NetworkEvent:
        """DNS tunneling for data exfiltration."""
        return NetworkEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="THREAT",
            event_code="dns",
            severity=SeverityLevel.CRITICAL,
            message=f"1,{datetime.now().strftime('%Y/%m/%d %H:%M:%S')},01234567890,THREAT,dns,2305,"
                   f"{datetime.now().strftime('%Y/%m/%d %H:%M:%S')},{fake.ipv4_private()},{fake.ipv4()},"
                   f"{fake.ipv4_private()},{fake.ipv4()},DNS-Tunneling-Block,{fake.user_name()},,dns,vsys1,"
                   f"Internal,External,ethernet1/1,ethernet1/2,LOG-Default,{datetime.now().strftime('%Y/%m/%d %H:%M:%S')},"
                   f"{random.randint(100000, 999999)},1,{random.randint(50000, 60000)},53,0,0,0x400000,udp,block-url,"
                   f"\"base64-encoded-data.{random.choice(self.malicious_domains)}\",(9999),command-and-control,high,client-to-server",
            source_ip=fake.ipv4_private(),
            destination_ip=fake.ipv4(),
            protocol="udp",
            destination_port=53,
            labels={"action": "block-url", "category": "command-and-control", "severity": "high"},
            pattern_id="T1071.004_DNS"
        )
    
    # T1566.001 - Phishing: Spearphishing Attachment
    def generate_malware_download_log(self) -> NetworkEvent:
        """Malware download via HTTP."""
        return NetworkEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="THREAT",
            event_code="file",
            severity=SeverityLevel.CRITICAL,
            message=f"1,{datetime.now().strftime('%Y/%m/%d %H:%M:%S')},01234567890,THREAT,file,2305,"
                   f"{datetime.now().strftime('%Y/%m/%d %H:%M:%S')},{fake.ipv4_private()},{fake.ipv4()},"
                   f"{fake.ipv4_private()},{fake.ipv4()},Block-Malware-Downloads,{fake.user_name()},,web-browsing,vsys1,"
                   f"Internal,External,ethernet1/1,ethernet1/2,LOG-Default,{datetime.now().strftime('%Y/%m/%d %H:%M:%S')},"
                   f"{random.randint(100000, 999999)},1,{random.randint(50000, 60000)},80,0,0,0x80004000,tcp,block-url,"
                   f"\"{random.choice(self.threat_signatures)}\",(9999),Malware,critical,client-to-server,"
                   f"{random.randint(40000, 50000)},0x0,US,Reserved,0,application/octet-stream,invoice.exe",
            source_ip=fake.ipv4_private(),
            destination_ip=fake.ipv4(),
            protocol="tcp",
            destination_port=80,
            labels={"action": "block-url", "threat_type": "Malware", "file_type": "executable"},
            pattern_id="T1566.001_PHISHING_ATTACHMENT"
        )
    
    # T1046 - Network Service Scanning
    def generate_port_scan_detection_log(self) -> NetworkEvent:
        """Port scanning detection."""
        return NetworkEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="TRAFFIC",
            event_code="1",
            severity=SeverityLevel.WARNING,
            message=f"1,{datetime.now().strftime('%Y/%m/%d %H:%M:%S')},01234567890,TRAFFIC,start,2305,"
                   f"{datetime.now().strftime('%Y/%m/%d %H:%M:%S')},{fake.ipv4()},{fake.ipv4_private()},"
                   f"{fake.ipv4()},{fake.ipv4_private()},Block-Port-Scans,,,incomplete,vsys1,"
                   f"External,Internal,ethernet1/2,ethernet1/1,LOG-Default,{datetime.now().strftime('%Y/%m/%d %H:%M:%S')},"
                   f"{random.randint(100000, 999999)},1,{random.randint(1024, 65535)},{random.choice([22, 23, 80, 443, 3389])},0,0,0x19,tcp,deny,0,0,0,0",
            source_ip=fake.ipv4(),
            destination_ip=fake.ipv4_private(),
            protocol="tcp",
            direction="inbound",
            labels={"action": "deny", "reason": "port_scan", "threat_type": "scanning"},
            pattern_id="T1046_NETWORK_SERVICE_SCANNING"
        )
    
    # T1190 - Exploit Public-Facing Application
    def generate_web_exploit_log(self) -> NetworkEvent:
        """Web application exploit attempt."""
        return NetworkEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="THREAT",
            event_code="vulnerability",
            severity=SeverityLevel.CRITICAL,
            message=f"1,{datetime.now().strftime('%Y/%m/%d %H:%M:%S')},01234567890,THREAT,vulnerability,2305,"
                   f"{datetime.now().strftime('%Y/%m/%d %H:%M:%S')},{fake.ipv4()},{fake.ipv4_private()},"
                   f"{fake.ipv4()},{fake.ipv4_private()},Block-Web-Exploits,,,web-browsing,vsys1,"
                   f"External,DMZ,ethernet1/2,ethernet1/3,LOG-Default,{datetime.now().strftime('%Y/%m/%d %H:%M:%S')},"
                   f"{random.randint(100000, 999999)},1,{random.randint(1024, 65535)},80,0,0,0x80004000,tcp,reset-both,"
                   f"\"SQL Injection Attack (40001)\",(40001),code-execution,critical,client-to-server",
            source_ip=fake.ipv4(),
            destination_ip=fake.ipv4_private(),
            protocol="tcp",
            destination_port=80,
            labels={"action": "reset-both", "vulnerability": "SQL Injection", "severity": "critical"},
            pattern_id="T1190_EXPLOIT_PUBLIC_APPLICATION"
        )


# === EXTENDED CISCO ASA COVERAGE ===

class CiscoASAExtendedGenerator(AuthenticLogGenerator):
    """Extended Cisco ASA coverage for comprehensive TTP mapping."""
    
    def __init__(self):
        super().__init__("Cisco", "ASA", NICECategory.NETWORK)
    
    # T1133 - External Remote Services
    def generate_vpn_brute_force_log(self) -> NetworkEvent:
        """VPN brute force attack detection."""
        return NetworkEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="VPN Authentication Failed",
            event_code="722022",
            severity=SeverityLevel.WARNING,
            message=f"%ASA-4-722022: Group <VPN_Users> User <{fake.user_name()}> "
                   f"IP <{fake.ipv4()}> Authentication failed: Reason = Invalid username or password",
            source_ip=fake.ipv4(),
            labels={"action": "auth_failed", "group": "VPN_Users", "reason": "invalid_credentials"},
            pattern_id="T1133_EXTERNAL_REMOTE_SERVICES"
        )
    
    def generate_ipsec_tunnel_established_log(self) -> NetworkEvent:
        """Successful IPSec VPN tunnel establishment."""
        return NetworkEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="IPSec Tunnel Established",
            event_code="713259",
            severity=SeverityLevel.INFO,
            message=f"%ASA-6-713259: IPSec tunnel to {fake.ipv4()} has been established. "
                   f"Tunnel Type: L2L, Group: BRANCH_OFFICE, Peer IP: {fake.ipv4()}",
            source_ip=fake.ipv4(),
            labels={"action": "tunnel_established", "tunnel_type": "L2L", "group": "BRANCH_OFFICE"},
            pattern_id="T1133_EXTERNAL_REMOTE_SERVICES"
        )
    
    # T1095 - Non-Application Layer Protocol
    def generate_custom_protocol_log(self) -> NetworkEvent:
        """Custom/unknown protocol detection."""
        return NetworkEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="Custom Protocol Detected",
            event_code="106100",
            severity=SeverityLevel.WARNING,
            message=f"%ASA-5-106100: access-list outside_access_in permitted protocol {random.randint(200, 254)} "
                   f"src outside:{fake.ipv4()}/{random.randint(1024, 65535)} "
                   f"dst inside:{fake.ipv4_private()}/{random.randint(1024, 65535)}",
            source_ip=fake.ipv4(),
            destination_ip=fake.ipv4_private(),
            protocol=f"protocol-{random.randint(200, 254)}",
            labels={"action": "permitted", "protocol_type": "custom", "suspicious": "true"},
            pattern_id="T1095_NON_APPLICATION_LAYER_PROTOCOL"
        )
    
    # T1021.001 - Remote Desktop Protocol
    def generate_rdp_connection_log(self) -> NetworkEvent:
        """RDP connection attempt."""
        return NetworkEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="RDP Connection",
            event_code="302013",
            severity=SeverityLevel.INFO,
            message=f"%ASA-6-302013: Built inbound TCP connection {random.randint(100000, 999999)} "
                   f"for outside:{fake.ipv4()}/3389 ({fake.ipv4()}/3389) to "
                   f"inside:{fake.ipv4_private()}/3389 ({fake.ipv4_private()}/3389)",
            source_ip=fake.ipv4(),
            destination_ip=fake.ipv4_private(),
            destination_port=3389,
            protocol="tcp",
            labels={"action": "connection_built", "service": "RDP", "direction": "inbound"},
            pattern_id="T1021.001_RDP"
        )
    
    # T1110 - Brute Force
    def generate_authentication_flood_log(self) -> NetworkEvent:
        """Authentication flood detection."""
        return NetworkEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="Authentication Flood",
            event_code="733100",
            severity=SeverityLevel.CRITICAL,
            message=f"%ASA-2-733100: [Authentication flood] drop rate-1 exceeded. "
                   f"Current burst rate is {random.randint(500, 1000)} per second, "
                   f"max configured rate is 50; Denying new authentications from {fake.ipv4()}",
            source_ip=fake.ipv4(),
            labels={"action": "drop", "attack_type": "authentication_flood", "rate_exceeded": "true"},
            pattern_id="T1110_BRUTE_FORCE"
        )


# === EXTENDED CROWDSTRIKE COVERAGE ===

class CrowdStrikeExtendedGenerator(AuthenticLogGenerator):
    """Extended CrowdStrike Falcon coverage for comprehensive TTP mapping."""
    
    def __init__(self):
        super().__init__("CrowdStrike", "Falcon", NICECategory.ENDPOINT)
    
    # T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
    def generate_registry_persistence_log(self) -> EndpointEvent:
        """Registry persistence mechanism detected."""
        event_data = {
            "metadata": {
                "eventType": "RegKeyActivitySummaryEvent",
                "eventCreationTime": int(datetime.now().timestamp() * 1000)
            },
            "event": {
                "RegKeyActivitySummaryEvent": {
                    "aid": f"{random.randint(100000000000000000000000000000, 999999999999999999999999999999):032x}",
                    "aip": fake.ipv4_private(),
                    "RegObjectName": "\\\\REGISTRY\\\\USER\\\\S-1-5-21-123456789-123456789-123456789-1001\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\SecurityUpdate",
                    "RegValueName": "SecurityUpdate",
                    "RegValueData": "C:\\\\Users\\\\Public\\\\svchost.exe",
                    "ProcessId": random.randint(1000, 9999),
                    "ProcessName": "\\\\Device\\\\HarddiskVolume2\\\\Windows\\\\System32\\\\reg.exe",
                    "CommandLine": "reg add \"HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\" /v SecurityUpdate /d \"C:\\\\Users\\\\Public\\\\svchost.exe\" /f",
                    "ComputerName": fake.hostname().upper(),
                    "UserName": f"{fake.hostname()}\\\\{fake.user_name()}"
                }
            }
        }
        
        return EndpointEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="RegKeyActivitySummaryEvent",
            event_code="RegKeyActivitySummaryEvent",
            severity=SeverityLevel.WARNING,
            message=json.dumps(event_data),
            source_ip=fake.ipv4_private(),
            labels={"tactic": "Persistence", "technique": "T1547.001", "registry_key": "Run"},
            process_name="reg.exe",
            command_line=event_data["event"]["RegKeyActivitySummaryEvent"]["CommandLine"],
            registry_key="HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run",
            registry_value="SecurityUpdate",
            pattern_id="T1547.001_REGISTRY_RUN_KEYS"
        )
    
    # T1543.003 - Create or Modify System Process: Windows Service
    def generate_service_creation_log(self) -> EndpointEvent:
        """Windows service creation for persistence."""
        event_data = {
            "metadata": {
                "eventType": "ServiceControlManagerEvent",
                "eventCreationTime": int(datetime.now().timestamp() * 1000)
            },
            "event": {
                "ServiceControlManagerEvent": {
                    "aid": f"{random.randint(100000000000000000000000000000, 999999999999999999999999999999):032x}",
                    "aip": fake.ipv4_private(),
                    "ServiceName": "WindowsUpdateService",
                    "ServiceDisplayName": "Windows Update Service",
                    "ServiceType": "SERVICE_WIN32_OWN_PROCESS",
                    "StartType": "SERVICE_AUTO_START",
                    "ServiceImagePath": "C:\\\\Windows\\\\System32\\\\svchost.exe -k netsvcs -p",
                    "ProcessId": random.randint(1000, 9999),
                    "CommandLine": "sc create WindowsUpdateService binPath=\"C:\\\\Windows\\\\System32\\\\svchost.exe -k netsvcs -p\" start=auto",
                    "ComputerName": fake.hostname().upper(),
                    "Action": "ServiceInstalled"
                }
            }
        }
        
        return EndpointEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="ServiceControlManagerEvent",
            event_code="ServiceInstalled",
            severity=SeverityLevel.WARNING,
            message=json.dumps(event_data),
            source_ip=fake.ipv4_private(),
            labels={"tactic": "Persistence", "technique": "T1543.003", "service_type": "malicious"},
            process_name="sc.exe",
            command_line=event_data["event"]["ServiceControlManagerEvent"]["CommandLine"],
            service_name="WindowsUpdateService",
            pattern_id="T1543.003_SERVICE_CREATION"
        )
    
    # T1055.012 - Process Injection: Process Hollowing
    def generate_process_hollowing_log(self) -> EndpointEvent:
        """Process hollowing detection."""
        event_data = {
            "metadata": {
                "eventType": "ProcessHollowingEvent",
                "eventCreationTime": int(datetime.now().timestamp() * 1000)
            },
            "event": {
                "ProcessHollowingEvent": {
                    "aid": f"{random.randint(100000000000000000000000000000, 999999999999999999999999999999):032x}",
                    "aip": fake.ipv4_private(),
                    "TargetProcessId": random.randint(1000, 9999),
                    "TargetProcessName": "\\\\Device\\\\HarddiskVolume2\\\\Windows\\\\System32\\\\notepad.exe",
                    "InjectorProcessId": random.randint(5000, 9999),
                    "InjectorProcessName": "\\\\Device\\\\HarddiskVolume2\\\\Users\\\\victim\\\\Desktop\\\\malware.exe",
                    "InjectionTechnique": "ProcessHollowing",
                    "InjectedCodeHash": f"{random.randint(10**63, 10**64-1):064x}",
                    "ComputerName": fake.hostname().upper(),
                    "DetectionConfidence": 95
                }
            }
        }
        
        return EndpointEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="ProcessHollowingEvent",
            event_code="ProcessHollowing",
            severity=SeverityLevel.CRITICAL,
            message=json.dumps(event_data),
            source_ip=fake.ipv4_private(),
            labels={"tactic": "Defense Evasion", "technique": "T1055.012", "confidence": "95"},
            process_name="malware.exe",
            process_id=event_data["event"]["ProcessHollowingEvent"]["InjectorProcessId"],
            pattern_id="T1055.012_PROCESS_HOLLOWING"
        )
    
    # T1003.001 - OS Credential Dumping: LSASS Memory
    def generate_lsass_access_log(self) -> EndpointEvent:
        """LSASS memory access detection."""
        event_data = {
            "metadata": {
                "eventType": "ProcessAccessEvent",
                "eventCreationTime": int(datetime.now().timestamp() * 1000)
            },
            "event": {
                "ProcessAccessEvent": {
                    "aid": f"{random.randint(100000000000000000000000000000, 999999999999999999999999999999):032x}",
                    "aip": fake.ipv4_private(),
                    "SourceProcessId": random.randint(1000, 9999),
                    "SourceProcessName": "\\\\Device\\\\HarddiskVolume2\\\\Windows\\\\System32\\\\taskmgr.exe",
                    "TargetProcessId": random.randint(500, 999),
                    "TargetProcessName": "\\\\Device\\\\HarddiskVolume2\\\\Windows\\\\System32\\\\lsass.exe",
                    "DesiredAccess": "0x1FFFFF",
                    "GrantedAccess": "0x1FFFFF",
                    "ComputerName": fake.hostname().upper(),
                    "SuspiciousActivity": "LSASS_MEMORY_ACCESS"
                }
            }
        }
        
        return EndpointEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="ProcessAccessEvent",
            event_code="LSASS_ACCESS",
            severity=SeverityLevel.CRITICAL,
            message=json.dumps(event_data),
            source_ip=fake.ipv4_private(),
            labels={"tactic": "Credential Access", "technique": "T1003.001", "target": "lsass.exe"},
            process_name="taskmgr.exe",
            process_id=event_data["event"]["ProcessAccessEvent"]["SourceProcessId"],
            pattern_id="T1003.001_LSASS_MEMORY"
        )
    
    # T1082 - System Information Discovery
    def generate_system_info_discovery_log(self) -> EndpointEvent:
        """System information discovery commands."""
        commands = [
            "systeminfo", "whoami /all", "net config workstation", 
            "wmic computersystem get domain,model,manufacturer,name,systemtype"
        ]
        
        event_data = {
            "metadata": {
                "eventType": "ProcessRollup2",
                "eventCreationTime": int(datetime.now().timestamp() * 1000)
            },
            "event": {
                "ProcessRollup2": {
                    "aid": f"{random.randint(100000000000000000000000000000, 999999999999999999999999999999):032x}",
                    "aip": fake.ipv4_private(),
                    "CommandLine": random.choice(commands),
                    "ComputerName": fake.hostname().upper(),
                    "ProcessId": random.randint(1000, 9999),
                    "ParentProcessId": random.randint(500, 999),
                    "FileName": "cmd.exe",
                    "FilePath": "\\\\Device\\\\HarddiskVolume2\\\\Windows\\\\System32\\\\cmd.exe",
                    "UserName": f"{fake.hostname()}\\\\{fake.user_name()}"
                }
            }
        }
        
        return EndpointEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="ProcessRollup2",
            event_code="ProcessRollup2",
            severity=SeverityLevel.INFO,
            message=json.dumps(event_data),
            source_ip=fake.ipv4_private(),
            labels={"tactic": "Discovery", "technique": "T1082", "command_type": "system_info"},
            process_name="cmd.exe",
            command_line=event_data["event"]["ProcessRollup2"]["CommandLine"],
            pattern_id="T1082_SYSTEM_INFORMATION_DISCOVERY"
        )


# === EXTENDED OKTA COVERAGE ===

class OktaExtendedGenerator(AuthenticLogGenerator):
    """Extended Okta coverage for comprehensive TTP mapping."""
    
    def __init__(self):
        super().__init__("Okta", "System Log", NICECategory.IDENTITY)
    
    # T1556.006 - Modify Authentication Process: Multi-Factor Authentication
    def generate_mfa_bypass_attempt_log(self) -> IdentityEvent:
        """MFA bypass attempt detection."""
        event_data = {
            "uuid": fake.uuid4(),
            "published": datetime.now(timezone.utc).isoformat(),
            "eventType": "user.mfa.attempt_bypass",
            "version": "0",
            "severity": "WARN",
            "displayMessage": "User attempted to bypass MFA",
            "actor": {
                "id": fake.uuid4(),
                "type": "User",
                "alternateId": f"{fake.user_name()}@company.com",
                "displayName": fake.name()
            },
            "client": {
                "userAgent": {
                    "rawUserAgent": "Mozilla/5.0 (compatible; automated-tool/1.0)",
                    "os": "Unknown",
                    "browser": "UNKNOWN"
                },
                "ipAddress": fake.ipv4(),
                "device": "Unknown"
            },
            "outcome": {
                "result": "FAILURE",
                "reason": "MFA bypass attempt blocked"
            },
            "debugContext": {
                "debugData": {
                    "bypassMethod": "remember_device_manipulation",
                    "suspiciousActivity": "true",
                    "riskScore": "HIGH"
                }
            }
        }
        
        return IdentityEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="user.mfa.attempt_bypass",
            event_code="FAILURE",
            severity=SeverityLevel.CRITICAL,
            message=json.dumps(event_data),
            source_ip=fake.ipv4(),
            labels={"bypass_method": "remember_device", "risk_score": "HIGH", "blocked": "true"},
            risk_score=9.2,
            pattern_id="T1556.006_MFA_BYPASS"
        )
    
    # T1078.004 - Valid Accounts: Cloud Accounts
    def generate_impossible_travel_log(self) -> IdentityEvent:
        """Impossible travel detection."""
        locations = [
            ("Moscow", "Russia", 55.7558, 37.6173),
            ("Beijing", "China", 39.9042, 116.4074),
            ("Tehran", "Iran", 35.6892, 51.3890)
        ]
        city, country, lat, lon = random.choice(locations)
        
        event_data = {
            "uuid": fake.uuid4(),
            "published": datetime.now(timezone.utc).isoformat(),
            "eventType": "security.threat.detected",
            "version": "0",
            "severity": "WARN",
            "displayMessage": f"Impossible travel detected: {city}, {country}",
            "actor": {
                "id": fake.uuid4(),
                "type": "User",
                "alternateId": f"{fake.user_name()}@company.com"
            },
            "client": {
                "ipAddress": fake.ipv4(),
                "geographicalContext": {
                    "city": city,
                    "country": country,
                    "geolocation": {"lat": lat, "lon": lon}
                }
            },
            "outcome": {"result": "SUCCESS"},
            "debugContext": {
                "debugData": {
                    "threatDetected": "Impossible Travel",
                    "previousLocation": "New York, United States",
                    "timespan": "2 hours",
                    "distanceKm": random.randint(8000, 15000)
                }
            }
        }
        
        return IdentityEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="security.threat.detected",
            event_code="IMPOSSIBLE_TRAVEL",
            severity=SeverityLevel.CRITICAL,
            message=json.dumps(event_data),
            source_ip=fake.ipv4(),
            labels={"threat_type": "impossible_travel", "country": country, "distance_km": str(event_data["debugContext"]["debugData"]["distanceKm"])},
            risk_score=9.5,
            pattern_id="T1078.004_VALID_ACCOUNTS_CLOUD"
        )
    
    # T1110.001 - Brute Force: Password Guessing
    def generate_password_spray_log(self) -> IdentityEvent:
        """Password spray attack detection."""
        event_data = {
            "uuid": fake.uuid4(),
            "published": datetime.now(timezone.utc).isoformat(),
            "eventType": "security.attack.detected",
            "version": "0",
            "severity": "HIGH",
            "displayMessage": "Password spray attack detected",
            "client": {
                "ipAddress": fake.ipv4(),
                "userAgent": {"rawUserAgent": "Mozilla/5.0 (compatible; password-spray-tool)"}
            },
            "outcome": {"result": "BLOCKED"},
            "debugContext": {
                "debugData": {
                    "attackType": "password_spray",
                    "targetAccounts": random.randint(50, 200),
                    "timeWindow": "300 seconds",
                    "uniquePasswords": random.randint(3, 10)
                }
            }
        }
        
        return IdentityEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="security.attack.detected",
            event_code="PASSWORD_SPRAY",
            severity=SeverityLevel.CRITICAL,
            message=json.dumps(event_data),
            source_ip=fake.ipv4(),
            labels={"attack_type": "password_spray", "target_accounts": str(event_data["debugContext"]["debugData"]["targetAccounts"])},
            risk_score=9.0,
            pattern_id="T1110.001_PASSWORD_GUESSING"
        )


# === COMPREHENSIVE TTP MAPPINGS ===

COMPREHENSIVE_TTP_MAPPINGS = {
    # Network-based TTPs
    "T1071.001_WEB_PROTOCOLS": {
        "Palo Alto Networks": [
            "generate_traffic_log_allowed", "generate_url_filtering_log", 
            "generate_web_tunnel_log"
        ]
    },
    "T1071.004_DNS": {
        "Palo Alto Networks": ["generate_dns_tunneling_log"]
    },
    "T1095_NON_APPLICATION_LAYER_PROTOCOL": {
        "Cisco ASA": ["generate_custom_protocol_log"]
    },
    
    # Initial Access
    "T1133_EXTERNAL_REMOTE_SERVICES": {
        "Cisco ASA": [
            "generate_vpn_brute_force_log", "generate_ipsec_tunnel_established_log"
        ]
    },
    "T1190_EXPLOIT_PUBLIC_APPLICATION": {
        "Palo Alto Networks": ["generate_web_exploit_log"]
    },
    "T1566.001_PHISHING_ATTACHMENT": {
        "Palo Alto Networks": ["generate_threat_log_malware", "generate_malware_download_log"]
    },
    
    # Execution
    "T1059.001_POWERSHELL": {
        "CrowdStrike": ["generate_process_creation_log"],
        "SentinelOne": ["generate_threat_detection_log"]
    },
    
    # Persistence
    "T1543.003_SERVICE_CREATION": {
        "CrowdStrike": ["generate_service_creation_log"]
    },
    "T1547.001_REGISTRY_RUN_KEYS": {
        "CrowdStrike": ["generate_registry_persistence_log"]
    },
    
    # Defense Evasion
    "T1055.012_PROCESS_HOLLOWING": {
        "CrowdStrike": ["generate_process_hollowing_log"]
    },
    
    # Credential Access
    "T1003.001_LSASS_MEMORY": {
        "CrowdStrike": ["generate_lsass_access_log"]
    },
    "T1110_BRUTE_FORCE": {
        "Cisco ASA": ["generate_authentication_flood_log"]
    },
    "T1110.001_PASSWORD_GUESSING": {
        "Okta": ["generate_password_spray_log"]
    },
    "T1556.006_MFA_BYPASS": {
        "Okta": ["generate_mfa_bypass_attempt_log"]
    },
    
    # Discovery
    "T1046_NETWORK_SERVICE_SCANNING": {
        "Palo Alto Networks": ["generate_port_scan_detection_log"],
        "Cisco ASA": ["generate_connection_denied_log", "generate_threat_detection_log"]
    },
    "T1082_SYSTEM_INFORMATION_DISCOVERY": {
        "CrowdStrike": ["generate_system_info_discovery_log"]
    },
    
    # Lateral Movement
    "T1021.001_RDP": {
        "Cisco ASA": ["generate_rdp_connection_log"]
    },
    
    # Collection & Exfiltration
    "T1078.004_VALID_ACCOUNTS_CLOUD": {
        "Okta": [
            "generate_user_authentication_log", "generate_suspicious_activity_log",
            "generate_impossible_travel_log"
        ]
    }
}

# Extended vendor generators registry
COMPREHENSIVE_VENDOR_GENERATORS = {
    "Palo Alto Networks": PaloAltoExtendedGenerator,
    "Cisco ASA": CiscoASAExtendedGenerator,
    "CrowdStrike": CrowdStrikeExtendedGenerator,
    "Okta": OktaExtendedGenerator,
}


def generate_comprehensive_ttp_logs(ttp_id: str, vendor: str, count: int = 3) -> List[BaseEvent]:
    """Generate comprehensive logs for a specific TTP and vendor combination."""
    if ttp_id not in COMPREHENSIVE_TTP_MAPPINGS:
        raise ValueError(f"TTP {ttp_id} not supported in comprehensive mappings")
    
    if vendor not in COMPREHENSIVE_TTP_MAPPINGS[ttp_id]:
        raise ValueError(f"Vendor {vendor} not mapped for TTP {ttp_id}")
    
    if vendor not in COMPREHENSIVE_VENDOR_GENERATORS:
        raise ValueError(f"Comprehensive vendor generator for {vendor} not found")
    
    generator = COMPREHENSIVE_VENDOR_GENERATORS[vendor]()
    methods = COMPREHENSIVE_TTP_MAPPINGS[ttp_id][vendor]
    
    events = []
    for _ in range(count):
        method_name = random.choice(methods)
        if hasattr(generator, method_name):
            event = getattr(generator, method_name)()
            events.append(event)
    
    return events


def get_comprehensive_ttp_coverage() -> Dict[str, List[str]]:
    """Get comprehensive TTP coverage mapping."""
    return {
        ttp_id: list(vendors.keys())
        for ttp_id, vendors in COMPREHENSIVE_TTP_MAPPINGS.items()
    }


def get_attack_chain_scenario(attack_chain: str) -> List[Dict[str, Any]]:
    """Generate a complete attack chain scenario with multiple TTPs."""
    attack_chains = {
        "APT29_CLOUD_COMPROMISE": [
            {"ttp": "T1566.001_PHISHING_ATTACHMENT", "vendor": "Palo Alto Networks", "stage": "Initial Access"},
            {"ttp": "T1059.001_POWERSHELL", "vendor": "CrowdStrike", "stage": "Execution"},
            {"ttp": "T1547.001_REGISTRY_RUN_KEYS", "vendor": "CrowdStrike", "stage": "Persistence"},
            {"ttp": "T1003.001_LSASS_MEMORY", "vendor": "CrowdStrike", "stage": "Credential Access"},
            {"ttp": "T1078.004_VALID_ACCOUNTS_CLOUD", "vendor": "Okta", "stage": "Lateral Movement"},
            {"ttp": "T1071.004_DNS", "vendor": "Palo Alto Networks", "stage": "Exfiltration"}
        ],
        "INSIDER_THREAT": [
            {"ttp": "T1078.004_VALID_ACCOUNTS_CLOUD", "vendor": "Okta", "stage": "Initial Access"},
            {"ttp": "T1082_SYSTEM_INFORMATION_DISCOVERY", "vendor": "CrowdStrike", "stage": "Discovery"},
            {"ttp": "T1543.003_SERVICE_CREATION", "vendor": "CrowdStrike", "stage": "Persistence"},
            {"ttp": "T1071.001_WEB_PROTOCOLS", "vendor": "Palo Alto Networks", "stage": "Exfiltration"}
        ],
        "EXTERNAL_RECONNAISSANCE": [
            {"ttp": "T1046_NETWORK_SERVICE_SCANNING", "vendor": "Palo Alto Networks", "stage": "Reconnaissance"},
            {"ttp": "T1190_EXPLOIT_PUBLIC_APPLICATION", "vendor": "Palo Alto Networks", "stage": "Initial Access"},
            {"ttp": "T1133_EXTERNAL_REMOTE_SERVICES", "vendor": "Cisco ASA", "stage": "Persistence"},
            {"ttp": "T1021.001_RDP", "vendor": "Cisco ASA", "stage": "Lateral Movement"}
        ]
    }
    
    return attack_chains.get(attack_chain, [])