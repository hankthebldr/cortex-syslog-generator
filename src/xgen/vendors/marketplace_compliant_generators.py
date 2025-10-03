"""
Marketplace-Compliant Log Format Generator

This module generates logs that are fully compatible with Cortex Marketplace
parsing rules, XDM schema requirements, and Broker VM applet expectations.
All logs are formatted to match exact marketplace specifications for optimal
parsing accuracy and field population.
"""

import json
import random
import re
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Union
from faker import Faker

from ..core.models import BaseEvent, EndpointEvent, NetworkEvent, IdentityEvent, CloudEvent
from ..core.models import NICECategory, SeverityLevel

fake = Faker()


class MarketplaceCompliantGenerator:
    """Base class for marketplace-compliant log generation."""
    
    def __init__(self, vendor: str, product: str, version: str = "1.0"):
        self.vendor = vendor
        self.product = product
        self.version = version
        self.facility = 16  # Local0 facility for security logs
        
    def _generate_syslog_header(self, severity: int = 6, timestamp: Optional[datetime] = None) -> str:
        """Generate RFC 3164 compliant syslog header."""
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)
        
        priority = self.facility * 8 + severity
        timestamp_str = timestamp.strftime("%b %d %H:%M:%S")
        hostname = fake.hostname()
        
        return f"<{priority}>{timestamp_str} {hostname}"
    
    def _generate_cef_header(self, event_id: str, name: str, severity: int) -> str:
        """Generate CEF header compliant with marketplace standards."""
        return f"CEF:0|{self.vendor}|{self.product}|{self.version}|{event_id}|{name}|{severity}"
    
    def _format_timestamp_iso8601(self, timestamp: Optional[datetime] = None) -> str:
        """Generate ISO 8601 timestamp for XDM compatibility."""
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)
        return timestamp.isoformat().replace('+00:00', 'Z')
    
    def _format_timestamp_epoch(self, timestamp: Optional[datetime] = None) -> int:
        """Generate epoch timestamp for XDM compatibility."""
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)
        return int(timestamp.timestamp() * 1000)  # Milliseconds
    
    def _generate_realistic_user_context(self) -> Dict[str, str]:
        """Generate realistic user context for XDM mapping."""
        username = fake.user_name()
        domain = fake.domain_word().upper()
        
        return {
            "username": username,
            "domain": domain,
            "upn": f"{username}@{domain.lower()}.com",
            "sid": f"S-1-5-21-{random.randint(1000000000, 9999999999)}-{random.randint(1000000000, 9999999999)}-{random.randint(1000000000, 9999999999)}-{random.randint(1000, 9999)}"
        }
    
    def _generate_realistic_asset_context(self) -> Dict[str, Any]:
        """Generate realistic asset context for XDM mapping."""
        hostname = fake.hostname()
        
        return {
            "hostname": hostname.upper(),
            "domain": f"{fake.domain_word()}.local",
            "os_family": random.choice(["WINDOWS", "LINUX", "MACOS"]),
            "ipv4": fake.ipv4_private(),
            "mac": fake.mac_address()
        }


# === PALO ALTO NETWORKS MARKETPLACE COMPLIANT ===

class PaloAltoMarketplaceGenerator(MarketplaceCompliantGenerator):
    """Palo Alto Networks logs compliant with marketplace parsing rules."""
    
    def __init__(self):
        super().__init__("Palo Alto Networks", "PAN-OS", "10.1.0")
    
    def generate_traffic_log_cef(self) -> NetworkEvent:
        """PAN-OS traffic log in CEF format for marketplace compliance."""
        timestamp = datetime.now(timezone.utc)
        src_ip = fake.ipv4_private()
        dst_ip = fake.ipv4()
        src_port = random.randint(49152, 65535)
        dst_port = random.choice([80, 443, 8080])
        session_id = random.randint(100000, 999999)
        
        # CEF extension fields matching marketplace parser expectations
        cef_extensions = [
            f"rt={self._format_timestamp_epoch(timestamp)}",
            f"src={src_ip}",
            f"dst={dst_ip}",
            f"spt={src_port}",
            f"dpt={dst_port}",
            f"proto=TCP",
            f"act=allow",
            f"app=web-browsing",
            f"cs1Label=Rule",
            f"cs1=Allow-Web-Traffic",
            f"cs2Label=SourceZone", 
            f"cs2=Trust",
            f"cs3Label=DestinationZone",
            f"cs3=Untrust",
            f"cn1Label=SessionID",
            f"cn1={session_id}",
            f"in={random.randint(1000, 10000)}",
            f"out={random.randint(500, 5000)}",
            f"cs4Label=VirtualSystem",
            f"cs4=vsys1"
        ]
        
        syslog_header = self._generate_syslog_header(6, timestamp)
        cef_header = self._generate_cef_header("TRAFFIC", "Traffic allowed", 6)
        cef_message = f"{syslog_header} {cef_header}|{' '.join(cef_extensions)}"
        
        return NetworkEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="TRAFFIC",
            event_code="TRAFFIC",
            severity=SeverityLevel.INFO,
            message=cef_message,
            source_ip=src_ip,
            destination_ip=dst_ip,
            source_port=src_port,
            destination_port=dst_port,
            protocol="TCP",
            direction="outbound",
            labels={
                "action": "allow",
                "rule": "Allow-Web-Traffic",
                "application": "web-browsing",
                "session_id": str(session_id),
                "format": "CEF"
            },
            bytes_in=random.randint(1000, 10000),
            bytes_out=random.randint(500, 5000),
            pattern_id="T1071.001_WEB_PROTOCOLS"
        )
    
    def generate_threat_log_cef(self) -> NetworkEvent:
        """PAN-OS threat log in CEF format for marketplace compliance."""
        timestamp = datetime.now(timezone.utc)
        src_ip = fake.ipv4_private()
        dst_ip = fake.ipv4()
        threat_name = random.choice([
            "Win32/Emotet.Variant",
            "Backdoor:Win32/CobaltStrike",
            "Trojan:JS/Phish.Generic",
            "Exploit:CVE-2021-44228"
        ])
        
        cef_extensions = [
            f"rt={self._format_timestamp_epoch(timestamp)}",
            f"src={src_ip}",
            f"dst={dst_ip}",
            f"spt={random.randint(49152, 65535)}",
            f"dpt=443",
            f"proto=TCP",
            f"act=block-url",
            f"app=ssl",
            f"cs1Label=Rule",
            f"cs1=Block-Malware",
            f"cs2Label=ThreatName",
            f"cs2={threat_name}",
            f"cs3Label=ThreatCategory",
            f"cs3=malware",
            f"cn1Label=ThreatID",
            f"cn1={random.randint(40000, 50000)}",
            f"cs4Label=Direction",
            f"cs4=client-to-server",
            f"cs5Label=URLCategory",
            f"cs5=malware"
        ]
        
        syslog_header = self._generate_syslog_header(2, timestamp)  # Critical severity
        cef_header = self._generate_cef_header("THREAT", "Malware detected", 2)
        cef_message = f"{syslog_header} {cef_header}|{' '.join(cef_extensions)}"
        
        return NetworkEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="THREAT",
            event_code="THREAT",
            severity=SeverityLevel.CRITICAL,
            message=cef_message,
            source_ip=src_ip,
            destination_ip=dst_ip,
            protocol="TCP",
            destination_port=443,
            direction="outbound",
            labels={
                "action": "block-url",
                "threat_name": threat_name,
                "threat_category": "malware",
                "format": "CEF"
            },
            pattern_id="T1566.001_PHISHING_ATTACHMENT"
        )
    
    def generate_csv_log_format(self) -> NetworkEvent:
        """PAN-OS CSV format matching exact marketplace parser expectations."""
        timestamp = datetime.now(timezone.utc)
        timestamp_str = timestamp.strftime("%Y/%m/%d %H:%M:%S")
        
        # CSV fields in exact order expected by marketplace parser
        csv_fields = [
            "FUTURE_USE",  # future_use1
            timestamp_str,  # receive_time
            f"01{random.randint(1000000000, 9999999999)}",  # serial_num
            "TRAFFIC",  # type
            "",  # threat_content_type (empty for traffic logs)
            "1",  # config_ver
            timestamp_str,  # time_generated
            fake.ipv4_private(),  # src
            fake.ipv4(),  # dst
            fake.ipv4_private(),  # natsrc
            fake.ipv4(),  # natdst
            "Allow-Web-Traffic",  # rule
            fake.user_name(),  # srcuser
            "",  # dstuser
            "web-browsing",  # app
            "vsys1",  # vsys
            "Trust",  # from
            "Untrust",  # to
            "ethernet1/1",  # inbound_if
            "ethernet1/2",  # outbound_if
            "default",  # logset
            timestamp_str,  # time_logged
            str(random.randint(100000, 999999)),  # sessionid
            "1",  # repeatcnt
            str(random.randint(49152, 65535)),  # sport
            "443",  # dport
            "0",  # natsport
            "0",  # natdport
            "0x19",  # flags
            "tcp",  # proto
            "allow",  # action
            str(random.randint(1000, 10000)),  # bytes
            str(random.randint(500, 5000)),  # bytes_sent
            str(random.randint(500, 5000)),  # bytes_received
            str(random.randint(10, 100)),  # packets
            timestamp_str,  # start_time
            "30",  # elapsed_time
            "low-risk",  # category
            str(random.randint(1000000, 9999999)),  # seqno
            "0x8000000000000000",  # actionflags
            "US",  # srcloc
            "Reserved"  # dstloc
        ]
        
        csv_message = ",".join(csv_fields)
        
        return NetworkEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="TRAFFIC",
            event_code="TRAFFIC",
            severity=SeverityLevel.INFO,
            message=csv_message,
            source_ip=csv_fields[7],  # src
            destination_ip=csv_fields[8],  # dst
            source_port=int(csv_fields[24]),  # sport
            destination_port=int(csv_fields[25]),  # dport
            protocol="tcp",
            direction="outbound",
            labels={
                "action": "allow",
                "rule": "Allow-Web-Traffic",
                "application": "web-browsing",
                "format": "CSV"
            },
            pattern_id="T1071.001_WEB_PROTOCOLS"
        )


# === CISCO ASA MARKETPLACE COMPLIANT ===

class CiscoASAMarketplaceGenerator(MarketplaceCompliantGenerator):
    """Cisco ASA logs compliant with marketplace parsing rules."""
    
    def __init__(self):
        super().__init__("Cisco", "ASA", "9.14")
    
    def generate_connection_log(self) -> NetworkEvent:
        """ASA connection log matching marketplace regex patterns."""
        timestamp = datetime.now(timezone.utc)
        src_ip = fake.ipv4()
        dst_ip = fake.ipv4_private()
        message_id = "106023"
        
        # ASA message format matching marketplace parser regex
        asa_message = (
            f"%ASA-4-{message_id}: Deny tcp src outside:{src_ip}/{random.choice([80, 443])} "
            f"dst inside:{dst_ip}/{random.randint(1024, 65535)} by access-group \"outside_access_in\" "
            f"[0x{random.randint(10000000, 99999999):08x}, 0x0]"
        )
        
        syslog_header = self._generate_syslog_header(4, timestamp)
        full_message = f"{syslog_header} {asa_message}"
        
        return NetworkEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="Connection Denied",
            event_code=message_id,
            severity=SeverityLevel.WARNING,
            message=full_message,
            source_ip=src_ip,
            destination_ip=dst_ip,
            protocol="tcp",
            direction="inbound",
            labels={
                "action": "deny",
                "reason": "access-group",
                "rule": "outside_access_in",
                "message_id": message_id,
                "format": "syslog"
            },
            pattern_id="T1046_NETWORK_SERVICE_SCANNING"
        )
    
    def generate_vpn_log(self) -> NetworkEvent:
        """ASA VPN log matching marketplace authentication patterns."""
        timestamp = datetime.now(timezone.utc)
        username = fake.user_name()
        user_ip = fake.ipv4()
        assigned_ip = fake.ipv4_private()
        
        asa_message = (
            f"%ASA-6-722051: Group <VPN_Users> User <{username}> "
            f"IP <{user_ip}> IPv4 Address <{assigned_ip}> IPv6 address <::> assigned to session"
        )
        
        syslog_header = self._generate_syslog_header(6, timestamp)
        full_message = f"{syslog_header} {asa_message}"
        
        return NetworkEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="VPN Session Established",
            event_code="722051",
            severity=SeverityLevel.INFO,
            message=full_message,
            source_ip=user_ip,
            labels={
                "action": "vpn_connect",
                "username": username,
                "group": "VPN_Users",
                "assigned_ip": assigned_ip,
                "format": "syslog"
            },
            pattern_id="T1133_EXTERNAL_REMOTE_SERVICES"
        )


# === CROWDSTRIKE MARKETPLACE COMPLIANT ===

class CrowdStrikeMarketplaceGenerator(MarketplaceCompliantGenerator):
    """CrowdStrike Falcon logs compliant with marketplace JSON parsing."""
    
    def __init__(self):
        super().__init__("CrowdStrike", "Falcon", "7.10")
    
    def generate_process_event_json(self) -> EndpointEvent:
        """CrowdStrike ProcessRollup2 event matching marketplace JSON schema."""
        timestamp = datetime.now(timezone.utc)
        aid = f"{random.randint(100000000000000000000000000000, 999999999999999999999999999999):032x}"
        cid = f"{random.randint(100000000000000000000000000000, 999999999999999999999999999999):032x}"
        user_context = self._generate_realistic_user_context()
        asset_context = self._generate_realistic_asset_context()
        
        # JSON structure matching exact marketplace parser expectations
        falcon_event = {
            "metadata": {
                "eventType": "ProcessRollup2",
                "eventCreationTime": self._format_timestamp_epoch(timestamp),
                "offset": random.randint(1000000, 9999999),
                "customerIDString": cid,
                "version": "1.0"
            },
            "event": {
                "ProcessRollup2": {
                    "aid": aid,
                    "aip": asset_context["ipv4"],
                    "CommandLine": "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQA",
                    "ComputerName": asset_context["hostname"],
                    "ProcessId": random.randint(1000, 9999),
                    "ParentProcessId": random.randint(500, 999),
                    "ProcessStartTime": self._format_timestamp_epoch(timestamp - timedelta(seconds=random.randint(1, 300))),
                    "SHA256HashData": f"{random.randint(10**63, 10**64-1):064x}",
                    "FileName": "powershell.exe",
                    "FilePath": "\\Device\\HarddiskVolume2\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "UserName": f"{user_context['domain']}\\{user_context['username']}",
                    "UserSid": user_context["sid"],
                    "ImageFileName": "\\Device\\HarddiskVolume2\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "RawProcessId": random.randint(1000, 9999),
                    "ProcessSxsFlags": 64,
                    "ProcessCreateFlags": 0,
                    "MD5HashData": fake.md5(),
                    "AuthenticationId": random.randint(100000, 999999)
                }
            }
        }
        
        json_message = json.dumps(falcon_event, separators=(',', ':'))
        
        return EndpointEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="ProcessRollup2",
            event_code="ProcessRollup2",
            severity=SeverityLevel.WARNING,
            message=json_message,
            source_ip=asset_context["ipv4"],
            labels={
                "aid": aid,
                "cid": cid,
                "tactic": "Execution",
                "technique": "T1059.001",
                "format": "JSON"
            },
            process_name="powershell.exe",
            process_id=falcon_event["event"]["ProcessRollup2"]["ProcessId"],
            parent_process_id=falcon_event["event"]["ProcessRollup2"]["ParentProcessId"],
            command_line=falcon_event["event"]["ProcessRollup2"]["CommandLine"],
            file_path=falcon_event["event"]["ProcessRollup2"]["FilePath"],
            process_sha256=falcon_event["event"]["ProcessRollup2"]["SHA256HashData"],
            pattern_id="T1059.001_POWERSHELL"
        )


# === OKTA MARKETPLACE COMPLIANT ===

class OktaMarketplaceGenerator(MarketplaceCompliantGenerator):
    """Okta System Log compliant with marketplace JSON parsing."""
    
    def __init__(self):
        super().__init__("Okta", "System Log", "2023.10.1")
    
    def generate_authentication_event_json(self) -> IdentityEvent:
        """Okta authentication event matching marketplace JSON schema."""
        timestamp = datetime.now(timezone.utc)
        user_context = self._generate_realistic_user_context()
        
        # JSON structure matching exact marketplace parser expectations
        okta_event = {
            "uuid": fake.uuid4(),
            "published": self._format_timestamp_iso8601(timestamp),
            "eventType": "user.authentication.sso",
            "version": "0",
            "severity": "INFO",
            "legacyEventType": "core.user_auth.login_success",
            "displayMessage": "Authentication of user via SSO",
            "actor": {
                "id": fake.uuid4(),
                "type": "User",
                "alternateId": user_context["upn"],
                "displayName": fake.name(),
                "detailEntry": None
            },
            "client": {
                "userAgent": {
                    "rawUserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
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
                    "alternateId": user_context["upn"],
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
                "externalSessionId": fake.uuid4(),
                "interface": "Okta Dashboard",
                "issuer": None
            },
            "securityContext": {
                "asNumber": random.randint(1000, 99999),
                "asOrg": fake.company(),
                "isp": fake.company() + " ISP",
                "domain": fake.domain_name(),
                "isProxy": False
            }
        }
        
        json_message = json.dumps(okta_event, separators=(',', ':'))
        
        return IdentityEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="user.authentication.sso",
            event_code="SUCCESS",
            severity=SeverityLevel.INFO,
            message=json_message,
            source_ip=okta_event["client"]["ipAddress"],
            labels={
                "event_type": "user.authentication.sso",
                "result": "SUCCESS",
                "authentication_provider": "OKTA_AUTHENTICATION_PROVIDER",
                "format": "JSON"
            },
            auth_method="SSO",
            session_id=okta_event["authenticationContext"]["externalSessionId"],
            application="Okta Dashboard",
            resource=user_context["upn"],
            pattern_id="T1078.004_VALID_ACCOUNTS_CLOUD"
        )


# === MARKETPLACE COMPLIANT GENERATOR REGISTRY ===

MARKETPLACE_COMPLIANT_GENERATORS = {
    "Palo Alto Networks": PaloAltoMarketplaceGenerator,
    "Cisco ASA": CiscoASAMarketplaceGenerator,
    "CrowdStrike": CrowdStrikeMarketplaceGenerator,
    "Okta": OktaMarketplaceGenerator,
}

# Format-specific generator methods
MARKETPLACE_FORMAT_METHODS = {
    "Palo Alto Networks": {
        "CEF": ["generate_traffic_log_cef", "generate_threat_log_cef"],
        "CSV": ["generate_csv_log_format"]
    },
    "Cisco ASA": {
        "Syslog": ["generate_connection_log", "generate_vpn_log"]
    },
    "CrowdStrike": {
        "JSON": ["generate_process_event_json"]
    },
    "Okta": {
        "JSON": ["generate_authentication_event_json"]
    }
}


def generate_marketplace_compliant_logs(vendor: str, format_type: str = "CEF", count: int = 5) -> List[BaseEvent]:
    """Generate marketplace-compliant logs for a specific vendor and format."""
    if vendor not in MARKETPLACE_COMPLIANT_GENERATORS:
        raise ValueError(f"Vendor {vendor} not supported for marketplace-compliant generation")
    
    if format_type not in MARKETPLACE_FORMAT_METHODS.get(vendor, {}):
        available_formats = list(MARKETPLACE_FORMAT_METHODS.get(vendor, {}).keys())
        raise ValueError(f"Format {format_type} not supported for {vendor}. Available: {available_formats}")
    
    generator = MARKETPLACE_COMPLIANT_GENERATORS[vendor]()
    methods = MARKETPLACE_FORMAT_METHODS[vendor][format_type]
    
    events = []
    for _ in range(count):
        method_name = random.choice(methods)
        if hasattr(generator, method_name):
            event = getattr(generator, method_name)()
            events.append(event)
    
    return events


def get_marketplace_supported_vendors() -> Dict[str, List[str]]:
    """Get all vendors supported by marketplace-compliant generators."""
    return {
        vendor: list(formats.keys())
        for vendor, formats in MARKETPLACE_FORMAT_METHODS.items()
    }


def validate_xdm_compliance(event: BaseEvent) -> Dict[str, Any]:
    """Validate event compliance with XDM schema requirements."""
    compliance_report = {
        "required_fields_present": True,
        "field_formats_valid": True,
        "xdm_mappable": True,
        "issues": []
    }
    
    # Check required fields
    required_fields = ["vendor", "product", "event_name", "severity", "message"]
    for field in required_fields:
        if not hasattr(event, field) or getattr(event, field) is None:
            compliance_report["required_fields_present"] = False
            compliance_report["issues"].append(f"Missing required field: {field}")
    
    # Validate IP addresses
    if hasattr(event, "source_ip") and event.source_ip:
        if not re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', event.source_ip):
            compliance_report["field_formats_valid"] = False
            compliance_report["issues"].append(f"Invalid source IP format: {event.source_ip}")
    
    # Validate ports
    if hasattr(event, "source_port") and event.source_port:
        if not (1 <= event.source_port <= 65535):
            compliance_report["field_formats_valid"] = False
            compliance_report["issues"].append(f"Invalid source port: {event.source_port}")
    
    # Check XDM-essential fields
    xdm_fields = ["timestamp", "source_ip", "pattern_id"]
    for field in xdm_fields:
        if not hasattr(event, field) or getattr(event, field) is None:
            compliance_report["xdm_mappable"] = False
            compliance_report["issues"].append(f"Missing XDM-essential field: {field}")
    
    return compliance_report