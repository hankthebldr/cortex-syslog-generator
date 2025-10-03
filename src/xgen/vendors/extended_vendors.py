"""
Extended vendor-specific log generators for comprehensive Cortex XDR data source coverage.

This module expands on the existing realistic_logs.py with additional vendors and data sources
commonly ingested by Cortex XDR, organized by ingestion method and data source category.
"""

import random
from datetime import datetime, timezone
from typing import Dict, List, Optional
from faker import Faker

from ..core.models import BaseEvent, EndpointEvent, NetworkEvent, IdentityEvent, CloudEvent
from ..core.models import NICECategory, SeverityLevel

fake = Faker()


class VendorLogGenerator:
    """Base class for vendor-specific log generation."""
    
    def __init__(self, vendor: str, product: str, nice_category: NICECategory):
        self.vendor = vendor
        self.product = product
        self.nice_category = nice_category


# === NETWORK SECURITY DEVICES ===

class CiscoASAGenerator(VendorLogGenerator):
    """Cisco ASA Firewall logs for network security TTPs."""
    
    def __init__(self):
        super().__init__("Cisco", "ASA", NICECategory.NETWORK)
    
    def generate_connection_denied(self) -> NetworkEvent:
        """Firewall connection denied - suspicious destination."""
        suspicious_ips = ["185.220.101.3", "192.42.116.16", "198.96.155.3", "185.220.100.240"]
        return NetworkEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="Connection Denied",
            event_code="106023",
            severity=SeverityLevel.WARNING,
            message=f"Deny tcp src outside:{random.choice(suspicious_ips)}/80 dst inside:{fake.ipv4_private()}/1433 by access-group",
            source_ip=random.choice(suspicious_ips),
            destination_ip=fake.ipv4_private(),
            source_port=80,
            destination_port=1433,
            protocol="TCP",
            direction="inbound",
            labels={
                "action": "deny",
                "rule": "outside_access_in",
                "reason": "Denied by ACL"
            },
            pattern_id="T1046_NETWORK_SERVICE_SCANNING"
        )
    
    def generate_vpn_authentication(self) -> NetworkEvent:
        """VPN user authentication event."""
        return NetworkEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="VPN Authentication",
            event_code="722051",
            severity=SeverityLevel.INFO,
            message=f"User <{fake.user_name()}> authentication successful",
            source_ip=fake.ipv4(),
            labels={
                "action": "authentication",
                "result": "success",
                "method": "radius",
                "tunnel_type": "SSL-VPN"
            },
            pattern_id="T1078_VALID_ACCOUNTS"
        )


class FortiGateGenerator(VendorLogGenerator):
    """FortiGate Firewall logs for network security events."""
    
    def __init__(self):
        super().__init__("Fortinet", "FortiGate", NICECategory.NETWORK)
    
    def generate_ips_signature(self) -> NetworkEvent:
        """IPS signature detection for malicious activity."""
        signatures = [
            "Backdoor.Generic.TCP",
            "Trojan.Agent.HTTP.Request",
            "Exploit.CVE-2021-34527.HTTP",
            "Malware.C2.DNS.Request"
        ]
        return NetworkEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="IPS Signature",
            event_code="18432",
            severity=SeverityLevel.CRITICAL,
            message=f"Intrusion detected: {random.choice(signatures)}",
            source_ip=fake.ipv4_private(),
            destination_ip=fake.ipv4(),
            source_port=random.randint(49152, 65535),
            destination_port=80,
            protocol="TCP",
            direction="outbound",
            labels={
                "action": "dropped",
                "signature": random.choice(signatures),
                "severity": "critical",
                "attack_id": str(random.randint(10000, 99999))
            },
            pattern_id="T1071.001_WEB_PROTOCOLS"
        )


class CheckPointGenerator(VendorLogGenerator):
    """Check Point Security Gateway logs."""
    
    def __init__(self):
        super().__init__("Check Point", "Security Gateway", NICECategory.NETWORK)
    
    def generate_threat_prevention(self) -> NetworkEvent:
        """Anti-malware and threat prevention detection."""
        threats = [
            "Trojan.Win32.Generic",
            "Backdoor.Linux.Mirai",
            "Exploit.MS17-010.WannaCry",
            "Phishing.URL.Detected"
        ]
        return NetworkEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="Threat Prevention",
            event_code="Malware",
            severity=SeverityLevel.CRITICAL,
            message=f"Threat detected: {random.choice(threats)}",
            source_ip=fake.ipv4_private(),
            destination_ip=fake.ipv4(),
            protocol="HTTP",
            direction="outbound",
            labels={
                "action": "block",
                "threat_type": "malware",
                "confidence": "high",
                "product": "Anti-Malware"
            },
            pattern_id="T1566.002_PHISHING_LINKS"
        )


# === ENDPOINT DETECTION AND RESPONSE ===

class SentinelOneGenerator(VendorLogGenerator):
    """SentinelOne EDR logs for endpoint security events."""
    
    def __init__(self):
        super().__init__("SentinelOne", "EDR", NICECategory.ENDPOINT)
    
    def generate_threat_detection(self) -> EndpointEvent:
        """Malware detection and mitigation."""
        return EndpointEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="Threat Detected",
            event_code="3101",
            severity=SeverityLevel.CRITICAL,
            message="Malicious behavior detected and mitigated",
            source_ip=fake.ipv4_private(),
            labels={
                "action": "mitigated",
                "threat_type": "malware",
                "classification": "Trojan",
                "confidence": "high"
            },
            process_name="powershell.exe",
            process_id=random.randint(1000, 9999),
            parent_process_name="cmd.exe",
            command_line="powershell.exe -ep bypass -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAE",
            file_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            process_sha256="c1d4e5f6789abcdef1234567890abcdef1234567890abcdef1234567890abcdef1",
            pattern_id="T1059.001_POWERSHELL"
        )
    
    def generate_behavioral_indicator(self) -> EndpointEvent:
        """Behavioral analytics detection."""
        return EndpointEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="Behavioral Indicator",
            event_code="3201",
            severity=SeverityLevel.WARNING,
            message="Suspicious process injection detected",
            source_ip=fake.ipv4_private(),
            labels={
                "action": "detected",
                "indicator_type": "process_injection",
                "technique": "CreateRemoteThread"
            },
            process_name="notepad.exe",
            process_id=random.randint(1000, 9999),
            parent_process_name="explorer.exe",
            pattern_id="T1055_PROCESS_INJECTION"
        )


class CarbonBlackGenerator(VendorLogGenerator):
    """VMware Carbon Black EDR logs."""
    
    def __init__(self):
        super().__init__("VMware", "Carbon Black", NICECategory.ENDPOINT)
    
    def generate_binary_analysis(self) -> EndpointEvent:
        """Binary reputation and analysis event."""
        return EndpointEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="Binary Analysis",
            event_code="BINARY",
            severity=SeverityLevel.WARNING,
            message="Unknown binary executed from suspicious location",
            source_ip=fake.ipv4_private(),
            labels={
                "action": "executed",
                "reputation": "unknown",
                "prevalence": "rare",
                "first_seen": "24h"
            },
            process_name="update.exe",
            process_id=random.randint(1000, 9999),
            file_path="C:\\Users\\Public\\Downloads\\update.exe",
            process_sha256="d2e3f4567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef2",
            pattern_id="T1204.002_MALICIOUS_FILE"
        )


# === IDENTITY AND ACCESS MANAGEMENT ===

class PingIdentityGenerator(VendorLogGenerator):
    """Ping Identity SSO and access management logs."""
    
    def __init__(self):
        super().__init__("Ping Identity", "PingFederate", NICECategory.IDENTITY)
    
    def generate_sso_authentication(self) -> IdentityEvent:
        """SAML SSO authentication event."""
        return IdentityEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="SSO Authentication",
            event_code="SAML_AUTH",
            severity=SeverityLevel.INFO,
            message="SAML authentication successful",
            source_ip=fake.ipv4(),
            labels={
                "action": "authenticate",
                "protocol": "SAML 2.0",
                "result": "success",
                "idp": "corporate-idp"
            },
            auth_method="SAML",
            mfa_method="TOTP",
            application="Salesforce",
            resource="https://mycompany.salesforce.com",
            pattern_id="T1078.004_VALID_ACCOUNTS_CLOUD"
        )


class DuoSecurityGenerator(VendorLogGenerator):
    """Duo Security MFA logs."""
    
    def __init__(self):
        super().__init__("Duo Security", "MFA", NICECategory.IDENTITY)
    
    def generate_mfa_bypass_attempt(self) -> IdentityEvent:
        """Suspicious MFA bypass attempt."""
        return IdentityEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="MFA Bypass Attempt",
            event_code="AUTH_BYPASS",
            severity=SeverityLevel.CRITICAL,
            message="Multiple MFA bypass attempts detected",
            source_ip=fake.ipv4(),
            labels={
                "action": "mfa_bypass",
                "result": "denied",
                "attempts": "5",
                "reason": "fraud_detection"
            },
            auth_method="Push",
            mfa_method="Duo Mobile",
            risk_score=9.5,
            pattern_id="T1111_TWO_FACTOR_AUTH_INTERCEPTION"
        )


# === CLOUD SERVICE PROVIDERS ===

class GCPAuditGenerator(VendorLogGenerator):
    """Google Cloud Platform Audit logs."""
    
    def __init__(self):
        super().__init__("Google", "Cloud Audit", NICECategory.CLOUD)
    
    def generate_iam_policy_change(self) -> CloudEvent:
        """IAM policy modification in GCP."""
        return CloudEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="SetIamPolicy",
            event_code="SUCCESS",
            severity=SeverityLevel.WARNING,
            message="IAM policy modified for project resource",
            source_ip=fake.ipv4(),
            labels={
                "action": "google.iam.admin.v1.SetIamPolicy",
                "resource_type": "project",
                "method": "SetIamPolicy"
            },
            cloud_provider="GCP",
            account_id=f"project-{random.randint(100000, 999999)}",
            region="us-central1",
            service_name="iam.googleapis.com",
            api_call="SetIamPolicy",
            resource_name="//cloudresourcemanager.googleapis.com/projects/my-project",
            pattern_id="T1098_ACCOUNT_MANIPULATION"
        )


class OfficeAuditGenerator(VendorLogGenerator):
    """Microsoft 365 Audit logs."""
    
    def __init__(self):
        super().__init__("Microsoft", "Office 365", NICECategory.CLOUD)
    
    def generate_email_forwarding_rule(self) -> CloudEvent:
        """Suspicious email forwarding rule creation."""
        return CloudEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="New-InboxRule",
            event_code="SUCCESS",
            severity=SeverityLevel.WARNING,
            message="Inbox rule created with external forwarding",
            source_ip=fake.ipv4(),
            labels={
                "action": "New-InboxRule",
                "workload": "Exchange",
                "operation": "New-InboxRule",
                "forward_to": "external@suspicious-domain.com"
            },
            cloud_provider="Microsoft 365",
            service_name="Exchange Online",
            api_call="New-InboxRule",
            pattern_id="T1114.003_EMAIL_FORWARDING_RULE"
        )


# === WEB SECURITY ===

class ZscalerGenerator(VendorLogGenerator):
    """Zscaler Cloud Security logs."""
    
    def __init__(self):
        super().__init__("Zscaler", "ZIA", NICECategory.NETWORK)
    
    def generate_web_threat_detection(self) -> NetworkEvent:
        """Web-based threat detection."""
        return NetworkEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="Web Threat",
            event_code="THREAT",
            severity=SeverityLevel.CRITICAL,
            message="Malicious URL blocked",
            source_ip=fake.ipv4_private(),
            destination_ip=fake.ipv4(),
            protocol="HTTPS",
            direction="outbound",
            domain="malicious-c2-domain.com",
            labels={
                "action": "blocked",
                "threat_category": "Command and Control",
                "risk_score": "95",
                "url_category": "Malware"
            },
            url="https://malicious-c2-domain.com/beacon",
            pattern_id="T1071.001_WEB_PROTOCOLS"
        )


class ProofpointGenerator(VendorLogGenerator):
    """Proofpoint Email Security logs."""
    
    def __init__(self):
        super().__init__("Proofpoint", "Email Protection", NICECategory.NETWORK)
    
    def generate_email_threat_detection(self) -> NetworkEvent:
        """Email-based threat detection."""
        return NetworkEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="Email Threat",
            event_code="THREAT",
            severity=SeverityLevel.CRITICAL,
            message="Malicious attachment detected and quarantined",
            source_ip=fake.ipv4(),
            labels={
                "action": "quarantined",
                "threat_type": "attachment",
                "malware_family": "Emotet",
                "recipient": f"{fake.user_name()}@company.com",
                "sender": f"{fake.user_name()}@suspicious-domain.com"
            },
            pattern_id="T1566.001_PHISHING_ATTACHMENT"
        )


# === DATABASE SECURITY ===

class OracleAuditGenerator(VendorLogGenerator):
    """Oracle Database Audit logs."""
    
    def __init__(self):
        super().__init__("Oracle", "Database", NICECategory.ENDPOINT)
    
    def generate_privilege_escalation(self) -> EndpointEvent:
        """Database privilege escalation attempt."""
        return EndpointEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="GRANT",
            event_code="AUDIT",
            severity=SeverityLevel.WARNING,
            message="DBA privileges granted to user account",
            source_ip=fake.ipv4_private(),
            labels={
                "action": "GRANT",
                "object": "DBA_ROLE",
                "user": fake.user_name(),
                "client_program": "sqlplus.exe"
            },
            pattern_id="T1078.003_LOCAL_ACCOUNTS"
        )


# === VULNERABILITY MANAGEMENT ===

class QualysGenerator(VendorLogGenerator):
    """Qualys VMDR vulnerability management logs."""
    
    def __init__(self):
        super().__init__("Qualys", "VMDR", NICECategory.ENDPOINT)
    
    def generate_critical_vulnerability(self) -> EndpointEvent:
        """Critical vulnerability detection."""
        cves = ["CVE-2021-44228", "CVE-2021-34527", "CVE-2020-1472", "CVE-2019-0708"]
        return EndpointEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="Vulnerability Detected",
            event_code="VULN",
            severity=SeverityLevel.CRITICAL,
            message=f"Critical vulnerability detected: {random.choice(cves)}",
            source_ip=fake.ipv4_private(),
            labels={
                "action": "detected",
                "cve": random.choice(cves),
                "cvss_score": "9.8",
                "exploitability": "high",
                "patch_available": "yes"
            },
            pattern_id="T1190_EXPLOIT_PUBLIC_APPLICATION"
        )


# === EXTENDED VENDOR REGISTRY ===

EXTENDED_VENDOR_GENERATORS = {
    "Cisco ASA": CiscoASAGenerator,
    "FortiGate": FortiGateGenerator,
    "Check Point": CheckPointGenerator,
    "SentinelOne": SentinelOneGenerator,
    "VMware Carbon Black": CarbonBlackGenerator,
    "Ping Identity": PingIdentityGenerator,
    "Duo Security": DuoSecurityGenerator,
    "Google Cloud": GCPAuditGenerator,
    "Microsoft 365": OfficeAuditGenerator,
    "Zscaler": ZscalerGenerator,
    "Proofpoint": ProofpointGenerator,
    "Oracle Database": OracleAuditGenerator,
    "Qualys": QualysGenerator,
}

# Extended APT mappings with new vendors
EXTENDED_APT_VENDOR_MAPPINGS = {
    "APT29": {
        "Cisco ASA": ["generate_vpn_authentication"],
        "SentinelOne": ["generate_threat_detection"],
        "Microsoft 365": ["generate_email_forwarding_rule"],
        "Google Cloud": ["generate_iam_policy_change"],
    },
    "APT28": {
        "FortiGate": ["generate_ips_signature"],
        "Check Point": ["generate_threat_prevention"],
        "VMware Carbon Black": ["generate_binary_analysis"],
    },
    "Lazarus Group": {
        "Zscaler": ["generate_web_threat_detection"],
        "Proofpoint": ["generate_email_threat_detection"],
        "Duo Security": ["generate_mfa_bypass_attempt"],
    },
    "APT40": {
        "Oracle Database": ["generate_privilege_escalation"],
        "Qualys": ["generate_critical_vulnerability"],
    },
    "Volt Typhoon": {
        "Ping Identity": ["generate_sso_authentication"],
        "Cisco ASA": ["generate_connection_denied"],
    }
}


def generate_extended_vendor_logs(apt_group: str, vendor: str, count: int = 5) -> List[BaseEvent]:
    """Generate logs using the extended vendor generators."""
    if apt_group not in EXTENDED_APT_VENDOR_MAPPINGS:
        raise ValueError(f"APT group {apt_group} not supported in extended mappings")
    
    if vendor not in EXTENDED_APT_VENDOR_MAPPINGS[apt_group]:
        raise ValueError(f"Vendor {vendor} not mapped for APT group {apt_group}")
    
    if vendor not in EXTENDED_VENDOR_GENERATORS:
        raise ValueError(f"Extended vendor generator for {vendor} not found")
    
    generator = EXTENDED_VENDOR_GENERATORS[vendor]()
    methods = EXTENDED_APT_VENDOR_MAPPINGS[apt_group][vendor]
    
    events = []
    for _ in range(count):
        method_name = random.choice(methods)
        if hasattr(generator, method_name):
            event = getattr(generator, method_name)()
            events.append(event)
    
    return events


def get_all_supported_vendors() -> Dict[str, List[str]]:
    """Get all supported vendors from both original and extended generators."""
    # Import the original mappings to combine them
    from .realistic_logs import APT_VENDOR_MAPPINGS as ORIGINAL_MAPPINGS
    
    all_mappings = {}
    
    # Combine original and extended mappings
    for apt_group in set(list(ORIGINAL_MAPPINGS.keys()) + list(EXTENDED_APT_VENDOR_MAPPINGS.keys())):
        vendors = []
        if apt_group in ORIGINAL_MAPPINGS:
            vendors.extend(ORIGINAL_MAPPINGS[apt_group].keys())
        if apt_group in EXTENDED_APT_VENDOR_MAPPINGS:
            vendors.extend(EXTENDED_APT_VENDOR_MAPPINGS[apt_group].keys())
        all_mappings[apt_group] = list(set(vendors))
    
    return all_mappings


def get_data_source_categories() -> Dict[str, List[str]]:
    """Get vendors organized by data source category."""
    return {
        "Network Security": [
            "Palo Alto Networks", "Cisco ASA", "FortiGate", "Check Point", "Zscaler", "Proofpoint"
        ],
        "Endpoint Security": [
            "CrowdStrike", "SentinelOne", "VMware Carbon Black", "Qualys"
        ],
        "Identity Management": [
            "Okta", "Microsoft Azure AD", "Ping Identity", "Duo Security"
        ],
        "Cloud Platforms": [
            "AWS", "Microsoft 365", "Google Cloud", "Kubernetes"
        ],
        "Database Security": [
            "Oracle Database"
        ]
    }