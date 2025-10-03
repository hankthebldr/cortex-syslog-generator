"""
Realistic vendor-specific log generators aligned to known threat actor TTPs.

This module creates authentic log formats that mirror real third-party data sources
when threat actors employ specific techniques. Designed to showcase Broker VM
ingestion capabilities across different applets and data sources.
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


class PaloAltoGenerator(VendorLogGenerator):
    """Palo Alto Networks PAN-OS logs for network-based TTPs."""
    
    def __init__(self):
        super().__init__("Palo Alto Networks", "PAN-OS", NICECategory.NETWORK)
    
    def generate_apt28_smb_lateral(self) -> NetworkEvent:
        """APT28 SMB lateral movement - PAN-OS Traffic log."""
        return NetworkEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="TRAFFIC",
            event_code="1",
            severity=SeverityLevel.INFO,
            message=f"SMB connection from {fake.ipv4_private()} to {fake.ipv4_private()}",
            source_ip=fake.ipv4_private(),
            destination_ip=fake.ipv4_private(), 
            source_port=random.randint(49152, 65535),
            destination_port=445,
            protocol="TCP",
            direction="internal",
            labels={
                "action": "allow",
                "rule": "LAN_to_LAN_Allow",
                "subtype": "end",
                "sessionid": str(random.randint(100000, 999999)),
                "application": "ms-ds-smb",
                "category": "business-systems"
            },
            bytes_in=random.randint(1000, 50000),
            bytes_out=random.randint(500, 10000),
            pattern_id="T1021.002_SMB_LATERAL"
        )
    
    def generate_apt29_c2_traffic(self) -> NetworkEvent:
        """APT29 HTTPS C2 communication - PAN-OS Threat log."""
        suspicious_domains = [
            "microsoft-update-catalog.com",
            "office365-management.net", 
            "azurewebsites.us",
            "sharepoint-admin.org"
        ]
        return NetworkEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="THREAT",
            event_code="1",
            severity=SeverityLevel.WARNING,
            message=f"Suspicious HTTPS connection to {random.choice(suspicious_domains)}",
            source_ip=fake.ipv4_private(),
            destination_ip=fake.ipv4(),
            source_port=random.randint(49152, 65535), 
            destination_port=443,
            protocol="TCP",
            direction="outbound",
            domain=random.choice(suspicious_domains),
            labels={
                "action": "allow",
                "threat_name": "APT29-style C2",
                "category": "command-and-control",
                "subtype": "url",
                "severity": "medium"
            },
            pattern_id="T1071.001_WEB_PROTOCOLS"
        )


class CrowdStrikeGenerator(VendorLogGenerator):
    """CrowdStrike Falcon EDR logs for endpoint TTPs."""
    
    def __init__(self):
        super().__init__("CrowdStrike", "Falcon", NICECategory.ENDPOINT)
    
    def generate_apt29_service_persistence(self) -> EndpointEvent:
        """APT29 Windows Service persistence."""
        service_names = ["WinDefend", "MpsSvc", "SecurityHealthService", "wscsvc"]
        return EndpointEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="ProcessRollup2",
            event_code="4688",
            severity=SeverityLevel.WARNING,
            message="Suspicious service creation detected",
            source_ip=fake.ipv4_private(),
            labels={
                "action": "ProcessRollup2",
                "tactic": "Persistence",
                "technique": "T1543.003"
            },
            process_name="sc.exe",
            process_id=random.randint(1000, 9999),
            parent_process_name="cmd.exe", 
            parent_process_id=random.randint(500, 999),
            command_line=f'sc create {random.choice(service_names)} binPath="C:\\Windows\\System32\\svchost.exe -k netsvcs" start=auto',
            file_path="C:\\Windows\\System32\\sc.exe",
            process_sha256="a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890",
            pattern_id="T1543.003_SERVICE_PERSIST"
        )
    
    def generate_lazarus_registry_persistence(self) -> EndpointEvent:
        """Lazarus Group registry autostart persistence."""
        return EndpointEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="RegGenericEvent",
            event_code="13",
            severity=SeverityLevel.CRITICAL,
            message="Registry Run key modification detected",
            source_ip=fake.ipv4_private(),
            labels={
                "action": "RegSetValue", 
                "tactic": "Persistence",
                "technique": "T1547.001"
            },
            process_name="reg.exe",
            process_id=random.randint(1000, 9999),
            parent_process_name="powershell.exe",
            command_line='reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "SecurityUpdate" /t REG_SZ /d "C:\\Users\\Public\\update.exe"',
            file_path="C:\\Windows\\System32\\reg.exe",
            registry_key="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            registry_value="SecurityUpdate",
            process_sha256="b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890ab",
            pattern_id="T1547.001_REGISTRY_AUTOSTART"
        )


class OktaGenerator(VendorLogGenerator):
    """Okta SSO logs for identity-based TTPs."""
    
    def __init__(self):
        super().__init__("Okta", "SSO", NICECategory.IDENTITY)
    
    def generate_apt29_cloud_initial_access(self) -> IdentityEvent:
        """APT29 valid cloud accounts initial access."""
        return IdentityEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="user.authentication.sso",
            event_code="SUCCESS",
            severity=SeverityLevel.NOTICE,
            message="User authentication via SSO",
            source_ip=fake.ipv4(),  # External IP
            labels={
                "action": "user.authentication.sso",
                "outcome": "SUCCESS",
                "risk_level": "HIGH"
            },
            auth_method="SAML",
            mfa_method="BYPASS",
            application="Office365",
            resource="https://portal.office.com",
            risk_score=8.5,
            pattern_id="T1078.004_VALID_ACCOUNTS_CLOUD"
        )
    
    def generate_impossible_travel(self) -> IdentityEvent:
        """Impossible travel detection (common APT technique)."""
        locations = [
            ("Moscow", "RU"), ("Beijing", "CN"), ("Pyongyang", "KP"),
            ("Tehran", "IR"), ("St. Petersburg", "RU")
        ]
        city, country = random.choice(locations)
        
        return IdentityEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="security.threat.detected",
            event_code="THREAT_DETECTED",
            severity=SeverityLevel.CRITICAL,
            message=f"Impossible travel detected - login from {city}, {country}",
            source_ip=fake.ipv4(),
            labels={
                "action": "security.threat.detected",
                "threat_type": "impossible_travel",
                "location": f"{city}, {country}",
                "risk_score": "HIGH"
            },
            auth_method="PASSWORD",
            risk_score=9.2,
            pattern_id="T1078.004_VALID_ACCOUNTS_CLOUD"
        )


class AzureADGenerator(VendorLogGenerator):
    """Azure AD (Entra ID) logs for cloud identity TTPs."""
    
    def __init__(self):
        super().__init__("Microsoft", "Azure AD", NICECategory.IDENTITY)
    
    def generate_apt29_additional_credentials(self) -> IdentityEvent:
        """APT29 additional cloud credentials creation."""
        return IdentityEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="Add service principal credentials",
            event_code="4624",
            severity=SeverityLevel.WARNING,
            message="Service principal credentials added",
            source_ip=fake.ipv4_private(),
            labels={
                "action": "Add service principal credentials",
                "category": "ApplicationManagement",
                "result": "success",
                "operationType": "Add"
            },
            auth_method="Certificate",
            application="Microsoft Graph",
            resource="https://graph.microsoft.com",
            pattern_id="T1098.001_CLOUD_CREDS"
        )


class KubernetesGenerator(VendorLogGenerator):
    """Kubernetes Audit logs for container TTPs."""
    
    def __init__(self):
        super().__init__("Kubernetes", "kube-apiserver", NICECategory.CLOUD)
    
    def generate_kubectl_exec(self) -> CloudEvent:
        """Container administration command (kubectl exec)."""
        return CloudEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="pods/exec",
            event_code="200",
            severity=SeverityLevel.INFO,
            message="Command executed in container",
            source_ip=fake.ipv4_private(),
            destination_port=443,
            protocol="HTTPS",
            labels={
                "action": "pods/exec",
                "verb": "create",
                "namespace": "default",
                "resource": "pods",
                "subresource": "exec",
                "user_agent": "kubectl/v1.28.0",
                "response_code": "200"
            },
            cloud_provider="EKS",
            service_name="kube-apiserver",
            api_call="POST /api/v1/namespaces/default/pods/nginx-pod/exec",
            pattern_id="T1609_CONTAINER_ADMIN_CMD"
        )
    
    def generate_privileged_pod_creation(self) -> CloudEvent:
        """Kubernetes escape to host via privileged pod."""
        return CloudEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="pods",
            event_code="201",
            severity=SeverityLevel.WARNING,
            message="Privileged pod created",
            source_ip=fake.ipv4_private(),
            destination_port=443,
            protocol="HTTPS",
            labels={
                "action": "create",
                "verb": "create",
                "namespace": "kube-system",
                "resource": "pods",
                "privileged": "true",
                "host_network": "true",
                "user_agent": "kubectl/v1.28.0"
            },
            cloud_provider="AKS",
            service_name="kube-apiserver", 
            api_call="POST /api/v1/namespaces/kube-system/pods",
            pattern_id="T1611_ESCAPE_TO_HOST"
        )


class AWSCloudTrailGenerator(VendorLogGenerator):
    """AWS CloudTrail logs for cloud TTPs."""
    
    def __init__(self):
        super().__init__("AWS", "CloudTrail", NICECategory.CLOUD)
    
    def generate_imds_credential_access(self) -> CloudEvent:
        """Cloud instance metadata service credential access."""
        return CloudEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="AssumeRole",
            event_code="SUCCESS",
            severity=SeverityLevel.WARNING,
            message="Role assumed using IMDS credentials",
            source_ip=fake.ipv4_private(),
            labels={
                "action": "AssumeRole",
                "user_identity_type": "AssumedRole", 
                "user_agent": "aws-cli/2.13.0 Python/3.11.4",
                "response_elements": "true"
            },
            cloud_provider="AWS",
            account_id=str(random.randint(100000000000, 999999999999)),
            region="us-east-1",
            service_name="sts.amazonaws.com",
            api_call="AssumeRole",
            pattern_id="T1552.005_CLOUD_IMDS"
        )
    
    def generate_s3_data_exfiltration(self) -> CloudEvent:
        """Data exfiltration to attacker-controlled S3 bucket."""
        return CloudEvent(
            vendor=self.vendor,
            product=self.product,
            event_name="CreateBucket",
            event_code="SUCCESS",
            severity=SeverityLevel.CRITICAL,
            message="S3 bucket created for data exfiltration",
            source_ip=fake.ipv4(),
            labels={
                "action": "CreateBucket",
                "bucket_name": f"backup-{random.randint(1000, 9999)}",
                "user_identity_type": "AssumedRole",
                "user_agent": "aws-cli/2.13.0"
            },
            cloud_provider="AWS",
            account_id=str(random.randint(100000000000, 999999999999)),
            region="us-west-2",
            service_name="s3.amazonaws.com", 
            api_call="CreateBucket",
            resource_name=f"backup-{random.randint(1000, 9999)}",
            pattern_id="T1567.002_EXFIL_TO_CLOUD"
        )


# Vendor generator registry
VENDOR_GENERATORS = {
    "Palo Alto Networks": PaloAltoGenerator,
    "CrowdStrike": CrowdStrikeGenerator,
    "Okta": OktaGenerator,
    "Microsoft Azure AD": AzureADGenerator,
    "Kubernetes": KubernetesGenerator,
    "AWS": AWSCloudTrailGenerator,
}

# APT Group to Vendor/TTP mapping
APT_VENDOR_MAPPINGS = {
    "APT28": {
        "Palo Alto Networks": ["generate_apt28_smb_lateral"],
        "CrowdStrike": ["generate_apt29_service_persistence"],  # Similar techniques
    },
    "APT29": {
        "Palo Alto Networks": ["generate_apt29_c2_traffic"],
        "CrowdStrike": ["generate_apt29_service_persistence"],
        "Okta": ["generate_apt29_cloud_initial_access"],
        "Microsoft Azure AD": ["generate_apt29_additional_credentials"],
    },
    "Lazarus Group": {
        "CrowdStrike": ["generate_lazarus_registry_persistence"],
        "Okta": ["generate_impossible_travel"],
    },
    "Volt Typhoon": {
        "Kubernetes": ["generate_kubectl_exec", "generate_privileged_pod_creation"],
        "AWS": ["generate_imds_credential_access"],
    },
    "APT40": {
        "AWS": ["generate_s3_data_exfiltration"],
        "Kubernetes": ["generate_kubectl_exec"],
    }
}


def generate_apt_vendor_logs(apt_group: str, vendor: str, count: int = 5) -> List[BaseEvent]:
    """Generate realistic logs for a specific APT group and vendor combination."""
    if apt_group not in APT_VENDOR_MAPPINGS:
        raise ValueError(f"APT group {apt_group} not supported")
    
    if vendor not in APT_VENDOR_MAPPINGS[apt_group]:
        raise ValueError(f"Vendor {vendor} not mapped for APT group {apt_group}")
    
    if vendor not in VENDOR_GENERATORS:
        raise ValueError(f"Vendor generator for {vendor} not found")
    
    generator = VENDOR_GENERATORS[vendor]()
    methods = APT_VENDOR_MAPPINGS[apt_group][vendor]
    
    events = []
    for _ in range(count):
        method_name = random.choice(methods)
        if hasattr(generator, method_name):
            event = getattr(generator, method_name)()
            events.append(event)
    
    return events


def get_supported_apt_vendors() -> Dict[str, List[str]]:
    """Get all supported APT group and vendor combinations."""
    return {
        apt_group: list(vendors.keys()) 
        for apt_group, vendors in APT_VENDOR_MAPPINGS.items()
    }