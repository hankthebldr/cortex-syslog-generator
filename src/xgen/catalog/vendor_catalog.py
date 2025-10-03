"""
Vendor catalog and NICE categorization for third-party logs.
Provides mappings of vendor/product to NICE categories and default schema hints.
"""

from typing import Dict, Optional
from ..core.models import NICECategory

# Group vendors by NICE categories
NICE_VENDOR_GROUPS: Dict[NICECategory, Dict[str, list]] = {
    NICECategory.NETWORK: {
        "Cisco": ["ASA", "Firepower", "IOS"],
        "Palo Alto Networks": ["PAN-OS", "Global Protect", "URL Logs", "Platform Logs"],
        "Zscaler": ["Web Proxy"],
        "Proofpoint": ["Email Security"],
    },
    NICECategory.IDENTITY: {
        "Okta": ["SSO", "Audit"],
        "Duo": ["Authentication"],
        "Azure": ["AD Audit Logs", "Signin Log"],
        "OneLogin": ["Events"],
        "PingOne": ["SSO"],
        "Google Workspace": ["Authentication"],
    },
    NICECategory.CLOUD: {
        "AWS": ["CloudTrail", "VPC Flow Logs"],
        "Azure": ["Audit Logs", "Flow Logs"],
        "GCP": ["Audit Logs", "Flow Logs"],
        "Kubernetes": ["Audit Logs"],
        "Microsoft 365": ["Email Logs"],
        "Google Workspace": ["Audit"],
    },
    NICECategory.ENDPOINT: {
        "Microsoft": ["Defender for Endpoint"],
        "CrowdStrike": ["Falcon"],
        "SentinelOne": ["EDR"],
        "Windows": ["Event Collector"],
        "Dropbox": ["Events"],
    },
}

# Default schema hints per NICE category
DEFAULT_SCHEMA_HINTS: Dict[NICECategory, Dict[str, str]] = {
    NICECategory.NETWORK: {
        "src_ip": "string",
        "src_port": "int",
        "dst_ip": "string",
        "dst_port": "int",
        "protocol": "string",
        "action": "string",
    },
    NICECategory.IDENTITY: {
        "username": "string",
        "user_id": "string",
        "ip_address": "string",
        "result": "string",
        "idp": "string",
    },
    NICECategory.CLOUD: {
        "cloud_provider": "string",
        "api_call": "string",
        "account_id": "string",
        "region": "string",
        "src_ip": "string",
    },
    NICECategory.ENDPOINT: {
        "hostname": "string",
        "process_name": "string",
        "file_path": "string",
        "sha256": "string",
        "action": "string",
    },
}


def get_nice_category(vendor: str, product: Optional[str]) -> Optional[NICECategory]:
    v = (vendor or "").strip()
    p = (product or "").strip() if product else None
    for category, mapping in NICE_VENDOR_GROUPS.items():
        for vend, products in mapping.items():
            if vend.lower() == v.lower():
                if not p:
                    return category
                for prod in products:
                    if prod.lower() == p.lower():
                        return category
                return category  # vendor match is enough
    return None


def get_schema_hints(category: NICECategory) -> Dict[str, str]:
    return DEFAULT_SCHEMA_HINTS.get(category, {})
