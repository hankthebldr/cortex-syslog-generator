"""
Transport-specific format mappings for optimal payload delivery.

Maps vendor/NICE category combinations to preferred formats per transport type:
- Syslog transports: CEF or LEEF (vendor-specific)
- HTTP/Webhook: JSON (structured for event collectors)
- XSIAM HTTP: JSON with XDM mapping
"""

from typing import Dict, Optional
from ..core.models import LogFormat, TransportType, NICECategory


# Vendor preferences for syslog-based transports
SYSLOG_FORMAT_MAPPING: Dict[str, LogFormat] = {
    # Network Security (prefer CEF for most)
    "Cisco": LogFormat.CEF,
    "Palo Alto Networks": LogFormat.CEF,
    "Zscaler": LogFormat.CEF,
    "Proofpoint": LogFormat.CEF,
    
    # IBM/QRadar vendors often prefer LEEF
    "IBM": LogFormat.LEEF,
    "QRadar": LogFormat.LEEF,
    
    # Identity providers (CEF is common)
    "Okta": LogFormat.CEF,
    "Duo": LogFormat.CEF,
    "Azure": LogFormat.CEF,
    "OneLogin": LogFormat.CEF,
    "PingOne": LogFormat.CEF,
    "Google Workspace": LogFormat.CEF,
    
    # Cloud providers (CEF typical for syslog)
    "AWS": LogFormat.CEF,
    "GCP": LogFormat.CEF,
    "Kubernetes": LogFormat.CEF,
    "Microsoft 365": LogFormat.CEF,
    
    # Endpoint security (CEF standard)
    "Microsoft": LogFormat.CEF,
    "CrowdStrike": LogFormat.CEF,
    "SentinelOne": LogFormat.CEF,
    "Windows": LogFormat.CEF,
    "Dropbox": LogFormat.CEF,
}

# NICE category fallbacks if vendor not found
NICE_FORMAT_MAPPING: Dict[NICECategory, LogFormat] = {
    NICECategory.NETWORK: LogFormat.CEF,
    NICECategory.IDENTITY: LogFormat.CEF,
    NICECategory.CLOUD: LogFormat.CEF,
    NICECategory.ENDPOINT: LogFormat.CEF,
}


def get_optimal_format(
    vendor: str, 
    nice_category: Optional[NICECategory], 
    transport_type: TransportType
) -> LogFormat:
    """
    Determine optimal log format based on vendor, NICE category, and transport.
    
    Args:
        vendor: Event vendor (e.g., "Cisco", "Okta")
        nice_category: NICE framework category
        transport_type: Target transport mechanism
        
    Returns:
        Optimal LogFormat for the combination
    """
    # HTTP-based transports always use JSON
    if transport_type in [TransportType.XSIAM_HTTP, TransportType.WEBHOOK, TransportType.HTTP_POST]:
        return LogFormat.JSON
    
    # Syslog-based transports use vendor/NICE preferences
    if transport_type in [TransportType.SYSLOG_UDP, TransportType.SYSLOG_TCP, TransportType.SYSLOG_TLS]:
        # Check vendor preference first
        vendor_clean = (vendor or "").strip()
        if vendor_clean in SYSLOG_FORMAT_MAPPING:
            return SYSLOG_FORMAT_MAPPING[vendor_clean]
        
        # Fall back to NICE category
        if nice_category and nice_category in NICE_FORMAT_MAPPING:
            return NICE_FORMAT_MAPPING[nice_category]
        
        # Ultimate fallback
        return LogFormat.CEF
    
    # Other transports default to JSON
    return LogFormat.JSON


def get_format_hint(vendor: str, nice_category: Optional[NICECategory]) -> str:
    """
    Get a human-readable hint about recommended formats for a vendor/category.
    
    Returns:
        String describing format preferences
    """
    vendor_clean = (vendor or "").strip()
    
    if vendor_clean in SYSLOG_FORMAT_MAPPING:
        fmt = SYSLOG_FORMAT_MAPPING[vendor_clean]
        return f"Syslog: {fmt.value.upper()}, HTTP: JSON"
    
    if nice_category:
        fmt = NICE_FORMAT_MAPPING.get(nice_category, LogFormat.CEF)
        return f"Syslog: {fmt.value.upper()}, HTTP: JSON"
    
    return "Syslog: CEF, HTTP: JSON"