"""
Core domain models for the XSIAM Log Generator.

This module defines the foundational data structures used throughout the application,
aligned with the NICE Cybersecurity Workforce Framework categories and MITRE ATT&CK.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Any, Union
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, validator, root_validator


class NICECategory(str, Enum):
    """NICE Cybersecurity Framework Categories."""
    NETWORK = "network"
    IDENTITY = "identity"  
    CLOUD = "cloud"
    ENDPOINT = "endpoint"


class AttackTactic(str, Enum):
    """MITRE ATT&CK Tactics (14 total)."""
    RECONNAISSANCE = "TA0043"
    RESOURCE_DEVELOPMENT = "TA0042"
    INITIAL_ACCESS = "TA0001"
    EXECUTION = "TA0002"
    PERSISTENCE = "TA0003"
    PRIVILEGE_ESCALATION = "TA0004"
    DEFENSE_EVASION = "TA0005"
    CREDENTIAL_ACCESS = "TA0006"
    DISCOVERY = "TA0007"
    LATERAL_MOVEMENT = "TA0008"
    COLLECTION = "TA0009"
    COMMAND_AND_CONTROL = "TA0011"
    EXFILTRATION = "TA0010"
    IMPACT = "TA0040"


class SeverityLevel(int, Enum):
    """Standard severity levels aligned with CEF and syslog standards."""
    EMERGENCY = 0    # System is unusable
    ALERT = 1        # Action must be taken immediately  
    CRITICAL = 2     # Critical conditions
    ERROR = 3        # Error conditions
    WARNING = 4      # Warning conditions
    NOTICE = 5       # Normal but significant condition
    INFO = 6         # Informational messages
    DEBUG = 7        # Debug-level messages


class LogFormat(str, Enum):
    """Supported log output formats."""
    CEF = "cef"
    LEEF = "leef"
    JSON = "json"
    SYSLOG = "syslog"


class TransportType(str, Enum):
    """Supported transport mechanisms."""
    SYSLOG_UDP = "syslog_udp"
    SYSLOG_TCP = "syslog_tcp"
    SYSLOG_TLS = "syslog_tls"
    XSIAM_HTTP = "xsiam_http"
    WEBHOOK = "webhook"
    HTTP_POST = "http_post"
    FILE = "file"
    STDOUT = "stdout"


class Actor(BaseModel):
    """Represents a user, service account, or automated actor."""
    
    user_id: str = Field(..., description="Unique identifier for the actor")
    username: str = Field(..., description="Human-readable username") 
    email: Optional[str] = Field(None, description="Email address if applicable")
    display_name: Optional[str] = Field(None, description="Human-readable display name")
    department: Optional[str] = Field(None, description="Organizational department")
    role: Optional[str] = Field(None, description="Role or title")
    identity_provider: Optional[str] = Field(None, description="Source identity provider")
    auth_factors: List[str] = Field(default_factory=list, description="Authentication factors used")
    risk_score: Optional[float] = Field(None, ge=0.0, le=10.0, description="Risk score 0-10")
    is_privileged: bool = Field(False, description="Whether this is a privileged account")
    tags: Dict[str, str] = Field(default_factory=dict, description="Additional metadata tags")
    
    class Config:
        schema_extra = {
            "example": {
                "user_id": "U123456",
                "username": "jdoe",
                "email": "john.doe@company.com",
                "display_name": "John Doe",
                "department": "Engineering",
                "role": "Senior Developer",
                "identity_provider": "Azure AD",
                "auth_factors": ["password", "mfa"],
                "risk_score": 2.3,
                "is_privileged": False,
                "tags": {"location": "headquarters"}
            }
        }


class Asset(BaseModel):
    """Represents a network asset, host, or cloud resource."""
    
    asset_id: str = Field(..., description="Unique identifier for the asset")
    hostname: Optional[str] = Field(None, description="Hostname or FQDN")
    ip_address: Optional[str] = Field(None, description="Primary IP address")
    mac_address: Optional[str] = Field(None, description="MAC address")
    asset_type: str = Field(..., description="Type of asset (workstation, server, etc.)")
    operating_system: Optional[str] = Field(None, description="Operating system")
    os_version: Optional[str] = Field(None, description="OS version")
    location: Optional[str] = Field(None, description="Physical or network location")
    subnet: Optional[str] = Field(None, description="Network subnet")
    vlan_id: Optional[int] = Field(None, description="VLAN identifier")
    zone: Optional[str] = Field(None, description="Security zone")
    cloud_account: Optional[str] = Field(None, description="Cloud account identifier")
    cloud_region: Optional[str] = Field(None, description="Cloud region")
    tags: Dict[str, str] = Field(default_factory=dict, description="Asset tags and metadata")
    
    class Config:
        schema_extra = {
            "example": {
                "asset_id": "A789012",
                "hostname": "workstation-01.corp.local",
                "ip_address": "192.168.1.100", 
                "mac_address": "00:1B:44:11:3A:B7",
                "asset_type": "workstation",
                "operating_system": "Windows",
                "os_version": "11 22H2",
                "location": "Building A",
                "subnet": "192.168.1.0/24",
                "vlan_id": 100,
                "zone": "corporate",
                "tags": {"criticality": "medium", "owner": "IT"}
            }
        }


class TacticTechnique(BaseModel):
    """MITRE ATT&CK Tactic and Technique mapping."""
    
    tactic_id: AttackTactic = Field(..., description="ATT&CK Tactic ID")
    tactic_name: str = Field(..., description="Human-readable tactic name")
    technique_id: str = Field(..., description="ATT&CK Technique ID (T1234)")  
    technique_name: str = Field(..., description="Human-readable technique name")
    subtechnique_id: Optional[str] = Field(None, description="ATT&CK Sub-technique ID (T1234.001)")
    subtechnique_name: Optional[str] = Field(None, description="Human-readable sub-technique name")
    mitre_url: Optional[str] = Field(None, description="MITRE ATT&CK URL reference")
    detection_notes: Optional[str] = Field(None, description="Notes on detection strategies")
    
    class Config:
        schema_extra = {
            "example": {
                "tactic_id": "TA0006", 
                "tactic_name": "Credential Access",
                "technique_id": "T1003",
                "technique_name": "OS Credential Dumping",
                "subtechnique_id": "T1003.001", 
                "subtechnique_name": "LSASS Memory",
                "mitre_url": "https://attack.mitre.org/techniques/T1003/001/",
                "detection_notes": "Monitor for unusual processes accessing LSASS memory"
            }
        }


class NetworkTuple(BaseModel):
    """Network 5-tuple for precise analytics correlation."""
    
    source_ip: str = Field(..., description="Source IP address")
    destination_ip: str = Field(..., description="Destination IP address")
    source_port: int = Field(..., ge=1, le=65535, description="Source port")
    destination_port: int = Field(..., ge=1, le=65535, description="Destination port")
    protocol: str = Field(..., description="Network protocol (TCP/UDP/ICMP)")
    
    def to_tuple(self) -> tuple:
        """Return as hashable tuple for analytics."""
        return (self.source_ip, self.destination_ip, self.source_port, self.destination_port, self.protocol)
    
    class Config:
        schema_extra = {
            "example": {
                "source_ip": "192.168.1.100",
                "destination_ip": "10.0.0.50",
                "source_port": 49152,
                "destination_port": 445,
                "protocol": "TCP"
            }
        }


class HeuristicPattern(BaseModel):
    """Heuristic behavioral pattern for analytics detection."""
    
    pattern_id: str = Field(..., description="Unique pattern identifier")
    pattern_name: str = Field(..., description="Human-readable pattern name")
    description: str = Field(..., description="Pattern description")
    
    # Pattern characteristics
    min_events: int = Field(5, ge=2, description="Minimum events to constitute pattern")
    max_events: int = Field(100, ge=5, description="Maximum events in pattern")
    time_window_seconds: float = Field(300.0, gt=0.0, description="Time window for pattern detection")
    
    # Network behavior signatures
    network_signatures: List[Dict[str, Any]] = Field(default_factory=list, description="Network behavior signatures")
    port_sequences: List[List[int]] = Field(default_factory=list, description="Expected port sequences")
    protocol_patterns: List[str] = Field(default_factory=list, description="Protocol patterns")
    
    # Behavioral indicators
    frequency_pattern: Optional[str] = Field(None, description="Frequency pattern (burst, periodic, etc.)")
    escalation_indicators: List[str] = Field(default_factory=list, description="Privilege escalation indicators")
    lateral_movement_indicators: List[str] = Field(default_factory=list, description="Lateral movement indicators")
    persistence_indicators: List[str] = Field(default_factory=list, description="Persistence indicators")
    
    class Config:
        schema_extra = {
            "example": {
                "pattern_id": "PERSIST_SMB_LATERAL",
                "pattern_name": "SMB Lateral Movement with Persistence",
                "description": "SMB connections followed by service creation for persistence",
                "min_events": 5,
                "time_window_seconds": 600.0,
                "network_signatures": [
                    {"dest_port": 445, "protocol": "TCP", "action": "connect"},
                    {"dest_port": 135, "protocol": "TCP", "action": "rpc_call"}
                ],
                "port_sequences": [[445, 135, 139]],
                "persistence_indicators": ["service_creation", "registry_modification"]
            }
        }


class BaseEvent(BaseModel):
    """Base event model with common fields and heuristic patterns."""
    
    # Core identifiers
    event_id: UUID = Field(default_factory=uuid4, description="Unique event identifier")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Event timestamp")
    scenario_id: Optional[UUID] = Field(None, description="Scenario run identifier")
    
    # Pattern correlation
    pattern_id: Optional[str] = Field(None, description="Associated heuristic pattern ID")
    burst_id: Optional[UUID] = Field(None, description="Burst sequence identifier for correlated events")
    sequence_number: Optional[int] = Field(None, description="Position in event sequence")
    
    # NICE and ATT&CK classification
    nice_category: NICECategory = Field(..., description="NICE framework category")
    tactic_technique: Optional[TacticTechnique] = Field(None, description="Associated ATT&CK TTP")
    
    # Source information
    vendor: str = Field(..., description="Vendor/manufacturer name")
    product: str = Field(..., description="Product name")
    product_version: Optional[str] = Field(None, description="Product version")
    
    # Event details
    event_name: str = Field(..., description="Event name or type")
    event_code: Optional[str] = Field(None, description="Vendor-specific event code")
    severity: SeverityLevel = Field(SeverityLevel.INFO, description="Event severity level")
    message: str = Field(..., description="Human-readable event message")
    
    # Enhanced Network 5-tuple for heuristics
    network_tuple: Optional[NetworkTuple] = Field(None, description="Network 5-tuple for analytics")
    
    # Legacy fields for backward compatibility
    source_ip: Optional[str] = Field(None, description="Source IP address (legacy)")
    destination_ip: Optional[str] = Field(None, description="Destination IP address (legacy)")
    source_port: Optional[int] = Field(None, ge=1, le=65535, description="Source port (legacy)")
    destination_port: Optional[int] = Field(None, ge=1, le=65535, description="Destination port (legacy)")
    protocol: Optional[str] = Field(None, description="Network protocol (legacy)")
    
    # Actors and assets involved
    actor: Optional[Actor] = Field(None, description="Primary actor/user")
    source_asset: Optional[Asset] = Field(None, description="Source asset")
    destination_asset: Optional[Asset] = Field(None, description="Destination asset")
    
    # Behavioral analysis fields
    connection_state: Optional[str] = Field(None, description="Network connection state")
    direction: Optional[str] = Field(None, description="Traffic direction (inbound, outbound, internal, unknown)")
    bytes_transferred: Optional[int] = Field(None, ge=0, description="Total bytes transferred")
    duration_ms: Optional[int] = Field(None, ge=0, description="Event duration in milliseconds")
    session_id: Optional[str] = Field(None, description="Network/application session ID")
    
    # Additional context
    indicators: List[str] = Field(default_factory=list, description="IoCs or indicators")
    labels: Dict[str, str] = Field(default_factory=dict, description="Event labels and tags")
    domain: Optional[str] = Field(None, description="Domain name involved (DNS/Identity/Application)")
    raw_data: Optional[Dict[str, Any]] = Field(None, description="Vendor-specific raw data")
    
    # Metadata
    generated_by: str = Field("xgen", description="Generator system identifier")
    generator_version: str = Field("1.0.0", description="Generator version")
    
    @validator('timestamp')
    def ensure_utc_timezone(cls, v):
        """Ensure timestamp is always UTC."""
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc)
    
    class Config:
        use_enum_values = True
        schema_extra = {
            "example": {
                "event_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
                "timestamp": "2023-10-03T14:30:00Z",
                "scenario_id": "a47ac10b-58cc-4372-a567-0e02b2c3d123",
                "nice_category": "identity",
                "vendor": "Microsoft", 
                "product": "Azure AD",
                "event_name": "UserLoggedIn",
                "severity": 6,
                "message": "User successfully logged in",
                "source_ip": "203.0.113.1",
                "generated_by": "xgen"
            }
        }


class NetworkEvent(BaseEvent):
    """Network-specific event extending BaseEvent."""
    nice_category: NICECategory = Field(NICECategory.NETWORK, const=True)
    
    # Network-specific fields
    bytes_in: Optional[int] = Field(None, ge=0, description="Bytes received")
    bytes_out: Optional[int] = Field(None, ge=0, description="Bytes sent")
    packets_in: Optional[int] = Field(None, ge=0, description="Packets received")
    packets_out: Optional[int] = Field(None, ge=0, description="Packets sent")
    connection_state: Optional[str] = Field(None, description="Connection state")
    rule_name: Optional[str] = Field(None, description="Firewall rule name")
    action: Optional[str] = Field(None, description="Allow/Deny/Drop action")
    url: Optional[str] = Field(None, description="URL if HTTP/HTTPS")
    user_agent: Optional[str] = Field(None, description="User agent string")
    

class IdentityEvent(BaseEvent):
    """Identity-specific event extending BaseEvent."""
    nice_category: NICECategory = Field(NICECategory.IDENTITY, const=True)
    
    # Identity-specific fields
    auth_method: Optional[str] = Field(None, description="Authentication method")
    mfa_method: Optional[str] = Field(None, description="MFA method used")
    session_id: Optional[str] = Field(None, description="Session identifier")
    application: Optional[str] = Field(None, description="Target application")
    resource: Optional[str] = Field(None, description="Accessed resource")
    permission_level: Optional[str] = Field(None, description="Permission level granted")
    group_memberships: List[str] = Field(default_factory=list, description="User group memberships")
    risk_score: Optional[float] = Field(None, ge=0.0, le=10.0, description="Calculated risk score")


class CloudEvent(BaseEvent):
    """Cloud-specific event extending BaseEvent.""" 
    nice_category: NICECategory = Field(NICECategory.CLOUD, const=True)
    
    # Cloud-specific fields
    cloud_provider: Optional[str] = Field(None, description="Cloud provider name")
    account_id: Optional[str] = Field(None, description="Cloud account identifier") 
    region: Optional[str] = Field(None, description="Cloud region")
    service_name: Optional[str] = Field(None, description="Cloud service name")
    api_call: Optional[str] = Field(None, description="API call made")
    resource_id: Optional[str] = Field(None, description="Resource identifier")
    resource_type: Optional[str] = Field(None, description="Type of cloud resource")
    resource_name: Optional[str] = Field(None, description="Resource name")
    request_id: Optional[str] = Field(None, description="Request correlation ID")
    user_identity_type: Optional[str] = Field(None, description="Type of user identity")
    

class EndpointEvent(BaseEvent):
    """Endpoint-specific event extending BaseEvent."""
    nice_category: NICECategory = Field(NICECategory.ENDPOINT, const=True)
    
    # Endpoint-specific fields
    process_name: Optional[str] = Field(None, description="Process name")
    process_id: Optional[int] = Field(None, description="Process ID")
    parent_process_name: Optional[str] = Field(None, description="Parent process name")
    parent_process_id: Optional[int] = Field(None, description="Parent process ID")
    command_line: Optional[str] = Field(None, description="Process command line")
    file_path: Optional[str] = Field(None, description="Process executable/file path")
    file_name: Optional[str] = Field(None, description="File name")
    file_hash: Optional[str] = Field(None, description="File hash (MD5/SHA1/SHA256)")
    process_sha256: Optional[str] = Field(None, description="Process SHA256 hash (if known)")
    registry_key: Optional[str] = Field(None, description="Registry key path")
    registry_value: Optional[str] = Field(None, description="Registry value")
    service_name: Optional[str] = Field(None, description="Windows service name")
    

class ScenarioStep(BaseModel):
    """Individual step in a scenario timeline."""
    
    step_id: str = Field(..., description="Unique step identifier")
    name: str = Field(..., description="Step name")
    description: Optional[str] = Field(None, description="Step description")
    tactic_technique: Optional[TacticTechnique] = Field(None, description="Associated TTP")
    
    # Timing
    offset_seconds: float = Field(0.0, ge=0.0, description="Offset from scenario start") 
    duration_seconds: Optional[float] = Field(None, ge=0.0, description="Step duration")
    
    # Event generation
    event_count: int = Field(1, ge=1, description="Number of events to generate")
    vendors: List[str] = Field(..., description="Target vendors for this step")
    nice_categories: List[NICECategory] = Field(..., description="NICE categories to target")
    
    # Dependencies and conditions
    depends_on: List[str] = Field(default_factory=list, description="Step dependencies")
    conditions: Dict[str, Any] = Field(default_factory=dict, description="Execution conditions")
    variables: Dict[str, Any] = Field(default_factory=dict, description="Step variables")
    

class Scenario(BaseModel):
    """Complete attack scenario with timeline and actors."""
    
    scenario_id: UUID = Field(default_factory=uuid4, description="Unique scenario identifier")
    name: str = Field(..., description="Scenario name")
    description: str = Field(..., description="Scenario description")
    author: Optional[str] = Field(None, description="Scenario author")
    version: str = Field("1.0.0", description="Scenario version")
    
    # Classification
    tactics_covered: List[AttackTactic] = Field(description="ATT&CK tactics covered")
    nice_categories: List[NICECategory] = Field(description="NICE categories involved")
    
    # Timeline and execution
    estimated_duration_seconds: float = Field(..., ge=0.0, description="Estimated scenario duration")
    steps: List[ScenarioStep] = Field(..., description="Scenario timeline steps")
    
    # Actors and assets
    actors: List[Actor] = Field(default_factory=list, description="Scenario actors")
    assets: List[Asset] = Field(default_factory=list, description="Scenario assets")
    
    # Configuration
    randomization_seed: Optional[int] = Field(None, description="Reproducibility seed")
    noise_level: float = Field(0.1, ge=0.0, le=1.0, description="Background noise level 0-1")
    variables: Dict[str, Any] = Field(default_factory=dict, description="Scenario variables")
    
    # Metadata
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    tags: List[str] = Field(default_factory=list, description="Scenario tags")
    
    class Config:
        use_enum_values = True


class GenerationConfig(BaseModel):
    """Configuration for log generation session."""
    
    # Output configuration
    formats: List[LogFormat] = Field([LogFormat.CEF], description="Output formats")
    transports: List[TransportType] = Field([TransportType.SYSLOG_UDP], description="Transport types")
    
    # Rate and volume
    events_per_second: float = Field(10.0, gt=0.0, description="Target events per second")
    total_events: Optional[int] = Field(None, gt=0, description="Total events to generate")
    duration_seconds: Optional[float] = Field(None, gt=0.0, description="Generation duration")
    
    # Content configuration  
    scenario: Optional[Scenario] = Field(None, description="Scenario to execute")
    nice_categories: List[NICECategory] = Field(list(NICECategory), description="NICE categories to include")
    vendors: List[str] = Field(default_factory=list, description="Vendors to include")
    severity_distribution: Dict[SeverityLevel, float] = Field(
        default_factory=lambda: {
            SeverityLevel.DEBUG: 0.3,
            SeverityLevel.INFO: 0.4, 
            SeverityLevel.WARNING: 0.2,
            SeverityLevel.ERROR: 0.08,
            SeverityLevel.CRITICAL: 0.02
        },
        description="Severity level distribution"
    )
    
    # Randomization
    randomization_seed: Optional[int] = Field(None, description="Reproducibility seed")
    add_noise: bool = Field(True, description="Add background noise events")
    noise_level: float = Field(0.1, ge=0.0, le=1.0, description="Noise level 0-1")
    
    # Output destinations
    output_file: Optional[str] = Field(None, description="Output file path")
    syslog_host: Optional[str] = Field(None, description="Syslog destination host")
    syslog_port: int = Field(514, ge=1, le=65535, description="Syslog destination port")
    
    @root_validator
    def validate_duration_or_events(cls, values):
        """Either duration_seconds or total_events must be specified."""
        duration = values.get('duration_seconds')
        events = values.get('total_events')
        if not duration and not events:
            raise ValueError("Either duration_seconds or total_events must be specified")
        return values
    
    class Config:
        use_enum_values = True