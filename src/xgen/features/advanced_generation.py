"""
Advanced Log Generation Features

This module provides advanced features for realistic log generation including
time correlation, user journey tracking, network flow correlation, and 
cross-vendor event sequencing for authentic attack simulation.
"""

import random
import uuid
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set, NamedTuple
from dataclasses import dataclass, field
from collections import defaultdict, deque
import ipaddress
import json

@dataclass
class UserSession:
    """Represents a user session across multiple systems."""
    user_id: str
    session_id: str
    start_time: datetime
    end_time: Optional[datetime] = None
    source_ip: str = ""
    user_agent: str = ""
    geo_location: str = ""
    devices: List[str] = field(default_factory=list)
    activities: List[Dict[str, Any]] = field(default_factory=list)
    risk_score: float = 0.0
    is_suspicious: bool = False

@dataclass 
class NetworkFlow:
    """Represents a network flow between endpoints."""
    flow_id: str
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    start_time: datetime
    end_time: Optional[datetime] = None
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    application: str = "unknown"
    classification: str = "normal"  # normal, suspicious, malicious

@dataclass
class AttackChainEvent:
    """Represents an event in an attack chain."""
    event_id: str
    technique_id: str
    timestamp: datetime
    vendor: str
    asset: str
    user: str
    source_ip: str
    destination_ip: str = ""
    severity: int = 1
    confidence: float = 0.8
    artifacts: Dict[str, Any] = field(default_factory=dict)
    parent_event_id: Optional[str] = None
    child_event_ids: List[str] = field(default_factory=list)

class TimeCorrelationEngine:
    """Engine for generating time-correlated events across vendors."""
    
    def __init__(self, time_skew_seconds: int = 60):
        self.time_skew_seconds = time_skew_seconds
        self.event_timeline = []
        
    def create_correlated_events(self, base_event: Dict[str, Any], 
                                vendors: List[str], 
                                correlation_window_minutes: int = 5) -> List[Dict[str, Any]]:
        """Create time-correlated events across multiple vendors."""
        correlated_events = []
        base_time = base_event.get('timestamp', datetime.now(timezone.utc))
        
        for vendor in vendors:
            # Create vendor-specific event with time correlation
            event = self._create_vendor_correlated_event(base_event, vendor, base_time)
            
            # Add realistic time skew (different systems may have slight time differences)
            time_skew = random.uniform(-self.time_skew_seconds, self.time_skew_seconds)
            event['timestamp'] = base_time + timedelta(seconds=time_skew)
            
            # Add correlation window jitter
            window_jitter = random.uniform(0, correlation_window_minutes * 60)
            event['timestamp'] += timedelta(seconds=window_jitter)
            
            correlated_events.append(event)
        
        return sorted(correlated_events, key=lambda x: x['timestamp'])
    
    def _create_vendor_correlated_event(self, base_event: Dict[str, Any], 
                                      vendor: str, base_time: datetime) -> Dict[str, Any]:
        """Create a vendor-specific correlated event."""
        event = base_event.copy()
        event['vendor'] = vendor
        event['correlation_id'] = base_event.get('correlation_id', str(uuid.uuid4()))
        
        # Vendor-specific event enrichment
        if vendor.lower() == 'palo_alto_networks':
            event.update({
                'firewall_rule': f"rule_{random.randint(1, 100)}",
                'vsys': 'vsys1',
                'zone_from': 'trust',
                'zone_to': 'untrust'
            })
        elif vendor.lower() == 'crowdstrike':
            event.update({
                'falcon_aid': f"aid_{uuid.uuid4().hex[:16]}",
                'process_graph_id': str(uuid.uuid4()),
                'detection_id': f"ldt:{uuid.uuid4().hex}"
            })
        elif vendor.lower() == 'microsoft_defender':
            event.update({
                'machine_id': str(uuid.uuid4()),
                'alert_id': f"da637{random.randint(100000, 999999)}",
                'investigation_id': random.randint(1000000, 9999999)
            })
        
        return event

class UserJourneyTracker:
    """Tracks user journeys across systems for realistic behavior simulation."""
    
    def __init__(self):
        self.active_sessions = {}
        self.user_profiles = self._initialize_user_profiles()
        self.behavior_patterns = self._initialize_behavior_patterns()
        
    def _initialize_user_profiles(self) -> Dict[str, Dict[str, Any]]:
        """Initialize realistic user profiles with behavior patterns."""
        return {
            "normal_user": {
                "login_times": ["08:00-09:00", "13:00-14:00"],  # Typical login windows
                "typical_duration_hours": (8, 10),
                "common_applications": ["email", "web", "file_share", "database"],
                "risk_multiplier": 1.0,
                "geo_locations": ["office", "home"],
                "devices": ["desktop", "laptop", "mobile"]
            },
            "power_user": {
                "login_times": ["07:00-08:00", "12:00-13:00", "18:00-19:00"],
                "typical_duration_hours": (10, 14),
                "common_applications": ["email", "web", "file_share", "database", "admin_tools", "dev_tools"],
                "risk_multiplier": 1.2,
                "geo_locations": ["office", "home", "remote"],
                "devices": ["desktop", "laptop", "mobile", "server"]
            },
            "admin_user": {
                "login_times": ["06:00-07:00", "22:00-23:00"],  # Early/late for maintenance
                "typical_duration_hours": (2, 12),
                "common_applications": ["admin_tools", "monitoring", "backup", "security_tools"],
                "risk_multiplier": 2.0,
                "geo_locations": ["office", "home", "datacenter"],
                "devices": ["desktop", "laptop", "server", "management_console"]
            },
            "suspicious_user": {
                "login_times": ["02:00-04:00", "23:00-01:00"],  # Unusual hours
                "typical_duration_hours": (1, 3),
                "common_applications": ["file_share", "database", "admin_tools"],
                "risk_multiplier": 5.0,
                "geo_locations": ["unknown", "foreign"],
                "devices": ["unknown_device"]
            }
        }
    
    def _initialize_behavior_patterns(self) -> Dict[str, List[str]]:
        """Initialize behavior patterns for different user types."""
        return {
            "normal_workflow": [
                "login", "check_email", "access_file_share", "use_application", 
                "lunch_break", "afternoon_work", "logout"
            ],
            "admin_workflow": [
                "privileged_login", "system_check", "maintenance_task", 
                "security_review", "backup_verification", "privileged_logout"
            ],
            "attack_workflow": [
                "initial_access", "credential_theft", "privilege_escalation",
                "lateral_movement", "data_collection", "exfiltration", "cleanup"
            ],
            "insider_threat": [
                "normal_login", "unusual_file_access", "bulk_download",
                "after_hours_activity", "external_transfer", "cleanup_attempt"
            ]
        }
    
    def create_user_journey(self, user_type: str, duration_hours: int = 8,
                          scenario: str = "normal_workflow") -> UserSession:
        """Create a realistic user journey with correlated activities."""
        user_profile = self.user_profiles.get(user_type, self.user_profiles["normal_user"])
        workflow = self.behavior_patterns.get(scenario, self.behavior_patterns["normal_workflow"])
        
        # Create session
        session = UserSession(
            user_id=self._generate_user_id(user_type),
            session_id=str(uuid.uuid4()),
            start_time=datetime.now(timezone.utc),
            source_ip=self._generate_user_ip(user_profile),
            user_agent=self._generate_user_agent(user_profile),
            geo_location=random.choice(user_profile["geo_locations"]),
            devices=[random.choice(user_profile["devices"])],
            risk_score=user_profile["risk_multiplier"],
            is_suspicious=user_type == "suspicious_user"
        )
        
        # Generate activities based on workflow
        session.activities = self._generate_workflow_activities(
            workflow, session, user_profile, duration_hours
        )
        
        session.end_time = session.start_time + timedelta(hours=duration_hours)
        
        return session
    
    def _generate_user_id(self, user_type: str) -> str:
        """Generate realistic user ID based on type."""
        prefixes = {
            "normal_user": ["john.doe", "alice.smith", "bob.wilson"],
            "power_user": ["sarah.manager", "mike.lead", "lisa.senior"],
            "admin_user": ["admin.user", "svc.admin", "system.admin"],
            "suspicious_user": ["temp.user", "contractor", "guest.user"]
        }
        
        base_names = prefixes.get(user_type, prefixes["normal_user"])
        return f"{random.choice(base_names)}{random.randint(1, 999)}"
    
    def _generate_user_ip(self, user_profile: Dict[str, Any]) -> str:
        """Generate realistic IP based on user profile."""
        if "office" in user_profile["geo_locations"]:
            # Corporate IP range
            return str(ipaddress.IPv4Address(f"10.{random.randint(1, 10)}.{random.randint(1, 254)}.{random.randint(1, 254)}"))
        elif "home" in user_profile["geo_locations"]:
            # Home IP ranges
            return str(ipaddress.IPv4Address(f"192.168.{random.randint(1, 10)}.{random.randint(1, 254)}"))
        else:
            # External/suspicious IP
            return str(ipaddress.IPv4Address(f"{random.randint(50, 200)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"))
    
    def _generate_user_agent(self, user_profile: Dict[str, Any]) -> str:
        """Generate realistic user agent string."""
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        ]
        
        if "mobile" in user_profile["devices"]:
            user_agents.extend([
                "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)",
                "Mozilla/5.0 (Android 11; Mobile; rv:68.0)"
            ])
        
        return random.choice(user_agents)
    
    def _generate_workflow_activities(self, workflow: List[str], session: UserSession,
                                    user_profile: Dict[str, Any], duration_hours: int) -> List[Dict[str, Any]]:
        """Generate activities based on workflow pattern."""
        activities = []
        current_time = session.start_time
        
        # Distribute activities across the session duration
        time_per_activity = timedelta(hours=duration_hours / len(workflow))
        
        for i, activity_type in enumerate(workflow):
            activity = {
                "activity_id": str(uuid.uuid4()),
                "activity_type": activity_type,
                "timestamp": current_time,
                "source_ip": session.source_ip,
                "user_agent": session.user_agent,
                "device": random.choice(session.devices),
                "risk_score": user_profile["risk_multiplier"],
                "details": self._generate_activity_details(activity_type, session)
            }
            
            activities.append(activity)
            
            # Add realistic time progression with some randomness
            time_advance = time_per_activity + timedelta(
                minutes=random.randint(-30, 30)
            )
            current_time += time_advance
        
        return activities
    
    def _generate_activity_details(self, activity_type: str, session: UserSession) -> Dict[str, Any]:
        """Generate detailed information for specific activity types."""
        details = {"session_id": session.session_id}
        
        activity_details = {
            "login": {
                "authentication_method": random.choice(["password", "mfa", "sso"]),
                "login_status": "success",
                "failed_attempts": 0
            },
            "check_email": {
                "emails_read": random.randint(5, 25),
                "attachments_downloaded": random.randint(0, 3),
                "external_emails": random.randint(0, 2)
            },
            "access_file_share": {
                "files_accessed": random.randint(2, 10),
                "files_modified": random.randint(0, 3),
                "folders_browsed": random.randint(1, 5)
            },
            "lateral_movement": {
                "target_systems": [f"server-{random.randint(1, 20)}" for _ in range(random.randint(1, 3))],
                "protocol": random.choice(["rdp", "ssh", "smb"]),
                "success": session.is_suspicious
            },
            "data_collection": {
                "files_collected": random.randint(10, 100),
                "data_volume_mb": random.randint(100, 10000),
                "file_types": random.sample(["docx", "xlsx", "pdf", "txt", "csv"], random.randint(2, 4))
            },
            "exfiltration": {
                "destination": random.choice(["cloud_storage", "ftp_server", "email"]),
                "data_volume_mb": random.randint(500, 50000),
                "encryption_used": session.is_suspicious
            }
        }
        
        details.update(activity_details.get(activity_type, {}))
        return details

class NetworkFlowCorrelator:
    """Correlates network flows to create realistic traffic patterns."""
    
    def __init__(self):
        self.active_flows = {}
        self.flow_templates = self._initialize_flow_templates()
        
    def _initialize_flow_templates(self) -> Dict[str, Dict[str, Any]]:
        """Initialize network flow templates for different scenarios."""
        return {
            "web_browsing": {
                "protocol": "TCP",
                "destination_ports": [80, 443, 8080],
                "typical_duration_minutes": (1, 30),
                "bytes_ratio": (1, 10),  # download much more than upload
                "packet_size_range": (64, 1500)
            },
            "file_transfer": {
                "protocol": "TCP", 
                "destination_ports": [21, 22, 445, 2049],
                "typical_duration_minutes": (5, 120),
                "bytes_ratio": (1, 1),  # balanced transfer
                "packet_size_range": (1000, 1500)
            },
            "database_query": {
                "protocol": "TCP",
                "destination_ports": [1433, 1521, 3306, 5432],
                "typical_duration_minutes": (0.1, 5),
                "bytes_ratio": (1, 5),  # more data retrieved than sent
                "packet_size_range": (100, 1000)
            },
            "c2_communication": {
                "protocol": "TCP",
                "destination_ports": [80, 443, 8080, 53],
                "typical_duration_minutes": (0.5, 2),
                "bytes_ratio": (1, 1),  # balanced but small amounts
                "packet_size_range": (64, 200),
                "is_suspicious": True
            },
            "data_exfiltration": {
                "protocol": "TCP",
                "destination_ports": [443, 80, 21],
                "typical_duration_minutes": (10, 300),
                "bytes_ratio": (10, 1),  # heavy upload
                "packet_size_range": (1000, 1500),
                "is_suspicious": True
            }
        }
    
    def create_correlated_flows(self, base_activity: Dict[str, Any],
                              flow_count: int = 5) -> List[NetworkFlow]:
        """Create correlated network flows based on activity."""
        flows = []
        activity_type = base_activity.get('activity_type', 'web_browsing')
        
        # Map activity types to flow types
        flow_type_mapping = {
            "check_email": "web_browsing",
            "access_file_share": "file_transfer", 
            "use_application": "database_query",
            "lateral_movement": "file_transfer",
            "data_collection": "file_transfer",
            "exfiltration": "data_exfiltration"
        }
        
        flow_type = flow_type_mapping.get(activity_type, "web_browsing")
        template = self.flow_templates[flow_type]
        
        base_time = base_activity.get('timestamp', datetime.now(timezone.utc))
        source_ip = base_activity.get('source_ip', '10.1.1.100')
        
        for i in range(flow_count):
            flow = self._create_flow_from_template(template, base_time, source_ip)
            flows.append(flow)
            
            # Add slight time offset for multiple flows
            base_time += timedelta(seconds=random.randint(1, 30))
        
        return flows
    
    def _create_flow_from_template(self, template: Dict[str, Any], 
                                 start_time: datetime, source_ip: str) -> NetworkFlow:
        """Create a network flow from template."""
        duration_minutes = random.uniform(*template["typical_duration_minutes"])
        end_time = start_time + timedelta(minutes=duration_minutes)
        
        # Generate destination IP based on flow type
        if template.get("is_suspicious", False):
            # External suspicious IP
            dest_ip = f"{random.randint(180, 220)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
        else:
            # Internal or legitimate external IP
            if random.random() < 0.7:  # 70% internal
                dest_ip = f"10.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
            else:  # 30% external legitimate
                dest_ip = f"{random.randint(1, 179)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
        
        # Calculate realistic byte counts
        packet_size = random.randint(*template["packet_size_range"])
        duration_seconds = duration_minutes * 60
        packets_per_second = random.uniform(1, 100)
        
        total_packets = int(duration_seconds * packets_per_second)
        total_bytes = total_packets * packet_size
        
        # Apply upload/download ratio
        upload_ratio, download_ratio = template["bytes_ratio"]
        total_ratio = upload_ratio + download_ratio
        
        bytes_sent = int(total_bytes * (upload_ratio / total_ratio))
        bytes_received = int(total_bytes * (download_ratio / total_ratio))
        
        packets_sent = int(total_packets * (upload_ratio / total_ratio))
        packets_received = int(total_packets * (download_ratio / total_ratio))
        
        flow = NetworkFlow(
            flow_id=str(uuid.uuid4()),
            source_ip=source_ip,
            destination_ip=dest_ip,
            source_port=random.randint(1024, 65535),
            destination_port=random.choice(template["destination_ports"]),
            protocol=template["protocol"],
            start_time=start_time,
            end_time=end_time,
            bytes_sent=bytes_sent,
            bytes_received=bytes_received,
            packets_sent=packets_sent,
            packets_received=packets_received,
            application=self._determine_application(template["destination_ports"][0]),
            classification="suspicious" if template.get("is_suspicious", False) else "normal"
        )
        
        return flow
    
    def _determine_application(self, port: int) -> str:
        """Determine application based on port."""
        port_app_mapping = {
            80: "HTTP", 443: "HTTPS", 21: "FTP", 22: "SSH",
            25: "SMTP", 53: "DNS", 445: "SMB", 1433: "MSSQL",
            1521: "Oracle", 3306: "MySQL", 5432: "PostgreSQL",
            2049: "NFS", 8080: "HTTP-Alt", 3389: "RDP"
        }
        return port_app_mapping.get(port, "Unknown")

class AttackChainOrchestrator:
    """Orchestrates realistic attack chains across multiple vendors and time."""
    
    def __init__(self):
        self.time_correlator = TimeCorrelationEngine()
        self.user_tracker = UserJourneyTracker()
        self.flow_correlator = NetworkFlowCorrelator()
        self.active_chains = {}
        
    def create_attack_chain(self, attack_type: str, target_user: str,
                          vendors: List[str], duration_hours: int = 24) -> List[AttackChainEvent]:
        """Create a complete attack chain with correlated events."""
        chain_id = str(uuid.uuid4())
        
        # Create user journey for the attack
        user_journey = self.user_tracker.create_user_journey(
            "suspicious_user" if "insider" not in attack_type else "normal_user",
            duration_hours,
            f"{attack_type}_workflow" if f"{attack_type}_workflow" in self.user_tracker.behavior_patterns else "attack_workflow"
        )
        
        # Generate attack chain events
        attack_events = []
        
        for i, activity in enumerate(user_journey.activities):
            # Create base event
            base_event = AttackChainEvent(
                event_id=str(uuid.uuid4()),
                technique_id=self._map_activity_to_technique(activity['activity_type']),
                timestamp=activity['timestamp'],
                vendor=random.choice(vendors),  # Primary detecting vendor
                asset=f"asset-{random.randint(1, 100)}",
                user=target_user,
                source_ip=activity['source_ip'],
                destination_ip=self._generate_target_ip(activity),
                severity=self._calculate_severity(activity),
                confidence=random.uniform(0.7, 0.95),
                artifacts=activity['details']
            )
            
            # Set parent-child relationships
            if i > 0:
                base_event.parent_event_id = attack_events[-1].event_id
                attack_events[-1].child_event_ids.append(base_event.event_id)
            
            attack_events.append(base_event)
            
            # Create correlated events across other vendors
            correlated_events = self._create_correlated_detection_events(
                base_event, [v for v in vendors if v != base_event.vendor]
            )
            attack_events.extend(correlated_events)
            
            # Generate network flows for this activity
            flows = self.flow_correlator.create_correlated_flows(activity)
            
            # Convert flows to events for network monitoring vendors
            flow_events = self._convert_flows_to_events(flows, vendors)
            attack_events.extend(flow_events)
        
        # Sort all events by timestamp
        attack_events.sort(key=lambda x: x.timestamp)
        
        # Store active chain
        self.active_chains[chain_id] = {
            "attack_type": attack_type,
            "events": attack_events,
            "user_journey": user_journey,
            "start_time": user_journey.start_time,
            "end_time": user_journey.end_time
        }
        
        return attack_events
    
    def _map_activity_to_technique(self, activity_type: str) -> str:
        """Map activity types to MITRE ATT&CK technique IDs."""
        technique_mapping = {
            "login": "T1078.004",  # Valid Accounts - Cloud
            "initial_access": "T1566.001",  # Spearphishing Attachment
            "credential_theft": "T1003.001",  # LSASS Memory
            "privilege_escalation": "T1055",  # Process Injection
            "lateral_movement": "T1021.001",  # Remote Desktop Protocol
            "data_collection": "T1005",  # Data from Local System
            "exfiltration": "T1041",  # Exfiltration Over C2 Channel
            "cleanup": "T1070.004",  # File Deletion
            "unusual_file_access": "T1083",  # File and Directory Discovery
            "bulk_download": "T1005",  # Data from Local System
            "after_hours_activity": "T1078",  # Valid Accounts
            "external_transfer": "T1567.002"  # Exfiltration to Cloud Storage
        }
        
        return technique_mapping.get(activity_type, "T1000")  # Default/unknown
    
    def _generate_target_ip(self, activity: Dict[str, Any]) -> str:
        """Generate realistic target IP based on activity."""
        activity_type = activity['activity_type']
        
        if activity_type in ['exfiltration', 'external_transfer']:
            # External IP for exfiltration
            return f"{random.randint(50, 200)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
        elif activity_type in ['lateral_movement', 'data_collection']:
            # Internal server IP
            return f"10.{random.randint(10, 50)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
        else:
            # General internal IP
            return f"10.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
    
    def _calculate_severity(self, activity: Dict[str, Any]) -> int:
        """Calculate severity based on activity and risk score."""
        base_severity = {
            "login": 1,
            "check_email": 1,
            "initial_access": 4,
            "credential_theft": 5,
            "privilege_escalation": 4,
            "lateral_movement": 4,
            "data_collection": 3,
            "exfiltration": 5,
            "cleanup": 2
        }
        
        activity_type = activity['activity_type']
        severity = base_severity.get(activity_type, 2)
        
        # Adjust based on risk score
        risk_score = activity.get('risk_score', 1.0)
        if risk_score > 3.0:
            severity = min(5, severity + 1)
        
        return severity
    
    def _create_correlated_detection_events(self, base_event: AttackChainEvent, 
                                          vendors: List[str]) -> List[AttackChainEvent]:
        """Create correlated detection events across vendors."""
        correlated_events = []
        
        for vendor in vendors:
            # Not all vendors detect all events
            detection_probability = self._get_vendor_detection_probability(
                vendor, base_event.technique_id
            )
            
            if random.random() < detection_probability:
                correlated_event = AttackChainEvent(
                    event_id=str(uuid.uuid4()),
                    technique_id=base_event.technique_id,
                    timestamp=base_event.timestamp + timedelta(
                        seconds=random.randint(-30, 300)  # Detection delay
                    ),
                    vendor=vendor,
                    asset=base_event.asset,
                    user=base_event.user,
                    source_ip=base_event.source_ip,
                    destination_ip=base_event.destination_ip,
                    severity=max(1, base_event.severity - random.randint(0, 1)),  # Slightly lower severity
                    confidence=max(0.5, base_event.confidence - random.uniform(0, 0.2)),
                    artifacts=self._generate_vendor_specific_artifacts(vendor, base_event),
                    parent_event_id=base_event.event_id
                )
                
                correlated_events.append(correlated_event)
                base_event.child_event_ids.append(correlated_event.event_id)
        
        return correlated_events
    
    def _get_vendor_detection_probability(self, vendor: str, technique_id: str) -> float:
        """Get probability that vendor detects specific technique."""
        # Vendor detection capabilities (simplified)
        vendor_capabilities = {
            "microsoft_defender": {
                "T1566.001": 0.9, "T1059.001": 0.9, "T1055": 0.8, "T1003.001": 0.95
            },
            "crowdstrike": {
                "T1566.001": 0.85, "T1059.001": 0.9, "T1055": 0.9, "T1003.001": 0.9
            },
            "fortinet": {
                "T1071.001": 0.8, "T1041": 0.7, "T1105": 0.75
            },
            "splunk": {
                "T1078": 0.9, "T1110.003": 0.85, "T1021.001": 0.8
            }
        }
        
        vendor_key = vendor.lower().replace(" ", "_")
        return vendor_capabilities.get(vendor_key, {}).get(technique_id, 0.3)  # Default 30%
    
    def _generate_vendor_specific_artifacts(self, vendor: str, 
                                          base_event: AttackChainEvent) -> Dict[str, Any]:
        """Generate vendor-specific artifacts for correlated events."""
        base_artifacts = base_event.artifacts.copy()
        
        vendor_specific = {
            "microsoft_defender": {
                "alert_id": f"da637{random.randint(100000, 999999)}",
                "machine_id": str(uuid.uuid4()),
                "detection_source": "EDR"
            },
            "crowdstrike": {
                "detection_id": f"ldt:{uuid.uuid4().hex}",
                "falcon_aid": f"aid_{uuid.uuid4().hex[:16]}",
                "process_graph_id": str(uuid.uuid4())
            },
            "fortinet": {
                "policy_id": random.randint(1, 100),
                "session_id": random.randint(100000, 999999),
                "device_name": "FortiGate-VM"
            },
            "splunk": {
                "search_id": f"search_{uuid.uuid4().hex[:8]}",
                "correlation_search": f"Notable-{base_event.technique_id}",
                "urgency": "high" if base_event.severity >= 4 else "medium"
            }
        }
        
        vendor_key = vendor.lower().replace(" ", "_")
        base_artifacts.update(vendor_specific.get(vendor_key, {}))
        
        return base_artifacts
    
    def _convert_flows_to_events(self, flows: List[NetworkFlow], 
                               vendors: List[str]) -> List[AttackChainEvent]:
        """Convert network flows to attack chain events."""
        flow_events = []
        
        # Only network-focused vendors generate flow events
        network_vendors = [v for v in vendors if v.lower() in ['fortinet', 'zscaler', 'darktrace']]
        
        for flow in flows:
            if flow.classification == "suspicious" or random.random() < 0.1:  # 10% of normal flows generate events
                vendor = random.choice(network_vendors) if network_vendors else vendors[0]
                
                event = AttackChainEvent(
                    event_id=str(uuid.uuid4()),
                    technique_id="T1071.001" if flow.classification == "suspicious" else "T1030",
                    timestamp=flow.start_time,
                    vendor=vendor,
                    asset=f"network-{flow.source_ip.split('.')[2]}",
                    user="network_flow",
                    source_ip=flow.source_ip,
                    destination_ip=flow.destination_ip,
                    severity=3 if flow.classification == "suspicious" else 1,
                    confidence=0.8 if flow.classification == "suspicious" else 0.3,
                    artifacts={
                        "flow_id": flow.flow_id,
                        "protocol": flow.protocol,
                        "source_port": flow.source_port,
                        "destination_port": flow.destination_port,
                        "bytes_sent": flow.bytes_sent,
                        "bytes_received": flow.bytes_received,
                        "application": flow.application,
                        "classification": flow.classification
                    }
                )
                
                flow_events.append(event)
        
        return flow_events

# Convenience functions for easy usage
def create_realistic_user_session(user_type: str = "normal_user", 
                                duration_hours: int = 8) -> UserSession:
    """Create a realistic user session with correlated activities."""
    tracker = UserJourneyTracker()
    return tracker.create_user_journey(user_type, duration_hours)

def generate_attack_scenario(attack_type: str, vendors: List[str], 
                           duration_hours: int = 24) -> List[AttackChainEvent]:
    """Generate a complete attack scenario with correlated events."""
    orchestrator = AttackChainOrchestrator()
    return orchestrator.create_attack_chain(attack_type, "target.user", vendors, duration_hours)

def correlate_events_across_time(base_events: List[Dict[str, Any]], 
                                vendors: List[str]) -> List[Dict[str, Any]]:
    """Correlate events across time and vendors."""
    correlator = TimeCorrelationEngine()
    all_correlated_events = []
    
    for event in base_events:
        correlated = correlator.create_correlated_events(event, vendors)
        all_correlated_events.extend(correlated)
    
    return sorted(all_correlated_events, key=lambda x: x['timestamp'])

# Export main classes and functions
__all__ = [
    "UserSession", "NetworkFlow", "AttackChainEvent", 
    "TimeCorrelationEngine", "UserJourneyTracker", "NetworkFlowCorrelator",
    "AttackChainOrchestrator", "create_realistic_user_session",
    "generate_attack_scenario", "correlate_events_across_time"
]