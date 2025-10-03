"""
Burst Generation Engine for Heuristic Pattern Implementation.

This module generates coordinated bursts of events that follow specific
network and behavioral patterns to trigger analytics detection systems.
Events are generated in waves of 5+ with precise 5-tuple correlation.
"""

import random
import time
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional, Tuple, Iterator
from uuid import UUID, uuid4

from faker import Faker

from .models import (
    BaseEvent, NetworkEvent, IdentityEvent, CloudEvent, EndpointEvent,
    NetworkTuple, HeuristicPattern, NICECategory, SeverityLevel,
    AttackTactic, TacticTechnique, Actor, Asset
)
from ..ttp.mitre_patterns import (
    get_pattern_by_id, get_patterns_by_apt_group, APTGroup
)


class BurstGenerator:
    """
    Generates coordinated event bursts based on heuristic patterns.
    
    Creates waves of events with specific network 5-tuple signatures
    designed to trigger behavioral analytics and detection systems.
    """
    
    def __init__(self, seed: Optional[int] = None):
        """Initialize the burst generator."""
        self.fake = Faker()
        if seed:
            random.seed(seed)
            Faker.seed(seed)
        
        # Network pools for realistic address assignment
        self.internal_networks = [
            "192.168.1.0/24", "10.0.0.0/16", "172.16.0.0/12"
        ]
        self.external_networks = [
            "203.0.113.0/24", "198.51.100.0/24", "209.165.201.0/24"
        ]
        
        # Common port pools by service
        self.ephemeral_ports = list(range(49152, 65536))
        self.service_ports = {
            "smb": [445, 139],
            "rpc": [135, 593],
            "rdp": [3389],
            "ssh": [22, 2222],
            "http": [80, 8080, 8000],
            "https": [443, 8443],
            "dns": [53],
            "ldap": [389, 636],
            "kerberos": [88],
            "winrm": [5985, 5986]
        }
    
    def generate_pattern_burst(
        self,
        pattern: HeuristicPattern,
        scenario_id: Optional[UUID] = None,
        actors: Optional[List[Actor]] = None,
        assets: Optional[List[Asset]] = None
    ) -> List[BaseEvent]:
        """
        Generate a coordinated burst of events following a specific pattern.
        
        Args:
            pattern: The heuristic pattern to implement
            scenario_id: Optional scenario identifier for correlation
            actors: Optional list of actors to use in events
            assets: Optional list of assets to use in events
            
        Returns:
            List of correlated events implementing the pattern
        """
        
        burst_id = uuid4()
        events = []
        
        # Determine number of events in this burst
        event_count = random.randint(pattern.min_events, pattern.max_events)
        
        # Generate base timeline with jitter
        base_time = datetime.now(timezone.utc)
        event_times = self._generate_event_timeline(
            base_time, event_count, pattern.time_window_seconds
        )
        
        # Select or generate actors and assets
        primary_actor = self._select_or_generate_actor(actors)
        source_asset = self._select_or_generate_asset(assets, "source")
        target_assets = self._select_or_generate_targets(assets, event_count)
        
        # Generate network 5-tuples following pattern signatures
        network_tuples = self._generate_pattern_network_tuples(
            pattern, source_asset, target_assets, event_count
        )
        
        # Generate events based on pattern type
        for i in range(event_count):
            event = self._create_pattern_event(
                pattern=pattern,
                sequence_number=i + 1,
                timestamp=event_times[i],
                burst_id=burst_id,
                scenario_id=scenario_id,
                actor=primary_actor,
                source_asset=source_asset,
                target_asset=target_assets[i % len(target_assets)],
                network_tuple=network_tuples[i]
            )
            events.append(event)
        
        return events
    
    def generate_apt_campaign(
        self,
        apt_group: str,
        duration_hours: float = 2.0,
        intensity: str = "medium"
    ) -> List[BaseEvent]:
        """
        Generate a realistic APT campaign with multiple coordinated bursts.
        
        Args:
            apt_group: APT group identifier (e.g., APTGroup.APT29)
            duration_hours: Campaign duration in hours
            intensity: Campaign intensity (low/medium/high)
            
        Returns:
            List of events representing the complete campaign
        """
        
        patterns = get_patterns_by_apt_group(apt_group)
        if not patterns:
            raise ValueError(f"No patterns found for APT group: {apt_group}")
        
        campaign_id = uuid4()
        all_events = []
        
        # Campaign parameters based on intensity
        intensity_params = {
            "low": {"bursts_per_hour": 1, "concurrent_patterns": 1},
            "medium": {"bursts_per_hour": 3, "concurrent_patterns": 2}, 
            "high": {"bursts_per_hour": 6, "concurrent_patterns": 3}
        }
        
        params = intensity_params.get(intensity, intensity_params["medium"])
        total_bursts = int(duration_hours * params["bursts_per_hour"])
        
        # Generate persistent actors and infrastructure
        campaign_actors = [self._generate_apt_actor(apt_group) for _ in range(3)]
        campaign_assets = [self._generate_infrastructure_asset() for _ in range(5)]
        target_assets = [self._generate_target_asset() for _ in range(10)]
        
        # Generate timeline of bursts
        campaign_start = datetime.now(timezone.utc)
        burst_times = self._generate_campaign_timeline(
            campaign_start, total_bursts, duration_hours
        )
        
        # Generate bursts with pattern progression
        for i, burst_time in enumerate(burst_times):
            # Select patterns for this burst (APT groups often use specific sequences)
            active_patterns = self._select_patterns_for_burst(
                patterns, i, total_bursts, params["concurrent_patterns"]
            )
            
            for pattern in active_patterns:
                # Generate burst with campaign context
                burst_events = self.generate_pattern_burst(
                    pattern=pattern,
                    scenario_id=campaign_id,
                    actors=campaign_actors,
                    assets=campaign_assets + target_assets
                )
                
                # Adjust timestamps to burst time
                time_offset = (burst_time - campaign_start).total_seconds()
                for event in burst_events:
                    event.timestamp = event.timestamp + timedelta(seconds=time_offset)
                
                all_events.extend(burst_events)
        
        # Sort events by timestamp
        all_events.sort(key=lambda e: e.timestamp)
        
        return all_events
    
    def _generate_event_timeline(
        self, 
        base_time: datetime, 
        event_count: int, 
        window_seconds: float
    ) -> List[datetime]:
        """Generate realistic event timeline with clustering."""
        
        times = []
        
        # Create time clusters based on pattern frequency
        if window_seconds <= 300:  # Rapid burst
            # Events clustered in first 30% of window
            cluster_window = window_seconds * 0.3
            for i in range(event_count):
                offset = random.uniform(0, cluster_window) + (i * 2)  # Small progressive delay
                times.append(base_time + timedelta(seconds=offset))
        
        elif window_seconds <= 1200:  # Medium burst  
            # Events spread across window with some clustering
            for i in range(event_count):
                cluster_offset = (i // 3) * (window_seconds / 4)  # Group every 3 events
                random_offset = random.uniform(0, window_seconds / 8)
                total_offset = cluster_offset + random_offset
                times.append(base_time + timedelta(seconds=total_offset))
        
        else:  # Extended campaign
            # Events spread more evenly with realistic gaps
            for i in range(event_count):
                base_offset = (i * window_seconds) / event_count
                jitter = random.uniform(-window_seconds * 0.1, window_seconds * 0.1)
                total_offset = base_offset + jitter
                times.append(base_time + timedelta(seconds=max(0, total_offset)))
        
        return sorted(times)
    
    def _generate_pattern_network_tuples(
        self,
        pattern: HeuristicPattern,
        source_asset: Asset,
        target_assets: List[Asset], 
        event_count: int
    ) -> List[NetworkTuple]:
        """Generate network 5-tuples matching pattern signatures."""
        
        tuples = []
        source_ip = source_asset.ip_address or self._generate_internal_ip()
        
        # Extract expected port sequences from pattern
        port_sequences = pattern.port_sequences
        network_signatures = pattern.network_signatures
        
        for i in range(event_count):
            target_asset = target_assets[i % len(target_assets)]
            dest_ip = target_asset.ip_address or self._generate_target_ip(pattern)
            
            # Select appropriate port sequence
            if port_sequences:
                sequence = random.choice(port_sequences)
                dest_port = sequence[i % len(sequence)]
            else:
                # Fall back to signature-based port selection
                dest_port = self._select_port_from_signatures(network_signatures)
            
            # Generate realistic source port
            source_port = random.choice(self.ephemeral_ports)
            
            # Determine protocol from pattern or signatures
            protocol = self._determine_protocol(pattern, network_signatures)
            
            tuple_obj = NetworkTuple(
                source_ip=source_ip,
                destination_ip=dest_ip,
                source_port=source_port,
                destination_port=dest_port,
                protocol=protocol
            )
            
            tuples.append(tuple_obj)
        
        return tuples
    
    def _create_pattern_event(
        self,
        pattern: HeuristicPattern,
        sequence_number: int,
        timestamp: datetime,
        burst_id: UUID,
        scenario_id: Optional[UUID],
        actor: Actor,
        source_asset: Asset,
        target_asset: Asset,
        network_tuple: NetworkTuple
    ) -> BaseEvent:
        """Create a specific event based on pattern and context."""
        
        # Determine event type based on pattern characteristics
        nice_category = self._infer_nice_category(pattern)
        
        # Create appropriate event subclass
        if nice_category == NICECategory.NETWORK:
            event = NetworkEvent(
                nice_category=nice_category,
                vendor=self._select_vendor_for_pattern(pattern),
                product=self._select_product_for_vendor_category(nice_category),
                event_name=self._generate_event_name(pattern, sequence_number),
                message=self._generate_event_message(pattern, sequence_number, network_tuple),
                severity=self._determine_event_severity(pattern, sequence_number),
                timestamp=timestamp,
                pattern_id=pattern.pattern_id,
                burst_id=burst_id,
                scenario_id=scenario_id,
                sequence_number=sequence_number,
                network_tuple=network_tuple,
                actor=actor,
                source_asset=source_asset,
                destination_asset=target_asset,
                # Network-specific fields
                bytes_transferred=self._generate_bytes_transferred(pattern),
                connection_state="ESTABLISHED" if sequence_number > 1 else "SYN_SENT",
                action=self._determine_network_action(pattern, sequence_number)
            )
            
        elif nice_category == NICECategory.IDENTITY:
            event = IdentityEvent(
                nice_category=nice_category,
                vendor=self._select_vendor_for_pattern(pattern),
                product=self._select_product_for_vendor_category(nice_category),
                event_name=self._generate_event_name(pattern, sequence_number),
                message=self._generate_event_message(pattern, sequence_number, network_tuple),
                severity=self._determine_event_severity(pattern, sequence_number),
                timestamp=timestamp,
                pattern_id=pattern.pattern_id,
                burst_id=burst_id,
                scenario_id=scenario_id,
                sequence_number=sequence_number,
                network_tuple=network_tuple,
                actor=actor,
                source_asset=source_asset,
                destination_asset=target_asset,
                # Identity-specific fields
                auth_method=self._determine_auth_method(pattern),
                session_id=str(uuid4())[:8],
                application=self._determine_target_application(pattern)
            )
            
        elif nice_category == NICECategory.CLOUD:
            event = CloudEvent(
                nice_category=nice_category,
                vendor=self._select_vendor_for_pattern(pattern),
                product=self._select_product_for_vendor_category(nice_category),
                event_name=self._generate_event_name(pattern, sequence_number),
                message=self._generate_event_message(pattern, sequence_number, network_tuple),
                severity=self._determine_event_severity(pattern, sequence_number),
                timestamp=timestamp,
                pattern_id=pattern.pattern_id,
                burst_id=burst_id,
                scenario_id=scenario_id,
                sequence_number=sequence_number,
                network_tuple=network_tuple,
                actor=actor,
                source_asset=source_asset,
                destination_asset=target_asset,
                # Cloud-specific fields
                cloud_provider=self._determine_cloud_provider(pattern),
                account_id=self._generate_cloud_account_id(),
                region=self._select_cloud_region(),
                api_call=self._determine_api_call(pattern, sequence_number),
                request_id=str(uuid4())
            )
            
        else:  # Endpoint
            event = EndpointEvent(
                nice_category=nice_category,
                vendor=self._select_vendor_for_pattern(pattern),
                product=self._select_product_for_vendor_category(nice_category),
                event_name=self._generate_event_name(pattern, sequence_number),
                message=self._generate_event_message(pattern, sequence_number, network_tuple),
                severity=self._determine_event_severity(pattern, sequence_number),
                timestamp=timestamp,
                pattern_id=pattern.pattern_id,
                burst_id=burst_id,
                scenario_id=scenario_id,
                sequence_number=sequence_number,
                network_tuple=network_tuple,
                actor=actor,
                source_asset=source_asset,
                destination_asset=target_asset,
                # Endpoint-specific fields
                process_name=self._determine_process_name(pattern, sequence_number),
                process_id=random.randint(1000, 9999),
                command_line=self._generate_command_line(pattern, sequence_number),
                file_path=self._generate_file_path(pattern)
            )
        
        # Add legacy fields for backward compatibility
        event.source_ip = network_tuple.source_ip
        event.destination_ip = network_tuple.destination_ip
        event.source_port = network_tuple.source_port
        event.destination_port = network_tuple.destination_port
        event.protocol = network_tuple.protocol
        
        return event
    
    # Helper methods for realistic data generation
    
    def _generate_internal_ip(self) -> str:
        """Generate a realistic internal IP address."""
        network = random.choice(["192.168.1", "10.0.0", "172.16.1"])
        host = random.randint(10, 254)
        return f"{network}.{host}"
    
    def _generate_target_ip(self, pattern: HeuristicPattern) -> str:
        """Generate target IP based on pattern context."""
        if "CLOUD" in pattern.pattern_id:
            # Cloud targets are often external
            return self.fake.ipv4_public()
        elif "LATERAL" in pattern.pattern_id:
            # Lateral movement targets are internal
            return self._generate_internal_ip()
        else:
            # Mix of internal and external based on pattern
            return random.choice([self._generate_internal_ip(), self.fake.ipv4_public()])
    
    def _infer_nice_category(self, pattern: HeuristicPattern) -> NICECategory:
        """Infer NICE category from pattern characteristics."""
        pattern_id = pattern.pattern_id.lower()
        
        if "cloud" in pattern_id:
            return NICECategory.CLOUD
        elif any(term in pattern_id for term in ["account", "user", "auth", "token", "cred"]):
            return NICECategory.IDENTITY
        elif any(term in pattern_id for term in ["lateral", "smb", "rdp", "ssh"]):
            return NICECategory.NETWORK
        else:
            return NICECategory.ENDPOINT
    
    def _select_vendor_for_pattern(self, pattern: HeuristicPattern) -> str:
        """Select appropriate vendor based on pattern context."""
        pattern_id = pattern.pattern_id.lower()
        
        vendor_mapping = {
            "cloud": ["Microsoft", "Amazon", "Google", "Azure"],
            "smb": ["Microsoft", "Palo Alto Networks", "CrowdStrike"],
            "rdp": ["Microsoft", "CrowdStrike", "SentinelOne"],
            "ssh": ["Linux", "CrowdStrike", "Zeek"],
            "service": ["Microsoft", "CrowdStrike", "SentinelOne"],
            "registry": ["Microsoft", "CrowdStrike", "SentinelOne"],
            "task": ["Microsoft", "CrowdStrike"]
        }
        
        for key, vendors in vendor_mapping.items():
            if key in pattern_id:
                return random.choice(vendors)
        
        return "Microsoft"  # Default
    
    def _select_product_for_vendor_category(self, nice_category: NICECategory) -> str:
        """Select product based on vendor and NICE category."""
        products = {
            NICECategory.NETWORK: ["PAN-OS", "ASA", "Windows Firewall", "Zeek", "Suricata"],
            NICECategory.IDENTITY: ["Azure AD", "Active Directory", "Okta", "Duo"],
            NICECategory.CLOUD: ["CloudTrail", "Azure Monitor", "Cloud Audit Logs"],
            NICECategory.ENDPOINT: ["Defender for Endpoint", "Falcon", "Sysmon", "Event Log"]
        }
        
        return random.choice(products.get(nice_category, ["Unknown"]))
    
    def _generate_event_name(self, pattern: HeuristicPattern, sequence: int) -> str:
        """Generate contextual event name based on pattern and sequence."""
        base_names = {
            "SERVICE": ["ServiceInstalled", "ServiceStarted", "ServiceCreated"],
            "REGISTRY": ["RegistryValueSet", "RegistryKeyCreated", "RegEdit"],
            "LATERAL": ["NetworkConnection", "RemoteLogon", "ShareAccess"],
            "CLOUD": ["APICall", "ResourceCreated", "PolicyModified"],
            "TOKEN": ["TokenCreated", "ImpersonationLevel", "PrivilegeAdjusted"]
        }
        
        for key, names in base_names.items():
            if key in pattern.pattern_id:
                return random.choice(names)
        
        return "SecurityEvent"
    
    def _generate_event_message(
        self, 
        pattern: HeuristicPattern, 
        sequence: int, 
        network_tuple: NetworkTuple
    ) -> str:
        """Generate detailed event message with network context."""
        
        base_msg = f"Pattern {pattern.pattern_id} step {sequence}: "
        
        if "SERVICE" in pattern.pattern_id:
            service_name = random.choice(["WindowsUpdate", "RemoteRegistry", "BITS"])
            return f"{base_msg}Service '{service_name}' installed and started from {network_tuple.source_ip}"
            
        elif "REGISTRY" in pattern.pattern_id:
            reg_key = random.choice([
                "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
            ])
            return f"{base_msg}Registry key modified: {reg_key}"
            
        elif "LATERAL" in pattern.pattern_id:
            return f"{base_msg}Network connection established {network_tuple.source_ip}:{network_tuple.source_port} -> {network_tuple.destination_ip}:{network_tuple.destination_port}"
            
        elif "CLOUD" in pattern.pattern_id:
            return f"{base_msg}Cloud API call from {network_tuple.source_ip} to create/modify resources"
            
        else:
            return f"{base_msg}Security event detected from {network_tuple.source_ip}"
    
    def _determine_event_severity(self, pattern: HeuristicPattern, sequence: int) -> SeverityLevel:
        """Determine event severity based on pattern and sequence position."""
        
        # Escalate severity as pattern progresses
        if sequence <= 2:
            return SeverityLevel.INFO
        elif sequence <= 4:
            return SeverityLevel.WARNING  
        else:
            return SeverityLevel.ERROR if "LATERAL" in pattern.pattern_id else SeverityLevel.WARNING
    
    # Additional helper methods would continue here for all the remaining _determine_* and _generate_* methods
    # ... (truncated for length, but pattern is established)
    
    def _select_or_generate_actor(self, actors: Optional[List[Actor]]) -> Actor:
        """Select from provided actors or generate a new one."""
        if actors:
            return random.choice(actors)
        
        return Actor(
            user_id=f"U{random.randint(100000, 999999)}",
            username=self.fake.user_name(),
            email=self.fake.email(),
            display_name=self.fake.name(),
            department=random.choice(["IT", "Engineering", "Finance", "HR"]),
            role=random.choice(["Admin", "User", "Service Account"]),
            identity_provider="Active Directory",
            auth_factors=["password", "mfa"],
            is_privileged=random.choice([True, False])
        )
    
    def _select_or_generate_asset(self, assets: Optional[List[Asset]], role: str) -> Asset:
        """Select from provided assets or generate a new one."""
        if assets:
            return random.choice(assets)
        
        return Asset(
            asset_id=f"A{random.randint(100000, 999999)}",
            hostname=f"{role}-{self.fake.word()}.corp.local",
            ip_address=self._generate_internal_ip() if role == "source" else self.fake.ipv4_public(),
            asset_type="workstation" if role == "source" else "server",
            operating_system=random.choice(["Windows", "Linux", "macOS"]),
            location=random.choice(["Datacenter", "Office", "Cloud"]),
            zone=random.choice(["internal", "dmz", "external"])
        )