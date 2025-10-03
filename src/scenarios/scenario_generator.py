"""
Cortex Scenario Generator
========================

This module generates realistic security events and logs for Cortex-specific scenarios,
integrating with the existing vendor library and TTP library to create comprehensive
attack simulations that showcase Cortex XSIAM and Cloud capabilities.
"""

from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timedelta
import random
import json
from dataclasses import dataclass, asdict

from .cortex_scenarios import (
    CortexScenarioLibrary, CortexScenario, CortexCapability, 
    ScenarioType, CORTEX_SCENARIO_LIBRARY
)
from ..vendors.vendor_library import ENTERPRISE_VENDOR_LIBRARY
from ..attack.ttp_library import TTP_LIBRARY
from ..features.advanced_generation import UserSession, NetworkFlow

@dataclass
class CortexEvent:
    """Enhanced event structure for Cortex scenarios"""
    timestamp: datetime
    scenario_id: str
    scenario_name: str
    event_id: str
    vendor: str
    cortex_capability: str
    mitre_technique: str
    severity: int
    confidence: float
    description: str
    detection_logic: str
    raw_log: str
    competitive_advantage: str
    correlation_id: Optional[str] = None
    
class CortexScenarioGenerator:
    """Generates realistic Cortex-aligned security scenarios with logs"""
    
    def __init__(self):
        self.scenario_library = CORTEX_SCENARIO_LIBRARY
        self.vendor_library = ENTERPRISE_VENDOR_LIBRARY
        self.ttp_library = TTP_LIBRARY
        self.event_counter = 0
        
    def generate_scenario_events(self, 
                                scenario_id: str, 
                                start_time: datetime = None,
                                include_noise: bool = True,
                                noise_ratio: float = 0.3) -> List[CortexEvent]:
        """Generate complete event timeline for a scenario"""
        scenario = self.scenario_library.get_scenario(scenario_id)
        if not scenario:
            raise ValueError(f"Scenario {scenario_id} not found")
        
        if start_time is None:
            start_time = datetime.now()
            
        events = []
        
        # Generate core attack events
        core_events = self._generate_core_attack_events(scenario, start_time)
        events.extend(core_events)
        
        # Generate correlated events from other vendors
        correlated_events = self._generate_correlated_events(scenario, core_events)
        events.extend(correlated_events)
        
        # Add noise events if requested
        if include_noise:
            noise_events = self._generate_noise_events(
                scenario, start_time, len(core_events), noise_ratio
            )
            events.extend(noise_events)
        
        # Sort by timestamp
        events.sort(key=lambda x: x.timestamp)
        
        return events
    
    def _generate_core_attack_events(self, scenario: CortexScenario, start_time: datetime) -> List[CortexEvent]:
        """Generate core attack events following scenario timeline"""
        events = []
        correlation_id = f"CORTEX_ATTACK_{random.randint(10000, 99999)}"
        
        for i, timeline_event in enumerate(scenario.timeline_events):
            # Parse timestamp
            time_parts = timeline_event["timestamp"].split(":")
            hours, minutes, seconds = map(int, time_parts)
            event_time = start_time + timedelta(hours=hours, minutes=minutes, seconds=seconds)
            
            # Select appropriate vendor for this technique
            vendor = self._select_vendor_for_technique(
                timeline_event["technique"], 
                scenario.cortex_capabilities
            )
            
            # Generate event
            event = self._create_cortex_event(
                timestamp=event_time,
                scenario=scenario,
                timeline_event=timeline_event,
                vendor=vendor,
                correlation_id=correlation_id,
                is_core_event=True
            )
            
            events.append(event)
            
        return events
    
    def _generate_correlated_events(self, scenario: CortexScenario, core_events: List[CortexEvent]) -> List[CortexEvent]:
        """Generate correlated events from other security tools"""
        correlated_events = []
        
        # For each core event, generate 1-3 correlated events from other vendors
        for core_event in core_events:
            num_correlated = random.randint(1, 3)
            
            for _ in range(num_correlated):
                # Select different vendor for correlation
                correlation_vendors = [v for v in self._get_scenario_vendors(scenario) 
                                     if v != core_event.vendor]
                
                if correlation_vendors:
                    vendor = random.choice(correlation_vendors)
                    
                    # Generate correlated event slightly after core event
                    corr_time = core_event.timestamp + timedelta(
                        minutes=random.randint(1, 15)
                    )
                    
                    correlated_event = self._create_correlated_event(
                        core_event, vendor, corr_time, scenario
                    )
                    
                    correlated_events.append(correlated_event)
        
        return correlated_events
    
    def _generate_noise_events(self, scenario: CortexScenario, start_time: datetime, 
                             core_count: int, noise_ratio: float) -> List[CortexEvent]:
        """Generate background noise events"""
        noise_events = []
        noise_count = int(core_count * noise_ratio)
        
        scenario_duration = timedelta(hours=scenario.duration_hours)
        vendors = self._get_scenario_vendors(scenario)
        
        for _ in range(noise_count):
            # Random time within scenario duration
            random_offset = timedelta(
                seconds=random.randint(0, int(scenario_duration.total_seconds()))
            )
            event_time = start_time + random_offset
            
            # Random vendor and technique
            vendor = random.choice(vendors)
            technique = random.choice(["T1078", "T1021.001", "T1059.001", "T1005", "T1083"])
            
            noise_event = self._create_noise_event(
                event_time, scenario, vendor, technique
            )
            
            noise_events.append(noise_event)
            
        return noise_events
    
    def _create_cortex_event(self, timestamp: datetime, scenario: CortexScenario,
                           timeline_event: Dict, vendor: str, correlation_id: str,
                           is_core_event: bool = True) -> CortexEvent:
        """Create a Cortex event with realistic log data"""
        self.event_counter += 1
        
        # Get technique details
        technique = timeline_event["technique"]
        ttp_data = self.ttp_library.get_technique(technique)
        
        # Get vendor details
        vendor_data = self.vendor_library.get_vendor(vendor)
        
        # Determine Cortex capability
        cortex_capability = self._determine_cortex_capability(vendor, technique)
        
        # Generate realistic log
        raw_log = self._generate_realistic_log(vendor_data, ttp_data, timestamp)
        
        # Determine competitive advantage
        competitive_advantage = timeline_event.get(
            "competitor_difference", 
            self._get_default_competitive_advantage(cortex_capability)
        )
        
        return CortexEvent(
            timestamp=timestamp,
            scenario_id=scenario.scenario_id,
            scenario_name=scenario.name,
            event_id=f"CORTEX_EVT_{self.event_counter:06d}",
            vendor=vendor,
            cortex_capability=cortex_capability,
            mitre_technique=technique,
            severity=ttp_data.get("severity", 3) if ttp_data else 3,
            confidence=random.uniform(0.75, 0.95) if is_core_event else random.uniform(0.4, 0.8),
            description=timeline_event["description"],
            detection_logic=timeline_event.get("cortex_detection", "Cortex correlation engine"),
            raw_log=raw_log,
            competitive_advantage=competitive_advantage,
            correlation_id=correlation_id if is_core_event else None
        )
    
    def _create_correlated_event(self, core_event: CortexEvent, vendor: str, 
                               timestamp: datetime, scenario: CortexScenario) -> CortexEvent:
        """Create correlated event from different vendor"""
        self.event_counter += 1
        
        vendor_data = self.vendor_library.get_vendor(vendor)
        ttp_data = self.ttp_library.get_technique(core_event.mitre_technique)
        
        # Generate correlated log
        raw_log = self._generate_realistic_log(vendor_data, ttp_data, timestamp)
        
        cortex_capability = self._determine_cortex_capability(vendor, core_event.mitre_technique)
        
        return CortexEvent(
            timestamp=timestamp,
            scenario_id=scenario.scenario_id,
            scenario_name=scenario.name,
            event_id=f"CORTEX_EVT_{self.event_counter:06d}",
            vendor=vendor,
            cortex_capability=cortex_capability,
            mitre_technique=core_event.mitre_technique,
            severity=random.randint(2, 4),
            confidence=random.uniform(0.6, 0.85),
            description=f"Correlated detection of {core_event.mitre_technique}",
            detection_logic=f"{vendor} correlation with primary event",
            raw_log=raw_log,
            competitive_advantage="Multi-vendor correlation enhances detection accuracy",
            correlation_id=core_event.correlation_id
        )
    
    def _create_noise_event(self, timestamp: datetime, scenario: CortexScenario,
                          vendor: str, technique: str) -> CortexEvent:
        """Create background noise event"""
        self.event_counter += 1
        
        vendor_data = self.vendor_library.get_vendor(vendor)
        ttp_data = self.ttp_library.get_technique(technique)
        
        raw_log = self._generate_realistic_log(vendor_data, ttp_data, timestamp)
        cortex_capability = self._determine_cortex_capability(vendor, technique)
        
        return CortexEvent(
            timestamp=timestamp,
            scenario_id=scenario.scenario_id,
            scenario_name=scenario.name,
            event_id=f"CORTEX_EVT_{self.event_counter:06d}",
            vendor=vendor,
            cortex_capability=cortex_capability,
            mitre_technique=technique,
            severity=random.randint(1, 2),
            confidence=random.uniform(0.2, 0.6),
            description=f"Background activity - {technique}",
            detection_logic=f"Standard {vendor} detection",
            raw_log=raw_log,
            competitive_advantage="",
            correlation_id=None
        )
    
    def _select_vendor_for_technique(self, technique: str, capabilities: List[CortexCapability]) -> str:
        """Select most appropriate vendor for technique based on Cortex capabilities"""
        
        # Map capabilities to preferred vendors
        capability_vendor_map = {
            CortexCapability.XDR_CORRELATION: ["Cortex XDR", "Palo Alto Networks"],
            CortexCapability.CONTAINER_SECURITY: ["Prisma Cloud", "Twistlock"],
            CortexCapability.SERVERLESS_PROTECTION: ["Prisma Cloud", "AWS CloudTrail"],
            CortexCapability.BEHAVIORAL_ANALYTICS: ["Cortex XDR", "Microsoft Sentinel"],
            CortexCapability.THREAT_INTELLIGENCE: ["AutoFocus", "Unit 42"],
            CortexCapability.MULTI_CLOUD_VISIBILITY: ["Prisma Cloud", "AWS CloudTrail", "Azure Monitor"]
        }
        
        # Technique-specific vendor preferences
        technique_vendor_map = {
            "T1566.001": ["Proofpoint", "Mimecast", "Microsoft Defender"],  # Email
            "T1059.001": ["Cortex XDR", "CrowdStrike", "Microsoft Defender"],  # Endpoint
            "T1021.001": ["Palo Alto Firewall", "Fortinet", "Check Point"],  # Network
            "T1611": ["Prisma Cloud", "Aqua Security", "Twistlock"],  # Container
            "T1078.004": ["AWS CloudTrail", "Azure AD", "GCP Audit"]  # Cloud
        }
        
        # Start with technique-specific preferences
        preferred_vendors = technique_vendor_map.get(technique, [])
        
        # Add capability-based preferences
        for capability in capabilities:
            preferred_vendors.extend(capability_vendor_map.get(capability, []))
        
        # Filter by available vendors
        available_vendors = list(self.vendor_library.vendors.keys())
        valid_vendors = [v for v in preferred_vendors if v in available_vendors]
        
        if valid_vendors:
            return random.choice(valid_vendors)
        else:
            # Fallback to random vendor
            return random.choice(available_vendors)
    
    def _get_scenario_vendors(self, scenario: CortexScenario) -> List[str]:
        """Get list of relevant vendors for scenario"""
        all_vendors = list(self.vendor_library.vendors.keys())
        
        # Filter based on scenario type and capabilities
        if scenario.scenario_type == ScenarioType.CLOUD_NATIVE:
            cloud_vendors = ["AWS CloudTrail", "Azure Monitor", "GCP Audit", 
                           "Prisma Cloud", "Microsoft Defender"]
            return [v for v in cloud_vendors if v in all_vendors]
        
        elif scenario.scenario_type == ScenarioType.TRADITIONAL_IR:
            traditional_vendors = ["Cortex XDR", "CrowdStrike", "Splunk", 
                                 "Fortinet", "Proofpoint"]
            return [v for v in traditional_vendors if v in all_vendors]
        
        else:
            # Return balanced mix
            return all_vendors[:8]  # Limit to prevent too many vendors
    
    def _determine_cortex_capability(self, vendor: str, technique: str) -> str:
        """Determine which Cortex capability this event demonstrates"""
        
        # Vendor-based capability mapping
        vendor_capability_map = {
            "Cortex XDR": "XDR Multi-Source Correlation",
            "Prisma Cloud": "Cloud Workload Protection",
            "AutoFocus": "Threat Intelligence Integration",
            "WildFire": "Advanced Malware Analysis",
            "Palo Alto Firewall": "Network Security Integration"
        }
        
        # Technique-based capability mapping
        technique_capability_map = {
            "T1566.001": "Email Security Correlation",
            "T1611": "Container Runtime Protection",
            "T1078": "Behavioral Analytics",
            "T1041": "Data Loss Prevention"
        }
        
        return (vendor_capability_map.get(vendor) or 
                technique_capability_map.get(technique) or
                "Multi-Layer Security")
    
    def _generate_realistic_log(self, vendor_data: Dict, ttp_data: Dict, timestamp: datetime) -> str:
        """Generate realistic log entry"""
        if not vendor_data:
            vendor_data = {"name": "Unknown", "log_format": "JSON"}
        
        # Use existing vendor log generation if available
        if hasattr(self.vendor_library, 'generate_sample_log'):
            return self.vendor_library.generate_sample_log(vendor_data["name"])
        
        # Fallback to simple log generation
        log_template = {
            "timestamp": timestamp.isoformat(),
            "vendor": vendor_data.get("name", "Unknown"),
            "event_type": "security_event",
            "technique": ttp_data.get("technique_id", "Unknown") if ttp_data else "Unknown",
            "severity": ttp_data.get("severity", "Medium") if ttp_data else "Medium",
            "message": ttp_data.get("description", "Security event detected") if ttp_data else "Security event detected"
        }
        
        return json.dumps(log_template, indent=2)
    
    def _get_default_competitive_advantage(self, capability: str) -> str:
        """Get default competitive advantage for capability"""
        advantages = {
            "XDR Multi-Source Correlation": "Unified correlation across all security layers vs siloed detection",
            "Cloud Workload Protection": "Native cloud integration vs bolt-on solutions",
            "Container Runtime Protection": "Kubernetes-native security vs traditional approaches",
            "Behavioral Analytics": "ML-powered user analytics vs rule-based detection",
            "Threat Intelligence Integration": "Built-in threat intelligence vs separate feeds"
        }
        
        return advantages.get(capability, "Cortex integrated platform advantage")
    
    def generate_competitive_demo(self, competitor: str = "CrowdStrike") -> Dict:
        """Generate side-by-side competitive demonstration"""
        comparison_data = self.scenario_library.generate_competitive_comparison(competitor)
        
        demo_results = {
            "competitor": competitor,
            "scenarios_tested": len(comparison_data["scenarios"]),
            "cortex_advantages": [],
            "scenario_results": []
        }
        
        for scenario, comparison in comparison_data["scenarios"]:
            # Generate events for this scenario
            events = self.generate_scenario_events(scenario.scenario_id)
            
            scenario_result = {
                "scenario_name": scenario.name,
                "cortex_detections": len([e for e in events if e.confidence > 0.7]),
                "total_events": len(events),
                "detection_rate": len([e for e in events if e.confidence > 0.7]) / len(events) if events else 0,
                "competitive_advantage": comparison.cortex_advantage,
                "key_differentiator": comparison.detection_difference
            }
            
            demo_results["scenario_results"].append(scenario_result)
            
            if comparison.cortex_advantage not in demo_results["cortex_advantages"]:
                demo_results["cortex_advantages"].append(comparison.cortex_advantage)
        
        return demo_results
    
    def generate_scenario_report(self, scenario_id: str) -> Dict:
        """Generate comprehensive scenario report"""
        scenario = self.scenario_library.get_scenario(scenario_id)
        if not scenario:
            return {"error": "Scenario not found"}
        
        events = self.generate_scenario_events(scenario_id)
        
        # Analyze events
        vendor_distribution = {}
        technique_distribution = {}
        severity_distribution = {}
        
        for event in events:
            vendor_distribution[event.vendor] = vendor_distribution.get(event.vendor, 0) + 1
            technique_distribution[event.mitre_technique] = technique_distribution.get(event.mitre_technique, 0) + 1
            severity_distribution[event.severity] = severity_distribution.get(event.severity, 0) + 1
        
        return {
            "scenario": {
                "id": scenario.scenario_id,
                "name": scenario.name,
                "type": scenario.scenario_type.value,
                "duration_hours": scenario.duration_hours,
                "target_environment": scenario.target_environment,
                "business_impact": scenario.business_impact
            },
            "events": {
                "total_count": len(events),
                "high_confidence": len([e for e in events if e.confidence > 0.8]),
                "correlated_events": len([e for e in events if e.correlation_id]),
                "vendor_distribution": vendor_distribution,
                "technique_distribution": technique_distribution,
                "severity_distribution": severity_distribution
            },
            "cortex_capabilities": [cap.value for cap in scenario.cortex_capabilities],
            "competitive_advantages": [comp.cortex_advantage for comp in scenario.competitor_comparisons],
            "timeline": [
                {
                    "timestamp": event.timestamp.isoformat(),
                    "vendor": event.vendor,
                    "technique": event.mitre_technique,
                    "description": event.description,
                    "confidence": event.confidence
                } for event in events[:10]  # First 10 events
            ]
        }

# Initialize the global scenario generator
CORTEX_SCENARIO_GENERATOR = CortexScenarioGenerator()