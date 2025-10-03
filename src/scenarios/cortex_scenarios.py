"""
Cortex XSIAM/Cloud Specific Security Scenarios
==============================================

This module contains detailed security scenarios specifically designed for Cortex XSIAM
and Cortex Cloud platforms, including competitive differentiation from CrowdStrike,
Microsoft Sentinel, and other leading security platforms.

Research Sources:
- Cortex XSIAM Documentation and Use Cases
- Cortex Cloud Security Capabilities
- CrowdStrike Falcon Platform Analysis
- Microsoft Sentinel Detection Scenarios
- Industry Best Practices and Real-World Incidents
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
import random
from enum import Enum

class ScenarioType(Enum):
    TRADITIONAL_IR = "traditional_incident_response"
    CLOUD_NATIVE = "cloud_native_security"
    HYBRID = "hybrid_environment"
    COMPETITIVE = "competitive_differentiation"

class CortexCapability(Enum):
    # Cortex XSIAM Specific
    XDR_CORRELATION = "xdr_multi_source_correlation"
    BEHAVIORAL_ANALYTICS = "behavioral_user_analytics"
    THREAT_INTELLIGENCE = "integrated_threat_intelligence"
    AUTOMATED_INVESTIGATION = "cortex_xsoar_automation"
    
    # Cortex Cloud Specific
    CLOUD_WORKLOAD_PROTECTION = "cwpp_runtime_protection"
    CONTAINER_SECURITY = "prisma_container_scanning"
    SERVERLESS_PROTECTION = "serverless_function_protection"
    INFRASTRUCTURE_AS_CODE = "iac_security_scanning"
    MULTI_CLOUD_VISIBILITY = "multi_cloud_asset_discovery"

@dataclass
class CortexDetectionRule:
    """Cortex-specific detection rule with analytics"""
    rule_id: str
    name: str
    description: str
    cortex_capability: CortexCapability
    mitre_techniques: List[str]
    severity: str
    confidence_score: float
    data_sources: List[str]
    detection_logic: str
    competitive_advantage: str

@dataclass
class CompetitorComparison:
    """Comparison with competitor capabilities"""
    competitor: str
    cortex_advantage: str
    scenario_highlight: str
    detection_difference: str
    response_difference: str

@dataclass
class CortexScenario:
    """Complete Cortex-aligned security scenario"""
    scenario_id: str
    name: str
    description: str
    scenario_type: ScenarioType
    duration_hours: int
    cortex_capabilities: List[CortexCapability]
    mitre_techniques: List[str]
    detection_rules: List[CortexDetectionRule]
    timeline_events: List[Dict]
    competitor_comparisons: List[CompetitorComparison]
    target_environment: str
    business_impact: str

class CortexScenarioLibrary:
    """Library of Cortex-specific security scenarios"""
    
    def __init__(self):
        self.scenarios = self._initialize_scenarios()
        self.detection_rules = self._initialize_detection_rules()
        
    def _initialize_detection_rules(self) -> Dict[str, CortexDetectionRule]:
        """Initialize Cortex-specific detection rules"""
        return {
            # XDR Correlation Rules
            "CORTEX_XDR_001": CortexDetectionRule(
                rule_id="CORTEX_XDR_001",
                name="Multi-Vector Attack Correlation",
                description="Correlates endpoint, network, and email events for APT detection",
                cortex_capability=CortexCapability.XDR_CORRELATION,
                mitre_techniques=["T1566.001", "T1059.001", "T1055", "T1021.001"],
                severity="High",
                confidence_score=0.92,
                data_sources=["Cortex XDR Agent", "Palo Alto Firewall", "Wildfire Analysis"],
                detection_logic="Multi-stage correlation engine identifies attack chains across security layers",
                competitive_advantage="Unlike CrowdStrike single-point detection, provides full attack chain visibility"
            ),
            
            "CORTEX_BEHAVIOR_001": CortexDetectionRule(
                rule_id="CORTEX_BEHAVIOR_001", 
                name="Advanced User Behavioral Analytics",
                description="ML-based detection of insider threats and compromised accounts",
                cortex_capability=CortexCapability.BEHAVIORAL_ANALYTICS,
                mitre_techniques=["T1078", "T1087.001", "T1005", "T1041"],
                severity="Medium",
                confidence_score=0.87,
                data_sources=["Cortex XDR", "Azure AD", "O365 Logs"],
                detection_logic="Baseline user behavior patterns and detect anomalies with ML models",
                competitive_advantage="Deeper behavioral analytics than Sentinel's basic UEBA"
            ),
            
            # Cloud Native Rules
            "CORTEX_CLOUD_001": CortexDetectionRule(
                rule_id="CORTEX_CLOUD_001",
                name="Container Runtime Threat Detection",
                description="Real-time detection of malicious activity in containerized workloads",
                cortex_capability=CortexCapability.CONTAINER_SECURITY,
                mitre_techniques=["T1611", "T1610", "T1613", "T1609"],
                severity="Critical",
                confidence_score=0.94,
                data_sources=["Prisma Cloud Defender", "Kubernetes API", "Container Runtime"],
                detection_logic="Runtime behavior analysis with container-specific threat intelligence",
                competitive_advantage="Native Kubernetes integration vs CrowdStrike's bolt-on approach"
            ),
            
            "CORTEX_SERVERLESS_001": CortexDetectionRule(
                rule_id="CORTEX_SERVERLESS_001",
                name="Serverless Function Abuse Detection", 
                description="Detects malicious serverless function execution and privilege escalation",
                cortex_capability=CortexCapability.SERVERLESS_PROTECTION,
                mitre_techniques=["T1578.002", "T1537", "T1552.005"],
                severity="High",
                confidence_score=0.89,
                data_sources=["AWS Lambda", "Azure Functions", "GCP Cloud Functions"],
                detection_logic="Function execution anomaly detection with privilege escalation patterns",
                competitive_advantage="Serverless-native protection unavailable in traditional EDR solutions"
            ),
            
            # Infrastructure as Code Rules
            "CORTEX_IAC_001": CortexDetectionRule(
                rule_id="CORTEX_IAC_001",
                name="Infrastructure as Code Security Violations",
                description="Detects security misconfigurations in IaC templates before deployment",
                cortex_capability=CortexCapability.INFRASTRUCTURE_AS_CODE,
                mitre_techniques=["T1580", "T1538", "T1526"],
                severity="Medium",
                confidence_score=0.91,
                data_sources=["Prisma Cloud Code Security", "CI/CD Pipeline", "Version Control"],
                detection_logic="Static analysis of Terraform, CloudFormation, ARM templates",
                competitive_advantage="Proactive IaC security vs reactive post-deployment detection"
            )
        }
    
    def _initialize_scenarios(self) -> Dict[str, CortexScenario]:
        """Initialize comprehensive Cortex scenarios"""
        return {
            # Traditional Incident Response Scenarios
            "APT_MULTI_VECTOR": self._create_apt_multi_vector_scenario(),
            "INSIDER_THREAT_ADVANCED": self._create_insider_threat_scenario(),
            "SUPPLY_CHAIN_COMPROMISE": self._create_supply_chain_scenario(),
            
            # Cloud Native Scenarios  
            "CONTAINER_ESCAPE": self._create_container_escape_scenario(),
            "SERVERLESS_ATTACK": self._create_serverless_attack_scenario(),
            "MULTI_CLOUD_BREACH": self._create_multi_cloud_scenario(),
            "IAC_POISONING": self._create_iac_poisoning_scenario(),
            
            # Competitive Differentiation
            "CORTEX_VS_CROWDSTRIKE": self._create_competitive_scenario(),
            "CORTEX_VS_SENTINEL": self._create_sentinel_comparison_scenario()
        }
    
    def _create_apt_multi_vector_scenario(self) -> CortexScenario:
        """Advanced APT scenario showcasing XDR correlation"""
        return CortexScenario(
            scenario_id="APT_MULTI_VECTOR_001",
            name="State-Sponsored APT with Multi-Vector Attack",
            description="Advanced persistent threat using email, endpoint, and network vectors with Cortex XDR correlation",
            scenario_type=ScenarioType.TRADITIONAL_IR,
            duration_hours=72,
            cortex_capabilities=[
                CortexCapability.XDR_CORRELATION,
                CortexCapability.THREAT_INTELLIGENCE,
                CortexCapability.AUTOMATED_INVESTIGATION
            ],
            mitre_techniques=[
                "T1566.001",  # Spearphishing Attachment
                "T1059.001",  # PowerShell 
                "T1055",      # Process Injection
                "T1021.001",  # Remote Desktop Protocol
                "T1003.001",  # LSASS Memory
                "T1041"       # Exfiltration Over C2 Channel
            ],
            detection_rules=[],  # Will be populated
            timeline_events=[
                {
                    "timestamp": "00:00:00",
                    "stage": "Initial Access",
                    "technique": "T1566.001", 
                    "description": "Spearphishing email with weaponized document",
                    "cortex_detection": "Email Security detects suspicious attachment, Wildfire analysis confirms malware",
                    "competitor_difference": "CrowdStrike would miss email vector correlation"
                },
                {
                    "timestamp": "00:15:30",
                    "stage": "Execution",
                    "technique": "T1059.001",
                    "description": "PowerShell execution of malicious payload",
                    "cortex_detection": "XDR Agent detects obfuscated PowerShell with behavioral analysis",
                    "competitor_difference": "Traditional EDR focuses only on process, misses context"
                },
                {
                    "timestamp": "01:45:20", 
                    "stage": "Persistence",
                    "technique": "T1055",
                    "description": "Process injection into legitimate Windows process",
                    "cortex_detection": "Multi-layer correlation identifies injection pattern across endpoints",
                    "competitor_difference": "Sentinel requires manual correlation rules"
                },
                {
                    "timestamp": "04:30:15",
                    "stage": "Lateral Movement", 
                    "technique": "T1021.001",
                    "description": "RDP lateral movement to domain controllers",
                    "cortex_detection": "Network analytics correlate with endpoint behavioral changes",
                    "competitor_difference": "CrowdStrike limited network visibility"
                }
            ],
            competitor_comparisons=[
                CompetitorComparison(
                    competitor="CrowdStrike Falcon",
                    cortex_advantage="Native multi-vector correlation vs single-point detection",
                    scenario_highlight="Automatic email-endpoint-network correlation",
                    detection_difference="Cortex correlates across all vectors automatically",
                    response_difference="Unified response vs separate tool orchestration"
                ),
                CompetitorComparison(
                    competitor="Microsoft Sentinel", 
                    cortex_advantage="Built-in correlation engine vs manual rule creation",
                    scenario_highlight="Pre-built APT playbooks and automated investigation",
                    detection_difference="ML-based correlation vs static rules",
                    response_difference="Native XSOAR automation vs Logic Apps complexity"
                )
            ],
            target_environment="Enterprise hybrid infrastructure",
            business_impact="Critical - Potential data exfiltration and intellectual property theft"
        )
    
    def _create_container_escape_scenario(self) -> CortexScenario:
        """Container escape scenario showcasing cloud-native protection"""
        return CortexScenario(
            scenario_id="CONTAINER_ESCAPE_001", 
            name="Container Breakout and Kubernetes Cluster Compromise",
            description="Malicious container escapes to host and compromises Kubernetes cluster",
            scenario_type=ScenarioType.CLOUD_NATIVE,
            duration_hours=6,
            cortex_capabilities=[
                CortexCapability.CONTAINER_SECURITY,
                CortexCapability.CLOUD_WORKLOAD_PROTECTION,
                CortexCapability.MULTI_CLOUD_VISIBILITY
            ],
            mitre_techniques=[
                "T1611",    # Escape to Host
                "T1610",    # Deploy Container  
                "T1613",    # Container Administration Command
                "T1609",    # Container Administration Service
                "T1552.007" # Container API
            ],
            detection_rules=[],
            timeline_events=[
                {
                    "timestamp": "00:00:00",
                    "stage": "Initial Access",
                    "technique": "T1610", 
                    "description": "Deployment of malicious container image",
                    "cortex_detection": "Prisma Cloud registry scanning detects embedded malware",
                    "competitor_difference": "CrowdStrike lacks native container image scanning"
                },
                {
                    "timestamp": "00:05:30",
                    "stage": "Privilege Escalation", 
                    "technique": "T1611",
                    "description": "Container escape via privileged mount abuse",
                    "cortex_detection": "Runtime protection detects mount namespace escape attempt",
                    "competitor_difference": "Traditional EDR cannot monitor container boundaries"
                },
                {
                    "timestamp": "00:12:45",
                    "stage": "Discovery",
                    "technique": "T1613", 
                    "description": "Kubernetes API enumeration for cluster resources",
                    "cortex_detection": "API audit logs correlated with container behavioral analysis",
                    "competitor_difference": "Sentinel requires manual K8s log ingestion configuration"
                }
            ],
            competitor_comparisons=[
                CompetitorComparison(
                    competitor="CrowdStrike Falcon",
                    cortex_advantage="Native Kubernetes security vs bolt-on container module",
                    scenario_highlight="Container-aware detection and response",
                    detection_difference="Runtime container behavior analysis",
                    response_difference="Container-specific response actions"
                )
            ],
            target_environment="Cloud-native Kubernetes environment",
            business_impact="High - Container infrastructure compromise with potential data access"
        )
    
    def _create_serverless_attack_scenario(self) -> CortexScenario:
        """Serverless attack scenario"""
        return CortexScenario(
            scenario_id="SERVERLESS_ATTACK_001",
            name="Serverless Function Hijacking and Privilege Escalation", 
            description="Compromise of serverless functions for cryptocurrency mining and data access",
            scenario_type=ScenarioType.CLOUD_NATIVE,
            duration_hours=4,
            cortex_capabilities=[
                CortexCapability.SERVERLESS_PROTECTION,
                CortexCapability.CLOUD_WORKLOAD_PROTECTION,
                CortexCapability.MULTI_CLOUD_VISIBILITY
            ],
            mitre_techniques=[
                "T1578.002", # Create Cloud Instance
                "T1537",     # Transfer Data to Cloud Account  
                "T1552.005", # Cloud Instance Metadata API
                "T1496"      # Resource Hijacking
            ],
            detection_rules=[],
            timeline_events=[
                {
                    "timestamp": "00:00:00",
                    "stage": "Initial Access",
                    "technique": "T1190",
                    "description": "Exploitation of vulnerable serverless function dependency",
                    "cortex_detection": "Function runtime analysis detects unexpected network connections",
                    "competitor_difference": "No serverless-specific protection available in traditional tools"
                },
                {
                    "timestamp": "00:08:15",
                    "stage": "Resource Development",
                    "technique": "T1578.002", 
                    "description": "Creation of additional Lambda functions for persistence",
                    "cortex_detection": "Cloud asset inventory detects unauthorized function deployment",
                    "competitor_difference": "CrowdStrike cannot monitor serverless deployment activities"
                }
            ],
            competitor_comparisons=[
                CompetitorComparison(
                    competitor="Traditional EDR Solutions",
                    cortex_advantage="Serverless-native protection vs no coverage",
                    scenario_highlight="Function-level security monitoring",
                    detection_difference="Runtime serverless behavior analysis",
                    response_difference="Serverless-aware incident response"
                )
            ],
            target_environment="Multi-cloud serverless architecture",
            business_impact="Medium - Resource hijacking and potential data exposure"
        )
    
    def _create_competitive_scenario(self) -> CortexScenario:
        """Scenario highlighting competitive advantages over CrowdStrike"""
        return CortexScenario(
            scenario_id="COMPETITIVE_DEMO_001",
            name="Cortex vs CrowdStrike: Multi-Platform Attack Detection",
            description="Side-by-side comparison of detection capabilities during complex attack",
            scenario_type=ScenarioType.COMPETITIVE,
            duration_hours=8,
            cortex_capabilities=[
                CortexCapability.XDR_CORRELATION,
                CortexCapability.BEHAVIORAL_ANALYTICS, 
                CortexCapability.CONTAINER_SECURITY,
                CortexCapability.THREAT_INTELLIGENCE
            ],
            mitre_techniques=[
                "T1566.001", "T1059.001", "T1055", "T1021.001",
                "T1611", "T1552.005", "T1041"
            ],
            detection_rules=[],
            timeline_events=[],
            competitor_comparisons=[
                CompetitorComparison(
                    competitor="CrowdStrike Falcon",
                    cortex_advantage="Unified XDR platform vs endpoint-centric approach",
                    scenario_highlight="Automatic correlation across email, endpoint, network, and cloud",
                    detection_difference="Single-pane multi-vector visibility vs siloed detection",
                    response_difference="Orchestrated response vs manual correlation"
                )
            ],
            target_environment="Hybrid cloud with containers and traditional infrastructure",
            business_impact="Demonstrates ROI through reduced MTTD and MTTR"
        )
    
    def _create_sentinel_comparison_scenario(self) -> CortexScenario:
        """Scenario comparing Cortex to Microsoft Sentinel"""
        return CortexScenario(
            scenario_id="SENTINEL_COMPARISON_001",
            name="Cortex vs Microsoft Sentinel: Cloud-Native Security",
            description="Comparison of cloud security detection and response capabilities",
            scenario_type=ScenarioType.COMPETITIVE,
            duration_hours=12,
            cortex_capabilities=[
                CortexCapability.MULTI_CLOUD_VISIBILITY,
                CortexCapability.CONTAINER_SECURITY,
                CortexCapability.AUTOMATED_INVESTIGATION
            ],
            mitre_techniques=[
                "T1538", "T1526", "T1580", "T1552.005", "T1611"
            ],
            detection_rules=[],
            timeline_events=[],
            competitor_comparisons=[
                CompetitorComparison(
                    competitor="Microsoft Sentinel",
                    cortex_advantage="Native multi-cloud support vs Azure-centric approach",
                    scenario_highlight="Pre-built playbooks vs custom KQL development",
                    detection_difference="Built-in ML models vs manual analytics rules",
                    response_difference="XSOAR automation vs Logic Apps complexity"
                )
            ],
            target_environment="Multi-cloud environment with AWS, Azure, GCP",
            business_impact="Demonstrates superior multi-cloud security posture"
        )
    
    def _create_insider_threat_scenario(self) -> CortexScenario:
        """Advanced insider threat scenario"""
        return CortexScenario(
            scenario_id="INSIDER_THREAT_ADVANCED_001",
            name="Privileged User Data Exfiltration with Behavioral Analytics",
            description="Insider threat using legitimate access with advanced behavioral detection",
            scenario_type=ScenarioType.TRADITIONAL_IR,
            duration_hours=168,  # 1 week
            cortex_capabilities=[
                CortexCapability.BEHAVIORAL_ANALYTICS,
                CortexCapability.XDR_CORRELATION,
                CortexCapability.THREAT_INTELLIGENCE
            ],
            mitre_techniques=[
                "T1078.002", # Valid Accounts: Domain Accounts
                "T1087.001", # Account Discovery: Local Account
                "T1005",     # Data from Local System
                "T1041",     # Exfiltration Over C2 Channel
                "T1070.004"  # File Deletion
            ],
            detection_rules=[],
            timeline_events=[
                {
                    "timestamp": "00:00:00",
                    "stage": "Reconnaissance",
                    "technique": "T1087.001",
                    "description": "Abnormal account enumeration by privileged user",
                    "cortex_detection": "UEBA detects deviation from normal behavior patterns",
                    "competitor_difference": "CrowdStrike lacks advanced UEBA capabilities"
                }
            ],
            competitor_comparisons=[],
            target_environment="Enterprise Active Directory environment",
            business_impact="Critical - Intellectual property theft by trusted insider"
        )
    
    def _create_supply_chain_scenario(self) -> CortexScenario:
        """Supply chain attack scenario"""
        return CortexScenario(
            scenario_id="SUPPLY_CHAIN_001",
            name="Third-Party Software Supply Chain Compromise",
            description="Compromise via trusted software vendor with widespread impact",
            scenario_type=ScenarioType.TRADITIONAL_IR,
            duration_hours=48,
            cortex_capabilities=[
                CortexCapability.THREAT_INTELLIGENCE,
                CortexCapability.XDR_CORRELATION,
                CortexCapability.BEHAVIORAL_ANALYTICS
            ],
            mitre_techniques=[
                "T1195.002", # Supply Chain Compromise: Software Supply Chain
                "T1027",     # Obfuscated Files or Information
                "T1105",     # Ingress Tool Transfer
                "T1071.001"  # Web Protocols
            ],
            detection_rules=[],
            timeline_events=[],
            competitor_comparisons=[],
            target_environment="Enterprise software distribution infrastructure", 
            business_impact="Critical - Widespread organizational compromise"
        )
    
    def _create_multi_cloud_scenario(self) -> CortexScenario:
        """Multi-cloud security scenario"""
        return CortexScenario(
            scenario_id="MULTI_CLOUD_001", 
            name="Cross-Cloud Account Takeover and Resource Abuse",
            description="Attack spanning multiple cloud providers with resource hijacking",
            scenario_type=ScenarioType.CLOUD_NATIVE,
            duration_hours=24,
            cortex_capabilities=[
                CortexCapability.MULTI_CLOUD_VISIBILITY,
                CortexCapability.CLOUD_WORKLOAD_PROTECTION,
                CortexCapability.BEHAVIORAL_ANALYTICS
            ],
            mitre_techniques=[
                "T1078.004", # Valid Accounts: Cloud Accounts
                "T1580",     # Cloud Infrastructure Discovery
                "T1496",     # Resource Hijacking
                "T1537"      # Transfer Data to Cloud Account
            ],
            detection_rules=[],
            timeline_events=[],
            competitor_comparisons=[],
            target_environment="AWS, Azure, and GCP multi-cloud environment",
            business_impact="High - Cloud resource abuse and data exposure"
        )
    
    def _create_iac_poisoning_scenario(self) -> CortexScenario:
        """Infrastructure as Code poisoning scenario"""
        return CortexScenario(
            scenario_id="IAC_POISONING_001",
            name="Infrastructure as Code Template Poisoning Attack",
            description="Malicious modifications to IaC templates for backdoor deployment",
            scenario_type=ScenarioType.CLOUD_NATIVE,
            duration_hours=2,
            cortex_capabilities=[
                CortexCapability.INFRASTRUCTURE_AS_CODE,
                CortexCapability.MULTI_CLOUD_VISIBILITY
            ],
            mitre_techniques=[
                "T1195.003", # Supply Chain Compromise: Compromise Hardware Supply Chain
                "T1554",     # Compromise Client Software Binary
                "T1059.009"  # Cloud API
            ],
            detection_rules=[],
            timeline_events=[],
            competitor_comparisons=[],
            target_environment="DevOps CI/CD pipeline with Terraform/CloudFormation",
            business_impact="High - Systematic infrastructure compromise via IaC"
        )
    
    def get_scenario(self, scenario_id: str) -> Optional[CortexScenario]:
        """Get specific scenario by ID"""
        return self.scenarios.get(scenario_id)
    
    def get_scenarios_by_type(self, scenario_type: ScenarioType) -> List[CortexScenario]:
        """Get scenarios filtered by type"""
        return [s for s in self.scenarios.values() if s.scenario_type == scenario_type]
    
    def get_scenarios_by_capability(self, capability: CortexCapability) -> List[CortexScenario]:
        """Get scenarios that demonstrate specific Cortex capability"""
        return [s for s in self.scenarios.values() if capability in s.cortex_capabilities]
    
    def generate_competitive_comparison(self, competitor: str) -> Dict:
        """Generate detailed competitive comparison"""
        relevant_scenarios = []
        for scenario in self.scenarios.values():
            for comp in scenario.competitor_comparisons:
                if competitor.lower() in comp.competitor.lower():
                    relevant_scenarios.append((scenario, comp))
        
        return {
            "competitor": competitor,
            "scenario_count": len(relevant_scenarios),
            "scenarios": relevant_scenarios,
            "summary": f"Cortex advantages over {competitor} across {len(relevant_scenarios)} scenarios"
        }

    def generate_scenario_timeline(self, scenario_id: str, start_time: datetime = None) -> List[Dict]:
        """Generate realistic timeline for scenario"""
        scenario = self.get_scenario(scenario_id)
        if not scenario:
            return []
        
        if start_time is None:
            start_time = datetime.now()
        
        timeline = []
        for event in scenario.timeline_events:
            # Parse timestamp (format: HH:MM:SS)
            time_parts = event["timestamp"].split(":")
            hours, minutes, seconds = map(int, time_parts)
            event_time = start_time + timedelta(hours=hours, minutes=minutes, seconds=seconds)
            
            timeline.append({
                "timestamp": event_time,
                "scenario": scenario.name,
                "stage": event["stage"],
                "technique": event["technique"],
                "description": event["description"],
                "cortex_detection": event["cortex_detection"],
                "competitor_difference": event.get("competitor_difference", "")
            })
        
        return sorted(timeline, key=lambda x: x["timestamp"])

# Initialize the global scenario library
CORTEX_SCENARIO_LIBRARY = CortexScenarioLibrary()