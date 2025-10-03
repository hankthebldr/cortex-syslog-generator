#!/usr/bin/env python3
"""
Cortex XSIAM/Cloud Security Scenarios - Standalone Demonstration
===============================================================

This standalone script demonstrates Cortex-specific security scenarios without
requiring the complex import dependencies. It showcases:

- Traditional incident response scenarios aligned to Cortex XSIAM strengths
- Cloud-native security scenarios leveraging Cortex Cloud/Prisma capabilities  
- Competitive differentiation from CrowdStrike, Microsoft Sentinel, and others
- MITRE ATT&CK technique mapping and realistic attack timelines
- Custom detection rules and analytics specific to Cortex platforms
"""

import json
import random
from datetime import datetime, timedelta
from dataclasses import dataclass
from typing import List, Dict, Any

# =============================================
# CORTEX SCENARIO DEFINITIONS
# =============================================

@dataclass
class CortexScenario:
    """Cortex-specific security scenario"""
    id: str
    name: str
    description: str
    scenario_type: str  # "traditional_ir", "cloud_native", "competitive"
    duration_hours: int
    capabilities: List[str]
    mitre_techniques: List[str]
    timeline_events: List[Dict]
    competitive_advantages: List[Dict]
    target_environment: str
    business_impact: str

def create_cortex_scenarios():
    """Create comprehensive Cortex scenario library"""
    return {
        # ===== TRADITIONAL INCIDENT RESPONSE SCENARIOS =====
        "APT_MULTI_VECTOR": CortexScenario(
            id="APT_MULTI_VECTOR",
            name="State-Sponsored APT with Multi-Vector Attack",
            description="Advanced persistent threat using email, endpoint, and network vectors with Cortex XDR correlation",
            scenario_type="traditional_ir",
            duration_hours=72,
            capabilities=[
                "XDR Multi-Source Correlation",
                "Threat Intelligence Integration", 
                "Behavioral Analytics",
                "Automated Investigation (XSOAR)"
            ],
            mitre_techniques=["T1566.001", "T1059.001", "T1055", "T1021.001", "T1003.001", "T1041"],
            timeline_events=[
                {
                    "timestamp": "00:00:00",
                    "stage": "Initial Access",
                    "technique": "T1566.001",
                    "description": "Spearphishing email with weaponized document",
                    "cortex_detection": "Email Security + Wildfire analysis detects malware, correlates with threat intel",
                    "competitive_advantage": "CrowdStrike misses email vector - only sees endpoint execution",
                    "vendors": ["Proofpoint", "WildFire", "Cortex XDR"]
                },
                {
                    "timestamp": "00:15:30", 
                    "stage": "Execution",
                    "technique": "T1059.001",
                    "description": "PowerShell execution of malicious payload",
                    "cortex_detection": "XDR Agent detects obfuscated PowerShell with behavioral analysis",
                    "competitive_advantage": "Traditional EDR focuses only on process, misses email context",
                    "vendors": ["Cortex XDR", "Microsoft Defender"]
                },
                {
                    "timestamp": "01:45:20",
                    "stage": "Persistence", 
                    "technique": "T1055",
                    "description": "Process injection into legitimate Windows process",
                    "cortex_detection": "Multi-layer correlation identifies injection pattern across endpoints",
                    "competitive_advantage": "Sentinel requires manual correlation rules - Cortex automatic",
                    "vendors": ["Cortex XDR", "CrowdStrike"]
                },
                {
                    "timestamp": "04:30:15",
                    "stage": "Lateral Movement",
                    "technique": "T1021.001", 
                    "description": "RDP lateral movement to domain controllers",
                    "cortex_detection": "Network analytics correlate with endpoint behavioral changes",
                    "competitive_advantage": "CrowdStrike limited network visibility vs unified XDR approach",
                    "vendors": ["Palo Alto Firewall", "Cortex XDR"]
                },
                {
                    "timestamp": "12:15:45",
                    "stage": "Credential Access",
                    "technique": "T1003.001",
                    "description": "LSASS memory dumping for credential extraction", 
                    "cortex_detection": "Advanced behavioral analytics detect credential access patterns",
                    "competitive_advantage": "ML-based detection vs signature-based approaches",
                    "vendors": ["Cortex XDR", "Microsoft Defender"]
                },
                {
                    "timestamp": "24:45:30",
                    "stage": "Exfiltration",
                    "technique": "T1041",
                    "description": "Data exfiltration over C2 channel",
                    "cortex_detection": "Network + endpoint correlation identifies data staging and exfiltration",
                    "competitive_advantage": "Full kill chain visibility vs point-solution detection",
                    "vendors": ["Palo Alto Firewall", "Cortex XDR", "AutoFocus"]
                }
            ],
            competitive_advantages=[
                {
                    "competitor": "CrowdStrike Falcon",
                    "advantage": "Native multi-vector correlation vs endpoint-centric approach",
                    "details": "Automatic correlation across email, endpoint, network, and cloud vs manual investigation"
                },
                {
                    "competitor": "Microsoft Sentinel",
                    "advantage": "Built-in correlation engine vs manual rule creation",
                    "details": "ML-based correlation vs static KQL queries requiring expertise"
                }
            ],
            target_environment="Enterprise hybrid infrastructure",
            business_impact="Critical - Potential data exfiltration and intellectual property theft"
        ),

        "INSIDER_THREAT_ADVANCED": CortexScenario(
            id="INSIDER_THREAT_ADVANCED",
            name="Privileged User Data Exfiltration with Behavioral Analytics",
            description="Insider threat using legitimate access with advanced behavioral detection",
            scenario_type="traditional_ir",
            duration_hours=168,  # 1 week
            capabilities=[
                "User and Entity Behavior Analytics (UEBA)",
                "Data Loss Prevention Integration",
                "Privilege Analytics",
                "Timeline Reconstruction"
            ],
            mitre_techniques=["T1078.002", "T1087.001", "T1005", "T1041", "T1070.004"],
            timeline_events=[
                {
                    "timestamp": "00:00:00",
                    "stage": "Reconnaissance", 
                    "technique": "T1087.001",
                    "description": "Abnormal account enumeration by privileged user",
                    "cortex_detection": "UEBA detects deviation from normal behavior patterns",
                    "competitive_advantage": "CrowdStrike lacks advanced UEBA capabilities",
                    "vendors": ["Cortex XDR", "Azure AD"]
                },
                {
                    "timestamp": "24:30:00",
                    "stage": "Collection",
                    "technique": "T1005", 
                    "description": "Accessing sensitive files outside normal job function",
                    "cortex_detection": "Data classification + access analytics identify anomalous patterns",
                    "competitive_advantage": "Integrated DLP vs separate point solutions",
                    "vendors": ["Cortex XDR", "Microsoft Information Protection"]
                },
                {
                    "timestamp": "120:15:00",
                    "stage": "Exfiltration",
                    "technique": "T1041",
                    "description": "Large file transfers to personal cloud storage",
                    "cortex_detection": "Network + endpoint correlation detects data staging and exfiltration", 
                    "competitive_advantage": "Behavioral baselines detect subtle insider activities",
                    "vendors": ["Palo Alto Firewall", "Cortex XDR"]
                }
            ],
            competitive_advantages=[
                {
                    "competitor": "Splunk Enterprise Security",
                    "advantage": "Built-in UEBA vs custom analytics development",
                    "details": "Pre-built behavioral models vs months of customization"
                }
            ],
            target_environment="Enterprise Active Directory environment",
            business_impact="Critical - Intellectual property theft by trusted insider"
        ),

        # ===== CLOUD NATIVE SCENARIOS =====
        "CONTAINER_ESCAPE": CortexScenario(
            id="CONTAINER_ESCAPE",
            name="Container Breakout and Kubernetes Cluster Compromise", 
            description="Malicious container escapes to host and compromises Kubernetes cluster",
            scenario_type="cloud_native",
            duration_hours=6,
            capabilities=[
                "Container Runtime Protection",
                "Kubernetes Security Posture Management",
                "Cloud Workload Protection Platform (CWPP)",
                "Infrastructure as Code Security"
            ],
            mitre_techniques=["T1611", "T1610", "T1613", "T1609", "T1552.007"],
            timeline_events=[
                {
                    "timestamp": "00:00:00",
                    "stage": "Initial Access",
                    "technique": "T1610",
                    "description": "Deployment of malicious container image",
                    "cortex_detection": "Prisma Cloud registry scanning detects embedded malware",
                    "competitive_advantage": "CrowdStrike lacks native container image scanning",
                    "vendors": ["Prisma Cloud", "Twistlock"]
                },
                {
                    "timestamp": "00:05:30",
                    "stage": "Privilege Escalation",
                    "technique": "T1611", 
                    "description": "Container escape via privileged mount abuse",
                    "cortex_detection": "Runtime protection detects mount namespace escape attempt",
                    "competitive_advantage": "Traditional EDR cannot monitor container boundaries",
                    "vendors": ["Prisma Cloud", "Aqua Security"]
                },
                {
                    "timestamp": "00:12:45",
                    "stage": "Discovery",
                    "technique": "T1613",
                    "description": "Kubernetes API enumeration for cluster resources",
                    "cortex_detection": "API audit logs correlated with container behavioral analysis",
                    "competitive_advantage": "Sentinel requires manual K8s log ingestion configuration",
                    "vendors": ["Prisma Cloud", "Kubernetes API Server"]
                },
                {
                    "timestamp": "01:30:20",
                    "stage": "Lateral Movement",
                    "technique": "T1609",
                    "description": "Compromise of additional pods and services",
                    "cortex_detection": "Cross-pod communication analysis detects lateral movement patterns",
                    "competitive_advantage": "Native Kubernetes security vs bolt-on approaches",
                    "vendors": ["Prisma Cloud", "Calico"]
                }
            ],
            competitive_advantages=[
                {
                    "competitor": "CrowdStrike Falcon",
                    "advantage": "Native Kubernetes security vs bolt-on container module",
                    "details": "Container-aware detection and response vs traditional host-based approach"
                },
                {
                    "competitor": "Microsoft Defender",
                    "advantage": "Multi-cloud container support vs Azure-centric approach", 
                    "details": "Consistent security across AWS, Azure, GCP container environments"
                }
            ],
            target_environment="Cloud-native Kubernetes environment",
            business_impact="High - Container infrastructure compromise with potential data access"
        ),

        "SERVERLESS_ATTACK": CortexScenario(
            id="SERVERLESS_ATTACK", 
            name="Serverless Function Hijacking and Privilege Escalation",
            description="Compromise of serverless functions for cryptocurrency mining and data access",
            scenario_type="cloud_native",
            duration_hours=4,
            capabilities=[
                "Serverless Protection",
                "Cloud Function Runtime Security", 
                "API Gateway Security",
                "Cloud Asset Inventory"
            ],
            mitre_techniques=["T1578.002", "T1537", "T1552.005", "T1496"],
            timeline_events=[
                {
                    "timestamp": "00:00:00",
                    "stage": "Initial Access",
                    "technique": "T1190",
                    "description": "Exploitation of vulnerable serverless function dependency",
                    "cortex_detection": "Function runtime analysis detects unexpected network connections",
                    "competitive_advantage": "No serverless-specific protection in traditional EDR",
                    "vendors": ["Prisma Cloud", "AWS Lambda"]
                },
                {
                    "timestamp": "00:08:15",
                    "stage": "Resource Development", 
                    "technique": "T1578.002",
                    "description": "Creation of additional Lambda functions for persistence",
                    "cortex_detection": "Cloud asset inventory detects unauthorized function deployment",
                    "competitive_advantage": "CrowdStrike cannot monitor serverless deployment activities",
                    "vendors": ["Prisma Cloud", "AWS CloudTrail"]
                },
                {
                    "timestamp": "00:25:40",
                    "stage": "Resource Hijacking",
                    "technique": "T1496",
                    "description": "Cryptocurrency mining using hijacked compute resources",
                    "cortex_detection": "Function execution anomaly detection identifies resource abuse",
                    "competitive_advantage": "Serverless-aware anomaly detection vs generic monitoring",
                    "vendors": ["Prisma Cloud", "AWS CloudWatch"]
                }
            ],
            competitive_advantages=[
                {
                    "competitor": "Traditional EDR Solutions",
                    "advantage": "Serverless-native protection vs no coverage",
                    "details": "Function-level security monitoring and runtime protection"
                }
            ],
            target_environment="Multi-cloud serverless architecture", 
            business_impact="Medium - Resource hijacking and potential data exposure"
        ),

        "MULTI_CLOUD_BREACH": CortexScenario(
            id="MULTI_CLOUD_BREACH",
            name="Cross-Cloud Account Takeover and Resource Abuse",
            description="Attack spanning multiple cloud providers with resource hijacking",
            scenario_type="cloud_native", 
            duration_hours=24,
            capabilities=[
                "Multi-Cloud Visibility",
                "Cloud Security Posture Management",
                "Identity and Access Management",
                "Cloud Asset Discovery"
            ],
            mitre_techniques=["T1078.004", "T1580", "T1496", "T1537"],
            timeline_events=[
                {
                    "timestamp": "00:00:00",
                    "stage": "Initial Access",
                    "technique": "T1078.004",
                    "description": "Compromised cloud service account credentials",
                    "cortex_detection": "Cross-cloud identity analytics detect anomalous login patterns",
                    "competitive_advantage": "Unified multi-cloud view vs cloud-specific tools",
                    "vendors": ["Prisma Cloud", "AWS IAM", "Azure AD"]
                },
                {
                    "timestamp": "02:15:30",
                    "stage": "Discovery",
                    "technique": "T1580", 
                    "description": "Enumeration of cloud resources across AWS, Azure, GCP",
                    "cortex_detection": "API call pattern analysis identifies reconnaissance activities",
                    "competitive_advantage": "Single pane visibility vs separate cloud security tools",
                    "vendors": ["Prisma Cloud", "AWS CloudTrail", "Azure Monitor"]
                }
            ],
            competitive_advantages=[
                {
                    "competitor": "Microsoft Sentinel",
                    "advantage": "Native multi-cloud support vs Azure-centric approach",
                    "details": "Consistent security policies across all major cloud providers"
                }
            ],
            target_environment="AWS, Azure, and GCP multi-cloud environment",
            business_impact="High - Cloud resource abuse and data exposure"
        ),

        # ===== COMPETITIVE SCENARIOS =====
        "CORTEX_VS_CROWDSTRIKE": CortexScenario(
            id="CORTEX_VS_CROWDSTRIKE",
            name="Cortex vs CrowdStrike: Multi-Platform Attack Detection", 
            description="Side-by-side comparison of detection capabilities during complex attack",
            scenario_type="competitive",
            duration_hours=8,
            capabilities=[
                "XDR Multi-Source Correlation",
                "Network Security Integration",
                "Email Security Correlation", 
                "Cloud Workload Protection"
            ],
            mitre_techniques=["T1566.001", "T1059.001", "T1055", "T1021.001", "T1611", "T1552.005"],
            timeline_events=[
                {
                    "timestamp": "00:00:00",
                    "stage": "Email Vector",
                    "technique": "T1566.001",
                    "description": "Malicious email attachment execution",
                    "cortex_detection": "Email security + endpoint correlation provides full context",
                    "competitive_advantage": "CrowdStrike: Misses email vector - only sees endpoint execution",
                    "vendors": ["Proofpoint", "Cortex XDR", "WildFire"]
                },
                {
                    "timestamp": "01:15:00", 
                    "stage": "Network Propagation",
                    "technique": "T1021.001",
                    "description": "Lateral movement across network segments", 
                    "cortex_detection": "Network firewall + endpoint correlation tracks movement",
                    "competitive_advantage": "CrowdStrike: Limited network visibility vs unified platform",
                    "vendors": ["Palo Alto Firewall", "Cortex XDR"]
                },
                {
                    "timestamp": "03:45:00",
                    "stage": "Container Compromise", 
                    "technique": "T1611",
                    "description": "Container escape and host compromise",
                    "cortex_detection": "Container runtime protection + host monitoring",
                    "competitive_advantage": "CrowdStrike: Bolt-on container module vs native integration",
                    "vendors": ["Prisma Cloud", "Cortex XDR"]
                }
            ],
            competitive_advantages=[
                {
                    "competitor": "CrowdStrike Falcon",
                    "advantage": "Unified XDR platform vs endpoint-centric approach", 
                    "details": "Single-pane multi-vector visibility vs separate tool correlation"
                }
            ],
            target_environment="Hybrid cloud with containers and traditional infrastructure",
            business_impact="Demonstrates ROI through reduced MTTD and MTTR"
        )
    }

def generate_realistic_events(scenario: CortexScenario, start_time: datetime = None) -> List[Dict]:
    """Generate realistic security events for scenario"""
    if start_time is None:
        start_time = datetime.now()
    
    events = []
    correlation_id = f"CORTEX_ATTACK_{random.randint(10000, 99999)}"
    
    # Generate core attack events
    for i, timeline_event in enumerate(scenario.timeline_events):
        # Parse timestamp
        time_parts = timeline_event["timestamp"].split(":")
        hours, minutes, seconds = map(int, time_parts)
        event_time = start_time + timedelta(hours=hours, minutes=minutes, seconds=seconds)
        
        # Create realistic event
        event = {
            "event_id": f"CORTEX_EVT_{random.randint(100000, 999999)}",
            "timestamp": event_time.isoformat(),
            "scenario": scenario.name,
            "scenario_id": scenario.id,
            "stage": timeline_event["stage"],
            "mitre_technique": timeline_event["technique"],
            "description": timeline_event["description"],
            "cortex_detection": timeline_event["cortex_detection"],
            "competitive_advantage": timeline_event["competitive_advantage"],
            "vendors": timeline_event.get("vendors", ["Cortex XDR"]),
            "severity": random.randint(3, 5),
            "confidence": random.uniform(0.85, 0.98),
            "correlation_id": correlation_id,
            "raw_log": generate_sample_log(timeline_event, event_time)
        }
        events.append(event)
        
        # Generate 1-2 correlated events from other vendors
        for _ in range(random.randint(1, 2)):
            corr_time = event_time + timedelta(minutes=random.randint(1, 15))
            correlated_event = {
                "event_id": f"CORTEX_EVT_{random.randint(100000, 999999)}",
                "timestamp": corr_time.isoformat(),
                "scenario": scenario.name,
                "scenario_id": scenario.id,
                "stage": f"Correlated - {timeline_event['stage']}",
                "mitre_technique": timeline_event["technique"],
                "description": f"Secondary detection: {timeline_event['description']}",
                "cortex_detection": f"Multi-vendor correlation enhances detection accuracy",
                "competitive_advantage": "Automatic correlation vs manual investigation",
                "vendors": [random.choice(["Splunk", "Microsoft Defender", "Fortinet"])],
                "severity": random.randint(2, 4),
                "confidence": random.uniform(0.65, 0.85),
                "correlation_id": correlation_id,
                "raw_log": generate_sample_log(timeline_event, corr_time)
            }
            events.append(correlated_event)
    
    # Sort by timestamp
    events.sort(key=lambda x: x["timestamp"])
    return events

def generate_sample_log(event: Dict, timestamp: datetime) -> str:
    """Generate realistic log entry"""
    log_data = {
        "timestamp": timestamp.isoformat(),
        "event_type": "security_alert",
        "technique": event.get("technique", "Unknown"),
        "stage": event.get("stage", "Unknown"),
        "severity": random.choice(["High", "Critical", "Medium"]),
        "confidence": round(random.uniform(0.75, 0.95), 2),
        "source": random.choice(["Cortex XDR", "Prisma Cloud", "Palo Alto Firewall"]),
        "description": event.get("description", "Security event detected"),
        "indicators": {
            "process": f"malware_{random.randint(1000, 9999)}.exe",
            "ip_address": f"10.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}",
            "user": f"user_{random.randint(100, 999)}",
            "host": f"HOST-{random.randint(1000, 9999)}"
        }
    }
    return json.dumps(log_data, indent=2)

def print_header(title: str, level: int = 1):
    """Print formatted header"""
    if level == 1:
        print(f"\n{'='*70}")
        print(f"🎯 {title}")
        print('='*70)
    elif level == 2:
        print(f"\n{'🔸' * 3} {title}")
        print('-' * 60)
    else:
        print(f"\n💡 {title}")

def demonstrate_scenario_overview(scenarios: Dict):
    """Show overview of all scenarios"""
    print_header("CORTEX SECURITY SCENARIOS OVERVIEW", 1)
    
    traditional = [s for s in scenarios.values() if s.scenario_type == "traditional_ir"]
    cloud_native = [s for s in scenarios.values() if s.scenario_type == "cloud_native"]
    competitive = [s for s in scenarios.values() if s.scenario_type == "competitive"]
    
    print(f"📊 Total Scenarios: {len(scenarios)}")
    print(f"   🏢 Traditional IR: {len(traditional)}")
    print(f"   ☁️  Cloud Native: {len(cloud_native)}")
    print(f"   🥊 Competitive: {len(competitive)}")
    
    print_header("TRADITIONAL INCIDENT RESPONSE", 2)
    for scenario in traditional:
        print(f"   • {scenario.name}")
        print(f"     Duration: {scenario.duration_hours}h | Impact: {scenario.business_impact}")
        print(f"     Capabilities: {', '.join(scenario.capabilities)}")
        print(f"     MITRE Techniques: {len(scenario.mitre_techniques)}")
        print()
    
    print_header("CLOUD NATIVE SECURITY", 2) 
    for scenario in cloud_native:
        print(f"   • {scenario.name}")
        print(f"     Duration: {scenario.duration_hours}h | Environment: {scenario.target_environment}")
        print(f"     Capabilities: {', '.join(scenario.capabilities)}")
        print()
    
    print_header("COMPETITIVE DIFFERENTIATION", 2)
    for scenario in competitive:
        print(f"   • {scenario.name}")
        competitors = set(comp["competitor"] for comp in scenario.competitive_advantages)
        print(f"     Competitors: {', '.join(competitors)}")
        print()

def demonstrate_apt_scenario(scenarios: Dict):
    """Detailed APT scenario demonstration"""
    print_header("APT MULTI-VECTOR ATTACK DEMONSTRATION", 1)
    
    scenario = scenarios["APT_MULTI_VECTOR"]
    print(f"🎭 Scenario: {scenario.name}")
    print(f"📝 Description: {scenario.description}")
    print(f"⏱️  Duration: {scenario.duration_hours} hours")
    print(f"🎯 Environment: {scenario.target_environment}")
    print(f"💥 Business Impact: {scenario.business_impact}")
    
    print_header("CORTEX CAPABILITIES", 2)
    for capability in scenario.capabilities:
        print(f"   ✅ {capability}")
    
    print_header("ATTACK TIMELINE", 2)
    for event in scenario.timeline_events:
        print(f"   {event['timestamp']} | {event['stage']} | {event['technique']}")
        print(f"      {event['description']}")
        print(f"      🛡️  Cortex: {event['cortex_detection']}")
        print(f"      🥊 vs Competition: {event['competitive_advantage']}")
        print(f"      📊 Vendors: {', '.join(event['vendors'])}")
        print()
    
    print_header("COMPETITIVE ADVANTAGES", 2)
    for advantage in scenario.competitive_advantages:
        print(f"   🏆 vs {advantage['competitor']}:")
        print(f"      {advantage['advantage']}")
        print(f"      Details: {advantage['details']}")
        print()
    
    print_header("REALISTIC EVENT GENERATION", 2)
    events = generate_realistic_events(scenario)
    
    high_confidence = len([e for e in events if e["confidence"] > 0.8])
    correlated = len([e for e in events if "correlation_id" in e])
    
    print(f"📊 Generated {len(events)} security events")
    print(f"   🎯 High Confidence: {high_confidence}")
    print(f"   🔗 Correlated Events: {correlated}")
    
    print(f"\n📋 Sample Events:")
    for i, event in enumerate(events[:3]):
        print(f"   Event {i+1}: {event['event_id']}")
        print(f"      Stage: {event['stage']}")
        print(f"      Technique: {event['mitre_technique']}")
        print(f"      Confidence: {event['confidence']:.2f}")
        print(f"      Vendors: {', '.join(event['vendors'])}")
        print()

def demonstrate_cloud_scenario(scenarios: Dict):
    """Cloud-native scenario demonstration"""
    print_header("CONTAINER BREAKOUT SCENARIO", 1)
    
    scenario = scenarios["CONTAINER_ESCAPE"] 
    print(f"🐳 Scenario: {scenario.name}")
    print(f"📝 Description: {scenario.description}")
    print(f"⏱️  Duration: {scenario.duration_hours} hours")
    print(f"🎯 Environment: {scenario.target_environment}")
    
    print_header("CLOUD-NATIVE CAPABILITIES", 2)
    for capability in scenario.capabilities:
        print(f"   ☁️  {capability}")
    
    print_header("ATTACK PROGRESSION", 2)
    for event in scenario.timeline_events:
        print(f"   {event['timestamp']} | {event['stage']} | {event['technique']}")
        print(f"      {event['description']}")
        print(f"      🛡️  Cortex: {event['cortex_detection']}")
        print(f"      🥊 Advantage: {event['competitive_advantage']}")
        print()
    
    print_header("CONTAINER-SPECIFIC EVENTS", 2)
    events = generate_realistic_events(scenario)
    
    container_events = [e for e in events if any(word in e["description"].lower() 
                                               for word in ["container", "kubernetes", "pod"])]
    print(f"🐳 Container Events: {len(container_events)}")
    print(f"📊 Total Events: {len(events)}")
    
    for event in container_events[:2]:
        print(f"\n   🔍 {event['event_id']}")
        print(f"      Technique: {event['mitre_technique']}")
        print(f"      Description: {event['description']}")
        print(f"      Vendors: {', '.join(event['vendors'])}")

def demonstrate_competitive_analysis(scenarios: Dict):
    """Competitive analysis demonstration"""
    print_header("COMPETITIVE ANALYSIS", 1)
    
    competitive_scenario = scenarios["CORTEX_VS_CROWDSTRIKE"]
    
    print_header("CORTEX vs CROWDSTRIKE", 2)
    print(f"🎭 Scenario: {competitive_scenario.name}")
    print(f"📝 {competitive_scenario.description}")
    
    events = generate_realistic_events(competitive_scenario)
    
    print(f"\n📊 Detection Comparison:")
    print(f"   Cortex Events Generated: {len(events)}")
    print(f"   High Confidence Detections: {len([e for e in events if e['confidence'] > 0.8])}")
    print(f"   Multi-Vendor Correlation: {len([e for e in events if 'correlation_id' in e])}")
    
    print(f"\n🏆 Key Advantages:")
    for advantage in competitive_scenario.competitive_advantages:
        print(f"   • vs {advantage['competitor']}:")
        print(f"     {advantage['advantage']}")
        print(f"     {advantage['details']}")
        print()
    
    print_header("SCENARIO COMPARISON MATRIX", 2)
    print(f"{'Capability':<30} {'Cortex':<15} {'CrowdStrike':<15}")
    print("-" * 60)
    print(f"{'Email Security':<30} {'✅ Integrated':<15} {'❌ Limited':<15}")
    print(f"{'Network Visibility':<30} {'✅ Native':<15} {'⚠️ Basic':<15}")
    print(f"{'Container Security':<30} {'✅ Built-in':<15} {'⚠️ Add-on':<15}")
    print(f"{'Cloud Workloads':<30} {'✅ Multi-cloud':<15} {'⚠️ Limited':<15}")
    print(f"{'Correlation Engine':<30} {'✅ Automatic':<15} {'❌ Manual':<15}")

def demonstrate_detection_rules(scenarios: Dict):
    """Show Cortex-specific detection rules"""
    print_header("CORTEX DETECTION RULES & ANALYTICS", 1)
    
    detection_rules = {
        "CORTEX_XDR_001": {
            "name": "Multi-Vector Attack Correlation",
            "description": "Correlates endpoint, network, and email events for APT detection",
            "capability": "XDR Multi-Source Correlation",
            "techniques": ["T1566.001", "T1059.001", "T1055", "T1021.001"],
            "confidence": 0.92,
            "data_sources": ["Cortex XDR Agent", "Palo Alto Firewall", "Email Security"],
            "competitive_advantage": "Unlike CrowdStrike single-point detection, provides full attack chain visibility"
        },
        "CORTEX_CLOUD_001": {
            "name": "Container Runtime Threat Detection", 
            "description": "Real-time detection of malicious activity in containerized workloads",
            "capability": "Container Security",
            "techniques": ["T1611", "T1610", "T1613", "T1609"],
            "confidence": 0.94,
            "data_sources": ["Prisma Cloud Defender", "Kubernetes API", "Container Runtime"],
            "competitive_advantage": "Native Kubernetes integration vs CrowdStrike's bolt-on approach"
        },
        "CORTEX_BEHAVIOR_001": {
            "name": "Advanced User Behavioral Analytics",
            "description": "ML-based detection of insider threats and compromised accounts", 
            "capability": "Behavioral Analytics",
            "techniques": ["T1078", "T1087.001", "T1005", "T1041"],
            "confidence": 0.87,
            "data_sources": ["Cortex XDR", "Azure AD", "O365 Logs"],
            "competitive_advantage": "Deeper behavioral analytics than Sentinel's basic UEBA"
        },
        "CORTEX_SERVERLESS_001": {
            "name": "Serverless Function Abuse Detection",
            "description": "Detects malicious serverless function execution and privilege escalation",
            "capability": "Serverless Protection", 
            "techniques": ["T1578.002", "T1537", "T1552.005"],
            "confidence": 0.89,
            "data_sources": ["AWS Lambda", "Azure Functions", "GCP Cloud Functions"],
            "competitive_advantage": "Serverless-native protection unavailable in traditional EDR"
        }
    }
    
    print(f"📊 Cortex Detection Rules: {len(detection_rules)}")
    
    for rule_id, rule in detection_rules.items():
        print(f"\n🔍 {rule_id}: {rule['name']}")
        print(f"   Description: {rule['description']}")
        print(f"   Capability: {rule['capability']}")
        print(f"   Techniques: {', '.join(rule['techniques'])}")
        print(f"   Confidence: {rule['confidence']:.0%}")
        print(f"   Data Sources: {', '.join(rule['data_sources'])}")
        print(f"   🏆 Advantage: {rule['competitive_advantage']}")

def main():
    """Main demonstration"""
    print("🌟" * 35)
    print("   CORTEX XSIAM/CLOUD SECURITY SCENARIOS")
    print("      Advanced Threat Detection & Response")
    print("       Competitive Research & Analysis") 
    print("🌟" * 35)
    
    print(f"\n🎯 This demonstration showcases:")
    print("   ✅ Cortex XSIAM/Cloud specific security scenarios")
    print("   ✅ Traditional incident response vs cloud-native scenarios")
    print("   ✅ Competitive research: CrowdStrike, Microsoft Sentinel, others")
    print("   ✅ Realistic multi-vendor event generation with MITRE mapping")
    print("   ✅ Custom detection rules aligned to Cortex capabilities")
    print("   ✅ Enterprise-grade attack simulation and response")
    
    # Create scenario library
    scenarios = create_cortex_scenarios()
    
    # Run demonstrations
    demonstrate_scenario_overview(scenarios)
    demonstrate_apt_scenario(scenarios)
    demonstrate_cloud_scenario(scenarios)
    demonstrate_competitive_analysis(scenarios)
    demonstrate_detection_rules(scenarios)
    
    print_header("CORTEX SCENARIOS READY FOR DEPLOYMENT", 1)
    print("🎉 All demonstrations completed successfully!")
    
    print(f"\n🚀 Perfect for Domain Consultants:")
    print("   • Customer security assessment presentations")
    print("   • Competitive displacement conversations")
    print("   • Proof of concept demonstrations")
    print("   • SOC team training and tabletop exercises")
    print("   • XSIAM/Prisma Cloud evaluation scenarios")
    
    print(f"\n📊 System Capabilities:")
    print(f"   • {len(scenarios)} comprehensive security scenarios")
    print("   • Traditional IR + Cloud-native coverage")
    print("   • CrowdStrike, Sentinel, Splunk competitive analysis")
    print("   • MITRE ATT&CK technique mapping")
    print("   • Realistic event generation with correlation")
    print("   • Custom Cortex detection rules and analytics")
    
    print(f"\n💼 Business Value:")
    print("   • Reduced mean time to detection (MTTD)")
    print("   • Lower mean time to response (MTTR)")  
    print("   • Unified security operations platform")
    print("   • Multi-cloud and hybrid environment support")
    print("   • Advanced threat correlation and analytics")
    
    return True

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"❌ Error: {e}")
        exit(1)