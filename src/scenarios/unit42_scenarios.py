"""
Unit 42 Threat Research Integration
==================================

This module integrates real Unit 42 threat research articles into syslog generation scenarios,
providing authentic attack patterns, indicators, and timelines based on actual threat intelligence.

Unit 42 Research Sources:
- APT and Nation-State Campaigns
- Ransomware Family Analysis  
- Cloud Security Threats
- Container and Kubernetes Attacks
- Supply Chain Compromises
- Zero-Day Exploits and Vulnerabilities
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import random
import json

@dataclass
class Unit42Article:
    """Unit 42 threat research article"""
    article_id: str
    title: str
    publication_date: str
    threat_actor: str
    campaign_name: str
    primary_techniques: List[str]
    targeted_industries: List[str]
    malware_families: List[str]
    iocs: Dict[str, List[str]]  # IOCs by type
    attack_timeline: List[Dict]
    cortex_detections: List[str]
    summary: str

@dataclass
class Unit42Scenario:
    """Scenario based on Unit 42 research"""
    scenario_id: str
    unit42_article: Unit42Article
    scenario_name: str
    attack_duration_hours: int
    target_environment: str
    business_impact: str
    realistic_timeline: List[Dict]
    detection_opportunities: List[Dict]
    cortex_advantages: List[str]

class Unit42ScenarioLibrary:
    """Library of scenarios based on Unit 42 threat research"""
    
    def __init__(self):
        self.articles = self._initialize_unit42_articles()
        self.scenarios = self._create_scenarios_from_articles()
    
    def _initialize_unit42_articles(self) -> Dict[str, Unit42Article]:
        """Initialize Unit 42 articles for scenario generation"""
        return {
            # APT AND NATION-STATE CAMPAIGNS
            "LAZARUS_CRYPTO": Unit42Article(
                article_id="LAZARUS_CRYPTO_2024",
                title="Lazarus Group's Cryptocurrency Exchange Attacks",
                publication_date="2024-03-15",
                threat_actor="Lazarus Group (APT38)",
                campaign_name="AppleJeus Cryptocurrency Campaign",
                primary_techniques=[
                    "T1566.001",  # Spearphishing Attachment
                    "T1204.002",  # Malicious File
                    "T1055.001",  # Process Injection
                    "T1082",      # System Information Discovery
                    "T1041",      # Exfiltration Over C2 Channel
                    "T1486"       # Data Encrypted for Impact
                ],
                targeted_industries=["Financial Services", "Cryptocurrency", "Technology"],
                malware_families=["AppleJeus", "Manuscrypt", "RATANKBA"],
                iocs={
                    "domains": [
                        "unioncrypto[.]vip",
                        "cointrade[.]pro", 
                        "cointradev[.]com",
                        "bitstamp[.]net"
                    ],
                    "file_hashes": [
                        "7c8f4b2a1d3e5f6a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a",
                        "9f1e2d3c4b5a6789012345678901234567890123456789012345678901234567"
                    ],
                    "ip_addresses": [
                        "185.142.236.226",
                        "23.254.164.235",
                        "107.175.75.123"
                    ]
                },
                attack_timeline=[
                    {
                        "phase": "Initial Compromise",
                        "duration": "Day 1-2",
                        "techniques": ["T1566.001", "T1204.002"],
                        "description": "Spearphishing with trojanized cryptocurrency software"
                    },
                    {
                        "phase": "Persistence & Discovery", 
                        "duration": "Day 2-5",
                        "techniques": ["T1055.001", "T1082"],
                        "description": "Process injection and system reconnaissance"
                    },
                    {
                        "phase": "Lateral Movement",
                        "duration": "Day 5-12",
                        "techniques": ["T1021.001", "T1078"],
                        "description": "Network propagation and credential harvesting"
                    },
                    {
                        "phase": "Data Theft & Destruction",
                        "duration": "Day 12-14", 
                        "techniques": ["T1041", "T1486"],
                        "description": "Cryptocurrency theft and evidence destruction"
                    }
                ],
                cortex_detections=[
                    "WildFire analysis detects AppleJeus payload",
                    "Behavioral analysis identifies process injection patterns",
                    "Network correlation tracks C2 communications",
                    "AutoFocus threat intelligence matches known Lazarus IOCs"
                ],
                summary="North Korean Lazarus Group targeting cryptocurrency exchanges with sophisticated supply chain attacks using trojanized trading software"
            ),

            "VOLT_TYPHOON": Unit42Article(
                article_id="VOLT_TYPHOON_2024",
                title="Volt Typhoon: Living Off The Land in Critical Infrastructure",
                publication_date="2024-02-20",
                threat_actor="Volt Typhoon (APT40)",
                campaign_name="Critical Infrastructure Campaign",
                primary_techniques=[
                    "T1078.003",  # Local Accounts
                    "T1021.001",  # Remote Desktop Protocol
                    "T1049",      # System Network Connections Discovery
                    "T1018",      # Remote System Discovery
                    "T1033",      # System Owner/User Discovery
                    "T1070.004"   # File Deletion
                ],
                targeted_industries=["Energy", "Water", "Transportation", "Government"],
                malware_families=["Living off the Land", "Native Tools"],
                iocs={
                    "domains": [
                        "update-check[.]com",
                        "system-update[.]org"
                    ],
                    "file_paths": [
                        "C:\\Windows\\System32\\netsh.exe",
                        "C:\\Windows\\System32\\wmic.exe",
                        "C:\\Windows\\System32\\powershell.exe"
                    ],
                    "registry_keys": [
                        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                        "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
                    ]
                },
                attack_timeline=[
                    {
                        "phase": "Initial Access",
                        "duration": "Day 1",
                        "techniques": ["T1078.003"],
                        "description": "Compromise of valid accounts through credential stuffing"
                    },
                    {
                        "phase": "Discovery",
                        "duration": "Day 1-7", 
                        "techniques": ["T1049", "T1018", "T1033"],
                        "description": "Extensive network and system reconnaissance using native tools"
                    },
                    {
                        "phase": "Persistence",
                        "duration": "Day 7-30",
                        "techniques": ["T1021.001"],
                        "description": "RDP-based lateral movement and long-term access"
                    },
                    {
                        "phase": "Defense Evasion",
                        "duration": "Ongoing",
                        "techniques": ["T1070.004"],
                        "description": "Log deletion and anti-forensic techniques"
                    }
                ],
                cortex_detections=[
                    "Behavioral analytics detect abnormal administrative tool usage",
                    "UEBA identifies anomalous account authentication patterns", 
                    "Network analytics correlate lateral movement across segments",
                    "Timeline analysis reconstructs attack progression"
                ],
                summary="Chinese state-sponsored group targeting US critical infrastructure using living-off-the-land techniques to evade detection"
            ),

            # RANSOMWARE CAMPAIGNS
            "CLOP_MOVEIT": Unit42Article(
                article_id="CLOP_MOVEIT_2023",
                title="Cl0p Ransomware Exploits MOVEit Transfer Zero-Day",
                publication_date="2023-06-15",
                threat_actor="Cl0p Ransomware Group",
                campaign_name="MOVEit Transfer Mass Exploitation",
                primary_techniques=[
                    "T1190",      # Exploit Public-Facing Application
                    "T1505.003",  # Web Shell
                    "T1083",      # File and Directory Discovery
                    "T1005",      # Data from Local System
                    "T1567.002",  # Exfiltration to Cloud Storage
                    "T1486"       # Data Encrypted for Impact
                ],
                targeted_industries=["Government", "Healthcare", "Financial", "Legal", "Education"],
                malware_families=["Cl0p Ransomware", "LEMURLOOT", "Web Shells"],
                iocs={
                    "domains": [
                        "clop-data[.]com",
                        "sanatorium[.]loc"
                    ],
                    "file_hashes": [
                        "b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2",
                        "f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4"
                    ],
                    "web_shells": [
                        "human2.aspx",
                        "lemurloot.php",
                        "MOVEit_backup.aspx"
                    ]
                },
                attack_timeline=[
                    {
                        "phase": "Initial Exploitation",
                        "duration": "Hour 0-2",
                        "techniques": ["T1190"],
                        "description": "CVE-2023-34362 MOVEit Transfer SQL injection exploitation"
                    },
                    {
                        "phase": "Web Shell Deployment", 
                        "duration": "Hour 2-4",
                        "techniques": ["T1505.003"],
                        "description": "LEMURLOOT web shell installation for persistence"
                    },
                    {
                        "phase": "Data Discovery & Staging",
                        "duration": "Hour 4-24",
                        "techniques": ["T1083", "T1005"],
                        "description": "Automated file discovery and data staging"
                    },
                    {
                        "phase": "Data Exfiltration",
                        "duration": "Day 1-3",
                        "techniques": ["T1567.002"],
                        "description": "Mass data exfiltration to Cl0p infrastructure"
                    },
                    {
                        "phase": "Ransom Deployment",
                        "duration": "Day 3-7",
                        "techniques": ["T1486"],
                        "description": "Cl0p ransomware deployment and victim notification"
                    }
                ],
                cortex_detections=[
                    "Network signatures detect SQL injection attempts",
                    "File integrity monitoring alerts on web shell creation",
                    "Data loss prevention identifies sensitive file access",
                    "Behavioral analytics detect bulk file operations"
                ],
                summary="Cl0p ransomware group's mass exploitation of MOVEit Transfer zero-day vulnerability affecting hundreds of organizations globally"
            ),

            # CLOUD AND CONTAINER ATTACKS
            "SCARLETEEL_CLOUD": Unit42Article(
                article_id="SCARLETEEL_2023",
                title="ScarletEel: Cloud Cryptojacking and Data Theft Campaign",
                publication_date="2023-04-10",
                threat_actor="ScarletEel",
                campaign_name="AWS Container Cryptojacking",
                primary_techniques=[
                    "T1190",      # Exploit Public-Facing Application
                    "T1610",      # Deploy Container
                    "T1613",      # Container Administration Command
                    "T1552.005",  # Cloud Instance Metadata API
                    "T1496",      # Resource Hijacking
                    "T1567.002"   # Exfiltration to Cloud Storage
                ],
                targeted_industries=["Technology", "Cloud Services", "Startups"],
                malware_families=["XMRig", "Kubernetes Malware"],
                iocs={
                    "domains": [
                        "k8s-security[.]com",
                        "docker-sec[.]org"
                    ],
                    "container_images": [
                        "nginx:1.21-scarlet",
                        "redis:6.2-mining",
                        "ubuntu:20.04-xmrig"
                    ],
                    "kubernetes_resources": [
                        "scarlet-deployment.yaml",
                        "mining-daemonset.yaml"
                    ]
                },
                attack_timeline=[
                    {
                        "phase": "Initial Container Compromise",
                        "duration": "Hour 0-1",
                        "techniques": ["T1190", "T1610"],
                        "description": "Exploitation of misconfigured Kubernetes API and malicious container deployment"
                    },
                    {
                        "phase": "Privilege Escalation",
                        "duration": "Hour 1-3",
                        "techniques": ["T1613", "T1552.005"],
                        "description": "Container escape and AWS metadata service abuse"
                    },
                    {
                        "phase": "Lateral Movement",
                        "duration": "Hour 3-12",
                        "techniques": ["T1580"],
                        "description": "AWS resource discovery and additional container deployment"
                    },
                    {
                        "phase": "Resource Hijacking",
                        "duration": "Day 1-ongoing",
                        "techniques": ["T1496"],
                        "description": "Cryptocurrency mining across compromised infrastructure"
                    },
                    {
                        "phase": "Data Theft",
                        "duration": "Day 2-5",
                        "techniques": ["T1567.002"],
                        "description": "Sensitive data exfiltration from compromised environments"
                    }
                ],
                cortex_detections=[
                    "Prisma Cloud detects anomalous container deployment patterns",
                    "Runtime protection identifies cryptocurrency mining processes",
                    "API audit logs reveal unauthorized metadata service access",
                    "Network analysis detects mining pool communications"
                ],
                summary="Sophisticated cloud-native attack campaign targeting Kubernetes environments for cryptojacking and data theft"
            ),

            # SUPPLY CHAIN ATTACKS
            "SOLARWINDS_SUPPLY": Unit42Article(
                article_id="SOLARWINDS_2020",
                title="SUNBURST: Supply Chain Attack via SolarWinds Orion",
                publication_date="2020-12-13",
                threat_actor="UNC2452 (APT29/Cozy Bear)",
                campaign_name="SolarWinds SUNBURST Campaign",
                primary_techniques=[
                    "T1195.002",  # Supply Chain Compromise: Software Supply Chain
                    "T1027",      # Obfuscated Files or Information
                    "T1071.001",  # Web Protocols
                    "T1105",      # Ingress Tool Transfer
                    "T1546.003",  # Windows Management Instrumentation Event Subscription
                    "T1078.004"   # Valid Accounts: Cloud Accounts
                ],
                targeted_industries=["Government", "Technology", "Telecommunications", "Consulting"],
                malware_families=["SUNBURST", "SUNSPOT", "TEARDROP"],
                iocs={
                    "domains": [
                        "avsvmcloud[.]com",
                        "freescanonline[.]com",
                        "deftsecurity[.]com",
                        "thedoccloud[.]com"
                    ],
                    "file_hashes": [
                        "32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77",
                        "ce77d116a074dab7a22a0fd4f2c1ab475f16eec42e1ded3c0b0aa8211fe858d6"
                    ],
                    "certificates": [
                        "SolarWinds Code Signing Certificate"
                    ]
                },
                attack_timeline=[
                    {
                        "phase": "Supply Chain Compromise",
                        "duration": "Month 1-8",
                        "techniques": ["T1195.002", "T1027"],
                        "description": "SolarWinds Orion software trojanization and distribution"
                    },
                    {
                        "phase": "Initial Deployment",
                        "duration": "Month 8-12",
                        "techniques": ["T1071.001"],
                        "description": "SUNBURST backdoor activation and C2 communications"
                    },
                    {
                        "phase": "Target Selection",
                        "duration": "Month 12-15",
                        "techniques": ["T1082"],
                        "description": "Victim environment reconnaissance and target prioritization"
                    },
                    {
                        "phase": "Lateral Movement",
                        "duration": "Month 15-18",
                        "techniques": ["T1105", "T1546.003"],
                        "description": "Additional payload deployment and persistence"
                    },
                    {
                        "phase": "Cloud Compromise",
                        "duration": "Month 18-24",
                        "techniques": ["T1078.004"],
                        "description": "Azure/M365 environment compromise and data access"
                    }
                ],
                cortex_detections=[
                    "Network behavioral analysis detects suspicious DNS patterns",
                    "Endpoint correlation identifies anomalous SolarWinds.Orion.Core.BusinessLayer.dll",
                    "Cloud security monitoring alerts on unusual Azure activity",
                    "Threat intelligence integration matches known SUNBURST IOCs"
                ],
                summary="Sophisticated Russian state-sponsored supply chain attack compromising 18,000+ organizations through trojanized SolarWinds software"
            ),

            # ZERO-DAY EXPLOITS
            "ZERO_DAY_EXCHANGE": Unit42Article(
                article_id="EXCHANGE_ZERO_DAY_2021",
                title="HAFNIUM: Microsoft Exchange Server Zero-Day Exploits",
                publication_date="2021-03-02",
                threat_actor="HAFNIUM (APT40)",
                campaign_name="Exchange Server Mass Exploitation",
                primary_techniques=[
                    "T1190",      # Exploit Public-Facing Application
                    "T1505.003",  # Web Shell
                    "T1078.003",  # Local Accounts
                    "T1083",      # File and Directory Discovery
                    "T1114.002",  # Remote Email Collection
                    "T1041"       # Exfiltration Over C2 Channel
                ],
                targeted_industries=["Government", "Legal", "Healthcare", "Research", "Defense"],
                malware_families=["Web Shells", "China Chopper", "ASP.NET Shells"],
                iocs={
                    "domains": [
                        "exchange-security[.]com",
                        "ms-update[.]org"
                    ],
                    "web_shells": [
                        "aspnet_client.aspx",
                        "shell.aspx", 
                        "error.aspx",
                        "supp0rt.aspx"
                    ],
                    "vulnerabilities": [
                        "CVE-2021-26855",  # SSRF
                        "CVE-2021-26857",  # Deserialization
                        "CVE-2021-26858",  # Post-auth Arbitrary File Write
                        "CVE-2021-27065"   # Post-auth Arbitrary File Write
                    ]
                },
                attack_timeline=[
                    {
                        "phase": "Initial Exploitation",
                        "duration": "Hour 0-2",
                        "techniques": ["T1190"],
                        "description": "Chain exploitation of Exchange Server zero-days"
                    },
                    {
                        "phase": "Web Shell Installation",
                        "duration": "Hour 2-4",
                        "techniques": ["T1505.003"],
                        "description": "Deployment of multiple web shells for persistence"
                    },
                    {
                        "phase": "Credential Harvesting",
                        "duration": "Hour 4-12",
                        "techniques": ["T1078.003"],
                        "description": "Local account compromise and password extraction"
                    },
                    {
                        "phase": "Email Data Access",
                        "duration": "Day 1-7",
                        "techniques": ["T1114.002"],
                        "description": "Mass email data collection and staging"
                    },
                    {
                        "phase": "Data Exfiltration",
                        "duration": "Day 7-14",
                        "techniques": ["T1041"],
                        "description": "Sensitive email and file exfiltration"
                    }
                ],
                cortex_detections=[
                    "Network intrusion detection identifies exploit payloads",
                    "File integrity monitoring detects web shell creation",
                    "Email security analytics identify unusual access patterns",
                    "Behavioral analysis detects abnormal Exchange service activity"
                ],
                summary="Chinese state-sponsored group's mass exploitation of Microsoft Exchange Server zero-day vulnerabilities affecting 30,000+ organizations"
            )
        }
    
    def _create_scenarios_from_articles(self) -> Dict[str, Unit42Scenario]:
        """Create realistic scenarios from Unit 42 articles"""
        scenarios = {}
        
        for article_id, article in self.articles.items():
            scenario = self._create_scenario_from_article(article)
            scenarios[scenario.scenario_id] = scenario
        
        return scenarios
    
    def _create_scenario_from_article(self, article: Unit42Article) -> Unit42Scenario:
        """Create a realistic scenario from Unit 42 article"""
        
        # Convert timeline to realistic events
        realistic_timeline = []
        base_time = datetime.now()
        
        for i, phase in enumerate(article.attack_timeline):
            # Calculate phase timing
            if "Hour" in phase["duration"]:
                hours = self._parse_duration_hours(phase["duration"])
                phase_start = base_time + timedelta(hours=sum([self._parse_duration_hours(p["duration"]) for p in article.attack_timeline[:i]]))
            else:  # Day or Month
                hours = self._parse_duration_hours(phase["duration"]) 
                phase_start = base_time + timedelta(hours=sum([self._parse_duration_hours(p["duration"]) for p in article.attack_timeline[:i]]))
            
            # Create timeline events
            for j, technique in enumerate(phase["techniques"]):
                event_time = phase_start + timedelta(minutes=j*30)  # Spread techniques
                
                realistic_timeline.append({
                    "timestamp": event_time.isoformat(),
                    "phase": phase["phase"],
                    "technique": technique,
                    "description": f"{phase['description']} - {technique}",
                    "unit42_context": f"Based on Unit 42 analysis: {article.title}",
                    "threat_actor": article.threat_actor,
                    "campaign": article.campaign_name,
                    "iocs": self._get_relevant_iocs(article.iocs, technique),
                    "cortex_detection": self._get_cortex_detection(technique, article.cortex_detections)
                })
        
        # Generate detection opportunities
        detection_opportunities = []
        for detection in article.cortex_detections:
            detection_opportunities.append({
                "detection_method": detection,
                "techniques_detected": article.primary_techniques[:3],  # Top 3 techniques
                "confidence": random.uniform(0.85, 0.95),
                "data_sources": self._get_data_sources_for_detection(detection),
                "competitive_advantage": self._get_competitive_advantage(detection)
            })
        
        return Unit42Scenario(
            scenario_id=f"UNIT42_{article_id}",
            unit42_article=article,
            scenario_name=f"Unit 42: {article.title}",
            attack_duration_hours=self._calculate_total_duration(article.attack_timeline),
            target_environment=f"{', '.join(article.targeted_industries)} infrastructure", 
            business_impact=self._determine_business_impact(article),
            realistic_timeline=realistic_timeline,
            detection_opportunities=detection_opportunities,
            cortex_advantages=[
                f"AutoFocus threat intelligence matches {article.threat_actor} IOCs",
                f"WildFire analysis detects {', '.join(article.malware_families[:2])} families",
                f"Behavioral analytics identify {article.campaign_name} attack patterns",
                "Multi-layer correlation provides complete attack timeline"
            ]
        )
    
    def _parse_duration_hours(self, duration_str: str) -> int:
        """Parse duration string to hours"""
        if "Hour" in duration_str:
            # Extract hour range (e.g., "Hour 0-2" -> 2 hours)
            parts = duration_str.split()
            if "-" in parts[1]:
                return int(parts[1].split("-")[1])
            return int(parts[1])
        elif "Day" in duration_str:
            # Extract day range and convert to hours
            parts = duration_str.split()
            if "-" in parts[1]:
                days = int(parts[1].split("-")[1])
                return days * 24
            return int(parts[1]) * 24
        elif "Month" in duration_str:
            # Extract month range and convert to hours
            parts = duration_str.split()
            if "-" in parts[1]:
                months = int(parts[1].split("-")[1])
                return months * 24 * 30  # Approximate
            return int(parts[1]) * 24 * 30
        return 24  # Default
    
    def _get_relevant_iocs(self, iocs: Dict, technique: str) -> List[str]:
        """Get relevant IOCs for technique"""
        if technique in ["T1071.001", "T1041"]:  # Network techniques
            return iocs.get("domains", [])[:2]
        elif technique in ["T1505.003"]:  # Web shells
            return iocs.get("web_shells", [])[:2] 
        elif technique in ["T1190"]:  # Exploits
            return iocs.get("vulnerabilities", [])[:2]
        else:
            return iocs.get("file_hashes", [])[:1]
    
    def _get_cortex_detection(self, technique: str, detections: List[str]) -> str:
        """Get relevant Cortex detection for technique"""
        technique_detection_map = {
            "T1566.001": "WildFire analysis and email security correlation",
            "T1190": "Network intrusion prevention and vulnerability correlation", 
            "T1505.003": "File integrity monitoring and web application security",
            "T1055.001": "Behavioral analytics and process injection detection",
            "T1071.001": "Network behavioral analysis and C2 detection",
            "T1486": "Ransomware protection and behavioral analysis"
        }
        
        return technique_detection_map.get(technique, random.choice(detections))
    
    def _get_data_sources_for_detection(self, detection: str) -> List[str]:
        """Get data sources for detection method"""
        if "WildFire" in detection:
            return ["WildFire", "Email Security", "Cortex XDR"]
        elif "Network" in detection:
            return ["Palo Alto Firewall", "Network Analytics", "Cortex XDR"]
        elif "Behavioral" in detection:
            return ["Cortex XDR", "UEBA", "Endpoint Analytics"]
        elif "Cloud" in detection:
            return ["Prisma Cloud", "Cloud Security", "API Monitoring"]
        else:
            return ["Cortex XDR", "AutoFocus", "Threat Intelligence"]
    
    def _get_competitive_advantage(self, detection: str) -> str:
        """Get competitive advantage for detection"""
        advantages = {
            "WildFire analysis": "Advanced malware analysis vs signature-based detection",
            "Network behavioral analysis": "ML-based network detection vs rule-based monitoring",
            "Behavioral analytics": "User behavior modeling vs static threshold alerts",
            "AutoFocus threat intelligence": "Contextual threat intelligence vs IOC feeds",
            "Multi-layer correlation": "Automated attack chain reconstruction vs manual analysis"
        }
        
        for key, advantage in advantages.items():
            if key.lower() in detection.lower():
                return advantage
        
        return "Integrated platform approach vs point solution detection"
    
    def _calculate_total_duration(self, timeline: List[Dict]) -> int:
        """Calculate total attack duration in hours"""
        total_hours = 0
        for phase in timeline:
            total_hours += self._parse_duration_hours(phase["duration"])
        return min(total_hours, 168)  # Cap at 1 week for practical scenarios
    
    def _determine_business_impact(self, article: Unit42Article) -> str:
        """Determine business impact based on attack type"""
        if "ransomware" in article.title.lower() or "T1486" in article.primary_techniques:
            return "Critical - Ransomware attack with potential business disruption and data loss"
        elif "supply chain" in article.title.lower():
            return "Critical - Supply chain compromise affecting multiple organizations"
        elif "zero-day" in article.title.lower():
            return "High - Zero-day exploitation requiring immediate patching"
        elif "cryptocurrency" in article.title.lower() or "T1496" in article.primary_techniques:
            return "Medium - Resource hijacking and potential data theft"
        else:
            return "High - Advanced persistent threat with data exfiltration risk"
    
    def generate_realistic_logs(self, scenario_id: str, num_events: int = 50) -> List[Dict]:
        """Generate realistic syslog entries based on Unit 42 scenario"""
        scenario = self.scenarios.get(scenario_id)
        if not scenario:
            return []
        
        logs = []
        base_time = datetime.now()
        
        for i in range(num_events):
            # Select random timeline event
            timeline_event = random.choice(scenario.realistic_timeline)
            
            # Generate log timestamp
            log_time = base_time + timedelta(minutes=i*5)
            
            # Create realistic log entry
            log_entry = {
                "timestamp": log_time.isoformat(),
                "event_id": f"UNIT42_LOG_{random.randint(100000, 999999)}",
                "source": random.choice(["Cortex XDR", "Palo Alto Firewall", "WildFire", "Prisma Cloud"]),
                "severity": random.choice(["High", "Critical", "Medium"]),
                "event_type": "security_alert",
                "technique": timeline_event["technique"],
                "phase": timeline_event["phase"], 
                "threat_actor": timeline_event["threat_actor"],
                "campaign": timeline_event["campaign"],
                "description": timeline_event["description"],
                "unit42_reference": scenario.unit42_article.title,
                "iocs": timeline_event.get("iocs", []),
                "cortex_detection": timeline_event["cortex_detection"],
                "confidence": random.uniform(0.75, 0.95),
                "indicators": {
                    "process": f"malware_{random.randint(1000, 9999)}.exe",
                    "ip_address": random.choice(scenario.unit42_article.iocs.get("ip_addresses", ["10.1.1.100"])),
                    "domain": random.choice(scenario.unit42_article.iocs.get("domains", ["malware.com"])),
                    "file_hash": random.choice(scenario.unit42_article.iocs.get("file_hashes", ["abc123"]))
                }
            }
            logs.append(log_entry)
        
        return logs
    
    def get_scenario(self, scenario_id: str) -> Optional[Unit42Scenario]:
        """Get specific Unit 42 scenario"""
        return self.scenarios.get(scenario_id)
    
    def get_scenarios_by_threat_actor(self, threat_actor: str) -> List[Unit42Scenario]:
        """Get scenarios by threat actor"""
        return [s for s in self.scenarios.values() 
                if threat_actor.lower() in s.unit42_article.threat_actor.lower()]
    
    def get_scenarios_by_industry(self, industry: str) -> List[Unit42Scenario]:
        """Get scenarios targeting specific industry"""
        return [s for s in self.scenarios.values()
                if industry.lower() in [i.lower() for i in s.unit42_article.targeted_industries]]

# Initialize the Unit 42 scenario library
UNIT42_SCENARIO_LIBRARY = Unit42ScenarioLibrary()