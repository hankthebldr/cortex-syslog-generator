"""
MITRE ATT&CK TTP patterns based on real APT groups and domains.

This module contains specific technique patterns used by known APT groups,
organized by domain (Enterprise, Cloud, Mobile) with network heuristics
for detection analytics.
"""

from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from uuid import UUID, uuid4

from ..core.models import (
    HeuristicPattern, 
    AttackTactic, 
    TacticTechnique,
    NICECategory,
    NetworkTuple
)


class APTGroup:
    """Known APT groups and their preferred techniques."""
    
    # Russian Groups
    APT28 = "APT28"  # Fancy Bear / Sofacy
    APT29 = "APT29"  # Cozy Bear / Midnight Blizzard
    TURLA = "Turla"  # Snake / Venomous Bear
    SANDWORM = "Sandworm Team"  # APT44
    
    # Chinese Groups  
    APT1 = "APT1"  # Comment Crew
    APT40 = "APT40"  # Leviathan
    APT41 = "APT41"  # Double Dragon
    VOLT_TYPHOON = "Volt Typhoon"
    
    # North Korean Groups
    LAZARUS = "Lazarus Group"
    APT38 = "APT38"  # BeagleBoyz
    
    # Iranian Groups
    APT33 = "APT33"  # Elfin
    APT34 = "APT34"  # OilRig
    
    # Other Notable Groups
    CARBANAK = "Carbanak"  # FIN7
    WIZARD_SPIDER = "Wizard Spider"  # Conti/TrickBot


# Enterprise Domain Patterns
ENTERPRISE_PERSISTENCE_PATTERNS = {
    
    # T1543.003 - Windows Service Persistence (APT29, APT28)
    "WINDOWS_SERVICE_PERSISTENCE": HeuristicPattern(
        pattern_id="T1543.003_SERVICE_PERSIST",
        pattern_name="Windows Service Persistence",
        description="Create malicious Windows services for persistence - commonly used by APT29 and APT28",
        min_events=5,
        max_events=15,
        time_window_seconds=600.0,
        network_signatures=[
            {"dest_port": 135, "protocol": "TCP", "action": "rpc_connect"},  # RPC endpoint mapper
            {"dest_port": 445, "protocol": "TCP", "action": "smb_connect"},   # SMB for service deployment
            {"dest_port": 139, "protocol": "TCP", "action": "netbios"}       # NetBIOS
        ],
        port_sequences=[[135, 445], [139, 445, 135]],
        protocol_patterns=["TCP"],
        frequency_pattern="burst",
        persistence_indicators=[
            "service_creation",
            "sc.exe_execution", 
            "service_start",
            "registry_service_key",
            "system_service_dll"
        ]
    ),
    
    # T1547.001 - Registry Run Keys (Lazarus, APT28)
    "REGISTRY_AUTOSTART_PERSISTENCE": HeuristicPattern(
        pattern_id="T1547.001_REGISTRY_AUTOSTART",
        pattern_name="Registry Autostart Persistence",
        description="Modify registry autostart keys - signature technique of Lazarus Group",
        min_events=7,
        max_events=20,
        time_window_seconds=300.0,
        network_signatures=[
            {"dest_port": 445, "protocol": "TCP", "action": "smb_connect"},
            {"dest_port": 139, "protocol": "TCP", "action": "netbios"},
            {"dest_port": 135, "protocol": "TCP", "action": "rpc_connect"}
        ],
        port_sequences=[[445, 139], [135, 445]],
        persistence_indicators=[
            "registry_run_key_modification",
            "registry_runonce_key",
            "startup_folder_modification",
            "reg.exe_execution",
            "powershell_registry_modification"
        ]
    ),
    
    # T1053.005 - Scheduled Task Persistence (APT41, Carbanak)
    "SCHEDULED_TASK_PERSISTENCE": HeuristicPattern(
        pattern_id="T1053.005_SCHTASK_PERSIST",
        pattern_name="Scheduled Task Persistence",
        description="Create scheduled tasks for persistence - APT41 signature technique",
        min_events=6,
        max_events=12,
        time_window_seconds=480.0,
        network_signatures=[
            {"dest_port": 445, "protocol": "TCP", "action": "smb_admin_share"},
            {"dest_port": 135, "protocol": "TCP", "action": "rpc_task_scheduler"},
            {"dest_port": 139, "protocol": "TCP", "action": "netbios"}
        ],
        port_sequences=[[445, 135], [139, 445, 135]],
        persistence_indicators=[
            "schtasks.exe_execution",
            "task_scheduler_service_interaction",
            "scheduled_task_creation",
            "task_xml_file_creation",
            "taskschd.dll_loading"
        ]
    ),
    
    # T1078.003 - Local Account Persistence (APT1, APT40)
    "LOCAL_ACCOUNT_MANIPULATION": HeuristicPattern(
        pattern_id="T1078.003_LOCAL_ACCOUNT",
        pattern_name="Local Account Manipulation",
        description="Create or modify local accounts for persistence - APT1 and APT40 technique",
        min_events=8,
        max_events=18,
        time_window_seconds=900.0,
        network_signatures=[
            {"dest_port": 445, "protocol": "TCP", "action": "smb_admin_connect"},
            {"dest_port": 139, "protocol": "TCP", "action": "netbios_session"},
            {"dest_port": 135, "protocol": "TCP", "action": "rpc_samr"}  # Security Account Manager RPC
        ],
        port_sequences=[[445, 135], [139, 445], [135, 139, 445]],
        persistence_indicators=[
            "net_user_add",
            "local_group_modification", 
            "password_policy_change",
            "account_privilege_escalation",
            "hidden_user_creation"
        ]
    )
}

# Cloud Domain Patterns (AWS, Azure, GCP)
CLOUD_PERSISTENCE_PATTERNS = {
    
    # T1098.001 - Additional Cloud Credentials (APT29, Volt Typhoon)
    "CLOUD_CREDENTIAL_PERSISTENCE": HeuristicPattern(
        pattern_id="T1098.001_CLOUD_CREDS",
        pattern_name="Additional Cloud Credentials",
        description="Create additional cloud credentials for persistence - APT29 cloud technique",
        min_events=5,
        max_events=12,
        time_window_seconds=1200.0,
        network_signatures=[
            {"dest_port": 443, "protocol": "TCP", "action": "https_api_call"},
            {"dest_port": 80, "protocol": "TCP", "action": "http_redirect"}
        ],
        port_sequences=[[443], [80, 443]],
        protocol_patterns=["TCP", "HTTPS"],
        frequency_pattern="periodic",
        persistence_indicators=[
            "access_key_creation",
            "service_principal_creation",
            "iam_user_creation",
            "api_key_generation",
            "oauth_app_registration"
        ]
    ),
    
    # T1578.002 - Create Cloud Instance (Sandworm, APT40)
    "CLOUD_INSTANCE_PERSISTENCE": HeuristicPattern(
        pattern_id="T1578.002_CLOUD_INSTANCE",
        pattern_name="Cloud Instance Persistence",
        description="Create cloud instances for persistence - Sandworm Team technique",
        min_events=6,
        max_events=15,
        time_window_seconds=1800.0,
        network_signatures=[
            {"dest_port": 443, "protocol": "TCP", "action": "cloud_api_call"},
            {"dest_port": 22, "protocol": "TCP", "action": "ssh_connect"},
            {"dest_port": 3389, "protocol": "TCP", "action": "rdp_connect"}
        ],
        port_sequences=[[443, 22], [443, 3389], [443, 22, 3389]],
        persistence_indicators=[
            "vm_instance_creation",
            "security_group_modification",
            "ssh_key_injection",
            "user_data_script_execution",
            "instance_metadata_access"
        ]
    ),
    
    # T1136.003 - Cloud Account Creation (APT34, Turla)
    "CLOUD_ACCOUNT_CREATION": HeuristicPattern(
        pattern_id="T1136.003_CLOUD_ACCOUNT",
        pattern_name="Cloud Account Creation",
        description="Create cloud accounts for persistence - APT34 OilRig technique",
        min_events=7,
        max_events=20,
        time_window_seconds=2400.0,
        network_signatures=[
            {"dest_port": 443, "protocol": "TCP", "action": "graph_api_call"},
            {"dest_port": 443, "protocol": "TCP", "action": "management_api"}
        ],
        port_sequences=[[443]],
        protocol_patterns=["HTTPS"],
        persistence_indicators=[
            "user_account_creation",
            "group_membership_modification",
            "role_assignment",
            "directory_sync_bypass",
            "guest_user_creation"
        ]
    ),
    
    # T1484.002 - Domain Policy Modification (APT29 Cloud)
    "CLOUD_POLICY_PERSISTENCE": HeuristicPattern(
        pattern_id="T1484.002_CLOUD_POLICY",
        pattern_name="Cloud Policy Modification",
        description="Modify cloud policies for persistence - APT29 advanced cloud technique",
        min_events=8,
        max_events=16,
        time_window_seconds=3600.0,
        network_signatures=[
            {"dest_port": 443, "protocol": "TCP", "action": "policy_api_call"},
            {"dest_port": 443, "protocol": "TCP", "action": "rbac_modification"}
        ],
        port_sequences=[[443]],
        persistence_indicators=[
            "conditional_access_policy_modification",
            "trust_policy_change",
            "resource_policy_modification",
            "federation_trust_modification",
            "mfa_bypass_policy"
        ]
    )
}

# Cloud Initial Access Patterns
CLOUD_INITIAL_ACCESS_PATTERNS = {
    # T1078.004 - Valid Accounts: Cloud Accounts (Initial Access)
    "VALID_ACCOUNTS_CLOUD": HeuristicPattern(
        pattern_id="T1078.004_VALID_ACCOUNTS_CLOUD",
        pattern_name="Valid Cloud Accounts (Initial Access)",
        description="Use of stolen or seeded valid cloud credentials for initial access",
        min_events=3,
        max_events=10,
        time_window_seconds=900.0,
        network_signatures=[
            {"dest_port": 443, "protocol": "TCP", "action": "idp_auth_attempt"},
            {"dest_port": 443, "protocol": "TCP", "action": "cloud_console_login"}
        ],
        port_sequences=[[443]],
        protocol_patterns=["HTTPS"],
        frequency_pattern="sequential",
        persistence_indicators=["mfa_bypass_attempt", "suspicious_successful_login", "impossible_travel"]
    )
}

# Cloud Discovery Patterns
CLOUD_DISCOVERY_PATTERNS = {
    # T1526 - Cloud Service Discovery
    "CLOUD_SERVICE_DISCOVERY": HeuristicPattern(
        pattern_id="T1526_CLOUD_SERVICE_DISCOVERY",
        pattern_name="Cloud Service Discovery",
        description="Enumerate cloud services, regions, and resources",
        min_events=5,
        max_events=20,
        time_window_seconds=1200.0,
        network_signatures=[
            {"dest_port": 443, "protocol": "TCP", "action": "list_services"},
            {"dest_port": 443, "protocol": "TCP", "action": "list_regions"},
            {"dest_port": 443, "protocol": "TCP", "action": "list_resources"}
        ],
        port_sequences=[[443]],
        protocol_patterns=["HTTPS"],
        frequency_pattern="periodic"
    ),
    # T1087.004 - Account Discovery: Cloud Account
    "CLOUD_ACCOUNT_DISCOVERY": HeuristicPattern(
        pattern_id="T1087.004_CLOUD_ACCOUNT_DISCOVERY",
        pattern_name="Account Discovery: Cloud Account",
        description="Enumerate users, roles, groups, and policies in cloud accounts",
        min_events=5,
        max_events=15,
        time_window_seconds=900.0,
        network_signatures=[
            {"dest_port": 443, "protocol": "TCP", "action": "iam_list_users"},
            {"dest_port": 443, "protocol": "TCP", "action": "iam_list_roles"},
            {"dest_port": 443, "protocol": "TCP", "action": "iam_list_policies"}
        ],
        port_sequences=[[443]],
        protocol_patterns=["HTTPS"],
        frequency_pattern="burst"
    )
}

# Cloud Credential Access Patterns
CLOUD_CREDENTIAL_ACCESS_PATTERNS = {
    # T1552.005 - Cloud Instance Metadata Service
    "CLOUD_IMDS_CREDENTIALS": HeuristicPattern(
        pattern_id="T1552.005_CLOUD_IMDS",
        pattern_name="Cloud Instance Metadata Service Credential Theft",
        description="Retrieve credentials from cloud instance metadata service (IMDS)",
        min_events=3,
        max_events=10,
        time_window_seconds=600.0,
        network_signatures=[
            {"dest_port": 80, "protocol": "TCP", "action": "http_imds_query"},
            {"dest_port": 443, "protocol": "TCP", "action": "imds_v2_token"}
        ],
        port_sequences=[[80], [80, 443]],
        protocol_patterns=["HTTP", "HTTPS"],
        frequency_pattern="rapid_burst",
        escalation_indicators=["sts_assume_role", "temporary_credentials_obtained"]
    ),
    # T1528 - Steal Application Access Token
    "STEAL_APP_ACCESS_TOKEN": HeuristicPattern(
        pattern_id="T1528_STEAL_APP_TOKEN",
        pattern_name="Steal Application Access Token",
        description="Steal tokens from OAuth apps or service principals for API access",
        min_events=4,
        max_events=12,
        time_window_seconds=900.0,
        network_signatures=[
            {"dest_port": 443, "protocol": "TCP", "action": "token_grant_exchange"},
            {"dest_port": 443, "protocol": "TCP", "action": "graph_api_call"}
        ],
        port_sequences=[[443]],
        protocol_patterns=["HTTPS"],
        frequency_pattern="sequential",
        escalation_indicators=["token_cache_access", "consent_grant_anomaly"]
    )
}

# Cloud Defense Evasion Patterns
CLOUD_DEFENSE_EVASION_PATTERNS = {
    # T1562.008 - Disable Cloud Logs
    "DISABLE_CLOUD_LOGS": HeuristicPattern(
        pattern_id="T1562.008_DISABLE_CLOUD_LOGS",
        pattern_name="Disable or Modify Cloud Logs",
        description="Disable, modify, or reduce retention of cloud logging services",
        min_events=3,
        max_events=8,
        time_window_seconds=600.0,
        network_signatures=[
            {"dest_port": 443, "protocol": "TCP", "action": "logging_config_update"},
            {"dest_port": 443, "protocol": "TCP", "action": "retention_policy_change"}
        ],
        port_sequences=[[443]],
        protocol_patterns=["HTTPS"],
        frequency_pattern="burst",
        persistence_indicators=["cloudtrail_disabled", "auditlog_sink_removed", "diagnostic_setting_removed"]
    )
}

# Cloud Collection Patterns
CLOUD_COLLECTION_PATTERNS = {
    # T1530 - Data from Cloud Storage Object
    "DATA_FROM_CLOUD_STORAGE": HeuristicPattern(
        pattern_id="T1530_DATA_FROM_CLOUD_STORAGE",
        pattern_name="Data from Cloud Storage Object",
        description="Access and collect data from cloud object storage buckets/containers",
        min_events=5,
        max_events=25,
        time_window_seconds=1800.0,
        network_signatures=[
            {"dest_port": 443, "protocol": "TCP", "action": "object_get"},
            {"dest_port": 443, "protocol": "TCP", "action": "list_objects"}
        ],
        port_sequences=[[443]],
        protocol_patterns=["HTTPS"],
        frequency_pattern="sequential"
    )
}

# Cloud Exfiltration Patterns
CLOUD_EXFILTRATION_PATTERNS = {
    # T1567.002 - Exfiltration to Cloud Storage
    "EXFIL_TO_CLOUD_STORAGE": HeuristicPattern(
        pattern_id="T1567.002_EXFIL_TO_CLOUD",
        pattern_name="Exfiltration to Cloud Storage",
        description="Exfiltrate data to attacker-controlled cloud storage",
        min_events=5,
        max_events=20,
        time_window_seconds=1200.0,
        network_signatures=[
            {"dest_port": 443, "protocol": "TCP", "action": "object_put"},
            {"dest_port": 443, "protocol": "TCP", "action": "create_bucket"}
        ],
        port_sequences=[[443]],
        protocol_patterns=["HTTPS"],
        frequency_pattern="burst"
    )
}

# Kubernetes/Containers Patterns (part of cloud domain)
KUBERNETES_PATTERNS = {
    # T1609 - Container Administration Command (kubectl exec)
    "K8S_CONTAINER_ADMIN_CMD": HeuristicPattern(
        pattern_id="T1609_CONTAINER_ADMIN_CMD",
        pattern_name="Kubernetes Container Administration Command",
        description="Execute commands inside containers using kubectl exec",
        min_events=5,
        max_events=20,
        time_window_seconds=900.0,
        network_signatures=[
            {"dest_port": 443, "protocol": "TCP", "action": "kube_api_exec"},
            {"dest_port": 10250, "protocol": "TCP", "action": "kubelet_exec"}
        ],
        port_sequences=[[443], [443, 10250]],
        protocol_patterns=["HTTPS"],
        persistence_indicators=["kubectl_exec", "pod_exec", "kubelet_execute"]
    ),
    # T1610 - Deploy Container (create or scale workloads)
    "K8S_DEPLOY_CONTAINER": HeuristicPattern(
        pattern_id="T1610_DEPLOY_CONTAINER",
        pattern_name="Deploy Malicious Container",
        description="Create/scale deployments, jobs, or pods for malicious workloads",
        min_events=5,
        max_events=15,
        time_window_seconds=1200.0,
        network_signatures=[
            {"dest_port": 443, "protocol": "TCP", "action": "kube_api_apply"}
        ],
        port_sequences=[[443]],
        protocol_patterns=["HTTPS"],
        persistence_indicators=["deployment_create", "job_create", "daemonset_create"]
    ),
    # T1611 - Escape to Host (privileged pod / hostPath mount)
    "K8S_ESCAPE_TO_HOST": HeuristicPattern(
        pattern_id="T1611_ESCAPE_TO_HOST",
        pattern_name="Kubernetes Escape to Host",
        description="Abuse privileged pods or host mounts to access node/host",
        min_events=4,
        max_events=10,
        time_window_seconds=900.0,
        network_signatures=[
            {"dest_port": 443, "protocol": "TCP", "action": "privileged_pod_create"}
        ],
        port_sequences=[[443]],
        protocol_patterns=["HTTPS"],
        escalation_indicators=["hostpath_mount", "privileged_true", "capabilities_add_all"]
    ),
    # T1613 - Container and Resource Discovery
    "K8S_RESOURCE_DISCOVERY": HeuristicPattern(
        pattern_id="T1613_CONTAINER_RESOURCE_DISCOVERY",
        pattern_name="Container and Resource Discovery",
        description="List pods, secrets, configmaps, and RBAC objects",
        min_events=6,
        max_events=18,
        time_window_seconds=900.0,
        network_signatures=[
            {"dest_port": 443, "protocol": "TCP", "action": "list_pods"},
            {"dest_port": 443, "protocol": "TCP", "action": "list_secrets"},
            {"dest_port": 443, "protocol": "TCP", "action": "list_rolebindings"}
        ],
        port_sequences=[[443]],
        protocol_patterns=["HTTPS"],
        frequency_pattern="burst"
    ),
}

# Mobile Domain Patterns
MOBILE_PERSISTENCE_PATTERNS = {
    
    # T1398 - Boot or Logon Autostart Execution (Lazarus Mobile)
    "MOBILE_AUTOSTART_PERSISTENCE": HeuristicPattern(
        pattern_id="T1398_MOBILE_AUTOSTART",
        pattern_name="Mobile Autostart Persistence",
        description="Configure mobile autostart for persistence - Lazarus mobile technique",
        min_events=5,
        max_events=10,
        time_window_seconds=600.0,
        network_signatures=[
            {"dest_port": 443, "protocol": "TCP", "action": "app_store_connect"},
            {"dest_port": 80, "protocol": "TCP", "action": "http_download"}
        ],
        port_sequences=[[443, 80], [443]],
        persistence_indicators=[
            "app_autostart_registration",
            "broadcast_receiver_registration",
            "service_autostart",
            "boot_receiver_registration"
        ]
    )
}

# Lateral Movement Patterns with Network Heuristics
LATERAL_MOVEMENT_PATTERNS = {
    
    # T1021.002 - SMB/Windows Admin Shares (APT1, APT28, APT29)
    "SMB_LATERAL_MOVEMENT": HeuristicPattern(
        pattern_id="T1021.002_SMB_LATERAL",
        pattern_name="SMB Lateral Movement",
        description="SMB-based lateral movement - signature of APT1, APT28, and APT29",
        min_events=10,
        max_events=50,
        time_window_seconds=1200.0,
        network_signatures=[
            {"dest_port": 445, "protocol": "TCP", "action": "smb_connect"},
            {"dest_port": 139, "protocol": "TCP", "action": "netbios_session"},
            {"dest_port": 135, "protocol": "TCP", "action": "rpc_endpoint"}
        ],
        port_sequences=[
            [445, 135],           # SMB + RPC
            [139, 445],           # NetBIOS + SMB
            [445, 139, 135],      # Full Windows suite
            [135, 445, 135]       # RPC probe + SMB + RPC service
        ],
        protocol_patterns=["TCP"],
        frequency_pattern="rapid_burst",
        lateral_movement_indicators=[
            "admin_share_access",
            "psexec_execution",
            "wmi_remote_execution",
            "service_remote_creation",
            "file_copy_admin_share"
        ]
    ),
    
    # T1021.001 - RDP Lateral Movement (APT41, Wizard Spider)
    "RDP_LATERAL_MOVEMENT": HeuristicPattern(
        pattern_id="T1021.001_RDP_LATERAL", 
        pattern_name="RDP Lateral Movement",
        description="RDP-based lateral movement - APT41 and Wizard Spider technique",
        min_events=8,
        max_events=25,
        time_window_seconds=1800.0,
        network_signatures=[
            {"dest_port": 3389, "protocol": "TCP", "action": "rdp_connect"},
            {"dest_port": 3389, "protocol": "UDP", "action": "rdp_discovery"}
        ],
        port_sequences=[[3389]],
        protocol_patterns=["TCP", "UDP"],
        frequency_pattern="sequential",
        lateral_movement_indicators=[
            "rdp_logon_success",
            "terminal_services_session",
            "rdp_certificate_validation",
            "clipboard_access",
            "drive_redirection"
        ]
    ),
    
    # T1021.004 - SSH Lateral Movement (APT40, Volt Typhoon)
    "SSH_LATERAL_MOVEMENT": HeuristicPattern(
        pattern_id="T1021.004_SSH_LATERAL",
        pattern_name="SSH Lateral Movement", 
        description="SSH-based lateral movement - APT40 and Volt Typhoon Linux technique",
        min_events=6,
        max_events=30,
        time_window_seconds=900.0,
        network_signatures=[
            {"dest_port": 22, "protocol": "TCP", "action": "ssh_connect"},
            {"dest_port": 2222, "protocol": "TCP", "action": "ssh_alt_port"}
        ],
        port_sequences=[[22], [2222], [22, 2222]],
        protocol_patterns=["TCP"],
        lateral_movement_indicators=[
            "ssh_key_authentication",
            "ssh_password_authentication", 
            "ssh_tunnel_creation",
            "scp_file_transfer",
            "ssh_command_execution"
        ]
    )
}

# Privilege Escalation Patterns
PRIVILEGE_ESCALATION_PATTERNS = {
    
    # T1068 - Exploitation for Privilege Escalation (APT28, Lazarus)
    "EXPLOIT_PRIVESC": HeuristicPattern(
        pattern_id="T1068_EXPLOIT_PRIVESC",
        pattern_name="Exploitation for Privilege Escalation",
        description="Exploit vulnerabilities for privilege escalation - APT28 and Lazarus technique",
        min_events=5,
        max_events=15,
        time_window_seconds=300.0,
        network_signatures=[
            {"dest_port": 445, "protocol": "TCP", "action": "smb_exploit_attempt"},
            {"dest_port": 135, "protocol": "TCP", "action": "rpc_exploit"},
            {"dest_port": 139, "protocol": "TCP", "action": "netbios_exploit"}
        ],
        port_sequences=[[445], [135, 445], [139, 445]],
        escalation_indicators=[
            "kernel_exploit_execution",
            "privilege_token_manipulation",
            "uac_bypass",
            "driver_exploitation",
            "service_privilege_escalation"
        ]
    ),
    
    # T1134.001 - Token Impersonation (APT29, APT33)
    "TOKEN_IMPERSONATION": HeuristicPattern(
        pattern_id="T1134.001_TOKEN_IMPERSONATION",
        pattern_name="Access Token Manipulation - Token Impersonation",
        description="Token impersonation for privilege escalation - APT29 signature technique",
        min_events=6,
        max_events=12,
        time_window_seconds=600.0,
        network_signatures=[
            {"dest_port": 445, "protocol": "TCP", "action": "smb_named_pipe"},
            {"dest_port": 135, "protocol": "TCP", "action": "rpc_lsarpc"}
        ],
        port_sequences=[[445, 135]],
        escalation_indicators=[
            "token_duplication",
            "impersonation_level_change",
            "privilege_adjustment",
            "lsass_process_access",
            "named_pipe_impersonation"
        ]
    )
}

# Defense Evasion Patterns  
DEFENSE_EVASION_PATTERNS = {
    
    # T1070.001 - Clear Windows Event Logs (APT28, APT38)
    "LOG_CLEARING_EVASION": HeuristicPattern(
        pattern_id="T1070.001_LOG_CLEARING",
        pattern_name="Clear Windows Event Logs",
        description="Clear event logs to evade detection - APT28 and APT38 technique",
        min_events=5,
        max_events=10,
        time_window_seconds=180.0,
        network_signatures=[
            {"dest_port": 445, "protocol": "TCP", "action": "smb_admin_share"},
            {"dest_port": 135, "protocol": "TCP", "action": "rpc_eventlog"}
        ],
        port_sequences=[[445], [135, 445]],
        escalation_indicators=[
            "wevtutil_log_clear",
            "event_log_service_stop",
            "log_file_deletion",
            "eventlog_registry_modification",
            "powershell_log_clearing"
        ]
    ),
    
    # T1055.001 - Process Hollowing (APT29, Turla)
    "PROCESS_HOLLOWING": HeuristicPattern(
        pattern_id="T1055.001_PROCESS_HOLLOWING",
        pattern_name="Process Injection - Process Hollowing",
        description="Process hollowing for defense evasion - APT29 and Turla advanced technique",
        min_events=7,
        max_events=15,
        time_window_seconds=420.0,
        network_signatures=[
            {"dest_port": 443, "protocol": "TCP", "action": "https_c2_connect"},
            {"dest_port": 80, "protocol": "TCP", "action": "http_beacon"}
        ],
        port_sequences=[[443], [80, 443]],
        escalation_indicators=[
            "process_creation_suspend",
            "memory_allocation_remote",
            "thread_context_modification",
            "image_section_mapping",
            "legitimate_process_abuse"
        ]
    )
}


def get_pattern_by_id(pattern_id: str) -> Optional[HeuristicPattern]:
    """Retrieve a specific pattern by ID."""
    all_patterns = {
        **ENTERPRISE_PERSISTENCE_PATTERNS,
        **CLOUD_PERSISTENCE_PATTERNS,
        **CLOUD_INITIAL_ACCESS_PATTERNS,
        **CLOUD_DISCOVERY_PATTERNS,
        **CLOUD_CREDENTIAL_ACCESS_PATTERNS,
        **CLOUD_DEFENSE_EVASION_PATTERNS,
        **CLOUD_COLLECTION_PATTERNS,
        **CLOUD_EXFILTRATION_PATTERNS,
        **KUBERNETES_PATTERNS,
        **MOBILE_PERSISTENCE_PATTERNS,
        **LATERAL_MOVEMENT_PATTERNS,
        **PRIVILEGE_ESCALATION_PATTERNS,
        **DEFENSE_EVASION_PATTERNS
    }
    return all_patterns.get(pattern_id)


def get_patterns_by_apt_group(apt_group: str) -> List[HeuristicPattern]:
    """Get patterns commonly used by a specific APT group."""
    
    apt_technique_mapping = {
        APTGroup.APT28: [
            "T1543.003_SERVICE_PERSIST",
            "T1547.001_REGISTRY_AUTOSTART", 
            "T1021.002_SMB_LATERAL",
            "T1068_EXPLOIT_PRIVESC",
            "T1070.001_LOG_CLEARING"
        ],
        APTGroup.APT29: [
            "T1543.003_SERVICE_PERSIST",
            "T1098.001_CLOUD_CREDS",
            "T1484.002_CLOUD_POLICY",
            "T1021.002_SMB_LATERAL",
            "T1134.001_TOKEN_IMPERSONATION",
            "T1055.001_PROCESS_HOLLOWING"
        ],
        APTGroup.APT1: [
            "T1078.003_LOCAL_ACCOUNT",
            "T1021.002_SMB_LATERAL"
        ],
        APTGroup.APT40: [
            "T1078.003_LOCAL_ACCOUNT",
            "T1578.002_CLOUD_INSTANCE",
            "T1021.004_SSH_LATERAL"
        ],
        APTGroup.APT41: [
            "T1053.005_SCHTASK_PERSIST",
            "T1021.001_RDP_LATERAL"
        ],
        APTGroup.VOLT_TYPHOON: [
            "T1098.001_CLOUD_CREDS",
            "T1021.004_SSH_LATERAL"
        ],
        APTGroup.LAZARUS: [
            "T1547.001_REGISTRY_AUTOSTART",
            "T1068_EXPLOIT_PRIVESC",
            "T1398_MOBILE_AUTOSTART"
        ],
        APTGroup.APT38: [
            "T1070.001_LOG_CLEARING"
        ],
        APTGroup.APT33: [
            "T1134.001_TOKEN_IMPERSONATION"
        ],
        APTGroup.APT34: [
            "T1136.003_CLOUD_ACCOUNT"
        ],
        APTGroup.CARBANAK: [
            "T1053.005_SCHTASK_PERSIST"
        ],
        APTGroup.WIZARD_SPIDER: [
            "T1021.001_RDP_LATERAL"
        ],
        APTGroup.SANDWORM: [
            "T1578.002_CLOUD_INSTANCE"
        ],
        APTGroup.TURLA: [
            "T1136.003_CLOUD_ACCOUNT",
            "T1055.001_PROCESS_HOLLOWING"
        ]
    }
    
    pattern_ids = apt_technique_mapping.get(apt_group, [])
    patterns = []
    for pattern_id in pattern_ids:
        pattern = get_pattern_by_id(pattern_id)
        if pattern:
            patterns.append(pattern)
    
    return patterns


def get_patterns_by_tactic(tactic: AttackTactic) -> List[HeuristicPattern]:
    """Get patterns by MITRE ATT&CK tactic."""
    
    tactic_mapping = {
        AttackTactic.INITIAL_ACCESS: list(CLOUD_INITIAL_ACCESS_PATTERNS.values()),
        AttackTactic.DISCOVERY: list(CLOUD_DISCOVERY_PATTERNS.values()),
        AttackTactic.CREDENTIAL_ACCESS: list(CLOUD_CREDENTIAL_ACCESS_PATTERNS.values()),
        AttackTactic.EXFILTRATION: list(CLOUD_EXFILTRATION_PATTERNS.values()),
        AttackTactic.COLLECTION: list(CLOUD_COLLECTION_PATTERNS.values()),
        AttackTactic.PERSISTENCE: [
            *ENTERPRISE_PERSISTENCE_PATTERNS.values(),
            *CLOUD_PERSISTENCE_PATTERNS.values(),
            *MOBILE_PERSISTENCE_PATTERNS.values()
        ],
        AttackTactic.LATERAL_MOVEMENT: list(LATERAL_MOVEMENT_PATTERNS.values()),
        AttackTactic.PRIVILEGE_ESCALATION: list(PRIVILEGE_ESCALATION_PATTERNS.values()),
        AttackTactic.DEFENSE_EVASION: list(DEFENSE_EVASION_PATTERNS.values()),
        AttackTactic.COMMAND_AND_CONTROL: [],
        AttackTactic.RESOURCE_DEVELOPMENT: [],
        AttackTactic.RECONNAISSANCE: [],
        AttackTactic.EXECUTION: [],
        AttackTactic.IMPACT: [],
    }
    
    return tactic_mapping.get(tactic, [])


def get_patterns_by_nice_category(nice_category: NICECategory) -> List[HeuristicPattern]:
    """Get patterns relevant to a NICE framework category."""
    
    if nice_category == NICECategory.NETWORK:
        return [
            *LATERAL_MOVEMENT_PATTERNS.values(),
            ENTERPRISE_PERSISTENCE_PATTERNS["WINDOWS_SERVICE_PERSISTENCE"],
            DEFENSE_EVASION_PATTERNS["LOG_CLEARING_EVASION"]
        ]
    elif nice_category == NICECategory.IDENTITY:
        return [
            ENTERPRISE_PERSISTENCE_PATTERNS["LOCAL_ACCOUNT_MANIPULATION"],
            *CLOUD_PERSISTENCE_PATTERNS.values(),
            PRIVILEGE_ESCALATION_PATTERNS["TOKEN_IMPERSONATION"]
        ]
    elif nice_category == NICECategory.CLOUD:
        return [
            *CLOUD_INITIAL_ACCESS_PATTERNS.values(),
            *CLOUD_DISCOVERY_PATTERNS.values(),
            *CLOUD_CREDENTIAL_ACCESS_PATTERNS.values(),
            *CLOUD_PERSISTENCE_PATTERNS.values(),
            *CLOUD_DEFENSE_EVASION_PATTERNS.values(),
            *CLOUD_COLLECTION_PATTERNS.values(),
            *CLOUD_EXFILTRATION_PATTERNS.values(),
            *KUBERNETES_PATTERNS.values(),
        ]
    elif nice_category == NICECategory.ENDPOINT:
        return [
            ENTERPRISE_PERSISTENCE_PATTERNS["WINDOWS_SERVICE_PERSISTENCE"],
            ENTERPRISE_PERSISTENCE_PATTERNS["REGISTRY_AUTOSTART_PERSISTENCE"], 
            ENTERPRISE_PERSISTENCE_PATTERNS["SCHEDULED_TASK_PERSISTENCE"],
            *PRIVILEGE_ESCALATION_PATTERNS.values(),
            DEFENSE_EVASION_PATTERNS["PROCESS_HOLLOWING"]
        ]
    
    return []


# Pattern validation and metrics
def validate_pattern_coverage() -> Dict[str, Any]:
    """Validate MITRE ATT&CK technique coverage."""
    
    all_patterns = {
        **ENTERPRISE_PERSISTENCE_PATTERNS,
        **CLOUD_PERSISTENCE_PATTERNS, 
        **CLOUD_INITIAL_ACCESS_PATTERNS,
        **CLOUD_DISCOVERY_PATTERNS,
        **CLOUD_CREDENTIAL_ACCESS_PATTERNS,
        **CLOUD_DEFENSE_EVASION_PATTERNS,
        **CLOUD_COLLECTION_PATTERNS,
        **CLOUD_EXFILTRATION_PATTERNS,
        **KUBERNETES_PATTERNS,
        **MOBILE_PERSISTENCE_PATTERNS,
        **LATERAL_MOVEMENT_PATTERNS,
        **PRIVILEGE_ESCALATION_PATTERNS,
        **DEFENSE_EVASION_PATTERNS
    }
    
    technique_ids = set()
    for pattern in all_patterns.values():
        # Extract technique ID from pattern_id
        if "_" in pattern.pattern_id:
            tech_id = pattern.pattern_id.split("_")[0]
            technique_ids.add(tech_id)
    
    return {
        "total_patterns": len(all_patterns),
        "unique_techniques": len(technique_ids),
        "techniques_covered": sorted(technique_ids),
        "apt_groups_covered": len(set([
            APTGroup.APT28, APTGroup.APT29, APTGroup.APT1, APTGroup.APT40,
            APTGroup.APT41, APTGroup.VOLT_TYPHOON, APTGroup.LAZARUS, APTGroup.APT38,
            APTGroup.APT33, APTGroup.APT34, APTGroup.CARBANAK, APTGroup.WIZARD_SPIDER,
            APTGroup.SANDWORM, APTGroup.TURLA
        ])),
        "tactics_covered": [
            AttackTactic.PERSISTENCE, AttackTactic.LATERAL_MOVEMENT,
            AttackTactic.PRIVILEGE_ESCALATION, AttackTactic.DEFENSE_EVASION
        ]
    }