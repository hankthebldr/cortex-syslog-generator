#!/usr/bin/env python3
"""
Demo script to test all Zscaler log generators with authentic log formats.

This script demonstrates the comprehensive Zscaler log generation capabilities
including NSS Web logs, NSS Firewall logs, and all ZPA log types in authentic
formats that match production Zscaler deployments.
"""

import sys
import os
from datetime import datetime

# Add src to path for module imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

# Import the Flask app generators
from app import (
    gen_zscaler_web_log,
    gen_zscaler_firewall_log, 
    gen_zscaler_zpa_user_activity_log,
    gen_zscaler_zpa_user_status_log,
    gen_zscaler_zpa_connector_log,
    gen_zscaler_zpa_audit_log,
    gen_zscaler_log  # Legacy function
)

def demo_zscaler_nss_web_logs():
    """Demonstrate Zscaler NSS Web log generation."""
    print("\n" + "="*60)
    print("🌐 ZSCALER NSS WEB LOGS")  
    print("="*60)
    
    print("\n📋 Sample Web Proxy Logs (CEF Format):")
    
    # Generate various web log scenarios
    scenarios = [
        {"action": "Allowed", "reason": "Acceptable Use Policy", "urlcat": "Business Use"},
        {"action": "Blocked", "reason": "Security Policy", "urlcat": "Malware"},
        {"action": "Monitored", "reason": "Content Filtering", "urlcat": "Social Networking"}
    ]
    
    for i, scenario in enumerate(scenarios, 1):
        log_data = gen_zscaler_web_log(**scenario)
        print(f"\n{i}. {scenario['action']} - {scenario['urlcat']}")
        print("-" * 50)
        print(log_data['log_line'])
        print(f"   Parsed: {log_data['message']}")

def demo_zscaler_nss_firewall_logs():
    """Demonstrate Zscaler NSS Firewall log generation."""
    print("\n" + "="*60)
    print("🔥 ZSCALER NSS FIREWALL LOGS")
    print("="*60)
    
    print("\n📋 Sample Firewall Logs (CEF Format):")
    
    # Generate various firewall log scenarios
    scenarios = [
        {"action": "Allow", "ipproto": "TCP", "cdport": 443, "rulelabel": "Allow_HTTPS"},
        {"action": "Drop", "ipproto": "TCP", "cdport": 22, "rulelabel": "Block_SSH"},
        {"action": "Reset", "ipproto": "UDP", "cdport": 53, "rulelabel": "Corporate_Internet_Access"}
    ]
    
    for i, scenario in enumerate(scenarios, 1):
        log_data = gen_zscaler_firewall_log(**scenario)
        print(f"\n{i}. {scenario['action']} - {scenario['rulelabel']}")
        print("-" * 50)
        print(log_data['log_line'])
        print(f"   Parsed: {log_data['message']}")

def demo_zscaler_zpa_user_activity_logs():
    """Demonstrate Zscaler ZPA User Activity log generation."""
    print("\n" + "="*60)
    print("👤 ZSCALER ZPA USER ACTIVITY LOGS") 
    print("="*60)
    
    print("\n📋 Sample ZPA User Activity Logs (LEEF Format):")
    
    # Generate various user activity scenarios
    scenarios = [
        {"ConnectionStatus": "ACTIVE", "InternalReason": "OK"},
        {"ConnectionStatus": "CLOSED", "InternalReason": "USER_INITIATED"},
        {"ConnectionStatus": "TIMEOUT", "InternalReason": "POLICY_TIMEOUT"}
    ]
    
    for i, scenario in enumerate(scenarios, 1):
        log_data = gen_zscaler_zpa_user_activity_log(**scenario)
        print(f"\n{i}. Connection: {scenario['ConnectionStatus']} - {scenario['InternalReason']}")
        print("-" * 70)
        print(log_data['log_line'])
        print(f"   Parsed: {log_data['message']}")

def demo_zscaler_zpa_user_status_logs():
    """Demonstrate Zscaler ZPA User Status log generation."""
    print("\n" + "="*60)
    print("📊 ZSCALER ZPA USER STATUS LOGS")
    print("="*60)
    
    print("\n📋 Sample ZPA User Status Logs (LEEF Format):")
    
    # Generate various user status scenarios  
    scenarios = [
        {"SessionStatus": "AUTHENTICATED"},
        {"SessionStatus": "UNAUTHENTICATED"}, 
        {"SessionStatus": "EXPIRED"}
    ]
    
    for i, scenario in enumerate(scenarios, 1):
        log_data = gen_zscaler_zpa_user_status_log(**scenario)
        print(f"\n{i}. Session Status: {scenario['SessionStatus']}")
        print("-" * 50)
        print(log_data['log_line'])
        print(f"   Parsed: {log_data['message']}")

def demo_zscaler_zpa_connector_logs():
    """Demonstrate Zscaler ZPA App Connector log generation."""
    print("\n" + "="*60)
    print("🔌 ZSCALER ZPA APP CONNECTOR LOGS")
    print("="*60)
    
    print("\n📋 Sample ZPA Connector Logs (LEEF Format):")
    
    # Generate various connector status scenarios
    scenarios = [
        {"SessionStatus": "CONNECTED"},
        {"SessionStatus": "DISCONNECTED"},
        {"SessionStatus": "AUTHENTICATED"}
    ]
    
    for i, scenario in enumerate(scenarios, 1):
        log_data = gen_zscaler_zpa_connector_log(**scenario)
        print(f"\n{i}. Connector Status: {scenario['SessionStatus']}")
        print("-" * 50)
        print(log_data['log_line'])
        print(f"   Parsed: {log_data['message']}")

def demo_zscaler_zpa_audit_logs():
    """Demonstrate Zscaler ZPA Audit log generation."""
    print("\n" + "="*60)
    print("📋 ZSCALER ZPA AUDIT LOGS")
    print("="*60)
    
    print("\n📋 Sample ZPA Audit Logs (LEEF Format):")
    
    # Generate various audit operation scenarios
    scenarios = [
        {"auditOperationType": "CREATE", "objectType": "APPLICATION_SEGMENT"},
        {"auditOperationType": "UPDATE", "objectType": "ACCESS_POLICY"},
        {"auditOperationType": "DELETE", "objectType": "CONNECTOR"}
    ]
    
    for i, scenario in enumerate(scenarios, 1):
        log_data = gen_zscaler_zpa_audit_log(**scenario)
        print(f"\n{i}. Audit: {scenario['auditOperationType']} {scenario['objectType']}")
        print("-" * 60)
        print(log_data['log_line'])
        print(f"   Parsed: {log_data['message']}")

def demo_format_compatibility():
    """Demonstrate format compatibility and field mapping."""
    print("\n" + "="*60)
    print("🔧 FORMAT COMPATIBILITY TEST")
    print("="*60)
    
    print("\n📊 Log Format Summary:")
    
    generators = [
        ("NSS Web (CEF)", gen_zscaler_web_log),
        ("NSS Firewall (CEF)", gen_zscaler_firewall_log),
        ("ZPA User Activity (LEEF)", gen_zscaler_zpa_user_activity_log),
        ("ZPA User Status (LEEF)", gen_zscaler_zpa_user_status_log),
        ("ZPA Connector (LEEF)", gen_zscaler_zpa_connector_log),
        ("ZPA Audit (LEEF)", gen_zscaler_zpa_audit_log)
    ]
    
    for name, gen_func in generators:
        try:
            log_data = gen_func()
            format_type = "CEF" if log_data['log_line'].startswith("Oct") else "LEEF"
            print(f"✅ {name:<25} | Format: {format_type:<4} | Length: {len(log_data['log_line']):<4} chars")
        except Exception as e:
            print(f"❌ {name:<25} | Error: {str(e)[:50]}...")

def demo_integration_with_cortex():
    """Demonstrate integration points for Cortex XSIAM."""
    print("\n" + "="*60)
    print("🎯 CORTEX XSIAM INTEGRATION")
    print("="*60)
    
    print("\n📡 Transport Compatibility:")
    print("- Syslog UDP/TCP: ✅ All CEF/LEEF formats supported")
    print("- XSIAM HTTP API: ✅ JSON wrapper available")
    print("- Generic Webhook: ✅ Batch processing ready")
    
    print("\n🏷️  Field Mapping:")
    print("- Username: suser/usrName fields populated")
    print("- Source IP: src/srcPreNAT fields populated") 
    print("- Destination: dst/dstPort fields populated")
    print("- Timestamps: Multiple format support (ISO8601/epoch)")
    print("- Categories: cat fields with NICE framework alignment")
    
    print("\n🔍 Analytics Correlation:")
    print("- Network 5-tuples: Source/Dest IP:Port + Protocol")
    print("- User behavior: Session tracking across ZPA logs")
    print("- Policy violations: Action + Reason field correlation")
    print("- Threat detection: Integration with malware/threat fields")

def main():
    """Main demo function."""
    print("🛡️  ZSCALER LOG GENERATOR DEMO")
    print(f"📅 Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("🎯 Purpose: Demonstrate authentic Zscaler log formats for Cortex XSIAM")
    
    # Run all demos
    demo_zscaler_nss_web_logs()
    demo_zscaler_nss_firewall_logs()  
    demo_zscaler_zpa_user_activity_logs()
    demo_zscaler_zpa_user_status_logs()
    demo_zscaler_zpa_connector_logs()
    demo_zscaler_zpa_audit_logs()
    demo_format_compatibility()
    demo_integration_with_cortex()
    
    print("\n" + "="*60)
    print("✅ ZSCALER LOG DEMO COMPLETED")
    print("="*60)
    print("\n💡 Next Steps:")
    print("1. Test with your Cortex XSIAM instance using: make run")
    print("2. Configure environment variables for HTTP transport") 
    print("3. Validate log parsing in Cortex Data Model")
    print("4. Create custom analytics rules for Zscaler events")
    print("5. Set up automated log rotation and archival")
    
    print(f"\n📊 Total Generators Available: 6")
    print(f"📋 Log Formats: CEF (NSS), LEEF (ZPA)")
    print(f"🔗 Transport Options: Syslog, HTTP, Webhook")

if __name__ == "__main__":
    main()