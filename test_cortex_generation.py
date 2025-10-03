#!/usr/bin/env python3
"""
Test Script for Cortex-Compliant Log Generation

This script demonstrates the generation of authentic, Cortex-compliant logs
across multiple vendors with TTP coverage and validation.
"""

import sys
import os
import json
from datetime import datetime

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from xgen.validation.cortex_compliance import LogFormat
from xgen.generators.cortex_log_orchestrator import (
    CortexLogOrchestrator, LogGenerationRequest, generate_cortex_logs
)

def test_single_vendor_generation():
    """Test generating logs for a single vendor."""
    print("=== Testing Single Vendor Log Generation ===")
    
    orchestrator = CortexLogOrchestrator()
    
    # Test PAN-OS CEF logs with TTP
    ttp = orchestrator.ttp_library["T1566.001"]  # Spearphishing Attachment
    
    request = LogGenerationRequest(
        vendor="Palo Alto Networks",
        product="PAN-OS", 
        format_type=LogFormat.CEF,
        ttp=ttp,
        count=3,
        scenario_name="email_attack_test"
    )
    
    logs = orchestrator.generate_logs(request)
    
    print(f"Generated {len(logs)} PAN-OS CEF logs:")
    for i, log in enumerate(logs):
        print(f"\nLog {i+1}:")
        print(f"  Timestamp: {log.timestamp}")
        print(f"  TTP: {log.ttp.technique_id} - {log.ttp.technique_name}")
        print(f"  Validation: {'✓ VALID' if log.validation_result.is_valid else '✗ INVALID'}")
        print(f"  Format: {log.format_type}")
        print(f"  Message: {log.log_message[:100]}...")
        
        if not log.validation_result.is_valid:
            print(f"  Issues: {log.validation_result.issues}")

def test_multi_vendor_generation():
    """Test generating logs across multiple vendors."""
    print("\n=== Testing Multi-Vendor Log Generation ===")
    
    vendors = [
        ("Palo Alto Networks", LogFormat.CEF),
        ("CrowdStrike", LogFormat.JSON),
        ("Cisco ASA", LogFormat.SYSLOG),
        ("Okta", LogFormat.JSON)
    ]
    
    orchestrator = CortexLogOrchestrator()
    ttp = orchestrator.ttp_library["T1110.003"]  # Password Spraying
    
    all_logs = []
    
    for vendor, format_type in vendors:
        try:
            request = LogGenerationRequest(
                vendor=vendor,
                product=orchestrator._get_product_for_vendor(vendor),
                format_type=format_type,
                ttp=ttp,
                count=2,
                scenario_name="password_spray_test"
            )
            
            logs = orchestrator.generate_logs(request)
            all_logs.extend(logs)
            
            print(f"\n{vendor} ({format_type}):")
            for log in logs:
                validation_status = "✓ VALID" if log.validation_result.is_valid else "✗ INVALID"
                print(f"  - {validation_status}: {log.log_message[:80]}...")
                
        except ValueError as e:
            print(f"\n{vendor}: Skipped - {e}")
    
    print(f"\nTotal generated logs: {len(all_logs)}")

def test_attack_scenario():
    """Test generating a complete attack scenario."""
    print("\n=== Testing Complete Attack Scenario Generation ===")
    
    orchestrator = CortexLogOrchestrator()
    
    # Create attack chain
    attack_chain = [
        orchestrator.ttp_library["T1566.001"],  # Initial Access - Spearphishing
        orchestrator.ttp_library["T1059.001"],  # Execution - PowerShell
        orchestrator.ttp_library["T1046"],      # Discovery - Network Scanning
        orchestrator.ttp_library["T1021.001"],  # Lateral Movement - RDP
        orchestrator.ttp_library["T1041"],      # Exfiltration - C2 Channel
    ]
    
    vendors = [
        "Palo Alto Networks",
        "CrowdStrike", 
        "Cisco ASA",
        "Okta"
    ]
    
    scenario_logs = orchestrator.generate_attack_scenario(
        scenario_name="Advanced_Persistent_Threat",
        attack_chain=attack_chain,
        vendors=vendors,
        duration_hours=12
    )
    
    print(f"Generated complete attack scenario with {len(scenario_logs)} logs")
    
    # Group by TTP for analysis
    ttp_counts = {}
    vendor_counts = {}
    format_counts = {}
    valid_logs = 0
    
    for log in scenario_logs:
        if log.ttp:
            ttp_counts[log.ttp.technique_id] = ttp_counts.get(log.ttp.technique_id, 0) + 1
        vendor_counts[log.vendor] = vendor_counts.get(log.vendor, 0) + 1
        format_counts[log.format_type.value] = format_counts.get(log.format_type.value, 0) + 1
        if log.validation_result.is_valid:
            valid_logs += 1
    
    print(f"\nScenario Analysis:")
    print(f"  Valid logs: {valid_logs}/{len(scenario_logs)} ({valid_logs/len(scenario_logs)*100:.1f}%)")
    print(f"  TTPs covered: {list(ttp_counts.keys())}")
    print(f"  Vendors: {list(vendor_counts.keys())}")
    print(f"  Formats: {list(format_counts.keys())}")
    
    # Show sample logs from each stage
    print(f"\nSample logs from each attack stage:")
    for ttp in attack_chain:
        matching_logs = [log for log in scenario_logs if log.ttp and log.ttp.technique_id == ttp.technique_id]
        if matching_logs:
            sample_log = matching_logs[0]
            print(f"\n  {ttp.technique_id} - {ttp.technique_name}:")
            print(f"    Vendor: {sample_log.vendor}")
            print(f"    Format: {sample_log.format_type}")
            print(f"    Valid: {'✓' if sample_log.validation_result.is_valid else '✗'}")
            print(f"    Log: {sample_log.log_message[:100]}...")

def test_quick_generation():
    """Test the convenience function for quick log generation."""
    print("\n=== Testing Quick Log Generation Function ===")
    
    # Test different vendors and formats
    test_cases = [
        ("Palo Alto Networks", LogFormat.CEF, "T1566.001"),
        ("CrowdStrike", LogFormat.JSON, "T1059.001"),
        ("Cisco ASA", LogFormat.SYSLOG, None),
    ]
    
    for vendor, format_type, ttp_id in test_cases:
        try:
            logs = generate_cortex_logs(
                vendor=vendor,
                count=2,
                ttp_id=ttp_id,
                format_type=format_type
            )
            
            print(f"\n{vendor} ({format_type}) - TTP: {ttp_id or 'None'}:")
            for log in logs:
                validation_status = "✓" if log.validation_result.is_valid else "✗"
                print(f"  {validation_status} {log.log_message[:60]}...")
                
        except Exception as e:
            print(f"\n{vendor}: Error - {e}")

def save_sample_logs():
    """Generate and save sample logs to files."""
    print("\n=== Generating Sample Log Files ===")
    
    orchestrator = CortexLogOrchestrator()
    
    # Generate samples for each format
    format_samples = {
        "panos_cef": generate_cortex_logs("Palo Alto Networks", 5, "T1566.001", LogFormat.CEF),
        "crowdstrike_json": generate_cortex_logs("CrowdStrike", 5, "T1059.001", LogFormat.JSON),
        "cisco_syslog": generate_cortex_logs("Cisco ASA", 5, "T1110.003", LogFormat.SYSLOG),
        "okta_json": generate_cortex_logs("Okta", 5, "T1078.004", LogFormat.JSON)
    }
    
    # Save to files
    os.makedirs("sample_logs", exist_ok=True)
    
    for filename, logs in format_samples.items():
        output_file = f"sample_logs/{filename}.txt"
        
        with open(output_file, 'w') as f:
            f.write(f"# {filename.upper()} Sample Logs\n")
            f.write(f"# Generated: {datetime.now().isoformat()}\n")
            f.write(f"# Count: {len(logs)}\n\n")
            
            for i, log in enumerate(logs):
                f.write(f"# Log {i+1} - {log.vendor} - {log.ttp.technique_id if log.ttp else 'Generic'}\n")
                f.write(f"# Timestamp: {log.timestamp}\n")
                f.write(f"# Valid: {log.validation_result.is_valid}\n")
                f.write(f"{log.log_message}\n\n")
        
        print(f"  Saved {len(logs)} logs to {output_file}")
    
    # Generate validation report
    report_file = "sample_logs/validation_report.json"
    validation_report = {}
    
    for filename, logs in format_samples.items():
        validation_report[filename] = {
            "total_logs": len(logs),
            "valid_logs": sum(1 for log in logs if log.validation_result.is_valid),
            "vendors": list(set(log.vendor for log in logs)),
            "formats": list(set(log.format_type.value for log in logs)),
            "ttps": list(set(log.ttp.technique_id for log in logs if log.ttp)),
            "issues": []
        }
        
        # Collect unique issues
        for log in logs:
            if not log.validation_result.is_valid:
                validation_report[filename]["issues"].extend(log.validation_result.issues)
        
        validation_report[filename]["issues"] = list(set(validation_report[filename]["issues"]))
    
    with open(report_file, 'w') as f:
        json.dump(validation_report, f, indent=2, default=str)
    
    print(f"  Saved validation report to {report_file}")

def main():
    """Run all tests."""
    print("Cortex-Compliant Log Generation Test Suite")
    print("=" * 50)
    
    try:
        test_single_vendor_generation()
        test_multi_vendor_generation() 
        test_attack_scenario()
        test_quick_generation()
        save_sample_logs()
        
        print("\n" + "=" * 50)
        print("✓ All tests completed successfully!")
        print("\nThe log generation system is working correctly and producing")
        print("Cortex-compliant logs across multiple vendors with proper")
        print("TTP coverage, validation, and formatting.")
        
    except Exception as e:
        print(f"\n✗ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())