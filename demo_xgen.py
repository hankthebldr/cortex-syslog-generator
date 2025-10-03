#!/usr/bin/env python3
"""
Demo script to test XGen burst generation capabilities.

This script demonstrates the new MITRE ATT&CK based burst generation
with network 5-tuple heuristics for analytics testing.
"""

import sys
import os
import logging
import time
from datetime import datetime

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from xgen.core.burst_generator import BurstGenerator
from xgen.core.models import LogFormat
from xgen.formats.renderers import render_events
from xgen.transports.adapters import create_transport_adapter, TransportType
from xgen.ttp.mitre_patterns import (
    get_patterns_by_apt_group, get_pattern_by_id, APTGroup,
    ENTERPRISE_PERSISTENCE_PATTERNS, CLOUD_PERSISTENCE_PATTERNS,
    LATERAL_MOVEMENT_PATTERNS, validate_pattern_coverage
)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def demo_apt29_campaign():
    """Demo APT29 campaign with multiple coordinated bursts."""
    print("\n🎯 APT29 (Cozy Bear) Campaign Demo")
    print("=" * 50)
    
    generator = BurstGenerator(seed=42)  # Reproducible results
    
    # Generate APT29 campaign
    print("Generating APT29 campaign events...")
    events = generator.generate_apt_campaign(
        apt_group=APTGroup.APT29,
        duration_hours=0.5,  # 30 minutes
        intensity="medium"
    )
    
    print(f"Generated {len(events)} events across {len(set(e.pattern_id for e in events if e.pattern_id))} patterns")
    
    # Show pattern breakdown
    pattern_counts = {}
    for event in events:
        if event.pattern_id:
            pattern_counts[event.pattern_id] = pattern_counts.get(event.pattern_id, 0) + 1
    
    print("\nPattern Breakdown:")
    for pattern_id, count in sorted(pattern_counts.items()):
        print(f"  {pattern_id}: {count} events")
    
    # Show first few events
    print("\nFirst 5 Events (with 5-tuple):")
    for i, event in enumerate(events[:5]):
        if event.network_tuple:
            tuple_info = f"{event.network_tuple.source_ip}:{event.network_tuple.source_port} -> {event.network_tuple.destination_ip}:{event.network_tuple.destination_port} ({event.network_tuple.protocol})"
        else:
            tuple_info = "No network tuple"
        print(f"  {i+1}. [{event.pattern_id}] {event.event_name} | {tuple_info}")
    
    return events


def demo_single_pattern():
    """Demo single pattern burst generation."""
    print("\n🔥 SMB Lateral Movement Pattern Demo")
    print("=" * 50)
    
    generator = BurstGenerator(seed=42)
    
    # Get the SMB lateral movement pattern
    pattern = get_pattern_by_id("T1021.002_SMB_LATERAL")
    if not pattern:
        print("Pattern not found!")
        return []
    
    print(f"Pattern: {pattern.pattern_name}")
    print(f"Description: {pattern.description}")
    print(f"Min events: {pattern.min_events}, Max events: {pattern.max_events}")
    print(f"Time window: {pattern.time_window_seconds} seconds")
    print(f"Port sequences: {pattern.port_sequences}")
    
    # Generate burst
    print("\nGenerating burst...")
    events = generator.generate_pattern_burst(pattern)
    
    print(f"Generated {len(events)} events in burst")
    
    # Show network 5-tuples
    print("\nNetwork 5-Tuples:")
    for i, event in enumerate(events):
        if event.network_tuple:
            print(f"  {i+1}. {event.network_tuple.source_ip}:{event.network_tuple.source_port} -> "
                  f"{event.network_tuple.destination_ip}:{event.network_tuple.destination_port} "
                  f"({event.network_tuple.protocol}) | Seq: {event.sequence_number}")
    
    return events


def demo_cef_formatting(events):
    """Demo CEF formatting of events."""
    print("\n📋 CEF Formatting Demo")
    print("=" * 30)
    
    if not events:
        print("No events to format!")
        return
    
    # Render first few events as CEF
    sample_events = events[:3]
    cef_logs = render_events(sample_events, LogFormat.CEF)
    
    print("Sample CEF logs:")
    for i, cef_log in enumerate(cef_logs):
        print(f"  {i+1}. {cef_log}")


def demo_syslog_transport():
    """Demo syslog transport (to localhost)."""
    print("\n🚀 Syslog Transport Demo")
    print("=" * 30)
    
    generator = BurstGenerator(seed=42)
    
    # Generate a small burst
    pattern = get_pattern_by_id("T1543.003_SERVICE_PERSIST")
    if not pattern:
        print("Pattern not found!")
        return
    
    events = generator.generate_pattern_burst(pattern)
    cef_logs = render_events(events, LogFormat.CEF)
    
    # Create syslog transport
    try:
        transport = create_transport_adapter(
            TransportType.SYSLOG_UDP,
            {"host": "127.0.0.1", "port": 514}
        )
        
        print(f"Sending {len(events)} events to syslog...")
        success = transport.send(events, cef_logs)
        
        stats = transport.get_stats()
        print(f"Sent: {stats['sent']}, Failed: {stats['failed']}, Bytes: {stats['bytes_sent']}")
        
        if success:
            print("✅ All events sent successfully!")
        else:
            print("⚠️  Some events failed to send")
        
        transport.close()
        
    except Exception as e:
        print(f"❌ Transport error: {e}")
        print("Note: Make sure syslog is running on localhost:514")


def demo_xsiam_transport():
    """Demo XSIAM HTTP transport using environment variables."""
    print("\n🚀 XSIAM HTTP Transport Demo")
    print("=" * 34)

    endpoint = os.getenv("XSIAM_HTTP_ENDPOINT")
    api_key = os.getenv("XSIAM_API_KEY")
    api_key_id = os.getenv("XSIAM_API_KEY_ID")
    tenant_id = os.getenv("XSIAM_TENANT_ID")

    if not endpoint or not api_key:
        print("❌ Missing XSIAM env vars. Please export XSIAM_HTTP_ENDPOINT and XSIAM_API_KEY (optionally XSIAM_API_KEY_ID, XSIAM_TENANT_ID).")
        return

    generator = BurstGenerator(seed=42)
    pattern = get_pattern_by_id("T1543.003_SERVICE_PERSIST") or get_pattern_by_id("T1021.002_SMB_LATERAL")
    events = generator.generate_pattern_burst(pattern) if pattern else generator.generate_apt_campaign(APTGroup.APT29, duration_hours=0.01, intensity="low")

    logs = render_events(events, LogFormat.JSON)

    try:
        transport = create_transport_adapter(
            TransportType.XSIAM_HTTP,
            {
                "endpoint": endpoint,
                "api_key": api_key,
                "api_key_id": api_key_id,
                "tenant_id": tenant_id,
                "batch_size": 500,
                "compress": True,
            }
        )
        print(f"Sending {len(events)} events to XSIAM...")
        success = transport.send(events, logs)
        stats = transport.get_stats()
        print(f"Sent: {stats['sent']}, Failed: {stats['failed']}, Bytes: {stats['bytes_sent']}")
        print("✅ Success" if success else "⚠️ Partial/Failed")
    except Exception as e:
        print(f"❌ Transport error: {e}")
    finally:
        try:
            transport.close()
        except Exception:
            pass


def demo_pattern_coverage():
    """Demo pattern coverage analysis."""
    print("\n📊 Pattern Coverage Analysis")
    print("=" * 35)
    
    coverage = validate_pattern_coverage()
    
    print(f"Total patterns: {coverage['total_patterns']}")
    print(f"Unique techniques: {coverage['unique_techniques']}")
    print(f"APT groups covered: {coverage['apt_groups_covered']}")
    
    print("\nTechniques covered:")
    for technique in coverage['techniques_covered']:
        print(f"  - {technique}")
    
    print(f"\nTactics covered: {len(coverage['tactics_covered'])}")
    for tactic in coverage['tactics_covered']:
        print(f"  - {tactic}")


def interactive_menu():
    """Interactive demo menu."""
    while True:
        print("\n🎮 XGen Demo Menu")
        print("=" * 20)
        print("1. APT29 Campaign Demo")
        print("2. Single Pattern Burst Demo")
        print("3. CEF Formatting Demo")
        print("4. Syslog Transport Demo")
        print("5. Pattern Coverage Analysis")
        print("6. XSIAM HTTP Transport Demo (env vars)")
        print("7. Exit")
        
        try:
            choice = input("\nSelect option (1-6): ").strip()
            
            if choice == '1':
                events = demo_apt29_campaign()
            elif choice == '2':
                events = demo_single_pattern()
            elif choice == '3':
                events = demo_single_pattern()  # Generate events first
                demo_cef_formatting(events)
            elif choice == '4':
                demo_syslog_transport()
            elif choice == '5':
                demo_pattern_coverage()
            elif choice == '6':
                demo_xsiam_transport()
            elif choice == '7':
                print("👋 Goodbye!")
                break
            else:
                print("❌ Invalid choice. Please select 1-6.")
                
        except KeyboardInterrupt:
            print("\n👋 Goodbye!")
            break
        except Exception as e:
            print(f"❌ Error: {e}")
            logger.exception("Demo error")


if __name__ == "__main__":
    print("🔬 XGen MITRE ATT&CK Burst Generator Demo")
    print("Realistic log generation with network heuristics")
    print("For Cortex XSIAM and SIEM analytics testing")
    
    try:
        interactive_menu()
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        logger.exception("Fatal demo error")
        sys.exit(1)