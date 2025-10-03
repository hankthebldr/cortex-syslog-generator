#!/usr/bin/env python3
"""
Cortex XSIAM/Cloud Security Scenarios Demonstration
==================================================

This script demonstrates the enhanced Cortex-specific security scenarios with:
- Traditional incident response scenarios 
- Cloud-native security scenarios
- Competitive differentiation from CrowdStrike, Microsoft Sentinel, and others
- Realistic log generation with multi-vendor correlation
- MITRE ATT&CK technique mapping
"""

import sys
import os

# Add src to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

try:
    from scenarios import (
        CORTEX_SCENARIO_LIBRARY, 
        CORTEX_SCENARIO_GENERATOR,
        ScenarioType,
        CortexCapability
    )
    from datetime import datetime, timedelta
    import json
    
    def print_header(title: str, level: int = 1):
        """Print formatted header"""
        if level == 1:
            print(f"\n{'='*60}")
            print(f"🎯 {title}")
            print('='*60)
        elif level == 2:
            print(f"\n{'🔸' * 3} {title}")
            print('-' * 50)
        else:
            print(f"\n💡 {title}")
    
    def print_scenario_overview():
        """Print overview of available scenarios"""
        print_header("CORTEX SCENARIO OVERVIEW", 1)
        
        scenarios = CORTEX_SCENARIO_LIBRARY.scenarios
        
        # Group by type
        traditional_scenarios = [s for s in scenarios.values() if s.scenario_type == ScenarioType.TRADITIONAL_IR]
        cloud_scenarios = [s for s in scenarios.values() if s.scenario_type == ScenarioType.CLOUD_NATIVE]
        competitive_scenarios = [s for s in scenarios.values() if s.scenario_type == ScenarioType.COMPETITIVE]
        
        print(f"📊 Total Scenarios: {len(scenarios)}")
        print(f"   🏢 Traditional IR: {len(traditional_scenarios)}")
        print(f"   ☁️  Cloud Native: {len(cloud_scenarios)}")
        print(f"   🥊 Competitive: {len(competitive_scenarios)}")
        
        print_header("TRADITIONAL INCIDENT RESPONSE SCENARIOS", 2)
        for scenario in traditional_scenarios:
            print(f"   • {scenario.name}")
            print(f"     Duration: {scenario.duration_hours}h | Environment: {scenario.target_environment}")
            print(f"     Capabilities: {', '.join([cap.value for cap in scenario.cortex_capabilities])}")
            print(f"     MITRE Techniques: {len(scenario.mitre_techniques)} | Business Impact: {scenario.business_impact}")
            print()
        
        print_header("CLOUD NATIVE SECURITY SCENARIOS", 2)
        for scenario in cloud_scenarios:
            print(f"   • {scenario.name}")
            print(f"     Duration: {scenario.duration_hours}h | Environment: {scenario.target_environment}")
            print(f"     Capabilities: {', '.join([cap.value for cap in scenario.cortex_capabilities])}")
            print(f"     MITRE Techniques: {len(scenario.mitre_techniques)} | Business Impact: {scenario.business_impact}")
            print()
        
        print_header("COMPETITIVE DIFFERENTIATION SCENARIOS", 2)
        for scenario in competitive_scenarios:
            print(f"   • {scenario.name}")
            print(f"     Duration: {scenario.duration_hours}h | Environment: {scenario.target_environment}")
            competitors = set(comp.competitor for comp in scenario.competitor_comparisons)
            print(f"     Competitors: {', '.join(competitors)}")
            print()
    
    def demonstrate_apt_scenario():
        """Demonstrate advanced APT scenario"""
        print_header("APT MULTI-VECTOR ATTACK DEMONSTRATION", 1)
        
        scenario_id = "APT_MULTI_VECTOR"
        scenario = CORTEX_SCENARIO_LIBRARY.get_scenario(scenario_id)
        
        print(f"🎭 Scenario: {scenario.name}")
        print(f"📝 Description: {scenario.description}")
        print(f"⏱️  Duration: {scenario.duration_hours} hours")
        print(f"🎯 Target: {scenario.target_environment}")
        print(f"💥 Impact: {scenario.business_impact}")
        
        print_header("CORTEX CAPABILITIES DEMONSTRATED", 2)
        for capability in scenario.cortex_capabilities:
            print(f"   ✅ {capability.value}")
        
        print_header("ATTACK TIMELINE", 2)
        timeline = CORTEX_SCENARIO_LIBRARY.generate_scenario_timeline(scenario_id)
        for event in timeline:
            print(f"   {event['timestamp'].strftime('%H:%M:%S')} | {event['stage']} | {event['technique']}")
            print(f"      Description: {event['description']}")
            print(f"      Cortex Detection: {event['cortex_detection']}")
            print(f"      Vs Competition: {event['competitor_difference']}")
            print()
        
        print_header("COMPETITIVE ADVANTAGES", 2)
        for comparison in scenario.competitor_comparisons:
            print(f"   🥊 vs {comparison.competitor}:")
            print(f"      Advantage: {comparison.cortex_advantage}")
            print(f"      Detection: {comparison.detection_difference}")
            print(f"      Response: {comparison.response_difference}")
            print()
        
        print_header("REALISTIC EVENT GENERATION", 2)
        events = CORTEX_SCENARIO_GENERATOR.generate_scenario_events(scenario_id, include_noise=False)
        
        print(f"📊 Generated {len(events)} security events")
        print(f"   🎯 High Confidence: {len([e for e in events if e.confidence > 0.8])}")
        print(f"   🔗 Correlated Events: {len([e for e in events if e.correlation_id])}")
        
        # Show sample events
        print("\n📋 Sample Events:")
        for i, event in enumerate(events[:5]):
            print(f"   Event {i+1}: {event.event_id}")
            print(f"      Timestamp: {event.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"      Vendor: {event.vendor}")
            print(f"      Technique: {event.mitre_technique}")
            print(f"      Confidence: {event.confidence:.2f}")
            print(f"      Capability: {event.cortex_capability}")
            print(f"      Description: {event.description}")
            print()
    
    def demonstrate_container_scenario():
        """Demonstrate container escape scenario"""
        print_header("CONTAINER BREAKOUT SCENARIO", 1)
        
        scenario_id = "CONTAINER_ESCAPE"
        scenario = CORTEX_SCENARIO_LIBRARY.get_scenario(scenario_id)
        
        print(f"🐳 Scenario: {scenario.name}")
        print(f"📝 Description: {scenario.description}")
        print(f"⏱️  Duration: {scenario.duration_hours} hours")
        print(f"🎯 Target: {scenario.target_environment}")
        
        print_header("CLOUD-NATIVE CAPABILITIES", 2)
        for capability in scenario.cortex_capabilities:
            print(f"   ☁️  {capability.value}")
        
        # Generate events for container scenario
        events = CORTEX_SCENARIO_GENERATOR.generate_scenario_events(scenario_id)
        
        print_header("CONTAINER SECURITY EVENTS", 2)
        print(f"📊 Total Events: {len(events)}")
        
        container_events = [e for e in events if "container" in e.description.lower() or "kubernetes" in e.description.lower()]
        print(f"🐳 Container-Specific Events: {len(container_events)}")
        
        # Show container-specific events
        for event in container_events[:3]:
            print(f"\n   🔍 {event.event_id}")
            print(f"      Technique: {event.mitre_technique}")
            print(f"      Vendor: {event.vendor}")
            print(f"      Capability: {event.cortex_capability}")
            print(f"      Description: {event.description}")
            print(f"      Competitive Edge: {event.competitive_advantage}")
    
    def demonstrate_competitive_analysis():
        """Demonstrate competitive analysis"""
        print_header("COMPETITIVE ANALYSIS DEMONSTRATION", 1)
        
        # CrowdStrike comparison
        print_header("CORTEX vs CROWDSTRIKE COMPARISON", 2)
        crowdstrike_demo = CORTEX_SCENARIO_GENERATOR.generate_competitive_demo("CrowdStrike")
        
        print(f"📊 Scenarios Tested: {crowdstrike_demo['scenarios_tested']}")
        print(f"🏆 Cortex Advantages:")
        for advantage in crowdstrike_demo['cortex_advantages']:
            print(f"   • {advantage}")
        
        print(f"\n📋 Scenario Results:")
        for result in crowdstrike_demo['scenario_results']:
            print(f"   {result['scenario_name']}:")
            print(f"      Detection Rate: {result['detection_rate']:.1%}")
            print(f"      High-Confidence Detections: {result['cortex_detections']}")
            print(f"      Key Differentiator: {result['key_differentiator']}")
            print()
        
        # Microsoft Sentinel comparison  
        print_header("CORTEX vs MICROSOFT SENTINEL", 2)
        sentinel_comparison = CORTEX_SCENARIO_LIBRARY.generate_competitive_comparison("Sentinel")
        
        print(f"📊 Scenarios with Sentinel Comparison: {sentinel_comparison['scenario_count']}")
        for scenario, comparison in sentinel_comparison['scenarios']:
            print(f"   • {scenario.name}")
            print(f"     Advantage: {comparison.cortex_advantage}")
            print(f"     Highlight: {comparison.scenario_highlight}")
            print()
    
    def demonstrate_scenario_report():
        """Generate and display detailed scenario report"""
        print_header("DETAILED SCENARIO REPORT", 1)
        
        scenario_id = "SERVERLESS_ATTACK"
        report = CORTEX_SCENARIO_GENERATOR.generate_scenario_report(scenario_id)
        
        print(f"📋 Scenario Report: {report['scenario']['name']}")
        print(f"   Type: {report['scenario']['type']}")
        print(f"   Duration: {report['scenario']['duration_hours']} hours")
        print(f"   Environment: {report['scenario']['target_environment']}")
        print(f"   Business Impact: {report['scenario']['business_impact']}")
        
        print_header("EVENT ANALYSIS", 2)
        events = report['events']
        print(f"📊 Total Events: {events['total_count']}")
        print(f"🎯 High Confidence: {events['high_confidence']}")
        print(f"🔗 Correlated Events: {events['correlated_events']}")
        
        print(f"\n📈 Vendor Distribution:")
        for vendor, count in list(events['vendor_distribution'].items())[:5]:
            print(f"   {vendor}: {count} events")
        
        print(f"\n🎪 Technique Distribution:")
        for technique, count in list(events['technique_distribution'].items())[:5]:
            print(f"   {technique}: {count} events")
        
        print_header("CORTEX CAPABILITIES", 2)
        for capability in report['cortex_capabilities']:
            print(f"   ✅ {capability}")
        
        print_header("COMPETITIVE ADVANTAGES", 2)
        for advantage in report['competitive_advantages']:
            print(f"   🏆 {advantage}")
        
        print_header("EVENT TIMELINE SAMPLE", 2)
        for event in report['timeline']:
            print(f"   {event['timestamp']} | {event['vendor']} | {event['technique']}")
            print(f"      {event['description']} (Confidence: {event['confidence']:.2f})")
    
    def demonstrate_capability_filtering():
        """Demonstrate capability-based scenario filtering"""
        print_header("CAPABILITY-BASED SCENARIO FILTERING", 1)
        
        # XDR Correlation scenarios
        xdr_scenarios = CORTEX_SCENARIO_LIBRARY.get_scenarios_by_capability(CortexCapability.XDR_CORRELATION)
        print(f"🔗 XDR Correlation Scenarios: {len(xdr_scenarios)}")
        for scenario in xdr_scenarios:
            print(f"   • {scenario.name} ({scenario.duration_hours}h)")
        
        # Container Security scenarios
        container_scenarios = CORTEX_SCENARIO_LIBRARY.get_scenarios_by_capability(CortexCapability.CONTAINER_SECURITY)
        print(f"\n🐳 Container Security Scenarios: {len(container_scenarios)}")
        for scenario in container_scenarios:
            print(f"   • {scenario.name} ({scenario.target_environment})")
        
        # Cloud scenarios
        cloud_scenarios = CORTEX_SCENARIO_LIBRARY.get_scenarios_by_type(ScenarioType.CLOUD_NATIVE)
        print(f"\n☁️  Cloud Native Scenarios: {len(cloud_scenarios)}")
        for scenario in cloud_scenarios:
            techniques = len(scenario.mitre_techniques)
            print(f"   • {scenario.name} ({techniques} MITRE techniques)")
    
    def main():
        """Main demonstration function"""
        print("🌟" * 30)
        print("   CORTEX XSIAM/CLOUD SECURITY SCENARIOS")
        print("     Advanced Threat Detection & Response")
        print("🌟" * 30)
        
        print(f"\n🎯 This demonstration showcases:")
        print("   ✅ Cortex XSIAM/Cloud specific security scenarios")
        print("   ✅ Traditional incident response vs cloud-native scenarios")
        print("   ✅ Competitive differentiation from CrowdStrike & Microsoft Sentinel")
        print("   ✅ Realistic multi-vendor event generation")
        print("   ✅ MITRE ATT&CK technique mapping")
        print("   ✅ Enterprise-scale attack simulations")
        
        # Run demonstrations
        print_scenario_overview()
        demonstrate_apt_scenario()
        demonstrate_container_scenario()
        demonstrate_competitive_analysis()
        demonstrate_scenario_report()
        demonstrate_capability_filtering()
        
        print_header("SCENARIO SYSTEM READY FOR DEPLOYMENT", 1)
        print("🎉 All Cortex scenario demonstrations completed successfully!")
        print("\n🚀 Key Benefits for Domain Consultants:")
        print("   • Showcase Cortex XSIAM's multi-vector correlation capabilities")
        print("   • Demonstrate cloud-native security advantages")
        print("   • Provide competitive differentiation talking points")
        print("   • Generate realistic attack scenarios for customer demos")
        print("   • Support both traditional IR and modern cloud security use cases")
        
        print("\n💼 Perfect for:")
        print("   • Customer security assessments")
        print("   • Proof of concept demonstrations")
        print("   • SOC team training scenarios")
        print("   • Competitive displacement opportunities")
        print("   • XSIAM/Prisma Cloud evaluation scenarios")
        
        print(f"\n📊 System Statistics:")
        total_scenarios = len(CORTEX_SCENARIO_LIBRARY.scenarios)
        total_detection_rules = len(CORTEX_SCENARIO_LIBRARY.detection_rules)
        print(f"   • {total_scenarios} comprehensive security scenarios")
        print(f"   • {total_detection_rules} Cortex-specific detection rules")
        print("   • 22 enterprise security vendors integrated")
        print("   • 50+ MITRE ATT&CK techniques mapped")
        print("   • Multi-vendor correlation capabilities")
        print("   • Cloud-native and traditional environment support")
        
        return True

    if __name__ == "__main__":
        try:
            success = main()
            if success:
                sys.exit(0)
            else:
                sys.exit(1)
        except ImportError as e:
            print(f"❌ Import Error: {e}")
            print("💡 Make sure all required modules are available.")
            print("   The system uses the existing vendor and TTP libraries.")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Error during demonstration: {e}")
            sys.exit(1)

except ImportError as e:
    print("❌ MISSING DEPENDENCIES")
    print(f"Error: {e}")
    print("\n💡 This appears to be because the scenarios module depends on:")
    print("   • The existing vendor library")
    print("   • The TTP (MITRE ATT&CK) library") 
    print("   • The advanced generation features")
    print("\n🔧 To resolve this, we can create a standalone demo that doesn't require these dependencies.")
    print("   Would you like me to create a simplified version?")
