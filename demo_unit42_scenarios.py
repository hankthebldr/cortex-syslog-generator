#!/usr/bin/env python3
"""
Unit 42 Threat Research Integration Demonstration
===============================================

This script demonstrates the integration of actual Unit 42 threat research articles
into realistic syslog generation scenarios, providing authentic attack patterns
based on real threat intelligence.

Featured Unit 42 Research:
- Lazarus Group Cryptocurrency Attacks
- Volt Typhoon Critical Infrastructure Campaign
- Cl0p Ransomware MOVEit Exploitation
- ScarletEel Cloud Cryptojacking Campaign
- SolarWinds SUNBURST Supply Chain Attack
- HAFNIUM Exchange Server Zero-Day Exploits
"""

import sys
import os
import json
from datetime import datetime

# Add src to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

try:
    from scenarios.unit42_scenarios import UNIT42_SCENARIO_LIBRARY
    
    def print_header(title: str, level: int = 1):
        """Print formatted header"""
        if level == 1:
            print(f"\n{'='*80}")
            print(f"🎯 {title}")
            print('='*80)
        elif level == 2:
            print(f"\n{'🔸' * 3} {title}")
            print('-' * 70)
        else:
            print(f"\n💡 {title}")
    
    def demonstrate_unit42_overview():
        """Show overview of Unit 42 research integration"""
        print_header("UNIT 42 THREAT RESEARCH INTEGRATION", 1)
        
        articles = UNIT42_SCENARIO_LIBRARY.articles
        scenarios = UNIT42_SCENARIO_LIBRARY.scenarios
        
        print(f"📊 Unit 42 Articles Integrated: {len(articles)}")
        print(f"🎭 Realistic Scenarios Generated: {len(scenarios)}")
        
        print_header("THREAT ACTOR COVERAGE", 2)
        threat_actors = set()
        for article in articles.values():
            threat_actors.add(article.threat_actor)
        
        for actor in sorted(threat_actors):
            actor_scenarios = UNIT42_SCENARIO_LIBRARY.get_scenarios_by_threat_actor(actor)
            print(f"   🎭 {actor}: {len(actor_scenarios)} scenario(s)")
        
        print_header("INDUSTRY TARGETING ANALYSIS", 2)
        industries = {}
        for article in articles.values():
            for industry in article.targeted_industries:
                industries[industry] = industries.get(industry, 0) + 1
        
        for industry, count in sorted(industries.items(), key=lambda x: x[1], reverse=True):
            print(f"   🏢 {industry}: Targeted by {count} campaigns")
        
        print_header("ATTACK TYPE BREAKDOWN", 2)
        attack_types = {
            "APT/Nation-State": ["Lazarus", "Volt Typhoon", "HAFNIUM", "UNC2452"],
            "Ransomware": ["Cl0p"],
            "Cloud/Container": ["ScarletEel"],
            "Supply Chain": ["SUNBURST"],
            "Zero-Day": ["Exchange"]
        }
        
        for attack_type, keywords in attack_types.items():
            matching_articles = [a for a in articles.values() 
                               if any(keyword in a.title or keyword in a.threat_actor 
                                     for keyword in keywords)]
            print(f"   ⚔️  {attack_type}: {len(matching_articles)} research articles")
    
    def demonstrate_lazarus_scenario():
        """Detailed Lazarus Group scenario demonstration"""
        print_header("LAZARUS GROUP CRYPTOCURRENCY ATTACK", 1)
        
        scenario = UNIT42_SCENARIO_LIBRARY.get_scenario("UNIT42_LAZARUS_CRYPTO")
        article = scenario.unit42_article
        
        print(f"📑 Unit 42 Article: {article.title}")
        print(f"📅 Publication Date: {article.publication_date}")
        print(f"🎭 Threat Actor: {article.threat_actor}")
        print(f"🎪 Campaign: {article.campaign_name}")
        print(f"📝 Summary: {article.summary}")
        
        print_header("TARGETED INDUSTRIES", 2)
        for industry in article.targeted_industries:
            print(f"   🏢 {industry}")
        
        print_header("MALWARE FAMILIES", 2)
        for malware in article.malware_families:
            print(f"   🦠 {malware}")
        
        print_header("MITRE ATT&CK TECHNIQUES", 2)
        for technique in article.primary_techniques:
            print(f"   🎯 {technique}")
        
        print_header("INDICATORS OF COMPROMISE (IOCs)", 2)
        for ioc_type, iocs in article.iocs.items():
            print(f"   📊 {ioc_type.upper()}:")
            for ioc in iocs[:3]:  # Show first 3 IOCs
                print(f"      • {ioc}")
        
        print_header("ATTACK TIMELINE ANALYSIS", 2)
        for phase in article.attack_timeline:
            print(f"   📅 {phase['phase']} ({phase['duration']})")
            print(f"      Techniques: {', '.join(phase['techniques'])}")
            print(f"      Description: {phase['description']}")
            print()
        
        print_header("CORTEX DETECTION CAPABILITIES", 2)
        for i, detection in enumerate(article.cortex_detections, 1):
            print(f"   ✅ {i}. {detection}")
        
        print_header("REALISTIC LOG GENERATION", 2)
        logs = UNIT42_SCENARIO_LIBRARY.generate_realistic_logs(scenario.scenario_id, 10)
        
        print(f"📊 Generated {len(logs)} realistic security events")
        print(f"   🎯 Based on Unit 42 research: {article.title}")
        print(f"   ⏱️  Timeline: {scenario.attack_duration_hours} hours")
        print(f"   🎭 Threat Actor: {article.threat_actor}")
        
        print(f"\n📋 Sample Log Entries:")
        for i, log in enumerate(logs[:3], 1):
            print(f"   Log {i}: {log['event_id']}")
            print(f"      Phase: {log['phase']}")
            print(f"      Technique: {log['technique']}")
            print(f"      Source: {log['source']}")
            print(f"      Severity: {log['severity']}")
            print(f"      IOCs: {', '.join(log['iocs'][:2]) if log['iocs'] else 'N/A'}")
            print(f"      Cortex Detection: {log['cortex_detection']}")
            print()
    
    def demonstrate_volt_typhoon_scenario():
        """Volt Typhoon living off the land scenario"""
        print_header("VOLT TYPHOON CRITICAL INFRASTRUCTURE ATTACK", 1)
        
        scenario = UNIT42_SCENARIO_LIBRARY.get_scenario("UNIT42_VOLT_TYPHOON")
        article = scenario.unit42_article
        
        print(f"📑 Unit 42 Research: {article.title}")
        print(f"🎭 Threat Actor: {article.threat_actor}")
        print(f"🎯 Campaign Focus: {article.campaign_name}")
        print(f"📝 Key Insight: {article.summary}")
        
        print_header("LIVING OFF THE LAND APPROACH", 2)
        print("   🔧 Native Windows Tools Used:")
        for tool in article.iocs.get("file_paths", []):
            print(f"      • {tool}")
        
        print(f"\n   📊 Registry Persistence:")
        for reg_key in article.iocs.get("registry_keys", []):
            print(f"      • {reg_key}")
        
        print_header("ATTACK PROGRESSION", 2)
        timeline_events = scenario.realistic_timeline[:8]  # Show first 8 events
        
        for event in timeline_events:
            timestamp = datetime.fromisoformat(event['timestamp'])
            print(f"   {timestamp.strftime('%H:%M:%S')} | {event['phase']} | {event['technique']}")
            print(f"      {event['description']}")
            print(f"      🛡️  Cortex: {event['cortex_detection']}")
            print()
        
        print_header("CRITICAL INFRASTRUCTURE TARGETING", 2)
        for industry in article.targeted_industries:
            scenarios_targeting = UNIT42_SCENARIO_LIBRARY.get_scenarios_by_industry(industry)
            print(f"   🏭 {industry}: {len(scenarios_targeting)} relevant scenarios")
        
        print_header("BEHAVIORAL DETECTION ADVANTAGES", 2)
        for advantage in scenario.cortex_advantages:
            print(f"   🏆 {advantage}")
    
    def demonstrate_clop_ransomware_scenario():
        """Cl0p ransomware MOVEit exploitation"""
        print_header("CL0P RANSOMWARE MOVEIT ZERO-DAY EXPLOITATION", 1)
        
        scenario = UNIT42_SCENARIO_LIBRARY.get_scenario("UNIT42_CLOP_MOVEIT")
        article = scenario.unit42_article
        
        print(f"📑 Unit 42 Analysis: {article.title}")
        print(f"💀 Ransomware Group: {article.threat_actor}")
        print(f"🎯 Mass Exploitation Campaign: {article.campaign_name}")
        print(f"📊 Business Impact: {scenario.business_impact}")
        
        print_header("ZERO-DAY VULNERABILITIES EXPLOITED", 2)
        print("   🚨 CVE-2023-34362: MOVEit Transfer SQL Injection")
        print("      Allows unauthenticated access to MOVEit database")
        print("      CVSS Score: 9.8 (Critical)")
        
        print_header("WEB SHELLS DEPLOYED", 2)
        for shell in article.iocs.get("web_shells", []):
            print(f"   🐚 {shell}")
        
        print_header("RAPID ATTACK TIMELINE", 2)
        for phase in article.attack_timeline:
            print(f"   ⏱️  {phase['phase']} ({phase['duration']})")
            print(f"      {phase['description']}")
            techniques_str = ', '.join(phase['techniques'])
            print(f"      Techniques: {techniques_str}")
            print()
        
        print_header("MASS EXPLOITATION IMPACT", 2)
        print("   📊 Organizations Affected: 600+ globally")
        print("   💰 Ransom Demands: $5M - $75M per victim")
        print("   📁 Data Types Stolen:")
        print("      • Personal Identifiable Information (PII)")
        print("      • Financial Records")
        print("      • Government Communications")  
        print("      • Healthcare Records")
        
        print_header("CORTEX DETECTION TIMELINE", 2)
        logs = UNIT42_SCENARIO_LIBRARY.generate_realistic_logs(scenario.scenario_id, 15)
        
        # Group logs by phase
        phases = {}
        for log in logs:
            phase = log['phase']
            if phase not in phases:
                phases[phase] = []
            phases[phase].append(log)
        
        for phase, phase_logs in phases.items():
            print(f"   📅 {phase}: {len(phase_logs)} security events")
            sample_log = phase_logs[0]
            print(f"      Example: {sample_log['description'][:60]}...")
            print(f"      Detection: {sample_log['cortex_detection']}")
            print()
    
    def demonstrate_cloud_attack_scenario():
        """ScarletEel cloud cryptojacking"""
        print_header("SCARLETEEL CLOUD CRYPTOJACKING CAMPAIGN", 1)
        
        scenario = UNIT42_SCENARIO_LIBRARY.get_scenario("UNIT42_SCARLETEEL_CLOUD")
        article = scenario.unit42_article
        
        print(f"☁️  Cloud-Native Attack: {article.title}")
        print(f"🎭 Threat Actor: {article.threat_actor}")
        print(f"💰 Primary Objective: Cryptocurrency mining + Data theft")
        print(f"🎯 Target: {scenario.target_environment}")
        
        print_header("CONTAINER AND KUBERNETES EXPLOITATION", 2)
        print("   📦 Malicious Container Images:")
        for image in article.iocs.get("container_images", []):
            print(f"      • {image}")
        
        print(f"\n   ⚙️  Kubernetes Resources:")
        for resource in article.iocs.get("kubernetes_resources", []):
            print(f"      • {resource}")
        
        print_header("CLOUD-NATIVE ATTACK CHAIN", 2)
        for phase in article.attack_timeline:
            print(f"   🕐 {phase['phase']} ({phase['duration']})")
            print(f"      {phase['description']}")
            for technique in phase['techniques']:
                print(f"        - {technique}")
            print()
        
        print_header("PRISMA CLOUD DETECTION CAPABILITIES", 2)
        for detection in article.cortex_detections:
            print(f"   🛡️  {detection}")
        
        print_header("CRYPTOJACKING INDICATORS", 2)
        logs = UNIT42_SCENARIO_LIBRARY.generate_realistic_logs(scenario.scenario_id, 8)
        
        mining_logs = [log for log in logs if "T1496" in log['technique']]
        if mining_logs:
            print("   ⛏️  Cryptocurrency Mining Detection:")
            for log in mining_logs[:2]:
                print(f"      Event: {log['event_id']}")
                print(f"      Process: {log['indicators']['process']}")
                print(f"      Network: Mining pool communication detected")
                print(f"      Detection: {log['cortex_detection']}")
                print()
    
    def demonstrate_supply_chain_scenario():
        """SolarWinds SUNBURST supply chain attack"""
        print_header("SOLARWINDS SUNBURST SUPPLY CHAIN ATTACK", 1)
        
        scenario = UNIT42_SCENARIO_LIBRARY.get_scenario("UNIT42_SOLARWINDS_SUPPLY")
        article = scenario.unit42_article
        
        print(f"🔗 Supply Chain Attack: {article.title}")
        print(f"🎭 Threat Actor: {article.threat_actor}")
        print(f"📊 Scale: 18,000+ organizations affected")
        print(f"⏱️  Duration: {scenario.attack_duration_hours} hours of patient operations")
        
        print_header("SOPHISTICATED TRADECRAFT", 2)
        print("   🎯 Supply Chain Compromise Techniques:")
        print("      • Trojanized SolarWinds Orion software updates")
        print("      • Legitimate code signing certificates")
        print("      • Domain generation algorithm for C2")
        print("      • Patient, targeted approach (18+ months)")
        
        print_header("ATTACK TIMELINE PHASES", 2)
        for i, phase in enumerate(article.attack_timeline, 1):
            print(f"   {i}. {phase['phase']} ({phase['duration']})")
            print(f"      {phase['description']}")
            print(f"      Techniques: {', '.join(phase['techniques'])}")
            print()
        
        print_header("HIGH-VALUE TARGETS", 2)
        print("   🏛️  Government Agencies:")
        print("      • Department of Homeland Security")
        print("      • Treasury Department") 
        print("      • Commerce Department")
        print("      • Energy Department")
        print("   🏢 Fortune 500 Companies:")
        print("      • Microsoft (Azure/M365 compromise)")
        print("      • FireEye (Security vendor)")
        print("      • Numerous technology firms")
        
        print_header("SUNBURST MALWARE ANALYSIS", 2)
        print("   🦠 SUNBURST Backdoor Characteristics:")
        print("      • Dormant period: 12-14 days")
        print("      • Domain generation algorithm")
        print("      • Victim profiling and targeting")
        print("      • Steganographic C2 communications")
        
        sunburst_domains = article.iocs.get("domains", [])[:4]
        print(f"\n   🌐 C2 Domains (sample):")
        for domain in sunburst_domains:
            print(f"      • {domain}")
        
        print_header("CORTEX DETECTION RETROSPECTIVE", 2)
        print("   🔍 How Cortex Would Have Detected SUNBURST:")
        for detection in article.cortex_detections:
            print(f"      ✅ {detection}")
    
    def demonstrate_competitive_analysis():
        """Show competitive advantages across Unit 42 scenarios"""
        print_header("UNIT 42 COMPETITIVE ANALYSIS", 1)
        
        print_header("DETECTION CAPABILITY COMPARISON", 2)
        
        scenarios = list(UNIT42_SCENARIO_LIBRARY.scenarios.values())
        
        print(f"{'Attack Type':<25} {'Cortex Advantage':<50}")
        print("-" * 75)
        
        competitive_highlights = {
            "APT/Living Off Land": "Behavioral analytics detect abnormal admin tool usage",
            "Ransomware Zero-Day": "Network signatures + file integrity monitoring",
            "Cloud Cryptojacking": "Native container runtime protection",
            "Supply Chain": "Multi-layer correlation identifies subtle indicators",
            "Exchange Zero-Day": "Email security + endpoint correlation",
            "Cryptocurrency Theft": "Threat intelligence integration with AutoFocus"
        }
        
        for attack_type, advantage in competitive_highlights.items():
            print(f"{attack_type:<25} {advantage:<50}")
        
        print_header("UNIT 42 INTELLIGENCE INTEGRATION", 2)
        total_iocs = 0
        total_techniques = 0
        
        for scenario in scenarios:
            article = scenario.unit42_article
            for ioc_list in article.iocs.values():
                total_iocs += len(ioc_list)
            total_techniques += len(article.primary_techniques)
        
        print(f"   📊 Total IOCs Integrated: {total_iocs}")
        print(f"   🎯 MITRE Techniques Covered: {total_techniques}")
        print(f"   📑 Research Articles: {len(UNIT42_SCENARIO_LIBRARY.articles)}")
        print(f"   🎭 Threat Actors: 6 major APT groups")
        
        print_header("AUTOFOCUS THREAT INTELLIGENCE", 2)
        print("   🔍 AutoFocus Integration Benefits:")
        print("      • Real-time IOC correlation with Unit 42 research")
        print("      • Contextual threat actor attribution")
        print("      • Campaign tracking and analysis")
        print("      • Proactive threat hunting capabilities")
        
        print_header("COMPETITIVE DIFFERENTIATION", 2)
        print("   🏆 vs CrowdStrike:")
        print("      • Unit 42 research integration provides context")
        print("      • Multi-vector attack correlation")
        print("      • Cloud-native protection capabilities")
        
        print("   🏆 vs Microsoft Sentinel:")
        print("      • Built-in threat intelligence vs manual IOC feeds")
        print("      • Pre-built Unit 42 detection rules")
        print("      • Automated investigation playbooks")
        
        print("   🏆 vs Splunk:")
        print("      • Native security focus vs generic SIEM")
        print("      • Real-time threat intelligence integration")
        print("      • Purpose-built detection analytics")
    
    def demonstrate_syslog_generation():
        """Show realistic syslog generation capabilities"""
        print_header("UNIT 42 SYSLOG GENERATION CAPABILITIES", 1)
        
        print_header("REALISTIC LOG GENERATION", 2)
        
        # Generate logs for different attack types
        scenarios_to_demo = [
            ("UNIT42_LAZARUS_CRYPTO", "Cryptocurrency Attack"),
            ("UNIT42_CLOP_MOVEIT", "Ransomware Attack"),
            ("UNIT42_SCARLETEEL_CLOUD", "Cloud Attack")
        ]
        
        for scenario_id, attack_type in scenarios_to_demo:
            print(f"\n   📊 {attack_type} Log Generation:")
            logs = UNIT42_SCENARIO_LIBRARY.generate_realistic_logs(scenario_id, 5)
            
            print(f"      Generated {len(logs)} events")
            
            # Show log format variety
            sources = set(log['source'] for log in logs)
            techniques = set(log['technique'] for log in logs)
            
            print(f"      Security Sources: {', '.join(sources)}")
            print(f"      MITRE Techniques: {', '.join(list(techniques)[:3])}...")
            
            # Show sample log in JSON format
            sample_log = logs[0]
            print(f"      Sample Log Entry:")
            print("      " + json.dumps({
                "timestamp": sample_log['timestamp'],
                "source": sample_log['source'],
                "technique": sample_log['technique'],
                "threat_actor": sample_log['threat_actor'],
                "description": sample_log['description'][:50] + "...",
                "iocs": sample_log['iocs'][:2]
            }, indent=8))
        
        print_header("LOG CORRELATION FEATURES", 2)
        print("   🔗 Cross-Vendor Correlation:")
        print("      • Automatic IOC correlation across security tools")
        print("      • Timeline reconstruction based on Unit 42 research")
        print("      • Threat actor attribution using campaign signatures")
        
        print("   📈 Volume and Realism:")
        print("      • Configurable event volume (10-1000+ events)")
        print("      • Realistic timestamps based on attack phases")
        print("      • Authentic IOCs from Unit 42 research")
        print("      • Proper severity and confidence scoring")
    
    def main():
        """Main demonstration function"""
        print("🌟" * 40)
        print("   UNIT 42 THREAT RESEARCH INTEGRATION")
        print("     Real-World Attack Scenario Generation")
        print("       Based on Palo Alto Networks Research")
        print("🌟" * 40)
        
        print(f"\n🎯 This demonstration showcases:")
        print("   ✅ Integration of actual Unit 42 threat research articles")
        print("   ✅ Realistic attack scenarios from real-world campaigns")
        print("   ✅ Authentic IOCs, techniques, and timelines")
        print("   ✅ Cortex-specific detection and response capabilities")
        print("   ✅ Competitive advantages backed by threat intelligence")
        print("   ✅ Enterprise-grade syslog generation with real context")
        
        # Run demonstrations
        demonstrate_unit42_overview()
        demonstrate_lazarus_scenario()
        demonstrate_volt_typhoon_scenario()
        demonstrate_clop_ransomware_scenario()
        demonstrate_cloud_attack_scenario()
        demonstrate_supply_chain_scenario()
        demonstrate_competitive_analysis()
        demonstrate_syslog_generation()
        
        print_header("UNIT 42 INTEGRATION COMPLETE", 1)
        print("🎉 All Unit 42 research integration demonstrations completed successfully!")
        
        print(f"\n🚀 Perfect for Security Teams:")
        print("   • Realistic threat simulation based on actual campaigns")
        print("   • Unit 42 research-backed detection scenarios")
        print("   • Authentic IOCs and attack patterns for testing")
        print("   • Competitive intelligence for vendor evaluations")
        print("   • Training scenarios based on real-world threats")
        
        print(f"\n📊 System Capabilities:")
        print("   • 6 major Unit 42 research articles integrated")
        print("   • 6 threat actors with realistic attack patterns")
        print("   • 100+ authentic IOCs from real campaigns")
        print("   • 30+ MITRE ATT&CK techniques with context")
        print("   • Multi-vendor log generation with correlation")
        print("   • Configurable attack timelines and scenarios")
        
        print(f"\n💼 Business Value:")
        print("   • Validate security controls against real threats")
        print("   • Test detection capabilities with known attack patterns")
        print("   • Train SOC analysts on actual threat actor behavior")
        print("   • Demonstrate Cortex advantages with threat intelligence")
        print("   • Provide realistic data for security tool evaluation")
        
        return True

except ImportError as e:
    print("❌ IMPORT ERROR")
    print(f"Error: {e}")
    print("\n💡 The Unit 42 scenarios module could not be imported.")
    print("   Make sure the src/scenarios directory structure is correct.")
    exit(1)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"❌ Error: {e}")
        exit(1)