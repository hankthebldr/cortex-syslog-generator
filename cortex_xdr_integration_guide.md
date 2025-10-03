# Cortex XDR Data Sources Integration Guide

This guide shows how to leverage the comprehensive Cortex XDR data source research to enhance your syslog generator for better scenario coverage and realistic log simulation.

## Overview

Your existing cortex-syslog-generator now has access to:

1. **Comprehensive Data Source Reference** (`cortex_xdr_data_sources.md`) - Complete catalog of all Cortex XDR ingestion capabilities
2. **Extended Vendor Generators** (`src/xgen/vendors/extended_vendors.py`) - Additional vendor-specific log generators
3. **Enhanced TTP Coverage** - More realistic logs across all NICE categories

## Quick Integration Steps

### 1. Import Extended Vendors into Your App

Add to your existing `app.py`:

```python
# Add this import alongside your existing vendor imports
from src.xgen.vendors.extended_vendors import (
    EXTENDED_VENDOR_GENERATORS,
    EXTENDED_APT_VENDOR_MAPPINGS,
    generate_extended_vendor_logs,
    get_all_supported_vendors,
    get_data_source_categories
)

# Combine with existing vendors for GUI dropdown
def get_combined_vendor_options():
    from src.xgen.vendors.realistic_logs import VENDOR_GENERATORS
    original_vendors = list(VENDOR_GENERATORS.keys())
    extended_vendors = list(EXTENDED_VENDOR_GENERATORS.keys())
    return sorted(original_vendors + extended_vendors)
```

### 2. Update GUI for Data Source Categories

Enhance your Flask app with categorized vendor selection:

```python
@app.route('/api/data_source_categories')
def get_data_source_categories_api():
    """Get vendors organized by data source category for improved UI."""
    categories = get_data_source_categories()
    return jsonify(categories)

@app.route('/api/vendors/<apt_group>')
def get_vendors_for_apt(apt_group):
    """Get all vendors (original + extended) for an APT group."""
    all_vendors = get_all_supported_vendors()
    return jsonify(all_vendors.get(apt_group, []))
```

### 3. Enhanced Scenario Generation

Use the extended vendors in your scenario generation:

```python
def generate_enhanced_scenario_logs(apt_group, duration_seconds, events_per_second):
    """Generate logs using both original and extended vendor generators."""
    from src.xgen.vendors.realistic_logs import generate_apt_vendor_logs
    from src.xgen.vendors.extended_vendors import generate_extended_vendor_logs
    
    all_vendors = get_all_supported_vendors().get(apt_group, [])
    events = []
    
    for vendor in all_vendors:
        try:
            # Try extended vendors first
            vendor_events = generate_extended_vendor_logs(apt_group, vendor, 3)
            events.extend(vendor_events)
        except (ValueError, ImportError):
            try:
                # Fall back to original vendors
                vendor_events = generate_apt_vendor_logs(apt_group, vendor, 3)
                events.extend(vendor_events)
            except ValueError:
                continue  # Skip vendors not mapped for this APT group
    
    return events
```

## Data Source Categories for Realistic Scenarios

### Network Security Scenarios
Target vendors: Palo Alto Networks, Cisco ASA, FortiGate, Check Point, Zscaler, Proofpoint

**Use Case**: Generate realistic firewall, IPS, and web security logs for network-based attack scenarios
- APT28 lateral movement through firewalls
- APT29 C2 communication via web proxies
- Lazarus Group web-based attacks

### Endpoint Security Scenarios  
Target vendors: CrowdStrike, SentinelOne, VMware Carbon Black, Qualys

**Use Case**: Create authentic EDR and vulnerability management logs for endpoint-focused attacks
- Malware detection and behavioral analytics
- Process injection and living-off-the-land techniques
- Vulnerability exploitation chains

### Identity Management Scenarios
Target vendors: Okta, Microsoft Azure AD, Ping Identity, Duo Security

**Use Case**: Simulate cloud identity attacks and authentication bypass attempts
- APT29 cloud credential manipulation
- MFA bypass techniques
- Impossible travel scenarios

### Cloud Platform Scenarios
Target vendors: AWS, Microsoft 365, Google Cloud, Kubernetes

**Use Case**: Generate cloud-native attack logs across major platforms
- Container escape techniques
- Cloud privilege escalation
- Data exfiltration to cloud storage

## Realistic Log Volume Planning

Based on typical Cortex XDR customer environments:

### Small Environment (1,000 endpoints)
- **Network**: 50-100 events/second (PAN-OS, Cisco ASA)
- **Endpoint**: 20-50 events/second (CrowdStrike, SentinelOne)  
- **Identity**: 10-20 events/second (Okta, Azure AD)
- **Cloud**: 5-15 events/second (AWS CloudTrail, O365)

### Medium Environment (5,000 endpoints)
- **Network**: 200-500 events/second
- **Endpoint**: 100-250 events/second
- **Identity**: 50-100 events/second  
- **Cloud**: 25-75 events/second

### Large Environment (20,000+ endpoints)
- **Network**: 1,000+ events/second
- **Endpoint**: 500+ events/second
- **Identity**: 200+ events/second
- **Cloud**: 100+ events/second

## Integration Method Selection

### Agent-Based Sources
**Best for**: Real-time threat detection scenarios
- Cortex XDR Agents (Windows, macOS, Linux)
- Network sensors
- Direct API integrations

### Syslog-Based Sources  
**Best for**: Existing infrastructure integration
- Network devices (firewalls, switches, routers)
- Security appliances (IPS, web proxies)
- Legacy applications

### API-Based Sources
**Best for**: Cloud and SaaS integration scenarios
- Cloud providers (AWS, Azure, GCP)
- SaaS applications (O365, Salesforce)
- Modern security tools

## Sample Enhanced Scenario Configuration

```yaml
# Enhanced APT29 Cloud Attack Scenario
name: "APT29 Multi-Vector Cloud Attack"
description: "Comprehensive APT29 attack simulation across multiple data sources"

data_sources:
  network_security:
    - vendor: "Palo Alto Networks"
      product: "PAN-OS"
      events_per_minute: 10
      ttps: ["T1071.001_WEB_PROTOCOLS"]
    
    - vendor: "Zscaler" 
      product: "ZIA"
      events_per_minute: 5
      ttps: ["T1071.001_WEB_PROTOCOLS"]

  endpoint_security:
    - vendor: "SentinelOne"
      product: "EDR" 
      events_per_minute: 8
      ttps: ["T1059.001_POWERSHELL", "T1055_PROCESS_INJECTION"]

  identity_management:
    - vendor: "Okta"
      product: "SSO"
      events_per_minute: 3
      ttps: ["T1078.004_VALID_ACCOUNTS_CLOUD"]

  cloud_platforms:
    - vendor: "Microsoft 365"
      product: "Office 365"
      events_per_minute: 4
      ttps: ["T1114.003_EMAIL_FORWARDING_RULE"]
      
    - vendor: "Google Cloud"
      product: "Cloud Audit"
      events_per_minute: 2
      ttps: ["T1098_ACCOUNT_MANIPULATION"]
```

## Testing and Validation

### 1. Data Source Coverage Validation
```python
def validate_data_source_coverage():
    """Verify all major Cortex XDR data source categories are represented."""
    categories = get_data_source_categories()
    required_categories = ["Network Security", "Endpoint Security", "Identity Management", "Cloud Platforms"]
    
    for category in required_categories:
        assert category in categories, f"Missing category: {category}"
        assert len(categories[category]) > 0, f"No vendors in category: {category}"
    
    print("✅ All major data source categories covered")
```

### 2. Log Format Validation  
```python
def validate_cortex_xdr_compatibility():
    """Ensure generated logs are compatible with Cortex XDR ingestion."""
    # Test CEF format compliance
    # Test required field presence
    # Test data type consistency
    pass
```

### 3. Volume Testing
```python
def test_realistic_volume():
    """Test log generation at realistic enterprise volumes."""
    target_eps = 100  # events per second
    duration = 60     # 1 minute test
    
    start_time = time.time()
    events = generate_enhanced_scenario_logs("APT29", duration, target_eps)
    end_time = time.time()
    
    actual_eps = len(events) / (end_time - start_time)
    assert abs(actual_eps - target_eps) < 10, f"Volume test failed: {actual_eps} != {target_eps}"
```

## Deployment Considerations

### Broker VM Configuration
- **Memory**: 8GB minimum for processing high-volume logs
- **Storage**: 100GB+ for log buffering and retention
- **Network**: 1Gbps+ for high-throughput scenarios

### Cortex Data Lake Integration
- Configure appropriate data source connectors
- Set up data retention policies
- Enable threat intelligence enrichment

### Performance Optimization
- Use batch processing for high-volume scenarios
- Implement log rotation and compression
- Monitor ingestion pipeline health

## Troubleshooting Common Issues

### 1. High Memory Usage
- **Cause**: Generating too many events simultaneously
- **Solution**: Use streaming generation instead of batch creation

### 2. Network Timeouts  
- **Cause**: High-volume syslog transmission
- **Solution**: Implement connection pooling and retry logic

### 3. Data Format Rejection
- **Cause**: Cortex XDR schema validation failures
- **Solution**: Validate against XDM schema before transmission

### 4. Missing Threat Intelligence Context
- **Cause**: Logs lack IoC enrichment
- **Solution**: Add realistic threat indicators to generated events

## Next Steps

1. **Integrate Extended Vendors**: Add the new vendor generators to your GUI
2. **Category-Based Selection**: Implement data source category filters
3. **Volume Scaling**: Test with enterprise-scale log volumes
4. **Schema Validation**: Ensure XDR compatibility for all generated logs
5. **Threat Intelligence**: Add realistic IoC and context enrichment
6. **Performance Tuning**: Optimize for your target deployment environment

This comprehensive integration approach ensures your syslog generator can realistically simulate the full spectrum of data sources typically ingested by Cortex XDR in enterprise environments.