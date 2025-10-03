# Cortex Marketplace Data Modeling and Parsing Rules Guide

This comprehensive guide covers the key requirements for generating logs that are compatible with Cortex XDR/XSIAM marketplace parsing rules, data modeling rules, and XDM (eXtensible Data Model) schema requirements.

## 1. Cortex Marketplace Content Structure

### 1.1 Content Pack Components

**Parsing Rules (.yaml)**
- Define how raw logs are parsed and fields extracted
- Use regex patterns, JSON path expressions, or predefined parsers
- Map extracted fields to XDM schema
- Handle different log formats from the same vendor

**Data Modeling Rules (.yaml)**
- Transform parsed fields into standardized XDM format
- Apply enrichment logic and field mappings
- Define conditional logic for different event types
- Normalize timestamps, severity levels, and categorization

**Correlations Rules (.yaml)**
- Define relationships between events
- Create analytics rules for threat detection
- Map to MITRE ATT&CK framework
- Configure alert generation criteria

**Playbooks and Automations**
- Response actions and workflows
- Investigation procedures
- Automated enrichment processes

### 1.2 Broker VM Applets

**Syslog Collector**
- Receives syslog messages (UDP/TCP/TLS)
- Applies parsing rules based on source IP/hostname
- Forwards parsed events to Cortex Data Lake
- Supports CEF, LEEF, and custom formats

**Generic API Collector**
- Polls REST APIs for log data
- Handles authentication (API keys, OAuth, certificates)
- Transforms JSON/XML responses to XDM
- Supports pagination and rate limiting

**File Collector**
- Monitors directories for log files
- Processes CSV, JSON, XML, and text formats
- Handles file rotation and archival
- Supports compression formats

## 2. XDM (eXtensible Data Model) Schema

### 2.1 Core XDM Structure

```yaml
# Base event structure
event:
  _time: "2024-01-01T12:00:00.000Z"        # ISO 8601 timestamp
  _vendor: "Palo Alto Networks"             # Vendor name
  _product: "PAN-OS"                        # Product name
  _event_type: "TRAFFIC"                    # Event classification
  _severity: "INFO"                         # Severity level
  _raw_log: "original log message"          # Original log content
```

### 2.2 XDM Field Categories

**Network Fields**
```yaml
xdm:
  network:
    src_ip: "192.168.1.100"
    dst_ip: "10.0.0.50"
    src_port: 49152
    dst_port: 443
    protocol: "TCP"
    direction: "OUTBOUND"
    bytes_sent: 1024
    bytes_received: 2048
    packets_sent: 10
    packets_received: 15
    application: "web-browsing"
    rule_name: "Allow-Web-Traffic"
    action: "ALLOW"
```

**Source/Target Assets**
```yaml
xdm:
  source:
    host:
      hostname: "workstation-01"
      domain: "corp.local"
      os_family: "WINDOWS"
      ipv4: ["192.168.1.100"]
      mac: "00:1B:44:11:3A:B7"
  target:
    host:
      hostname: "web-server-01"
      ipv4: ["10.0.0.50"]
```

**Process Information**
```yaml
xdm:
  source:
    process:
      name: "powershell.exe"
      pid: 1234
      parent_name: "cmd.exe"
      parent_pid: 5678
      command_line: "powershell.exe -ExecutionPolicy Bypass"
      executable_path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
      sha256: "abc123...def789"
      integrity_level: "HIGH"
```

**User/Identity Information**
```yaml
xdm:
  source:
    user:
      username: "jdoe"
      domain: "CORP"
      upn: "jdoe@corp.local"
      groups: ["Domain Users", "Administrators"]
      sid: "S-1-5-21-123456789-123456789-123456789-1001"
```

**Authentication Events**
```yaml
xdm:
  auth:
    method: "PASSWORD"
    mfa_method: "TOTP"
    result: "SUCCESS"
    failure_reason: null
    session_id: "sess_abc123"
    application: "Okta Dashboard"
    resource: "https://company.okta.com"
```

**Cloud Events**
```yaml
xdm:
  cloud:
    provider: "AWS"
    account_id: "123456789012"
    region: "us-east-1"
    service: "iam.amazonaws.com"
    operation: "AttachUserPolicy"
    resource_id: "arn:aws:iam::123456789012:user/john"
    user_identity_type: "IAMUser"
```

### 2.3 MITRE ATT&CK Integration

**Technique Mapping**
```yaml
xdm:
  alert:
    mitre_tactics: ["TA0003"]  # Persistence
    mitre_techniques: ["T1547.001"]  # Boot or Logon Autostart Execution
    mitre_subtechniques: ["T1547.001"]  # Registry Run Keys
    severity: "MEDIUM"
    category: "Persistence"
    subcategory: "Registry Modification"
```

## 3. Parsing Rule Patterns

### 3.1 Common Regex Patterns

**Timestamp Parsing**
```yaml
# ISO 8601 format
timestamp: '\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z?'

# Syslog format
timestamp: '[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}'

# Custom format
timestamp: '\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}'
```

**IP Address Extraction**
```yaml
# IPv4
ipv4: '\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'

# IPv6
ipv6: '\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
```

**Process Information**
```yaml
# Process with PID
process_info: '(?P<process_name>\w+\.exe)\s*\((?P<pid>\d+)\)'

# Command line
command_line: 'CommandLine:\s*"(?P<cmdline>[^"]*)"'

# File path
file_path: '(?P<filepath>[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*)'
```

### 3.2 Vendor-Specific Parsing Examples

**Palo Alto Networks PAN-OS**
```yaml
# Traffic log parsing
regex: '^(?P<future_use1>[^,]*),(?P<receive_time>[^,]*),(?P<serial_num>[^,]*),(?P<type>[^,]*),(?P<threat_content_type>[^,]*),(?P<config_ver>[^,]*),(?P<time_generated>[^,]*),(?P<src>[^,]*),(?P<dst>[^,]*),(?P<natsrc>[^,]*),(?P<natdst>[^,]*),(?P<rule>[^,]*),(?P<srcuser>[^,]*),(?P<dstuser>[^,]*),(?P<app>[^,]*),(?P<vsys>[^,]*),(?P<from>[^,]*),(?P<to>[^,]*),(?P<inbound_if>[^,]*),(?P<outbound_if>[^,]*),(?P<logset>[^,]*),(?P<time_logged>[^,]*),(?P<sessionid>[^,]*),(?P<repeatcnt>[^,]*),(?P<sport>[^,]*),(?P<dport>[^,]*),(?P<natsport>[^,]*),(?P<natdport>[^,]*),(?P<flags>[^,]*),(?P<proto>[^,]*),(?P<action>[^,]*),(?P<bytes>[^,]*),(?P<bytes_sent>[^,]*),(?P<bytes_received>[^,]*),(?P<packets>[^,]*),(?P<start_time>[^,]*),(?P<elapsed_time>[^,]*),(?P<category>[^,]*),(?P<seqno>[^,]*),(?P<actionflags>[^,]*),(?P<srcloc>[^,]*),(?P<dstloc>[^,]*)'

field_mappings:
  _time: receive_time
  xdm.network.src_ip: src
  xdm.network.dst_ip: dst
  xdm.network.src_port: sport
  xdm.network.dst_port: dport
  xdm.network.protocol: proto
  xdm.network.action: action
  xdm.network.rule_name: rule
  xdm.network.application: app
```

**Cisco ASA**
```yaml
# ASA syslog parsing
regex: '%ASA-(?P<severity>\d+)-(?P<message_id>\d+):\s*(?P<message>.*)'

field_mappings:
  _time: timestamp
  xdm.event.original_event_type: message_id
  xdm.observer.name: hostname
  xdm.alert.severity: severity
```

**CrowdStrike Falcon**
```yaml
# JSON-based parsing
json_path_mappings:
  _time: "$.metadata.eventCreationTime"
  xdm.source.process.name: "$.event.ProcessRollup2.FileName"
  xdm.source.process.pid: "$.event.ProcessRollup2.ProcessId"
  xdm.source.process.command_line: "$.event.ProcessRollup2.CommandLine"
  xdm.source.host.hostname: "$.event.ProcessRollup2.ComputerName"
  xdm.source.user.username: "$.event.ProcessRollup2.UserName"
```

**Okta System Log**
```yaml
# JSON-based parsing
json_path_mappings:
  _time: "$.published"
  xdm.event.type: "$.eventType"
  xdm.auth.result: "$.outcome.result"
  xdm.source.user.username: "$.actor.alternateId"
  xdm.network.src_ip: "$.client.ipAddress"
  xdm.source.location.country: "$.client.geographicalContext.country"
```

## 4. Data Type Specifications

### 4.1 Required Data Types

**Timestamps**
- Must be in UTC
- ISO 8601 format preferred: `2024-01-01T12:00:00.000Z`
- Unix epoch timestamps accepted
- Custom formats require parsing rules

**IP Addresses**
- IPv4: Standard dotted decimal notation
- IPv6: Full or compressed notation
- Private/Public classification automatic
- Geolocation enrichment applied

**Ports**
- Integer values 1-65535
- Well-known port mapping applied
- Protocol context considered

**Severity Levels**
```yaml
# Numeric severity (RFC 3164)
0: EMERGENCY
1: ALERT  
2: CRITICAL
3: ERROR
4: WARNING
5: NOTICE
6: INFO
7: DEBUG

# Text severity mapping
CRITICAL -> 2
HIGH -> 3
MEDIUM -> 4
LOW -> 5
INFO -> 6
```

**Actions**
- Standardized action values
- ALLOW, DENY, BLOCK, DROP, RESET
- Vendor-specific actions mapped to standard

### 4.2 Field Validation Rules

**Required Fields**
```yaml
required_fields:
  - _time
  - _vendor
  - _product
  - _event_type
  - xdm.event.original_event_type
```

**Data Validation**
```yaml
validation_rules:
  ip_address:
    type: "ipv4|ipv6"
    required: false
  port:
    type: "integer"
    range: [1, 65535]
  severity:
    type: "integer|string"
    values: [0,1,2,3,4,5,6,7] | ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]
```

## 5. Broker VM Configuration Templates

### 5.1 Syslog Collector Configuration

```yaml
# Syslog input configuration
input:
  type: syslog
  protocol: udp
  port: 514
  bind_ip: "0.0.0.0"
  
# Parsing configuration
parsing:
  vendor_identification:
    - pattern: "CEF:0\\|Palo Alto Networks\\|"
      vendor: "Palo Alto Networks"
      product: "PAN-OS"
      parser: "panos_cef"
      
    - pattern: "%ASA-\\d+-\\d+:"
      vendor: "Cisco"
      product: "ASA"
      parser: "cisco_asa"
      
    - pattern: "\\{\"metadata\":\\{\"eventType\":"
      vendor: "CrowdStrike"
      product: "Falcon"
      parser: "crowdstrike_json"

# Output configuration      
output:
  type: cortex_data_lake
  api_endpoint: "https://api.xdr.us.paloaltonetworks.com"
  tenant_id: "${TENANT_ID}"
  api_key: "${API_KEY}"
```

### 5.2 API Collector Configuration

```yaml
# API input configuration
input:
  type: rest_api
  endpoint: "https://api.okta.com/api/v1/logs"
  method: GET
  authentication:
    type: bearer_token
    token: "${OKTA_API_TOKEN}"
  polling_interval: 300
  
# Response parsing
parsing:
  format: json
  timestamp_field: "published"
  batch_processing: true
  
# Field mappings
field_mappings:
  _time: "published"
  _vendor: "Okta"
  _product: "System Log"
  _event_type: "eventType"
  xdm.auth.result: "outcome.result"
```

## 6. Marketplace Compliance Requirements

### 6.1 Content Pack Standards

**Naming Conventions**
```yaml
content_pack:
  name: "Vendor Product Integration"
  version: "1.0.0"
  category: "Data Collection"
  
parsing_rule:
  name: "vendor_product_parser"
  version: "1.0.0"
  
modeling_rule:
  name: "vendor_product_modeling"
  version: "1.0.0"
```

**Documentation Requirements**
- Parser coverage matrix
- Supported log types and formats
- Field mapping documentation
- Testing procedures and test data
- Configuration examples

**Quality Assurance**
- Parsing accuracy > 95%
- XDM field coverage > 80%
- Performance benchmarks
- Error handling validation

### 6.2 Testing Framework

**Unit Tests**
```yaml
test_cases:
  - name: "traffic_log_parsing"
    input: "sample_traffic_log.txt"
    expected_fields:
      xdm.network.src_ip: "192.168.1.100"
      xdm.network.dst_ip: "10.0.0.50"
      xdm.network.action: "ALLOW"
      
  - name: "threat_log_parsing"
    input: "sample_threat_log.txt"
    expected_fields:
      xdm.alert.severity: "CRITICAL"
      xdm.alert.category: "malware"
```

**Integration Tests**
- End-to-end data flow validation
- Broker VM compatibility testing
- Data Lake ingestion verification
- Analytics rule execution

## 7. Best Practices for Log Generation

### 7.1 Format Consistency

**CEF Format Compliance**
```
CEF:0|Vendor|Product|Version|EventID|Name|Severity|Extension
```

**Syslog Header Format**
```
<Priority>Timestamp Hostname CEF:0|...
```

**JSON Format Structure**
```json
{
  "timestamp": "2024-01-01T12:00:00.000Z",
  "vendor": "Vendor Name",
  "product": "Product Name",
  "event": {
    "type": "event_type",
    "data": { ... }
  }
}
```

### 7.2 Field Population Guidelines

**Mandatory Fields**
- Always populate timestamp, vendor, product
- Include event type and severity
- Provide source IP when available
- Include user context for authentication events

**Optional Enrichment**
- Geographic information
- Asset identification
- Process genealogy
- Network flow details

### 7.3 Realistic Data Generation

**IP Address Ranges**
- Use RFC 1918 private ranges for internal traffic
- Use public ranges for external threats
- Include realistic geo-diversity

**Timing Patterns**
- Respect business hours for user activity
- Include burst patterns for attacks
- Add realistic delays between related events

**User Behavior**
- Generate consistent user sessions
- Include realistic failure rates
- Add seasonal and weekly patterns

This comprehensive guide ensures that generated logs will be properly parsed, modeled, and analyzed by Cortex XDR/XSIAM systems, providing maximum value for domain consultants and customers.