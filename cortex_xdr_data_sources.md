# Cortex XDR Data Sources Reference

This document provides a comprehensive overview of all data sources that can be ingested by Cortex XDR, organized by category and ingestion method.

## 1. Agent-Based Data Sources

### 1.1 Endpoint Agents

#### Cortex XDR Agent (Windows)
- **Data Types**: Process execution, file operations, registry changes, network connections, DLL loads
- **Collection Methods**: Kernel-level hooks, ETW (Event Tracing for Windows)
- **Key Events**: 
  - Process creation/termination (Windows Event ID 4688, 4689)
  - Network connections (port bindings, connections)
  - File system operations (create, modify, delete)
  - Registry operations (create, modify, delete keys/values)
  - Module loads (DLL/executable loads)
  - Authentication events (4624, 4625, 4634)

#### Cortex XDR Agent (macOS)
- **Data Types**: Process execution, file operations, network connections, system calls
- **Collection Methods**: Endpoint Security Framework, kernel extensions
- **Key Events**:
  - Process/fork events
  - File system events (FSEvents)
  - Network connections
  - Authentication events
  - System extension loads

#### Cortex XDR Agent (Linux)
- **Data Types**: Process execution, file operations, network connections, system calls
- **Collection Methods**: eBPF, audit subsystem, kernel modules
- **Key Events**:
  - Process execution (execve, fork, clone)
  - File operations (open, read, write, unlink)
  - Network connections (socket operations)
  - User authentication
  - System call monitoring

### 1.2 Network Sensors

#### Cortex XDR Network Sensor
- **Data Types**: Network traffic metadata, protocol analysis, threat detection
- **Collection Methods**: Network packet inspection, flow analysis
- **Supported Protocols**: HTTP/HTTPS, DNS, SMTP, FTP, SSH, SMB, RDP

## 2. API-Based Integrations

### 2.1 Cloud Service Providers

#### Amazon Web Services (AWS)
- **CloudTrail**: API calls, management events, data events
- **VPC Flow Logs**: Network traffic flows
- **GuardDuty**: Threat intelligence and anomaly detection
- **Config**: Configuration changes and compliance
- **S3 Access Logs**: Object access events
- **ELB Access Logs**: Load balancer traffic
- **CloudWatch Logs**: Application and system logs
- **WAF Logs**: Web application firewall events

#### Microsoft Azure
- **Activity Logs**: Management plane operations
- **Azure AD Audit Logs**: Identity and access events
- **Azure AD Sign-in Logs**: Authentication events
- **Network Security Group Flow Logs**: Network traffic
- **Application Gateway Access Logs**: Web traffic
- **Key Vault Audit Logs**: Cryptographic operations
- **Storage Account Logs**: Blob, file, queue, table access

#### Google Cloud Platform (GCP)
- **Cloud Audit Logs**: Admin activity, data access, system events
- **VPC Flow Logs**: Network traffic metadata
- **Cloud DNS Logs**: DNS query/response data
- **Cloud NAT Logs**: Network address translation
- **Identity and Access Management (IAM) Logs**: Access control events

### 2.2 Identity and Access Management

#### Azure Active Directory (Entra ID)
- **Sign-in Logs**: User authentication events
- **Audit Logs**: Administrative actions
- **Provisioning Logs**: User/group provisioning
- **Risk Detections**: Identity risk events

#### Okta
- **System Log**: Authentication, authorization, and admin events
- **Authentication Events**: MFA, SSO, password events
- **Application Events**: App access and usage
- **Admin Events**: Configuration changes

#### Ping Identity
- **Authentication Events**: SSO, MFA events
- **Authorization Events**: Access decisions
- **Administrative Events**: Configuration changes

### 2.3 Email and Collaboration

#### Microsoft 365
- **Exchange Online**: Email flow, mailbox access
- **SharePoint Online**: Document access and sharing
- **Teams**: Chat, meeting, and file activities
- **OneDrive**: File synchronization and sharing
- **Defender for Office 365**: Email security events

#### Google Workspace
- **Gmail**: Email events and security
- **Drive**: File operations and sharing
- **Admin Console**: Administrative actions
- **Calendar**: Meeting and event data

### 2.4 Container and Orchestration

#### Kubernetes
- **Audit Logs**: API server requests and responses
- **Event Logs**: Cluster events and state changes
- **Container Runtime**: Docker/containerd events
- **Pod Logs**: Application logs from containers

#### Docker
- **Container Events**: Start, stop, create, destroy
- **Image Events**: Pull, push, build operations
- **Network Events**: Container networking
- **Volume Events**: Storage operations

## 3. Syslog-Based Ingestion

### 3.1 Network Security Devices

#### Palo Alto Networks
- **PAN-OS Firewalls**: Traffic, threat, URL, data filtering logs
- **Prisma Access**: Cloud security service logs
- **GlobalProtect**: VPN and endpoint logs
- **Traps/XDR Agent**: Endpoint security events

#### Cisco Security
- **ASA/Firepower**: Firewall and IPS logs
- **Umbrella**: DNS security and web filtering
- **AMP for Endpoints**: Endpoint detection logs
- **Identity Services Engine (ISE)**: Network access control
- **Web Security Appliance (WSA)**: Web proxy logs
- **Email Security Appliance (ESA)**: Email security events

#### Fortinet
- **FortiGate**: Firewall traffic and security logs
- **FortiMail**: Email security events
- **FortiWeb**: Web application firewall logs
- **FortiAnalyzer**: Centralized logging

#### Check Point
- **Security Gateways**: Firewall and VPN logs
- **Threat Prevention**: IPS and anti-malware logs
- **Application Control**: Application usage logs
- **URL Filtering**: Web access logs

### 3.2 Network Infrastructure

#### Cisco Networking
- **Switches (Catalyst)**: Port security, VLAN, STP events
- **Routers (ISR/ASR)**: Routing, interface events
- **Wireless Controllers**: WiFi access and security
- **Prime Infrastructure**: Network monitoring events

#### Juniper
- **SRX Series**: Firewall and IPS logs
- **MX Series**: Router operational logs
- **EX Series**: Switch operational logs

#### Arista
- **EOS Switches**: Interface, routing, and security events

### 3.3 Web and Application Security

#### F5 Networks
- **BIG-IP**: Load balancer and application security logs
- **Application Security Manager (ASM)**: WAF events
- **Access Policy Manager (APM)**: Authentication logs

#### Imperva
- **Web Application Firewall**: Attack detection logs
- **Database Security**: Database access monitoring
- **File Security**: File access monitoring

#### Akamai
- **Web Application Protector**: Security events
- **Bot Manager**: Bot detection logs
- **Enterprise Application Access**: Zero trust access

## 4. Third-Party Security Tools Integration

### 4.1 Endpoint Detection and Response (EDR)

#### CrowdStrike Falcon
- **Detection Events**: Malware, suspicious behavior
- **Process Events**: Execution timeline
- **Network Events**: Connections and DNS
- **File Events**: Hash analysis and reputation

#### SentinelOne
- **Detection Events**: Threat detection and mitigation
- **Behavioral Events**: Process and file activity
- **Network Events**: Communication patterns
- **Forensic Data**: Detailed investigation data

#### Carbon Black (VMware)
- **Endpoint Events**: Process, network, file operations
- **Binary Analysis**: File reputation and analysis
- **Threat Intelligence**: IOC matching

### 4.2 Security Information and Event Management (SIEM)

#### Splunk
- **Universal Forwarder**: Log collection and forwarding
- **Heavy Forwarder**: Data processing and forwarding
- **HTTP Event Collector**: API-based log ingestion

#### IBM QRadar
- **Event Processor**: Security event processing
- **Log Source Events**: Normalized security data
- **Flow Events**: Network flow analysis

#### ArcSight (Micro Focus)
- **SmartConnectors**: Various data source connectors
- **Logger Events**: Centralized log storage events
- **ESM Events**: Correlation and alerting

### 4.3 Vulnerability Management

#### Rapid7 InsightVM
- **Vulnerability Scans**: Asset vulnerabilities
- **Asset Discovery**: Network asset inventory
- **Remediation Tracking**: Vulnerability lifecycle

#### Qualys VMDR
- **Vulnerability Data**: Scan results and findings
- **Asset Inventory**: Discovered assets
- **Compliance Data**: Regulatory compliance status

#### Tenable.io
- **Vulnerability Scans**: Network and web app vulnerabilities
- **Asset Discovery**: IT asset inventory
- **Compliance Results**: Configuration assessments

## 5. Custom and Specialized Sources

### 5.1 Database Security

#### Oracle Database
- **Audit Trail**: Database access and operations
- **Alert Log**: Database errors and warnings
- **Listener Log**: Connection attempts

#### Microsoft SQL Server
- **Audit Logs**: Database access events
- **Error Log**: System and security messages
- **Agent Job History**: Scheduled task execution

#### MySQL/MariaDB
- **General Query Log**: All database queries
- **Error Log**: Server errors and warnings
- **Slow Query Log**: Performance issues

### 5.2 Web Servers

#### Apache HTTP Server
- **Access Log**: Web request logs
- **Error Log**: Server errors and security events
- **ModSecurity Audit Log**: WAF events

#### Microsoft IIS
- **IIS Logs**: Web request and response data
- **Failed Request Tracing**: Detailed error analysis
- **HTTP.sys Error Log**: Kernel-mode driver errors

#### NGINX
- **Access Log**: Request logs with custom formats
- **Error Log**: Server and security errors

### 5.3 Application Frameworks

#### Java Applications
- **Application Logs**: Log4j, SLF4J, Java Util Logging
- **JMX Metrics**: Application performance data
- **Garbage Collection Logs**: Memory management events

#### .NET Applications
- **Event Log**: Windows application events
- **ETW Events**: Application tracing
- **IIS Application Events**: ASP.NET events

### 5.4 DevOps and CI/CD

#### Jenkins
- **Build Logs**: Compilation and deployment events
- **Audit Trail**: User actions and configuration changes
- **Plugin Events**: Extension activity

#### GitLab/GitHub
- **Audit Logs**: Repository and administrative events
- **Push Events**: Code changes and commits
- **Pipeline Events**: CI/CD execution logs

#### Docker Registry
- **Access Logs**: Image pull/push events
- **Webhook Events**: Registry notifications

## 6. IoT and Operational Technology

### 6.1 Industrial Control Systems

#### Schneider Electric
- **Modicon PLCs**: Industrial process events
- **PowerLogic**: Power management events
- **EcoStruxure**: IoT platform events

#### Siemens
- **SIMATIC**: Industrial automation events
- **WinCC**: HMI and SCADA events
- **SINEC**: Industrial network security

### 6.2 Building Management Systems

#### Honeywell
- **Building Automation**: HVAC and security events
- **Access Control**: Physical security events
- **Fire Safety**: Alarm and suppression events

## 7. Data Ingestion Methods and Formats

### 7.1 Supported Log Formats
- **CEF (Common Event Format)**: ArcSight standard format
- **LEEF (Log Event Extended Format)**: IBM QRadar format
- **JSON**: Structured data format
- **Syslog (RFC 3164/5424)**: Standard syslog formats
- **CSV**: Comma-separated values
- **XML**: Structured markup format
- **Key-Value Pairs**: Simple structured format

### 7.2 Transport Protocols
- **Syslog UDP (514)**: Standard syslog transport
- **Syslog TCP (514)**: Reliable syslog transport
- **Syslog over TLS (6514)**: Encrypted syslog transport
- **HTTP/HTTPS**: RESTful API ingestion
- **Kafka**: Streaming data platform
- **MQTT**: IoT messaging protocol
- **SNMP Traps**: Network device notifications

### 7.3 Authentication Methods
- **API Keys**: Simple token-based authentication
- **OAuth 2.0**: Standard authorization framework
- **Certificate-based**: X.509 certificate authentication
- **SAML**: Security Assertion Markup Language
- **Kerberos**: Network authentication protocol

## 8. Integration Architecture

### 8.1 Direct Integration
- Native XDR agent deployment
- API-based real-time streaming
- Webhook subscriptions

### 8.2 Broker-Based Integration
- Cortex Data Lake connectors
- Third-party log shippers (Fluentd, Logstash)
- Message queue integration (Kafka, RabbitMQ)

### 8.3 Batch Processing
- Scheduled data imports
- File-based transfers (SFTP, S3)
- Database bulk exports

## 9. Data Normalization and Enrichment

### 9.1 XDM (Extended Detection and Response Data Model)
- Unified schema for all ingested data
- Automatic field mapping and normalization
- Context enrichment with threat intelligence

### 9.2 Data Processing Pipeline
- Parsing and field extraction
- Data validation and cleansing
- Correlation with existing data
- Threat intelligence enrichment
- Analytics and machine learning processing

This comprehensive reference covers the major data sources and ingestion methods supported by Cortex XDR. The platform's strength lies in its ability to normalize and correlate data from diverse sources into a unified security operations view.