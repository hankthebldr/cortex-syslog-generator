# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Overview

The **Cortex Syslog Generator** is a production-ready enterprise security log generator and analytics simulator designed for Cortex XSIAM validation, SOC training, and competitive analysis. It generates realistic attack sequences mapped to **MITRE ATT&CK** with authentic log formats from 22+ enterprise security vendors.

## Quick Start

### Essential Commands

```bash
# One-command setup (All platforms)
make venv install run

# Step by step
make venv      # Create virtual environment  
make install   # Install all dependencies
make run       # Start web UI (localhost:5001)

# Testing and quality
make test      # Run test suite with coverage
make quality   # Run all quality checks (lint, type-check, security)
make format    # Format code with black and ruff

# Demos
make demo      # Interactive CLI demo
make demo-cortex    # Cortex XDR demo scenarios
make demo-enhanced  # Enhanced features demo
```

### Docker
```bash
# Build and run
docker build -t cortex-syslog-generator .
docker run -p 5001:5001 --rm cortex-syslog-generator

# Or use docker-compose (if available)
make docker-compose
```

## Tech Stack

- **Language**: Python 3.9+ (supports 3.9-3.12)
- **Build System**: setuptools with pyproject.toml
- **Web Framework**: Flask 2.3+ with Jinja2 templates
- **CLI Framework**: Typer with Click foundation
- **Data Generation**: Faker, NumPy, Pandas
- **Network/Transport**: Requests, HTTPX, AIOHttp
- **Serialization**: PyYAML, OrJSON for performance
- **Development**: Ruff, Black, MyPy, Pytest, Pre-commit
- **Deployment**: Docker multi-stage build, Gunicorn WSGI
- **Monitoring**: Structlog, Prometheus metrics

### Entrypoints
- **Primary**: `app.py` - Flask web application (port 5001)
- **CLI Scripts**: `cortex-syslog-generator`, `cortex-generator` (via pyproject.toml)
- **Demo Scripts**: `demo_*.py` - Various demonstration scenarios
- **Test Scripts**: `test_*.py` - Validation and integration tests

## Architecture Overview

```
┌─────────────────────┐    ┌─────────────────────┐    ┌─────────────────────┐
│   Web Interface     │    │   XGen Framework    │    │  Transport Layer    │
│   (Flask app.py)    │◄──►│  (src/xgen/core/)   │◄──►│ (syslog/HTTP/file)  │
└─────────────────────┘    └─────────────────────┘    └─────────────────────┘
          │                          │                          │
          ▼                          ▼                          ▼
┌─────────────────────┐    ┌─────────────────────┐    ┌─────────────────────┐
│  Legacy Generators  │    │   MITRE ATT&CK      │    │   Output Formats    │
│  (Built-in to app)  │    │   Pattern Library   │    │   CEF/JSON/SYSLOG   │
└─────────────────────┘    └─────────────────────┘    └─────────────────────┘
```

### Data Flow
1. **Config Loading**: Web UI → session config → transport selection
2. **Generator Selection**: Legacy generators vs XGen burst patterns
3. **Event Generation**: Vendor-specific logs with realistic 5-tuples
4. **Format Rendering**: CEF/JSON/SYSLOG with authentic field mapping
5. **Transport Delivery**: Syslog UDP/TCP, XSIAM HTTP, Generic Webhooks
6. **Session Management**: Threading with pause/resume, real-time streaming

### Concurrency Model
- **Threading**: Event generation runs in daemon threads
- **Queue Management**: Thread-safe event queues with locks
- **Backpressure**: Configurable rate limiting and sleep intervals
- **Session Lifecycle**: Stop/pause events with graceful shutdown

### Core Components

- **Flask Web App** (`app.py`): Main UI and legacy log generators for 22+ vendors
- **XGen Framework** (`src/xgen/`): Modern MITRE ATT&CK-based burst generation
- **Pattern Library** (`src/xgen/ttp/`): 50+ MITRE techniques with realistic network 5-tuples
- **Transport Adapters** (`src/xgen/transports/`): Syslog UDP/TCP/TLS, XSIAM HTTP, webhooks
- **Vendor Libraries** (`src/xgen/vendors/`): Authentic log formats for enterprise security tools

### Key Modules

- `src/xgen/core/burst_generator.py` - Main event generation engine
- `src/xgen/core/models.py` - Core data models (Actor, Asset, NetworkTuple, etc.)
- `src/xgen/ttp/mitre_patterns.py` - MITRE ATT&CK pattern definitions
- `src/xgen/formats/renderers.py` - CEF/JSON/SYSLOG formatting
- `src/xgen/integration/app_integration.py` - Bridge between Flask app and XGen

## XGen Framework Integration

The XGen framework (`src/xgen/`) provides modern MITRE ATT&CK-based burst generation with behavioral analytics focus.

### Core Architecture
- **Burst Generator** (`core/burst_generator.py`): Coordinated event generation with network 5-tuples
- **Session Manager** (`integration/app_integration.py`): Flask-XGen bridge with threading
- **Pattern Library** (`ttp/mitre_patterns.py`): 50+ MITRE techniques with realistic indicators
- **Transport Adapters** (`transports/adapters.py`): Multi-protocol delivery (Syslog/HTTP/Webhook)
- **Event Models** (`core/models.py`): Pydantic models for Actor, Asset, NetworkTuple

### Integration Points
1. **Session Initialization**: `XGenSession` manages threading and transport setup
2. **Configuration Bridge**: Web UI toggles → XGen transport selection
3. **Event Streaming**: Thread-safe queues with SSE for real-time display
4. **Format Compatibility**: XGen events render to CEF/JSON/LEEF formats

### Usage Patterns

```python
# Generate APT campaign
from xgen.core.burst_generator import BurstGenerator
from xgen.ttp.mitre_patterns import APTGroup

generator = BurstGenerator(seed=42)
events = generator.generate_apt_campaign(
    apt_group=APTGroup.APT29,
    duration_hours=0.5,
    intensity="medium"
)

# Generate single pattern burst
from xgen.ttp.mitre_patterns import get_pattern_by_id
pattern = get_pattern_by_id("T1021.002_SMB_LATERAL")
events = generator.generate_pattern_burst(pattern)

# Render as CEF with transport
from xgen.formats.renderers import render_events, LogFormat
from xgen.transports.adapters import create_transport_adapter, TransportType
cef_logs = render_events(events, LogFormat.CEF)

transport = create_transport_adapter(
    TransportType.SYSLOG_UDP,
    {"host": "127.0.0.1", "port": 514}
)
transport.send(events, cef_logs)
```

### Adding New Patterns
```python
# In src/xgen/ttp/mitre_patterns.py
T1234_NEW_TECHNIQUE = HeuristicPattern(
    pattern_id="T1234.001_NEW_TECHNIQUE",
    pattern_name="New Attack Technique",
    technique_id="T1234.001",
    tactic=AttackTactic.PERSISTENCE,
    min_events=3,
    max_events=8,
    time_window_seconds=300,
    port_sequences=[[445, 135], [3389]],  # SMB then RDP
    vendor_signatures={
        "Microsoft": ["4625", "4648"],  # Failed/explicit logon
        "CrowdStrike": ["ProcessRollup2"]
    }
)
```

### Available APT Groups and Patterns

**APT Campaigns:**
- APT29 (Cozy Bear) - Cloud & Enterprise persistence
- APT28 (Fancy Bear) - Enterprise lateral movement
- Volt Typhoon - Cloud credentials + living-off-land
- Lazarus Group - Registry persistence + mobile
- Carbanak (FIN7) - Task scheduling + financial fraud

**Individual Patterns:**
- `T1543.003_SERVICE_PERSIST` - Windows Service Persistence
- `T1021.002_SMB_LATERAL` - SMB Lateral Movement
- `T1098.001_CLOUD_CREDS` - Cloud Credential Manipulation
- `T1134.001_TOKEN_IMPERSONATION` - Token Impersonation

## Cortex Integration Points

The system provides multiple transport mechanisms for Cortex ecosystem integration:

### Transport Architecture
- **Syslog Protocols**: RFC3164/RFC5424 compliant (UDP 514, TCP 514, TLS 6514)
- **HTTP APIs**: XSIAM native ingestion with batching and compression
- **Authentication**: API keys, bearer tokens, mTLS support
- **Field Mapping**: Automatic XDM schema alignment for analytics

### Syslog Transport (Default)
```bash
# Local syslog (UDP 514)
dest_ip: "127.0.0.1"
enable_syslog: true

# Cortex Broker VM (recommended)
dest_ip: "<broker-vm-ip>"
enable_syslog: true

# TLS syslog for production
transport_type: "syslog_tls" 
port: 6514
```

### XSIAM HTTP Transport
```bash
# Environment variables for secure credential management
export XSIAM_HTTP_ENDPOINT="https://api-yourtenant/logs/v1/xsiam"
export XSIAM_API_KEY="${XSIAM_API_KEY}"        # Required
export XSIAM_API_KEY_ID="${XSIAM_API_KEY_ID}"  # Optional
export XSIAM_TENANT_ID="${XSIAM_TENANT_ID}"   # Optional

# Advanced HTTP configuration
export XSIAM_BATCH_SIZE="500"      # Events per batch
export XSIAM_TIMEOUT="30"          # Request timeout seconds
export XSIAM_COMPRESS="true"       # Gzip compression

# Enable via web UI or programmatically
enable_xsiam_http: true
```

### Generic Webhook
```bash
export WEBHOOK_ENDPOINT="https://your-endpoint/webhook"
export WEBHOOK_TOKEN="${WEBHOOK_TOKEN}"
export WEBHOOK_HEADERS="Content-Type:application/json,X-Source:cortex-generator"

enable_webhook: true
```

### XDM Field Mappings
Automatic mapping to Cortex XDM schema for analytics:

| Generator Field | XDM Field | Description |
|---|---|---|
| `suser`/`usrName` | `xdm.source.user.username` | Acting user |
| `src` | `xdm.source.ipv4` | Source IP address |
| `dst` | `xdm.target.ipv4` | Destination IP address |
| `spt`/`dstPort` | `xdm.source.port`/`xdm.target.port` | Network ports |
| `act`/`ConnectionStatus` | `xdm.event.outcome` | Action result |
| `cat` | `xdm.event.type` | Event category |
| `devTime` | `xdm.event.timestamp` | Event time |
| MITRE technique | `xdm.alert.mitre_technique` | ATT&CK technique |

### Integration Testing
```bash
# Test syslog connectivity 
nc -u 127.0.0.1 514  # UDP test
nc 127.0.0.1 514     # TCP test

# Test XSIAM HTTP endpoint
curl -I $XSIAM_HTTP_ENDPOINT

# Test webhook delivery
curl -X POST $WEBHOOK_ENDPOINT \
  -H "Authorization: Bearer $WEBHOOK_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"test": "connection"}'
```

## Configuration and Secrets

### Environment Variables
- `XSIAM_HTTP_ENDPOINT` - Cortex XSIAM HTTP endpoint
- `XSIAM_API_KEY` - XSIAM API key for authentication
- `WEBHOOK_ENDPOINT` - Generic webhook URL
- `WEBHOOK_TOKEN` - Bearer token for webhook auth
- `SYSLOG_HOST` - Syslog receiver hostname (default: 127.0.0.1)
- `SYSLOG_PORT` - Syslog receiver port (default: 514)

### Configuration Precedence
1. Web UI form inputs (per-run overrides)
2. Environment variables
3. Application defaults

### Secrets Management
- Store secrets in environment variables, never in code
- Use `.env` files for local development (not committed)
- Redact secrets in logs and output

### Development Workflows

### User Rules (CRITICAL)

⚠️ **These rules are mandatory for all contributions:**

1. **Never delete code** - Comment out superseded blocks with clear rationale annotations
2. **Never delete generated content** - Move to separate markdown files or searchable index with cross-links
3. **Firebase deployment is N/A** - This repo does not use Firebase/GCP; standard Python deployment applies
4. **Preserve orphaned components** - Document unused components in `DEPRECATED_COMPONENTS.md` for future reference

### Branch Strategy and Git Workflow

```bash
# Development workflow
git checkout -b feature/new-vendor-support    # Feature branches
git checkout -b fix/memory-leak-issue        # Bug fixes
git checkout -b docs/update-api-reference    # Documentation

# Before committing
make quality                                 # Run all quality checks
git add -A
git commit -m "feat(vendors): add Zscaler NSS Web Proxy generator"

# Pull request workflow
git push origin feature/new-vendor-support
# Open PR via GitHub with:
# - Clear description of changes
# - Reference to related issues
# - Screenshots for UI changes
# - Test results summary
```

### Commit Message Convention

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```bash
# Format: type(scope): description

feat(vendors): add Microsoft Defender ATP log generator
fix(xgen): resolve memory leak in burst generation
docs(readme): update installation instructions for macOS
test(integration): add Cortex XSIAM HTTP transport tests
refactor(core): improve event rendering performance
style(format): apply black formatting to all Python files
perf(transports): optimize syslog batch processing
ci(github): add Python 3.12 to test matrix
```

### Pre-commit Workflow and Quality Gates

```bash
# Install pre-commit hooks (required)
make pre-commit                    # Setup automated checks

# Manual quality validation
make lint                          # Ruff + Black code formatting
make type-check                    # MyPy static type checking
make security                      # Bandit security analysis
make test                          # Full test suite with coverage
make quality                       # All quality checks combined

# Continuous Integration checks
make test-integration              # Integration tests
make test-fast                     # Quick smoke tests
```

### Code Review Guidelines

#### For Contributors:
- Run `make quality` before opening PR
- Include test coverage for new functionality
- Update documentation for API changes
- Provide clear commit messages and PR descriptions
- Add vendor-specific examples and test cases

#### For Reviewers:
- Verify all quality gates pass
- Check for proper error handling and logging
- Validate performance impact with load tests
- Ensure no secrets or PII in code or tests
- Confirm backward compatibility is maintained

### Development Environment Setup

```bash
# Complete development setup
git clone https://github.com/PaloAltoNetworks/cortex-syslog-generator.git
cd cortex-syslog-generator

# Environment setup with all dev tools
make venv install pre-commit       # Virtual env + deps + hooks

# Verify installation
make info                          # System and dependency info
make test-fast                     # Quick verification test

# Start development server
make run                           # Web UI on http://localhost:5001
```

## Common Tasks

### Add New Vendor Log Generator

#### Method 1: Flask Integration (Legacy Generators)
```bash
# 1. Create generator function in app.py
def generate_new_vendor_logs():
    """Generate authentic NewVendor security logs."""
    # Add generator logic following existing patterns
    pass

# 2. Add to PRODUCTS list in app.py
PRODUCTS = [
    # ... existing products ...
    "NewVendor SecureProduct",
]

# 3. Update noise generation in app.py
def add_noise_to_logs():
    # Add NewVendor to noise patterns
    pass

# 4. Test implementation
make test-fast
python app.py  # Start web UI and test generator
```

#### Method 2: XGen Framework (Modern Approach)
```bash
# 1. Create vendor module
touch src/xgen/vendors/newvendor_generators.py

# 2. Implement generator class
cat > src/xgen/vendors/newvendor_generators.py << 'EOF'
from ..core.models import BaseEvent, Vendor, Product
from .base import BaseVendorGenerator

class NewVendorGenerator(BaseVendorGenerator):
    def __init__(self):
        vendor = Vendor(
            name="NewVendor",
            category="endpoint",  # endpoint, network, identity, cloud
            competitive_analysis="vs CrowdStrike: Better X, worse Y"
        )
        super().__init__(vendor)
    
    def generate_log(self, scenario: str) -> BaseEvent:
        # Implementation details
        pass
EOF

# 3. Register in vendor catalog
echo 'from .newvendor_generators import NewVendorGenerator' >> src/xgen/vendors/__init__.py
vim src/xgen/catalog/vendor_catalog.py  # Add to VENDOR_CATALOG

# 4. Test implementation
python demo_xgen.py --vendor NewVendor
make test
```

### Add New Output Transport/Sink

```bash
# 1. Define transport type in models
vim src/xgen/core/models.py
# Add to TransportType enum: NEW_TRANSPORT = "new_transport"

# 2. Implement transport adapter
cat > src/xgen/transports/new_transport_adapter.py << 'EOF'
from .base import BaseTransportAdapter
from ..core.models import BaseEvent, TransportType

class NewTransportAdapter(BaseTransportAdapter):
    def __init__(self, config: dict):
        super().__init__(TransportType.NEW_TRANSPORT, config)
    
    def send(self, events: List[BaseEvent], rendered_logs: List[str]) -> bool:
        # Implementation: HTTP, gRPC, file, message queue, etc.
        pass
EOF

# 3. Register in transport factory
vim src/xgen/transports/adapters.py
# Add to create_transport_adapter() function

# 4. Update integration layer
vim src/xgen/integration/app_integration.py
# Add transport parsing in _parse_transports()

# 5. Test transport
python -c "from src.xgen.transports.adapters import create_transport_adapter; print('Transport OK')"
make test-integration
```

### Add New Field Mapping/Transform

```bash
# 1. Update field mappings in renderers
vim src/xgen/formats/renderers.py

# Example: Add new XDM field mapping
def map_to_xdm_fields(event: BaseEvent) -> dict:
    xdm_event = {
        # ... existing mappings ...
        "xdm.new_field": event.custom_attribute,
        "xdm.network.rule": event.security_rule_name,
    }
    return xdm_event

# 2. Update CEF/LEEF field mappings
def render_cef_event(event: BaseEvent) -> str:
    cef_fields = {
        # ... existing fields ...
        "cs4": event.new_custom_field,  # Custom String 4
        "cn1": event.new_numeric_field,  # Custom Number 1
    }

# 3. Test field mappings
python test_log_authenticity.py  # Validate field compliance
python demo_enhanced_features.py  # Test rendering
```

### Run High-Volume Load Tests Safely

```bash
# 1. Prepare test environment
export SYSLOG_HOST="127.0.0.1"           # Local testing only
export SYSLOG_PORT="515"                 # Non-standard port for safety
export LOG_LEVEL="WARNING"               # Reduce log noise
export BATCH_SIZE="1000"                 # Optimize batching

# 2. Start local syslog receiver (optional)
sudo nc -u -l 515 > /tmp/test-logs.txt &  # Simple UDP receiver
NC_PID=$!

# 3. Run performance test scenarios
python test_performance_load.py --events-per-second=500 --duration=60
python demo_enhanced_features.py         # Enhanced generation features

# 4. Monitor system resources
htop &                                   # Monitor CPU/memory
watch -n 1 'netstat -an | grep :515'    # Monitor connections
watch -n 1 'wc -l /tmp/test-logs.txt'   # Monitor log count

# 5. Cleanup
kill $NC_PID
rm /tmp/test-logs.txt
unset SYSLOG_HOST SYSLOG_PORT LOG_LEVEL BATCH_SIZE
```

### Enable Debug Logging and Metrics

```bash
# 1. Enable comprehensive debug logging
export LOG_LEVEL=DEBUG
export FLASK_ENV=development
export XGEN_DEBUG=true
export TRANSPORT_DEBUG=true

# 2. Enable performance profiling
export ENABLE_PROFILING=true
export PROFILE_OUTPUT_DIR="./profiling"
mkdir -p profiling

# 3. Start application with debug mode
python -m flask --app app run --debug --host 0.0.0.0 --port 5001

# 4. Monitor logs in separate terminal
tail -f logs/cortex-generator.log | jq '.'

# 5. Generate test load and monitor
curl -X POST http://localhost:5001/start_generation \
  -H "Content-Type: application/json" \
  -d '{"duration_minutes": 1, "messages_per_second": 100}'

# 6. Analyze performance data
ls -la profiling/                       # Check generated profiles
python -m pstats profiling/profile.stats
```

### Regenerate Test Fixtures and Data

```bash
# 1. Generate new vendor log samples
python scripts/generate_vendor_samples.py --vendor=CrowdStrike --count=100
python scripts/generate_vendor_samples.py --vendor=Zscaler --count=50

# 2. Update MITRE ATT&CK pattern samples
python scripts/generate_mitre_samples.py --technique=T1566.001 --count=20
python scripts/generate_mitre_samples.py --apt-group=APT29 --duration=30

# 3. Regenerate test network data
python scripts/generate_network_fixtures.py \
  --internal-networks="192.168.0.0/16,10.0.0.0/8" \
  --external-networks="203.0.113.0/24"

# 4. Update vendor compliance validation data
python test_log_authenticity.py --regenerate-samples
python scripts/validate_vendor_compliance.py --update-baselines

# 5. Commit updated fixtures
git add sample_logs/ tests/fixtures/
git commit -m "test: regenerate vendor log fixtures and test data"
```

### Generate Comprehensive Zscaler Logs

```bash
# Test all Zscaler log formats (CEF/LEEF)
python demo_zscaler_logs.py

# Available Zscaler generators:
# - NSS Web Proxy (CEF format)
# - NSS Firewall (CEF format)  
# - ZPA User Activity (LEEF format)
# - ZPA User Status (LEEF format)
# - ZPA App Connector (LEEF format)
# - ZPA Audit Logs (LEEF format)

# Generate specific Zscaler scenario
python demo_zscaler_logs.py --scenario=web_proxy --count=100 --format=cef
python demo_zscaler_logs.py --scenario=zpa_user_activity --count=50 --format=leef
```

### Custom CSV Ingestion Workflow

```bash
# 1. Prepare CSV file with required columns
# Columns: timestamp,vendor,product,severity,event_name,message,username,src_ip,dst_ip,src_port,dst_port,protocol
cat > custom_logs.csv << 'EOF'
timestamp,vendor,product,severity,event_name,message,username,src_ip,dst_ip,src_port,dst_port,protocol
2025-10-07T10:00:00Z,Cisco,ASA,6,ConnectionAllowed,TCP connection allowed,jdoe,192.168.1.100,203.0.113.10,51234,443,TCP
2025-10-07T10:01:00Z,Palo Alto Networks,PAN-OS,4,ThreatPrevention,Malware blocked,admin,10.0.0.50,198.51.100.5,49152,80,TCP
EOF

# 2. Test CSV ingestion via Python API
python -c "from src.xgen.custom.csv_ingest import CsvIngestor; ing = CsvIngestor('custom_logs.csv'); print(f'Ingested {len(ing.events)} events')"

# 3. Use CSV ingestion in web UI
# - Start web UI: make run
# - Enter CSV path in "Custom CSV Path" field
# - Select transport options
# - Click "Start Generation"

# 4. Programmatic CSV processing
python scripts/ingest_csv_logs.py --input=custom_logs.csv --output-format=cef --transport=syslog
```

## Testing Strategy

### Test Pyramid Overview
- **Unit Tests**: 70% coverage - Fast execution (<5 seconds)
- **Integration Tests**: 20% coverage - Component interaction validation
- **End-to-End Tests**: 10% coverage - Full system scenarios
- **Performance Tests**: Load/stress testing with defined SLAs

### Unit Tests
```bash
# Full test suite execution
make test                      # Complete suite with coverage report
pytest tests/unit/ -v         # Unit tests with verbose output
pytest -k "generator" -x      # Specific pattern, fail fast
pytest --cov=src --cov-report=html  # HTML coverage report

# Test categories
pytest tests/unit/test_generators.py   # Log generator functions
pytest tests/unit/test_xgen.py         # XGen framework components
pytest tests/unit/test_transports.py   # Transport layer adapters
pytest tests/unit/test_formats.py      # CEF/LEEF/JSON renderers
```

### Integration Testing
```bash
# Multi-component interaction tests
python test_cortex_generation.py      # Cortex XDR integration scenarios
python test_enhanced_system.py        # Enhanced features validation
python test_log_authenticity.py       # Format compliance (98.5% target)
python test_mitre_mappings.py         # ATT&CK technique accuracy
python test_transport_delivery.py     # End-to-end transport validation

# Vendor-specific integration
python test_zscaler_integration.py    # Zscaler CEF/LEEF validation
python test_crowdstrike_formats.py    # CrowdStrike EDR log accuracy
python test_palo_alto_formats.py      # PAN-OS syslog compliance
```

### End-to-End Testing

#### Cortex XSIAM E2E Workflow
```bash
# 1. Setup test environment
export XSIAM_HTTP_ENDPOINT="https://test-tenant.xsiam.paloaltonetworks.com/logs/v1/xsiam"
export XSIAM_API_KEY="$(vault kv get -field=api_key secret/xsiam/test)"

# 2. Start application
make run &
APP_PID=$!

# 3. Execute E2E test scenarios
python test_e2e_xsiam_ingestion.py

# 4. Cleanup
kill $APP_PID
```

#### Local Syslog E2E Testing
1. **Setup**: Start local syslog receiver: `rsyslog` or `syslog-ng`
2. **Execute**: Run web UI and generate test scenarios
3. **Validate**: Parse received logs for correctness
4. **Metrics**: Measure ingestion rates and parsing success

```bash
# Local syslog receiver setup
sudo rsyslog -n -f /etc/rsyslog.conf -i /tmp/rsyslog.pid &
tail -f /var/log/syslog | grep "cortex-generator" &

# Run E2E test suite
python test_e2e_syslog_delivery.py
```

### Performance Testing

#### Performance Targets and SLAs
- **Throughput**: 10,000+ events/minute sustained (167 events/second)
- **Memory Usage**: <100MB for typical workloads, <500MB peak
- **Response Time**: Web UI <2 seconds, Log generation <100ms/event
- **Resource Efficiency**: <5% CPU utilization at 1,000 events/minute
- **Transport Latency**: <50ms for syslog, <500ms for HTTP endpoints

#### Load Testing Scripts
```bash
# High-throughput performance testing
python test_performance_load.py --events-per-second=200 --duration=300

# Memory usage profiling
python -m memory_profiler test_memory_usage.py

# Threading concurrency validation
python test_concurrent_generation.py --workers=8 --events=10000

# Transport stress testing
python test_transport_stress.py --transport=xsiam_http --batch-size=1000
```

#### Deterministic Testing
```bash
# Reproducible test runs with fixed seeds
BURST_SEED=42 pytest tests/performance/
XGEN_SEED=12345 python demo_xgen.py

# Example: Generate identical APT29 campaign
from xgen.core.burst_generator import BurstGenerator
generator = BurstGenerator(seed=42)
events = generator.generate_apt_campaign(APTGroup.APT29, duration_hours=1)
# Will always produce same event sequence for testing
```

### Continuous Integration Testing

#### GitHub Actions Pipeline
```yaml
# .github/workflows/test.yml example structure
strategy:
  matrix:
    python-version: [3.9, 3.10, 3.11, 3.12]
    
steps:
- name: Unit Tests
  run: make test
  
- name: Integration Tests  
  run: python test_cortex_generation.py
  
- name: Performance Benchmarks
  run: python test_performance_baseline.py
  
- name: Security Scanning
  run: make security
```

#### Quality Gates
- **Code Coverage**: Minimum 80% line coverage
- **Performance Regression**: <10% degradation vs baseline
- **Security**: Zero high/critical vulnerabilities
- **Log Authenticity**: 98.5% vendor compliance rate

### Test Data Management

#### Test Fixtures
- **Synthetic Network Data**: Pre-generated 5-tuples for consistency
- **MITRE ATT&CK Patterns**: Reference technique implementations
- **Vendor Log Samples**: Authentic log samples for validation
- **Transport Configs**: Pre-configured endpoint settings

```bash
# Test data generation
python scripts/generate_test_fixtures.py
python scripts/validate_vendor_samples.py
```

### Regression Testing

#### Automated Regression Suite
```bash
# Full regression test execution (30-45 minutes)
make regression-test

# Quick regression (5 minutes)
make smoke-test

# Performance regression baseline
python test_performance_regression.py --baseline=v2.1.0
```

#### Test Categories
- **Log Format Stability**: Ensure output formats remain consistent
- **API Compatibility**: XGen framework interface stability 
- **Transport Reliability**: Multi-protocol delivery consistency
- **Memory Leak Detection**: Long-running session validation

## Observability and Troubleshooting

### Structured Logging Framework
```bash
# Enable comprehensive debug logging
export LOG_LEVEL=DEBUG
export LOG_FORMAT=json          # JSON structured logs
export LOG_FILE=logs/cortex-generator.log

# Component-specific logging
export XGEN_LOG_LEVEL=DEBUG     # XGen framework detailed logs
export TRANSPORT_LOG_LEVEL=INFO # Transport layer events
export WEB_LOG_LEVEL=WARNING    # Web UI minimal logging

# Start with enhanced logging
make run

# Real-time log monitoring
tail -f logs/cortex-generator.log | jq '.' # Pretty-print JSON logs
tail -f logs/cortex-generator.log | grep "ERROR\|WARN" # Filter issues
```

### Application Metrics and Monitoring
```bash
# Built-in metrics endpoints (if implemented)
curl http://localhost:5001/metrics           # Prometheus metrics
curl http://localhost:5001/health            # Health check
curl http://localhost:5001/stats             # Generation statistics

# Manual monitoring commands
watch -n 5 'netstat -an | grep :514 | wc -l'  # Active syslog connections
watch -n 2 'ps aux | grep cortex | grep -v grep' # Process monitoring
```

### Common Issues and Solutions

#### **Web Interface Issues**

**Issue**: Web Interface Not Loading
```bash
# Diagnostic steps
python --version                 # Verify Python 3.9+
which python                    # Check Python path
source .venv/bin/activate       # Activate virtual environment
pip list | grep -i flask       # Verify Flask installation

# Resolution
make clean venv install         # Clean reinstall
echo $FLASK_ENV $FLASK_DEBUG    # Check Flask environment
lsof -i :5001                  # Check port availability
```

**Issue**: Flask Application Startup Errors
```bash
# Check for syntax errors
python -m py_compile app.py     # Syntax validation
python -c "import app"          # Import validation

# Check dependencies
pip check                       # Dependency conflicts
pip install --upgrade -r requirements.txt  # Update dependencies
```

#### **Transport Layer Issues**

**Issue**: XSIAM HTTP Delivery Failing
```bash
# Connectivity diagnostics
curl -I $XSIAM_HTTP_ENDPOINT                    # Basic connectivity
curl -v $XSIAM_HTTP_ENDPOINT 2>&1 | grep SSL   # TLS handshake
nslookup $(echo $XSIAM_HTTP_ENDPOINT | cut -d'/' -f3)  # DNS resolution

# Authentication validation
echo "API Key length: $(echo $XSIAM_API_KEY | wc -c)"  # Key format check
curl -H "Authorization: Bearer $XSIAM_API_KEY" -I $XSIAM_HTTP_ENDPOINT

# Resolution steps
export XSIAM_TIMEOUT=60         # Increase timeout
export XSIAM_RETRY_COUNT=3      # Enable retries
export XSIAM_BATCH_SIZE=100     # Reduce batch size
```

**Issue**: Syslog Delivery Not Working
```bash
# Network connectivity tests
nc -u 127.0.0.1 514 <<< "test message"        # UDP test
nc -z 127.0.0.1 514 && echo "Port open"       # TCP port test
ss -tuln | grep :514                          # Check listeners

# Firewall diagnostics
sudo ufw status numbered        # Linux firewall
sudo pfctl -sr | grep 514      # macOS firewall
sudo iptables -L | grep 514    # Linux iptables

# Local syslog service validation
sudo systemctl status rsyslog   # Linux rsyslog status
sudo service syslog status      # Alternative service check
sudo lsof -i :514              # Process using syslog port
```

#### **Performance and Resource Issues**

**Issue**: High Memory Usage
```bash
# Memory profiling
python -m memory_profiler app.py               # Profile memory usage
top -p $(pgrep -f cortex) -o %MEM              # Monitor memory

# Memory optimization
export BATCH_SIZE=500           # Reduce batch size
export WORKER_THREADS=2         # Limit threading
export GC_THRESHOLD=100         # Aggressive garbage collection

# Memory leak detection
valgrind --tool=memcheck python app.py         # Advanced debugging
```

**Issue**: Poor Generation Performance
```bash
# Performance profiling
python -m cProfile -o profile.stats app.py     # Profile execution
python -c "import pstats; pstats.Stats('profile.stats').sort_stats('tottime').print_stats(10)"

# Resource monitoring
htop                            # Interactive process monitor  
iostat -x 1                    # I/O statistics
netstat -i                     # Network interface statistics

# Optimization settings
export WORKERS=4                # Increase workers
export ASYNC_TRANSPORT=true    # Enable async transport
export COMPRESSION=false       # Disable compression for speed
```

#### **XGen Framework Issues**

**Issue**: MITRE Pattern Generation Errors
```bash
# Framework diagnostics
python -c "from xgen.core.burst_generator import BurstGenerator; print('XGen OK')"
python -c "from xgen.ttp.mitre_patterns import list_patterns; print(len(list_patterns()))"

# Pattern validation
python scripts/validate_mitre_patterns.py      # Validate pattern definitions
python demo_xgen.py --pattern=T1021.002        # Test specific pattern

# Debug pattern generation
export XGEN_DEBUG=true
python -c "from xgen.core.burst_generator import BurstGenerator; g=BurstGenerator(seed=42); g.generate_pattern_burst()"
```

### Advanced Debugging Techniques

#### **Network Traffic Analysis**
```bash
# Capture syslog traffic
sudo tcpdump -i lo port 514 -w syslog.pcap     # Capture packets
sudo tcpdump -i lo port 514 -A                 # Real-time ASCII output
wireshark syslog.pcap                          # GUI analysis

# Analyze HTTP traffic
sudo tcpdump -i any -A -s 0 'port 443 and host api'  # HTTPS traffic
curl -w "@curl-format.txt" $XSIAM_HTTP_ENDPOINT      # Detailed timing
```

#### **Application State Debugging**
```bash
# Flask debugging
export FLASK_DEBUG=1
export FLASK_ENV=development
python app.py                   # Debug mode with auto-reload

# Interactive debugging
python -i -c "import app; app.app.run(debug=True, host='0.0.0.0')"

# Thread debugging
python -c "import threading; print(threading.active_count())"  # Thread count
kill -QUIT $(pgrep -f cortex)   # Send SIGQUIT for thread dump
```

### Log Analysis and Patterns

#### **Parsing Application Logs**
```bash
# Extract error patterns
grep -E "ERROR|CRITICAL" logs/cortex-generator.log | tail -20

# Performance metrics extraction
grep "events_generated" logs/cortex-generator.log | awk '{print $NF}' | sort -n

# Transport success rates
grep "transport_" logs/cortex-generator.log | grep -c "success"
grep "transport_" logs/cortex-generator.log | grep -c "failed"
```

#### **System-level Diagnostics**
```bash
# System resource utilization
vmstat 1 5                      # CPU, memory, I/O stats
sar -u 1 5                     # CPU utilization over time
df -h                          # Disk space usage

# Network statistics
ss -tuln                       # Active network connections
netstat -s                     # Protocol statistics

# Process tree analysis
pstree -p $(pgrep -f cortex)   # Process hierarchy
lsof -p $(pgrep -f cortex)     # Open files and connections
```

### Recovery Procedures

#### **Service Recovery**
```bash
# Graceful restart
kill -TERM $(pgrep -f cortex)   # Send termination signal
sleep 5
make run                       # Restart service

# Emergency stop
kill -KILL $(pgrep -f cortex)   # Force kill if needed

# State cleanup
rm -rf /tmp/cortex-*           # Clean temporary files
rm -rf __pycache__/            # Clear Python cache
```

#### **Configuration Reset**
```bash
# Reset to default configuration
git checkout HEAD -- config/   # Reset config files
unset XSIAM_*                  # Clear environment variables
unset WEBHOOK_*

# Dependency refresh
make clean venv install        # Complete rebuild
```

## Vendor Coverage and Competitive Analysis

### Supported Vendors (22+)
- **Endpoint**: Microsoft Defender, CrowdStrike Falcon, SentinelOne EDR
- **Network**: Palo Alto PAN-OS, Cisco ASA, Fortinet FortiGate
- **Secure Web Gateway**: Zscaler NSS (Web/Firewall), ZPA (User Activity/Status/Connector/Audit)
- **Email**: Proofpoint, Mimecast
- **Identity**: Okta, Azure AD, Duo
- **Cloud**: AWS CloudTrail, Azure Logs, GCP Audit

### Competitive Advantages
- **vs CrowdStrike**: Multi-vector correlation (20x faster investigation)
- **vs Splunk**: Purpose-built security focus (80% less configuration)
- **vs Microsoft Sentinel**: Built-in ML analytics vs manual KQL development

See [PRODUCTION_READY_SUMMARY.md](PRODUCTION_READY_SUMMARY.md) for detailed competitive analysis.

## Production Deployment

### System Requirements

#### Minimum Hardware Requirements
- **CPU**: 2 cores, 2.4GHz+ (4 cores recommended for high-volume)
- **Memory**: 4GB RAM (8GB recommended for sustained 10K+ events/min)
- **Storage**: 2GB disk space (additional for logs: ~100MB/day at 1K events/min)
- **Network**: 100Mbps+ for high-throughput scenarios

#### Software Dependencies
- **Python**: 3.9+ (3.11 recommended for performance)
- **Operating System**: Linux (Ubuntu 20.04+), macOS 12+, Windows 10+ with WSL2
- **Network Access**: Outbound to syslog receivers or XSIAM endpoints
- **Optional**: Docker 20.10+ for containerized deployment

### Pre-deployment Checklist

#### **Code Quality and Testing**
- [ ] **Unit Tests**: 80%+ code coverage achieved (`make test`)
- [ ] **Integration Tests**: All transport methods validated
- [ ] **Security Scan**: Zero high/critical vulnerabilities (`make security`)
- [ ] **Performance Baseline**: 10,000+ events/minute sustained load tested
- [ ] **Memory Leak Testing**: 24+ hour continuous operation validated

#### **Log Format Compliance**
- [ ] **Vendor Authenticity**: 98.5%+ compliance rate verified
- [ ] **MITRE Mapping**: 50+ ATT&CK techniques accurately implemented
- [ ] **Format Standards**: CEF/LEEF/JSON/Syslog RFC compliance validated
- [ ] **Field Consistency**: XDM schema alignment for Cortex analytics

#### **Transport Layer Validation**
- [ ] **Syslog Protocols**: UDP/TCP/TLS connectivity tested
- [ ] **XSIAM HTTP**: Authentication and batching verified
- [ ] **Webhook Delivery**: Generic endpoint integration tested
- [ ] **Error Handling**: Connection failures and retry logic validated
- [ ] **Rate Limiting**: Configurable throttling mechanisms tested

#### **Security and Compliance**
- [ ] **Credential Management**: Environment variables for all secrets
- [ ] **Network Security**: TLS 1.2+ for encrypted transports
- [ ] **Access Control**: Principle of least privilege applied
- [ ] **Audit Logging**: Security events logged for compliance
- [ ] **Data Privacy**: No PII in generated logs (synthetic data only)

### Deployment Configurations

#### **Production Environment Setup**
```bash
# Production environment variables
export ENVIRONMENT=production
export LOG_LEVEL=INFO                    # Reduce verbose logging
export WORKERS=4                         # Scale based on CPU cores  
export BATCH_SIZE=1000                   # Optimize for throughput
export CONNECTION_POOL_SIZE=20           # HTTP connection pooling
export ENABLE_METRICS=true               # Enable monitoring

# Security settings
export XSIAM_HTTP_ENDPOINT="https://prod-tenant.xsiam.paloaltonetworks.com/logs/v1/xsiam"
export XSIAM_API_KEY="${XSIAM_PROD_API_KEY}"  # From secure vault
export WEBHOOK_TOKEN="${WEBHOOK_PROD_TOKEN}"

# Performance tuning
export GC_OPTIMIZATION=true              # Garbage collection tuning
export ASYNC_TRANSPORT=true              # Asynchronous transport
export COMPRESSION=true                  # Enable compression
```

#### **Docker Production Deployment**
```yaml
# docker-compose.prod.yml
version: '3.8'
services:
  cortex-generator:
    build: .
    ports:
      - "5001:5001"
    environment:
      - ENVIRONMENT=production
      - LOG_LEVEL=INFO
      - WORKERS=4
    env_file:
      - .env.prod  # Secure environment file
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:5001/health"]
      interval: 30s
      timeout: 10s
      retries: 3
    resources:
      limits:
        cpus: '2.0'
        memory: 4G
      reservations:
        cpus: '1.0'
        memory: 2G
```

### Monitoring and Observability

#### **Key Performance Indicators (KPIs)**
```bash
# Performance metrics to monitor
- Events/second generated: Target 167+ (10K+/minute)
- Memory utilization: <80% of allocated
- CPU utilization: <70% average
- Transport success rate: >99.5%
- Response time: Web UI <2s, API <500ms
- Error rate: <0.1% of generated events
```

#### **Alerting Thresholds**
```yaml
# Example monitoring configuration
alerts:
  high_memory_usage:
    condition: memory_percent > 85
    severity: warning
    
  transport_failure_rate:
    condition: error_rate > 1.0
    severity: critical
    
  low_throughput:
    condition: events_per_second < 100
    severity: warning
    
  service_down:
    condition: health_check_failed
    severity: critical
```

### High Availability and Scaling

#### **Horizontal Scaling**
```bash
# Multiple instance deployment
# Instance 1: Vendor logs 1-10
export GENERATOR_SUBSET="vendors_1_10"
export PORT=5001

# Instance 2: Vendor logs 11-22
export GENERATOR_SUBSET="vendors_11_22"
export PORT=5002

# Load balancer configuration (nginx/HAProxy)
upstream cortex_generators {
    server 127.0.0.1:5001 weight=1;
    server 127.0.0.1:5002 weight=1;
    keepalive 32;
}
```

#### **Failover Configuration**
```bash
# Primary/secondary transport configuration
export XSIAM_PRIMARY_ENDPOINT="https://prod-tenant.xsiam.com/logs/v1/xsiam"
export XSIAM_SECONDARY_ENDPOINT="https://dr-tenant.xsiam.com/logs/v1/xsiam"
export FAILOVER_ENABLED=true
export FAILOVER_TIMEOUT=30
```

### Performance, Reliability, and Safety Guidelines

#### **Rate Limiting and Backpressure Management**

```bash
# Configure rate limiting for safe operation
export RATE_LIMIT_ENABLED=true
export MAX_EVENTS_PER_SECOND=1000        # Global rate limit
export BURST_SIZE=100                    # Maximum burst events
export BACKPRESSURE_THRESHOLD=5000       # Queue size before throttling

# Transport-specific rate limits
export SYSLOG_RATE_LIMIT=500            # Events per second for syslog
export HTTP_RATE_LIMIT=200              # Events per second for HTTP
export WEBHOOK_RATE_LIMIT=100           # Events per second for webhooks

# Circuit breaker configuration
export CIRCUIT_BREAKER_ENABLED=true
export FAILURE_THRESHOLD=10             # Failures before circuit opens
export RECOVERY_TIMEOUT=30              # Seconds before retry
```

#### **Resource Ceilings and Safety Limits**

```bash
# Memory management
export MAX_MEMORY_MB=2048               # Maximum memory usage
export GC_INTERVAL=60                   # Garbage collection interval (seconds)
export MAX_QUEUE_SIZE=10000             # Maximum event queue size

# CPU and threading limits
export MAX_WORKER_THREADS=8             # Limit concurrent workers
export CPU_THRESHOLD=80                 # CPU usage threshold (percentage)
export THREAD_POOL_SIZE=16              # Maximum thread pool size

# File descriptor limits
export MAX_OPEN_FILES=1024              # Maximum file descriptors
export CONNECTION_POOL_SIZE=100         # Maximum concurrent connections

# Disk space management
export MAX_LOG_SIZE_MB=1000             # Maximum log file size
export LOG_RETENTION_DAYS=7             # Log retention period
export MIN_DISK_SPACE_MB=1000           # Minimum required disk space
```

#### **Time Control and Deterministic Testing**

```bash
# Time synchronization and control
export TIME_SYNC_ENABLED=true           # Enable NTP synchronization
export TIME_SKEW_MAX_SECONDS=30         # Maximum acceptable time skew
export CLOCK_SOURCE="system"            # Options: system, ntp, mock

# Deterministic testing with seeds
export RANDOM_SEED=42                   # Fixed seed for reproducible tests
export FAKER_SEED=12345                 # Faker library seed
export NETWORK_SEED=67890               # Network generation seed

# Time replay and simulation
export ENABLE_TIME_REPLAY=false         # Enable historical time simulation
export REPLAY_START_TIME="2025-01-01T00:00:00Z"
export REPLAY_SPEED_MULTIPLIER=1.0      # 1.0 = real-time, 10.0 = 10x speed

# Example: Generate identical datasets
BURST_SEED=42 python demo_xgen.py --apt-group=APT29 --duration=60
# Will always produce same event sequence and timestamps
```

#### **TLS Certificate Management in Development**

```bash
# Development TLS setup
mkdir -p certs/dev

# Generate self-signed certificates for testing
openssl req -x509 -newkey rsa:4096 -keyout certs/dev/key.pem \
  -out certs/dev/cert.pem -days 365 -nodes \
  -subj "/CN=localhost/O=CortexSyslogGenerator/C=US"

# Configure TLS for syslog transport
export SYSLOG_TLS_ENABLED=true
export SYSLOG_TLS_CERT_PATH="./certs/dev/cert.pem"
export SYSLOG_TLS_KEY_PATH="./certs/dev/key.pem"
export SYSLOG_TLS_VERIFY=false          # Disable verification for dev

# Certificate rotation workflow
bash scripts/rotate_dev_certs.sh         # Automated rotation script

# Validate TLS configuration
curl -k https://localhost:6514 --cert certs/dev/cert.pem --key certs/dev/key.pem
```

#### **Production Safety Rules**

⚠️ **Critical Safety Requirements:**

1. **Never Target Production Endpoints**: Always use dedicated test/sandbox environments
   ```bash
   # Safe development endpoints only
   export XSIAM_HTTP_ENDPOINT="https://test-tenant.xsiam.com/logs/v1/xsiam"
   export WEBHOOK_ENDPOINT="https://dev.example.com/webhook"
   export SYSLOG_HOST="dev-syslog.internal.com"
   ```

2. **Rate Limiting Enforcement**: Mandatory rate limits to prevent target overload
   ```bash
   # Enforce conservative limits
   export ENFORCE_RATE_LIMITS=true
   export MAX_SUSTAINED_EPS=100            # Events per second sustained
   export BURST_DURATION_MAX=60           # Maximum burst duration (seconds)
   ```

3. **Resource Monitoring**: Continuous monitoring with automatic shutdowns
   ```bash
   # Resource monitoring thresholds
   export MONITOR_RESOURCES=true
   export SHUTDOWN_ON_HIGH_MEMORY=true    # Auto-shutdown at memory limit
   export SHUTDOWN_ON_HIGH_CPU=true       # Auto-shutdown at CPU limit
   export ALERT_ON_ERROR_RATE=true        # Alert on high error rates
   ```

4. **Graceful Shutdown**: Clean termination procedures
   ```bash
   # Graceful shutdown handling
   trap 'echo "Shutting down gracefully..."; kill -TERM $APP_PID; wait' INT TERM
   python app.py &
   APP_PID=$!
   wait $APP_PID
   ```

5. **Sandbox Tenant Validation**: Verify target environments
   ```bash
   # Validate endpoint safety
   python scripts/validate_endpoint_safety.py --endpoint $XSIAM_HTTP_ENDPOINT
   # Should return: "SAFE: Development/test environment detected"
   ```

#### **Development Safety Checklist**

```bash
# Pre-deployment safety validation
make safety-check                       # Run complete safety validation

# Safety check components:
# ✓ No production endpoints configured
# ✓ Rate limits within safe bounds
# ✓ Resource limits configured
# ✓ TLS certificates are test-only
# ✓ No production API keys in environment
# ✓ Monitoring and alerting enabled
# ✓ Graceful shutdown handlers installed
```

#### **Performance Optimization Guidelines**

```bash
# High-performance configuration
export ENABLE_ASYNC_IO=true             # Enable asynchronous I/O
export USE_CONNECTION_POOLING=true      # HTTP connection pooling
export ENABLE_COMPRESSION=true          # Enable gzip compression
export BATCH_PROCESSING=true            # Enable event batching
export PARALLEL_TRANSPORTS=true         # Parallel transport processing

# Memory optimization
export USE_MEMORY_MAPPING=true          # Memory-mapped files for large datasets
export ENABLE_OBJECT_POOLING=true       # Reuse objects to reduce GC
export OPTIMIZE_JSON_PARSING=true       # Fast JSON parsing

# Network optimization
export TCP_NODELAY=true                 # Disable Nagle's algorithm
export SOCKET_BUFFER_SIZE=65536         # Increase socket buffer size
export HTTP_KEEPALIVE_TIMEOUT=30        # HTTP keep-alive timeout
```

#### **Reliability and Fault Tolerance**

```bash
# Retry and resilience configuration
export ENABLE_RETRIES=true
export MAX_RETRY_ATTEMPTS=3
export RETRY_BACKOFF_MULTIPLIER=2.0
export INITIAL_RETRY_DELAY=1.0

# Health checking
export ENABLE_HEALTH_CHECKS=true
export HEALTH_CHECK_INTERVAL=30
export HEALTH_CHECK_TIMEOUT=10
export HEALTH_CHECK_FAILURE_THRESHOLD=3

# Failover configuration
export ENABLE_FAILOVER=true
export FAILOVER_TIMEOUT=30
export FAILOVER_MAX_ATTEMPTS=2

# Example: Test resilience
python test_fault_tolerance.py --simulate-failures --duration=300
```

### Safety and Operational Guidelines

#### **Operational Procedures**
```bash
# Deployment procedure
1. Deploy to staging environment
2. Run full test suite: `make regression-test`
3. Performance validation: `python test_performance_baseline.py`
4. Security scan: `make security`
5. Blue/green deployment to production
6. Monitor KPIs for 24 hours
7. Rollback procedure if issues detected

# Maintenance procedures
1. Schedule maintenance windows during low usage
2. Implement graceful shutdown: `kill -TERM $(pgrep -f cortex)`
3. Backup current state and configurations
4. Apply updates/patches
5. Run smoke tests before full service restoration
6. Monitor post-maintenance performance
```

### Disaster Recovery

#### **Backup Strategies**
```bash
# Configuration backup
tar -czf backup-$(date +%Y%m%d).tar.gz \
  app.py requirements.txt Makefile \
  src/ scripts/ logs/

# Environment backup
env | grep -E "(XSIAM|WEBHOOK|CORTEX)" > env-backup-$(date +%Y%m%d).txt
```

#### **Recovery Procedures**
1. **Service Recovery**: Automated restart procedures with health checks
2. **Configuration Recovery**: Version-controlled configuration restoration
3. **Data Recovery**: Regenerate synthetic data (no permanent data loss risk)
4. **Transport Recovery**: Automatic failover to secondary endpoints

### Compliance and Documentation

#### **Production Documentation Requirements**
- [ ] **Architecture Diagrams**: Current deployment architecture
- [ ] **Runbooks**: Operational procedures and troubleshooting guides
- [ ] **Change Logs**: Version history and feature changes
- [ ] **Security Documentation**: Security controls and compliance evidence
- [ ] **Performance Baselines**: Historical performance metrics and trends

## CI/CD and Releases

### CI/CD Pipeline Architecture

#### GitHub Actions Workflow

```yaml
# .github/workflows/ci.yml (example structure)
name: Cortex Syslog Generator CI/CD

on:
  push:
    branches: [ main, develop, 'release/*' ]
  pull_request:
    branches: [ main ]
  release:
    types: [ published ]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: [3.9, 3.10, 3.11, 3.12]
    
    steps:
    - uses: actions/checkout@v4
    - name: Set up Python ${{ matrix.python-version }}
      uses: actions/setup-python@v4
      with:
        python-version: ${{ matrix.python-version }}
    
    - name: Install dependencies
      run: |
        make venv install
    
    - name: Run quality checks
      run: |
        make quality
    
    - name: Run tests with coverage
      run: |
        make test
    
    - name: Upload coverage reports
      uses: codecov/codecov-action@v3

  security:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - name: Run security analysis
      run: |
        make security
    
    - name: Run dependency check
      run: |
        pip-audit --desc --format=json

  docker:
    runs-on: ubuntu-latest
    needs: [test, security]
    if: github.ref == 'refs/heads/main' || startsWith(github.ref, 'refs/tags/')
    
    steps:
    - uses: actions/checkout@v4
    - name: Build Docker image
      run: |
        docker build -t cortex-syslog-generator:${{ github.sha }} .
    
    - name: Run container tests
      run: |
        docker run --rm cortex-syslog-generator:${{ github.sha }} python -c "import app; print('Container OK')"
    
    - name: Push to registry (on release)
      if: startsWith(github.ref, 'refs/tags/')
      run: |
        echo ${{ secrets.DOCKER_PASSWORD }} | docker login -u ${{ secrets.DOCKER_USERNAME }} --password-stdin
        docker tag cortex-syslog-generator:${{ github.sha }} paloaltonetworks/cortex-syslog-generator:${{ github.ref_name }}
        docker tag cortex-syslog-generator:${{ github.sha }} paloaltonetworks/cortex-syslog-generator:latest
        docker push paloaltonetworks/cortex-syslog-generator:${{ github.ref_name }}
        docker push paloaltonetworks/cortex-syslog-generator:latest
```

#### Local CI Reproduction

```bash
# Reproduce CI pipeline locally
make ci-local                           # Run full CI pipeline

# Individual CI steps
make lint type-check security test      # Quality gates
make test-integration                   # Integration tests
make test-performance                   # Performance benchmarks
make docker-build docker-test          # Container validation

# Multi-Python version testing (using pyenv)
pyenv install 3.9.18 3.10.13 3.11.7 3.12.1
for version in 3.9.18 3.10.13 3.11.7 3.12.1; do
  pyenv local $version
  make venv install test
done

# Security and dependency scanning
make security                          # Bandit security analysis
pip-audit --desc                      # Dependency vulnerability scan
safety check                          # Additional security check
```

### Versioning Strategy

#### Semantic Versioning (SemVer)

We follow strict [Semantic Versioning 2.0.0](https://semver.org/):

```bash
# Version format: MAJOR.MINOR.PATCH
# Examples:
# 2.1.0 - Minor feature release
# 2.1.1 - Patch/bug fix release
# 3.0.0 - Major breaking change release

# Version sources (in precedence order):
# 1. pyproject.toml - Authoritative version
# 2. Git tags - Release markers
# 3. VERSION file - Optional backup

# Check current version
python -c "import importlib.metadata; print(importlib.metadata.version('cortex-syslog-generator'))"
grep '^version' pyproject.toml
git describe --tags --always
```

#### Version Bump Workflow

```bash
# Automated version bumping
pip install bump2version  # Version management tool

# Patch release (2.1.0 -> 2.1.1)
bump2version patch

# Minor release (2.1.1 -> 2.2.0)
bump2version minor

# Major release (2.2.0 -> 3.0.0)
bump2version major

# Pre-release versions
bump2version --tag --new-version 2.2.0-rc.1 prerelease

# Manual version update
vim pyproject.toml  # Update version = "x.y.z"
git add pyproject.toml
git commit -m "chore: bump version to x.y.z"
git tag -a v/x.y.z -m "Release version x.y.z"
git push origin main --tags
```

### Release Process

#### Release Checklist

```bash
# Pre-release validation
- [ ] All tests passing on main branch
- [ ] Documentation updated (README, CHANGELOG)
- [ ] Version bumped in pyproject.toml
- [ ] Security scan completed (no HIGH/CRITICAL issues)
- [ ] Performance benchmarks validated
- [ ] Docker image builds successfully
- [ ] Release notes prepared

# Release execution
1. git checkout main
2. git pull origin main
3. bump2version [patch|minor|major]
4. git push origin main --tags
5. Create GitHub release with notes
6. Verify Docker image publication
7. Update documentation links
```

#### Automated Release Creation

```bash
# Using GitHub CLI for release automation
gh release create v2.1.0 \
  --title "Release v2.1.0 - Enhanced Zscaler Support" \
  --notes-file RELEASE_NOTES.md \
  --latest \
  --discussion-category "General"

# Release artifacts to include:
# - Source code (automatic)
# - Docker image (automatic via CI)
# - Binary distributions (if applicable)
# - SHA256 checksums
# - GPG signatures (for security)
```

### Release Artifacts and Distribution

#### Container Registry

```bash
# Docker Hub releases (automated)
https://hub.docker.com/r/paloaltonetworks/cortex-syslog-generator

# Pull production image
docker pull paloaltonetworks/cortex-syslog-generator:latest
docker pull paloaltonetworks/cortex-syslog-generator:v2.1.0

# Multi-architecture builds
docker buildx build --platform linux/amd64,linux/arm64 \
  -t paloaltonetworks/cortex-syslog-generator:v2.1.0 .
```

#### PyPI Distribution (Future)

```bash
# Python package distribution (when available)
pip install cortex-syslog-generator==2.1.0

# Development/pre-release versions
pip install --pre cortex-syslog-generator

# Installation with all extras
pip install 'cortex-syslog-generator[dev,docs,performance]'
```

### Changelog and Release Notes

#### Changelog Format

```markdown
# Changelog

## [2.1.0] - 2025-01-15

### Added
- Zscaler ZPA User Activity log generator with LEEF format
- Custom CSV ingestion with automatic vendor mapping
- XGen APT29 campaign scenarios with enhanced attribution
- TLS syslog transport support (RFC 5425)
- Performance optimization for high-volume generation

### Changed
- Updated MITRE ATT&CK pattern library to v14.1
- Improved Cortex XSIAM HTTP transport batching
- Enhanced error handling and retry mechanisms
- Optimized memory usage for sustained generation

### Fixed
- Resolved memory leak in burst generation engine
- Fixed timestamp alignment in multi-transport scenarios
- Corrected CEF field mapping for network events
- Fixed Docker container startup on ARM64 platforms

### Security
- Updated dependencies to address CVE-2024-XXXX
- Enhanced input validation for CSV ingestion
- Improved secret handling in environment variables

### Deprecated
- Legacy Flask generator functions (use XGen framework)
- Direct database connections (use file-based fixtures)

## [2.0.1] - 2024-12-20

### Fixed
- Critical fix for syslog UDP transport connection handling
- Resolved compatibility issue with Python 3.12
```

#### Release Notes Template

```markdown
# Release Notes - v2.1.0 🚀

## 🎯 Highlights

- **Enhanced Zscaler Support**: Complete ZPA User Activity generators
- **Performance Improvements**: 40% faster event generation
- **Security Updates**: All dependencies updated, zero vulnerabilities

## 📈 Performance Benchmarks

- Events/second: 12,000+ (was 8,500+) - 40% improvement
- Memory usage: <80MB sustained (was 120MB) - 33% reduction
- Startup time: <3 seconds (was 5 seconds) - 40% faster

## 🔧 Breaking Changes

- Minimum Python version increased to 3.9
- Legacy generator functions deprecated (migration guide below)
- Docker base image updated to Python 3.11-slim

## 📚 Migration Guide

### Upgrading from v2.0.x

```bash
# Update Python virtual environment
make clean venv install

# Update Docker deployments
docker pull paloaltonetworks/cortex-syslog-generator:v2.1.0

# Configuration changes (none required)
```

## 🐛 Known Issues

- Windows: PowerShell execution policy may block scripts
- macOS: ARM64 performance optimization in progress
- Docker: Health check timeout increased to 30s

## 👥 Contributors

- @contributor1 - Zscaler generator implementation
- @contributor2 - Performance optimization
- @contributor3 - Documentation updates
```

### Branch and Tag Strategy

#### Git Flow Model

```bash
# Main branches
main           # Production-ready code
develop        # Integration branch for features

# Supporting branches
feature/*      # New features (from develop)
release/*      # Release preparation (from develop)
hotfix/*       # Critical fixes (from main)

# Tag naming convention
v2.1.0         # Release tags
v2.1.0-rc.1    # Release candidates
v2.1.0-beta.1  # Beta releases
```

#### Release Branch Workflow

```bash
# Create release branch
git checkout develop
git pull origin develop
git checkout -b release/v2.1.0

# Finalize release
vim pyproject.toml        # Update version
vim CHANGELOG.md          # Add release notes
make quality test         # Final validation

# Merge to main and tag
git checkout main
git merge --no-ff release/v2.1.0
git tag -a v2.1.0 -m "Release version 2.1.0"
git push origin main --tags

# Merge back to develop
git checkout develop
git merge --no-ff release/v2.1.0
git branch -d release/v2.1.0
```

### Firebase Deployment

**N/A** - This repository does not use Firebase or GCP Cloud Functions. All deployment is via traditional hosting, Docker containers, or direct Python execution. For cloud deployment, use standard containerization with Docker and orchestration platforms like Kubernetes, Docker Compose, or cloud container services.

## Appendix

### Key Files Reference

#### **Core Application Files**
- `app.py` - Main Flask web application and legacy log generators
- `Makefile` - Cross-platform development automation (Windows/macOS/Linux)
- `pyproject.toml` - Python project configuration and dependencies
- `requirements.txt` - Production Python dependencies
- `requirements-dev.txt` - Development dependencies (if exists)
- `Dockerfile` - Multi-stage container build configuration
- `.pre-commit-config.yaml` - Pre-commit hooks configuration

#### **XGen Framework Structure**
- `src/xgen/core/burst_generator.py` - Main event generation engine
- `src/xgen/core/models.py` - Core data models (Actor, Asset, NetworkTuple, etc.)
- `src/xgen/integration/app_integration.py` - Flask-XGen bridge with threading
- `src/xgen/ttp/mitre_patterns.py` - MITRE ATT&CK pattern definitions
- `src/xgen/transports/adapters.py` - Multi-protocol transport adapters
- `src/xgen/formats/renderers.py` - CEF/LEEF/JSON formatting
- `src/xgen/vendors/` - Vendor-specific log generators
- `src/xgen/catalog/vendor_catalog.py` - Vendor metadata and mappings

#### **Demonstration and Testing Scripts**
- `demo_xgen.py` - XGen framework demonstration
- `demo_cortex_scenarios.py` - Cortex XDR integration scenarios
- `demo_enhanced_features.py` - Enhanced generation features
- `demo_zscaler_logs.py` - Zscaler log generator testing
- `test_cortex_generation.py` - Cortex integration tests
- `test_enhanced_system.py` - Enhanced system validation
- `test_log_authenticity.py` - Log format compliance validation
- `test_zscaler_standalone.py` - Zscaler standalone testing

#### **Configuration and Documentation**
- `WARP.md` - This comprehensive developer guide
- `README.md` - User-facing setup and usage guide
- `IMPLEMENTATION_SUMMARY.md` - Technical implementation details
- `VENDOR_PRODUCT_INDEX.md` - Complete vendor coverage list
- `PRODUCTION_READY_SUMMARY.md` - Production deployment guide
- `cortex_xdr_integration_guide.md` - XDR-specific configuration
- `cortex_marketplace_data_modeling_guide.md` - Data modeling guidelines
- `ZSCALER_LOG_EXAMPLES.md` - Zscaler log format examples

#### **Sample Data and Validation**
- `sample_logs/validation_report.json` - Log authenticity validation results
- `examples/apt29_scenario.yaml` - APT29 campaign configuration example
- `src/scenarios/` - Pre-built attack scenarios
- `src/xgen/validation/cortex_compliance.py` - Cortex schema validation

### Documentation Links

#### **Project Documentation**
- [README.md](README.md) - Comprehensive setup and usage guide
- [IMPLEMENTATION_SUMMARY.md](IMPLEMENTATION_SUMMARY.md) - Technical implementation details
- [VENDOR_PRODUCT_INDEX.md](VENDOR_PRODUCT_INDEX.md) - Complete vendor coverage list
- [Cortex Integration Guide](cortex_xdr_integration_guide.md) - XDR-specific configuration
- [Cortex Marketplace Guide](cortex_marketplace_data_modeling_guide.md) - Data modeling
- [Production Deployment Guide](PRODUCTION_READY_SUMMARY.md) - Enterprise deployment
- [Zscaler Log Examples](ZSCALER_LOG_EXAMPLES.md) - Zscaler format reference

#### **External References**
- [MITRE ATT&CK Framework](https://attack.mitre.org/) - Attack technique reference
- [Common Event Format (CEF) Specification](https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-8.3/cef-implementation-standard/) - CEF format standard
- [Log Event Extended Format (LEEF) Guide](https://www.ibm.com/docs/en/dsm?topic=overview-leef-format) - LEEF format standard
- [RFC 3164 - Syslog Protocol](https://tools.ietf.org/html/rfc3164) - Traditional syslog standard
- [RFC 5424 - Syslog Protocol](https://tools.ietf.org/html/rfc5424) - Modern syslog standard
- [Cortex XSIAM Documentation](https://docs.paloaltonetworks.com/cortex/cortex-xsiam) - Official Cortex docs
- [Palo Alto Networks GitHub](https://github.com/PaloAltoNetworks) - Open source projects

### Technology Stack Dependencies

#### **Core Runtime Requirements**
- **Python**: 3.9+ (3.11 recommended for performance)
- **Operating Systems**: 
  - Linux: Ubuntu 20.04+, CentOS 8+, RHEL 8+
  - macOS: 12+ (Monterey)
  - Windows: 10+ with WSL2 or native PowerShell
- **Memory**: 4GB RAM minimum (8GB recommended for high-volume)
- **Storage**: 2GB disk space + logs (100MB/day at 1K events/min)
- **Network**: Outbound access to target endpoints (syslog/HTTP)

#### **Development Dependencies**
- **Git**: Version control and collaboration
- **Docker**: 20.10+ for containerized deployment (optional)
- **Build Tools**: 
  - Linux: `build-essential`, `python3-dev`
  - macOS: Xcode Command Line Tools
  - Windows: Visual Studio Build Tools (optional)

#### **Python Package Ecosystem**
- **Web Framework**: Flask 2.3+, Jinja2 templates
- **CLI Framework**: Typer with Click foundation
- **Data Generation**: Faker, NumPy, Pandas for realistic data
- **Network/HTTP**: Requests, HTTPX, AIOHttp for transport
- **Serialization**: PyYAML, OrJSON for performance
- **Development Tools**: Ruff, Black, MyPy, Pytest, Pre-commit
- **Security**: Bandit for security analysis

#### **Optional Infrastructure Dependencies**
- **Local Syslog Daemon**: `rsyslog`, `syslog-ng` for testing
- **Container Orchestration**: Docker Compose, Kubernetes
- **Load Testing**: Artillery, Apache Bench for performance testing
- **Monitoring**: Prometheus, Grafana for metrics (if implemented)

### Glossary

#### **Core Concepts**
- **APT (Advanced Persistent Threat)**: Nation-state or sophisticated threat actors
- **Burst Generation**: Coordinated event sequences that trigger analytics
- **CEF (Common Event Format)**: Industry-standard log format for SIEM systems
- **Cortex XSIAM**: Palo Alto Networks' cloud-native SIEM platform
- **CVE**: Common Vulnerabilities and Exposures identifier
- **LEEF (Log Event Extended Format)**: IBM's structured log format
- **MITRE ATT&CK**: Framework for categorizing adversary tactics and techniques
- **Network 5-tuple**: Source IP, destination IP, source port, destination port, protocol
- **NICE Framework**: NIST cybersecurity workforce framework categories
- **Syslog**: Standard protocol for message logging (RFC 3164/5424)
- **TTP (Tactics, Techniques, Procedures)**: Adversary behavior patterns
- **XDM (eXtended Data Model)**: Cortex XSIAM's normalized data schema
- **XGen Framework**: Modern burst generation engine for coordinated events

#### **Vendor and Product Terms**
- **EDR (Endpoint Detection and Response)**: Endpoint security monitoring
- **NGFW (Next-Generation Firewall)**: Advanced firewall with deep inspection
- **SIEM (Security Information and Event Management)**: Security data aggregation
- **SOAR (Security Orchestration, Automation, Response)**: Security workflow automation
- **SOC (Security Operations Center)**: Centralized security monitoring facility
- **SWG (Secure Web Gateway)**: Web traffic security filtering
- **UEBA (User and Entity Behavior Analytics)**: Behavioral anomaly detection
- **XDR (Extended Detection and Response)**: Integrated security platform

#### **Technical Terms**
- **Backpressure**: Flow control mechanism to prevent system overload
- **Circuit Breaker**: Fault tolerance pattern for preventing cascade failures
- **Event Correlation**: Linking related security events across time and systems
- **False Positive**: Legitimate activity incorrectly flagged as malicious
- **Indicator of Compromise (IoC)**: Artifacts that suggest malicious activity
- **Lateral Movement**: Adversary movement within compromised networks
- **Rate Limiting**: Controlling the frequency of events or requests
- **Threat Hunting**: Proactive search for threats within an environment
- **Time-to-Detection (TTD)**: Time between attack start and detection
- **Zero-Day**: Previously unknown vulnerability or attack technique

### Contact and Support

#### **Community and Contributions**
- **GitHub Repository**: [cortex-syslog-generator](https://github.com/PaloAltoNetworks/cortex-syslog-generator)
- **Issues and Bug Reports**: GitHub Issues tracker
- **Feature Requests**: GitHub Discussions
- **Community Contributions**: Fork, enhance, and submit pull requests

#### **Enterprise Support**
- **Professional Services**: Contact Palo Alto Networks representative
- **Technical Support**: Cortex support channels for licensed customers
- **Training and Certification**: Palo Alto Networks Education Services
- **Partner Ecosystem**: Solution partner integrations and support

#### **Security and Vulnerability Reporting**
- **Security Issues**: Follow responsible disclosure to security@paloaltonetworks.com
- **CVE Coordination**: Work with PSIRT (Product Security Incident Response Team)
- **Vulnerability Scanning**: Regular automated scanning with Bandit and pip-audit

---

### Quick Reference Card

```bash
# Essential Commands Reference Card

# 🚀 Quick Start
make venv install run              # One-command setup and launch
docker build -t cortex . && docker run -p 5001:5001 cortex

# 🧪 Testing
make test                          # Full test suite with coverage
make test-fast                     # Quick smoke tests
make quality                       # All quality checks (lint/type/security)

# 🔧 Development
make lint format                   # Code formatting and linting
make pre-commit                    # Setup git hooks
make demo                          # Interactive demonstration

# 📊 Monitoring
curl http://localhost:5001/health  # Health check
htop                               # Resource monitoring
tail -f logs/cortex-generator.log  # Application logs

# 🔒 Security
export XSIAM_HTTP_ENDPOINT="https://test-tenant.xsiam.com/logs/v1/xsiam"
export XSIAM_API_KEY="${XSIAM_API_KEY}"  # Never hardcode secrets
make security                      # Security analysis
```

**🛡️ Built with ❤️ by the Palo Alto Networks Cortex Team**

*Empowering Security Operations with Authentic Attack Simulation*
