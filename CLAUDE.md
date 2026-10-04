# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

The **Cortex Syslog Generator** is a production-ready enterprise security log generator designed for Cortex XSIAM validation, SOC training, and competitive analysis. It generates realistic attack sequences mapped to MITRE ATT&CK with authentic log formats from 22+ enterprise security vendors.

**Key Capabilities:**
- Multi-vendor log generation (CrowdStrike, Microsoft Defender, Palo Alto Networks, AWS CloudTrail, etc.)
- MITRE ATT&CK-aligned attack scenarios (50+ techniques across all tactics)
- Multiple transport protocols (Syslog UDP/TCP/TLS, Cortex XSIAM HTTP, Generic Webhooks)
- CSV ingestion for third-party logs
- Real-time burst generation with timing control
- Web UI (Flask) and CLI interfaces

## Quick Start

**One-line setup and run:**
```bash
make venv install run
```

This creates the virtual environment, installs dependencies, and starts the web UI on http://localhost:5001

## Essential Commands

```bash
make run           # Start web UI (localhost:5001)
make test          # Run tests
make format        # Auto-format code (black + ruff)
make quality       # Run all checks (lint + type + security + tests)
```

**Other useful commands:** `make demo`, `make demo-cortex`, `make docker-build`

## Architecture

### Core Data Models (`src/xgen/core/models.py`)

The system is built around **Pydantic models** aligned with the **NICE Cybersecurity Framework** and **MITRE ATT&CK**:

1. **NICECategory** - Four security domains:
   - `NETWORK` - Firewalls, proxies, network devices
   - `IDENTITY` - Authentication, SSO, IAM systems
   - `CLOUD` - AWS CloudTrail, Azure, GCP audit logs
   - `ENDPOINT` - EDR, antivirus, host-based events

2. **BaseEvent** - Root event model with:
   - Core identifiers (event_id, timestamp, scenario_id)
   - Pattern correlation (pattern_id, burst_id, sequence_number)
   - Vendor/product metadata
   - Network 5-tuple (NetworkTuple) for analytics
   - Actor and Asset relationships
   - MITRE ATT&CK mapping (TacticTechnique)

3. **Specialized Events** - Category-specific models:
   - `NetworkEvent` - Firewall rules, connections, bytes/packets
   - `IdentityEvent` - Authentication, MFA, sessions
   - `CloudEvent` - API calls, resource operations
   - `EndpointEvent` - Process execution, file operations, registry

4. **HeuristicPattern** - Behavioral detection patterns with:
   - Event count thresholds and time windows
   - Network signatures and port sequences
   - Behavioral indicators (escalation, lateral movement, persistence)

### Burst Generation System (`src/xgen/core/burst_generator.py`)

The **BurstGenerator** creates temporally-correlated event sequences that mimic real attack patterns:

- **Pattern-based bursts**: Generate events matching specific MITRE techniques
- **APT campaigns**: Multi-stage attack scenarios (APT29, APT28, Lazarus, etc.)
- **Timing control**: Events respect realistic temporal relationships
- **Multi-vendor coordination**: Generate correlated logs across multiple products

### Transport Layer (`src/xgen/transports/adapters.py`)

**Transport adapters** handle log delivery with format optimization:

1. **SyslogUDPAdapter** - Default syslog delivery (RFC 3164 compatible)
   - Best for: Broker VMs, traditional SIEM ingestion

2. **SyslogTCPAdapter** - Reliable syslog with reconnection
   - Supports TLS for encrypted delivery

3. **XSIAMHTTPAdapter** - Native Cortex XSIAM integration
   - Maps BaseEvent fields to XDM schema
   - Includes MITRE ATT&CK, actor, asset, and network 5-tuple
   - Batching (1000 events/batch), compression, and retry logic

4. **WebhookAdapter** - Generic HTTP POST with flexible auth
   - Bearer token, basic auth, or API key
   - Configurable headers and retry

**Key Pattern**: Each transport gets **format-optimized logs** via `src/xgen/catalog/transport_mapping.py`:
```python
from src.xgen.catalog.transport_mapping import get_optimal_format

# Returns optimal format based on vendor, NICE category, and transport type
optimal_fmt = get_optimal_format(
    vendor="CrowdStrike",
    nice_category=NICECategory.ENDPOINT,
    transport_type=TransportType.XSIAM_HTTP
)
# Returns: LogFormat.JSON (for XSIAM HTTP)
```

### Format Renderers (`src/xgen/formats/renderers.py`)

The `render_events()` function converts BaseEvent objects to formatted strings:
- **CEF (Common Event Format)** - Industry standard for SIEMs
- **JSON** - Structured logs for modern systems
- **LEEF (Log Event Extended Format)** - IBM QRadar format
- **Syslog** - Plain text with syslog headers

### MITRE ATT&CK Patterns (`src/xgen/ttp/mitre_patterns.py`)

Pre-built attack patterns organized by:
- **ENTERPRISE_PERSISTENCE_PATTERNS** - T1543.003 (Windows Service), T1547.001 (Registry Run Keys)
- **CLOUD_PERSISTENCE_PATTERNS** - T1098.001 (Cloud Credential Manipulation)
- **LATERAL_MOVEMENT_PATTERNS** - T1021.002 (SMB), T1021.001 (RDP)
- **PRIVILEGE_ESCALATION_PATTERNS** - T1134.001 (Token Impersonation)

**APT Group Campaigns**:
- `APTGroup.APT29` - Cloud credential manipulation + enterprise persistence
- `APTGroup.APT28` - Enterprise lateral movement focus
- `APTGroup.LAZARUS` - Registry persistence + mobile techniques
- `APTGroup.VOLT_TYPHOON` - Cloud credentials + living-off-the-land

### Flask Integration (`src/xgen/integration/app_integration.py`)

The `XGenSession` class bridges the burst generation engine with Flask:

**Key Methods**:
- `start_burst_session(config)` - Starts threaded generation
- `pause_resume()` - Toggle pause state
- `stop()` - Stop current session
- `get_events_for_streaming()` - Get queued events for server-sent events (SSE)

**Session Modes**:
1. `apt_campaign` - Full APT group campaign with duration/intensity
2. `pattern_burst` - Single MITRE technique pattern
3. `custom_csv` - CSV ingestion with NICE categorization
4. `enhanced_random` - Random generation with optional burst injection

### Vendor Catalog (`src/xgen/catalog/vendor_catalog.py`)

Maps vendors/products to NICE categories for CSV ingestion:
```python
from src.xgen.catalog.vendor_catalog import get_nice_category

category = get_nice_category("CrowdStrike", "Falcon")
# Returns: NICECategory.ENDPOINT
```

**Supported Vendor Groups**:
- **Network**: Cisco, Palo Alto Networks, Zscaler, Proofpoint
- **Identity**: Okta, Duo, Azure AD, OneLogin, PingOne
- **Cloud**: AWS, Azure, GCP, Kubernetes, Microsoft 365
- **Endpoint**: Microsoft Defender, CrowdStrike, SentinelOne, Windows

### CSV Ingestion (`src/xgen/custom/csv_ingest.py`)

Import third-party logs from CSV files:

**Required Columns**: `timestamp`, `vendor`, `product`, `severity`, `event_name`, `message`

**Optional Columns**: `username`, `src_ip`, `src_port`, `dst_ip`, `dst_port`, `protocol`

**Usage**:
```python
from src.xgen.custom.csv_ingest import events_from_csv

events = events_from_csv(
    csv_path="logs.csv",
    default_vendor="Cisco",
    default_product="ASA"
)
# Returns: List[BaseEvent] with auto-assigned NICE categories
```

## Configuration

### Environment Variables

**Cortex XSIAM HTTP**:
```bash
export XSIAM_HTTP_ENDPOINT="https://api-{tenant}/logs/v1/xsiam"
export XSIAM_API_KEY="your-api-key"
export XSIAM_API_KEY_ID="key-id"         # Optional
export XSIAM_TENANT_ID="tenant-id"       # Optional
```

**Generic Webhook/HTTP**:
```bash
export WEBHOOK_ENDPOINT="https://example.com/webhook"
export WEBHOOK_TOKEN="bearer-token"
```

**Syslog Configuration**: Set via web UI or config dict (dest_ip, dest_port)

### Transport Toggles

The web UI and API support per-request transport toggles:
- `enable_syslog` - Enable/disable syslog UDP delivery (default: true)
- `enable_xsiam_http` - Enable/disable XSIAM HTTP (default: true if env vars set)
- `enable_webhook` - Enable/disable webhook (default: true if endpoint configured)

**Per-request HTTP overrides**:
- `http_endpoint` - Override WEBHOOK_ENDPOINT for this run
- `http_token` - Override WEBHOOK_TOKEN for this run

## Key Workflows

### Adding a New Vendor

1. Define vendor in `src/xgen/vendors/` (e.g., `new_vendor.py`)
2. Register in `src/xgen/catalog/vendor_catalog.py` under appropriate NICE category
3. Add log generation logic following existing vendor patterns
4. Update `VENDOR_PRODUCT_INDEX.md` with competitive analysis

### Creating a New Attack Pattern

1. Define pattern in `src/xgen/ttp/mitre_patterns.py`:
```python
NEW_PATTERN = HeuristicPattern(
    pattern_id="ATTACK_PATTERN_NAME",
    pattern_name="Human-readable name",
    description="What this pattern detects",
    min_events=5,
    time_window_seconds=300.0,
    network_signatures=[{"dest_port": 445, "protocol": "TCP"}]
)
```

2. Add to appropriate category dict (ENTERPRISE_PERSISTENCE_PATTERNS, etc.)
3. Test with `demo_cortex_scenarios.py` or web UI

### Adding a New Transport

1. Create adapter class in `src/xgen/transports/adapters.py`:
```python
class NewTransportAdapter(TransportAdapter):
    def send(self, events: List[BaseEvent], formatted_logs: List[str]) -> bool:
        # Implementation
        pass

    def close(self):
        # Cleanup
        pass
```

2. Register in `create_transport_adapter()` factory function
3. Add to `TransportType` enum in `src/xgen/core/models.py`

## Testing Strategy

- **Unit tests**: Test individual components in isolation
- **Integration tests**: Test transport adapters with mock endpoints
- **Scenario tests**: Validate full attack scenarios generate expected patterns
- **Log authenticity tests**: Verify generated logs match vendor formats

**Run specific test files**:
```bash
pytest test_cortex_generation.py -v
pytest test_zscaler_standalone.py -v
pytest test_log_authenticity.py -v
```

## Code Patterns

### Creating Events Programmatically

```python
from src.xgen.core.burst_generator import BurstGenerator
from src.xgen.ttp.mitre_patterns import get_pattern_by_id

generator = BurstGenerator()

# Generate pattern burst
pattern = get_pattern_by_id("T1543_003_WINDOWS_SERVICE")
events = generator.generate_pattern_burst(
    pattern=pattern,
    scenario_id=uuid4()
)

# Generate APT campaign
events = generator.generate_apt_campaign(
    apt_group="APT29",
    duration_hours=1.0,
    intensity="medium"
)
```

### Sending Events to Multiple Transports

```python
from src.xgen.transports.adapters import create_transport_adapter
from src.xgen.formats.renderers import render_events
from src.xgen.core.models import TransportType, LogFormat

# Create transports
syslog = create_transport_adapter(TransportType.SYSLOG_UDP, {
    "host": "127.0.0.1",
    "port": 514
})

xsiam = create_transport_adapter(TransportType.XSIAM_HTTP, {
    "endpoint": "https://api.example.com/logs",
    "api_key": "key123"
})

# Render and send
cef_logs = render_events(events, LogFormat.CEF)
syslog.send(events, cef_logs)

json_logs = render_events(events, LogFormat.JSON)
xsiam.send(events, json_logs)
```

## Important Notes

- **Platform Support**: Makefile detects OS (macOS, Linux, Windows) and adjusts commands
- **Virtual Environment**: Always work within `.venv` (created by `make venv`)
- **Python Version**: Requires Python 3.9+ (specified in pyproject.toml)
- **Git Workflow**: Main branch is `main` (use this for PRs)
- **Log Format Optimization**: Transports automatically receive optimal format based on vendor/category
- **Thread Safety**: XGenSession uses threading.Lock for queue operations
- **Timestamp Handling**: All timestamps are UTC (validated in BaseEvent)

## Documentation Files

- `README.md` - Installation, usage, and feature overview
- `WARP.md` - Cloudflare WARP log generation specifics
- `VENDOR_PRODUCT_INDEX.md` - Complete vendor catalog with competitive analysis
- `IMPLEMENTATION_SUMMARY.md` - Feature implementation details
- `PRODUCTION_READY_SUMMARY.md` - Production deployment guidelines
- `cortex_marketplace_data_modeling_guide.md` - Data modeling for Cortex marketplace
- `cortex_xdr_integration_guide.md` - XDR integration instructions
- `ZSCALER_LOG_EXAMPLES.md` - Zscaler log format examples

## Common Tasks

### Run the web UI and test log generation
```bash
make venv install
make run
# Open http://localhost:5001
# Select vendors, configure transports, click "Start Generation"
```

### Generate CSV from custom logs and send to syslog
```bash
# Prepare CSV with columns: timestamp, vendor, product, severity, event_name, message
make run
# In UI: Enter CSV path, set syslog IP, click "Start Generation"
```

### Test XSIAM HTTP delivery
```bash
export XSIAM_HTTP_ENDPOINT="https://api-yourtenant.xdr.us.paloaltonetworks.com/logs/v1/xsiam"
export XSIAM_API_KEY="your-key"
make run
# Enable XSIAM HTTP toggle in UI
```

### Run APT campaign from CLI
```python
python demo_unit42_scenarios.py
# Follow prompts to select APT group and duration
```
