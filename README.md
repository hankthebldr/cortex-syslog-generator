# Cortex Syslog/Log Generator (Security Analytics Simulator)

A modular, NICE-aligned log generation and ingestion simulator designed for Cortex XSIAM validation and SOC training. It generates realistic attack sequences mapped to MITRE ATT&CK, supports ingestion of third‑party logs (CSV), and delivers logs via Syslog (UDP/TCP/TLS) and HTTP POST (XSIAM HTTP endpoint or generic webhooks).

## Quick Start (Mac, zsh)

- Create and activate virtualenv
  - make venv
  - source .activate
- Run the GUI (localhost:5001)
  - make run
- Optional: Run the interactive demo in terminal
  - make demo

## Environment Variables (Transports)

Set these in your shell before running the app when you want to enable HTTP delivery:

- Cortex XSIAM HTTP (preferred)
  - export XSIAM_HTTP_ENDPOINT="https://api-yourtenant/logs/v1/xsiam"
  - export XSIAM_API_KEY="${XSIAM_API_KEY}"
  - Optional:
    - export XSIAM_API_KEY_ID="${XSIAM_API_KEY_ID}"
    - export XSIAM_TENANT_ID="${XSIAM_TENANT_ID}"

- Generic Webhook/HTTP
  - export WEBHOOK_ENDPOINT="https://example/webhook"
  - export WEBHOOK_TOKEN="${WEBHOOK_TOKEN}"

Notes:
- Replace ${…} placeholders with your real values.
- The GUI also allows per-run HTTP overrides (endpoint and token) without touching env vars.

## What’s in the GUI

- Sending Options
  - Randomization: select vendors/products, duration, and rate
  - Story: select XGen scenarios
    - APT Group Campaigns (e.g., APT29, APT28, APT1, Volt Typhoon, Lazarus, Carbanak)
    - Individual Patterns (e.g., T1543.003 Service Persistence, T1021.002 SMB Lateral)
- Transports
  - Enable Syslog (Broker VM) — default enabled
  - Enable Cortex XSIAM HTTP (uses env vars)
  - Enable Webhook (uses env vars or per‑run overrides)
- Custom inputs
  - Custom CSV Path (optional): run Custom CSV mode
  - HTTP Endpoint and HTTP Bearer Token (optional, per run)

## CSV Ingestion (third‑party logs)

You can ingest third‑party logs from a CSV file, map them to NICE categories, and forward them to Syslog/HTTP.

- Minimal CSV columns supported (missing values are handled reasonably):
  - timestamp, vendor, product, severity, event_name, message,
  - username, src_ip, src_port, dst_ip, dst_port, protocol

- Example CSV row
  - 2025-10-02T21:51:00Z,Cisco,ASA,6,ConnectionAllowed,Allowed TCP connection,user1,10.0.0.5,51515,172.16.0.10,443,TCP

- How NICE mappings are applied
  - Vendors and products are categorized automatically via src/xgen/catalog/vendor_catalog.py into:
    - Network: Cisco, Palo Alto Networks, Zscaler, Proofpoint
    - Identity: Okta, Duo, Azure (AD Audit/Signin), OneLogin, PingOne, Google Workspace (Auth)
    - Cloud: AWS (CloudTrail/Flow), Azure (Audit/Flow), GCP (Audit/Flow), Kubernetes (Audit), Microsoft 365 (Email)
    - Endpoint: Microsoft Defender for Endpoint, CrowdStrike, SentinelOne, Windows Event Collector, Dropbox Events

- Running Custom CSV via GUI
  - Enter CSV path under “Custom CSV Path (optional)” and click Start
  - Choose transports via the toggles
  - Optional: use “HTTP Endpoint” and “HTTP Bearer Token” fields to override env vars per run

## Delivery Transports

- Syslog (UDP)
  - The app sends CEF or JSON wrapped in a syslog header to the configured host/port
  - Default: 127.0.0.1:514

- Cortex XSIAM HTTP
  - Adapter maps fields to XDM‑style properties including 5‑tuple, actor, assets, and MITRE fields when present
  - Batching, retry, and optional gzip compression

- Generic HTTP/Webhook
  - Simple JSON payload with events and metadata; supports bearer token auth

## Example: HTTP POST (curl)

If you want to post directly with curl (bypassing the app) to a webhook endpoint:

- export WEBHOOK_ENDPOINT="https://example/webhook"
- export WEBHOOK_TOKEN="${WEBHOOK_TOKEN}"

Example request body (single event):

```
{
  "events": [
    {
      "timestamp": "2025-10-02T21:51:00Z",
      "vendor": "Cisco",
      "product": "ASA",
      "severity": 6,
      "event_name": "ConnectionAllowed",
      "message": "Allowed TCP connection",
      "src_ip": "10.0.0.5",
      "src_port": 51515,
      "dst_ip": "172.16.0.10",
      "dst_port": 443,
      "protocol": "TCP"
    }
  ]
}
```

curl command:

```
curl -sS -X POST \
  -H "Authorization: Bearer ${WEBHOOK_TOKEN}" \
  -H "Content-Type: application/json" \
  -d @payload.json \
  "${WEBHOOK_ENDPOINT}"
```

Replace ${WEBHOOK_TOKEN} and ${WEBHOOK_ENDPOINT} with your values.

## Example: Syslog UDP Delivery

- Ensure a receiver is listening on 127.0.0.1:514 (or set your Broker VM IP)
- In the GUI, set “Syslog receiver IP” and keep “Enable Syslog” checked
- Start a scenario or CSV run; logs will stream and be forwarded to syslog

## XGen Scenarios (MITRE‑aligned)

- Campaigns
  - APT29: Cloud credential manipulation + enterprise persistence
  - APT28: Enterprise lateral movement focus
  - APT1: SMB lateral movement
  - Volt Typhoon: Cloud credentials
  - Lazarus Group: Registry & Mobile
  - Carbanak (FIN7): Task scheduling

- Patterns
  - T1543.003 Windows Service Persistence
  - T1547.001 Registry Autostart Persistence
  - T1053.005 Scheduled Tasks
  - T1021.002 SMB Lateral Movement
  - T1021.001 RDP Lateral Movement
  - T1098.001 Cloud Credential Manipulation
  - T1134.001 Token Impersonation

## Developer Notes

- Project layout (key modules):
  - src/xgen/core: BaseEvent, NICE, transport types; burst generator
  - src/xgen/ttp: MITRE ATT&CK patterns library
  - src/xgen/formats: CEF/JSON renderers
  - src/xgen/transports: Syslog UDP/TCP/TLS, XSIAM HTTP, Webhook/HTTP
  - src/xgen/integration/app_integration.py: Bridge for Flask app
  - src/xgen/custom/csv_ingest.py: CSV → BaseEvent ingestion
  - src/xgen/catalog/vendor_catalog.py: NICE vendor catalog

- Makefile targets
  - make venv — create venv and install requirements
  - make run — run Flask GUI on localhost:5001
  - make demo — run interactive terminal demo
  - make format — run black+ruff
  - make pytest — run tests

## Troubleshooting

- GUI not loading? Ensure venv is active and Flask is installed (make venv; source .activate; make run)
- HTTP delivery not working? Check env vars or set HTTP Endpoint/Token in the GUI
- XSIAM rejects payload? Verify your endpoint, credentials, and tenant headers. If your deployment expects “Authorization: Bearer …”, request that variant and we’ll adjust the adapter headers
- Syslog not received? Confirm the receiver is reachable and open on the selected host/port
- CSV parsing issues? Validate header names and types. The parser is liberal but requires valid ints for ports when provided

## Security and Safety

- Do not use production credentials or endpoints in demos
- Keep tokens in env vars; avoid putting secrets into code or CSVs

---

Prepared for Cortex domain consultants to validate analytics pipelines end‑to‑end: generate realistic events, ingest third‑party logs, organize data under NICE, and deliver to syslog or HTTP (XSIAM/webhooks) for detection content validation.
