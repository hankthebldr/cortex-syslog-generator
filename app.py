

import csv

import random

import time

from datetime import datetime

from faker import Faker

from flask import Flask, render_template_string, request, Response, jsonify

import socket

import os

import threading

import json

  

# Initialize Flask app and Faker

app = Flask(__name__)

fake = Faker()

HOSTNAME = socket.gethostname()

# Enhanced with XGen burst generation capabilities

DEFAULT_VENDOR = "Gambit"

LOG_DIR = "logs"

# Import XGen integration layer
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

try:
    from xgen.integration.app_integration import xgen_session, get_available_apt_groups, get_available_patterns
    XGEN_AVAILABLE = True
except ImportError as e:
    print(f"XGen integration not available: {e}")
    XGEN_AVAILABLE = False

  

# Global state to manage the generation session

session_state = {
    'thread': None,
    'stop_event': threading.Event(),
    'pause_event': threading.Event(),
    'logs_queue': [],
    'is_running': False,
    'is_paused': False,
    'start_time': None,
    'xgen_mode': False,
}

session_lock = threading.Lock()

  

# Define a list of departments for the user base

DEPARTMENTS = [
    "Engineering", "Marketing", "Sales", "Human Resources",
    "Finance", "IT Support", "Customer Service", "Product Management"
]

  

# Define Known Bad IPs and URLs for story generation

KNOWN_BAD_IPS = ["203.0.113.5", "198.51.100.12", "209.165.201.25"]

KNOWN_BAD_URLS = ["http://malicious-phishing.com/login", "http://exploit-kit.ru/payload", "http://ransomware-c2.net/checkin"]

  

# The updated HTML template is embedded here as a string

HTML = '''

<!doctype html>

<html lang="en">

<head>

  <meta charset="utf-8">

  <title>Gambit the Syslog Generator</title>

  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet">

  <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;600&display=swap" rel="stylesheet">

  <style>

    body {

      background-color: #1a1a1a;

      color: #e0e0e0;

      font-family: 'Poppins', sans-serif;

    }

    .container {

      max-width: 900px;

    }

    .rounded {

      border-color: #333 !important;

      background-color: #2c2c2c;

    }

    .form-label, h5 {

      color: #e0e0e0;

    }

    .form-control, .form-select, .form-check-input[type="text"] {

      background-color: #3e3e3e;

      color: #e0e0e0;

      border-color: #555;

    }

    .form-control:focus, .form-select:focus, .form-check-input[type="text"]:focus {

      background-color: #3e3e3e;

      color: #e0e0e0;

      border-color: #555;

      box-shadow: 0 0 0 0.25rem rgba(76, 175, 80, 0.25);

    }

    .form-check-label {

      color: #e0e0e0;

    }

    .btn-success {

      background-color: #4caf50;

      border-color: #4caf50;

    }

    .btn-warning {

      background-color: #ff9800;

      border-color: #ff9800;

    }

    .btn-danger {

      background-color: #f44336;

      border-color: #f44336;

    }

    .btn-info {

        background-color: #03a9f4;

        border-color: #03a9f4;

    }

    #log_display {

      height: 400px;

      overflow-y: scroll;

      background-color: #121212;

      border: 1px solid #444;

      padding: 10px;

      font-family: monospace;

      white-space: pre-wrap;

      border-radius: 0.25rem;

    }

    .log-line {

      border-bottom: 1px dashed #333;

      padding-bottom: 5px;

      margin-bottom: 5px;

    }

    .alert-info {

        background-color: #2e2e2e;

        color: #e0e0e0;

        border-color: #444;

    }

    .alert-success {

        background-color: #2e2e2e;

        color: #4caf50;

        border-color: #444;

    }

    .alert-danger {

        background-color: #2e2e2e;

        color: #f44336;

        border-color: #444;

    }

    .alert-warning {

        background-color: #2e2e2e;

        color: #ff9800;

        border-color: #444;

    }

    .story-controls, .random-controls { display: none; }

    h5[data-bs-toggle="collapse"] {

        cursor: pointer;

    }

    .accordion-button {

        background-color: #3e3e3e;

        color: #e0e0e0;

    }

    .accordion-button:not(.collapsed) {

        background-color: #4caf50;

        color: white;

    }

    .accordion-body {

        background-color: #2c2c2c;

    }

    #selected-products-container {

        margin-top: 1rem;

    }

    .product-tag {

        display: inline-block;

        background-color: #4caf50;

        color: white;

        padding: .25rem .5rem;

        border-radius: .25rem;

        margin-right: .5rem;

        margin-bottom: .5rem;

        font-size: 0.8rem;

    }

    .product-tag .remove-tag {

        cursor: pointer;

        margin-left: .5rem;

        font-weight: bold;

    }

    footer {

        text-align: center;

        margin-top: 2rem;

        color: #888;

        font-size: 0.8rem;

    }

    footer a {

        color: #4caf50;

    }

  </style>

</head>

<body class="p-4">

  <div class="container text-center">

    <h1>Gambit</h1>

    <p class="fs-5">The Syslog Generator</p>

    <br>

  </div>

  <div class="container">

    <form id="generator-form">

      <div class="row">

        <div class="col-md-6">

          <div class="mb-4 p-3 border rounded">

            <h5 class="mb-3">Log Destination & Format</h5>

            <div class="mb-3">

              <label for="dest_ip" class="form-label">Syslog receiver IP</label>

              <input type="text" class="form-control" id="dest_ip" name="dest_ip" required placeholder="127.0.0.1" value="">

              <small class="form-text text-muted">Enter Syslog Receiver IP</small>

            </div>

            <div id="log-format-sources-row">

                <div class="mb-3" style="display: none;">

                  <label for="log_format" class="form-label">Log Format</label>

                  <select class="form-select" id="log_format" name="log_format">
                    <option value="cef" selected>CEF (Common Event Format)</option>
                    <option value="leef">LEEF (Log Event Extended Format)</option>
                    <option value="json">JSON (for HTTP endpoints)</option>
                  </select>

                </div>

                <div id="standard-log-sources">

                    <div class="mb-3">

                        <label class="form-label">Log Sources</label>

                        <div class="accordion" id="vendorAccordion" style="height: 200px; overflow-y: auto;">

                            <!-- Accordion items will be injected here by JavaScript -->

                        </div>

                    </div>

                    <div id="selected-products-container">

                        <label class="form-label">Selected Products</label>

                        <div id="selected-products" style="min-height: 50px; background-color: #3e3e3e; border-radius: .25rem; padding: .5rem;"></div>

                    </div>

                </div>

            </div>

          </div>

        </div>

        <div class="col-md-6">

          <div class="mb-4 p-3 border rounded">

            <h5 class="mb-3">Sending Options</h5>

            <div class="mb-3">

              <div class="form-check form-check-inline">

                <input class="form-check-input" type="radio" name="send_mode" id="mode_random" value="random" checked>

                <label class="form-check-label" for="mode_random">Randomization</label>

              </div>

              <div class="form-check form-check-inline">

                <input class="form-check-input" type="radio" name="send_mode" id="mode_story" value="story">

                <label class="form-check-label" for="mode_story">Story</label>

              </div>

            </div>

            <div class="random-controls">

                <div class="mb-3" id="random-settings">

                    <label for="duration_minutes" class="form-label">Session Duration (minutes)</label>

                    <input type="number" class="form-control" id="duration_minutes" name="duration_minutes" required value="1">

                </div>

                <div class="mb-3">
                    <label for="messages_per_second" class="form-label">Messages per Second</label>
                    <input type="number" class="form-control" id="messages_per_second" name="messages_per_second" required value="10">
                </div>

                <div class="mb-3">
                    <label for="csv_path" class="form-label">Custom CSV Path (optional)</label>
                    <input type="text" class="form-control" id="csv_path" name="csv_path" placeholder="/path/to/events.csv">
                    <small class="form-text text-muted">If provided, runs Custom CSV mode and ignores randomization products.</small>
                </div>

                <div class="mb-3">
                    <label for="http_endpoint" class="form-label">HTTP Endpoint (optional)</label>
                    <input type="text" class="form-control" id="http_endpoint" name="http_endpoint" placeholder="https://example/api/ingest">
                </div>
                <div class="mb-3">
                    <label for="http_token" class="form-label">HTTP Bearer Token (optional)</label>
                    <input type="password" class="form-control" id="http_token" name="http_token" placeholder="token">
                    <small class="form-text text-muted">Used only if HTTP Endpoint is provided.</small>
                </div>

                <hr>

                <div class="mb-3">
                  <label class="form-label">Transports</label>
                  <div class="form-check">
                    <input class="form-check-input" type="checkbox" id="enable_syslog" name="enable_syslog" checked>
                    <label class="form-check-label" for="enable_syslog">Enable Syslog (Broker VM)</label>
                  </div>
                  <div class="form-check">
                    <input class="form-check-input" type="checkbox" id="enable_xsiam_http" name="enable_xsiam_http" checked>
                    <label class="form-check-label" for="enable_xsiam_http">Enable Cortex XSIAM HTTP (uses env vars)</label>
                  </div>
                  <div class="form-check">
                    <input class="form-check-input" type="checkbox" id="enable_webhook" name="enable_webhook" checked>
                    <label class="form-check-label" for="enable_webhook">Enable Webhook (uses env vars)</label>
                  </div>
                </div>

                <div class="form-check form-switch mb-3">

                  <input class="form-check-input" type="checkbox" id="custom_log_toggle" name="custom_log_toggle">

                  <label class="form-check-label" for="custom_log_toggle">Create Custom Log</label>

                </div>

                <div id="custom-log-fields" style="display: none;">

                    <div class="mb-3">

                        <label for="custom_vendor" class="form-label">Custom Vendor</label>

                        <input type="text" class="form-control" id="custom_vendor" name="custom_vendor">

                    </div>

                    <div class="mb-3">

                        <label for="custom_product" class="form-label">Custom Product</label>

                        <input type="text" class="form-control" id="custom_product" name="custom_product">

                        <small class="form-text text-muted">Try keywords like: NGFW, EDR, Proxy, VPN</small>

                    </div>

                </div>

            </div>

            <div class="story-controls">

                <div class="mb-3">

                    <label for="story_type" class="form-label">Select a Story</label>

                    <select class="form-select" id="story_type" name="story_type">
                        <optgroup label="APT Group Campaigns (XGen)">
                            <option value="apt_campaign:APT29">APT29 (Cozy Bear) - Cloud & Enterprise</option>
                            <option value="apt_campaign:APT28">APT28 (Fancy Bear) - Enterprise Focus</option>
                            <option value="apt_campaign:APT1">APT1 (Comment Crew) - SMB Lateral Movement</option>
                            <option value="apt_campaign:APT40">APT40 (Leviathan) - Cloud & SSH</option>
                            <option value="apt_campaign:APT41">APT41 (Double Dragon) - RDP & Tasks</option>
                            <option value="apt_campaign:Volt Typhoon">Volt Typhoon - Cloud Credentials</option>
                            <option value="apt_campaign:Lazarus Group">Lazarus Group - Registry & Mobile</option>
                            <option value="apt_campaign:Carbanak">Carbanak (FIN7) - Task Scheduling</option>
                        </optgroup>
                        <optgroup label="Individual Patterns (XGen)">
                            <option value="pattern:T1543.003_SERVICE_PERSIST">Windows Service Persistence</option>
                            <option value="pattern:T1547.001_REGISTRY_AUTOSTART">Registry Autostart Persistence</option>
                            <option value="pattern:T1053.005_SCHTASK_PERSIST">Scheduled Task Persistence</option>
                            <option value="pattern:T1021.002_SMB_LATERAL">SMB Lateral Movement</option>
                            <option value="pattern:T1021.001_RDP_LATERAL">RDP Lateral Movement</option>
                            <option value="pattern:T1098.001_CLOUD_CREDS">Cloud Credential Manipulation</option>
                            <option value="pattern:T1134.001_TOKEN_IMPERSONATION">Token Impersonation</option>
                        </optgroup>
                        <optgroup label="Legacy Attack Scenarios">
                        <optgroup label="Attack Scenarios">

                            <option value="rogue_insider_story">Rogue Insider Story</option>

                            <option value="web_server_breach_story">Web Server Breach Story</option>

                            <option value="brute_force_data_theft_story">Brute-Force & Data Theft Story</option>

                            <option value="aws_compromise_story">AWS Compromise Story</option>

                            <option value="gcp_compromise_story">GCP Compromise Story</option>

                            <option value="azure_compromise_story">Azure Compromise Story</option>

                        </optgroup>

                        <optgroup label="MITRE ATT&CK Tactics">

                            <option value="reconnaissance_story">Reconnaissance (TA0043)</option>

                            <option value="resource_development_story">Resource Development (TA0042)</option>

                            <option value="initial_access_story">Initial Access (TA0001)</option>

                            <option value="execution_story">Execution (TA0002)</option>

                            <option value="persistence_story">Persistence (TA0003)</option>

                            <option value="privilege_escalation_story">Privilege Escalation (TA0004)</option>

                            <option value="defense_evasion_story">Defense Evasion (TA0005)</option>

                            <option value="credential_access_story">Credential Access (TA0006)</option>

                            <option value="discovery_story">Discovery (TA0007)</option>

                            <option value="lateral_movement_story">Lateral Movement (TA0008)</option>

                            <option value="collection_story">Collection (TA0009)</option>

                            <option value="command_and_control_story">Command and Control (TA0011)</option>

                            <option value="exfiltration_story">Exfiltration (TA0010)</option>

                            <option value="impact_story">Impact (TA0040)</option>

                        </optgroup>

                    </select>

                </div>

                <div class="form-check mb-3">

                    <input class="form-check-input" type="checkbox" id="add_noise" name="add_noise" checked>

                    <label class="form-check-label" for="add_noise">Add Noise (up to 100 logs total)</label>

                </div>

            </div>

            <div class="d-flex gap-2 mb-3">

                <button type="button" class="btn btn-success" id="start-btn">Start</button>

                <button type="button" class="btn btn-warning" id="pause-btn">Pause</button>

                <button type="button" class="btn btn-danger" id="stop-btn">Stop</button>

            </div>

            <div class="form-check mb-3">

              <input class="form-check-input" type="checkbox" id="save_file" name="save_file">

              <label class="form-check-label" for="save_file">Save generated logs to CSV file</label>

            </div>

          </div>

        </div>

      </div>

    </form>

    <div id="status-alert" class="alert mt-3 d-none"></div>

    <div class="mt-4">

        <div class="d-flex justify-content-between align-items-center mb-2">

            <h3>Live Log Display</h3>

            <div>

                <button type="button" class="btn btn-secondary btn-sm" id="new-session-btn">New Session</button>

                <button type="button" class="btn btn-info btn-sm" id="clear-btn">Clear Logs</button>

            </div>

        </div>

        <div id="log_display"></div>

    </div>

  </div>

  <footer>

      <p>Gambit was developed by Ben Sookying, created for security practioners. This is not intended for commercial use. Make sure to visit the github repo for the latest version of the code. <a href="https://github.com/bsookying/Gambit-The-Syslog-Generator" target="_blank">https://github.com/bsookying/Gambit-The-Syslog-Generator</a></p>

  </footer>

  

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/js/bootstrap.bundle.min.js"></script>

  <script>

    const form = document.getElementById('generator-form');

    const startBtn = document.getElementById('start-btn');

    const pauseBtn = document.getElementById('pause-btn');

    const stopBtn = document.getElementById('stop-btn');

    const clearBtn = document.getElementById('clear-btn');

    const newSessionBtn = document.getElementById('new-session-btn');

    const statusAlert = document.getElementById('status-alert');

    const logDisplay = document.getElementById('log_display');

    const storyModeRadio = document.getElementById('mode_story');

    const randomModeRadio = document.getElementById('mode_random');

    const storyControls = document.querySelector('.story-controls');

    const randomControls = document.querySelector('.random-controls');

    const standardLogSources = document.getElementById('standard-log-sources');

    const customLogToggle = document.getElementById('custom_log_toggle');

    const customLogFields = document.getElementById('custom-log-fields');

  

    const productsByVendor = {

        "AWS": ["CloudTrail", "VPC Flow Logs"],

        "Azure": ["Audit Logs", "Flow Logs", "Signin Log", "AD Audit Logs"],

        "GCP": ["Audit Logs", "Flow Logs"],

        "Kubernetes": ["Audit Logs"],

        "Okta": ["SSO", "Audit"],

        "Duo": ["Authentication"],

        "PingOne": ["SSO"],

        "OneLogin": ["Events"],

        "Google Workspace": ["Audit", "Authentication"],

        "Microsoft 365": ["Email Logs"],

        "Palo Alto Networks": ["PAN-OS", "Global Protect", "Platform Logs", "URL Logs"],

        "Cisco": ["ASA"],

        "Zscaler": ["Web Proxy", "NSS Firewall", "ZPA User Activity", "ZPA User Status", "ZPA Connector", "ZPA Audit"],

        "Proofpoint": ["Email Security"],

        "Microsoft": ["Defender for Endpoint"],

        "CrowdStrike": ["Falcon"],

        "SentinelOne": ["EDR"],

        "Dropbox": ["Events"],

        "Windows": ["Event Collector"]

    };

  

    let eventSource = null;

  

    function setButtonsState(running, paused) {

      startBtn.disabled = running;

      pauseBtn.disabled = !running;

      stopBtn.disabled = !running;

      pauseBtn.textContent = paused ? 'Resume' : 'Pause';

    }

  

    function showStatus(message, type = 'info') {

      statusAlert.textContent = message;

      statusAlert.className = `alert alert-${type} mt-3`;

      statusAlert.classList.remove('d-none');

    }

  

    function startStreaming(stream_url) {

      if (eventSource) {

        eventSource.close();

      }

      logDisplay.innerHTML = '';

      eventSource = new EventSource(stream_url);

      setupEventSource();

    }

  

    function setupEventSource() {

        eventSource.onmessage = function(event) {

          try {

            const data = JSON.parse(event.data);

            if (data.status) {

              showStatus(data.status, data.type);

              setButtonsState(data.is_running, data.is_paused);

              if (data.status.includes("completed") || data.status.includes("stopped") || data.status.includes("not yet implemented")) {

                  if(eventSource) eventSource.close();

              }

            } else if (data.log) {

              const logElement = document.createElement('div');

              logElement.className = 'log-line';

              logElement.textContent = data.log;

              logDisplay.appendChild(logElement);

              logDisplay.scrollTop = logDisplay.scrollHeight;

            }

          } catch (e) {

            console.error("Failed to parse JSON:", event.data, e);

          }

        };

        eventSource.onerror = function(err) {

          console.error("EventSource failed:", err);

          eventSource.close();

          showStatus("Event stream failed. Check console for details.", 'danger');

        };

    }

  

    function updateUIMode(sendMode) {

        if (sendMode === 'story') {

            storyControls.style.display = 'block';

            randomControls.style.display = 'none';

            standardLogSources.style.display = 'none';

        } else { // 'random' mode

            storyControls.style.display = 'none';

            randomControls.style.display = 'block';

            const isCustom = customLogToggle.checked;

            customLogFields.style.display = isCustom ? 'block' : 'none';

            standardLogSources.style.display = isCustom ? 'none' : 'block';

        }

    }

    function updateSelectedProductsDisplay() {

        const selectedProductsContainer = document.getElementById('selected-products');

        selectedProductsContainer.innerHTML = '';

        const selectedCheckboxes = document.querySelectorAll('input[name="products"]:checked');

        selectedCheckboxes.forEach(cb => {

            const [vendor, product] = cb.value.split('-');

            const tag = document.createElement('span');

            tag.className = 'product-tag';

            tag.textContent = `${product} (${vendor})`;

            const removeSpan = document.createElement('span');

            removeSpan.className = 'remove-tag';

            removeSpan.textContent = 'x';

            removeSpan.onclick = () => {

                cb.checked = false;

                updateSelectedProductsDisplay();

            };

            tag.appendChild(removeSpan);

            selectedProductsContainer.appendChild(tag);

        });

    }

  

    function populateVendors() {

        const vendorAccordion = document.getElementById('vendorAccordion');

        Object.keys(productsByVendor).forEach((vendor, index) => {

            const vendorId = `vendor_${vendor.replace(/ /g, '_')}`;

            const collapseId = `collapse_${vendorId}`;

            const accordionItem = document.createElement('div');

            accordionItem.className = 'accordion-item';

  

            let productCheckboxesHTML = '';

            const products = productsByVendor[vendor] || [];

            products.forEach(product => {

                const productIdentifier = `${vendor}-${product}`;

                productCheckboxesHTML += `

                    <div class="form-check">

                        <input class="form-check-input" type="checkbox" name="products" value="${productIdentifier}" id="prod_${productIdentifier.replace(/ /g, '_')}">

                        <label class="form-check-label" for="prod_${productIdentifier.replace(/ /g, '_')}">${product}</label>

                    </div>

                `;

            });

  

            accordionItem.innerHTML = `

                <h2 class="accordion-header" id="heading_${vendorId}">

                  <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#${collapseId}" aria-expanded="false" aria-controls="${collapseId}">

                    ${vendor}

                  </button>

                </h2>

                <div id="${collapseId}" class="accordion-collapse collapse" aria-labelledby="heading_${vendorId}" data-bs-parent="#vendorAccordion">

                  <div class="accordion-body">

                    ${productCheckboxesHTML}

                  </div>

                </div>

            `;

            vendorAccordion.appendChild(accordionItem);

        });

        vendorAccordion.addEventListener('change', updateSelectedProductsDisplay);

    }

  

    customLogToggle.addEventListener('change', () => {

        const isCustom = customLogToggle.checked;

        customLogFields.style.display = isCustom ? 'block' : 'none';

        standardLogSources.style.display = isCustom ? 'none' : 'block';

    });

  

    randomModeRadio.addEventListener('change', (e) => updateUIMode(e.target.value));

    storyModeRadio.addEventListener('change', (e) => updateUIMode(e.target.value));

    startBtn.addEventListener('click', () => {

        const formData = new FormData(form);

        const data = Object.fromEntries(formData.entries());

        if (data.custom_log_toggle) {

            if (!data.custom_vendor || !data.custom_product) {

                showStatus('Please provide both a custom vendor and product.', 'danger');

                return;

            }

        } else if (data.send_mode === 'random') {

            data.products = Array.from(document.querySelectorAll('input[name="products"]:checked')).map(cb => cb.value);

            if (data.products.length === 0) {

                showStatus('Please select at least one product for random mode.', 'danger');

                return;

            }

        }

  

        data.dest_port = 514;

        fetch('/start', {

            method: 'POST',

            headers: { 'Content-Type': 'application/json' },

            body: JSON.stringify(data)

        }).then(response => response.json()).then(result => {

            if (result.success) {

                showStatus(result.message, 'success');

                setButtonsState(true, false);

                startStreaming('/stream');

            } else {

                showStatus(result.message, 'danger');

            }

        });

    });

  

    pauseBtn.addEventListener('click', () => {

        fetch('/pause', { method: 'POST' }).then(response => response.json()).then(result => {

            showStatus(result.message, 'warning');

            setButtonsState(result.is_running, result.is_paused);

        });

    });

  

    stopBtn.addEventListener('click', () => {

        fetch('/stop', { method: 'POST' }).then(response => response.json()).then(result => {

            showStatus(result.message, 'danger');

            setButtonsState(false, false);

            if (eventSource) {

                eventSource.close();

                eventSource = null;

            }

        });

    });

  

    clearBtn.addEventListener('click', () => {

        logDisplay.innerHTML = '';

        showStatus('Log display cleared.', 'info');

    });

  

    newSessionBtn.addEventListener('click', () => {

        logDisplay.innerHTML = '';

        form.reset();

        updateSelectedProductsDisplay();

        updateUIMode('random');

        showStatus('New session started.', 'info');

    });

  

    // Initial state check and UI update

    populateVendors();

    fetch('/status').then(response => response.json()).then(status => {

      setButtonsState(status.is_running, status.is_paused);

      if (status.is_running) {

        showStatus(status.message, 'info');

        startStreaming('/stream');

      }

      updateUIMode(form.elements.send_mode.value);

    });

  

  </script>

</body>

</html>

'''

  

# --- BACKEND LOGIC ---

def format_log_line(vendor, product, severity, event_id, message_dict, fmt='cef'):

    """Formats a log message into a CEF or LEEF string."""

    now = datetime.now()

    log_data = {

        'timestamp': now.isoformat(), 'vendor': vendor, 'product': product, 'severity': severity,

        'event_id': event_id, 'name': message_dict.get('name', 'N/A'),

        'username': message_dict.get('username', 'N/A'), 'src_ip': message_dict.get('src_ip', 'N/A'),

        'dst_ip': message_dict.get('dst_ip', 'N/A'), 'message': message_dict.get('message', 'N/A')

    }

    header = f'{now.strftime("%b %d %H:%M:%S")} {HOSTNAME} CEF:0|{vendor}|{product}|1.0|{event_id}|{message_dict.get("name", "N/A")}|{severity}|'

    fields = [f'suser={message_dict.get("username", "")}', f'src={message_dict.get("src_ip", "")}', f'dst={message_dict.get("dst_ip", "")}', f'msg={message_dict.get("message", "")}']

    log_data['log_line'] = header + " ".join(filter(None, fields))

    return log_data

  

def gen_user_info():

    return {'username': fake.user_name(), 'department': random.choice(DEPARTMENTS)}

  

# --- Custom Log Generator ---

def gen_custom_log(fmt='cef', **kwargs):

    vendor = kwargs.get('custom_vendor', 'CustomVendor')

    product = kwargs.get('custom_product', 'CustomProduct')

    product_lower = product.lower()

  

    message_dict = {

        'username': fake.user_name(),

        'src_ip': fake.ipv4_public(),

        'dst_ip': fake.ipv4_private(),

    }

  

    # Context-aware log generation based on keywords

    if any(kw in product_lower for kw in ['ngfw', 'firewall', 'fw']):

        message_dict['name'] = random.choice(['Connection Allowed', 'Connection Denied', 'Threat Detected'])

        message_dict['message'] = f"Firewall event: {message_dict['name']} from {message_dict['src_ip']} to {message_dict['dst_ip']}"

    elif 'edr' in product_lower:

        message_dict['name'] = random.choice(['Suspicious Process Detected', 'Malware Quarantined', 'Ransomware Behavior Blocked'])

        message_dict['message'] = f"EDR alert: {message_dict['name']} on host {fake.hostname()}"

    elif 'proxy' in product_lower:

        message_dict['name'] = random.choice(['URL Blocked', 'URL Allowed', 'Content Category Filtered'])

        message_dict['message'] = f"Proxy event: {message_dict['name']} for user {message_dict['username']}"

    elif 'vpn' in product_lower:

        message_dict['name'] = random.choice(['VPN Connection Success', 'VPN Connection Failed'])

        message_dict['message'] = f"VPN event: {message_dict['name']} for user {message_dict['username']} from {message_dict['src_ip']}"

    else:

        # Fallback to generic message

        message_dict['name'] = 'Custom Event'

        message_dict['message'] = f'This is a custom log event for {product}.'

  

    return format_log_line(vendor, product, 5, 99999, message_dict, fmt)

  
  

# --- Vendor Specific Log Generators ---

def gen_aws_cloudtrail_log(fmt='cef', **kwargs):

    message_dict = {'name': 'ConsoleLogin', 'username': fake.user_name(), 'src_ip': fake.ipv4_public(), 'message': 'Successful AWS Console login'}

    message_dict.update(kwargs)

    return format_log_line("AWS", "CloudTrail", 3, 20000, message_dict, fmt)

  

def gen_aws_vpc_flow_log(fmt='cef', **kwargs):

    message_dict = {'name': 'VPC Flow', 'src_ip': fake.ipv4_public(), 'dst_ip': fake.ipv4_private(), 'message': 'AWS VPC network flow event'}

    message_dict.update(kwargs)

    return format_log_line("AWS", "VPC Flow Logs", 2, 20001, message_dict, fmt)

  

def gen_azure_audit_log(fmt='cef', **kwargs):

    message_dict = {'name': 'Update User', 'username': fake.user_name(), 'src_ip': fake.ipv4_public(), 'message': 'Azure AD user updated'}

    message_dict.update(kwargs)

    return format_log_line("Azure", "Audit Logs", 4, 9000, message_dict, fmt)

  

def gen_azure_flow_log(fmt='cef', **kwargs):

    message_dict = {'name': 'Network Flow', 'src_ip': fake.ipv4_public(), 'dst_ip': fake.ipv4_private(), 'message': 'Azure network flow event'}

    message_dict.update(kwargs)

    return format_log_line("Azure", "Flow Logs", 2, 9001, message_dict, fmt)

  

def gen_azure_signin_log(fmt='cef', **kwargs):

    message_dict = {'name': 'UserLoggedIn', 'username': fake.user_name(), 'src_ip': fake.ipv4_public(), 'message': 'Successful user sign-in'}

    message_dict.update(kwargs)

    return format_log_line("Azure", "Signin Log", 3, 9002, message_dict, fmt)

  

def gen_azure_ad_audit_log(fmt='cef', **kwargs):

    message_dict = {'name': 'Add member to group', 'username': fake.user_name(), 'message': 'User added to security group'}

    message_dict.update(kwargs)

    return format_log_line("Azure", "AD Audit Logs", 6, 9003, message_dict, fmt)

  

def gen_gcp_audit_log(fmt='cef', **kwargs):

    message_dict = {'name': 'v1.compute.instances.insert', 'username': fake.user_name(), 'src_ip': fake.ipv4_public(), 'message': 'GCP VM instance created'}

    message_dict.update(kwargs)

    return format_log_line("GCP", "Audit Logs", 5, 10000, message_dict, fmt)

  

def gen_gcp_flow_log(fmt='cef', **kwargs):

    message_dict = {'name': 'VPC Flow', 'src_ip': fake.ipv4_public(), 'dst_ip': fake.ipv4_private(), 'message': 'GCP network flow event'}

    message_dict.update(kwargs)

    return format_log_line("GCP", "Flow Logs", 2, 10001, message_dict, fmt)

  

def gen_kubernetes_audit_log(fmt='cef', **kwargs):

    message_dict = {'name': 'create-pod', 'username': 'system:kube-scheduler', 'src_ip': fake.ipv4_private(), 'message': 'Pod created in default namespace'}

    message_dict.update(kwargs)

    return format_log_line("Kubernetes", "Audit Logs", 4, 11000, message_dict, fmt)

  

def gen_okta_sso_log(fmt='cef', **kwargs):

    message_dict = {'name': 'user.session.start', 'username': fake.user_name(), 'src_ip': fake.ipv4_public(), 'message': 'Okta SSO event'}

    message_dict.update(kwargs)

    return format_log_line("Okta", "SSO", 3, 3000, message_dict, fmt)

  

def gen_okta_audit_log(fmt='cef', **kwargs):

    message_dict = {'name': 'user.privilege.grant', 'username': fake.user_name(), 'message': 'User granted admin privileges'}

    message_dict.update(kwargs)

    return format_log_line("Okta", "Audit", 8, 3001, message_dict, fmt)

  

def gen_duo_log(fmt='cef', **kwargs):

    message_dict = {'name': 'authentication.success', 'username': fake.user_name(), 'src_ip': fake.ipv4_public(), 'message': 'Duo authentication successful'}

    message_dict.update(kwargs)

    return format_log_line("Duo", "Authentication", 2, 12000, message_dict, fmt)

  

def gen_pingone_log(fmt='cef', **kwargs):

    message_dict = {'name': 'sso.success', 'username': fake.user_name(), 'src_ip': fake.ipv4_public(), 'message': 'PingOne SSO successful'}

    message_dict.update(kwargs)

    return format_log_line("PingOne", "SSO", 2, 13000, message_dict, fmt)

  

def gen_onelogin_log(fmt='cef', **kwargs):

    message_dict = {'name': 'login.success', 'username': fake.user_name(), 'src_ip': fake.ipv4_public(), 'message': 'OneLogin event'}

    message_dict.update(kwargs)

    return format_log_line("OneLogin", "Events", 2, 14000, message_dict, fmt)

  

def gen_google_workspace_audit_log(fmt='cef', **kwargs):

    message_dict = {'name': 'drive.view', 'username': fake.user_name(), 'message': 'User viewed a file in Google Drive'}

    message_dict.update(kwargs)

    return format_log_line("Google Workspace", "Audit", 3, 15000, message_dict, fmt)

  

def gen_google_workspace_auth_log(fmt='cef', **kwargs):

    message_dict = {'name': 'login.success', 'username': fake.user_name(), 'src_ip': fake.ipv4_public(), 'message': 'Google Workspace login successful'}

    message_dict.update(kwargs)

    return format_log_line("Google Workspace", "Authentication", 2, 15001, message_dict, fmt)

  

def gen_m365_email_log(fmt='cef', **kwargs):

    message_dict = {'name': 'email.sent', 'username': fake.user_name(), 'message': 'Email sent from user mailbox'}

    message_dict.update(kwargs)

    return format_log_line("Microsoft 365", "Email Logs", 2, 16000, message_dict, fmt)

  

def gen_panos_log(fmt='cef', **kwargs):

    message_dict = {'name': 'TRAFFIC', 'src_ip': fake.ipv4_public(), 'dst_ip': fake.ipv4_private(), 'message': 'Traffic log'}

    message_dict.update(kwargs)

    return format_log_line("Palo Alto Networks", "PAN-OS", 2, 1000, message_dict, fmt)

  

def gen_cisco_asa_log(fmt='cef', **kwargs):

    message_dict = {'name': 'Connection Denied', 'src_ip': fake.ipv4_public(), 'dst_ip': fake.ipv4_private(), 'message': 'Teardown TCP connection'}

    message_dict.update(kwargs)

    return format_log_line("Cisco", "ASA", 5, 106023, message_dict, fmt)

  

def gen_zscaler_web_log(fmt='cef', **kwargs):
    """Generate authentic Zscaler NSS Web log in CEF format."""
    now = datetime.now()
    username = kwargs.get('username', fake.user_name())
    client_ip = kwargs.get('src_ip', fake.ipv4_private())
    server_ip = kwargs.get('dst_ip', fake.ipv4_public())
    host = kwargs.get('ehost', fake.domain_name())
    url = kwargs.get('eurl', f"https://{host}/path/to/resource")
    
    # Realistic Zscaler web log data
    actions = ['Allowed', 'Blocked', 'Monitored']
    action = kwargs.get('action', random.choice(actions))
    reasons = ['Acceptable Use Policy', 'Security Policy', 'Bandwidth Control', 'Content Filtering']
    reason = kwargs.get('reason', random.choice(reasons))
    url_categories = ['Business Use', 'Social Networking', 'Malware', 'Phishing', 'Adult Content']
    url_cat = kwargs.get('urlcat', random.choice(url_categories))
    
    # Generate authentic Zscaler NSS Web log format
    log_line = (f"{now.strftime('%b %d %H:%M:%S')} zscaler-nss "
                f"CEF:0|Zscaler|NSSWeblog|5.0|{action}|{reason}|3|"
                f"act={action} app=HTTP cat={url_cat} dhost={host} dst={server_ip} "
                f"src={client_ip} in={random.randint(1024, 65536)} outcome={random.randint(200, 404)} "
                f"out={random.randint(512, 8192)} request={url} "
                f"rt={now.strftime('%b %d %y %H:%M:%S')} "
                f"sourceTranslatedAddress={fake.ipv4_private()} "
                f"requestClientApplication=Mozilla/5.0 requestMethod=GET suser={username} "
                f"spriv={fake.city()} externalId={random.randint(100000, 999999)} "
                f"fileType=html reason={reason} destinationServiceName=WebService "
                f"cn1={random.randint(1, 100)} cn1Label=riskscore "
                f"cs1={random.choice(DEPARTMENTS)} cs1Label=dept "
                f"cs2=General_Browsing cs2Label=urlsupercat "
                f"cs3=Web_Browser cs3Label=appclass "
                f"cs4=None cs4Label=malwarecat "
                f"cs5=None cs5Label=threatname "
                f"cs6=None cs6Label=dlpeng "
                f"ZscalerNSSWeblogURLClass=Acceptable "
                f"ZscalerNSSWeblogDLPDictionaries=None "
                f"requestContext= contenttype=text/html "
                f"unscannabletype=None deviceowner={username} "
                f"devicehostname={fake.hostname()}")
    
    return {
        'timestamp': now.isoformat(), 'vendor': 'Zscaler', 'product': 'NSSWeblog', 
        'severity': 3, 'event_id': 4001, 'name': action,
        'username': username, 'src_ip': client_ip, 'dst_ip': server_ip,
        'message': f'{action}: {url} - {reason}', 'log_line': log_line
    }

def gen_zscaler_firewall_log(fmt='cef', **kwargs):
    """Generate authentic Zscaler NSS Firewall log in CEF format."""
    now = datetime.now()
    username = kwargs.get('username', fake.user_name())
    client_ip = kwargs.get('src_ip', fake.ipv4_private())
    server_ip = kwargs.get('dst_ip', fake.ipv4_public())
    
    # Realistic firewall log data
    actions = ['Allow', 'Drop', 'Reset']
    action = kwargs.get('action', random.choice(actions))
    protocols = ['TCP', 'UDP', 'ICMP']
    proto = kwargs.get('ipproto', random.choice(protocols))
    src_port = kwargs.get('csport', random.randint(1024, 65535))
    dst_port = kwargs.get('cdport', random.choice([80, 443, 22, 25, 53, 3389]))
    
    rule_labels = ['Corporate_Internet_Access', 'Block_P2P', 'Allow_HTTPS', 'Block_Malware']
    rule_label = kwargs.get('rulelabel', random.choice(rule_labels))
    
    # Generate authentic Zscaler NSS Firewall log format
    log_line = (f"{now.strftime('%b %d %H:%M:%S')} zscaler-nss-fw "
                f"CEF:0|Zscaler|NSSFWlog|5.7|{action}|{rule_label}|3|"
                f"act={action} suser={username} src={client_ip} spt={src_port} "
                f"dst={server_ip} dpt={dst_port} "
                f"deviceTranslatedAddress={fake.ipv4_private()} "
                f"deviceTranslatedPort={random.randint(1024, 65535)} "
                f"destinationTranslatedAddress={server_ip} "
                f"destinationTranslatedPort={dst_port} "
                f"sourceTranslatedAddress={client_ip} "
                f"sourceTranslatedPort={src_port} "
                f"proto={proto} tunnelType=IPSEC dnat=No stateful=Yes "
                f"spriv={fake.city()} reason={rule_label} "
                f"in={random.randint(1024, 1048576)} out={random.randint(512, 524288)} "
                f"rt={now.strftime('%b %d %H:%M:%S')} deviceDirection=1 "
                f"cs1={random.choice(DEPARTMENTS)} cs1Label=dept "
                f"cs2=InternetAccess cs2Label=nwService "
                f"cs3=WebBrowsing cs3Label=nwApp "
                f"cs4=No cs4Label=aggregated "
                f"cs6=None cs6label=threatname "
                f"cn1={random.randint(100, 30000)} cn1Label=durationms "
                f"cn2=1 cn2Label=numsessions "
                f"cs5Label=ipCat cs5=Acceptable "
                f"cat=None destCountry={fake.country_code()} "
                f"avgduration={random.randint(1000, 10000)}")
    
    return {
        'timestamp': now.isoformat(), 'vendor': 'Zscaler', 'product': 'NSSFWlog', 
        'severity': 3, 'event_id': 4002, 'name': action,
        'username': username, 'src_ip': client_ip, 'dst_ip': server_ip,
        'message': f'{action}: {client_ip}:{src_port} -> {server_ip}:{dst_port} ({proto})', 'log_line': log_line
    }

def gen_zscaler_zpa_user_activity_log(fmt='leef', **kwargs):
    """Generate authentic Zscaler ZPA User Activity log in LEEF format."""
    now = datetime.now()
    username = kwargs.get('username', fake.user_name())
    client_public_ip = kwargs.get('src_ip', fake.ipv4_public())
    client_private_ip = kwargs.get('srcPreNAT', fake.ipv4_private())
    server_ip = kwargs.get('dst_ip', fake.ipv4_private())
    
    # ZPA specific data
    connection_statuses = ['ACTIVE', 'CLOSED', 'TIMEOUT']
    connection_status = kwargs.get('ConnectionStatus', random.choice(connection_statuses))
    internal_reasons = ['OK', 'USER_INITIATED', 'POLICY_TIMEOUT', 'NETWORK_ERROR']
    internal_reason = kwargs.get('InternalReason', random.choice(internal_reasons))
    
    session_id = kwargs.get('SessionID', fake.uuid4())
    connection_id = kwargs.get('ConnectionID', fake.uuid4())
    customer = kwargs.get('Customer', 'Corp_Customer_001')
    
    # Generate authentic ZPA User Activity log in LEEF format
    log_line = (f"LEEF:1.0|Zscaler|ZPA|4.1|{connection_status}{internal_reason}|"
                f"cat=ZPA User Activity\tdevTime={int(now.timestamp())}"
                f"\tCustomer={customer}\tSessionID={session_id}"
                f"\tConnectionID={connection_id}\tInternalReason={internal_reason}"
                f"\tConnectionStatus={connection_status}\tproto=6"
                f"\tDoubleEncryption=1\tusrName={username}"
                f"\tdstPort={random.choice([80, 443, 22, 3389])}\tsrc={client_public_ip}"
                f"\tsrcPreNAT={client_private_ip}"
                f"\tClientLatitude={fake.latitude()}\tClientLongitude={fake.longitude()}"
                f"\tClientCountryCode={fake.country_code()}\tClientZEN=ZEN_{fake.city()}"
                f"\tpolicy=Corp_Access_Policy\tConnector={fake.hostname()}-connector"
                f"\tConnectorZEN=ZEN_{fake.city()}\tConnectorIP={fake.ipv4_private()}"
                f"\tConnectorPort={random.randint(1024, 65535)}"
                f"\tApplicationName={fake.domain_name()}\tApplicationSegment=Corp_App_Segment"
                f"\tAppGroup=Production_Apps\tServer={fake.hostname()}"
                f"\tdst={server_ip}\tServerPort={random.choice([80, 443, 22])}"
                f"\tPolicyProcessingTime={random.randint(10, 100)}"
                f"\tServerSetupTime={random.randint(50, 500)}"
                f"\tTimestampConnectionStart:iso8601={now.isoformat()}"
                f"\tTimestampConnectionEnd:iso8601={now.isoformat()}"
                f"\tZENTotalBytesRxClient={random.randint(1024, 1048576)}"
                f"\tZENTotalBytesTxClient={random.randint(512, 524288)}"
                f"\tIdp=ActiveDirectory")
    
    return {
        'timestamp': now.isoformat(), 'vendor': 'Zscaler', 'product': 'ZPA', 
        'severity': 6, 'event_id': 4003, 'name': f'UserActivity_{connection_status}',
        'username': username, 'src_ip': client_public_ip, 'dst_ip': server_ip,
        'message': f'ZPA User Activity: {username} - {connection_status}', 'log_line': log_line
    }

def gen_zscaler_zpa_user_status_log(fmt='leef', **kwargs):
    """Generate authentic Zscaler ZPA User Status log in LEEF format."""
    now = datetime.now()
    username = kwargs.get('username', fake.user_name())
    public_ip = kwargs.get('src_ip', fake.ipv4_public())
    private_ip = kwargs.get('srcPreNAT', fake.ipv4_private())
    
    session_statuses = ['AUTHENTICATED', 'UNAUTHENTICATED', 'EXPIRED']
    session_status = kwargs.get('SessionStatus', random.choice(session_statuses))
    session_id = kwargs.get('SessionID', fake.uuid4())
    customer = kwargs.get('Customer', 'Corp_Customer_001')
    
    # Generate authentic ZPA User Status log in LEEF format  
    log_line = (f"LEEF:1.0|Zscaler|ZPA|4.1|{session_status}|cat=ZPA User Status"
                f"\tdevTime={int(now.timestamp())}\tCustomer={customer}"
                f"\tusrName={username}\tSessionID={session_id}"
                f"\tSessionStatus={session_status}\tVersion=22.41.1"
                f"\tZEN=ZEN_{fake.city()}\tCertificateCN={username}@corp.com"
                f"\tsrcPreNAT={private_ip}\tsrc={public_ip}"
                f"\tLatitude={fake.latitude()}\tLongitude={fake.longitude()}"
                f"\tCountryCode={fake.country_code()}"
                f"\tTimestampAuthentication:iso8601={now.isoformat()}"
                f"\tdstBytes={random.randint(1024, 1048576)}"
                f"\tsrcBytes={random.randint(512, 524288)}\tIdp=ActiveDirectory"
                f"\tidentHostName={fake.hostname()}\tPlatform=Windows"
                f"\tClientType=ZPA_CLIENT")
    
    return {
        'timestamp': now.isoformat(), 'vendor': 'Zscaler', 'product': 'ZPA', 
        'severity': 6, 'event_id': 4004, 'name': f'UserStatus_{session_status}',
        'username': username, 'src_ip': public_ip, 'dst_ip': 'N/A',
        'message': f'ZPA User Status: {username} - {session_status}', 'log_line': log_line
    }

def gen_zscaler_zpa_connector_log(fmt='leef', **kwargs):
    """Generate authentic Zscaler ZPA App Connector log in LEEF format."""
    now = datetime.now()
    public_ip = kwargs.get('src_ip', fake.ipv4_public())
    private_ip = kwargs.get('srcPreNAT', fake.ipv4_private())
    
    session_statuses = ['CONNECTED', 'DISCONNECTED', 'AUTHENTICATED']
    session_status = kwargs.get('SessionStatus', random.choice(session_statuses))
    session_id = kwargs.get('SessionID', fake.uuid4())
    customer = kwargs.get('Customer', 'Corp_Customer_001')
    connector_name = f"{fake.hostname()}-connector"
    
    # Generate authentic ZPA App Connector log in LEEF format
    log_line = (f"LEEF:1.0|Zscaler|ZPA|4.1|{session_status}|cat=Connector Status"
                f"\tdevTime={int(now.timestamp())}\tCustomer={customer}"
                f"\tSessionID={session_id}\tSessionType=CONNECTOR"
                f"\tVersion=22.41.1\tPlatform=Linux\tZEN=ZEN_{fake.city()}"
                f"\tConnector={connector_name}\tConnectorGroup=Production_Connectors"
                f"\tsrcPreNAT={private_ip}\tsrc={public_ip}"
                f"\tLatitude={fake.latitude()}\tLongitude={fake.longitude()}"
                f"\tCountryCode={fake.country_code()}"
                f"\tTimestampAuthentication:iso8601={now.isoformat()}"
                f"\tCPUUtilization={random.randint(10, 80)}"
                f"\tMemUtilization={random.randint(20, 70)}"
                f"\tServiceCount={random.randint(5, 25)}"
                f"\tInterfaceDefRoute=eth0\tDefRouteGW={fake.ipv4_private()}"
                f"\tPrimaryDNSResolver={fake.ipv4_private()}"
                f"\tNumOfInterfaces=2\tTotalBytesRx={random.randint(1048576, 10485760)}"
                f"\tTotalBytesTx={random.randint(524288, 5242880)}")
    
    return {
        'timestamp': now.isoformat(), 'vendor': 'Zscaler', 'product': 'ZPA', 
        'severity': 6, 'event_id': 4005, 'name': f'ConnectorStatus_{session_status}',
        'username': 'N/A', 'src_ip': public_ip, 'dst_ip': 'N/A',
        'message': f'ZPA Connector Status: {connector_name} - {session_status}', 'log_line': log_line
    }

def gen_zscaler_zpa_audit_log(fmt='leef', **kwargs):
    """Generate authentic Zscaler ZPA Audit log in LEEF format."""
    now = datetime.now()
    username = kwargs.get('username', fake.user_name())
    
    # ZPA audit operations
    audit_operations = ['CREATE', 'UPDATE', 'DELETE', 'READ']
    operation = kwargs.get('auditOperationType', random.choice(audit_operations))
    
    object_types = ['APPLICATION_SEGMENT', 'ACCESS_POLICY', 'CONNECTOR', 'USER']
    object_type = kwargs.get('objectType', random.choice(object_types))
    object_name = kwargs.get('objectName', f'{object_type.lower()}_001')
    
    request_id = kwargs.get('requestId', fake.uuid4())
    session_id = kwargs.get('sessionId', fake.uuid4())
    customer_id = kwargs.get('customerId', random.randint(100000, 999999))
    
    # Generate authentic ZPA Audit log in LEEF format
    log_line = (f"LEEF:1.0|Zscaler|ZPA|4.1|{operation}|cat=ZPA_Audit_Log\t"
                f"devTime={int(now.timestamp())}\t"
                f"creationTime={now.isoformat()}\t"
                f"requestId={request_id}\t"
                f"sessionId={session_id}\t"
                f"auditOldValue=\t"
                f"auditNewValue=\t"
                f"auditOperationType={operation}\t"
                f"objectType={object_type}\t"
                f"objectName={object_name}\t"
                f"objectId={random.randint(1000, 9999)}\t"
                f"accountName={customer_id}\t"
                f"usrName={username}")
    
    return {
        'timestamp': now.isoformat(), 'vendor': 'Zscaler', 'product': 'ZPA_Audit', 
        'severity': 6, 'event_id': 4006, 'name': f'Audit_{operation}',
        'username': username, 'src_ip': 'N/A', 'dst_ip': 'N/A',
        'message': f'ZPA Audit: {operation} {object_type} {object_name}', 'log_line': log_line
    }

# Legacy function for backward compatibility
def gen_zscaler_log(fmt='cef', **kwargs):
    """Legacy Zscaler log generator - delegates to Web Proxy for backward compatibility."""
    return gen_zscaler_web_log(fmt=fmt, **kwargs)
    message_dict.update(kwargs)

    return format_log_line("Zscaler", "Web Proxy", 8, 4000, message_dict, fmt)

  

def gen_proofpoint_log(fmt='cef', **kwargs):

    message_dict = {'name': 'Malicious URL Clicked', 'username': fake.user_name(), 'src_ip': fake.ipv4_private(), 'message': 'User clicked a malicious link in an email'}

    message_dict.update(kwargs)

    return format_log_line("Proofpoint", "Email Security", 9, 5000, message_dict, fmt)

  

def gen_mde_log(fmt='cef', **kwargs):

    message_dict = {'name': 'LSASS Memory Access', 'username': fake.user_name(), 'src_ip': fake.ipv4_private(), 'message': 'Suspicious process accessed LSASS memory'}

    message_dict.update(kwargs)

    return format_log_line("Microsoft", "Defender for Endpoint", 10, 6000, message_dict, fmt)

  

def gen_crowdstrike_log(fmt='cef', **kwargs):

    message_dict = {'name': 'Process Spawning from Office App', 'username': fake.user_name(), 'src_ip': fake.ipv4_private(), 'message': 'winword.exe spawned powershell.exe'}

    message_dict.update(kwargs)

    return format_log_line("CrowdStrike", "Falcon", 8, 7000, message_dict, fmt)

  

def gen_sentinelone_log(fmt='cef', **kwargs):

    message_dict = {'name': 'Ransomware Behavior Detected', 'username': fake.user_name(), 'src_ip': fake.ipv4_private(), 'message': 'A process is rapidly encrypting files'}

    message_dict.update(kwargs)

    return format_log_line("SentinelOne", "EDR", 10, 8000, message_dict, fmt)

  

def gen_dropbox_log(fmt='cef', **kwargs):

    message_dict = {'name': 'file.download', 'username': fake.user_name(), 'src_ip': fake.ipv4_public(), 'message': 'User downloaded a file from Dropbox'}

    message_dict.update(kwargs)

    return format_log_line("Dropbox", "Events", 3, 17000, message_dict, fmt)

  

def gen_windows_event_collector_log(fmt='cef', **kwargs):

    message_dict = {'name': 'Forwarded Event', 'username': fake.user_name(), 'src_ip': fake.ipv4_private(), 'message': 'An event was forwarded by the collector'}

    message_dict.update(kwargs)

    return format_log_line("Windows", "Event Collector", 2, 18000, message_dict, fmt)

  

# --- Story Generators ---

  

def send_log(log_function, sock, csv_writer, dest_ip, dest_port, fmt='cef', **kwargs):

    """Helper function to generate, send, and queue a single log."""

    if session_state['stop_event'].is_set(): return

    log_dict = log_function(fmt=fmt, **kwargs)

    log_line = log_dict['log_line']

    try:

        socket.inet_aton(dest_ip)

        resolved_ip = dest_ip

    except socket.error:

        try:

            resolved_ip = socket.gethostbyname(dest_ip)

        except socket.gaierror:

            raise ConnectionError(f"Could not resolve hostname: {dest_ip}")

  

    sock.sendto(log_line.encode('utf-8'), (resolved_ip, dest_port))

    if csv_writer: csv_writer.writerow(log_dict)

    with session_lock:

        session_state['logs_queue'].append(f'data: {json.dumps({"log": log_line})}\n\n')

    # Use a shorter, more controlled sleep for noise generation

    if kwargs.get('is_noise'):

        time.sleep(random.uniform(0.1, 0.5))

    else:

        time.sleep(random.uniform(0.5, 2.0))

  

def rogue_insider_story(config, sock, csv_writer):

    """Generates logs for a rogue insider scenario."""

    dest_ip = config.get('dest_ip', '127.0.0.1')

    dest_port = int(config.get('dest_port', 514))

    insider_username = fake.user_name()

    insider_ip = fake.ipv4_private()

  

    send_log(gen_okta_audit_log, sock, csv_writer, dest_ip, dest_port,

             username=insider_username, 

             message=f'User {insider_username} added to "Domain Admins" group')

  

    sensitive_files = ["Q4_Financial_Forecast.xlsx", "Project_Phoenix_Roadmap.pdf", "employee_salary_data_2025.csv"]

    for fname in sensitive_files:

        send_log(gen_dropbox_log, sock, csv_writer, dest_ip, dest_port,

                 username=insider_username, 

                 src_ip=insider_ip,

                 message=f'User {insider_username} downloaded file "{fname}"')

  

    send_log(gen_proofpoint_log, sock, csv_writer, dest_ip, dest_port,

             username=insider_username,

             src_ip=insider_ip,

             message=f'Outbound email to personal address with large attachment detected from {insider_username}')

    send_log(gen_google_workspace_audit_log, sock, csv_writer, dest_ip, dest_port,

             username=insider_username,

             name='drive.delete',

             message=f'User {insider_username} deleted an item from Google Drive audit log')

  

def web_server_breach_story(config, sock, csv_writer):

    """Generates logs for a web server breach scenario."""

    dest_ip = config.get('dest_ip', '127.0.0.1')

    dest_port = int(config.get('dest_port', 514))

    attacker_ip = fake.ipv4_public()

    web_server_ip = fake.ipv4_private()

  

    send_log(gen_panos_log, sock, csv_writer, dest_ip, dest_port,

             src_ip=attacker_ip, dst_ip=web_server_ip,

             message='SQL Injection attempt detected against web server')

    send_log(gen_crowdstrike_log, sock, csv_writer, dest_ip, dest_port,

             src_ip=web_server_ip,

             message=f'Web server process (w3wp.exe) spawned cmd.exe')

  

    send_log(gen_mde_log, sock, csv_writer, dest_ip, dest_port,

             src_ip=web_server_ip,

             message='LSASS memory accessed by suspicious process originating from web server')

  

    send_log(gen_zscaler_log, sock, csv_writer, dest_ip, dest_port,

             src_ip=web_server_ip, dst_ip=random.choice(KNOWN_BAD_IPS),

             message='C2 Beaconing detected from web server')

  

def brute_force_data_theft_story(config, sock, csv_writer):

    """Generates logs for a brute-force and data theft scenario."""

    dest_ip = config.get('dest_ip', '127.0.0.1')

    dest_port = int(config.get('dest_port', 514))

    attacker_ip = fake.ipv4_public()

    target_user = fake.user_name()

  

    for _ in range(10): # Simulate multiple failed logins

        send_log(gen_azure_signin_log, sock, csv_writer, dest_ip, dest_port,

                 username=target_user, src_ip=attacker_ip,

                 name='UserLoginFailed', message='Failed user sign-in attempt')

  

    send_log(gen_azure_signin_log, sock, csv_writer, dest_ip, dest_port,

             username=target_user, src_ip=attacker_ip,

             message='Successful user sign-in')

  

    send_log(gen_m365_email_log, sock, csv_writer, dest_ip, dest_port,

             username=target_user,

             message='Email forwarding rule created to external address')

  

    send_log(gen_gcp_audit_log, sock, csv_writer, dest_ip, dest_port,

             username=target_user, src_ip=attacker_ip,

             message='storage.buckets.update IAM policy changed to public')

  

def aws_compromise_story(config, sock, csv_writer):

    """Generates logs for an AWS compromise scenario."""

    dest_ip = config.get('dest_ip', '127.0.0.1')

    dest_port = int(config.get('dest_port', 514))

    attacker_ip = fake.ipv4_public()

    compromised_user = fake.user_name()

  

    send_log(gen_aws_cloudtrail_log, sock, csv_writer, dest_ip, dest_port,

             username=compromised_user, src_ip=attacker_ip,

             message=f'Successful AWS Console login for user {compromised_user} from unusual IP')

  

    send_log(gen_aws_cloudtrail_log, sock, csv_writer, dest_ip, dest_port,

             username=compromised_user, src_ip=attacker_ip, name='CreateUser',

             message='New IAM user "backdoor_user" created')

  

    send_log(gen_aws_cloudtrail_log, sock, csv_writer, dest_ip, dest_port,

             username=compromised_user, src_ip=attacker_ip, name='AttachUserPolicy',

             message='AdministratorAccess policy attached to user "backdoor_user"')

  

    send_log(gen_aws_vpc_flow_log, sock, csv_writer, dest_ip, dest_port,

             src_ip=fake.ipv4_private(), dst_ip=random.choice(KNOWN_BAD_IPS),

             message='Large volume of data egress observed from internal instance to known malicious IP')

  

def gcp_compromise_story(config, sock, csv_writer):

    """Generates logs for a GCP compromise scenario."""

    dest_ip = config.get('dest_ip', '127.0.0.1')

    dest_port = int(config.get('dest_port', 514))

    attacker_ip = fake.ipv4_public()

    compromised_sa = f"compromised-sa@{fake.word()}.iam.gserviceaccount.com"

  

    send_log(gen_gcp_audit_log, sock, csv_writer, dest_ip, dest_port,

             username=attacker_ip, name='v1.iam.serviceAccounts.keys.create',

             message=f'New service account key created for {compromised_sa}')

  

    send_log(gen_gcp_audit_log, sock, csv_writer, dest_ip, dest_port,

             username=compromised_sa, src_ip=attacker_ip, name='v1.storage.buckets.update',

             message='IAM policy on sensitive-data-bucket changed to public')

  

    send_log(gen_gcp_flow_log, sock, csv_writer, dest_ip, dest_port,

             src_ip=fake.ipv4_private(), dst_ip=attacker_ip,

             message='Anomalous data transfer from internal GCS bucket to external IP')

  

def azure_compromise_story(config, sock, csv_writer):

    """Generates logs for an Azure compromise scenario."""

    dest_ip = config.get('dest_ip', '127.0.0.1')

    dest_port = int(config.get('dest_port', 514))

    attacker_ip = fake.ipv4_public()

    target_user = fake.user_name()

  

    send_log(gen_azure_signin_log, sock, csv_writer, dest_ip, dest_port,

             username=target_user, src_ip=attacker_ip,

             message='Successful sign-in from unfamiliar location')

  

    send_log(gen_azure_ad_audit_log, sock, csv_writer, dest_ip, dest_port,

             username=target_user, name='Add owner to application',

             message='Owner added to a high-privilege enterprise application')

  

    send_log(gen_azure_audit_log, sock, csv_writer, dest_ip, dest_port,

             username=target_user, src_ip=attacker_ip, name='Microsoft.Storage/storageAccounts/listkeys/action',

             message='Storage account keys listed for production_data_storage')

  

    send_log(gen_azure_flow_log, sock, csv_writer, dest_ip, dest_port,

             src_ip=fake.ipv4_private(), dst_ip=random.choice(KNOWN_BAD_IPS),

             message='High-volume data egress from Azure storage to known malicious IP')

  

# --- MITRE ATT&CK Tactic Stories ---

def reconnaissance_story(config, sock, csv_writer):

    dest_ip = config.get('dest_ip', '127.0.0.1')

    dest_port = int(config.get('dest_port', 514))

    send_log(gen_panos_log, sock, csv_writer, dest_ip, dest_port, src_ip=fake.ipv4_public(), dst_ip=fake.ipv4_public(), message='Network port scan detected from external source')

  

def resource_development_story(config, sock, csv_writer):

    dest_ip = config.get('dest_ip', '127.0.0.1')

    dest_port = int(config.get('dest_port', 514))

    send_log(gen_gcp_audit_log, sock, csv_writer, dest_ip, dest_port, username='suspicious_user', message='New VM instance created with public IP')

  

def initial_access_story(config, sock, csv_writer):

    dest_ip = config.get('dest_ip', '127.0.0.1')

    dest_port = int(config.get('dest_port', 514))

    send_log(gen_proofpoint_log, sock, csv_writer, dest_ip, dest_port, message=f'User clicked a malicious link in a phishing email to {random.choice(KNOWN_BAD_URLS)}')

  

def execution_story(config, sock, csv_writer):

    dest_ip = config.get('dest_ip', '127.0.0.1')

    dest_port = int(config.get('dest_port', 514))

    send_log(gen_crowdstrike_log, sock, csv_writer, dest_ip, dest_port, message='powershell.exe executed with encoded command')

  

def persistence_story(config, sock, csv_writer):

    dest_ip = config.get('dest_ip', '127.0.0.1')

    dest_port = int(config.get('dest_port', 514))

    send_log(gen_azure_ad_audit_log, sock, csv_writer, dest_ip, dest_port, message='New user account created and added to Global Administrators')

  

def privilege_escalation_story(config, sock, csv_writer):

    dest_ip = config.get('dest_ip', '127.0.0.1')

    dest_port = int(config.get('dest_port', 514))

    send_log(gen_okta_audit_log, sock, csv_writer, dest_ip, dest_port, message='User privilege escalated to Super Admin')

  

def defense_evasion_story(config, sock, csv_writer):

    dest_ip = config.get('dest_ip', '127.0.0.1')

    dest_port = int(config.get('dest_port', 514))

    send_log(gen_windows_event_collector_log, sock, csv_writer, dest_ip, dest_port, name='System Event Log Cleared', message='The system event log was cleared by an administrator')

  

def credential_access_story(config, sock, csv_writer):

    dest_ip = config.get('dest_ip', '127.0.0.1')

    dest_port = int(config.get('dest_port', 514))

    send_log(gen_mde_log, sock, csv_writer, dest_ip, dest_port)

  

def discovery_story(config, sock, csv_writer):

    dest_ip = config.get('dest_ip', '127.0.0.1')

    dest_port = int(config.get('dest_port', 514))

    send_log(gen_windows_event_collector_log, sock, csv_writer, dest_ip, dest_port, name='Network Discovery Command', message='Command executed: netstat -an')

  

def lateral_movement_story(config, sock, csv_writer):

    dest_ip = config.get('dest_ip', '127.0.0.1')

    dest_port = int(config.get('dest_port', 514))

    send_log(gen_azure_signin_log, sock, csv_writer, dest_ip, dest_port, src_ip=fake.ipv4_private(), message='Successful remote login to another host on the network')

  

def collection_story(config, sock, csv_writer):

    dest_ip = config.get('dest_ip', '127.0.0.1')

    dest_port = int(config.get('dest_port', 514))

    send_log(gen_dropbox_log, sock, csv_writer, dest_ip, dest_port, message='Large number of files downloaded from multiple folders')

  

def command_and_control_story(config, sock, csv_writer):

    dest_ip = config.get('dest_ip', '127.0.0.1')

    dest_port = int(config.get('dest_port', 514))

    send_log(gen_zscaler_log, sock, csv_writer, dest_ip, dest_port)

  

def exfiltration_story(config, sock, csv_writer):

    dest_ip = config.get('dest_ip', '127.0.0.1')

    dest_port = int(config.get('dest_port', 514))

    send_log(gen_m365_email_log, sock, csv_writer, dest_ip, dest_port, message='Email sent to external domain with large encrypted attachment')

  

def impact_story(config, sock, csv_writer):

    dest_ip = config.get('dest_ip', '127.0.0.1')

    dest_port = int(config.get('dest_port', 514))

    send_log(gen_sentinelone_log, sock, csv_writer, dest_ip, dest_port)

  

# --- NOISE GENERATION ---

def add_story_noise(config, sock, csv_writer):

    """Adds random, unrelated logs to a story."""

    dest_ip = config.get('dest_ip', '127.0.0.1')

    dest_port = int(config.get('dest_port', 514))

    noise_generators = [

        gen_azure_flow_log, gen_gcp_flow_log, gen_duo_log, gen_okta_sso_log,

        gen_panos_log, gen_google_workspace_auth_log, gen_windows_event_collector_log,

        gen_zscaler_web_log, gen_zscaler_firewall_log, gen_zscaler_zpa_user_status_log

    ]

    for _ in range(random.randint(50, 100)):

        if session_state['stop_event'].is_set(): break

        log_function = random.choice(noise_generators)

        send_log(log_function, sock, csv_writer, dest_ip, dest_port, is_noise=True)

  
  

# --- SESSION MANAGEMENT ---

def generate_logs_session(config):

    send_mode = config.get('send_mode', 'random')

    dest_ip = config.get('dest_ip', '127.0.0.1')

    dest_port = int(config.get('dest_port', 514))

    fmt = config.get('log_format', 'cef')

    if send_mode == 'story': fmt = 'cef'

    save_file = config.get('save_file', False)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    fhandle, csv_writer = None, None

    if save_file:

        os.makedirs(LOG_DIR, exist_ok=True)

        filename = f"syslog_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{fmt}.csv"

        file_path = os.path.join(LOG_DIR, filename)

        fhandle = open(file_path, 'w', newline='', encoding='utf-8')

        fieldnames = ['timestamp', 'vendor', 'product', 'severity', 'event_id', 'name', 'username', 'src_ip', 'dst_ip', 'message', 'log_line']

        csv_writer = csv.DictWriter(fhandle, fieldnames=fieldnames, extrasaction='ignore')

        csv_writer.writeheader()

  

    try:

        if send_mode == 'random':

            run_randomization_session(config, sock, csv_writer)

        elif send_mode == 'story':

            run_story_session(config, sock, csv_writer)

        with session_lock:

             if not session_state['stop_event'].is_set():

                session_state['logs_queue'].append(f'data: {json.dumps({"status": "Session completed.", "type": "success", "is_running": False, "is_paused": False})}\n\n')

  

    except Exception as e:

        print(f"Error in generator thread: {e}")

        with session_lock:

            error_message = f"Error in generator: {e}"

            session_state['logs_queue'].append(f'data: {json.dumps({"status": error_message, "type": "danger", "is_running": False, "is_paused": False})}\n\n')

    finally:

        sock.close()

        if fhandle: fhandle.close()

        with session_lock:

            session_state['is_running'] = False

            session_state['is_paused'] = False

            session_state['thread'] = None

  

def run_randomization_session(config, sock, csv_writer):

    duration_minutes = int(config.get('duration_minutes', 1))

    messages_per_second = int(config.get('messages_per_second', 10))

    fmt = config.get('log_format', 'cef')

    dest_ip = config.get('dest_ip', '127.0.0.1')

    dest_port = int(config.get('dest_port', 514))

    is_custom_mode = 'custom_vendor' in config and config.get('custom_vendor') and 'custom_product' in config and config.get('custom_product')

  

    log_generators = {

        "AWS-CloudTrail": gen_aws_cloudtrail_log, "AWS-VPC Flow Logs": gen_aws_vpc_flow_log,

        "Azure-Audit Logs": gen_azure_audit_log, "Azure-Flow Logs": gen_azure_flow_log, "Azure-Signin Log": gen_azure_signin_log,

        "Azure-AD Audit Logs": gen_azure_ad_audit_log, "GCP-Audit Logs": gen_gcp_audit_log, "GCP-Flow Logs": gen_gcp_flow_log,

        "Kubernetes-Audit Logs": gen_kubernetes_audit_log, "Okta-SSO": gen_okta_sso_log, "Okta-Audit": gen_okta_audit_log,

        "Duo-Authentication": gen_duo_log, "PingOne-SSO": gen_pingone_log, "OneLogin-Events": gen_onelogin_log,

        "Google Workspace-Audit": gen_google_workspace_audit_log, "Google Workspace-Authentication": gen_google_workspace_auth_log,

        "Microsoft 365-Email Logs": gen_m365_email_log, "Palo Alto Networks-PAN-OS": gen_panos_log, "Cisco-ASA": gen_cisco_asa_log,

        "Zscaler-Web Proxy": gen_zscaler_web_log, "Zscaler-NSS Firewall": gen_zscaler_firewall_log,
        "Zscaler-ZPA User Activity": gen_zscaler_zpa_user_activity_log, "Zscaler-ZPA User Status": gen_zscaler_zpa_user_status_log,
        "Zscaler-ZPA Connector": gen_zscaler_zpa_connector_log, "Zscaler-ZPA Audit": gen_zscaler_zpa_audit_log,
        "Proofpoint-Email Security": gen_proofpoint_log,

        "Microsoft-Defender for Endpoint": gen_mde_log, "CrowdStrike-Falcon": gen_crowdstrike_log,

        "SentinelOne-EDR": gen_sentinelone_log, "Dropbox-Events": gen_dropbox_log, "Windows-Event Collector": gen_windows_event_collector_log

    }

    if not is_custom_mode:

        selected_products = config.get('products', [])

        if not selected_products: return

  

    end_time = time.time() + (duration_minutes * 60)

    sleep_interval = 1.0 / messages_per_second

  

    while time.time() < end_time and not session_state['stop_event'].is_set():

        if session_state['pause_event'].is_set():

            time.sleep(0.5)

            continue

  

        if is_custom_mode:

            send_log(gen_custom_log, sock, csv_writer, dest_ip, dest_port, fmt=fmt, 

                     custom_vendor=config['custom_vendor'], 

                     custom_product=config['custom_product'])

        else:

            product_to_gen = random.choice(selected_products)

            log_function = log_generators.get(product_to_gen)

            if log_function:

                send_log(log_function, sock, csv_writer, dest_ip, dest_port, fmt=fmt)

        time.sleep(sleep_interval)

  
  

def run_story_session(config, sock, csv_writer):

    story_type = config.get('story_type')

    add_noise = config.get('add_noise')

    story_functions = {

        'rogue_insider_story': rogue_insider_story,

        'web_server_breach_story': web_server_breach_story,

        'brute_force_data_theft_story': brute_force_data_theft_story,

        'aws_compromise_story': aws_compromise_story,

        'gcp_compromise_story': gcp_compromise_story,

        'azure_compromise_story': azure_compromise_story,

        'reconnaissance_story': reconnaissance_story,

        'resource_development_story': resource_development_story,

        'initial_access_story': initial_access_story,

        'execution_story': execution_story,

        'persistence_story': persistence_story,

        'privilege_escalation_story': privilege_escalation_story,

        'defense_evasion_story': defense_evasion_story,

        'credential_access_story': credential_access_story,

        'discovery_story': discovery_story,

        'lateral_movement_story': lateral_movement_story,

        'collection_story': collection_story,

        'command_and_control_story': command_and_control_story,

        'exfiltration_story': exfiltration_story,

        'impact_story': impact_story,

    }

  

    story_func = story_functions.get(story_type)

    if story_func:

        if add_noise:

            noise_thread = threading.Thread(target=add_story_noise, args=(config, sock, csv_writer))

            noise_thread.daemon = True

            noise_thread.start()

        story_func(config, sock, csv_writer)

  

        if add_noise:

            noise_thread.join()

    else:

        message = f"Story '{story_type}' is not yet implemented. Stopping session."

        with session_lock:

            session_state['logs_queue'].append(f'data: {json.dumps({"status": message, "type": "warning", "is_running": False, "is_paused": False})}\n\n')

        time.sleep(1)

  
  

# --- FLASK ROUTES ---

@app.route('/')

def index():

    return render_template_string(HTML)

  

@app.route('/start', methods=['POST'])

def start_generation():
    with session_lock:
        if session_state['thread'] and session_state['thread'].is_alive():
            return jsonify({'success': False, 'message': 'A session is already running.'})

        config = request.json or {}
        config['log_format'] = 'cef'

        session_state['stop_event'].clear()
        session_state['pause_event'].clear()
        session_state['logs_queue'].clear()
        session_state['is_running'] = True
        session_state['is_paused'] = False
        session_state['xgen_mode'] = False

        # Determine if this is an XGen-driven session
        story_type = config.get('story_type') or ''
        if story_type.startswith('apt_campaign:') or story_type.startswith('pattern:'):
            # Build XGen config
            xgen_config = {}
            if story_type.startswith('apt_campaign:'):
                xgen_config['send_mode'] = 'apt_campaign'
                xgen_config['apt_group'] = story_type.split(':', 1)[1]
                xgen_config['duration_minutes'] = int(config.get('duration_minutes', 60))
                xgen_config['intensity'] = config.get('intensity', 'medium')
            else:
                xgen_config['send_mode'] = 'pattern_burst'
                xgen_config['pattern_id'] = story_type.split(':', 1)[1]

            # Transport toggles
            xgen_config['enable_syslog'] = bool(config.get('enable_syslog', True))
            xgen_config['enable_xsiam_http'] = bool(config.get('enable_xsiam_http', True))
            xgen_config['enable_webhook'] = bool(config.get('enable_webhook', True))
            xgen_config['dest_ip'] = config.get('dest_ip', '127.0.0.1')
            xgen_config['dest_port'] = int(config.get('dest_port', 514))

            # Start XGen session
            result = xgen_session.start_burst_session(xgen_config) if XGEN_AVAILABLE else {"success": False, "message": "XGen not available"}
            if not result.get('success'):
                session_state['is_running'] = False
                return jsonify({'success': False, 'message': result.get('message', 'Failed to start XGen session')})

            session_state['xgen_mode'] = True

            # Start bridge thread to stream XGen events into existing SSE queue
            def bridge_events():
                try:
                    while True:
                        events = xgen_session.get_events_for_streaming()
                        with session_lock:
                            for e in events:
                                session_state['logs_queue'].append(e)
                            running = xgen_session.is_running
                        if not running and not events:
                            break
                        time.sleep(0.2)
                except Exception as e:
                    with session_lock:
                        session_state['logs_queue'].append(f'data: {{"status": "Bridge error: {str(e)}", "type": "danger", "is_running": false, "is_paused": false}}\n\n')

            session_state['thread'] = threading.Thread(target=bridge_events, daemon=True)
            session_state['thread'].start()
            return jsonify({'success': True, 'message': 'XGen session started.'})

        # Otherwise, run legacy generator session
        session_state['thread'] = threading.Thread(target=generate_logs_session, args=(config,))
        session_state['thread'].daemon = True
        session_state['thread'].start()
        return jsonify({'success': True, 'message': 'Log generation started.'})

  

@app.route('/pause', methods=['POST'])

def pause_generation():
    with session_lock:
        if not session_state['is_running']:
            return jsonify({'success': False, 'message': 'No session is running.'})

        # If XGen, delegate pause/resume
        if session_state.get('xgen_mode') and XGEN_AVAILABLE:
            result = xgen_session.pause_resume()
            session_state['is_paused'] = result.get('is_paused', session_state['is_paused'])
            message = result.get('message', 'Toggled pause')
        else:
            if session_state['is_paused']:
                session_state['pause_event'].clear()
                session_state['is_paused'] = False
                message = 'Session resumed.'
            else:
                session_state['pause_event'].set()
                session_state['is_paused'] = True
                message = 'Session paused.'

        return jsonify({
            'success': True, 'message': message,
            'is_running': session_state['is_running'],
            'is_paused': session_state['is_paused']
        })

  

@app.route('/stop', methods=['POST'])

def stop_generation():
    with session_lock:
        if not session_state['is_running']:
            return jsonify({'success': False, 'message': 'No session is running.'})

        # If XGen, request stop
        if session_state.get('xgen_mode') and XGEN_AVAILABLE:
            try:
                xgen_session.stop()
            except Exception:
                pass

        session_state['stop_event'].set()
        session_state['pause_event'].clear()

    if session_state['thread']:
        session_state['thread'].join(timeout=2)

    with session_lock:
        session_state['is_running'] = False
        session_state['is_paused'] = False
        session_state['thread'] = None
        session_state['xgen_mode'] = False

    return jsonify({'success': True, 'message': 'Log generation stopped.'})

  

@app.route('/status')

def status():

    with session_lock:

        message = "Session is running." if session_state['is_running'] else "No active session."

        if session_state['is_running'] and session_state['is_paused']:

            message = "Session is paused."

        return jsonify({

            'is_running': session_state['is_running'],

            'is_paused': session_state['is_paused'],

            'message': message

        })

  

@app.route('/stream')

def stream():

    def event_stream():

        last_sent_index = 0

        while True:

            with session_lock:

                if not session_state['is_running'] and last_sent_index >= len(session_state['logs_queue']):

                    break

                queue_len = len(session_state['logs_queue'])

                if last_sent_index < queue_len:

                    for i in range(last_sent_index, queue_len):

                        yield session_state['logs_queue'][i]

                    last_sent_index = queue_len

            time.sleep(0.1)

    return Response(event_stream(), mimetype='text/event-stream')

  

if __name__ == '__main__':

    app.run(debug=True, threaded=True, host='0.0.0.0', port=5001)

  
