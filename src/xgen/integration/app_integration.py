"""
Integration layer for connecting the new burst generation engine 
to the existing Flask application.
"""

import os
import sys
import threading
import time
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from uuid import UUID, uuid4

# Add the src directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../..'))

from src.xgen.core.burst_generator import BurstGenerator
from src.xgen.core.models import BaseEvent, LogFormat, TransportType
from src.xgen.formats.renderers import render_events
from src.xgen.transports.adapters import create_transport_adapter
from src.xgen.ttp.mitre_patterns import (
    get_patterns_by_apt_group, get_pattern_by_id, APTGroup,
    ENTERPRISE_PERSISTENCE_PATTERNS, CLOUD_PERSISTENCE_PATTERNS,
    LATERAL_MOVEMENT_PATTERNS, PRIVILEGE_ESCALATION_PATTERNS
)

logger = logging.getLogger(__name__)


class XGenSession:
    """
    Enhanced session manager that integrates burst generation
    with the existing Flask application.
    """
    
    def __init__(self):
        self.burst_generator = BurstGenerator()
        self.session_id: Optional[UUID] = None
        self.is_running = False
        self.is_paused = False
        self.stop_event = threading.Event()
        self.pause_event = threading.Event()
        self.thread: Optional[threading.Thread] = None
        self.transports: List[Any] = []
        self.stats = {
            "events_generated": 0,
            "events_sent": 0,
            "events_failed": 0,
            "start_time": None,
            "end_time": None,
            "patterns_executed": []
        }
        self.event_queue = []
        self.queue_lock = threading.Lock()
    
    def start_burst_session(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Start a burst generation session."""
        
        if self.is_running:
            return {"success": False, "message": "Session already running"}
        
        try:
            # Parse configuration
            session_config = self._parse_config(config)
            
            # Initialize transports
            self._initialize_transports(session_config)
            
            # Start generation thread
            self.session_id = uuid4()
            self.stop_event.clear()
            self.pause_event.clear()
            self.is_running = True
            self.is_paused = False
            self.stats["start_time"] = datetime.now(timezone.utc).isoformat()
            self.stats["events_generated"] = 0
            self.stats["events_sent"] = 0
            self.stats["events_failed"] = 0
            self.stats["patterns_executed"] = []
            
            self.thread = threading.Thread(
                target=self._run_burst_generation,
                args=(session_config,),
                daemon=True
            )
            self.thread.start()
            
            return {
                "success": True,
                "message": "Burst generation session started",
                "session_id": str(self.session_id)
            }
            
        except Exception as e:
            logger.error(f"Failed to start burst session: {e}")
            return {"success": False, "message": str(e)}
    
    def _parse_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Parse and validate configuration."""
        
        # Extract APT group or pattern selection
        send_mode = config.get("send_mode", "random")
        
        if send_mode == "apt_campaign":
            # New APT campaign mode
            apt_group = config.get("apt_group", APTGroup.APT29)
            duration_hours = float(config.get("duration_minutes", 60)) / 60.0
            intensity = config.get("intensity", "medium")
            
            return {
                "mode": "apt_campaign",
                "apt_group": apt_group,
                "duration_hours": duration_hours,
                "intensity": intensity,
                "dest_ip": config.get("dest_ip", "127.0.0.1"),
                "dest_port": int(config.get("dest_port", 514)),
                "log_format": config.get("log_format", "cef"),
                "save_file": config.get("save_file", False),
                "transports": self._parse_transports(config)
            }
        
        elif send_mode == "pattern_burst":
            # Single pattern burst mode
            pattern_id = config.get("pattern_id")
            if not pattern_id:
                raise ValueError("pattern_id required for pattern_burst mode")
            
            pattern = get_pattern_by_id(pattern_id)
            if not pattern:
                raise ValueError(f"Pattern not found: {pattern_id}")
            
            return {
                "mode": "pattern_burst",
                "pattern": pattern,
                "dest_ip": config.get("dest_ip", "127.0.0.1"),
                "dest_port": int(config.get("dest_port", 514)),
                "log_format": config.get("log_format", "cef"),
                "save_file": config.get("save_file", False),
                "transports": self._parse_transports(config)
            }
        
        elif send_mode == "custom_csv" or config.get("csv_path"):
            # Custom CSV ingestion mode
            return {
                "mode": "custom_csv",
                "csv_path": config.get("csv_path"),
                "default_vendor": config.get("custom_vendor") or config.get("default_vendor") or "Custom",
                "default_product": config.get("custom_product") or config.get("default_product") or "Generic",
                "dest_ip": config.get("dest_ip", "127.0.0.1"),
                "dest_port": int(config.get("dest_port", 514)),
                "log_format": config.get("log_format", "cef"),
                "transports": self._parse_transports(config)
            }
        else:
            # Enhanced random mode with burst awareness
            return {
                "mode": "enhanced_random",
                "duration_minutes": int(config.get("duration_minutes", 1)),
                "messages_per_second": int(config.get("messages_per_second", 10)),
                "products": config.get("products", []),
                "custom_vendor": config.get("custom_vendor"),
                "custom_product": config.get("custom_product"),
                "dest_ip": config.get("dest_ip", "127.0.0.1"),
                "dest_port": int(config.get("dest_port", 514)),
                "log_format": config.get("log_format", "cef"),
                "save_file": config.get("save_file", False),
                "add_bursts": config.get("add_bursts", True),  # New option
                "transports": self._parse_transports(config)
            }
    
    def _parse_transports(self, config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse transport configurations honoring UI toggles and env vars."""
        transports = []
        
        enable_syslog = bool(config.get("enable_syslog", True))
        enable_xsiam = bool(config.get("enable_xsiam_http", True))
        enable_webhook = bool(config.get("enable_webhook", True))
        
        # Syslog UDP transport
        if enable_syslog:
            transports.append({
                "type": TransportType.SYSLOG_UDP,
                "config": {
                    "host": config.get("dest_ip", "127.0.0.1"),
                    "port": int(config.get("dest_port", 514))
                }
            })
        
        # Cortex XSIAM HTTP if configured via env and enabled
        xsiam_endpoint = os.getenv("XSIAM_HTTP_ENDPOINT")
        xsiam_api_key = os.getenv("XSIAM_API_KEY")
        xsiam_api_key_id = os.getenv("XSIAM_API_KEY_ID")
        xsiam_tenant_id = os.getenv("XSIAM_TENANT_ID")
        if enable_xsiam and xsiam_endpoint and xsiam_api_key:
            transports.append({
                "type": TransportType.XSIAM_HTTP,
                "config": {
                    "endpoint": xsiam_endpoint,
                    "api_key": xsiam_api_key,
                    "api_key_id": xsiam_api_key_id,
                    "tenant_id": xsiam_tenant_id,
                    "batch_size": int(config.get("xsiam_batch_size", 1000)),
                    "compress": bool(config.get("xsiam_compress", True))
                }
            })
        
        # Webhook if configured via env and enabled; allow per-request overrides
        webhook_endpoint = config.get("http_endpoint") or os.getenv("WEBHOOK_ENDPOINT") 
        webhook_token = config.get("http_token") or os.getenv("WEBHOOK_TOKEN")
        if enable_webhook and webhook_endpoint:
            webhook_config = {
                "endpoint": webhook_endpoint,
                "method": "POST",
                "timeout": 30.0
            }
            if webhook_token:
                webhook_config.update({
                    "auth_type": "bearer",
                    "auth_value": webhook_token
                })
            transports.append({
                "type": TransportType.HTTP_POST,
                "config": webhook_config
            })
        
        return transports
    
    def _initialize_transports(self, config: Dict[str, Any]):
        """Initialize transport adapters with type metadata."""
        self.transports = []
        
        for transport_config in config.get("transports", []):
            try:
                adapter = create_transport_adapter(
                    transport_config["type"],
                    transport_config["config"]
                )
                # Store transport type for format optimization
                adapter.transport_type = transport_config["type"]
                self.transports.append(adapter)
                logger.info(f"Initialized transport: {transport_config['type']}")
            except Exception as e:
                logger.error(f"Failed to initialize transport {transport_config['type']}: {e}")
    
    def _run_burst_generation(self, config: Dict[str, Any]):
        """Main burst generation loop."""
        
        try:
            if config["mode"] == "apt_campaign":
                self._run_apt_campaign(config)
            elif config["mode"] == "pattern_burst":
                self._run_pattern_burst(config)
            elif config["mode"] == "custom_csv":
                self._run_custom_csv(config)
            else:
                self._run_enhanced_random(config)
                
        except Exception as e:
            logger.error(f"Error in burst generation: {e}")
            self._queue_status_message(f"Error: {e}", "danger")
        
        finally:
            # Clean up
            self.is_running = False
            self.is_paused = False
            self.stats["end_time"] = datetime.now(timezone.utc).isoformat()
            self._close_transports()
            self._queue_status_message("Session completed", "success")
    
    def _run_apt_campaign(self, config: Dict[str, Any]):
        """Run APT campaign generation."""
        
        apt_group = config["apt_group"]
        duration_hours = config["duration_hours"]
        intensity = config["intensity"]
        
        logger.info(f"Starting {apt_group} campaign: {duration_hours}h at {intensity} intensity")
        
        # Generate campaign events
        events = self.burst_generator.generate_apt_campaign(
            apt_group=apt_group,
            duration_hours=duration_hours,
            intensity=intensity
        )
        
        self.stats["events_generated"] = len(events)
        self.stats["patterns_executed"] = list(set(
            e.pattern_id for e in events if e.pattern_id
        ))
        
        # Send events with timing
        self._send_events_with_timing(events, config)
    
    def _run_custom_csv(self, config: Dict[str, Any]):
        """Ingest a CSV and send events via selected transports."""
        from src.xgen.custom.csv_ingest import events_from_csv
        from src.xgen.formats.renderers import render_events
        from src.xgen.core.models import LogFormat

        csv_path = config.get("csv_path")
        default_vendor = config.get("default_vendor", "Custom")
        default_product = config.get("default_product", "Generic")
        fmt = config.get("log_format", "cef").lower()

        if not csv_path:
            raise ValueError("csv_path required for custom_csv mode")

        events = events_from_csv(csv_path, default_vendor, default_product)
        self.stats["events_generated"] = len(events)

        # Send in one or more chunks with optimal format per transport
        from src.xgen.catalog.transport_mapping import get_optimal_format
        batch_size = 500
        total_sent = 0
        for i in range(0, len(events), batch_size):
            batch_events = events[i:i+batch_size]
            any_success = False
            first_sample_line = None
            
            for t in self.transports:
                try:
                    # Get optimal format for this transport
                    sample_event = batch_events[0] if batch_events else None
                    if sample_event:
                        optimal_fmt = get_optimal_format(
                            sample_event.vendor,
                            sample_event.nice_category,
                            getattr(t, 'transport_type', TransportType.SYSLOG_UDP)
                        )
                    else:
                        optimal_fmt = LogFormat.CEF
                    
                    # Render batch with optimal format
                    batch_logs = render_events(batch_events, optimal_fmt)
                    
                    if t.send(batch_events, batch_logs):
                        any_success = True
                    
                    # Save first sample for UI
                    if first_sample_line is None and batch_logs:
                        first_sample_line = f"[{optimal_fmt.value.upper()}] {batch_logs[0]}"
                        
                except Exception as e:
                    logger.error(f"Transport send failed: {e}")
            
            total_sent += len(batch_events) if any_success else 0
            # Queue sample log to UI
            if first_sample_line:
                self._queue_log_message(first_sample_line)

        self.stats["events_sent"] = total_sent
        self._queue_status_message(f"CSV sent: {total_sent}/{len(events)}", "success")

    def _run_pattern_burst(self, config: Dict[str, Any]):
        """Run single pattern burst."""
        
        pattern = config["pattern"]
        logger.info(f"Generating burst for pattern: {pattern.pattern_id}")
        
        events = self.burst_generator.generate_pattern_burst(
            pattern=pattern,
            scenario_id=self.session_id
        )
        
        self.stats["events_generated"] = len(events)
        self.stats["patterns_executed"] = [pattern.pattern_id]
        
        # Send events with timing
        self._send_events_with_timing(events, config)
    
    def _run_enhanced_random(self, config: Dict[str, Any]):
        """Run enhanced random generation with optional bursts."""
        
        duration_minutes = config["duration_minutes"]
        messages_per_second = config["messages_per_second"]
        add_bursts = config.get("add_bursts", True)
        
        end_time = time.time() + (duration_minutes * 60)
        sleep_interval = 1.0 / messages_per_second
        
        # Generate some burst patterns if enabled
        burst_patterns = []
        if add_bursts:
            # Add random persistence and lateral movement patterns
            all_patterns = {
                **ENTERPRISE_PERSISTENCE_PATTERNS,
                **LATERAL_MOVEMENT_PATTERNS
            }
            burst_patterns = list(all_patterns.values())[:3]  # Use first 3
        
        event_count = 0
        burst_schedule = []
        
        # Schedule bursts at random intervals
        if burst_patterns:
            import random
            burst_times = []
            for i in range(2):  # 2 bursts during session
                burst_time = time.time() + random.uniform(10, duration_minutes * 30)
                if burst_time < end_time:
                    burst_times.append(burst_time)
            
            for burst_time in sorted(burst_times):
                pattern = random.choice(burst_patterns)
                burst_schedule.append((burst_time, pattern))
        
        # Generation loop
        next_burst_idx = 0
        while time.time() < end_time and not self.stop_event.is_set():
            
            if self.pause_event.is_set():
                time.sleep(0.5)
                continue
            
            # Check for scheduled bursts
            current_time = time.time()
            if (next_burst_idx < len(burst_schedule) and 
                current_time >= burst_schedule[next_burst_idx][0]):
                
                pattern = burst_schedule[next_burst_idx][1]
                logger.info(f"Executing burst pattern: {pattern.pattern_id}")
                
                burst_events = self.burst_generator.generate_pattern_burst(
                    pattern=pattern,
                    scenario_id=self.session_id
                )
                
                # Send burst immediately
                self._send_events_immediately(burst_events, config)
                
                self.stats["patterns_executed"].append(pattern.pattern_id)
                next_burst_idx += 1
            
            # Generate regular random event (simplified version of original logic)
            # TODO: Implement legacy random generation here
            
            time.sleep(sleep_interval)
            event_count += 1
        
        self.stats["events_generated"] = event_count
    
    def _send_events_with_timing(self, events: List[BaseEvent], config: Dict[str, Any]):
        """Send events respecting their timestamps."""
        
        if not events:
            return
        
        # Sort events by timestamp
        events.sort(key=lambda e: e.timestamp)
        
        base_time = time.time()
        first_event_time = events[0].timestamp.timestamp()
        
        for event in events:
            if self.stop_event.is_set():
                break
            
            # Wait for event time
            target_time = base_time + (event.timestamp.timestamp() - first_event_time)
            current_time = time.time()
            
            if target_time > current_time:
                sleep_time = min(target_time - current_time, 5.0)  # Max 5 sec wait
                time.sleep(sleep_time)
            
            # Check pause
            while self.pause_event.is_set() and not self.stop_event.is_set():
                time.sleep(0.1)
            
            # Send single event
            self._send_events_immediately([event], config)
    
    def _send_events_immediately(self, events: List[BaseEvent], config: Dict[str, Any]):
        """Send events immediately to all transports with optimal formats."""
        from src.xgen.catalog.transport_mapping import get_optimal_format
        
        if not events or not self.transports:
            return
        
        # Send to each transport with optimal format
        first_log_line = None
        for transport in self.transports:
            try:
                # Get optimal format for this transport type
                sample_event = events[0] if events else None
                if sample_event:
                    optimal_fmt = get_optimal_format(
                        sample_event.vendor,
                        sample_event.nice_category,
                        getattr(transport, 'transport_type', TransportType.SYSLOG_UDP)
                    )
                else:
                    optimal_fmt = LogFormat.CEF
                
                # Render with optimal format
                formatted_logs = render_events(events, optimal_fmt)
                
                # Send to transport
                success = transport.send(events, formatted_logs)
                if success:
                    self.stats["events_sent"] += len(events)
                else:
                    self.stats["events_failed"] += len(events)
                
                # Save first log line for UI display
                if first_log_line is None and formatted_logs:
                    first_log_line = f"[{optimal_fmt.value.upper()}] {formatted_logs[0]}"
                
            except Exception as e:
                logger.error(f"Transport error: {e}")
                self.stats["events_failed"] += len(events)
        
        # Queue first formatted log for UI display
        if first_log_line:
            self._queue_log_message(first_log_line)
    
    def _queue_log_message(self, log_line: str):
        """Queue log message for UI display."""
        with self.queue_lock:
            self.event_queue.append(f'data: {{"log": "{log_line}"}}\n\n')
    
    def _queue_status_message(self, message: str, msg_type: str = "info"):
        """Queue status message for UI display."""
        with self.queue_lock:
            self.event_queue.append(f'data: {{"status": "{message}", "type": "{msg_type}", "is_running": {str(self.is_running).lower()}, "is_paused": {str(self.is_paused).lower()}}}\n\n')
    
    def get_events_for_streaming(self) -> List[str]:
        """Get queued events for server-sent events."""
        with self.queue_lock:
            events = self.event_queue.copy()
            self.event_queue.clear()
            return events
    
    def pause_resume(self) -> Dict[str, Any]:
        """Toggle pause state."""
        if not self.is_running:
            return {"success": False, "message": "No session is running"}
        
        if self.is_paused:
            self.pause_event.clear()
            self.is_paused = False
            message = "Session resumed"
        else:
            self.pause_event.set()
            self.is_paused = True
            message = "Session paused"
        
        return {
            "success": True,
            "message": message,
            "is_running": self.is_running,
            "is_paused": self.is_paused
        }
    
    def stop(self) -> Dict[str, Any]:
        """Stop the current session."""
        if not self.is_running:
            return {"success": False, "message": "No session is running"}
        
        self.stop_event.set()
        self.pause_event.clear()
        
        if self.thread:
            self.thread.join(timeout=5.0)
        
        self.is_running = False
        self.is_paused = False
        
        return {"success": True, "message": "Session stopped"}
    
    def get_status(self) -> Dict[str, Any]:
        """Get current session status."""
        message = "Session is running" if self.is_running else "No active session"
        if self.is_running and self.is_paused:
            message = "Session is paused"
        
        return {
            "is_running": self.is_running,
            "is_paused": self.is_paused,
            "message": message,
            "stats": self.stats.copy()
        }
    
    def _close_transports(self):
        """Close all transport connections."""
        for transport in self.transports:
            try:
                transport.close()
            except Exception as e:
                logger.error(f"Error closing transport: {e}")
        self.transports = []


# Global session instance for Flask integration
xgen_session = XGenSession()


def get_available_apt_groups() -> List[Dict[str, str]]:
    """Get list of available APT groups for UI."""
    return [
        {"id": APTGroup.APT29, "name": "APT29 (Cozy Bear)", "description": "Russian APT - Cloud & Enterprise"},
        {"id": APTGroup.APT28, "name": "APT28 (Fancy Bear)", "description": "Russian APT - Enterprise Focus"},
        {"id": APTGroup.APT1, "name": "APT1 (Comment Crew)", "description": "Chinese APT - SMB Lateral Movement"},
        {"id": APTGroup.APT40, "name": "APT40 (Leviathan)", "description": "Chinese APT - Cloud & SSH"},
        {"id": APTGroup.APT41, "name": "APT41 (Double Dragon)", "description": "Chinese APT - RDP & Scheduled Tasks"},
        {"id": APTGroup.VOLT_TYPHOON, "name": "Volt Typhoon", "description": "Chinese APT - Cloud Credentials"},
        {"id": APTGroup.LAZARUS, "name": "Lazarus Group", "description": "North Korean APT - Registry & Mobile"},
        {"id": APTGroup.CARBANAK, "name": "Carbanak (FIN7)", "description": "Financial Crime - Task Scheduling"}
    ]


def get_available_patterns() -> List[Dict[str, str]]:
    """Get list of available individual patterns for UI."""
    patterns = []
    
    # Enterprise Persistence
    for key, pattern in ENTERPRISE_PERSISTENCE_PATTERNS.items():
        patterns.append({
            "id": pattern.pattern_id,
            "name": pattern.pattern_name,
            "description": pattern.description,
            "category": "Enterprise Persistence"
        })
    
    # Cloud Persistence  
    for key, pattern in CLOUD_PERSISTENCE_PATTERNS.items():
        patterns.append({
            "id": pattern.pattern_id,
            "name": pattern.pattern_name,
            "description": pattern.description,
            "category": "Cloud Persistence"
        })
    
    # Lateral Movement
    for key, pattern in LATERAL_MOVEMENT_PATTERNS.items():
        patterns.append({
            "id": pattern.pattern_id,
            "name": pattern.pattern_name,
            "description": pattern.description,
            "category": "Lateral Movement"
        })
    
    return patterns