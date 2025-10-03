"""
Transport Adapters for Log Delivery.

This module provides transport adapters for delivering logs to various
destinations including syslog, Cortex XSIAM HTTP, and generic webhooks.
"""

import asyncio
import gzip
import json
import logging
import socket
import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Union
from urllib.parse import urlparse
from uuid import uuid4

import requests
import httpx
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

from ..core.models import BaseEvent, TransportType

logger = logging.getLogger(__name__)


class TransportAdapter(ABC):
    """Base class for transport adapters."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.stats = {
            "sent": 0,
            "failed": 0,
            "bytes_sent": 0,
            "last_error": None,
            "last_success": None
        }
    
    @abstractmethod
    def send(self, events: List[BaseEvent], formatted_logs: List[str]) -> bool:
        """Send formatted log events to the transport destination."""
        pass
    
    @abstractmethod
    def close(self):
        """Clean up transport resources."""
        pass
    
    def get_stats(self) -> Dict[str, Any]:
        """Get transport statistics."""
        return self.stats.copy()


class SyslogUDPAdapter(TransportAdapter):
    """UDP Syslog transport adapter compatible with Broker VMs."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.host = config.get("host", "127.0.0.1")
        self.port = config.get("port", 514)
        self.facility = config.get("facility", 16)  # Local0
        self.socket = None
        
        # Initialize socket
        self._initialize_socket()
    
    def _initialize_socket(self):
        """Initialize UDP socket."""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            logger.info(f"Initialized UDP syslog transport to {self.host}:{self.port}")
        except Exception as e:
            logger.error(f"Failed to initialize UDP socket: {e}")
            raise
    
    def send(self, events: List[BaseEvent], formatted_logs: List[str]) -> bool:
        """Send logs via UDP syslog."""
        if not self.socket:
            logger.error("Socket not initialized")
            return False
        
        success_count = 0
        total_bytes = 0
        
        for event, log_line in zip(events, formatted_logs):
            try:
                # Add syslog header (RFC 3164 compatible)
                priority = self.facility * 8 + int(event.severity)
                timestamp_str = event.timestamp.strftime("%b %d %H:%M:%S")
                hostname = getattr(event.source_asset, 'hostname', 'localhost') if event.source_asset else 'localhost'
                
                # Format as: <priority>timestamp hostname message
                syslog_msg = f"<{priority}>{timestamp_str} {hostname} {log_line}"
                
                # Send to destination
                self.socket.sendto(syslog_msg.encode('utf-8'), (self.host, self.port))
                
                success_count += 1
                total_bytes += len(syslog_msg.encode('utf-8'))
                
            except Exception as e:
                logger.error(f"Failed to send syslog message: {e}")
                self.stats["failed"] += 1
                self.stats["last_error"] = str(e)
        
        # Update statistics
        self.stats["sent"] += success_count
        self.stats["bytes_sent"] += total_bytes
        if success_count > 0:
            self.stats["last_success"] = datetime.now(timezone.utc).isoformat()
        
        return success_count == len(events)
    
    def close(self):
        """Close UDP socket."""
        if self.socket:
            self.socket.close()
            self.socket = None
            logger.info("Closed UDP syslog transport")


class SyslogTCPAdapter(TransportAdapter):
    """TCP Syslog transport adapter with reconnection."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.host = config.get("host", "127.0.0.1")
        self.port = config.get("port", 514)
        self.facility = config.get("facility", 16)
        self.use_tls = config.get("tls", False)
        self.socket = None
        self.reconnect_attempts = 0
        self.max_reconnect_attempts = config.get("max_reconnect_attempts", 3)
    
    def _connect(self) -> bool:
        """Establish TCP connection."""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(10.0)  # 10 second timeout
            
            if self.use_tls:
                import ssl
                context = ssl.create_default_context()
                self.socket = context.wrap_socket(self.socket, server_hostname=self.host)
            
            self.socket.connect((self.host, self.port))
            self.reconnect_attempts = 0
            logger.info(f"Connected to {'TLS' if self.use_tls else 'TCP'} syslog at {self.host}:{self.port}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to connect to syslog server: {e}")
            self.socket = None
            return False
    
    def send(self, events: List[BaseEvent], formatted_logs: List[str]) -> bool:
        """Send logs via TCP syslog with reconnection."""
        if not self.socket and not self._connect():
            return False
        
        success_count = 0
        total_bytes = 0
        
        for event, log_line in zip(events, formatted_logs):
            try:
                # Add syslog header and frame (RFC 5424 or RFC 3164)
                priority = self.facility * 8 + int(event.severity)
                timestamp_str = event.timestamp.strftime("%b %d %H:%M:%S")
                hostname = getattr(event.source_asset, 'hostname', 'localhost') if event.source_asset else 'localhost'
                
                syslog_msg = f"<{priority}>{timestamp_str} {hostname} {log_line}\n"
                
                # Send with length framing for TCP
                self.socket.send(syslog_msg.encode('utf-8'))
                
                success_count += 1
                total_bytes += len(syslog_msg.encode('utf-8'))
                
            except (socket.error, BrokenPipeError) as e:
                logger.warning(f"Socket error, attempting reconnect: {e}")
                
                # Try to reconnect
                self.close()
                if self.reconnect_attempts < self.max_reconnect_attempts:
                    self.reconnect_attempts += 1
                    if self._connect():
                        # Retry sending this message
                        try:
                            self.socket.send(syslog_msg.encode('utf-8'))
                            success_count += 1
                            total_bytes += len(syslog_msg.encode('utf-8'))
                        except Exception:
                            self.stats["failed"] += 1
                    else:
                        self.stats["failed"] += 1
                else:
                    logger.error(f"Max reconnect attempts reached")
                    self.stats["failed"] += 1
                    break
                    
            except Exception as e:
                logger.error(f"Failed to send TCP syslog message: {e}")
                self.stats["failed"] += 1
                self.stats["last_error"] = str(e)
        
        # Update statistics
        self.stats["sent"] += success_count
        self.stats["bytes_sent"] += total_bytes
        if success_count > 0:
            self.stats["last_success"] = datetime.now(timezone.utc).isoformat()
        
        return success_count == len(events)
    
    def close(self):
        """Close TCP socket."""
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            self.socket = None
            logger.info("Closed TCP syslog transport")


class XSIAMHTTPAdapter(TransportAdapter):
    """Cortex XSIAM HTTP endpoint adapter with XDM field mapping."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.endpoint = config["endpoint"]  # e.g., https://api-{fqdn}/logs/v1/xsiam
        self.api_key = config["api_key"]
        self.api_key_id = config.get("api_key_id")
        self.tenant_id = config.get("tenant_id")
        
        # XSIAM specific configuration
        self.batch_size = config.get("batch_size", 1000)  # XSIAM can handle larger batches
        self.compress = config.get("compress", True)
        self.format = config.get("format", "json")  # json, cef, or raw
        
        # Setup HTTP session with retries
        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            status_forcelist=[429, 500, 502, 503, 504],
            backoff_factor=2,
            respect_retry_after_header=True
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Set headers for XSIAM API
        headers = {
            "Content-Type": "application/json",
            "x-xdr-auth-id": str(self.api_key_id) if self.api_key_id else "",
            "Authorization": self.api_key
        }
        
        if self.tenant_id:
            headers["x-xdr-tenant-id"] = self.tenant_id
        
        if self.compress:
            headers["Content-Encoding"] = "gzip"
        
        self.session.headers.update(headers)
    
    def send(self, events: List[BaseEvent], formatted_logs: List[str]) -> bool:
        """Send events to XSIAM HTTP endpoint with XDM mapping."""
        
        # Prepare XSIAM events with XDM field mapping
        xsiam_events = []
        for event, log_line in zip(events, formatted_logs):
            # Map to XDM schema where possible
            xdm_event = {
                "_time": event.timestamp.isoformat(),
                "event_id": str(event.event_id),
                "vendor_name": event.vendor,
                "product_name": event.product,
                "event_name": event.event_name,
                "event_type": event.event_code or "security_event",
                "severity": self._map_severity_to_xdm(event.severity),
                "description": event.message,
                "raw_log": log_line,
                
                # XGen specific fields for analytics correlation
                "xgen_pattern_id": event.pattern_id,
                "xgen_burst_id": str(event.burst_id) if event.burst_id else None,
                "xgen_scenario_id": str(event.scenario_id) if event.scenario_id else None,
                "xgen_sequence_number": event.sequence_number,
                "xgen_nice_category": event.nice_category
            }
            
            # Add network 5-tuple with XDM field names
            if event.network_tuple:
                xdm_event.update({
                    "source_ipv4": event.network_tuple.source_ip,
                    "destination_ipv4": event.network_tuple.destination_ip,
                    "source_port": event.network_tuple.source_port,
                    "destination_port": event.network_tuple.destination_port,
                    "ip_protocol": event.network_tuple.protocol.lower()
                })
            
            # Add actor information with XDM mapping
            if event.actor:
                xdm_event.update({
                    "actor_primary_username": event.actor.username,
                    "actor_primary_user_email": event.actor.email,
                    "actor_primary_user_department": event.actor.department,
                    "actor_primary_user_is_privileged": event.actor.is_privileged
                })
            
            # Add asset information
            if event.source_asset:
                xdm_event.update({
                    "source_host_hostname": event.source_asset.hostname,
                    "source_host_ipv4_addresses": [event.source_asset.ip_address] if event.source_asset.ip_address else [],
                    "source_host_os": event.source_asset.operating_system,
                    "source_host_asset_type": event.source_asset.asset_type
                })
            
            if event.destination_asset:
                xdm_event.update({
                    "destination_host_hostname": event.destination_asset.hostname,
                    "destination_host_ipv4_addresses": [event.destination_asset.ip_address] if event.destination_asset.ip_address else [],
                    "destination_host_os": event.destination_asset.operating_system
                })
            
            # Add MITRE ATT&CK mapping if present
            if event.tactic_technique:
                xdm_event.update({
                    "mitre_tactic_id": event.tactic_technique.tactic_id,
                    "mitre_tactic_name": event.tactic_technique.tactic_name,
                    "mitre_technique_id": event.tactic_technique.technique_id,
                    "mitre_technique_name": event.tactic_technique.technique_name,
                    "mitre_subtechnique_id": event.tactic_technique.subtechnique_id
                })
            
            xsiam_events.append(xdm_event)
        
        # Send in batches
        success_count = 0
        total_bytes = 0
        
        for i in range(0, len(xsiam_events), self.batch_size):
            batch = xsiam_events[i:i + self.batch_size]
            
            try:
                # Prepare XSIAM payload format
                payload = {
                    "request_id": str(uuid4()),
                    "events": batch
                }
                
                payload_json = json.dumps(payload, default=str)
                
                # Compress if enabled
                if self.compress:
                    payload_bytes = gzip.compress(payload_json.encode('utf-8'))
                else:
                    payload_bytes = payload_json.encode('utf-8')
                
                # Send to XSIAM
                response = self.session.post(
                    self.endpoint,
                    data=payload_bytes,
                    timeout=60.0  # Longer timeout for XSIAM
                )
                
                if 200 <= response.status_code < 300:
                    success_count += len(batch)
                    total_bytes += len(payload_bytes)
                    logger.debug(f"Sent batch of {len(batch)} events to XSIAM")
                else:
                    logger.error(f"XSIAM returned {response.status_code}: {response.text}")
                    self.stats["failed"] += len(batch)
                    self.stats["last_error"] = f"HTTP {response.status_code}: {response.text}"
                    
            except requests.RequestException as e:
                logger.error(f"Failed to send batch to XSIAM: {e}")
                self.stats["failed"] += len(batch)
                self.stats["last_error"] = str(e)
            
            except Exception as e:
                logger.error(f"Unexpected error sending to XSIAM: {e}")
                self.stats["failed"] += len(batch)
                self.stats["last_error"] = str(e)
        
        # Update statistics
        self.stats["sent"] += success_count
        self.stats["bytes_sent"] += total_bytes
        if success_count > 0:
            self.stats["last_success"] = datetime.now(timezone.utc).isoformat()
        
        return success_count == len(events)
    
    def _map_severity_to_xdm(self, severity_level) -> str:
        """Map syslog severity levels to XDM severity values."""
        severity_mapping = {
            0: "critical",    # Emergency
            1: "high",       # Alert  
            2: "high",       # Critical
            3: "medium",     # Error
            4: "medium",     # Warning
            5: "low",        # Notice
            6: "informational", # Info
            7: "informational"  # Debug
        }
        return severity_mapping.get(int(severity_level), "informational")
    
    def close(self):
        """Close HTTP session."""
        if self.session:
            self.session.close()
            logger.info("Closed XSIAM HTTP transport")


class WebhookAdapter(TransportAdapter):
    """Generic webhook adapter with customizable headers and retry."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.endpoint = config["endpoint"]
        self.headers = config.get("headers", {})
        self.method = config.get("method", "POST").upper()
        self.auth_type = config.get("auth_type", None)  # bearer, basic, api_key
        self.auth_value = config.get("auth_value", None)
        
        # Request configuration
        self.timeout = config.get("timeout", 30.0)
        self.batch_size = config.get("batch_size", 50)
        self.compress = config.get("compress", False)
        
        # Setup HTTP session
        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            status_forcelist=[429, 500, 502, 503, 504],
            backoff_factor=2,
            respect_retry_after_header=True
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Set headers
        self.session.headers.update(self.headers)
        self.session.headers.update({"Content-Type": "application/json"})
        
        # Setup authentication
        if self.auth_type == "bearer" and self.auth_value:
            self.session.headers.update({"Authorization": f"Bearer {self.auth_value}"})
        elif self.auth_type == "basic" and self.auth_value:
            self.session.headers.update({"Authorization": f"Basic {self.auth_value}"})
        elif self.auth_type == "api_key" and self.auth_value:
            self.session.headers.update({"X-API-Key": self.auth_value})
        
        if self.compress:
            self.session.headers.update({"Content-Encoding": "gzip"})
    
    def send(self, events: List[BaseEvent], formatted_logs: List[str]) -> bool:
        """Send events to webhook endpoint."""
        
        # Prepare webhook payload
        webhook_events = []
        for event, log_line in zip(events, formatted_logs):
            webhook_event = {
                "timestamp": event.timestamp.isoformat(),
                "event_id": str(event.event_id),
                "vendor": event.vendor,
                "product": event.product,
                "event_name": event.event_name,
                "severity": int(event.severity),
                "message": event.message,
                "nice_category": event.nice_category,
                "raw_log": log_line,
                "pattern_id": event.pattern_id,
                "burst_id": str(event.burst_id) if event.burst_id else None,
                "scenario_id": str(event.scenario_id) if event.scenario_id else None,
                "sequence_number": event.sequence_number
            }
            
            # Add network 5-tuple
            if event.network_tuple:
                webhook_event["network"] = {
                    "src_ip": event.network_tuple.source_ip,
                    "dest_ip": event.network_tuple.destination_ip,
                    "src_port": event.network_tuple.source_port,
                    "dest_port": event.network_tuple.destination_port,
                    "protocol": event.network_tuple.protocol
                }
            
            # Add actor information
            if event.actor:
                webhook_event["actor"] = {
                    "username": event.actor.username,
                    "email": event.actor.email,
                    "department": event.actor.department,
                    "is_privileged": event.actor.is_privileged
                }
            
            # Add asset information
            if event.source_asset:
                webhook_event["source_asset"] = {
                    "hostname": event.source_asset.hostname,
                    "ip_address": event.source_asset.ip_address,
                    "asset_type": event.source_asset.asset_type,
                    "operating_system": event.source_asset.operating_system
                }
            
            webhook_events.append(webhook_event)
        
        # Send in batches
        success_count = 0
        total_bytes = 0
        
        for i in range(0, len(webhook_events), self.batch_size):
            batch = webhook_events[i:i + self.batch_size]
            
            try:
                # Prepare payload
                payload = {
                    "events": batch,
                    "metadata": {
                        "generator": "xgen",
                        "batch_size": len(batch),
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }
                }
                
                payload_json = json.dumps(payload, default=str)
                
                # Compress if enabled
                if self.compress:
                    payload_bytes = gzip.compress(payload_json.encode('utf-8'))
                else:
                    payload_bytes = payload_json.encode('utf-8')
                
                # Send to webhook
                response = self.session.request(
                    self.method,
                    self.endpoint,
                    data=payload_bytes,
                    timeout=self.timeout
                )
                
                if 200 <= response.status_code < 300:
                    success_count += len(batch)
                    total_bytes += len(payload_bytes)
                    logger.debug(f"Sent batch of {len(batch)} events to webhook")
                else:
                    logger.error(f"Webhook returned {response.status_code}: {response.text}")
                    self.stats["failed"] += len(batch)
                    self.stats["last_error"] = f"HTTP {response.status_code}: {response.text}"
                    
            except requests.RequestException as e:
                logger.error(f"Failed to send batch to webhook: {e}")
                self.stats["failed"] += len(batch)
                self.stats["last_error"] = str(e)
            
            except Exception as e:
                logger.error(f"Unexpected error sending to webhook: {e}")
                self.stats["failed"] += len(batch)
                self.stats["last_error"] = str(e)
        
        # Update statistics
        self.stats["sent"] += success_count
        self.stats["bytes_sent"] += total_bytes
        if success_count > 0:
            self.stats["last_success"] = datetime.now(timezone.utc).isoformat()
        
        return success_count == len(events)
    
    def close(self):
        """Close HTTP session."""
        if self.session:
            self.session.close()
            logger.info("Closed webhook transport")


def create_transport_adapter(transport_type: TransportType, config: Dict[str, Any]) -> TransportAdapter:
    """Factory function to create transport adapters."""
    
    if transport_type == TransportType.SYSLOG_UDP:
        return SyslogUDPAdapter(config)
    elif transport_type == TransportType.SYSLOG_TCP:
        return SyslogTCPAdapter(config)
    elif transport_type == TransportType.SYSLOG_TLS:
        config["tls"] = True
        return SyslogTCPAdapter(config)
    elif transport_type == TransportType.XSIAM_HTTP:
        return XSIAMHTTPAdapter(config)
    elif transport_type in [TransportType.WEBHOOK, TransportType.HTTP_POST]:
        return WebhookAdapter(config)
    else:
        raise ValueError(f"Unsupported transport type: {transport_type}")