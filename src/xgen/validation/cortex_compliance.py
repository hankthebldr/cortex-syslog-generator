"""
Cortex Compliance Validation System

This module ensures that all generated logs are fully compliant with Cortex XDR/XSIAM
parsing rules, data modeling expectations, and upstream processing requirements.
"""

import re
import json
import socket
import random
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass
from enum import Enum

class LogFormat(str, Enum):
    RAW = "raw"
    SYSLOG = "syslog"
    CEF = "cef"
    LEEF = "leef"  
    JSON = "json"

class CortexProduct(str, Enum):
    XDR = "xdr"
    XSIAM = "xsiam"
    DATA_LAKE = "data_lake"

@dataclass
class VendorParsingRule:
    """Defines how Cortex parses logs for a specific vendor/product."""
    vendor: str
    product: str
    supported_formats: List[LogFormat]
    identification_patterns: List[str]  # Regex patterns to identify vendor
    required_fields: List[str]  # Fields that must be present
    field_mappings: Dict[str, str]  # Field name mappings to XDM
    timestamp_formats: List[str]  # Supported timestamp formats
    severity_mappings: Dict[str, int]  # Severity level mappings

@dataclass
class ValidationResult:
    """Result of log validation against Cortex compliance."""
    is_valid: bool
    format_compliance: bool
    field_compliance: bool
    parsing_compliance: bool
    xdm_compliance: bool
    issues: List[str]
    recommendations: List[str]

class CortexComplianceValidator:
    """Validates logs against Cortex parsing and data modeling requirements."""
    
    def __init__(self):
        self.vendor_rules = self._initialize_vendor_rules()
        self.xdm_schema = self._initialize_xdm_schema()
        
    def _initialize_vendor_rules(self) -> Dict[str, VendorParsingRule]:
        """Initialize vendor-specific parsing rules based on Cortex marketplace content."""
        return {
            "palo_alto_networks": VendorParsingRule(
                vendor="Palo Alto Networks",
                product="PAN-OS",
                supported_formats=[LogFormat.CEF, LogFormat.SYSLOG, LogFormat.RAW],
                identification_patterns=[
                    r"CEF:0\|Palo Alto Networks\|",
                    r"<\d+>.*PAN-OS:",
                    r"^\d+,\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2},\d+,TRAFFIC"
                ],
                required_fields=["timestamp", "src", "dst", "action"],
                field_mappings={
                    "src": "xdm.source.ip",
                    "dst": "xdm.target.ip", 
                    "spt": "xdm.source.port",
                    "dpt": "xdm.target.port",
                    "proto": "xdm.network.ip_protocol",
                    "act": "xdm.network.rule.action"
                },
                timestamp_formats=[
                    "%Y/%m/%d %H:%M:%S",
                    "%b %d %H:%M:%S"
                ],
                severity_mappings={
                    "critical": 2, "high": 3, "medium": 4, 
                    "low": 5, "informational": 6
                }
            ),
            
            "cisco_asa": VendorParsingRule(
                vendor="Cisco",
                product="ASA",
                supported_formats=[LogFormat.SYSLOG, LogFormat.RAW],
                identification_patterns=[
                    r"%ASA-\d+-\d+:",
                    r"<\d+>.*%ASA-"
                ],
                required_fields=["timestamp", "message_id", "message"],
                field_mappings={
                    "src_ip": "xdm.source.ip",
                    "dst_ip": "xdm.target.ip",
                    "message_id": "xdm.event.original_event_type"
                },
                timestamp_formats=["%b %d %H:%M:%S"],
                severity_mappings={
                    "0": 0, "1": 1, "2": 2, "3": 3, 
                    "4": 4, "5": 5, "6": 6, "7": 7
                }
            ),
            
            "crowdstrike": VendorParsingRule(
                vendor="CrowdStrike",
                product="Falcon",
                supported_formats=[LogFormat.JSON],
                identification_patterns=[
                    r'{"metadata":{"eventType":',
                    r'"event":{"ProcessRollup2":'
                ],
                required_fields=["metadata", "event"],
                field_mappings={
                    "metadata.eventCreationTime": "xdm.event.timestamp",
                    "event.ProcessRollup2.ComputerName": "xdm.source.host.hostname",
                    "event.ProcessRollup2.FileName": "xdm.source.process.name",
                    "event.ProcessRollup2.CommandLine": "xdm.source.process.command_line"
                },
                timestamp_formats=["epoch_ms"],
                severity_mappings={"INFO": 6, "WARN": 4, "ERROR": 3}
            ),
            
            "okta": VendorParsingRule(
                vendor="Okta",
                product="System Log",
                supported_formats=[LogFormat.JSON],
                identification_patterns=[
                    r'"eventType":"user\.',
                    r'"published":".*Z"',
                    r'"outcome":{"result":'
                ],
                required_fields=["uuid", "published", "eventType", "outcome"],
                field_mappings={
                    "published": "xdm.event.timestamp",
                    "client.ipAddress": "xdm.source.ip",
                    "actor.alternateId": "xdm.source.user.username",
                    "outcome.result": "xdm.auth.auth_outcome"
                },
                timestamp_formats=["iso8601"],
                severity_mappings={"INFO": 6, "WARN": 4, "ERROR": 3}
            )
        }
    
    def _initialize_xdm_schema(self) -> Dict[str, Any]:
        """Initialize XDM schema requirements."""
        return {
            "required_base_fields": [
                "_time", "_vendor", "_product", "_event_type"
            ],
            "network_fields": {
                "xdm.source.ip": {"type": "ip", "required": False},
                "xdm.target.ip": {"type": "ip", "required": False},
                "xdm.source.port": {"type": "int", "range": [1, 65535]},
                "xdm.target.port": {"type": "int", "range": [1, 65535]},
                "xdm.network.ip_protocol": {"type": "string", "values": ["TCP", "UDP", "ICMP"]},
                "xdm.network.rule.action": {"type": "string", "values": ["ALLOW", "DENY", "BLOCK", "DROP"]}
            },
            "endpoint_fields": {
                "xdm.source.host.hostname": {"type": "string", "required": True},
                "xdm.source.process.name": {"type": "string", "required": True},
                "xdm.source.process.command_line": {"type": "string", "required": False},
                "xdm.source.process.pid": {"type": "int", "required": False}
            },
            "identity_fields": {
                "xdm.source.user.username": {"type": "string", "required": True},
                "xdm.auth.auth_outcome": {"type": "string", "values": ["SUCCESS", "FAILURE"]},
                "xdm.auth.auth_method": {"type": "string", "required": False}
            }
        }

    def validate_log(self, log_message: str, vendor: str, format_type: LogFormat) -> ValidationResult:
        """Validate a log message against Cortex compliance requirements."""
        vendor_key = vendor.lower().replace(" ", "_").replace("-", "_")
        
        if vendor_key not in self.vendor_rules:
            return ValidationResult(
                is_valid=False,
                format_compliance=False,
                field_compliance=False,
                parsing_compliance=False,
                xdm_compliance=False,
                issues=[f"Vendor '{vendor}' not supported"],
                recommendations=["Use a supported vendor: " + ", ".join(self.vendor_rules.keys())]
            )
        
        rule = self.vendor_rules[vendor_key]
        issues = []
        recommendations = []
        
        # Format compliance check
        format_compliance = format_type in rule.supported_formats
        if not format_compliance:
            issues.append(f"Format '{format_type}' not supported for {vendor}")
            recommendations.append(f"Use supported formats: {rule.supported_formats}")
        
        # Identification pattern check
        parsing_compliance = any(re.search(pattern, log_message) for pattern in rule.identification_patterns)
        if not parsing_compliance:
            issues.append(f"Log doesn't match identification patterns for {vendor}")
            recommendations.append("Ensure log format matches vendor specifications")
        
        # Field compliance check
        field_compliance = self._validate_fields(log_message, rule, format_type)
        if not field_compliance:
            issues.append("Required fields missing or invalid")
            recommendations.append(f"Include required fields: {rule.required_fields}")
        
        # XDM compliance check
        xdm_compliance = self._validate_xdm_compliance(log_message, rule)
        if not xdm_compliance:
            issues.append("Log not mappable to XDM schema")
            recommendations.append("Ensure fields can be mapped to XDM schema")
        
        is_valid = all([format_compliance, parsing_compliance, field_compliance, xdm_compliance])
        
        return ValidationResult(
            is_valid=is_valid,
            format_compliance=format_compliance,
            field_compliance=field_compliance,
            parsing_compliance=parsing_compliance,
            xdm_compliance=xdm_compliance,
            issues=issues,
            recommendations=recommendations
        )
    
    def _validate_fields(self, log_message: str, rule: VendorParsingRule, format_type: LogFormat) -> bool:
        """Validate required fields are present in the log."""
        if format_type == LogFormat.CEF:
            return self._validate_cef_fields(log_message, rule)
        elif format_type == LogFormat.JSON:
            return self._validate_json_fields(log_message, rule)
        elif format_type == LogFormat.SYSLOG:
            return self._validate_syslog_fields(log_message, rule)
        return True
    
    def _validate_cef_fields(self, log_message: str, rule: VendorParsingRule) -> bool:
        """Validate CEF format fields."""
        # Check CEF header structure
        cef_pattern = r"CEF:0\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)"
        match = re.search(cef_pattern, log_message)
        
        if not match:
            return False
        
        # Validate vendor and product match
        vendor, product = match.groups()[:2]
        return vendor == rule.vendor and product == rule.product
    
    def _validate_json_fields(self, log_message: str, rule: VendorParsingRule) -> bool:
        """Validate JSON format fields."""
        try:
            data = json.loads(log_message)
            
            # Check if all required fields are present
            for field in rule.required_fields:
                if '.' in field:
                    # Handle nested fields
                    keys = field.split('.')
                    current = data
                    for key in keys:
                        if key not in current:
                            return False
                        current = current[key]
                else:
                    if field not in data:
                        return False
            
            return True
        except json.JSONDecodeError:
            return False
    
    def _validate_syslog_fields(self, log_message: str, rule: VendorParsingRule) -> bool:
        """Validate syslog format fields."""
        # Check syslog header format
        syslog_pattern = r"<(\d+)>(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)"
        match = re.search(syslog_pattern, log_message)
        
        return match is not None
    
    def _validate_xdm_compliance(self, log_message: str, rule: VendorParsingRule) -> bool:
        """Validate XDM schema compliance."""
        # Check if log contains fields that can be mapped to XDM
        mappable_fields = 0
        total_mappings = len(rule.field_mappings)
        
        if total_mappings == 0:
            return True  # No specific mappings required
        
        for source_field, xdm_field in rule.field_mappings.items():
            if self._field_present_in_log(log_message, source_field):
                mappable_fields += 1
        
        # Require at least 50% of mappable fields to be present
        return mappable_fields >= (total_mappings * 0.5)
    
    def _field_present_in_log(self, log_message: str, field_name: str) -> bool:
        """Check if a field is present in the log message."""
        # Simple pattern matching - can be enhanced based on format
        patterns = [
            rf"\b{field_name}=",  # key=value format
            rf'"{field_name}":',  # JSON format
            rf"\b{field_name}\b"  # General field name
        ]
        
        return any(re.search(pattern, log_message) for pattern in patterns)


class CortexLogFormatter:
    """Formats logs to be fully compliant with Cortex expectations."""
    
    def __init__(self):
        self.validator = CortexComplianceValidator()
    
    def format_log(self, data: Dict[str, Any], vendor: str, format_type: LogFormat) -> str:
        """Format log data into Cortex-compliant format."""
        if format_type == LogFormat.CEF:
            return self._format_cef(data, vendor)
        elif format_type == LogFormat.JSON:
            return self._format_json(data, vendor)
        elif format_type == LogFormat.SYSLOG:
            return self._format_syslog(data, vendor)
        elif format_type == LogFormat.LEEF:
            return self._format_leef(data, vendor)
        else:
            return self._format_raw(data, vendor)
    
    def _format_cef(self, data: Dict[str, Any], vendor: str) -> str:
        """Format as CEF (Common Event Format)."""
        vendor_key = vendor.lower().replace(" ", "_").replace("-", "_")
        rule = self.validator.vendor_rules.get(vendor_key)
        
        if not rule:
            # Default CEF format
            header = f"CEF:0|{vendor}|Unknown|1.0|0|Generic Event|5"
        else:
            header = f"CEF:0|{rule.vendor}|{rule.product}|1.0|{data.get('event_id', '0')}|{data.get('event_name', 'Event')}|{data.get('severity', 5)}"
        
        # Build extension fields
        extensions = []
        
        # Standard CEF fields
        cef_mappings = {
            'src': data.get('source_ip'),
            'dst': data.get('destination_ip'), 
            'spt': data.get('source_port'),
            'dpt': data.get('destination_port'),
            'proto': data.get('protocol'),
            'act': data.get('action'),
            'app': data.get('application'),
            'msg': data.get('message')
        }
        
        for key, value in cef_mappings.items():
            if value is not None:
                extensions.append(f"{key}={value}")
        
        # Add timestamp
        if 'timestamp' in data:
            if isinstance(data['timestamp'], datetime):
                rt = int(data['timestamp'].timestamp() * 1000)
            else:
                rt = int(datetime.now(timezone.utc).timestamp() * 1000)
            extensions.append(f"rt={rt}")
        
        # Add custom fields
        for key, value in data.get('labels', {}).items():
            extensions.append(f"cs1Label={key}")
            extensions.append(f"cs1={value}")
            break  # CEF has limited custom fields
        
        # Generate syslog header
        priority = 16 * 8 + data.get('severity', 5)  # Local0 facility
        timestamp_str = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
        hostname = data.get('hostname', 'localhost')
        
        syslog_header = f"<{priority}>{timestamp_str} {hostname}"
        
        return f"{syslog_header} {header}|{' '.join(extensions)}"
    
    def _format_json(self, data: Dict[str, Any], vendor: str) -> str:
        """Format as JSON."""
        json_data = {
            "_time": data.get('timestamp', datetime.now(timezone.utc)).isoformat() if isinstance(data.get('timestamp'), datetime) else datetime.now(timezone.utc).isoformat(),
            "_vendor": vendor,
            "_product": data.get('product', 'Unknown'),
            "_event_type": data.get('event_name', 'generic'),
            "_severity": data.get('severity', 5),
            "_raw_log": data.get('message', ''),
            "xdm": {}
        }
        
        # Add XDM mappings based on vendor
        vendor_key = vendor.lower().replace(" ", "_").replace("-", "_")
        rule = self.validator.vendor_rules.get(vendor_key)
        
        if rule:
            for source_field, xdm_field in rule.field_mappings.items():
                if source_field in data:
                    # Handle nested XDM fields
                    xdm_keys = xdm_field.replace("xdm.", "").split(".")
                    current = json_data["xdm"]
                    
                    for i, key in enumerate(xdm_keys[:-1]):
                        if key not in current:
                            current[key] = {}
                        current = current[key]
                    
                    current[xdm_keys[-1]] = data[source_field]
        
        return json.dumps(json_data, separators=(',', ':'), default=str)
    
    def _format_syslog(self, data: Dict[str, Any], vendor: str) -> str:
        """Format as RFC 3164 syslog."""
        priority = 16 * 8 + data.get('severity', 5)  # Local0 facility
        timestamp_str = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
        hostname = data.get('hostname', socket.gethostname())
        
        # Vendor-specific message format
        vendor_key = vendor.lower().replace(" ", "_").replace("-", "_")
        
        if vendor_key == "cisco_asa":
            message = f"%ASA-{data.get('severity', 5)}-{data.get('event_code', '0')}: {data.get('message', '')}"
        elif vendor_key == "palo_alto_networks":
            message = f"PAN-OS: {data.get('message', '')}"
        else:
            message = f"{vendor}: {data.get('message', '')}"
        
        return f"<{priority}>{timestamp_str} {hostname} {message}"
    
    def _format_leef(self, data: Dict[str, Any], vendor: str) -> str:
        """Format as LEEF (Log Event Extended Format)."""
        # LEEF header
        header = f"LEEF:2.0|{vendor}|{data.get('product', 'Unknown')}|1.0|{data.get('event_name', 'Event')}"
        
        # LEEF attributes
        attributes = []
        
        leef_mappings = {
            'srcIP': data.get('source_ip'),
            'dstIP': data.get('destination_ip'),
            'srcPort': data.get('source_port'),
            'dstPort': data.get('destination_port'),
            'protocol': data.get('protocol'),
            'eventTime': data.get('timestamp'),
            'severity': data.get('severity')
        }
        
        for key, value in leef_mappings.items():
            if value is not None:
                if isinstance(value, datetime):
                    value = value.strftime("%Y-%m-%d %H:%M:%S")
                attributes.append(f"{key}={value}")
        
        # Generate syslog header
        priority = 16 * 8 + data.get('severity', 5)
        timestamp_str = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
        hostname = data.get('hostname', 'localhost')
        
        syslog_header = f"<{priority}>{timestamp_str} {hostname}"
        
        return f"{syslog_header} {header}|{'^'.join(attributes)}"
    
    def _format_raw(self, data: Dict[str, Any], vendor: str) -> str:
        """Format as raw vendor-specific format."""
        vendor_key = vendor.lower().replace(" ", "_").replace("-", "_")
        
        if vendor_key == "palo_alto_networks":
            # PAN-OS CSV format
            fields = [
                "FUTURE_USE",
                datetime.now().strftime("%Y/%m/%d %H:%M:%S"),
                f"01{random.randint(1000000000, 9999999999)}",
                data.get('event_name', 'TRAFFIC'),
                "",
                "1",
                datetime.now().strftime("%Y/%m/%d %H:%M:%S"),
                data.get('source_ip', ''),
                data.get('destination_ip', ''),
                data.get('source_ip', ''),  # NAT source
                data.get('destination_ip', ''),  # NAT destination
                data.get('rule', 'default'),
                data.get('username', ''),
                "",
                data.get('application', 'unknown'),
                "vsys1",
                "trust",
                "untrust",
                "ethernet1/1",
                "ethernet1/2",
                "default",
                datetime.now().strftime("%Y/%m/%d %H:%M:%S"),
                str(data.get('session_id', 123456)),
                "1",
                str(data.get('source_port', 0)),
                str(data.get('destination_port', 0)),
                "0", "0", "0x19",
                data.get('protocol', 'tcp').lower(),
                data.get('action', 'allow'),
                str(data.get('bytes', 0)),
                str(data.get('bytes_sent', 0)),
                str(data.get('bytes_received', 0)),
                str(data.get('packets', 0)),
                datetime.now().strftime("%Y/%m/%d %H:%M:%S"),
                "0",
                data.get('category', 'any'),
                "0", "0x8000000000000000",
                "US", "Reserved"
            ]
            return ",".join(fields)
        
        else:
            # Generic raw format
            return f"{datetime.now().isoformat()} {vendor} {data.get('message', '')}"


def validate_and_format_log(data: Dict[str, Any], vendor: str, format_type: LogFormat) -> Tuple[str, ValidationResult]:
    """Validate and format a log for Cortex compliance."""
    formatter = CortexLogFormatter()
    validator = CortexComplianceValidator()
    
    # Format the log
    formatted_log = formatter.format_log(data, vendor, format_type)
    
    # Validate the formatted log
    validation_result = validator.validate_log(formatted_log, vendor, format_type)
    
    return formatted_log, validation_result


# Export main functions for use by other modules
__all__ = [
    'LogFormat', 'CortexProduct', 'ValidationResult',
    'CortexComplianceValidator', 'CortexLogFormatter',
    'validate_and_format_log'
]