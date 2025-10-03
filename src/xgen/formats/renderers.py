"""
Format renderers: CEF, LEEF, and JSON.

These functions convert BaseEvent instances into strings suitable for
transport. CEF/LEEF are rendered with proper escaping; JSON renderer
returns normalized JSON strings.
"""

import json
import re
from datetime import datetime
from typing import List

from ..core.models import BaseEvent, LogFormat


CEF_HEADER = "CEF:0|{vendor}|{product}|{version}|{event_code}|{event_name}|{severity}|"

# CEF escaping per spec: backslash and equals, pipes, and newlines
_CEF_ESCAPE_MAP = {
    "\\": r"\\\\",
    "|": r"\|",
    "=": r"\=",
    "\n": r"\\n",
    "\r": r"\\r"
}


def _cef_escape(value: str) -> str:
    s = str(value)
    for k, v in _CEF_ESCAPE_MAP.items():
        s = s.replace(k, v)
    return s


def _map_device_direction(direction: str) -> int:
    if not direction:
        return 2  # unknown
    d = direction.strip().lower()
    if d in ("in", "inbound"):
        return 0
    if d in ("out", "outbound"):
        return 1
    return 2


def render_cef(events: List[BaseEvent]) -> List[str]:
    rendered = []
    for e in events:
        header = CEF_HEADER.format(
            vendor=_cef_escape(e.vendor),
            product=_cef_escape(e.product),
            version=_cef_escape(getattr(e, "generator_version", "1.0")),
            event_code=_cef_escape(e.event_code or "0"),
            event_name=_cef_escape(e.event_name),
            severity=int(e.severity),
        )
        # Common CEF extensions
        ext = {
            "rt": int(e.timestamp.timestamp() * 1000),
            "msg": e.message,
            "deviceVendor": e.vendor,
            "deviceProduct": e.product,
            "externalId": str(e.event_id),
            "cat": e.nice_category,
            "act": getattr(e, 'action', None) or e.labels.get('action') if hasattr(e, 'labels') else None,
            "deviceDirection": _map_device_direction(getattr(e, 'direction', None)),
            "patternId": e.pattern_id or "",
            "burstId": str(e.burst_id) if e.burst_id else "",
            "sequenceNumber": e.sequence_number or 0,
        }
        # 5-tuple
        if e.network_tuple:
            ext.update({
                "src": e.network_tuple.source_ip,
                "dst": e.network_tuple.destination_ip,
                "spt": e.network_tuple.source_port,
                "dpt": e.network_tuple.destination_port,
                "proto": e.network_tuple.protocol,
            })
        # Legacy fallbacks
        else:
            if e.source_ip: ext["src"] = e.source_ip
            if e.destination_ip: ext["dst"] = e.destination_ip
            if e.source_port: ext["spt"] = e.source_port
            if e.destination_port: ext["dpt"] = e.destination_port
            if e.protocol: ext["proto"] = e.protocol
        
        # Hostnames
        if getattr(e, 'source_asset', None) and getattr(e.source_asset, 'hostname', None):
            ext['shost'] = e.source_asset.hostname
        if getattr(e, 'destination_asset', None) and getattr(e.destination_asset, 'hostname', None):
            ext['dhost'] = e.destination_asset.hostname
        
        # Username
        if getattr(e, 'actor', None) and getattr(e.actor, 'username', None):
            ext['suser'] = e.actor.username
        
        # Domain
        if getattr(e, 'domain', None):
            ext['destinationDnsDomain'] = e.domain
            ext['cs2Label'] = 'domain'
            ext['cs2'] = e.domain
        
        # File/Process fields (Endpoint)
        if hasattr(e, 'file_path') and getattr(e, 'file_path', None):
            ext['filePath'] = e.file_path
        if hasattr(e, 'file_hash') and getattr(e, 'file_hash', None):
            ext['fileHash'] = e.file_hash
        if hasattr(e, 'process_sha256') and getattr(e, 'process_sha256', None):
            # Provide explicit SHA256 label if available
            ext['cs6Label'] = 'sha256'
            ext['cs6'] = e.process_sha256
        if hasattr(e, 'command_line') and getattr(e, 'command_line', None):
            ext['cs1Label'] = 'processCmd'
            ext['cs1'] = e.command_line
        
        # Build CEF extension string
        ext_str = " ".join([f"{k}={_cef_escape(v)}" for k, v in ext.items() if v not in (None, "")])
        rendered.append(header + ext_str)
    return rendered


def render_leef(events: List[BaseEvent]) -> List[str]:
    """Render events as LEEF (Log Event Extended Format) v2.0."""
    rendered = []
    for e in events:
        # LEEF:2.0|Vendor|Product|Version|EventID|Delimiter|Extensions
        delim = "\t"  # Tab delimiter
        header = f"LEEF:2.0|{e.vendor}|{e.product}|1.0|{e.event_code or '0'}|{delim}"
        
        # LEEF extensions (key=value pairs separated by delimiter)
        ext = {
            "devTime": e.timestamp.strftime("%b %d %Y %H:%M:%S"),
            "devTimeFormat": "MMM dd yyyy HH:mm:ss",
            "severity": str(e.severity),
            "eventName": e.event_name,
            "message": e.message,
            "externalId": str(e.event_id),
            "cat": e.nice_category or "",
            "action": getattr(e, 'action', None) or e.labels.get('action') if hasattr(e, 'labels') else None,
            "direction": getattr(e, 'direction', None) or "unknown",
            "patternId": e.pattern_id or "",
            "burstId": str(e.burst_id) if e.burst_id else "",
            "sequenceNumber": str(e.sequence_number or 0),
        }
        
        # Add 5-tuple
        if e.network_tuple:
            ext.update({
                "srcIP": e.network_tuple.source_ip,
                "dstIP": e.network_tuple.destination_ip,
                "srcPort": str(e.network_tuple.source_port),
                "dstPort": str(e.network_tuple.destination_port),
                "protocol": e.network_tuple.protocol,
            })
        
        # Add actor info
        if e.actor:
            ext.update({
                "usrName": e.actor.username,
                "usrID": e.actor.user_id,
            })
        
        # Hostname and domain
        if getattr(e, 'source_asset', None) and getattr(e.source_asset, 'hostname', None):
            ext['hostName'] = e.source_asset.hostname
        if getattr(e, 'domain', None):
            ext['domain'] = e.domain
        
        # File/Process fields
        if hasattr(e, 'file_path') and getattr(e, 'file_path', None):
            ext['filePath'] = e.file_path
        if hasattr(e, 'file_hash') and getattr(e, 'file_hash', None):
            ext['fileHash'] = e.file_hash
        if hasattr(e, 'process_sha256') and getattr(e, 'process_sha256', None):
            ext['sha256'] = e.process_sha256
        if hasattr(e, 'command_line') and getattr(e, 'command_line', None):
            ext['processCmd'] = e.command_line
        
        # Build LEEF extension string
        ext_str = delim.join([f"{k}={v}" for k, v in ext.items() if v not in (None, "")])
        rendered.append(header + ext_str)
    
    return rendered


def render_json(events: List[BaseEvent]) -> List[str]:
    rendered = []
    for e in events:
        obj = {
            "timestamp": e.timestamp.isoformat(),
            "event_id": str(e.event_id),
            "external_id": str(e.event_id),
            "vendor": e.vendor,
            "product": e.product,
            "event_name": e.event_name,
            "event_code": e.event_code,
            "severity": int(e.severity),
            "message": e.message,
            "nice_category": e.nice_category,
            "category": e.nice_category,
            "action": getattr(e, 'action', None) or e.labels.get('action') if hasattr(e, 'labels') else None,
            "direction": getattr(e, 'direction', None),
            "pattern_id": e.pattern_id,
            "burst_id": str(e.burst_id) if e.burst_id else None,
            "sequence_number": e.sequence_number,
            "scenario_id": str(e.scenario_id) if e.scenario_id else None,
            "hostname": getattr(e.source_asset, 'hostname', None) if getattr(e, 'source_asset', None) else None,
            "username": getattr(e.actor, 'username', None) if getattr(e, 'actor', None) else None,
            "domain": getattr(e, 'domain', None),
            "process_command_line": getattr(e, 'command_line', None) if hasattr(e, 'command_line') else None,
            "process_sha256": getattr(e, 'process_sha256', None) if hasattr(e, 'process_sha256') else None,
            "process_file_path": getattr(e, 'file_path', None) if hasattr(e, 'file_path') else None,
        }
        if e.network_tuple:
            obj.update({
                "src_ip": e.network_tuple.source_ip,
                "dest_ip": e.network_tuple.destination_ip,
                "src_port": e.network_tuple.source_port,
                "dest_port": e.network_tuple.destination_port,
                "protocol": e.network_tuple.protocol,
            })
        rendered.append(json.dumps(obj))
    return rendered


def render_events(events: List[BaseEvent], fmt: LogFormat) -> List[str]:
    if fmt == LogFormat.CEF:
        return render_cef(events)
    elif fmt == LogFormat.LEEF:
        return render_leef(events)
    elif fmt == LogFormat.JSON:
        return render_json(events)
    else:
        raise ValueError(f"Unsupported format: {fmt}")
