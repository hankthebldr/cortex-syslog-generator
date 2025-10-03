"""
CSV ingestion utilities for creating BaseEvent objects from a CSV file.
Expected CSV columns (missing values are handled with defaults):
  timestamp, vendor, product, severity, event_id, event_name, username,
  src_ip, src_port, dst_ip, dst_port, protocol, message
"""

import csv
from datetime import datetime, timezone
from typing import List, Optional
from uuid import uuid4

from ..core.models import BaseEvent, SeverityLevel, NetworkTuple, Actor, NICECategory
from ..catalog.vendor_catalog import get_nice_category


def _parse_int(value: Optional[str], default: int) -> int:
    try:
        return int(value) if value is not None and value != "" else default
    except Exception:
        return default


def _parse_ts(value: Optional[str]) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    for fmt in (
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
    ):
        try:
            dt = datetime.strptime(value, fmt)
            if not dt.tzinfo:
                return dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            continue
    # Fallback to now
    return datetime.now(timezone.utc)


def events_from_csv(
    csv_path: str,
    default_vendor: str = "Custom",
    default_product: str = "Generic",
) -> List[BaseEvent]:
    events: List[BaseEvent] = []

    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ts = _parse_ts(row.get("timestamp"))
            sev = _parse_int(row.get("severity"), SeverityLevel.INFO)
            vendor = row.get("vendor") or default_vendor
            product = row.get("product") or default_product
            event_name = row.get("event_name") or row.get("name") or "CustomEvent"
            message = row.get("message") or ""

            # Optional actor
            username = row.get("username") or row.get("user")
            actor = Actor(
                user_id=username or "user-unknown",
                username=username or "unknown",
            ) if username else None

            # Optional network tuple
            src_ip = row.get("src_ip") or row.get("source_ip")
            dst_ip = row.get("dst_ip") or row.get("destination_ip")
            src_port = _parse_int(row.get("src_port"), 0)
            dst_port = _parse_int(row.get("dst_port"), 0)
            proto = (row.get("protocol") or "TCP").upper()

            nt = None
            if src_ip and dst_ip and src_port and dst_port:
                nt = NetworkTuple(
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    source_port=src_port,
                    destination_port=dst_port,
                    protocol=proto,
                )

            ev = BaseEvent(
                event_id=uuid4(),
                timestamp=ts,
                vendor=vendor,
                product=product,
                event_name=event_name,
                message=message,
                severity=sev,
                actor=actor,
                network_tuple=nt,
            )

            # Assign NICE category if determinable
            try:
                nice = get_nice_category(vendor, product)
                if nice:
                    ev.nice_category = nice
            except Exception:
                pass
            events.append(ev)

    return events
