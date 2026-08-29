"""
CampusShield AI — Live Passive Inbound Traffic Collector
==========================================================
Receives incoming request telemetry from test websites, packet forwarders,
or passive network taps WITHOUT sending any outbound traffic.

Analyzes source IP origins, request frequencies, protocol distributions,
and runs them through the unidirectional anomaly detection engine.
"""

import time
from typing import Any
from pydantic import BaseModel


class InboundTrafficEvent(BaseModel):
    source_ip: str | None = None
    target_path: str = "/"
    method: str = "GET"
    payload_size: int = 128
    headers: dict[str, str] | None = None
    user_agent: str | None = None


class BatchInboundTelemetry(BaseModel):
    target_host: str = "localhost"
    target_port: int = 8000
    events: list[InboundTrafficEvent]


# In-memory circular buffer of live captured events
_MAX_LIVE_BUFFER = 2000
_LIVE_INBOUND_BUFFER: list[dict[str, Any]] = []


def record_live_inbound_event(
    client_ip: str,
    method: str = "GET",
    path: str = "/",
    payload_size: int = 128,
    headers: dict | None = None,
) -> dict:
    """Record an incoming observed request in the passive listener buffer."""
    now = time.time()
    event = {
        "timestamp": now,
        "src_ip": client_ip or "127.0.0.1",
        "method": method,
        "path": path,
        "size": max(40, payload_size),
        "headers": headers or {},
    }
    _LIVE_INBOUND_BUFFER.append(event)
    if len(_LIVE_INBOUND_BUFFER) > _MAX_LIVE_BUFFER:
        _LIVE_INBOUND_BUFFER.pop(0)

    return event


def get_recent_inbound_events(limit: int = 100) -> list[dict]:
    """Retrieve the most recent passive incoming telemetry events."""
    return _LIVE_INBOUND_BUFFER[-limit:]
