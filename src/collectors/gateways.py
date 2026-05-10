"""Gateway monitor — RTT, loss, status per gateway."""
from __future__ import annotations

from typing import TypedDict

from src.client import OPNsenseClient


class GatewayStatus(TypedDict):
    name: str
    address: str
    monitor: str
    status: str             # raw OPNsense ("none", "down", ...)
    status_human: str       # status_translated
    delay_ms: float
    loss_pct: float
    stddev_ms: float
    is_up: bool


def _parse_metric(value: str) -> float:
    """OPNsense returns '~' or '12.345 ms' or '0.0 %'. Coerce to float."""
    if not value or value == "~":
        return 0.0
    cleaned = value.replace("ms", "").replace("%", "").strip()
    try:
        return float(cleaned)
    except ValueError:
        return 0.0


def collect_gateways(client: OPNsenseClient) -> list[GatewayStatus]:
    payload = client.get("/api/routes/gateway/status")
    items = payload.get("items", []) if isinstance(payload, dict) else []
    out: list[GatewayStatus] = []
    for it in items:
        status_raw = str(it.get("status", "none"))
        status_human = str(it.get("status_translated", ""))
        out.append(
            GatewayStatus(
                name=str(it.get("name", "")),
                address=str(it.get("address", "")),
                monitor=str(it.get("monitor", "")),
                status=status_raw,
                status_human=status_human,
                delay_ms=_parse_metric(str(it.get("delay", ""))),
                loss_pct=_parse_metric(str(it.get("loss", ""))),
                stddev_ms=_parse_metric(str(it.get("stddev", ""))),
                # "Online" + status "none" = monitoring disabled but iface up.
                # "down" or any non-Online translation = treated as down.
                is_up=status_human.lower() == "online",
            )
        )
    return out
