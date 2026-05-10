"""Services collector — running/locked state per OPNsense service."""
from __future__ import annotations

from typing import TypedDict

from src.client import OPNsenseClient


class ServiceState(TypedDict):
    id: str
    name: str
    description: str
    running: bool
    locked: bool


class ServiceSummary(TypedDict):
    total: int
    running: int
    stopped: int
    items: list[ServiceState]


def _bool_from_int(value: object) -> bool:
    try:
        return int(str(value).strip()) == 1
    except (ValueError, AttributeError):
        return False


def collect_services(client: OPNsenseClient) -> ServiceSummary:
    payload = client.get("/api/core/service/search")
    rows = payload.get("rows", []) if isinstance(payload, dict) else []

    items: list[ServiceState] = []
    running = 0
    for r in rows:
        is_running = _bool_from_int(r.get("running"))
        if is_running:
            running += 1
        items.append(
            ServiceState(
                id=str(r.get("id", "")),
                name=str(r.get("name", "")),
                description=str(r.get("description", "")),
                running=is_running,
                locked=_bool_from_int(r.get("locked")),
            )
        )
    return ServiceSummary(
        total=len(items),
        running=running,
        stopped=len(items) - running,
        items=items,
    )
