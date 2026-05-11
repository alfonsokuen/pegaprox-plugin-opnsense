"""Cross-node divergence detector for OPNsense HA pairs.

Takes two per-node snapshots (the same shape `build_overview` returns) and
emits a flat list of `Divergence` entries. Each entry has a `category`, a
human-readable `key`, a `severity`, and the two values for context.

Categories covered (v1.13.0):
- system          config_revision drift, version mismatch
- carp            split-brain (both master / both backup / one unknown)
- hasync          pfSync disabled on one side, peer-ip mismatch
- services        running set difference
- gateways        status mismatch (online on A, offline on B)
- interfaces      link state mismatch on the same iface name
- certs           cert present on one side only, by SHA256 fingerprint

NOT covered yet (v1.14+): firewall rules, NAT rules, full alias content,
DHCP reservations, Unbound entries, WireGuard peers. These need writer-level
listing endpoints that aren't aggregated in the overview snapshot.
"""
from __future__ import annotations

from typing import Any, Literal, TypedDict

Severity = Literal["info", "warning", "error"]


class Divergence(TypedDict):
    category: str
    key: str
    severity: Severity
    a: Any
    b: Any
    detail: str


def _eq_or_diff(category: str, key: str, a: Any, b: Any, severity: Severity, detail: str) -> Divergence | None:
    if a == b:
        return None
    return Divergence(category=category, key=key, severity=severity, a=a, b=b, detail=detail)


def _diff_system(a: dict, b: dict) -> list[Divergence]:
    out: list[Divergence] = []
    a_sys, b_sys = a.get("system", {}) or {}, b.get("system", {}) or {}
    for field, sev, detail in (
        ("config_revision", "warning", "Config revision drift — pfSync may be falling behind."),
        ("version", "info", "OPNsense version mismatch between peers."),
        ("product_id", "info", "Product/edition mismatch (Business vs Community)."),
    ):
        d = _eq_or_diff("system", field, a_sys.get(field), b_sys.get(field), sev, detail)
        if d:
            out.append(d)
    return out


def _diff_carp(a: dict, b: dict) -> list[Divergence]:
    a_c, b_c = a.get("carp", {}) or {}, b.get("carp", {}) or {}
    role_a, role_b = a_c.get("role"), b_c.get("role")
    out: list[Divergence] = []
    if not role_a or not role_b:
        return out
    # Healthy pair: exactly one master + one backup. Anything else flags.
    healthy = {role_a, role_b} == {"master", "backup"}
    if not healthy and (role_a, role_b) != ("disabled", "disabled"):
        sev: Severity = "error" if (role_a == "master" and role_b == "master") else "warning"
        out.append(Divergence(
            category="carp",
            key="role_pair",
            severity=sev,
            a=role_a,
            b=role_b,
            detail=("Split-brain: both nodes report MASTER." if sev == "error"
                    else f"Unexpected CARP roles ({role_a} / {role_b}); expected master+backup."),
        ))
    # Maintenance mode toggled on one side only is usually intentional but worth surfacing.
    if a_c.get("maintenance_mode") != b_c.get("maintenance_mode"):
        out.append(Divergence(
            category="carp",
            key="maintenance_mode",
            severity="info",
            a=a_c.get("maintenance_mode"),
            b=b_c.get("maintenance_mode"),
            detail="Maintenance mode enabled on one node only.",
        ))
    # Demotion delta: negative values indicate CARP demoted the node due to
    # interface trouble. If either side reports demotion != 0, surface it.
    dem_a, dem_b = a_c.get("demotion", 0), b_c.get("demotion", 0)
    if dem_a != dem_b and (dem_a or dem_b):
        out.append(Divergence(
            category="carp",
            key="demotion",
            severity="warning",
            a=dem_a,
            b=dem_b,
            detail="CARP demotion values differ — at least one node has been demoted by a link/service issue.",
        ))
    return out


def _diff_hasync(a: dict, b: dict) -> list[Divergence]:
    a_h, b_h = a.get("hasync", {}) or {}, b.get("hasync", {}) or {}
    out: list[Divergence] = []
    if a_h.get("enabled") != b_h.get("enabled"):
        out.append(Divergence(
            category="hasync",
            key="enabled",
            severity="error",
            a=a_h.get("enabled"),
            b=b_h.get("enabled"),
            detail="pfSync enabled on one node only — config drift will accumulate.",
        ))
    for field, sev, detail in (
        ("pfsync_interface", "warning", "pfSync interface differs between peers."),
        ("pfsync_version", "info", "pfSync version mismatch."),
        ("sync_compatibility", "info", "Sync compatibility setting differs."),
    ):
        d = _eq_or_diff("hasync", field, a_h.get(field), b_h.get(field), sev, detail)
        if d:
            out.append(d)
    return out


def _diff_services(a: dict, b: dict) -> list[Divergence]:
    a_s = a.get("services", {}) or {}
    b_s = b.get("services", {}) or {}
    items_a = {svc.get("name"): svc for svc in (a_s.get("items", []) or []) if svc.get("name")}
    items_b = {svc.get("name"): svc for svc in (b_s.get("items", []) or []) if svc.get("name")}
    out: list[Divergence] = []
    for name in sorted(set(items_a) | set(items_b)):
        ra = items_a.get(name, {}).get("running")
        rb = items_b.get(name, {}).get("running")
        if ra != rb:
            out.append(Divergence(
                category="services",
                key=name,
                severity="warning",
                a=ra,
                b=rb,
                detail=f"Service '{name}' running state differs.",
            ))
    return out


def _diff_gateways(a: dict, b: dict) -> list[Divergence]:
    a_g = {g.get("name"): g for g in (a.get("gateways", []) or []) if isinstance(g, dict)}
    b_g = {g.get("name"): g for g in (b.get("gateways", []) or []) if isinstance(g, dict)}
    out: list[Divergence] = []
    for name in sorted(set(a_g) | set(b_g)):
        sa = a_g.get(name, {}).get("status")
        sb = b_g.get(name, {}).get("status")
        if sa != sb:
            out.append(Divergence(
                category="gateways",
                key=name or "<unnamed>",
                severity="warning",
                a=sa,
                b=sb,
                detail=f"Gateway '{name}' reports different status on each node.",
            ))
    return out


def _diff_interfaces(a: dict, b: dict) -> list[Divergence]:
    a_i = {i.get("name"): i for i in (a.get("interfaces", []) or []) if isinstance(i, dict)}
    b_i = {i.get("name"): i for i in (b.get("interfaces", []) or []) if isinstance(i, dict)}
    out: list[Divergence] = []
    for name in sorted(set(a_i) | set(b_i)):
        la = a_i.get(name, {}).get("link")
        lb = b_i.get(name, {}).get("link")
        if la != lb and {la, lb} <= {"up", "down", None, ""}:
            out.append(Divergence(
                category="interfaces",
                key=name or "<unnamed>",
                severity="warning",
                a=la,
                b=lb,
                detail=f"Interface '{name}' link state differs.",
            ))
    return out


def _diff_certs(a: dict, b: dict) -> list[Divergence]:
    a_c = a.get("certs", {}) or {}
    b_c = b.get("certs", {}) or {}
    list_a = a_c.get("expiring_soon", []) or []
    list_b = b_c.get("expiring_soon", []) or []
    fps_a = {c.get("fingerprint") or c.get("descr"): c for c in list_a if isinstance(c, dict)}
    fps_b = {c.get("fingerprint") or c.get("descr"): c for c in list_b if isinstance(c, dict)}
    out: list[Divergence] = []
    only_a = set(fps_a) - set(fps_b)
    only_b = set(fps_b) - set(fps_a)
    for k in sorted(only_a):
        out.append(Divergence(
            category="certs",
            key=str(k),
            severity="info",
            a="present",
            b="missing",
            detail="Certificate (expiring soon) present on A only.",
        ))
    for k in sorted(only_b):
        out.append(Divergence(
            category="certs",
            key=str(k),
            severity="info",
            a="missing",
            b="present",
            detail="Certificate (expiring soon) present on B only.",
        ))
    return out


def compute_divergence(snapshot_a: dict, snapshot_b: dict) -> list[Divergence]:
    """Compare two per-node overview snapshots. Empty list = nodes are in sync."""
    out: list[Divergence] = []
    out.extend(_diff_system(snapshot_a, snapshot_b))
    out.extend(_diff_carp(snapshot_a, snapshot_b))
    out.extend(_diff_hasync(snapshot_a, snapshot_b))
    out.extend(_diff_services(snapshot_a, snapshot_b))
    out.extend(_diff_gateways(snapshot_a, snapshot_b))
    out.extend(_diff_interfaces(snapshot_a, snapshot_b))
    out.extend(_diff_certs(snapshot_a, snapshot_b))
    # Stable order: severity desc (error > warning > info), then category, then key.
    rank = {"error": 0, "warning": 1, "info": 2}
    out.sort(key=lambda d: (rank.get(d["severity"], 9), d["category"], d["key"]))
    return out
