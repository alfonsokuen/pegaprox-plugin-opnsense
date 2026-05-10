"""Prometheus text exposition for the OPNsense plugin.

Renders the standard text format (v0.0.4) without depending on the
`prometheus_client` library — the plugin runs inside PegaProx whose
runtime we don't want to perturb. Tiny custom serializer is plenty for
our metric set (~10 metrics, mostly gauges).

Metric inventory (matches §4 of the brief):
- opnsense_up                              {host}                 0|1
- opnsense_pf_states_current               {host}                 gauge
- opnsense_pf_states_limit                 {host}                 gauge
- opnsense_memory_used_bytes               {host}                 gauge
- opnsense_memory_total_bytes              {host}                 gauge
- opnsense_iface_rx_bytes_total            {host, iface, label}   counter (informational)
- opnsense_iface_tx_bytes_total            {host, iface, label}   counter
- opnsense_iface_rx_errors_total           {host, iface}          counter
- opnsense_iface_tx_errors_total           {host, iface}          counter
- opnsense_iface_drops_total               {host, iface}          counter
- opnsense_iface_up                        {host, iface}          gauge 0|1
- opnsense_gateway_rtt_seconds             {host, gw}             gauge
- opnsense_gateway_loss_ratio              {host, gw}             gauge
- opnsense_gateway_up                      {host, gw}             gauge 0|1
- opnsense_service_running                 {host, service}        gauge 0|1
- opnsense_cert_expiry_seconds             {host, cert}           gauge
- opnsense_vpn_peers_total                 {host, type}           gauge
- opnsense_ha_enabled                      {host}                 gauge 0|1
"""
from __future__ import annotations

from typing import Any, Iterable

from src.client import OPNsenseClient
from src.collectors import (
    collect_certificates,
    collect_gateways,
    collect_hasync,
    collect_interfaces,
    collect_services,
    collect_system,
    collect_vpn,
)


def _escape(label: str) -> str:
    return str(label).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _line(name: str, value: float, labels: dict[str, Any] | None = None) -> str:
    if labels:
        rendered = ",".join(
            f'{k}="{_escape(v)}"' for k, v in labels.items() if v is not None
        )
        return f'{name}{{{rendered}}} {value}'
    return f"{name} {value}"


def _section(name: str, kind: str, help_text: str) -> Iterable[str]:
    yield f"# HELP {name} {help_text}"
    yield f"# TYPE {name} {kind}"


def render_metrics(client: OPNsenseClient, host_label: str | None = None) -> str:
    host = host_label or client.host.name
    common = {"host": host}
    out: list[str] = []

    # ---- system ----
    try:
        sys = collect_system(client)
        up = 1
    except Exception:
        # If even the system snapshot fails, surface up=0 and stop.
        out.extend(_section("opnsense_up", "gauge", "1 if the OPNsense API responded successfully"))
        out.append(_line("opnsense_up", 0, common))
        return "\n".join(out) + "\n"

    out.extend(_section("opnsense_up", "gauge", "1 if the OPNsense API responded successfully"))
    out.append(_line("opnsense_up", up, common))

    out.extend(_section("opnsense_pf_states_current", "gauge", "Current pf state count"))
    out.append(_line("opnsense_pf_states_current", sys["pf_states_current"], common))
    out.extend(_section("opnsense_pf_states_limit", "gauge", "pf state table size limit"))
    out.append(_line("opnsense_pf_states_limit", sys["pf_states_limit"], common))

    out.extend(_section("opnsense_memory_used_bytes", "gauge", "Memory used in bytes (approx, derived from MB)"))
    out.append(_line("opnsense_memory_used_bytes", sys["memory_used_mb"] * 1024 * 1024, common))
    out.extend(_section("opnsense_memory_total_bytes", "gauge", "Memory total in bytes (approx, derived from MB)"))
    out.append(_line("opnsense_memory_total_bytes", sys["memory_total_mb"] * 1024 * 1024, common))

    # ---- interfaces ----
    ifaces = collect_interfaces(client)
    out.extend(_section("opnsense_iface_rx_bytes_total", "counter", "Total bytes received per interface"))
    for i in ifaces:
        out.append(_line("opnsense_iface_rx_bytes_total", i["received_bytes"],
                         {**common, "iface": i["name"], "label": i["label"]}))
    out.extend(_section("opnsense_iface_tx_bytes_total", "counter", "Total bytes sent per interface"))
    for i in ifaces:
        out.append(_line("opnsense_iface_tx_bytes_total", i["sent_bytes"],
                         {**common, "iface": i["name"], "label": i["label"]}))
    out.extend(_section("opnsense_iface_rx_errors_total", "counter", "Total receive errors per interface"))
    for i in ifaces:
        out.append(_line("opnsense_iface_rx_errors_total", i["received_errors"],
                         {**common, "iface": i["name"]}))
    out.extend(_section("opnsense_iface_tx_errors_total", "counter", "Total transmit errors per interface"))
    for i in ifaces:
        out.append(_line("opnsense_iface_tx_errors_total", i["send_errors"],
                         {**common, "iface": i["name"]}))
    out.extend(_section("opnsense_iface_drops_total", "counter", "Dropped packets per interface"))
    for i in ifaces:
        out.append(_line("opnsense_iface_drops_total", i["dropped_packets"],
                         {**common, "iface": i["name"]}))
    out.extend(_section("opnsense_iface_up", "gauge", "1 if the interface is up+running"))
    for i in ifaces:
        out.append(_line("opnsense_iface_up", 1 if i["is_up"] else 0,
                         {**common, "iface": i["name"]}))

    # ---- gateways ----
    gws = collect_gateways(client)
    out.extend(_section("opnsense_gateway_rtt_seconds", "gauge", "Gateway monitor round-trip time in seconds"))
    for g in gws:
        out.append(_line("opnsense_gateway_rtt_seconds", g["delay_ms"] / 1000.0,
                         {**common, "gw": g["name"]}))
    out.extend(_section("opnsense_gateway_loss_ratio", "gauge", "Gateway monitor loss ratio (0..1)"))
    for g in gws:
        out.append(_line("opnsense_gateway_loss_ratio", g["loss_pct"] / 100.0,
                         {**common, "gw": g["name"]}))
    out.extend(_section("opnsense_gateway_up", "gauge", "1 if the gateway monitor reports Online"))
    for g in gws:
        out.append(_line("opnsense_gateway_up", 1 if g["is_up"] else 0,
                         {**common, "gw": g["name"]}))

    # ---- services ----
    svc = collect_services(client)
    out.extend(_section("opnsense_service_running", "gauge", "1 if the service is running"))
    for s in svc["items"]:
        out.append(_line("opnsense_service_running", 1 if s["running"] else 0,
                         {**common, "service": s["id"]}))

    # ---- certs ----
    certs = collect_certificates(client)
    out.extend(_section("opnsense_cert_expiry_seconds", "gauge", "Seconds until the certificate expires (negative if past)"))
    for c in certs:
        out.append(_line("opnsense_cert_expiry_seconds", c["days_to_expiry"] * 86400,
                         {**common, "cert": c["name"] or c["uuid"]}))

    # ---- VPN aggregates ----
    vpn = collect_vpn(client)
    out.extend(_section("opnsense_vpn_peers_total", "gauge", "Number of VPN peers/sessions per engine"))
    out.append(_line("opnsense_vpn_peers_total", len(vpn["wireguard_peers"]),
                     {**common, "type": "wireguard"}))
    out.append(_line("opnsense_vpn_peers_total", len(vpn["ipsec_phase1"]),
                     {**common, "type": "ipsec"}))
    out.append(_line("opnsense_vpn_peers_total", len(vpn["openvpn_sessions"]),
                     {**common, "type": "openvpn"}))

    # ---- HA ----
    ha = collect_hasync(client)
    out.extend(_section("opnsense_ha_enabled", "gauge", "1 if pfsync is configured (peer interface selected)"))
    out.append(_line("opnsense_ha_enabled", 1 if ha["enabled"] else 0, common))

    return "\n".join(out) + "\n"
