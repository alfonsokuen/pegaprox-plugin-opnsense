"""Read-only collectors against an OPNsense host.

Each collector takes an `OPNsenseClient` and returns a normalized snapshot
(dataclass-like TypedDict). They are deliberately small and composable so
the route layer can pick which to run per tab tick.
"""
from .carp import CarpStatus, CarpVhid, collect_carp_status  # noqa: F401
from .certificates import CertSummary, collect_certificates  # noqa: F401
from .firewall_log import LogEntry, collect_firewall_log  # noqa: F401
from .gateways import GatewayStatus, collect_gateways  # noqa: F401
from .hasync import HASyncSnapshot, collect_hasync  # noqa: F401
from .interfaces import InterfaceStat, collect_interfaces  # noqa: F401
from .routes import Neighbor, Route, collect_arp, collect_ndp, collect_routes  # noqa: F401
from .services import ServiceState, ServiceSummary, collect_services  # noqa: F401
from .system import SystemSnapshot, collect_system  # noqa: F401
from .vpn import (  # noqa: F401
    VPNPeer,
    VPNSnapshot,
    collect_ipsec,
    collect_openvpn,
    collect_vpn,
    collect_wireguard,
)
