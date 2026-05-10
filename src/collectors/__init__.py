"""Read-only collectors against an OPNsense host.

Each collector takes an `OPNsenseClient` and returns a normalized snapshot
(dataclass-like TypedDict). They are deliberately small and composable so
the route layer can pick which to run per tab tick.
"""
from .certificates import CertSummary, collect_certificates  # noqa: F401
from .gateways import GatewayStatus, collect_gateways  # noqa: F401
from .interfaces import InterfaceStat, collect_interfaces  # noqa: F401
from .services import ServiceState, ServiceSummary, collect_services  # noqa: F401
from .system import SystemSnapshot, collect_system  # noqa: F401
