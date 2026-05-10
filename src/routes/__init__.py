"""REST routes exposed by the plugin to the PegaProx dashboard."""
from .logs import build_logs_payload  # noqa: F401
from .nat import build_nat_action_payload, build_nat_list_payload  # noqa: F401
from .network import build_network, build_network_payload  # noqa: F401
from .overview import build_overview, build_overview_payload  # noqa: F401
from .unbound import build_unbound_action_payload, build_unbound_list_payload  # noqa: F401
from .wg import build_wg_action_payload, build_wg_list_payload  # noqa: F401
