"""REST routes exposed by the plugin to the PegaProx dashboard."""
from .dhcp import build_dhcp_action_payload, build_dhcp_list_payload  # noqa: F401
from .logs import build_logs_payload  # noqa: F401
from .nat import build_nat_action_payload, build_nat_list_payload  # noqa: F401
from .one_to_one import (  # noqa: F401
    build_one_to_one_action_payload,
    build_one_to_one_list_payload,
)
from .network import build_network, build_network_payload  # noqa: F401
from .overview import build_overview, build_overview_payload  # noqa: F401
from .unbound import (  # noqa: F401
    build_unbound_action_payload,
    build_unbound_domain_action_payload,
    build_unbound_domain_list_payload,
    build_unbound_dot_action_payload,
    build_unbound_dot_list_payload,
    build_unbound_list_payload,
)
from .wg import build_wg_action_payload, build_wg_list_payload  # noqa: F401
