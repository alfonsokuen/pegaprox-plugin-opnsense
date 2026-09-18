"""VPN status without loading the entire single-node or cluster overview."""
from src.client import OPNsenseClient, OPNsenseError
from src.collectors import collect_vpn
from src.routes.firewall import _error


def build_vpn_payload(host):
    try:
        return 200, {"ok": True, "data": {"vpn": collect_vpn(OPNsenseClient(host))}}
    except OPNsenseError as exc:
        return _error(exc)
