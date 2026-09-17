"""Native OPNsense 26.1 DNAT model adapter (no additional filter rules)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class PortForwardInput:
    interface: str
    target: str
    destination_port: str
    target_port: str
    source_net: str = "any"
    source_port: str = ""
    destination_net: str = "wanip"
    description: str = ""
    enabled: bool = False
    log: bool = False
    ipprotocol: str = "inet"
    protocol: str = "tcp"
    sequence: int = 1
    filter_association: str = ""
    natreflection: str = ""

    def to_payload(self) -> dict[str, Any]:
        return {"rule": {
            "interface": self.interface, "target": self.target,
            "source": {"network": self.source_net, "port": self.source_port},
            "destination": {"network": self.destination_net, "port": self.destination_port},
            "local-port": self.target_port, "descr": self.description,
            "disabled": "0" if self.enabled else "1", "log": "1" if self.log else "0",
            "ipprotocol": self.ipprotocol,
            "protocol": "TCP/UDP" if self.protocol.lower() == "tcp/udp" else self.protocol,
            "sequence": str(self.sequence), "pass": self.filter_association,
            "natreflection": self.natreflection,
        }}
