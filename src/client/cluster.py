"""Cluster-aware wrapper over two `OPNsenseClient`s.

Holds A and B with their canonical names (e.g. NODOA / NODOB), resolves
the current CARP master by querying both, and exposes:

  cluster.both()         -> (client_a, client_b)
  cluster.master()       -> the client whose CARP role is "master"
  cluster.backup()       -> the other one
  cluster.master_name()  -> "NODOA" | "NODOB"
  cluster.health()       -> {a: ok, b: ok, master: name, error?: str}

Master resolution is cached per request but never persisted across requests:
CARP roles can flip without notice, and a stale cache would route writes to
the wrong node. Callers wanting to avoid the extra round-trip can pass the
already-collected `CarpStatus` snapshots via `set_carp_cache(...)`.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from .opnsense_client import OPNsenseClient, OPNsenseError

if TYPE_CHECKING:
    from src.collectors.carp import CarpStatus

Side = Literal["a", "b"]


@dataclass
class _CarpProbe:
    role: str = "unknown"
    enabled: bool = False


class OPNsenseClusterClient:
    def __init__(self, client_a: OPNsenseClient, client_b: OPNsenseClient,
                 name_a: str = "NODOA", name_b: str = "NODOB") -> None:
        self.a = client_a
        self.b = client_b
        self.name_a = name_a
        self.name_b = name_b
        self._probe_a: _CarpProbe | None = None
        self._probe_b: _CarpProbe | None = None

    def both(self) -> tuple[OPNsenseClient, OPNsenseClient]:
        return self.a, self.b

    def names(self) -> tuple[str, str]:
        return self.name_a, self.name_b

    def set_carp_cache(self, status_a: "CarpStatus | None", status_b: "CarpStatus | None") -> None:
        """Populate the master-resolution cache from already-collected CARP snapshots."""
        if status_a is not None:
            self._probe_a = _CarpProbe(role=status_a.get("role", "unknown"),
                                       enabled=status_a.get("enabled", False))
        if status_b is not None:
            self._probe_b = _CarpProbe(role=status_b.get("role", "unknown"),
                                       enabled=status_b.get("enabled", False))

    def _ensure_probes(self) -> None:
        if self._probe_a is not None and self._probe_b is not None:
            return
        # Lazy import to avoid circular: collectors -> client -> cluster -> collectors.
        from src.collectors.carp import collect_carp_status
        if self._probe_a is None:
            s = collect_carp_status(self.a)
            self._probe_a = _CarpProbe(role=s["role"], enabled=s["enabled"])
        if self._probe_b is None:
            s = collect_carp_status(self.b)
            self._probe_b = _CarpProbe(role=s["role"], enabled=s["enabled"])

    def master_side(self) -> Side:
        """Return 'a' or 'b' identifying which client is the CARP master.

        Resolution rules (first match wins):
          1. If A is master and B is not master -> a
          2. If B is master and A is not master -> b
          3. Otherwise (both master, both backup, both disabled, unknown) -> a
             with the caller responsible for verifying via `health()` first.
        """
        self._ensure_probes()
        assert self._probe_a is not None and self._probe_b is not None
        if self._probe_a.role == "master" and self._probe_b.role != "master":
            return "a"
        if self._probe_b.role == "master" and self._probe_a.role != "master":
            return "b"
        return "a"

    def master(self) -> OPNsenseClient:
        return self.a if self.master_side() == "a" else self.b

    def backup(self) -> OPNsenseClient:
        return self.b if self.master_side() == "a" else self.a

    def master_name(self) -> str:
        return self.name_a if self.master_side() == "a" else self.name_b

    def backup_name(self) -> str:
        return self.name_b if self.master_side() == "a" else self.name_a

    def health(self) -> dict:
        reachable_a = True
        reachable_b = True
        err_a = err_b = ""
        try:
            self.a.get("/api/core/firmware/info")
        except OPNsenseError as e:
            reachable_a = False
            err_a = str(e)
        try:
            self.b.get("/api/core/firmware/info")
        except OPNsenseError as e:
            reachable_b = False
            err_b = str(e)

        try:
            master = self.master_name() if reachable_a and reachable_b else (
                self.name_a if reachable_a else self.name_b if reachable_b else ""
            )
        except OPNsenseError:
            master = ""

        return {
            "a": {"name": self.name_a, "reachable": reachable_a, "error": err_a},
            "b": {"name": self.name_b, "reachable": reachable_b, "error": err_b},
            "master": master,
        }
