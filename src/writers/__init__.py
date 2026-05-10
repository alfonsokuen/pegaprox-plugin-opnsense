"""Write operations against the OPNsense API.

Every writer follows the same lifecycle:

  1. validate the input (caller's responsibility — schemas live in routes/)
  2. POST the change → OPNsense returns `{result: "saved", uuid: "..."}`
  3. POST `<module>/reconfigure` (or `apply`) — empty JSON body, server
     refuses without a Content-Length so we always send `{}`
  4. (optional) POST `/api/core/hasync/syncTo` so the peer picks up the
     change, then re-fetch on the peer to verify.
  5. Append an audit row to the local JSONL log.
  6. On exception between (2) and (5) → rollback the original write.

This package exposes:
- `AuditLog`       — append-only JSONL recorder.
- `HAVerifier`     — calls hasync syncTo and re-fetches the peer.
- `AliasWriter`    — CRUD for `/api/firewall/alias/*`.
- `RuleWriter`     — CRUD for `/api/firewall/filter/*`.
"""
from .alias import AliasInput, AliasWriter  # noqa: F401
from .audit import AuditEntry, AuditLog  # noqa: F401
from .hasync_writer import HAVerifier  # noqa: F401
from .rule import RuleInput, RuleWriter  # noqa: F401
