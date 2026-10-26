"""Locally-simulated firewall state.

**This is NOT a real cloud firewall.** Cloud deploy is still deferred (Phase
0/1), so there is no real security group / WAF to call. Instead, "blocking an
IP" writes to a local JSON state file that represents which IPs are currently
blocked -- something the target app could plausibly consult. The Phase 2 report
labels this as local-simulated so the gap is visible, not hidden.

When a real cloud account exists, only this module changes: `block_ip` makes
the actual API call (e.g. authorize/revoke a security-group ingress rule) and
the state file becomes a cache of it.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger("containment.firewall")

STATE_FILE = Path(
    os.environ.get(
        "CONTAINMENT_FIREWALL_STATE",
        Path(__file__).resolve().parents[1] / "containment" / "firewall_state.json",
    )
)

# Marker so no one mistakes this for a real control plane.
_SIMULATED = True


def _load() -> Dict[str, Any]:
    if not STATE_FILE.exists():
        return {"simulated": _SIMULATED, "blocked": {}}
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        logger.warning("firewall state unreadable; starting fresh")
        return {"simulated": _SIMULATED, "blocked": {}}


def _save(state: Dict[str, Any]) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")


def blocked_ips() -> List[str]:
    return sorted(_load().get("blocked", {}).keys())


def is_blocked(ip: str) -> bool:
    return ip in _load().get("blocked", {})


def block_ips(ips: List[str], *, incident_id: str, reason: str) -> Dict[str, Any]:
    """Block a set of IPs in the simulated firewall. The real side effect.

    Idempotent per IP. Returns a record of what changed, which the caller logs
    and reports back as evidence the action actually ran.
    """
    state = _load()
    blocked = state.setdefault("blocked", {})
    now = datetime.now(timezone.utc).isoformat()

    newly, already = [], []
    for ip in ips:
        if ip in blocked:
            already.append(ip)
        else:
            blocked[ip] = {"incident_id": incident_id, "reason": reason, "blocked_at": now}
            newly.append(ip)

    state["simulated"] = _SIMULATED
    state["updated_at"] = now
    _save(state)

    logger.warning(
        "[SIMULATED FIREWALL] blocked %d new IP(s) %s (already blocked: %s) for incident %s",
        len(newly), newly, already, incident_id,
    )
    return {
        "simulated": _SIMULATED,
        "newly_blocked": newly,
        "already_blocked": already,
        "total_blocked_now": len(blocked),
        "at": now,
    }


def unblock_ips(ips: List[str], *, incident_id: str, reason: str) -> Dict[str, Any]:
    """Lift blocks on a set of IPs. The recovery side effect (Phase 3).

    Only removes rules this incident created, so recovery of one incident never
    lifts a block another incident still needs.
    """
    state = _load()
    blocked = state.setdefault("blocked", {})
    now = datetime.now(timezone.utc).isoformat()

    removed, skipped = [], []
    for ip in ips:
        rule = blocked.get(ip)
        if rule is None:
            continue
        if rule.get("incident_id") == incident_id:
            del blocked[ip]
            removed.append(ip)
        else:
            skipped.append(ip)  # owned by a different incident; leave it

    state["simulated"] = _SIMULATED
    state["updated_at"] = now
    _save(state)

    logger.warning(
        "[SIMULATED FIREWALL] unblocked %d IP(s) %s (kept for other incidents: %s) for incident %s",
        len(removed), removed, skipped, incident_id,
    )
    return {
        "simulated": _SIMULATED,
        "unblocked": removed,
        "kept_for_other_incidents": skipped,
        "total_blocked_now": len(blocked),
        "at": now,
    }
