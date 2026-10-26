"""Phase 3 exit criterion 6: the simulated firewall is genuinely reverted once
Forensics signals it is safe to lift containment.

Seeds a CONTAINED incident with a real block in the simulated firewall, then
sends a real recovery_plan A2A (Forensics -> Containment) with safe_to_lift.
The lift only happens on that signal, through the authorized Forensics->
Containment path -- and the block for the incident is actually removed.

    .venv-adk\\Scripts\\python scripts/test_recovery_revert.py   (needs the stack + a2a-sdk)
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from containment.firewall import block_ips, blocked_ips  # noqa: E402
from shared.a2a_support import CONTAINMENT_URL, send_incident_message  # noqa: E402
from shared.guardrail import ACTION_RECOVERY_PLAN  # noqa: E402
from shared.schemas import IncidentMessage, IncidentStatus, Severity, SystemName, new_incident_id  # noqa: E402
from shared.store import IncidentStore  # noqa: E402

results = {}


def check(name, ok, detail=""):
    results[name] = ok
    print(f"[recovery] {'PASS' if ok else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""))


async def _send(incident_id, safe_to_lift):
    msg = IncidentMessage(
        incident_id=incident_id, source_system=SystemName.FORENSICS,
        target_system=SystemName.CONTAINMENT,
        payload={"action": ACTION_RECOVERY_PLAN, "safe_to_lift": safe_to_lift, "plan": "test recovery"},
    )
    return await send_incident_message(msg, peer_base_url=CONTAINMENT_URL)


def main() -> int:
    store = IncidentStore()
    iid = new_incident_id()
    attacker_ips = [f"203.0.113.{200 + (hash(iid) % 20)}", f"203.0.113.{220 + (hash(iid) % 20)}"]

    # Seed a contained incident with a genuine block in the simulated firewall.
    store.create_incident(iid, status=IncidentStatus.CONTAINED, severity=Severity.HIGH,
                          incident_type="Brute Force",
                          raw_payload={"containment": {"blocked_ips": attacker_ips, "state": "EXECUTED"}})
    block_ips(attacker_ips, incident_id=iid, reason="recovery test seed")
    check("firewall shows the incident's IPs blocked before recovery",
          all(ip in blocked_ips() for ip in attacker_ips), str(attacker_ips))

    # 1) safe_to_lift=False -> blocks must remain.
    reply_no = asyncio.run(_send(iid, False))
    check("recovery_plan(safe_to_lift=False) does NOT lift",
          reply_no.payload.get("lifted") is False and all(ip in blocked_ips() for ip in attacker_ips))

    # 2) safe_to_lift=True -> the real block is reverted.
    reply_yes = asyncio.run(_send(iid, True))
    lifted = reply_yes.payload.get("lifted") is True
    gone = all(ip not in blocked_ips() for ip in attacker_ips)
    check("recovery_plan(safe_to_lift=True) lifts via Containment", lifted, f"unblocked={reply_yes.payload.get('unblocked')}")
    check("the simulated firewall rule is genuinely reverted", gone, f"still blocked? {[ip for ip in attacker_ips if ip in blocked_ips()]}")

    rec = store.get_incident(iid)
    check("recovery recorded on the incident", (rec.raw_payload or {}).get("recovery", {}).get("lifted") is True)

    store.delete_incident(iid)

    failed = [k for k, v in results.items() if not v]
    print(f"\n[recovery] {len(results) - len(failed)}/{len(results)} checks passed")
    if failed:
        print("[recovery] FAILED: " + ", ".join(failed)); return 1
    print("[recovery] ALL PASSED -- gated recovery revert works")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
