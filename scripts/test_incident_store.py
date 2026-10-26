"""Phase 0 smoke test for the shared incident-state store.

Inserts a dummy incident, reads it back, verifies every field survived the
round trip, exercises the payload merge, then cleans up after itself.

    python scripts/test_incident_store.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from shared.schemas import IncidentStatus, Severity, new_incident_id  # noqa: E402
from shared.store import IncidentStore  # noqa: E402


def main() -> int:
    store = IncidentStore()
    print(f"[store] dsn = {store.dsn}")

    if not store.ping():
        print("[store] FAIL: could not SELECT 1")
        return 1
    print("[store] connection ok")

    incident_id = new_incident_id()
    payload = {
        "note": "phase-0 dummy record",
        "observed": {"source_ip": "203.0.113.42", "failed_logins": 7},
    }

    created = store.create_incident(
        incident_id, status=IncidentStatus.DETECTED, severity=None, raw_payload=payload
    )
    print(f"[store] inserted  {created.incident_id} status={created.status} severity={created.severity}")

    fetched = store.get_incident(incident_id)
    if fetched is None:
        print("[store] FAIL: record not found after insert")
        return 1

    checks = {
        "incident_id": fetched.incident_id == incident_id,
        "status": fetched.status == "DETECTED",
        "severity is null": fetched.severity is None,
        "raw_payload round-trip": fetched.raw_payload == payload,
        "created_at set": fetched.created_at is not None,
        "updated_at set": fetched.updated_at is not None,
    }
    for name, ok in checks.items():
        print(f"[store] {'PASS' if ok else 'FAIL'}  {name}")
    if not all(checks.values()):
        return 1

    print(f"[store] read back  raw_payload = {fetched.raw_payload}")

    # Payload merge must add keys without dropping the existing ones.
    updated = store.update_incident(
        incident_id,
        status=IncidentStatus.ASSESSED,
        severity=Severity.HIGH,
        raw_payload={"assigned_to": "on_call"},
    )
    merge_ok = (
        updated is not None
        and updated.status == "ASSESSED"
        and updated.severity == "High"
        and updated.raw_payload.get("note") == "phase-0 dummy record"
        and updated.raw_payload.get("assigned_to") == "on_call"
        and updated.updated_at >= updated.created_at
    )
    print(f"[store] {'PASS' if merge_ok else 'FAIL'}  update + payload merge + updated_at trigger")
    if not merge_ok:
        return 1

    store.delete_incident(incident_id)
    if store.get_incident(incident_id) is not None:
        print("[store] FAIL: cleanup did not remove the test record")
        return 1
    print("[store] cleaned up test record")

    print("\n[store] ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
