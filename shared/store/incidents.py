"""Client for the shared incident-state store (Postgres).

Every agent system talks to the same `incidents` table over the network. This
module is the one place the SQL lives so the six systems cannot drift on column
names or status handling.

Phase 0 scope: create / fetch / update-status / list. No reasoning, no
severity rules.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

import psycopg
from psycopg.rows import dict_row

from shared.schemas.incident_message import IncidentStatus, Severity
from shared.trace import record_trace

DEFAULT_DSN = "postgresql://crisis:crisis_dev_pw@localhost:5433/incidents"


def store_dsn() -> str:
    """Connection string for the incident store.

    Override with INCIDENT_STORE_DSN when the store moves off localhost.
    """
    return os.environ.get("INCIDENT_STORE_DSN", DEFAULT_DSN)


def _as_value(v: Any) -> Any:
    """Unwrap an Enum to the string the database column actually stores."""
    return v.value if isinstance(v, Enum) else v


@dataclass
class IncidentRecord:
    incident_id: str
    created_at: datetime
    updated_at: datetime
    status: str
    severity: Optional[str]
    raw_payload: Dict[str, Any]
    escalated: bool = False
    incident_type: Optional[str] = None

    @classmethod
    def from_row(cls, row: Dict[str, Any]) -> "IncidentRecord":
        return cls(
            incident_id=row["incident_id"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            status=row["status"],
            severity=row["severity"],
            raw_payload=row["raw_payload"],
            escalated=row.get("escalated", False),
            incident_type=row.get("incident_type"),
        )

    def summary(self) -> str:
        """One-line form for logs."""
        bits = [self.incident_id, self.status]
        if self.severity:
            bits.append(f"severity={self.severity}")
        if self.incident_type:
            bits.append(f"type={self.incident_type}")
        if self.escalated:
            bits.append("ESCALATED")
        return " ".join(bits)


class IncidentStore:
    """Thin, connection-per-call wrapper around the incidents table.

    Connection-per-call keeps this safe to use from agent processes that may be
    long-lived and mostly idle, at the cost of per-call connect overhead that
    does not matter at this project's volumes.
    """

    def __init__(self, dsn: Optional[str] = None) -> None:
        self.dsn = dsn or store_dsn()

    def _connect(self) -> psycopg.Connection:
        return psycopg.connect(self.dsn, row_factory=dict_row)

    def ping(self) -> bool:
        with self._connect() as conn:
            return conn.execute("SELECT 1 AS ok").fetchone()["ok"] == 1

    def create_incident(
        self,
        incident_id: str,
        *,
        status: str | IncidentStatus = IncidentStatus.DETECTED,
        severity: Optional[str | Severity] = None,
        raw_payload: Optional[Dict[str, Any]] = None,
        incident_type: Optional[str] = None,
        escalated: bool = False,
    ) -> IncidentRecord:
        with self._connect() as conn:
            row = conn.execute(
                """
                INSERT INTO incidents
                    (incident_id, status, severity, raw_payload, incident_type, escalated)
                VALUES (%s, %s, %s, %s::jsonb, %s, %s)
                RETURNING *
                """,
                (
                    incident_id,
                    _as_value(status),
                    _as_value(severity),
                    json.dumps(raw_payload or {}),
                    incident_type,
                    escalated,
                ),
            ).fetchone()
        return IncidentRecord.from_row(row)

    def get_incident(self, incident_id: str) -> Optional[IncidentRecord]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM incidents WHERE incident_id = %s",
                (incident_id,),
            ).fetchone()
        return IncidentRecord.from_row(row) if row else None

    def update_incident(
        self,
        incident_id: str,
        *,
        status: Optional[str | IncidentStatus] = None,
        severity: Optional[str | Severity] = None,
        raw_payload: Optional[Dict[str, Any]] = None,
        incident_type: Optional[str] = None,
        escalated: Optional[bool] = None,
    ) -> Optional[IncidentRecord]:
        """Update whichever fields are supplied. raw_payload is merged, not replaced.

        Merging matters because several systems write into the same incident's
        payload and must not clobber each other's keys.
        """
        sets: List[str] = []
        params: List[Any] = []
        if status is not None:
            sets.append("status = %s")
            params.append(_as_value(status))
        if severity is not None:
            sets.append("severity = %s")
            params.append(_as_value(severity))
        if incident_type is not None:
            sets.append("incident_type = %s")
            params.append(incident_type)
        if escalated is not None:
            sets.append("escalated = %s")
            params.append(escalated)
        if raw_payload is not None:
            sets.append("raw_payload = raw_payload || %s::jsonb")
            params.append(json.dumps(raw_payload))
        if not sets:
            return self.get_incident(incident_id)

        params.append(incident_id)
        with self._connect() as conn:
            row = conn.execute(
                f"UPDATE incidents SET {', '.join(sets)} WHERE incident_id = %s RETURNING *",
                tuple(params),
            ).fetchone()
        return IncidentRecord.from_row(row) if row else None

    def list_incidents(self, *, limit: int = 50) -> List[IncidentRecord]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM incidents ORDER BY created_at DESC LIMIT %s",
                (limit,),
            ).fetchall()
        return [IncidentRecord.from_row(r) for r in rows]

    def advance_status(
        self,
        incident_id: str,
        to_status: IncidentStatus,
        *,
        by_system: str,
        severity: Optional[str | Severity] = None,
        incident_type: Optional[str] = None,
        escalated: Optional[bool] = None,
        payload: Optional[Dict[str, Any]] = None,
        note: Optional[str] = None,
    ) -> IncidentRecord:
        """Move an incident forward through the lifecycle, recording who did it.

        Refuses to move backwards. With six systems writing concurrently and no
        orchestrator, a late message from an earlier stage could otherwise drag
        an assessed incident back to DETECTED and strand it. Re-asserting the
        current status is allowed, since a retried message is not an error.

        Every transition appends to `raw_payload.status_history`, which is what
        makes a row's progression auditable after the fact.
        """
        current = self.get_incident(incident_id)
        if current is None:
            raise KeyError(f"no incident {incident_id!r} to advance")

        try:
            current_status = IncidentStatus(current.status)
        except ValueError as exc:
            raise ValueError(
                f"incident {incident_id} holds status {current.status!r}, which is not in "
                "the agreed vocabulary -- the store needs migrating"
            ) from exc

        if to_status.rank < current_status.rank:
            raise ValueError(
                f"refusing to move {incident_id} backwards: "
                f"{current_status.value} -> {to_status.value} (requested by {by_system})"
            )

        entry = {
            "from": current_status.value,
            "to": to_status.value,
            "by": by_system,
            "at": datetime.now(timezone.utc).isoformat(),
        }
        if note:
            entry["note"] = note

        merged: Dict[str, Any] = dict(payload or {})
        history = list((current.raw_payload or {}).get("status_history", []))
        history.append(entry)
        merged["status_history"] = history

        record = self.update_incident(
            incident_id,
            status=to_status,
            severity=severity,
            incident_type=incident_type,
            escalated=escalated,
            raw_payload=merged,
        )
        if record is None:  # pragma: no cover - the row existed a moment ago
            raise KeyError(f"incident {incident_id!r} vanished mid-update")
        # Phase 5 trace: observation only, after the move has happened.
        record_trace(
            incident_id=incident_id, from_system=by_system, event_type="status_advanced", decision="auto",
            summary=f"{current_status.value} -> {to_status.value}",
            detail={"from": current_status.value, "to": to_status.value,
                    "severity": _as_value(severity) if severity else None},
        )
        return record

    def reclassify(
        self,
        incident_id: str,
        *,
        by_system: str,
        severity: Optional[str | Severity] = None,
        incident_type: Optional[str] = None,
        escalated: Optional[bool] = None,
        reason: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> IncidentRecord:
        """Revise an incident's assessment without moving `status` backward.

        The deliberate, narrow exception to the backward-move guard (Phase 3
        Decision 1). A re-classification is not "the incident regressed" -- it
        is "the assessment was revised while the lifecycle continues". So
        `status` is left exactly where it is (e.g. CONTAINED stays CONTAINED),
        while `severity`/`incident_type`/`escalated` are updated and a
        `status_history` entry tagged ``reclassified`` records what changed,
        by whom, and why. Refused once the incident is RESOLVED.
        """
        current = self.get_incident(incident_id)
        if current is None:
            raise KeyError(f"no incident {incident_id!r} to reclassify")
        if current.status == IncidentStatus.RESOLVED.value:
            raise ValueError(f"cannot reclassify {incident_id}: already RESOLVED")

        entry: Dict[str, Any] = {
            "event": "reclassified",
            "status": current.status,  # unchanged -- recorded for the audit trail
            "by": by_system,
            "at": datetime.now(timezone.utc).isoformat(),
            "reason": reason,
            "from": {"severity": current.severity, "incident_type": current.incident_type,
                     "escalated": current.escalated},
            "to": {"severity": _as_value(severity) if severity is not None else current.severity,
                   "incident_type": incident_type if incident_type is not None else current.incident_type,
                   "escalated": escalated if escalated is not None else current.escalated},
        }

        merged: Dict[str, Any] = dict(payload or {})
        history = list((current.raw_payload or {}).get("status_history", []))
        history.append(entry)
        merged["status_history"] = history

        record = self.update_incident(
            incident_id,
            severity=severity,
            incident_type=incident_type,
            escalated=escalated,
            raw_payload=merged,
        )
        if record is None:  # pragma: no cover
            raise KeyError(f"incident {incident_id!r} vanished mid-reclassify")
        return record

    def append_history(self, incident_id: str, entry: Dict[str, Any]) -> bool:
        """Append one audit entry to ``status_history`` WITHOUT touching ``status``.

        For events that belong to an incident's story but are not lifecycle
        moves (Phase 4: a customer draft was created, signed off, published).
        Entries carry an ``event`` key; lifecycle entries do not. The append is
        one atomic SQL statement, so it cannot clobber a concurrent write to the
        same row's history the way read-modify-write would.
        """
        entry = {"at": datetime.now(timezone.utc).isoformat(), **entry}
        with self._connect() as conn:
            cur = conn.execute(
                """
                UPDATE incidents
                   SET raw_payload = jsonb_set(
                           raw_payload, '{status_history}',
                           COALESCE(raw_payload->'status_history', '[]'::jsonb) || %s::jsonb)
                 WHERE incident_id = %s
                """,
                (json.dumps([entry]), incident_id),
            )
            return cur.rowcount > 0

    def status_history(self, incident_id: str) -> List[Dict[str, Any]]:
        """The recorded transitions for an incident, oldest first."""
        record = self.get_incident(incident_id)
        if record is None:
            return []
        return list((record.raw_payload or {}).get("status_history", []))

    def delete_incident(self, incident_id: str) -> bool:
        with self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM incidents WHERE incident_id = %s",
                (incident_id,),
            )
            return cur.rowcount > 0
