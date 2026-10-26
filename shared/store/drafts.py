"""Store access for customer-communications drafts (Phase 4).

Same connection-per-call style as ``IncidentStore``. Every state transition is
a conditional UPDATE (``WHERE status = <expected>``), so two concurrent actors
-- a human signing off while a newer draft supersedes -- cannot both win.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

import psycopg
from psycopg.rows import dict_row

from shared.store.incidents import store_dsn
from shared.trace import record_trace

STATUS_PENDING = "PENDING_SIGNOFF"
STATUS_APPROVED = "APPROVED"
STATUS_REJECTED = "REJECTED"
STATUS_PUBLISHED = "PUBLISHED"
STATUS_SUPERSEDED = "SUPERSEDED"


def new_draft_id() -> str:
    return f"drf-{uuid.uuid4().hex[:12]}"


@dataclass
class Draft:
    draft_id: str
    incident_id: str
    event_type: str
    severity_at_draft: Optional[str]
    draft_text: str
    status: str
    approved_by: Optional[str]
    created_at: datetime
    decided_at: Optional[datetime]
    published_at: Optional[datetime]
    publish_channel: Optional[str]
    sent: Optional[bool]
    rejection_reason: Optional[str] = None
    generation: Optional[str] = None
    original_text: Optional[str] = None
    edited_by_human: bool = False
    impact: Optional[str] = None
    superseded_by: Optional[str] = None

    @classmethod
    def from_row(cls, row: Dict[str, Any]) -> "Draft":
        return cls(**{k: row.get(k) for k in cls.__dataclass_fields__})

    def to_dict(self) -> Dict[str, Any]:
        out = {}
        for k in self.__dataclass_fields__:
            v = getattr(self, k)
            out[k] = v.isoformat() if isinstance(v, datetime) else v
        return out


class DraftStore:
    def __init__(self, dsn: Optional[str] = None) -> None:
        self.dsn = dsn or store_dsn()

    def _connect(self) -> psycopg.Connection:
        return psycopg.connect(self.dsn, row_factory=dict_row)

    def create(
        self,
        incident_id: str,
        *,
        event_type: str,
        draft_text: str,
        severity_at_draft: Optional[str],
        status: str = STATUS_PENDING,
        rejection_reason: Optional[str] = None,
        generation: Optional[str] = None,
        impact: Optional[str] = None,
        approved_by: Optional[str] = None,
    ) -> Draft:
        with self._connect() as conn:
            row = conn.execute(
                """
                INSERT INTO comms_drafts
                    (draft_id, incident_id, event_type, severity_at_draft, draft_text,
                     status, rejection_reason, generation, impact, approved_by)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING *
                """,
                (new_draft_id(), incident_id, event_type, severity_at_draft, draft_text,
                 status, rejection_reason, generation, impact, approved_by),
            ).fetchone()
        draft = Draft.from_row(row)
        # Phase 5 trace: metadata only -- never the draft text (a REJECTED draft may hold exactly
        # the text the validator refused).
        record_trace(
            incident_id=incident_id, from_system="customer_comms", event_type="draft_created",
            decision="blocked" if status == "REJECTED" else "n/a",
            summary=f"{event_type} draft {draft.draft_id} -> {status}"
                    + (" (refused by the customer-text validator)" if status == "REJECTED" else ""),
            detail={"draft_id": draft.draft_id, "event": event_type, "status": status,
                    "generation": generation, "severity": severity_at_draft},
        )
        return draft

    def get(self, draft_id: str) -> Optional[Draft]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM comms_drafts WHERE draft_id = %s", (draft_id,)).fetchone()
        return Draft.from_row(row) if row else None

    def list(
        self, *, incident_id: Optional[str] = None, status: Optional[str] = None, limit: int = 100
    ) -> List[Draft]:
        clauses, params = [], []
        if incident_id:
            clauses.append("incident_id = %s"); params.append(incident_id)
        if status:
            clauses.append("status = %s"); params.append(status)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM comms_drafts {where} ORDER BY created_at ASC LIMIT %s", tuple(params)
            ).fetchall()
        return [Draft.from_row(r) for r in rows]

    def supersede_unpublished(self, incident_id: str, *, superseded_by: str) -> List[str]:
        """Mark every unpublished draft of this incident (except the new one)
        SUPERSEDED. Published drafts are history and are left alone."""
        with self._connect() as conn:
            rows = conn.execute(
                """
                UPDATE comms_drafts
                   SET status = 'SUPERSEDED', superseded_by = %s, decided_at = COALESCE(decided_at, now())
                 WHERE incident_id = %s AND draft_id <> %s AND status IN ('PENDING_SIGNOFF', 'APPROVED')
                RETURNING draft_id
                """,
                (superseded_by, incident_id, superseded_by),
            ).fetchall()
        return [r["draft_id"] for r in rows]

    def decide(
        self,
        draft_id: str,
        *,
        status: str,
        approved_by: Optional[str],
        rejection_reason: Optional[str] = None,
        edited_text: Optional[str] = None,
    ) -> Optional[Draft]:
        """Record a human decision, only while the draft is still PENDING_SIGNOFF.

        Returns None when the draft was not pending (already decided, or
        superseded in the meantime) so the caller can refuse instead of
        overwriting.
        """
        with self._connect() as conn:
            if edited_text is not None:
                row = conn.execute(
                    """
                    UPDATE comms_drafts
                       SET status = %s, approved_by = %s, decided_at = now(), rejection_reason = %s,
                           original_text = draft_text, draft_text = %s, edited_by_human = TRUE
                     WHERE draft_id = %s AND status = 'PENDING_SIGNOFF'
                    RETURNING *
                    """,
                    (status, approved_by, rejection_reason, edited_text, draft_id),
                ).fetchone()
            else:
                row = conn.execute(
                    """
                    UPDATE comms_drafts
                       SET status = %s, approved_by = %s, decided_at = now(), rejection_reason = %s
                     WHERE draft_id = %s AND status = 'PENDING_SIGNOFF'
                    RETURNING *
                    """,
                    (status, approved_by, rejection_reason, draft_id),
                ).fetchone()
        return Draft.from_row(row) if row else None

    def mark_published(self, draft_id: str, *, channel: str, sent: bool) -> Optional[Draft]:
        """APPROVED -> PUBLISHED. Conditional so a draft is published once."""
        with self._connect() as conn:
            row = conn.execute(
                """
                UPDATE comms_drafts
                   SET status = 'PUBLISHED', published_at = now(), publish_channel = %s, sent = %s
                 WHERE draft_id = %s AND status = 'APPROVED'
                RETURNING *
                """,
                (channel, sent, draft_id),
            ).fetchone()
        return Draft.from_row(row) if row else None
