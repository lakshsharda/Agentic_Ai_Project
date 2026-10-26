"""The baseline A2A message contract for Crisis Coordination Agents.

Every A2A task sent between the six systems carries an ``IncidentMessage`` as
its JSON body. The envelope fields (``incident_id``, ``timestamp``,
``source_system``, ``target_system``) are fixed for the life of the project.
``payload`` is intentionally free-form -- each later phase defines the payload
shape its own system expects, and documents it next to that system.

Phase 0 only proves the envelope travels over the wire intact.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional

from pydantic import BaseModel, ConfigDict, Field

SCHEMA_VERSION = "0.1.0"


class SystemName(str, Enum):
    """The six agent systems, plus the Phase 0 scaffolding placeholders.

    Using an enum (rather than free text) means a typo in a target system name
    fails at the sender instead of silently routing nowhere.
    """

    DETECTION = "detection"
    THREAT_ASSESSMENT = "threat_assessment"
    CONTAINMENT = "containment"
    FORENSICS = "forensics"
    CUSTOMER_COMMS = "customer_comms"
    ON_CALL = "on_call"

    # Phase 0 scaffolding only -- the hello-world agents, kept so the Phase 0
    # exchange still runs. Real systems must not use these.
    SCAFFOLD_ADK = "scaffold_adk"
    SCAFFOLD_CREW = "scaffold_crew"


class IncidentStatus(str, Enum):
    """The fixed lifecycle vocabulary for `incidents.status`.

    Settled before Phase 1 and enforced by a CHECK constraint in the database,
    so six systems cannot invent their own spellings. Strictly ordered: see
    `rank` for the comparison the store uses to refuse backwards moves.

    Phase 1 only ever writes DETECTED, CANDIDATE and ASSESSED.
    """

    DETECTED = "DETECTED"
    CANDIDATE = "CANDIDATE"
    ASSESSED = "ASSESSED"
    DISPATCHED = "DISPATCHED"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"

    @property
    def rank(self) -> int:
        return _STATUS_ORDER.index(self)


_STATUS_ORDER = [
    IncidentStatus.DETECTED,
    IncidentStatus.CANDIDATE,
    IncidentStatus.ASSESSED,
    IncidentStatus.DISPATCHED,
    IncidentStatus.CONTAINED,
    IncidentStatus.RESOLVED,
]

# `escalated` is a separate boolean column, deliberately NOT part of this
# vocabulary: Threat Assessment can escalate an incident at any status without
# disturbing where it sits in the lifecycle.


class Severity(str, Enum):
    """Severity assigned by Threat Assessment's classification agent."""

    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


def new_incident_id() -> str:
    """Generate a fresh incident id.

    Prefixed so an id is recognisable in logs and DB rows at a glance.
    """
    return f"inc-{uuid.uuid4().hex[:12]}"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class IncidentMessage(BaseModel):
    """The envelope every A2A task between systems carries."""

    model_config = ConfigDict(extra="forbid", use_enum_values=True)

    schema_version: str = Field(
        default=SCHEMA_VERSION,
        description="Version of this envelope contract, so receivers can reject unknown shapes.",
    )
    incident_id: str = Field(
        ...,
        description="Stable id for the incident this message is about; the join key into the incident store.",
    )
    timestamp: datetime = Field(
        default_factory=_utcnow,
        description="UTC time the message was created by the sending system.",
    )
    source_system: SystemName = Field(..., description="System that produced this message.")
    target_system: SystemName = Field(..., description="System this message is addressed to.")
    payload: Dict[str, Any] = Field(
        default_factory=dict,
        description="System-specific body. Shape grows per system in later phases.",
    )

    # Optional envelope extras that cost nothing now and save rework later.
    correlation_id: Optional[str] = Field(
        default=None,
        description="Id of the message being replied to, for request/response pairing.",
    )

    def to_wire(self) -> str:
        """Serialise for transport over A2A (JSON, ISO-8601 timestamps)."""
        return self.model_dump_json()

    @classmethod
    def from_wire(cls, raw: str | bytes | Dict[str, Any]) -> "IncidentMessage":
        """Parse and validate a message received over A2A."""
        if isinstance(raw, dict):
            return cls.model_validate(raw)
        return cls.model_validate_json(raw)

    def reply(
        self,
        payload: Dict[str, Any],
        *,
        source_system: Optional[SystemName] = None,
    ) -> "IncidentMessage":
        """Build a response message addressed back at this message's sender."""
        return IncidentMessage(
            incident_id=self.incident_id,
            source_system=source_system or self.target_system,
            target_system=self.source_system,
            payload=payload,
            correlation_id=self.incident_id,
        )


def json_schema() -> Dict[str, Any]:
    """The envelope as a JSON Schema document, for non-Python consumers."""
    return IncidentMessage.model_json_schema()


if __name__ == "__main__":  # pragma: no cover - convenience for regenerating the .json
    import json

    print(json.dumps(json_schema(), indent=2))
