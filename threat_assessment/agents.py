"""Threat Assessment's reasoning agents.

  * correlation_agent -- enriches the incoming candidate against threat intel
    and summarises what the enrichment means. Reasoning, not a lookup table:
    the threat_intel tool returns facts; the agent interprets them.

  * severity_agent -- assigns a severity (Low/Medium/High/Critical) and an
    incident type label, with real reasoning over the evidence and the
    correlation summary.

Both produce structured output so the server can act on it deterministically.
"""

from __future__ import annotations

import logging

from google.adk.agents import LlmAgent
from pydantic import BaseModel, Field

from shared.llm import ROLE_REASONING, adk_model
from threat_assessment.threat_intel import threat_intel_tool

logger = logging.getLogger("threat_assessment.agents")

CORRELATION_STATE_KEY = "correlation"
SEVERITY_STATE_KEY = "severity_assessment"


# --------------------------------------------------------------------------
# Correlation
# --------------------------------------------------------------------------


class CorrelationResult(BaseModel):
    intel_summary: str = Field(
        description="What the threat-intel lookups revealed about the source IPs, in prose."
    )
    malicious_ip_count: int = Field(description="How many source IPs came back 'malicious'.", ge=0)
    suspicious_ip_count: int = Field(description="How many came back 'suspicious'.", ge=0)
    enrichment_notes: str = Field(
        description="How this intelligence changes the picture of the incident -- "
        "what it makes more or less concerning, and why."
    )


CORRELATION_INSTRUCTION = """\
You are the Correlation agent in a Threat Assessment system. A candidate security \
incident has arrived from Detection. Its evidence -- including the source IPs \
involved in the suspicious traffic -- is in the user message.

Call lookup_ip_reputation with the source IPs from the evidence (the top failed-login \
IPs and top source IPs). Then reason about what the results mean for THIS incident. \
A malicious-reputation IP raises concern, but weigh it against the rest of the \
evidence -- volume, spread, whether logins succeeded -- rather than letting one hit \
decide the outcome. Note anything the intel makes more or less serious.

Respond using the CorrelationResult structure.
"""


def build_correlation_agent() -> LlmAgent:
    return LlmAgent(
        name="correlation",
        model=adk_model(ROLE_REASONING, agent_name="correlation"),
        description="Enriches a candidate incident against threat intelligence.",
        instruction=CORRELATION_INSTRUCTION,
        tools=[threat_intel_tool],
        output_schema=CorrelationResult,
        output_key=CORRELATION_STATE_KEY,
    )


# --------------------------------------------------------------------------
# Severity classification
# --------------------------------------------------------------------------


class SeverityAssessment(BaseModel):
    severity: str = Field(description="Exactly one of: Low, Medium, High, Critical.")
    incident_type: str = Field(
        description="A concise type label, e.g. 'Brute Force', 'Credential Stuffing', "
        "'Traffic Spike / DoS', 'Reconnaissance'."
    )
    escalate: bool = Field(
        description="True if this incident warrants immediate human/on-call attention "
        "beyond the normal pipeline."
    )
    rationale: str = Field(
        description="Why this severity and type, citing the evidence and the correlation summary."
    )


SEVERITY_INSTRUCTION = """\
You are the Severity Classification agent in a Threat Assessment system. You are given \
a candidate incident's evidence (traffic statistics observed by Detection) and the \
Correlation agent's threat-intel summary, in the user message.

Assign:
- severity: Low, Medium, High, or Critical.
- incident_type: a concise label for what this is.
- escalate: whether it needs immediate on-call attention.

Reason over the actual evidence. Rough guidance, not a formula:
- Critical: a clearly successful or very large-scale compromise attempt, e.g. many \
  successful logins under attack, or an overwhelming distributed assault.
- High: a strong, deliberate attack pattern (large brute force / credential stuffing \
  from malicious infrastructure) even if not yet successful.
- Medium: a real but limited or unsuccessful probe, or suspicious-but-not-confirmed \
  activity.
- Low: minor or likely-benign anomalies.

Weigh malicious-reputation sources, the number of distinct IPs and usernames, the \
request rate, and whether any logins actually succeeded. Explain your choice.

Respond using the SeverityAssessment structure.
"""


def build_severity_agent() -> LlmAgent:
    return LlmAgent(
        name="severity_classifier",
        model=adk_model(ROLE_REASONING, agent_name="severity_classifier"),
        description="Assigns severity and incident type with reasoning over the evidence.",
        instruction=SEVERITY_INSTRUCTION,
        output_schema=SeverityAssessment,
        output_key=SEVERITY_STATE_KEY,
    )


# The four allowed severities, so the server can defend against an off-vocab
# label from the model rather than writing it straight to the DB.
VALID_SEVERITIES = {"Low", "Medium", "High", "Critical"}
