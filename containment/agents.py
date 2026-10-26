"""Containment's CrewAI agents.

Two reasoning agents in a sequential crew:

  * Situation Review -- reads the incident and the current firewall state and
    summarises what, if anything, needs doing.
  * Immediate Action -- decides the concrete mitigation (which offending IPs to
    block) and why, as structured output the server can act on.

Status Reporting is not an LLM step -- it is the server writing the store and
sending the A2A status update -- so it lives in server.py, not here.

The agents only *decide*. Execution is gated by the shared guardrail and done
in code (firewall.block_ips); an agent cannot block an IP by "deciding" to.
"""

from __future__ import annotations

import logging
from typing import List

from crewai import Agent, Crew, Process, Task
from pydantic import BaseModel, Field

from shared.llm import ROLE_REASONING, crew_llm

logger = logging.getLogger("containment.agents")


class MitigationPlan(BaseModel):
    block_ips: List[str] = Field(
        default_factory=list,
        description="The source IPs to block. Draw ONLY from the offending IPs in the "
        "incident evidence; never invent addresses.",
    )
    action: str = Field(description="Short action label, e.g. 'block_ips' or 'no_action'.")
    rationale: str = Field(description="Why this mitigation fits the incident, in 1-2 sentences.")


def build_containment_crew(incident_brief: str) -> Crew:
    """A sequential crew: review the situation, then decide the mitigation."""
    llm = crew_llm(ROLE_REASONING, agent_name="containment")

    reviewer = Agent(
        role="Containment Situation Reviewer",
        goal="Understand the incident and the current firewall state, and state plainly "
        "whether mitigation is warranted.",
        backstory="A SOC operator who triages incidents handed over for containment.",
        llm=llm,
        verbose=False,
        allow_delegation=False,
    )
    actioner = Agent(
        role="Immediate Action Officer",
        goal="Decide the concrete containment action: which offending IPs to block.",
        backstory="You take the reviewer's read and commit to a minimal, proportionate action. "
        "In this phase the only action available is blocking the offending source IPs.",
        llm=llm,
        verbose=False,
        allow_delegation=False,
    )

    review_task = Task(
        description=(
            "Review this incident handed over for containment:\n\n"
            f"{incident_brief}\n\n"
            "Summarise the threat and whether blocking the offending source IPs is warranted."
        ),
        expected_output="A short situation summary and a recommendation.",
        agent=reviewer,
    )
    action_task = Task(
        description=(
            "Based on the situation review, decide the containment action. The only action "
            "available this phase is blocking offending source IPs. End your reply with a "
            "final line that is EXACTLY one of:\n"
            "  DECISION: BLOCK\n"
            "  DECISION: NO_ACTION\n"
            "Use BLOCK when blocking the offending source IPs is warranted, NO_ACTION otherwise. "
            "Give a one-sentence rationale before that final line."
        ),
        expected_output="A rationale sentence followed by a final 'DECISION: BLOCK' or 'DECISION: NO_ACTION' line.",
        agent=actioner,
        context=[review_task],
    )

    # NOTE: deliberately no output_pydantic. CrewAI 1.x routes structured output
    # through instructor, which re-sends the model string (including the
    # "litellm/" prefix we need to force the LiteLLM route) to litellm and is
    # rejected. Parsing a sentinel line from plain text avoids that path and is
    # robust across CrewAI's routing quirks. The server derives the IPs to block
    # from the incident evidence, not from free-form model text, so a block can
    # never target an address the model invented.
    return Crew(
        agents=[reviewer, actioner],
        tasks=[review_task, action_task],
        process=Process.sequential,
        verbose=False,
    )


def interpret_plan(crew_output: str, offending_ips: List[str]) -> MitigationPlan:
    """Turn the crew's text decision into an executable plan.

    The IPs come from the incident evidence (offending_ips), never from the
    model's text -- the model only decides BLOCK vs NO_ACTION. A missing or
    unparseable decision fails safe to BLOCK, since the incident already passed
    Detection and Threat Assessment as a real attack.
    """
    text = (crew_output or "").strip()
    last = text.splitlines()[-1].strip().upper() if text else ""
    no_action = "DECISION: NO_ACTION" in text.upper() or last == "DECISION: NO_ACTION"
    if no_action:
        return MitigationPlan(block_ips=[], action="no_action", rationale=text[-500:] or "no action")
    return MitigationPlan(block_ips=list(offending_ips), action="block_ips", rationale=text[-500:] or "block offending IPs")
