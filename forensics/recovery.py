"""Recovery Planning -- advisory recovery plan + lift-containment signal (Phase 3).

A CrewAI agent writes a short recovery plan and ends with a sentinel line
`LIFT: YES` or `LIFT: NO`. Recovery is advisory: it does not itself reverse
containment -- it emits a "safe to lift" signal that Containment acts on,
gated by the same guardrail pattern.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from crewai import Agent, Crew, Process, Task

from shared.llm import ROLE_REASONING, crew_llm

logger = logging.getLogger("forensics.recovery")


@dataclass
class RecoveryPlan:
    plan_text: str
    safe_to_lift: bool


def plan_recovery(incident_brief: str) -> RecoveryPlan:
    """Produce a recovery plan and a go/no-go lift signal via a CrewAI agent."""
    llm = crew_llm(ROLE_REASONING, agent_name="recovery_planning")
    planner = Agent(
        role="Recovery Planner",
        goal="Decide whether it is safe to lift containment and outline the recovery steps.",
        backstory="You weigh the root-cause findings and decide if the blocked IPs can be "
        "released yet, and what to verify during recovery.",
        llm=llm,
        verbose=False,
        allow_delegation=False,
    )
    task = Task(
        description=(
            "Given the incident and its root-cause analysis below, write a short recovery plan "
            "(2-4 bullet points) and decide whether it is safe to lift the IP blocks now. End "
            "your reply with a final line that is EXACTLY one of:\n"
            "  LIFT: YES\n"
            "  LIFT: NO\n"
            "Choose LIFT: YES only if the threat is understood and contained and no further "
            "escalation is pending.\n\n"
            f"{incident_brief}"
        ),
        expected_output="A short recovery plan ending with a 'LIFT: YES' or 'LIFT: NO' line.",
        agent=planner,
    )
    crew = Crew(agents=[planner], tasks=[task], process=Process.sequential, verbose=False)
    text = str(crew.kickoff()).strip()
    safe = "LIFT: YES" in text.upper()
    logger.info("recovery plan produced; safe_to_lift=%s", safe)
    return RecoveryPlan(plan_text=text, safe_to_lift=safe)
