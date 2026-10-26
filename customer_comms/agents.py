"""Customer Communications' CrewAI agents.

  * Impact Assessment Agent (mechanical chain) -- reads the incident's current
    state and says whether customers see the service as degraded, at risk,
    mitigated or restored. Ends with a sentinel line ``IMPACT: <LABEL>``.
  * Message Drafting Agent (reasoning chain) -- writes the customer-facing
    notice from that summary; tone and detail follow severity and the event.

The Publishing Agent is deliberately NOT here: publishing is a tool behind a
code gate (publisher.py), not something a model decides.

No ``output_pydantic`` -- CrewAI is forced onto LiteLLM via a ``litellm/``
prefix (see shared/llm.py), which breaks instructor-based structured output.
Both agents emit plain text with a sentinel that is parsed here.
"""

from __future__ import annotations

import logging
import re
from typing import Dict, Optional

from crewai import Agent, Crew, Process, Task

from customer_comms.pipeline import (
    EVENT_CONTAINED,
    EVENT_RECLASSIFIED,
    EVENT_RESOLVED,
    IMPACT_LABELS,
    Impact,
    fallback_impact,
)
from shared.llm import ROLE_MECHANICAL, ROLE_REASONING, crew_llm

logger = logging.getLogger("customer_comms.agents")

_EVENT_GUIDE = {
    EVENT_CONTAINED: "We detected an issue and have taken protective action. State that protective "
                     "action is in place and that we are monitoring.",
    EVENT_RECLASSIFIED: "This is an UPDATED notice that replaces our earlier one: our assessment of "
                        "the issue has changed after further review. Say so plainly and say what "
                        "customers should do now.",
    EVENT_RESOLVED: "The issue is resolved and the service is back to normal. Thank customers for "
                    "their patience.",
}

_SEVERITY_GUIDE = {
    "Low": "Short and calm: two sentences. No action needed from customers.",
    "Medium": "Short and calm: two or three sentences. No action needed unless they see something unusual.",
    "High": "Clearer and more direct: three to four sentences. Tell customers what to do (for example, "
            "reset their password if they see unfamiliar sign-ins) and where to get help.",
    "Critical": "Clear and direct: three to five sentences. Tell customers what to do (for example, "
                "reset their password now and review recent account activity) and where to get help.",
}


def _text(crew: Crew) -> str:
    return str(crew.kickoff()).strip()


def assess_impact(snapshot: Dict, event: str) -> Impact:
    """Impact Assessment Agent: state -> (label, short customer-impact summary)."""
    llm = crew_llm(ROLE_MECHANICAL, agent_name="comms_impact")
    agent = Agent(
        role="Customer Impact Assessor",
        goal="Describe, in customer-visible terms only, how the incident affects the service.",
        backstory="You translate an internal incident state into what a customer would experience. "
        "You never mention technical causes, addresses, accounts or system names.",
        llm=llm, verbose=False, allow_delegation=False,
    )
    task = Task(
        description=(
            "Internal incident state:\n"
            f"- severity: {snapshot['severity']}\n"
            f"- lifecycle status: {snapshot['status']}\n"
            f"- protective containment executed: {snapshot['containment_done']}\n"
            f"- recovery / lift completed: {snapshot['recovery_done']}\n"
            f"- event being reported: {event}\n\n"
            "Write ONE sentence describing the customer-visible impact (no technical detail, no "
            "addresses, no account names). Then end with a final line that is EXACTLY one of:\n"
            "  IMPACT: DEGRADED\n  IMPACT: AT_RISK\n  IMPACT: MITIGATED\n  IMPACT: RESTORED\n"
            "DEGRADED = service is disrupted; AT_RISK = not disrupted but under threat; "
            "MITIGATED = protective action in place, service OK; RESTORED = back to normal."
        ),
        expected_output="One sentence followed by a final 'IMPACT: <LABEL>' line.",
        agent=agent,
    )
    out = _text(Crew(agents=[agent], tasks=[task], process=Process.sequential, verbose=False))
    match = re.findall(r"IMPACT:\s*([A-Z_]+)", out.upper())
    label = match[-1] if match else None
    if label not in IMPACT_LABELS:
        logger.warning("impact assessor returned no usable label (%r); using deterministic label", label)
        return fallback_impact(snapshot, event)
    summary = re.sub(r"(?im)^\s*IMPACT:.*$", "", out).strip() or fallback_impact(snapshot, event).summary
    return Impact(label, summary)


def draft_message(snapshot: Dict, event: str, impact: Impact, feedback: Optional[str]) -> str:
    """Message Drafting Agent: impact summary -> customer-facing text."""
    llm = crew_llm(ROLE_REASONING, agent_name="comms_drafting")
    agent = Agent(
        role="Customer Communications Writer",
        goal="Write a clear, honest, calm customer notice that follows the content rules exactly.",
        backstory="You write status-page updates for a security-conscious SaaS company. You say what "
        "is affected, what is being done, and what customers should do -- nothing more.",
        llm=llm, verbose=False, allow_delegation=False,
    )
    previous = snapshot.get("previous_published_text")
    task = Task(
        description=(
            f"Event: {event}. {_EVENT_GUIDE[event]}\n"
            f"Severity band: {snapshot['severity']}. {_SEVERITY_GUIDE.get(snapshot['severity'], _SEVERITY_GUIDE['Medium'])}\n"
            f"Customer-impact summary: {impact.label} -- {impact.summary}\n"
            + (f"Our previously published notice (this one replaces it): {previous}\n" if previous else "")
            + "\nHARD RULES: Do NOT include any IP address, username, account name, hostname, port, "
            "or any explanation of the technical cause or attack method. Do not name internal systems. "
            "Plain text only, no markdown, no greeting, no sign-off.\n"
            + (f"\nCORRECTION: {feedback}\n" if feedback else "")
            + "\nBegin your reply with the line 'MESSAGE:' followed by the notice text."
        ),
        expected_output="'MESSAGE:' followed by the customer notice.",
        agent=agent,
    )
    out = _text(Crew(agents=[agent], tasks=[task], process=Process.sequential, verbose=False))
    if "MESSAGE:" in out:
        out = out.split("MESSAGE:", 1)[1]
    return out.strip().strip('"').strip()
