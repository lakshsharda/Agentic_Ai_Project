"""On-Call's CrewAI agent: compose the page text.

A short, bounded drafting step -- the one piece of On-Call that benefits from a
model. Lookup, timing and the approval signal are mechanical and live in
ops.py / server.py. If the model is unavailable the server falls back to a
template, so a page always goes out.
"""

from __future__ import annotations

import logging

from crewai import Agent, Crew, Process, Task

from shared.llm import ROLE_MECHANICAL, crew_llm

logger = logging.getLogger("on_call.agents")


def compose_page_text(incident_brief: str) -> str:
    """Draft a concise on-call page for the incident via a CrewAI agent."""
    llm = crew_llm(ROLE_MECHANICAL, agent_name="on_call")
    drafter = Agent(
        role="On-Call Paging Assistant",
        goal="Write a concise, scannable page for the on-call responder.",
        backstory="You turn an incident summary into a short alert a human can act on in seconds.",
        llm=llm,
        verbose=False,
        allow_delegation=False,
    )
    task = Task(
        description=(
            "Write a short on-call page (max ~4 lines) for this incident. Include severity, "
            "type, the key evidence in one line, and that containment is awaiting approval.\n\n"
            f"{incident_brief}"
        ),
        expected_output="A short plain-text alert, ready to send to Slack.",
        agent=drafter,
    )
    crew = Crew(agents=[drafter], tasks=[task], process=Process.sequential, verbose=False)
    result = crew.kickoff()
    return str(result).strip()
