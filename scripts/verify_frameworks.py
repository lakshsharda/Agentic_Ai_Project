"""Phase 0 verification for ADK and CrewAI.

Run once per virtualenv -- each framework lives in its own venv, so each run
reports on whichever framework is installed there:

    .venv-adk\\Scripts\\python  scripts/verify_frameworks.py
    .venv-crew\\Scripts\\python scripts/verify_frameworks.py

The script separates two different questions, because they have different
answers in a fresh environment:

  * Is the framework installed and able to build and wire up an agent?
    This needs no credentials and is checked unconditionally.
  * Can the agent actually reach a model and produce a response?
    This needs a provider API key. Without one the script reports SKIPPED and
    says which key is missing, rather than failing and implying the install
    is broken.
"""

from __future__ import annotations

import asyncio
import os
import platform
import sys
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

GOOGLE_KEYS = ("GOOGLE_API_KEY", "GEMINI_API_KEY")
CREW_KEYS = ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY")


def _pkg_version(name: str) -> Optional[str]:
    try:
        return version(name)
    except PackageNotFoundError:
        return None


def _first_key(names) -> Optional[str]:
    return next((n for n in names if os.environ.get(n)), None)


def header(text: str) -> None:
    print(f"\n{'=' * 66}\n{text}\n{'=' * 66}")


# --------------------------------------------------------------------------
# Google ADK
# --------------------------------------------------------------------------


def verify_adk() -> bool:
    header("Google ADK")
    installed = _pkg_version("google-adk")
    if installed is None:
        print("SKIP  google-adk is not installed in this interpreter")
        return True

    print(f"PASS  google-adk == {installed}")
    print(f"      google-genai == {_pkg_version('google-genai')}")

    from google.adk.agents import LlmAgent
    from google.adk.tools import FunctionTool

    def add(a: int, b: int) -> int:
        """Add two integers.

        Args:
            a: First integer.
            b: Second integer.
        """
        return a + b

    agent = LlmAgent(
        name="adk_quickstart_check",
        model="gemini-2.0-flash",
        description="Phase 0 install check.",
        instruction="Use the add tool to answer arithmetic questions.",
        tools=[FunctionTool(func=add)],
    )
    print(f"PASS  built LlmAgent {agent.name!r} with {len(agent.tools)} tool(s)")

    key = _first_key(GOOGLE_KEYS)
    if key is None:
        print(f"SKIP  live model call -- set one of {', '.join(GOOGLE_KEYS)}")
        print("      (install verified; model response NOT verified)")
        return True

    print(f"      using credential from {key}")
    return asyncio.run(_adk_live_call(agent))


async def _adk_live_call(agent) -> bool:
    from google.adk.runners import InMemoryRunner
    from google.genai import types as genai_types

    runner = InMemoryRunner(agent=agent, app_name="phase0_check")
    session = await runner.session_service.create_session(
        app_name="phase0_check", user_id="phase0"
    )

    replies = []
    async for event in runner.run_async(
        user_id="phase0",
        session_id=session.id,
        new_message=genai_types.Content(
            role="user", parts=[genai_types.Part(text="What is 17 plus 25?")]
        ),
    ):
        if event.content and event.content.parts:
            for part in event.content.parts:
                if part.text:
                    replies.append(part.text.strip())

    final = " ".join(r for r in replies if r)
    if final:
        print(f"PASS  live model call -- agent replied: {final[:200]}")
        return True
    print("FAIL  live model call produced no text")
    return False


# --------------------------------------------------------------------------
# CrewAI
# --------------------------------------------------------------------------


def verify_crewai() -> bool:
    header("CrewAI")
    installed = _pkg_version("crewai")
    if installed is None:
        print("SKIP  crewai is not installed in this interpreter")
        return True

    print(f"PASS  crewai == {installed}")

    from crewai import Agent, Crew, Task

    researcher = Agent(
        role="Phase 0 Checker",
        goal="Confirm the CrewAI install works.",
        backstory="A throwaway agent used once to verify the environment.",
        verbose=False,
        allow_delegation=False,
    )
    task = Task(
        description="Reply with the single word WORKING.",
        expected_output="The single word WORKING.",
        agent=researcher,
    )
    crew = Crew(agents=[researcher], tasks=[task], verbose=False)
    print(f"PASS  built Crew with {len(crew.agents)} agent(s), {len(crew.tasks)} task(s)")

    key = _first_key(CREW_KEYS)
    if key is None:
        print(f"SKIP  crew kickoff -- set one of {', '.join(CREW_KEYS)}")
        print("      (install verified; crew response NOT verified)")
        return True

    print(f"      using credential from {key}")
    try:
        result = crew.kickoff()
        print(f"PASS  crew kickoff -- result: {str(result).strip()[:200]}")
        return True
    except Exception as exc:  # noqa: BLE001
        print(f"FAIL  crew kickoff raised {type(exc).__name__}: {exc}")
        return False


# --------------------------------------------------------------------------
# A2A SDK + shared schema
# --------------------------------------------------------------------------


def verify_shared() -> bool:
    header("a2a-sdk and the shared schema")
    print(f"PASS  a2a-sdk == {_pkg_version('a2a-sdk')}")

    from shared.schemas import IncidentMessage, SystemName, new_incident_id

    msg = IncidentMessage(
        incident_id=new_incident_id(),
        source_system=SystemName.DETECTION,
        target_system=SystemName.CONTAINMENT,
        payload={"check": True},
    )
    round_tripped = IncidentMessage.from_wire(msg.to_wire())
    ok = round_tripped.incident_id == msg.incident_id and round_tripped.payload == msg.payload
    print(f"{'PASS' if ok else 'FAIL'}  IncidentMessage serialise/parse round trip")

    from shared.a2a_support import build_agent_card, from_a2a_message, to_a2a_message

    card = build_agent_card(
        name="check",
        description="check",
        url="http://127.0.0.1:9999",
        system=SystemName.DETECTION,
    )
    card_ok = card.name == "check" and len(card.supported_interfaces) == 1
    print(f"{'PASS' if card_ok else 'FAIL'}  AgentCard construction")

    wire_ok = from_a2a_message(to_a2a_message(msg)).incident_id == msg.incident_id
    print(f"{'PASS' if wire_ok else 'FAIL'}  IncidentMessage <-> A2A Message conversion")

    return ok and card_ok and wire_ok


def main() -> int:
    header("Environment")
    print(f"      python     == {platform.python_version()} ({sys.executable})")
    print(f"      platform   == {platform.platform()}")

    results = {
        "shared": verify_shared(),
        "adk": verify_adk(),
        "crewai": verify_crewai(),
    }

    header("Summary")
    for name, ok in results.items():
        print(f"      {name:8s} {'OK' if ok else 'FAILED'}")
    return 0 if all(results.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
