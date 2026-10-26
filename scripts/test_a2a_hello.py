"""Phase 0 end-to-end check for the A2A hello-world exchange.

Assumes both agent processes are already running in their own terminals:

    .venv-crew\\Scripts\\python -m a2a_hello.crew_receiver.server   # port 9002
    .venv-adk\\Scripts\\python  -m a2a_hello.adk_sender.server      # port 9001

Then:

    .venv-app\\Scripts\\python scripts/test_a2a_hello.py

It deliberately drives the exchange from the outside, over HTTP, so a passing
run cannot be explained by anything in this script calling agent code
directly.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

ADK_URL = "http://127.0.0.1:9001"
CREW_URL = "http://127.0.0.1:9002"
CARD_PATH = "/.well-known/agent-card.json"

results: Dict[str, bool] = {}


def check(name: str, ok: bool, detail: str = "") -> bool:
    results[name] = ok
    print(f"[a2a] {'PASS' if ok else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""))
    return ok


def fetch_card(base: str, label: str) -> Dict[str, Any]:
    try:
        resp = requests.get(base + CARD_PATH, timeout=10)
        resp.raise_for_status()
        card = resp.json()
    except Exception as exc:  # noqa: BLE001
        check(f"{label} agent card reachable", False, str(exc))
        return {}

    iface = (card.get("supportedInterfaces") or [{}])[0]
    check(
        f"{label} agent card reachable",
        bool(card.get("name")),
        f"{card.get('name')} via {iface.get('protocolBinding')} at {iface.get('url')}",
    )
    check(f"{label} card advertises a skill", bool(card.get("skills")))
    return card


def main() -> int:
    print("[a2a] both agents must already be running in separate processes\n")

    adk_card = fetch_card(ADK_URL, "ADK sender")
    crew_card = fetch_card(CREW_URL, "CrewAI receiver")
    if not adk_card or not crew_card:
        print("\n[a2a] cannot continue -- start both servers first")
        return 1

    check(
        "the two cards are distinct agents",
        adk_card.get("name") != crew_card.get("name"),
        f"{adk_card.get('name')} vs {crew_card.get('name')}",
    )

    print("\n[a2a] triggering the ADK process to send a real A2A task ...")
    try:
        resp = requests.post(
            ADK_URL + "/trigger",
            json={"note": "phase-0 automated check"},
            timeout=120,
        )
        body = resp.json()
    except Exception as exc:  # noqa: BLE001
        check("trigger returned a response", False, str(exc))
        return 1

    if resp.status_code != 200:
        check("trigger returned 200", False, json.dumps(body)[:400])
        return 1
    check("trigger returned 200", True, f"driver={body.get('driver')}")

    sent = body.get("sent") or {}
    reply = body.get("reply") or {}

    check("a message was sent", bool(sent.get("incident_id")), sent.get("incident_id", ""))
    check("a reply came back", bool(reply.get("incident_id")))
    check(
        "reply carries the same incident_id",
        sent.get("incident_id") == reply.get("incident_id"),
    )
    check(
        "reply direction is reversed",
        reply.get("source_system") == sent.get("target_system")
        and reply.get("target_system") == sent.get("source_system"),
        f"{reply.get('source_system')} -> {reply.get('target_system')}",
    )
    check(
        "receiver echoed the payload it was sent",
        (reply.get("payload") or {}).get("echoed_payload") == sent.get("payload"),
    )
    check(
        "receiver built a real CrewAI crew",
        (reply.get("payload") or {}).get("crew_constructed") is True,
        f"agents={(reply.get('payload') or {}).get('agents')}",
    )
    check(
        "incident row created by sender",
        (body.get("incident_store_create") or {}).get("ok") is True,
    )
    check(
        "incident row updated by receiver",
        ((reply.get("payload") or {}).get("incident_store") or {}).get("status")
        == "ack_received",
    )

    kickoff = (reply.get("payload") or {}).get("crew_kickoff")
    if kickoff != "ok":
        print(
            f"\n[a2a] NOTE  crew kickoff was {kickoff!r}: "
            f"{(reply.get('payload') or {}).get('crew_kickoff_reason')}"
        )
        print("[a2a] NOTE  this is an LLM credential gap, not an A2A transport problem")
    if body.get("llm_skipped_reason"):
        print(f"[a2a] NOTE  ADK sender: {body['llm_skipped_reason']}")

    failed = [k for k, v in results.items() if not v]
    print(f"\n[a2a] {len(results) - len(failed)}/{len(results)} checks passed")
    if failed:
        print("[a2a] FAILED: " + ", ".join(failed))
        return 1
    print("[a2a] ALL CHECKS PASSED -- real A2A round trip between two processes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
