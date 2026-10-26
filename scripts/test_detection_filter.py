"""Phase 1: prove the Noise Filtering agent discriminates attack from noise.

Generates two real traffic bursts against the live target app and runs
Detection's actual Noise Filtering agent over each:

  * a baseline burst  -> expect escalate = False
  * a brute-force burst -> expect escalate = True

Both windows are built from real access-log lines the script just caused, via
Detection's own reader + windowing + agent -- no synthetic stats.

    .venv-adk\\Scripts\\python scripts/test_detection_filter.py

Needs the target app running and GOOGLE_API_KEY set. This drives only the
filter (no A2A, no store writes), so Threat Assessment need not be up.
"""

from __future__ import annotations

import asyncio
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from google.adk.runners import InMemoryRunner
from google.genai import types as genai_types

from detection.agents import (
    VERDICT_STATE_KEY,
    WINDOW_STATS_STATE_KEY,
    NoiseVerdict,
    build_noise_filter_agent,
)
from detection.log_reader import AccessLogReader
from detection.windowing import SignalWindow
from shared.llm import require_google_api_key

LOG_PATH = Path(__file__).resolve().parents[1] / "target_app" / "logs" / "access.log"
PY_APP = Path(__file__).resolve().parents[1] / ".venv-app" / "Scripts" / "python.exe"
SIM = Path(__file__).resolve().parents[1] / "scripts" / "attack_simulate.py"


def _simulate(pattern: str, intensity: int) -> None:
    subprocess.run(
        [str(PY_APP), str(SIM), "--pattern", pattern, "--intensity", str(intensity), "--delay", "0.01"],
        check=True,
        capture_output=True,
    )


async def _assess(runner: InMemoryRunner, stats: dict) -> NoiseVerdict:
    session = await runner.session_service.create_session(
        app_name="filtertest", user_id="t", state={WINDOW_STATS_STATE_KEY: stats}
    )
    async for _ in runner.run_async(
        user_id="t",
        session_id=session.id,
        new_message=genai_types.Content(
            role="user", parts=[genai_types.Part(text="Assess the current traffic window.")]
        ),
    ):
        pass
    session = await runner.session_service.get_session(
        app_name="filtertest", user_id="t", session_id=session.id
    )
    return NoiseVerdict.model_validate(session.state.get(VERDICT_STATE_KEY))


async def _run_case(runner: InMemoryRunner, label: str, pattern: str, intensity: int, expect: bool) -> bool:
    print(f"\n{'=' * 70}\n{label}: generating '{pattern}' traffic (intensity {intensity})\n{'=' * 70}")

    # Start reading at the current end of file, so only this case's traffic is
    # in the window.
    reader = AccessLogReader(LOG_PATH, from_end=True)
    window = SignalWindow(window_seconds=120.0)

    _simulate(pattern, intensity)
    time.sleep(0.4)  # let the app flush its log

    window.add_all(reader.read_new())
    stats = window.aggregate()
    print(
        f"window: {stats.get('total_requests')} reqs, "
        f"{stats.get('failed_logins', 0)} failed logins, "
        f"{stats.get('distinct_ips_with_failed_logins', 0)} distinct failing IPs, "
        f"{stats.get('distinct_usernames_targeted', 0)} usernames"
    )

    verdict = await _assess(runner, stats)
    ok = verdict.escalate == expect
    print(f"verdict: escalate={verdict.escalate} pattern={verdict.pattern_type} "
          f"confidence={verdict.confidence:.2f}")
    print(f"reasoning: {verdict.reasoning}")
    print(f"[{'PASS' if ok else 'FAIL'}] expected escalate={expect}, got {verdict.escalate}")
    return ok


async def main() -> int:
    require_google_api_key()

    import requests

    try:
        requests.get("http://127.0.0.1:8080/status", timeout=5).raise_for_status()
    except Exception as exc:  # noqa: BLE001
        print(f"target app not reachable: {exc}", file=sys.stderr)
        return 1

    runner = InMemoryRunner(agent=build_noise_filter_agent(), app_name="filtertest")

    results = []
    results.append(await _run_case(runner, "NEGATIVE CASE", "baseline", 16, expect=False))
    results.append(await _run_case(runner, "POSITIVE CASE", "brute-force", 35, expect=True))

    passed = sum(results)
    print(f"\n{'=' * 70}\n{passed}/{len(results)} cases passed")
    if passed == len(results):
        print("PASS -- the Noise Filtering agent distinguishes attack from baseline")
        return 0
    print("FAIL -- discrimination not demonstrated")
    return 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
