"""Phase 3, Task 3: partial-generation-cutoff continuation for the RCA path.

Forces truncation with a tiny per-round token budget so the first model stops
mid-generation, then confirms the shared continuation path picks up and
stitches the rest across rounds (and, when the chain has >1 provider, across
providers). Uses the real RCA generation helper the Forensics agent uses.

    .venv-adk\\Scripts\\python scripts/test_rca_continuation.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from shared.llm import ROLE_REASONING, generate_with_continuation, require_google_api_key


def main() -> int:
    require_google_api_key()

    r = generate_with_continuation(
        ROLE_REASONING,
        system_prompt="You are a security analyst writing a detailed root-cause narrative.",
        user_prompt=(
            "Write a thorough, multi-paragraph root-cause analysis of a distributed "
            "credential-stuffing attack: how it unfolded, the blast radius, the evidence, "
            "and the residual risk. Be specific and complete."
        ),
        agent_name="rca_continuation_test",
        max_tokens_per_round=160,  # small -> forces mid-generation cutoff, but enough text per round
        max_rounds=4,
    )

    print(f"mode={r['mode']} rounds={r['rounds']} continued={r['continued']} finished={r['finished']}")
    print(f"providers={r['providers']}")
    print(f"\n--- stitched narrative ({len(r['text'].split())} words) ---\n{r['text'][:700]}...\n")

    ok_multi = r["rounds"] > 1
    ok_text = len(r["text"].split()) > 40
    ok_continued = r["continued"] or r["mode"] == "continuation"

    print(f"[rca] {'PASS' if ok_multi else 'FAIL'}  generation spanned multiple rounds (truncation handled)")
    print(f"[rca] {'PASS' if ok_continued else 'FAIL'}  continuation mode was used (not a single shot)")
    print(f"[rca] {'PASS' if ok_text else 'FAIL'}  stitched output is a substantial narrative")

    if ok_multi and ok_continued and ok_text:
        print("\n[rca] ALL PASSED -- mid-generation cutoff is handled by continuation")
        return 0
    print("\n[rca] FAILED")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
