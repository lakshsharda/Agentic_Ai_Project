"""Small CLI over Customer Comms' sign-off API, so the demo needs no curl.

    python scripts/comms_signoff.py list [--all] [--incident ID]
    python scripts/comms_signoff.py approve DRAFT_ID --as NAME [--edit "new text"]
    python scripts/comms_signoff.py reject  DRAFT_ID --as NAME [--reason "why"]

Standard library only, so any of the project's interpreters runs it. The
incident id is looked up from the draft, so only the draft id is needed.
Set COMMS_URL to point at a non-default host.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

BASE = os.environ.get("COMMS_URL", "http://127.0.0.1:9106")


def call(method: str, path: str, body: dict | None = None) -> tuple[int, dict]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def find_draft(draft_id: str) -> dict | None:
    _, body = call("GET", "/drafts?status=all")
    return next((d for d in body.get("drafts", []) if d["draft_id"] == draft_id), None)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    ls = sub.add_parser("list", help="show pending drafts")
    ls.add_argument("--all", action="store_true", help="every draft, any status")
    ls.add_argument("--incident")
    for name in ("approve", "reject"):
        p = sub.add_parser(name)
        p.add_argument("draft_id")
        p.add_argument("--as", dest="approver", required=True, help="your name (a person, not a system)")
        if name == "approve":
            p.add_argument("--edit", dest="edited_text", help="replace the text before approving")
        else:
            p.add_argument("--reason")
    args = ap.parse_args()

    if args.cmd == "list":
        q = "status=all" if args.all else ""
        if args.incident:
            q += ("&" if q else "") + f"incident_id={args.incident}"
        _, body = call("GET", "/drafts" + (f"?{q}" if q else ""))
        drafts = body.get("drafts", [])
        if not drafts:
            print("no drafts" + ("" if args.all else " pending sign-off"))
        for d in drafts:
            print(f"{d['draft_id']}  incident={d['incident_id']}  event={d['event_type']}  "
                  f"severity={d['severity_at_draft']}  status={d['status']}")
            print(f"    {d['draft_text']}")
        return 0

    draft = find_draft(args.draft_id)
    if draft is None:
        print(f"no such draft: {args.draft_id}", file=sys.stderr)
        return 1
    body = {"incident_id": draft["incident_id"], "draft_id": args.draft_id,
            "decision": args.cmd, "approver": args.approver}
    if args.cmd == "approve" and args.edited_text is not None:
        body["edited_text"] = args.edited_text
    if args.cmd == "reject":
        body["reason"] = args.reason
    code, result = call("POST", "/signoff", body)
    print(json.dumps(result, indent=2, default=str))
    return 0 if code == 200 else 1


if __name__ == "__main__":
    raise SystemExit(main())
