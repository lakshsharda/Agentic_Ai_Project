"""Deterministic validator for customer-facing text (Phase 4, Task 2).

The customer-content rule is enforced here, in code, on every draft and again
on every human edit -- not only requested in a prompt. A customer message may
say what is affected, what is being done and what customers should do. It must
never carry attacker IPs, usernames seen in the attack signals, internal
hostnames or ports, or root-cause detail.

Pure functions, no I/O beyond reading the incident record handed in, so it is
unit-testable without any process or model running.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable, List, Set

_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d])")
# A full IPv6 literal or a compressed one with at least two groups.
_IPV6 = re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?![\w:])")
# Ports: "host:8080", ":9103", "port 5432", "ports 80 and 443".
_PORT_COLON = re.compile(r"(?<![\d:])(?:[A-Za-z0-9_.\-\]]+)?:\d{2,5}\b(?!\s*(?:am|pm|AM|PM|UTC|utc))")
_PORT_WORD = re.compile(r"\bports?\s+\d{2,5}\b", re.IGNORECASE)
# Internal-looking hostnames: anything under a private TLD / cluster suffix,
# `localhost`, or a bare `name-NN` style host label such as db-01 / app-server-2.
_INTERNAL_HOST = re.compile(
    r"\b(?:[a-z0-9\-]+\.)+(?:internal|local|localdomain|lan|corp|intranet|private|svc|test|example|cluster\.local)\b"
    r"|\blocalhost\b"
    r"|\b(?:db|app|web|api|auth|redis|cache|worker|gateway|bastion|vpn|prod|stg|staging)[-_][a-z0-9\-_]*\d+[a-z0-9\-_]*\b",
    re.IGNORECASE,
)
# Attack-technique / root-cause vocabulary that has no place in a customer notice.
_ROOT_CAUSE_TERMS = re.compile(
    r"\b(?:brute[- ]?force|credential[- ]stuffing|password[- ]spray(?:ing)?|sql[- ]injection|"
    r"root[- ]cause|exploit(?:ed|ation)?|vulnerabilit(?:y|ies)|CVE-\d{4}-\d+|firewall rule|"
    r"blocked (?:ip|address)(?:es)?|source ip|failed logins?)\b",
    re.IGNORECASE,
)


@dataclass
class ValidationResult:
    ok: bool
    violations: List[str] = field(default_factory=list)

    @property
    def reason(self) -> str:
        return "; ".join(self.violations)


def _walk(obj: Any, *, key_hint: str = "") -> Iterable[Any]:
    """Yield (leaf value) pairs keyed by a path hint, for every nested leaf."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk(v, key_hint=str(k))
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            yield from _walk(item, key_hint=key_hint)
    else:
        yield (key_hint, obj)


def sensitive_terms(raw_payload: dict) -> dict:
    """Pull the identifying strings out of an incident's stored signals.

    Returns ``{"usernames": set, "hosts": set}``. Usernames come from any
    ``username``/``user`` key and from the evidence's ``top_targeted_usernames``
    lists; hosts from any ``host``/``hostname`` key.
    """
    usernames: Set[str] = set()
    hosts: Set[str] = set()
    detection = (raw_payload or {}).get("detection", {}) or {}

    evidence = detection.get("evidence", {}) or {}
    for entry in evidence.get("top_targeted_usernames", []) or []:
        name = entry[0] if isinstance(entry, (list, tuple)) and entry else entry
        if isinstance(name, str) and name.strip():
            usernames.add(name.strip())

    for key, value in _walk(detection):
        if not isinstance(value, str) or not value.strip():
            continue
        k = key.lower()
        if k in ("username", "user", "user_name", "login", "account"):
            usernames.add(value.strip())
        elif k in ("host", "hostname", "server", "server_name"):
            hosts.add(value.strip())
    return {"usernames": usernames, "hosts": hosts}


def validate_customer_text(text: str, raw_payload: dict | None = None) -> ValidationResult:
    """Check customer-facing text against the content rule.

    ``raw_payload`` is the incident's ``raw_payload`` (for the usernames and
    hostnames that appeared in its signals). Without it only the pattern-based
    checks run.
    """
    violations: List[str] = []
    body = (text or "").strip()
    if not body:
        return ValidationResult(False, ["empty text"])

    for m in _IPV4.finditer(body):
        octets = m.group(0).split(".")
        if all(0 <= int(o) <= 255 for o in octets):
            violations.append(f"contains an IPv4 address ({m.group(0)})")
            break
    if _IPV6.search(body):
        violations.append("contains an IPv6 address")
    if _PORT_COLON.search(body) or _PORT_WORD.search(body):
        violations.append("contains a port number")
    host_hit = _INTERNAL_HOST.search(body)
    if host_hit:
        violations.append(f"contains an internal hostname ({host_hit.group(0)})")

    cause_hit = _ROOT_CAUSE_TERMS.search(body)
    if cause_hit:
        violations.append(f"contains root-cause / technical attack detail ({cause_hit.group(0)})")

    terms = sensitive_terms(raw_payload or {})
    for name in sorted(terms["usernames"], key=len, reverse=True):
        if re.search(rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])", body, re.IGNORECASE):
            violations.append(f"contains a username from the incident signals ({name})")
    for host in sorted(terms["hosts"], key=len, reverse=True):
        if host.lower() in body.lower():
            violations.append(f"contains a hostname from the incident signals ({host})")

    return ValidationResult(not violations, violations)
