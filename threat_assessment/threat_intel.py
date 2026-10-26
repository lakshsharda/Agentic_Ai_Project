"""Mock threat-intelligence source for the Correlation agent.

A real intel feed is out of scope for this phase. What matters is that the
Correlation agent *reasons* over what the lookup returns, rather than the
lookup itself making the decision. So this is deliberately a plain data source
exposed as a FunctionTool: it reports what it knows about an IP, and the agent
decides what that means for the incident.

The "known bad" ranges below are documentation/test IP blocks (RFC 5737) so
they can never match a real host. The attack simulator sources its traffic
from these same blocks, so a simulated brute force will light up here.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Any, Dict, List

from google.adk.tools import FunctionTool

logger = logging.getLogger("threat_assessment.threat_intel")

# (cidr, reputation, category, note). Ordered most-specific-intent first.
_KNOWN_BAD: List[tuple[str, str, str, str]] = [
    ("203.0.113.0/24", "malicious", "botnet",
     "Associated with distributed credential-stuffing botnet activity."),
    ("198.51.100.0/24", "malicious", "scanner",
     "Known host-scanning / brute-force source range."),
    ("192.0.2.128/25", "suspicious", "anonymizer",
     "Open-proxy / VPN exit range; elevated abuse rate."),
]

# Reputation for anything that matches nothing above.
_DEFAULT = ("unknown", "none", "No prior intelligence on this address.")


def _classify_ip(ip_str: str) -> Dict[str, Any]:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return {
            "ip": ip_str,
            "reputation": "invalid",
            "category": "none",
            "note": "not a parseable IP address",
        }
    for cidr, reputation, category, note in _KNOWN_BAD:
        if ip in ipaddress.ip_network(cidr):
            return {
                "ip": ip_str,
                "reputation": reputation,
                "category": category,
                "matched_range": cidr,
                "note": note,
            }
    rep, cat, note = _DEFAULT
    return {"ip": ip_str, "reputation": rep, "category": cat, "note": note}


def lookup_ip_reputation(ips: List[str]) -> Dict[str, Any]:
    """Look up threat-intel reputation for a list of source IP addresses.

    For each IP, returns its reputation ('malicious', 'suspicious', 'unknown',
    or 'invalid'), a category, and a human-readable note. Use this to enrich an
    incident, then reason about how much the reputations change its severity --
    do not treat a single 'malicious' hit as automatically critical.
    """
    results = [_classify_ip(ip) for ip in ips]
    summary = {
        "malicious": sum(1 for r in results if r["reputation"] == "malicious"),
        "suspicious": sum(1 for r in results if r["reputation"] == "suspicious"),
        "unknown": sum(1 for r in results if r["reputation"] == "unknown"),
        "invalid": sum(1 for r in results if r["reputation"] == "invalid"),
    }
    logger.info("threat-intel lookup over %d IP(s): %s", len(ips), summary)
    return {"results": results, "summary": summary, "total_checked": len(ips)}


threat_intel_tool = FunctionTool(func=lookup_ip_reputation)
