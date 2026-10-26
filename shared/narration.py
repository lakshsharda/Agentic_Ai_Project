"""Static causal map for the live reasoning feed (Phase 6.1).

Which reasoning entry directly caused which is fixed by the pipeline's design, not by anything an agent
decides, so it lives here as data. ``chain_for(agent_name)`` returns ``(caused_by, depth)``: the
``agent_name`` of the entry that triggered this one (``None`` for the root) and how many hops from the
root it sits. The viewer uses both to indent the feed into a top-to-bottom story. Presentation only:
nothing here is read by any agent or gate.

    Noise Filtering -> Correlation -> Severity Classification -+-> Containment Planning -> Impact Assessment -> Message Drafting
                                                               +-> On-Call Paging
                                                               +-> Root Cause Analysis -+-> Recovery Planning
                                                                                        +-> Severity Classification (re-classification)
"""

from __future__ import annotations

from typing import Dict, Optional, Tuple

_SEVERITY = "Severity Classification Agent"

# agent_name -> (caused_by agent_name, depth)
CHAIN: Dict[str, Tuple[Optional[str], int]] = {
    "Noise Filtering Agent": (None, 0),
    "Correlation Agent": ("Noise Filtering Agent", 1),
    _SEVERITY: ("Correlation Agent", 2),
    # the parallel dispatch fan-out from Severity Classification
    "Containment Planning Agent": (_SEVERITY, 3),
    "On-Call Paging Agent": (_SEVERITY, 3),
    "Root Cause Analysis Agent": (_SEVERITY, 3),
    # downstream consequences
    "Impact Assessment Agent": ("Containment Planning Agent", 4),
    "Customer Message Drafting Agent": ("Impact Assessment Agent", 5),
    "Recovery Planning Agent": ("Root Cause Analysis Agent", 4),
    "Severity Classification Agent (re-classification)": ("Root Cause Analysis Agent", 4),
}


# Parents whose children are launched together (the Threat Assessment dispatch), so the viewer can badge them.
PARALLEL_FANOUT = {_SEVERITY}


def is_parallel(agent_name: str) -> bool:
    parent, _ = chain_for(agent_name)
    return parent in PARALLEL_FANOUT


def chain_for(agent_name: str) -> Tuple[Optional[str], int]:
    """(caused_by, depth) for an agent; an unmapped agent is a depth-0 root with no parent."""
    return CHAIN.get(agent_name, (None, 0))
