"""Threat Assessment & Intelligence -- System 2 (Google ADK).

Receives candidate incidents from Detection over A2A, enriches them against a
(mock) threat-intel source, classifies severity and incident type with real
LLM reasoning, advances the incident through CANDIDATE -> ASSESSED in the
store, and -- in this phase -- logs the fan-out it *would* send to Containment
and On-Call rather than sending it.

Runs as its own process on port 9102. Replaces the Phase 0 crew_receiver role.
"""
