"""Containment / Ops -- System 3 (CrewAI).

Receives action requests from Threat Assessment, decides a mitigation (block
the offending IPs), and -- gated by the shared guardrail -- executes it against
a locally-simulated firewall, then reports status back.

Runs as its own process on port 9103.
"""
