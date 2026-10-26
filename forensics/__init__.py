"""Forensics & Recovery -- System 4 (CrewAI).

Triggered when Threat Assessment dispatches an incident. Preserves evidence
(snapshot of the simulated firewall + the signals that led to the incident),
performs long-form root-cause analysis, feeds a re-classification back upstream
to Threat Assessment when the analysis warrants it, and finally produces an
advisory recovery plan plus a lift-containment signal.

Runs as its own process on port 9105.
"""
