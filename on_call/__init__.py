"""On-Call / Escalation -- System 6 (CrewAI).

Receives pages from Threat Assessment, notifies the on-call contact for real
(Slack webhook, with an honest local file-sink fallback when no webhook is
configured), starts an escalation timer, and writes a provenance-tagged
approval signal that Containment's guardrail reads -- on human acknowledgment,
or on timeout auto-approval.

Runs as its own process on port 9104.
"""
