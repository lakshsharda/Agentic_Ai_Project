"""Detection & Monitoring -- System 1 (Google ADK).

Reads the target app's access log, reasons over windows of recent traffic to
separate noise from genuine attack patterns, and hands anything that survives
to Threat Assessment over A2A as a new DETECTED incident.

Runs as its own process on port 9101. Replaces the Phase 0 adk_sender scaffold.
"""
