"""Rolling window of recent signals, plus the aggregation the LLM reasons over.

The Noise Filtering agent must reason over *context*, not single lines -- "5
failed logins from 5 IPs in 10 seconds" reads very differently from "1 failed
login from a known user". This module keeps a time-bounded buffer of recent
signals and reduces it to the aggregate stats the agent's FunctionTool serves.

No verdicts here. This is arithmetic; the judgement is the model's.
"""

from __future__ import annotations

import time
from collections import Counter, deque
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List


class SignalWindow:
    """Time-bounded buffer of recent signals.

    Bounded by wall-clock age (window_seconds) and a hard cap (max_signals) so
    a flood cannot grow memory without limit.
    """

    def __init__(self, *, window_seconds: float = 30.0, max_signals: int = 2000) -> None:
        self.window_seconds = window_seconds
        self.max_signals = max_signals
        self._signals: Deque[Dict[str, Any]] = deque(maxlen=max_signals)

    def add(self, signal: Dict[str, Any]) -> None:
        # Stamp arrival time; the log's own timestamp is used for display, but
        # eviction runs off a monotonic-ish arrival clock so a bad/missing
        # timestamp in a line cannot keep it in the window forever.
        signal.setdefault("_ingested_at", time.time())
        self._signals.append(signal)

    def add_all(self, signals: List[Dict[str, Any]]) -> None:
        for s in signals:
            self.add(s)

    def _evict_old(self) -> None:
        cutoff = time.time() - self.window_seconds
        while self._signals and self._signals[0].get("_ingested_at", 0) < cutoff:
            self._signals.popleft()

    def current(self) -> List[Dict[str, Any]]:
        self._evict_old()
        return list(self._signals)

    def __len__(self) -> int:
        self._evict_old()
        return len(self._signals)

    def aggregate(self) -> Dict[str, Any]:
        """Reduce the current window to the stats the agent reasons over.

        Everything here is descriptive -- counts, distinct cardinalities, rates,
        top-N breakdowns. Deliberately no 'is_attack' flag or threshold: that
        conclusion is the model's to draw from these numbers.
        """
        signals = self.current()
        total = len(signals)

        if total == 0:
            return {
                "total_requests": 0,
                "window_seconds": self.window_seconds,
                "note": "no traffic in the current window",
            }

        login_attempts = [s for s in signals if s.get("endpoint") == "/login"]
        failed_logins = [s for s in login_attempts if s.get("auth_outcome") == "invalid_credentials"]
        successful_logins = [s for s in login_attempts if s.get("auth_outcome") == "success"]

        ips = Counter(s.get("source_ip", "unknown") for s in signals)
        failed_login_ips = Counter(s.get("source_ip", "unknown") for s in failed_logins)
        attempted_usernames = Counter(
            s.get("username") for s in failed_logins if s.get("username")
        )
        endpoints = Counter(s.get("endpoint", "unknown") for s in signals)
        statuses = Counter(s.get("status_code") for s in signals)

        span = self._observed_span_seconds(signals)
        rate = round(total / span, 2) if span > 0 else float(total)

        return {
            "total_requests": total,
            "window_seconds": self.window_seconds,
            "observed_span_seconds": round(span, 2),
            "request_rate_per_sec": rate,
            "distinct_source_ips": len(ips),
            "login_attempts": len(login_attempts),
            "failed_logins": len(failed_logins),
            "successful_logins": len(successful_logins),
            "distinct_ips_with_failed_logins": len(failed_login_ips),
            "distinct_usernames_targeted": len(attempted_usernames),
            "top_source_ips": ips.most_common(5),
            "top_failed_login_ips": failed_login_ips.most_common(5),
            "top_targeted_usernames": attempted_usernames.most_common(5),
            "requests_by_endpoint": dict(endpoints),
            "requests_by_status": {str(k): v for k, v in statuses.items()},
        }

    @staticmethod
    def _observed_span_seconds(signals: List[Dict[str, Any]]) -> float:
        times = [s["ts"] for s in signals if isinstance(s.get("ts"), datetime)]
        if len(times) < 2:
            return 0.0
        lo, hi = min(times), max(times)
        if lo.tzinfo is None:
            lo = lo.replace(tzinfo=timezone.utc)
        if hi.tzinfo is None:
            hi = hi.replace(tzinfo=timezone.utc)
        return (hi - lo).total_seconds()
