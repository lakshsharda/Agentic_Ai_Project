"""Alert Ingestion -- the non-reasoning front of Detection.

Tails the target app's access log and turns each new JSON line into a raw
signal dict. Polling, not inotify/streaming: the phase brief says polling is
fine, and it keeps this dependency-free and trivial to reason about.

A signal is just the parsed log line plus a parsed `ts` datetime. The reader
holds no opinion about whether a signal matters -- that is the Noise Filtering
agent's job.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("detection.log_reader")


def _parse_ts(raw: str) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(raw)
    except (ValueError, TypeError):
        return None


class AccessLogReader:
    """Incremental reader over the newline-delimited JSON access log.

    Tracks a byte offset so each poll returns only lines appended since the
    last one. Handles the file not existing yet (the app may start after
    Detection) and truncation/rotation (offset past EOF -> start over).
    """

    def __init__(self, log_path: Path, *, from_end: bool = True) -> None:
        self.log_path = Path(log_path)
        self._offset = 0
        self._partial = ""
        # Default to starting at the current end of file, so a run reacts to
        # traffic generated *after* Detection starts rather than replaying the
        # whole history on every boot. Pass from_end=False to read it all.
        if from_end and self.log_path.exists():
            self._offset = self.log_path.stat().st_size

    def read_new(self) -> List[Dict[str, Any]]:
        if not self.log_path.exists():
            return []

        size = self.log_path.stat().st_size
        if size < self._offset:
            # File shrank -- rotated or truncated. Start from the top.
            logger.info("access log shrank (%d < %d); resetting offset", size, self._offset)
            self._offset = 0
            self._partial = ""

        signals: List[Dict[str, Any]] = []
        with self.log_path.open("r", encoding="utf-8") as fh:
            fh.seek(self._offset)
            chunk = fh.read()
            self._offset = fh.tell()

        data = self._partial + chunk
        # A final line without a trailing newline is incomplete -- hold it over
        # so we never parse half a JSON object.
        lines = data.split("\n")
        self._partial = lines.pop() if not data.endswith("\n") else ""
        if data.endswith("\n"):
            lines = [ln for ln in lines if ln]

        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                logger.warning("skipping unparsable log line: %.120s", line)
                continue
            record["ts"] = _parse_ts(record.get("timestamp", ""))
            signals.append(record)

        if signals:
            logger.debug("ingested %d new signal(s)", len(signals))
        return signals
