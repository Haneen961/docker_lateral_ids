"""Structured JSON alert sink (stdout + optional file)."""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

log = logging.getLogger(__name__)


class AlertSink:
    def __init__(self, path: Optional[str | Path] = None):
        self.path = Path(path) if path else None
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def emit(self, alert: Dict[str, Any]) -> None:
        alert = {"ts_iso": datetime.now(timezone.utc).isoformat(), **alert}
        line = json.dumps(alert, default=str)
        log.warning("ALERT %s", line)
        if self.path is not None:
            with self.path.open("a") as fh:
                fh.write(line + os.linesep)
