"""
Auto-mitigation via the Docker Engine API.

We map source IP → container ID by inspecting all containers on the
host once at start-up and refreshing the cache on cache-miss.

Safety controls:
  - dry_run: only log the intended action
  - whitelist: never stop these containers (e.g., the IDS itself)
  - rate_limit: per-container minimum interval between stops
"""

from __future__ import annotations

import logging
import time
from typing import Dict, Iterable, Optional, Set

import docker
from docker.errors import APIError, NotFound

log = logging.getLogger(__name__)


class Mitigator:
    def __init__(
        self,
        dry_run: bool = False,
        whitelist: Optional[Iterable[str]] = None,
        rate_limit_sec: float = 60.0,
    ):
        self.dry_run = dry_run
        self.whitelist: Set[str] = set(whitelist or [])
        self.rate_limit_sec = rate_limit_sec
        self._ip_to_cid: Dict[str, str] = {}
        self._last_action: Dict[str, float] = {}
        try:
            self.client = docker.from_env()
            self._refresh()
        except Exception as e:
            log.error("Docker client unavailable: %s — running in dry mode", e)
            self.client = None
            self.dry_run = True

    def _refresh(self) -> None:
        if self.client is None:
            return
        mapping: Dict[str, str] = {}
        try:
            for c in self.client.containers.list():
                nets = c.attrs.get("NetworkSettings", {}).get("Networks", {}) or {}
                for _, ncfg in nets.items():
                    ip = ncfg.get("IPAddress")
                    if ip:
                        mapping[ip] = c.id
        except APIError as e:
            log.error("Docker API error during refresh: %s", e)
        self._ip_to_cid = mapping
        log.info("Mitigator IP→container map: %d entries", len(mapping))

    def resolve(self, ip: str) -> Optional[str]:
        cid = self._ip_to_cid.get(ip)
        if cid is None:
            self._refresh()
            cid = self._ip_to_cid.get(ip)
        return cid

    def mitigate(self, ip: str, reason: str) -> Optional[str]:
        cid = self.resolve(ip)
        if cid is None:
            log.warning("No container found for IP %s — cannot mitigate", ip)
            return None
        try:
            c = self.client.containers.get(cid) if self.client else None
            name = c.name if c else cid[:12]
        except NotFound:
            return None

        if name in self.whitelist or cid in self.whitelist:
            log.info("WHITELIST hit, not stopping %s", name)
            return None
        # If the container is already stopped, don't try again — keeps the log clean.
        try:
            if c is not None:
                c.reload()
                status = c.attrs.get("State", {}).get("Status", "")
                if status not in ("running", "restarting"):
                    log.info("Container %s already %s — nothing to do", name, status)
                    return None
        except APIError:
            pass

        now = time.time()
        if now - self._last_action.get(cid, 0.0) < self.rate_limit_sec:
            log.info("Rate-limited mitigation for %s", name)
            return None
        self._last_action[cid] = now

        if self.dry_run or self.client is None:
            log.warning(
                "[DRY-RUN] would stop container %s (ip=%s) reason=%s", name, ip, reason
            )
            return name

        try:
            c.stop(timeout=2)
            log.warning("STOPPED container %s (ip=%s) reason=%s", name, ip, reason)
            return name
        except APIError as e:
            log.error("Failed to stop %s: %s", name, e)
            return None
