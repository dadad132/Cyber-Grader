"""Runs scans with the current settings and protects the site from abuse (rate limits, concurrency)."""
from __future__ import annotations

import threading
import time
from collections import deque

from .context import DEFAULT_USER_AGENT
from .dnsutil import Inconclusive
from .grader import grade_domain
from .models import Report
from .settings import Settings, SettingsStore
from .target import BlockedTarget, normalize_domain

RATE_WINDOW = 600  # seconds


class ScanRefused(Exception):
    def __init__(self, message: str, status: int) -> None:
        super().__init__(message)
        self.status = status


class RateLimiter:
    """Sliding-window limit per client key."""

    def __init__(self, limit: int, window: float) -> None:
        self.limit, self.window = limit, window
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def _recent(self, key: str, now: float) -> deque[float]:
        if len(self._hits) > 10_000:  # forget idle clients
            self._hits = {k: v for k, v in self._hits.items() if v and now - v[-1] < self.window}
        hits = self._hits.setdefault(key, deque())
        while hits and now - hits[0] > self.window:
            hits.popleft()
        return hits

    def allow(self, key: str) -> bool:
        """Record a hit for key; False if it was already at the limit."""
        now = time.monotonic()
        with self._lock:
            hits = self._recent(key, now)
            if len(hits) >= self.limit:
                return False
            hits.append(now)
            return True

    def blocked(self, key: str) -> bool:
        """True if key is at the limit, without recording a hit."""
        with self._lock:
            return len(self._recent(key, time.monotonic())) >= self.limit


class GraderService:
    def __init__(self, store: SettingsStore) -> None:
        self.store = store
        settings = store.current
        self.db_path = store.path.parent / "grader.db"
        self.scan_limiter = RateLimiter(settings.rate_limit, RATE_WINDOW)
        self.login_limiter = RateLimiter(5, 900)        # super-admin sign-in failures per IP
        self.customer_login_limiter = RateLimiter(10, 900)
        self.signup_limiter = RateLimiter(5, 3600)
        self.reset_limiter = RateLimiter(5, 3600)
        self._slots_lock = threading.Lock()
        self._slots_size = settings.max_concurrent
        self._slots = threading.BoundedSemaphore(self._slots_size)

    @property
    def settings(self) -> Settings:
        return self.store.current

    def _slots_for(self, size: int) -> threading.BoundedSemaphore:
        # Recreated when the setting changes; in-flight scans release the semaphore they acquired.
        with self._slots_lock:
            if size != self._slots_size:
                self._slots, self._slots_size = threading.BoundedSemaphore(size), size
            return self._slots

    def scan(self, domain: str, *, client: str | None = None) -> Report:
        """Grade an already-normalised domain. client=None skips the rate limit (super admin)."""
        settings = self.settings
        if client is not None:
            self.scan_limiter.limit = settings.rate_limit
            if not self.scan_limiter.allow(client):
                raise ScanRefused("You've run a lot of checks in a short time. Please wait a few minutes and try again.", 429)
        slots = self._slots_for(settings.max_concurrent)
        if not slots.acquire(timeout=60):
            raise ScanRefused("The grader is very busy right now. Please try again in a minute.", 503)
        try:
            return grade_domain(domain, timeout=settings.timeout, nameservers=settings.nameservers or None,
                                allow_private=False, user_agent=settings.user_agent or DEFAULT_USER_AGENT,
                                dnsbl_nameservers=settings.dnsbl_nameservers or None, spamhaus_key=settings.spamhaus_dqs_key)
        except (ValueError, BlockedTarget) as exc:
            raise ScanRefused(str(exc), 400) from exc
        except Inconclusive as exc:
            raise ScanRefused(f"DNS lookups for {domain} failed ({exc}). Please try again shortly.", 502) from exc
        finally:
            slots.release()


def check_domain_input(raw: str) -> str:
    """Normalise what the visitor typed, or raise ScanRefused with a friendly message."""
    try:
        return normalize_domain(raw)
    except ValueError as exc:
        raise ScanRefused(str(exc), 400) from exc
