"""Rate-limiter: per-host token bucket + глобальный семафор.

Инвариант bug-bounty: не превышать rps, объявленный программой (по умолчанию 5).
Реализация — thread-safe token bucket, без внешних зависимостей.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass
class _Bucket:
    tokens: float
    updated: float


class RateLimiter:
    """Один экземпляр на процесс. Вызов acquire(url) блокирует до наличия токена."""

    def __init__(self, rps_per_host: float = 5.0, burst: int = 5) -> None:
        if rps_per_host <= 0:
            raise ValueError("rps must be positive")
        self.rps = float(rps_per_host)
        self.burst = int(burst)
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _host(url: str) -> str:
        p = urlparse(url)
        return (p.hostname or "").lower()

    def acquire(self, url: str, timeout_s: float = 30.0) -> None:
        host = self._host(url) or "_default"
        deadline = time.monotonic() + timeout_s
        while True:
            with self._lock:
                b = self._buckets.get(host)
                now = time.monotonic()
                if b is None:
                    b = _Bucket(tokens=float(self.burst), updated=now)
                    self._buckets[host] = b
                elapsed = now - b.updated
                b.tokens = min(self.burst, b.tokens + elapsed * self.rps)
                b.updated = now
                if b.tokens >= 1.0:
                    b.tokens -= 1.0
                    return
                need = 1.0 - b.tokens
                wait = need / self.rps
            if time.monotonic() + wait > deadline:
                raise TimeoutError(f"rate-limit acquire timeout for host {host}")
            time.sleep(min(wait, 0.5))
