from __future__ import annotations

import time

import pytest

from orchestrator.ratelimit import RateLimiter


def test_burst_allows_immediate() -> None:
    rl = RateLimiter(rps_per_host=1.0, burst=3)
    t = time.monotonic()
    for _ in range(3):
        rl.acquire("https://x.example/a")
    assert time.monotonic() - t < 0.1


def test_rate_limits_after_burst() -> None:
    rl = RateLimiter(rps_per_host=10.0, burst=1)
    rl.acquire("https://x/a")
    t = time.monotonic()
    rl.acquire("https://x/a")
    assert time.monotonic() - t >= 0.05


def test_per_host_isolation() -> None:
    rl = RateLimiter(rps_per_host=1.0, burst=1)
    rl.acquire("https://a/x")
    t = time.monotonic()
    rl.acquire("https://b/x")
    assert time.monotonic() - t < 0.05


def test_bad_rps() -> None:
    with pytest.raises(ValueError):
        RateLimiter(rps_per_host=0)
