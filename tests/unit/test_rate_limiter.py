import time

import pytest

from src.resources.rate_limiter import RateLimiter


def test_rate_limiter_allows_within_limit() -> None:
    limiter = RateLimiter(limit=2, interval=1)
    assert limiter.allow() is True
    assert limiter.allow() is True
    assert limiter.allow() is False


def test_rate_limiter_refills_tokens(monkeypatch: pytest.MonkeyPatch) -> None:
    limiter = RateLimiter(limit=1, interval=1)

    first_time = time.time()
    monkeypatch.setattr(time, "time", lambda: first_time)
    assert limiter.allow() is True

    monkeypatch.setattr(time, "time", lambda: first_time + 2)
    assert limiter.allow() is True


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__])
