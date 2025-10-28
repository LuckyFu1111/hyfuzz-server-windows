"""Simple token bucket rate limiter."""

from __future__ import annotations

import time


class RateLimiter:
    def __init__(self, limit: int, interval: float) -> None:
        self.limit = limit
        self.interval = interval
        self.tokens = limit
        self.last_refill = time.time()

    def allow(self) -> bool:
        now = time.time()
        elapsed = now - self.last_refill
        if elapsed >= self.interval:
            refill_tokens = int(elapsed / self.interval) * self.limit
            self.tokens = min(self.limit, self.tokens + refill_tokens)
            self.last_refill = now
        if self.tokens > 0:
            self.tokens -= 1
            return True
        return False


if __name__ == "__main__":
    limiter = RateLimiter(limit=2, interval=1)
    print([limiter.allow() for _ in range(3)])
