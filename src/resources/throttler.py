"""Throttling helper."""

from __future__ import annotations

import time


class Throttler:
    def __init__(self, delay: float) -> None:
        self.delay = delay
        self._last_run = 0.0

    def wait(self) -> None:
        now = time.time()
        elapsed = now - self._last_run
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)
        self._last_run = time.time()


if __name__ == "__main__":
    throttler = Throttler(0.1)
    throttler.wait()
    throttler.wait()
    print("Throttled twice")
