"""Utility helpers used by defense modules."""

from __future__ import annotations

from statistics import mean
from typing import Iterable


def rolling_average(values: Iterable[float]) -> float:
    vals = list(values)
    return mean(vals) if vals else 0.0


if __name__ == "__main__":
    assert rolling_average([1, 2, 3]) == 2
    print("defense.utils self-test passed.")
