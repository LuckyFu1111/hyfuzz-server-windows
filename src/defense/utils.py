"""Utility helpers for defense analytics."""

from __future__ import annotations

from math import sqrt
from typing import Iterable


def cosine_similarity(lhs: Iterable[float], rhs: Iterable[float]) -> float:
    lhs_list = list(lhs)
    rhs_list = list(rhs)
    if not lhs_list or not rhs_list or len(lhs_list) != len(rhs_list):
        return 0.0
    dot_product = sum(l * r for l, r in zip(lhs_list, rhs_list))
    lhs_norm = sqrt(sum(l * l for l in lhs_list))
    rhs_norm = sqrt(sum(r * r for r in rhs_list))
    if lhs_norm == 0 or rhs_norm == 0:
        return 0.0
    return dot_product / (lhs_norm * rhs_norm)


if __name__ == "__main__":  # pragma: no cover - sanity test
    assert 0.99 < cosine_similarity([1, 0], [2, 0]) <= 1.0
    assert cosine_similarity([0, 0], [0, 0]) == 0.0
    print("Defense utils self-test passed.")
