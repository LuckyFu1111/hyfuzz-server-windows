"""Resource related data models."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ResourceRequest:
    cpu: int
    memory: int


if __name__ == "__main__":
    print(ResourceRequest(cpu=2, memory=1024))
