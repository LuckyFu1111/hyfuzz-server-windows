"""Allocates resources for tasks."""

from __future__ import annotations

from typing import Dict

from .resource_models import ResourceRequest


class ResourceAllocator:
    def __init__(self) -> None:
        self.available: Dict[str, ResourceRequest] = {}

    def register_pool(self, name: str, cpu: int, memory: int) -> None:
        self.available[name] = ResourceRequest(cpu=cpu, memory=memory)

    def allocate(self, name: str, request: ResourceRequest) -> bool:
        pool = self.available.get(name)
        if not pool:
            return False
        if pool.cpu < request.cpu or pool.memory < request.memory:
            return False
        pool.cpu -= request.cpu
        pool.memory -= request.memory
        return True


if __name__ == "__main__":
    allocator = ResourceAllocator()
    allocator.register_pool("default", cpu=8, memory=16000)
    print(allocator.allocate("default", ResourceRequest(cpu=2, memory=1024)))
