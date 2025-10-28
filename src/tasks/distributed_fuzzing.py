"""Utilities for coordinating distributed fuzzing tasks."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List

from .task_models import TaskDefinition


@dataclass
class FuzzingNode:
    name: str
    capacity: int
    weight: float


class DistributedFuzzingPlanner:
    """Assigns tasks across fuzzing nodes using weighted distribution."""

    def __init__(self, nodes: Iterable[FuzzingNode]) -> None:
        self.nodes = list(nodes)
        total_weight = sum(node.weight for node in self.nodes) or 1
        for node in self.nodes:
            node.weight = node.weight / total_weight

    def plan(self, tasks: Iterable[TaskDefinition]) -> Dict[str, List[TaskDefinition]]:
        plan: Dict[str, List[TaskDefinition]] = {node.name: [] for node in self.nodes}
        node_cycle = self._weighted_cycle()
        for task in tasks:
            node = next(node_cycle)
            plan[node.name].append(task)
        return plan

    def _weighted_cycle(self):
        while True:
            for node in self.nodes:
                slots = max(1, int(node.weight * 10))
                for _ in range(slots):
                    yield node


if __name__ == "__main__":
    nodes = [FuzzingNode("A", capacity=10, weight=0.7), FuzzingNode("B", capacity=5, weight=0.3)]
    planner = DistributedFuzzingPlanner(nodes)
    tasks = [TaskDefinition(name=f"task-{i}", payload={}) for i in range(5)]
    plan = planner.plan(tasks)
    for node, assigned in plan.items():
        print(node, len(assigned))
