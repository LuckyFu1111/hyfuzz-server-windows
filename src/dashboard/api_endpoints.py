"""Dashboard component: Api Endpoints."""

from dataclasses import dataclass
from typing import List

@dataclass
class DashboardMessage:
    channel: str
    payload: str

class ApiEndpoints:
    """Simple dashboard component stub."""

    def __init__(self) -> None:
        self.messages: List[DashboardMessage] = []

    def emit(self, channel: str, payload: str) -> None:
        self.messages.append(DashboardMessage(channel=channel, payload=payload))

def _self_test() -> bool:
    component = ApiEndpoints()
    component.emit('test', 'ok')
    return component.messages[0].payload == 'ok'

if __name__ == "__main__":
    print("Dashboard module self test:", _self_test())
