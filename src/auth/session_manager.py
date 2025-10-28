"""Session management."""

from __future__ import annotations

from typing import Dict, Optional

from .auth_models import SessionToken


class SessionManager:
    def __init__(self) -> None:
        self.sessions: Dict[str, SessionToken] = {}

    def store(self, token: SessionToken) -> None:
        self.sessions[token.token] = token

    def get(self, token_value: str) -> Optional[SessionToken]:
        token = self.sessions.get(token_value)
        if token and token.is_expired():
            self.sessions.pop(token_value, None)
            return None
        return token


if __name__ == "__main__":
    manager = SessionManager()
    token = SessionToken.create("demo", ttl_seconds=1)
    manager.store(token)
    print(manager.get(token.token))
