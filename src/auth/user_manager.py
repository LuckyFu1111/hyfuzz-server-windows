"""User management utilities."""

from __future__ import annotations

from typing import Dict, Optional

from .auth_models import SessionToken, User
from .session_manager import SessionManager


class UserManager:
    def __init__(self) -> None:
        self.users: Dict[str, User] = {}
        self.sessions = SessionManager()

    def store(self, user: User) -> None:
        self.users[user.username] = user

    def get(self, username: str) -> Optional[User]:
        return self.users.get(username)

    def add_session(self, token: SessionToken) -> None:
        self.sessions.store(token)


if __name__ == "__main__":
    manager = UserManager()
    user = User(username="demo", password_hash="hash")
    manager.store(user)
    print(manager.get("demo"))
