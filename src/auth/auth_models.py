"""Authentication models."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from secrets import token_urlsafe


@dataclass
class User:
    username: str
    password_hash: str


@dataclass
class SessionToken:
    token: str
    username: str
    expires_at: datetime

    @classmethod
    def create(cls, username: str, ttl_seconds: int = 3600) -> "SessionToken":
        return cls(token=token_urlsafe(16), username=username, expires_at=datetime.utcnow() + timedelta(seconds=ttl_seconds))

    def is_expired(self) -> bool:
        return datetime.utcnow() >= self.expires_at


if __name__ == "__main__":
    token = SessionToken.create("demo")
    print(token, token.is_expired())
