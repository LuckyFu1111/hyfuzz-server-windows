"""Basic authentication workflow."""

from __future__ import annotations

import hashlib
from typing import Dict

from .auth_models import SessionToken, User
from .user_manager import UserManager
from .jwt_handler import JWTHandler


class Authenticator:
    def __init__(self) -> None:
        self.users = UserManager()
        self.jwt = JWTHandler(secret="hyfuzz-secret")

    def _hash(self, password: str) -> str:
        return hashlib.sha256(password.encode()).hexdigest()

    def register(self, username: str, password: str) -> User:
        user = User(username=username, password_hash=self._hash(password))
        self.users.store(user)
        return user

    def login(self, username: str, password: str) -> Dict[str, str]:
        user = self.users.get(username)
        if not user or user.password_hash != self._hash(password):
            raise ValueError("invalid credentials")
        token = SessionToken.create(username)
        self.users.add_session(token)
        jwt_token = self.jwt.issue({"sub": username})
        return {"session": token.token, "jwt": jwt_token}


if __name__ == "__main__":
    auth = Authenticator()
    auth.register("demo", "password")
    print(auth.login("demo", "password"))
