"""Authentication subsystem."""

from .authenticator import Authenticator
from .auth_models import User, SessionToken

__all__ = ["Authenticator", "User", "SessionToken"]


if __name__ == "__main__":
    auth = Authenticator()
    user = auth.register("demo", "password")
    token = auth.login("demo", "password")
    print(user, token)
