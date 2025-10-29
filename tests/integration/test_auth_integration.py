import pytest

from src.auth.authenticator import Authenticator


def test_auth_flow_persists_session() -> None:
    auth = Authenticator()
    auth.register("integration", "secret")

    tokens = auth.login("integration", "secret")
    session_token = auth.users.sessions.get(tokens["session"])

    assert session_token is not None
    assert session_token.username == "integration"


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__])
