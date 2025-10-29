import pytest

from src.auth.authenticator import Authenticator


def test_authenticator_register_and_login() -> None:
    auth = Authenticator()
    auth.register("tester", "password123")

    tokens = auth.login("tester", "password123")

    assert "jwt" in tokens and "session" in tokens
    payload = auth.jwt.verify(tokens["jwt"])
    assert payload["sub"] == "tester"


def test_authenticator_rejects_invalid_credentials() -> None:
    auth = Authenticator()
    auth.register("tester", "password123")

    with pytest.raises(ValueError):
        auth.login("tester", "wrong")


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__])
