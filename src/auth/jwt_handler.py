"""Very small JWT handler (not secure, for demonstration only)."""

from __future__ import annotations

import base64
import json
from hmac import digest
from typing import Dict


class JWTHandler:
    def __init__(self, secret: str) -> None:
        self.secret = secret.encode()

    def issue(self, payload: Dict[str, object]) -> str:
        header = {"alg": "HS256", "typ": "JWT"}
        segments = [self._encode(header), self._encode(payload)]
        signature = self._sign(".".join(segments))
        segments.append(signature)
        return ".".join(segments)

    def verify(self, token: str) -> Dict[str, object]:
        header_b64, payload_b64, signature = token.split(".")
        expected_sig = self._sign(f"{header_b64}.{payload_b64}")
        if not self._constant_time_compare(signature, expected_sig):
            raise ValueError("invalid signature")
        return json.loads(base64.urlsafe_b64decode(self._pad(payload_b64)))

    def _encode(self, data: Dict[str, object]) -> str:
        raw = json.dumps(data, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    def _sign(self, message: str) -> str:
        signature = digest(self.secret, message.encode(), "sha256")
        return base64.urlsafe_b64encode(signature).decode().rstrip("=")

    @staticmethod
    def _pad(value: str) -> bytes:
        return value + "=" * (-len(value) % 4)

    @staticmethod
    def _constant_time_compare(a: str, b: str) -> bool:
        if len(a) != len(b):
            return False
        result = 0
        for x, y in zip(a.encode(), b.encode()):
            result |= x ^ y
        return result == 0


if __name__ == "__main__":
    handler = JWTHandler(secret="demo")
    token = handler.issue({"sub": "user"})
    print(token)
    print(handler.verify(token))
