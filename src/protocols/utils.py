"""Helper utilities shared between protocol implementations."""

from __future__ import annotations

import hashlib
from typing import Mapping


def payload_fingerprint(payload: Mapping[str, object]) -> str:
    """Return a stable fingerprint for a protocol payload."""

    encoded = repr(sorted(payload.items())).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


if __name__ == "__main__":
    fingerprint = payload_fingerprint({"code": "GET", "payload": ""})
    assert len(fingerprint) == 64
    print("protocols.utils self-test passed.")
