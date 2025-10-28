"""Shared utilities for protocol handlers."""

from __future__ import annotations

from urllib.parse import urlparse


def extract_host(target: str) -> str:
    parsed = urlparse(target)
    return parsed.hostname or target


def extract_port(target: str, default: int = 0) -> int:
    parsed = urlparse(target)
    return parsed.port or default


if __name__ == "__main__":
    print(extract_host("http://example.com:8080"))
    print(extract_port("http://example.com:8080", default=80))
