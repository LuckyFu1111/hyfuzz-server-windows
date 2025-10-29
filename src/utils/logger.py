"""Simple logging helpers for HyFuzz."""

from __future__ import annotations

import logging
from typing import Optional

_DEFAULT_LEVEL = logging.INFO


def configure(level: int | None = None) -> None:
    """Configure the root logger with basic settings."""
    logging.basicConfig(level=level or _DEFAULT_LEVEL,
                        format="[%(asctime)s] %(levelname)s %(name)s: %(message)s")


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """Return a configured logger instance."""
    if not logging.getLogger().handlers:
        configure()
    return logging.getLogger(name or "hyfuzz")


def _self_test() -> bool:
    logger = get_logger(__name__)
    logger.debug("debug message")
    logger.info("info message")
    return True


if __name__ == "__main__":
    print("Logger self test:", _self_test())
