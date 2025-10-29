"""Unit tests for API route dataclasses."""

from __future__ import annotations

import importlib.util
from pathlib import Path


def load_routes_module():
    path = Path("src/api/routes.py")
    spec = importlib.util.spec_from_file_location("api_routes", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def test_api_route_dataclass() -> None:
    routes = load_routes_module()
    route = routes.APIRoute(path="/status", handler="status_handler")
    assert route.path == "/status"
