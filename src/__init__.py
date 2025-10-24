# src/__init__.py
# ==============================================================================
# HyFuzz Server - Windows MCP Server Package
# ==============================================================================

"""
HyFuzz Server - Hybrid AI-Enhanced Vulnerability Detection Framework

A Windows-based MCP (Model Context Protocol) server that integrates Large Language
Models with structured vulnerability knowledge for intelligent fuzzing and exploit
generation.

Main Features:
- LLM-CoT reasoning for intelligent payload generation
- Dual knowledge base (Graph DB + Vector DB)
- MCP protocol handler for client communication
- Feedback-driven adaptive learning
- Support for multiple protocols (CoAP, Modbus)

Usage:
    from src.mcp_server.server import MCPServer

    server = MCPServer()
    server.start()

Documentation:
    https://github.com/your-org/hyfuzz-server-windows/docs
"""

# ==============================================================================
# VERSION INFORMATION
# ==============================================================================
__version__ = "1.0.0"
__author__ = "HyFuzz Contributors"
__email__ = "support@hyfuzz.ai"
__license__ = "MIT"
__copyright__ = "Copyright (c) 2025 HyFuzz Contributors"

# ==============================================================================
# PACKAGE METADATA
# ==============================================================================
__title__ = "hyfuzz-server"
__description__ = "Hybrid AI-Enhanced Vulnerability Detection Framework - Windows MCP Server"
__url__ = "https://github.com/your-org/hyfuzz-server-windows"

# ==============================================================================
# SEMANTIC VERSIONING
# ==============================================================================
# Version format: MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]
# - MAJOR: Breaking changes
# - MINOR: New features, backwards compatible
# - PATCH: Bug fixes
# - PRERELEASE: alpha, beta, rc (e.g., 1.0.0-rc1)
# - BUILD: Build metadata (e.g., +20250115)

VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH = __version__.split(".")[:3]

# ==============================================================================
# EXPORTS
# ==============================================================================
__all__ = [
    "__version__",
    "__author__",
    "__email__",
    "__license__",
    "__title__",
    "__description__",
    "VERSION_MAJOR",
    "VERSION_MINOR",
    "VERSION_PATCH",
]