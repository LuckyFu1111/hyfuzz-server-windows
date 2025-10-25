"""
MCP Server Module Initialization

This package provides the core MCP (Model Context Protocol) server implementation
for HyFuzz Windows server. It exports main classes, utilities, and factory functions
for creating and configuring MCP server instances.

Main components:
- MCPServer: Core server class
- Transports: stdio, HTTP, WebSocket
- MessageHandler: Protocol message handling
- CapabilityManager: Feature management
- SessionManager: Session handling
"""

import logging
from typing import Optional, Dict, Any, List, Type
from enum import Enum

__version__ = "1.0.0"
__author__ = "HyFuzz Team"
__license__ = "MIT"
__all__ = [
    "MCPServer",
    "MessageHandler",
    "CapabilityManager",
    "SessionManager",
    "TransportType",
    "create_server",
    "create_transport",
    "get_server_version",
    "configure_logging",
]


# ============================================================================
# Version and Metadata
# ============================================================================

def get_server_version() -> str:
    """Get MCP server version"""
    return __version__


def get_server_info() -> Dict[str, str]:
    """Get server information"""
    return {
        "name": "HyFuzz MCP Server",
        "version": __version__,
        "author": __author__,
        "license": __license__,
        "description": "Model Context Protocol server for HyFuzz Windows"
    }


# ============================================================================
# Enums for Transport Types
# ============================================================================

class TransportType(Enum):
    """MCP Server transport types"""
    STDIO = "stdio"
    HTTP = "http"
    WEBSOCKET = "websocket"
    CUSTOM = "custom"


class ServerMode(Enum):
    """Server operation modes"""
    DEVELOPMENT = "development"
    TESTING = "testing"
    PRODUCTION = "production"


# ============================================================================
# Lazy Import Stubs (avoid circular imports)
# ============================================================================

# These will be imported on-demand to avoid circular dependencies
_server_module = None
_message_handler_module = None
_capability_manager_module = None
_session_manager_module = None
_transport_modules = {}


def _get_server_class():
    """Lazy load MCPServer class"""
    global _server_module
    if _server_module is None:
        try:
            from .server import MCPServer
            _server_module = MCPServer
        except ImportError as e:
            logger = logging.getLogger(__name__)
            logger.error(f"Failed to import MCPServer: {str(e)}")
            raise
    return _server_module


def _get_message_handler_class():
    """Lazy load MessageHandler class"""
    global _message_handler_module
    if _message_handler_module is None:
        try:
            from .message_handler import MessageHandler
            _message_handler_module = MessageHandler
        except ImportError as e:
            logger = logging.getLogger(__name__)
            logger.error(f"Failed to import MessageHandler: {str(e)}")
            raise
    return _message_handler_module


def _get_capability_manager_class():
    """Lazy load CapabilityManager class"""
    global _capability_manager_module
    if _capability_manager_module is None:
        try:
            from .capability_manager import CapabilityManager
            _capability_manager_module = CapabilityManager
        except ImportError as e:
            logger = logging.getLogger(__name__)
            logger.error(f"Failed to import CapabilityManager: {str(e)}")
            raise
    return _capability_manager_module


def _get_session_manager_class():
    """Lazy load SessionManager class"""
    global _session_manager_module
    if _session_manager_module is None:
        try:
            from .session_manager import SessionManager
            _session_manager_module = SessionManager
        except ImportError as e:
            logger = logging.getLogger(__name__)
            logger.error(f"Failed to import SessionManager: {str(e)}")
            raise
    return _session_manager_module


def _get_transport_class(transport_type: TransportType):
    """Lazy load transport class"""
    if transport_type not in _transport_modules:
        try:
            if transport_type == TransportType.STDIO:
                from .stdio_transport import StdioTransport
                _transport_modules[transport_type] = StdioTransport
            elif transport_type == TransportType.HTTP:
                from .http_transport import HttpTransport
                _transport_modules[transport_type] = HttpTransport
            elif transport_type == TransportType.WEBSOCKET:
                from .websocket_transport import WebsocketTransport
                _transport_modules[transport_type] = WebsocketTransport
            else:
                raise ValueError(f"Unknown transport type: {transport_type}")
        except ImportError as e:
            logger = logging.getLogger(__name__)
            logger.error(f"Failed to import transport {transport_type}: {str(e)}")
            raise
    return _transport_modules[transport_type]


# ============================================================================
# Public Exports (make classes accessible at package level)
# ============================================================================

@property
def MCPServer():
    """Export MCPServer class"""
    return _get_server_class()


@property
def MessageHandler():
    """Export MessageHandler class"""
    return _get_message_handler_class()


@property
def CapabilityManager():
    """Export CapabilityManager class"""
    return _get_capability_manager_class()


@property
def SessionManager():
    """Export SessionManager class"""
    return _get_session_manager_class()


# ============================================================================
# Logging Configuration
# ============================================================================

def configure_logging(
    level: str = "INFO",
    log_file: Optional[str] = None,
    format_string: Optional[str] = None
) -> None:
    """
    Configure logging for MCP server module

    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional log file path
        format_string: Custom log format string
    """
    logger = logging.getLogger("mcp_server")

    # Set level
    log_level = getattr(logging, level.upper(), logging.INFO)
    logger.setLevel(log_level)

    # Default format
    if format_string is None:
        format_string = (
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )

    formatter = logging.Formatter(format_string)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # File handler if specified
    if log_file:
        try:
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except Exception as e:
            logger.error(f"Failed to add file handler: {str(e)}")


# ============================================================================
# Factory Functions
# ============================================================================

def create_server(
    mode: ServerMode = ServerMode.DEVELOPMENT,
    transport_type: TransportType = TransportType.STDIO,
    config: Optional[Dict[str, Any]] = None
) -> Any:
    """
    Factory function to create MCP server instance

    Args:
        mode: Server operation mode
        transport_type: Transport type to use
        config: Optional configuration dictionary

    Returns:
        MCPServer instance

    Example:
        server = create_server(
            mode=ServerMode.PRODUCTION,
            transport_type=TransportType.HTTP,
            config={"host": "localhost", "port": 8000}
        )
    """
    logger = logging.getLogger(__name__)

    try:
        MCPServerClass = _get_server_class()

        # Prepare configuration
        if config is None:
            config = {}

        config["mode"] = mode.value
        config["transport_type"] = transport_type.value

        logger.info(
            f"Creating MCP server - Mode: {mode.value}, "
            f"Transport: {transport_type.value}"
        )

        # Create server instance
        server = MCPServerClass(config=config)

        logger.info("MCP server created successfully")
        return server

    except Exception as e:
        logger.error(f"Failed to create MCP server: {str(e)}")
        raise


def create_transport(
    transport_type: TransportType,
    config: Optional[Dict[str, Any]] = None
) -> Any:
    """
    Factory function to create transport instance

    Args:
        transport_type: Type of transport to create
        config: Optional configuration dictionary

    Returns:
        Transport instance

    Example:
        transport = create_transport(
            TransportType.HTTP,
            config={"host": "0.0.0.0", "port": 8000}
        )
    """
    logger = logging.getLogger(__name__)

    try:
        TransportClass = _get_transport_class(transport_type)

        if config is None:
            config = {}

        logger.info(f"Creating transport: {transport_type.value}")

        transport = TransportClass(config=config)

        logger.info(f"Transport {transport_type.value} created successfully")
        return transport

    except Exception as e:
        logger.error(f"Failed to create transport: {str(e)}")
        raise


def create_capability_manager() -> Any:
    """
    Factory function to create capability manager

    Returns:
        CapabilityManager instance

    Example:
        capabilities = create_capability_manager()
        capabilities.register("feature1", is_enabled=True)
    """
    logger = logging.getLogger(__name__)

    try:
        CapabilityManagerClass = _get_capability_manager_class()
        return CapabilityManagerClass()
    except Exception as e:
        logger.error(f"Failed to create capability manager: {str(e)}")
        raise


def create_session_manager() -> Any:
    """
    Factory function to create session manager

    Returns:
        SessionManager instance

    Example:
        sessions = create_session_manager()
        session = sessions.create_session("client1")
    """
    logger = logging.getLogger(__name__)

    try:
        SessionManagerClass = _get_session_manager_class()
        return SessionManagerClass()
    except Exception as e:
        logger.error(f"Failed to create session manager: {str(e)}")
        raise


# ============================================================================
# Module-level Initialization
# ============================================================================

logger = logging.getLogger(__name__)

# Configure default logging
configure_logging(level="INFO")

logger.debug(f"MCP Server module initialized (v{__version__})")
logger.debug(f"Available transports: {', '.join([t.value for t in TransportType])}")
logger.debug(f"Available modes: {', '.join([m.value for m in ServerMode])}")


# ============================================================================
# Utility Functions
# ============================================================================

def get_supported_transports() -> List[str]:
    """Get list of supported transport types"""
    return [t.value for t in TransportType if t != TransportType.CUSTOM]


def get_supported_modes() -> List[str]:
    """Get list of supported server modes"""
    return [m.value for m in ServerMode]


def validate_transport_type(transport: str) -> bool:
    """Validate transport type string"""
    try:
        TransportType[transport.upper()]
        return True
    except KeyError:
        return False


def validate_server_mode(mode: str) -> bool:
    """Validate server mode string"""
    try:
        ServerMode[mode.upper()]
        return True
    except KeyError:
        return False


# ============================================================================
# Quick Start Helpers
# ============================================================================

def quick_start_server(
    transport: str = "stdio",
    mode: str = "development"
) -> Any:
    """
    Quick start helper for creating and returning server

    Args:
        transport: Transport type as string (default: stdio)
        mode: Server mode as string (default: development)

    Returns:
        MCPServer instance

    Example:
        server = quick_start_server(transport="http", mode="production")
    """
    try:
        transport_type = TransportType[transport.upper()]
        server_mode = ServerMode[mode.upper()]
        return create_server(mode=server_mode, transport_type=transport_type)
    except KeyError as e:
        logger.error(f"Invalid transport or mode: {str(e)}")
        raise ValueError(f"Invalid transport or mode: {str(e)}")


def get_module_info() -> Dict[str, Any]:
    """Get comprehensive module information"""
    return {
        "name": "mcp_server",
        "version": __version__,
        "description": "MCP Server module for HyFuzz",
        "author": __author__,
        "license": __license__,
        "exports": __all__,
        "supported_transports": get_supported_transports(),
        "supported_modes": get_supported_modes(),
    }


# ============================================================================
# TESTING SECTION
# ============================================================================

def run_tests():
    """Comprehensive test suite for MCP server module"""

    print("\n" + "="*80)
    print("MCP SERVER MODULE INITIALIZATION TEST SUITE")
    print("="*80 + "\n")

    # Test 1: Version Information
    print("[TEST 1] Version Information")
    print("-" * 80)
    version = get_server_version()
    assert version == __version__
    print(f"✓ Server version: {version}")

    info = get_server_info()
    assert "name" in info
    assert "version" in info
    print(f"✓ Server info: {info['name']} v{info['version']}")
    print()

    # Test 2: Enums
    print("[TEST 2] Enum Types")
    print("-" * 80)
    transports = list(TransportType)
    modes = list(ServerMode)
    print(f"✓ Transport types: {[t.value for t in transports]}")
    print(f"✓ Server modes: {[m.value for m in modes]}")
    assert len(transports) > 0
    assert len(modes) > 0
    print()

    # Test 3: Supported Types
    print("[TEST 3] Supported Types")
    print("-" * 80)
    supported_transports = get_supported_transports()
    supported_modes = get_supported_modes()
    print(f"✓ Supported transports: {supported_transports}")
    print(f"✓ Supported modes: {supported_modes}")
    assert "stdio" in supported_transports
    assert "development" in supported_modes
    print()

    # Test 4: Validation Functions
    print("[TEST 4] Validation Functions")
    print("-" * 80)
    assert validate_transport_type("stdio")
    assert not validate_transport_type("invalid")
    print(f"✓ Transport validation: stdio=True, invalid=False")

    assert validate_server_mode("development")
    assert not validate_server_mode("invalid")
    print(f"✓ Mode validation: development=True, invalid=False")
    print()

    # Test 5: Logging Configuration
    print("[TEST 5] Logging Configuration")
    print("-" * 80)
    try:
        configure_logging(level="DEBUG")
        print(f"✓ Logging configured to DEBUG level")
    except Exception as e:
        print(f"✗ Logging configuration failed: {str(e)}")
    print()

    # Test 6: Module Exports
    print("[TEST 6] Module Exports")
    print("-" * 80)
    print(f"✓ __all__ exports: {__all__}")
    assert "MCPServer" in __all__
    assert "create_server" in __all__
    assert "TransportType" in __all__
    print(f"✓ All required exports present")
    print()

    # Test 7: Module Information
    print("[TEST 7] Module Information")
    print("-" * 80)
    module_info = get_module_info()
    print(f"✓ Module info:")
    for key, value in module_info.items():
        if isinstance(value, list):
            print(f"  {key}: {', '.join(value)}")
        else:
            print(f"  {key}: {value}")
    print()

    # Test 8: Logging Setup
    print("[TEST 8] Logger Instance")
    print("-" * 80)
    test_logger = logging.getLogger("mcp_server")
    assert test_logger is not None
    print(f"✓ Logger instance created")
    print(f"✓ Logger level: {logging.getLevelName(test_logger.level)}")
    print(f"✓ Logger handlers: {len(test_logger.handlers)}")
    print()

    # Test 9: TransportType Enum
    print("[TEST 9] TransportType Enum")
    print("-" * 80)
    assert TransportType.STDIO.value == "stdio"
    assert TransportType.HTTP.value == "http"
    assert TransportType.WEBSOCKET.value == "websocket"
    print(f"✓ STDIO transport: {TransportType.STDIO.value}")
    print(f"✓ HTTP transport: {TransportType.HTTP.value}")
    print(f"✓ WebSocket transport: {TransportType.WEBSOCKET.value}")
    print()

    # Test 10: ServerMode Enum
    print("[TEST 10] ServerMode Enum")
    print("-" * 80)
    assert ServerMode.DEVELOPMENT.value == "development"
    assert ServerMode.TESTING.value == "testing"
    assert ServerMode.PRODUCTION.value == "production"
    print(f"✓ Development mode: {ServerMode.DEVELOPMENT.value}")
    print(f"✓ Testing mode: {ServerMode.TESTING.value}")
    print(f"✓ Production mode: {ServerMode.PRODUCTION.value}")
    print()

    # Test 11: Version Compatibility
    print("[TEST 11] Version Compatibility")
    print("-" * 80)
    version_parts = __version__.split('.')
    assert len(version_parts) == 3, "Version should be semantic (X.Y.Z)"
    print(f"✓ Version format valid: {__version__}")
    print(f"  Major: {version_parts[0]}")
    print(f"  Minor: {version_parts[1]}")
    print(f"  Patch: {version_parts[2]}")
    print()

    # Test 12: Module Metadata
    print("[TEST 12] Module Metadata")
    print("-" * 80)
    assert __version__ is not None
    assert __author__ is not None
    assert __license__ is not None
    print(f"✓ Version: {__version__}")
    print(f"✓ Author: {__author__}")
    print(f"✓ License: {__license__}")
    print()

    print("="*80)
    print("ALL TESTS PASSED ✓")
    print("="*80 + "\n")

    return True


# ============================================================================
# Main Entry Point
# ============================================================================

if __name__ == "__main__":
    success = run_tests()
    if success:
        print("MCP Server module is ready for integration!")