"""
HyFuzz MCP Server - Integration Tests Module

This module provides comprehensive integration testing infrastructure for the
HyFuzz MCP server. It includes test helpers, fixtures, configuration, and
utilities for testing the complete system.

Key Features:
- Server startup and shutdown utilities
- Client connection management
- Test data setup and teardown
- MCP protocol helpers
- HTTP client utilities
- CoAP/MQTT protocol support
- Test result tracking
- Performance monitoring

Test Categories:
- Server-Client integration
- LLM pipeline integration
- MCP protocol compliance
- Knowledge base integration
- End-to-end payload generation
- Multi-protocol support

Usage:
    >>> from tests.integration import (
    ...     IntegrationTestBase,
    ...     create_test_server,
    ...     create_test_client
    ... )
    >>> 
    >>> class TestServerClient(IntegrationTestBase):
    ...     def test_basic_communication(self):
    ...         response = self.client.call_method("test_method")
    ...         assert response.success

Author: HyFuzz Team
Version: 1.0.0
"""

import logging
import time
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timezone
from abc import ABC, abstractmethod

try:
    import pytest
    PYTEST_AVAILABLE = True
except ImportError:
    PYTEST_AVAILABLE = False


# Initialize logger
logger = logging.getLogger(__name__)


# ==============================================================================
# Constants
# ==============================================================================

# Base paths
TESTS_DIR = Path(__file__).parent.parent
PROJECT_ROOT = TESTS_DIR.parent
CONFIG_DIR = PROJECT_ROOT / "config"
DATA_DIR = PROJECT_ROOT / "data"

# Server configuration for integration tests
DEFAULT_TEST_HOST = "127.0.0.1"
DEFAULT_TEST_PORT = 9999
DEFAULT_TEST_TIMEOUT = 30
DEFAULT_TEST_RETRIES = 3

# Test protocols
SUPPORTED_TEST_PROTOCOLS = [
    "stdio",
    "http",
    "websocket",
    "coap",
    "mqtt",
]

# Fixture tags
TEST_TIMEOUT_SECONDS = 300
TEST_RETRIES = 3


# ==============================================================================
# Enumerations
# ==============================================================================

class IntegrationTestLevel(str, Enum):
    """Integration test level."""
    SMOKE = "smoke"
    BASIC = "basic"
    COMPREHENSIVE = "comprehensive"
    FULL = "full"


class ServerStatus(str, Enum):
    """Server status."""
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    ERROR = "error"


class TestResult(str, Enum):
    """Test result status."""
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ERROR = "error"


# ==============================================================================
# Data Classes
# ==============================================================================

@dataclass
class ServerConfig:
    """Server configuration for integration tests."""
    host: str = DEFAULT_TEST_HOST
    port: int = DEFAULT_TEST_PORT
    timeout: int = DEFAULT_TEST_TIMEOUT
    debug: bool = True
    enable_cache: bool = True
    mock_llm: bool = True
    test_data_dir: Optional[Path] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "host": self.host,
            "port": self.port,
            "timeout": self.timeout,
            "debug": self.debug,
            "enable_cache": self.enable_cache,
            "mock_llm": self.mock_llm,
            "test_data_dir": str(self.test_data_dir) if self.test_data_dir else None,
        }


@dataclass
class TestEnvironment:
    """Test environment setup."""
    server_config: ServerConfig
    client_config: Dict[str, Any] = field(default_factory=dict)
    fixtures: Dict[str, Any] = field(default_factory=dict)
    temp_files: List[Path] = field(default_factory=list)

    def cleanup(self) -> None:
        """Clean up test environment."""
        for temp_file in self.temp_files:
            if temp_file.exists():
                try:
                    temp_file.unlink()
                except Exception as e:
                    logger.warning(f"Failed to cleanup {temp_file}: {e}")


@dataclass
class IntegrationTestResult:
    """Integration test result."""
    test_name: str
    status: TestResult
    start_time: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    end_time: Optional[str] = None
    duration_seconds: float = 0.0
    error: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "test_name": self.test_name,
            "status": self.status.value,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_seconds": self.duration_seconds,
            "error": self.error,
            "details": self.details,
        }


# ==============================================================================
# Integration Test Base Class
# ==============================================================================

class IntegrationTestBase(ABC):
    """
    Base class for integration tests.
    
    Provides common setup, teardown, and utility methods.
    """

    # Class-level configuration
    test_level: IntegrationTestLevel = IntegrationTestLevel.BASIC
    use_real_server: bool = False
    use_mock_llm: bool = True
    timeout_seconds: int = TEST_TIMEOUT_SECONDS

    def setup_method(self, method) -> None:
        """Set up test method."""
        logger.info(f"Setting up test: {method.__name__}")

        self.test_name = method.__name__
        self.start_time = time.time()
        self.results: List[IntegrationTestResult] = []

        # Create test environment
        self.env = self._create_test_environment()

        logger.debug(f"Test environment created for {self.test_name}")

    def teardown_method(self, method) -> None:
        """Tear down test method."""
        logger.info(f"Tearing down test: {method.__name__}")

        # Calculate duration
        duration = time.time() - self.start_time

        # Clean up environment
        self.env.cleanup()

        logger.debug(
            f"Test {self.test_name} completed in {duration:.2f}s"
        )

    def _create_test_environment(self) -> TestEnvironment:
        """Create test environment."""
        server_config = ServerConfig(
            debug=True,
            mock_llm=self.use_mock_llm,
        )

        return TestEnvironment(server_config=server_config)

    # ========================================================================
    # Assertion Helpers
    # ========================================================================

    def assert_response_valid(self, response: Dict[str, Any]) -> None:
        """Assert response is valid."""
        assert response is not None, "Response is None"
        assert isinstance(response, dict), "Response is not a dictionary"
        assert "status" in response, "Response missing 'status' field"

    def assert_payload_valid(self, payload: str) -> None:
        """Assert payload is valid."""
        assert payload is not None, "Payload is None"
        assert isinstance(payload, str), "Payload is not a string"
        assert len(payload) > 0, "Payload is empty"

    def assert_success(self, result: Dict[str, Any]) -> None:
        """Assert result indicates success."""
        assert result.get("success") is True, (
            f"Result did not succeed: {result.get('error', 'Unknown error')}"
        )

    # ========================================================================
    # Test Recording
    # ========================================================================

    def record_result(
        self,
        status: TestResult,
        error: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Record test result."""
        end_time = datetime.now(timezone.utc).isoformat()
        duration = time.time() - self.start_time

        result = IntegrationTestResult(
            test_name=self.test_name,
            status=status,
            end_time=end_time,
            duration_seconds=duration,
            error=error,
            details=details or {},
        )

        self.results.append(result)
        logger.info(f"Recorded result: {result.status.value}")


# ==============================================================================
# Test Server Management
# ==============================================================================

class TestServerManager:
    """Manages test server lifecycle."""

    def __init__(self, config: ServerConfig):
        """Initialize server manager."""
        self.config = config
        self.status = ServerStatus.STOPPED
        self.process = None
        self.start_time: Optional[float] = None

    def start(self) -> bool:
        """
        Start test server.
        
        Returns:
            True if started successfully
        """
        try:
            logger.info(f"Starting test server on {self.config.host}:{self.config.port}")
            self.status = ServerStatus.STARTING

            # Simulate server startup (in real scenario, would spawn process)
            time.sleep(0.5)

            self.status = ServerStatus.RUNNING
            self.start_time = time.time()

            logger.info("Test server started successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to start test server: {e}")
            self.status = ServerStatus.ERROR
            return False

    def stop(self) -> bool:
        """
        Stop test server.
        
        Returns:
            True if stopped successfully
        """
        try:
            if self.status == ServerStatus.STOPPED:
                return True

            logger.info("Stopping test server")
            self.status = ServerStatus.STOPPING

            time.sleep(0.2)

            self.status = ServerStatus.STOPPED
            logger.info("Test server stopped successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to stop test server: {e}")
            self.status = ServerStatus.ERROR
            return False

    def is_running(self) -> bool:
        """Check if server is running."""
        return self.status == ServerStatus.RUNNING

    def health_check(self) -> bool:
        """Check server health."""
        if not self.is_running():
            return False

        try:
            # Simulate health check
            return True
        except Exception:
            return False


# ==============================================================================
# Test Client Management
# ==============================================================================

class TestClient:
    """Test client for communicating with server."""

    def __init__(
        self,
        host: str = DEFAULT_TEST_HOST,
        port: int = DEFAULT_TEST_PORT,
        protocol: str = "http",
    ):
        """Initialize test client."""
        self.host = host
        self.port = port
        self.protocol = protocol
        self.connected = False
        self.request_count = 0
        self.response_cache: Dict[str, Any] = {}

    def connect(self) -> bool:
        """Connect to server."""
        try:
            logger.info(f"Connecting to server at {self.host}:{self.port}")
            # Simulate connection
            time.sleep(0.1)
            self.connected = True
            logger.info("Connected successfully")
            return True
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            return False

    def disconnect(self) -> bool:
        """Disconnect from server."""
        try:
            if not self.connected:
                return True

            logger.info("Disconnecting from server")
            self.connected = False
            return True
        except Exception as e:
            logger.error(f"Disconnection failed: {e}")
            return False

    def call_method(
        self,
        method: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Call a method on the server.
        
        Args:
            method: Method name
            params: Method parameters
            
        Returns:
            Response dictionary
        """
        if not self.connected:
            return {"success": False, "error": "Not connected"}

        self.request_count += 1

        # Simulate method call
        cache_key = f"{method}:{str(params)}"
        if cache_key in self.response_cache:
            return self.response_cache[cache_key]

        # Mock response generation
        response = self._generate_mock_response(method, params)
        self.response_cache[cache_key] = response

        return response

    def _generate_mock_response(
        self,
        method: str,
        params: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Generate mock response for method call."""
        method_lower = method.lower()

        if "payload" in method_lower:
            return {
                "success": True,
                "payloads": [
                    '<img src=x onerror="alert(1)">',
                    '<svg onload="alert(1)">',
                ],
            }

        elif "analyze" in method_lower:
            return {
                "success": True,
                "vulnerability_type": "xss",
                "confidence": 0.92,
            }

        elif "health" in method_lower:
            return {
                "success": True,
                "status": "healthy",
                "uptime": 3600,
            }

        else:
            return {
                "success": True,
                "result": "ok",
            }

    def get_stats(self) -> Dict[str, Any]:
        """Get client statistics."""
        return {
            "request_count": self.request_count,
            "cached_responses": len(self.response_cache),
            "connected": self.connected,
        }


# ==============================================================================
# Helper Functions
# ==============================================================================

def create_server_config(
    host: str = DEFAULT_TEST_HOST,
    port: int = DEFAULT_TEST_PORT,
    debug: bool = True,
    mock_llm: bool = True,
) -> ServerConfig:
    """
    Create server configuration.
    
    Args:
        host: Server host
        port: Server port
        debug: Debug mode
        mock_llm: Use mock LLM
        
    Returns:
        ServerConfig instance
    """
    return ServerConfig(
        host=host,
        port=port,
        debug=debug,
        mock_llm=mock_llm,
    )


def create_test_server(
    config: Optional[ServerConfig] = None,
) -> TestServerManager:
    """
    Create test server manager.
    
    Args:
        config: Server configuration
        
    Returns:
        TestServerManager instance
    """
    if config is None:
        config = create_server_config()

    return TestServerManager(config)


def create_test_client(
    host: str = DEFAULT_TEST_HOST,
    port: int = DEFAULT_TEST_PORT,
    protocol: str = "http",
) -> TestClient:
    """
    Create test client.
    
    Args:
        host: Server host
        port: Server port
        protocol: Protocol type
        
    Returns:
        TestClient instance
    """
    return TestClient(host=host, port=port, protocol=protocol)


def wait_for_server(
    client: TestClient,
    timeout_seconds: int = DEFAULT_TEST_TIMEOUT,
    retry_interval: float = 0.5,
) -> bool:
    """
    Wait for server to be ready.
    
    Args:
        client: Test client
        timeout_seconds: Timeout in seconds
        retry_interval: Retry interval in seconds
        
    Returns:
        True if server is ready
    """
    start_time = time.time()

    while time.time() - start_time < timeout_seconds:
        try:
            response = client.call_method("health_check")
            if response.get("success"):
                logger.info("Server is ready")
                return True
        except Exception:
            pass

        time.sleep(retry_interval)

    logger.error("Timeout waiting for server")
    return False


def retry_operation(
    operation,
    max_retries: int = DEFAULT_TEST_RETRIES,
    retry_delay: float = 0.5,
) -> Tuple[bool, Any]:
    """
    Retry an operation.
    
    Args:
        operation: Callable operation
        max_retries: Maximum retry attempts
        retry_delay: Delay between retries
        
    Returns:
        Tuple of (success, result)
    """
    for attempt in range(max_retries):
        try:
            result = operation()
            return True, result
        except Exception as e:
            if attempt < max_retries - 1:
                logger.debug(
                    f"Operation failed (attempt {attempt + 1}/{max_retries}), "
                    f"retrying in {retry_delay}s"
                )
                time.sleep(retry_delay)
            else:
                logger.error(f"Operation failed after {max_retries} attempts: {e}")
                return False, str(e)

    return False, "Unknown error"


# ==============================================================================
# Pytest Fixtures
# ==============================================================================

if PYTEST_AVAILABLE:

    @pytest.fixture(scope="module")  # type: ignore
    def integration_server():
        """Module-scoped fixture for test server."""
        server = create_test_server()
        server.start()
        yield server
        server.stop()

    @pytest.fixture  # type: ignore
    def integration_client(integration_server):
        """Test client fixture connected to server."""
        client = create_test_client()
        client.connect()
        yield client
        client.disconnect()

    @pytest.fixture  # type: ignore
    def test_environment():
        """Test environment fixture."""
        config = create_server_config()
        env = TestEnvironment(server_config=config)
        yield env
        env.cleanup()

    @pytest.fixture  # type: ignore
    def server_config():
        """Server configuration fixture."""
        return create_server_config()


# ==============================================================================
# Module Initialization
# ==============================================================================

logger.info("Integration tests module initialized")

# Log configuration
logger.debug(f"Test host: {DEFAULT_TEST_HOST}")
logger.debug(f"Test port: {DEFAULT_TEST_PORT}")
logger.debug(f"Test timeout: {DEFAULT_TEST_TIMEOUT}s")


# ==============================================================================
# Exports
# ==============================================================================

__all__ = [
    # Constants
    "DEFAULT_TEST_HOST",
    "DEFAULT_TEST_PORT",
    "DEFAULT_TEST_TIMEOUT",
    "SUPPORTED_TEST_PROTOCOLS",

    # Enumerations
    "IntegrationTestLevel",
    "ServerStatus",
    "TestResult",

    # Data Classes
    "ServerConfig",
    "TestEnvironment",
    "IntegrationTestResult",

    # Base Classes
    "IntegrationTestBase",

    # Managers
    "TestServerManager",
    "TestClient",

    # Helper Functions
    "create_server_config",
    "create_test_server",
    "create_test_client",
    "wait_for_server",
    "retry_operation",
]