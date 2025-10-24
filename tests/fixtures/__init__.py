"""
HyFuzz MCP Server - Test Fixtures Module

This module provides test fixtures, mock objects, and test data for the entire test suite.

Key Features:
- Mock LLM client and responses
- Mock MCP server components
- Test data factories for creating test objects
- Sample CWE/CVE data
- Sample payloads and vulnerabilities
- Fixture loaders for loading external test data
- Helper utilities for test setup and teardown

Structure:
    - mock_llm.py: Mock LLM client and responses
    - mock_models.py: Mock data models
    - mock_data.py: Sample test data
    - fixtures_loader.py: Fixture loading utilities

Usage:
    >>> from tests.fixtures import get_payload_factory
    >>> from tests.fixtures import get_sample_cwe_data
    >>>
    >>> # Create test payload
    >>> factory = get_payload_factory()
    >>> payload = factory.create_xss_payload(protocol="http")
    >>>
    >>> # Use mock LLM (async context)
    >>> from tests.fixtures import MockLLMClient
    >>> llm = MockLLMClient()
    >>> # response = await llm.generate("test prompt")  # In async function

Author: HyFuzz Team
Version: 1.0.0
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone

# Lazy imports for pytest fixtures
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

FIXTURES_DIR = Path(__file__).parent
PROJECT_ROOT = FIXTURES_DIR.parent.parent
DATA_DIR = FIXTURES_DIR / "data"
MOCK_RESPONSES_FILE = FIXTURES_DIR / "mock_responses.json"

# Supported test protocols
SUPPORTED_PROTOCOLS = [
    "http",
    "https",
    "coap",
    "mqtt",
    "grpc",
    "websocket",
    "modbus",
    "dns",
]

# Sample CWE IDs for testing
SAMPLE_CWE_IDS = [
    "CWE-79",   # Cross-site Scripting (XSS)
    "CWE-89",   # SQL Injection
    "CWE-94",   # Code Injection
    "CWE-78",   # Command Injection
    "CWE-22",   # Path Traversal
    "CWE-611",  # XML External Entity (XXE)
    "CWE-352",  # Cross-Site Request Forgery (CSRF)
    "CWE-502",  # Deserialization of Untrusted Data
]

# Sample CVE IDs for testing
SAMPLE_CVE_IDS = [
    "CVE-2021-3129",    # Laravel Framework
    "CVE-2021-21224",   # Chrome
    "CVE-2021-20091",   # Docker
    "CVE-2021-3156",    # Sudo
]


# ==============================================================================
# Test Data Classes
# ==============================================================================

@dataclass
class TestPayload:
    """Test payload data structure."""
    id: str
    protocol: str
    vulnerability_type: str
    payload: str
    description: str = ""
    cwe_id: Optional[str] = None
    cve_id: Optional[str] = None
    target_version: Optional[str] = None
    success_rate: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class TestTarget:
    """Test target information."""
    host: str
    port: int
    protocol: str
    service: Optional[str] = None
    version: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class TestSession:
    """Test MCP session."""
    session_id: str
    protocol_version: str
    client_name: str
    client_version: str
    capabilities: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class TestExecutionResult:
    """Test execution result."""
    status: str  # success, failure, error
    payload: str
    target: TestTarget
    output: str = ""
    error: Optional[str] = None
    response_code: Optional[int] = None
    response_time_ms: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


# ==============================================================================
# Factory Methods
# ==============================================================================

class PayloadFactory:
    """Factory for creating test payloads."""

    @staticmethod
    def create_xss_payload(
        protocol: str = "http",
        target: str = "localhost",
        payload_id: Optional[str] = None,
    ) -> TestPayload:
        """Create XSS test payload."""
        if payload_id is None:
            payload_id = f"xss_{protocol}_{id(target)}"

        payload_content = (
            '<img src=x onerror="alert(\'XSS\')">'
            if protocol in ["http", "https", "websocket"]
            else f"xss_payload_{protocol}"
        )

        return TestPayload(
            id=payload_id,
            protocol=protocol,
            vulnerability_type="xss",
            payload=payload_content,
            description=f"XSS payload for {protocol}://{target}",
            cwe_id="CWE-79",
            success_rate=0.75,
        )

    @staticmethod
    def create_sql_injection_payload(
        protocol: str = "http",
        target: str = "localhost",
        payload_id: Optional[str] = None,
    ) -> TestPayload:
        """Create SQL injection test payload."""
        if payload_id is None:
            payload_id = f"sqli_{protocol}_{id(target)}"

        payload_content = "' OR '1'='1"

        return TestPayload(
            id=payload_id,
            protocol=protocol,
            vulnerability_type="sql_injection",
            payload=payload_content,
            description=f"SQL injection payload for {protocol}://{target}",
            cwe_id="CWE-89",
            success_rate=0.82,
        )

    @staticmethod
    def create_command_injection_payload(
        protocol: str = "http",
        target: str = "localhost",
        payload_id: Optional[str] = None,
    ) -> TestPayload:
        """Create command injection test payload."""
        if payload_id is None:
            payload_id = f"cmdi_{protocol}_{id(target)}"

        payload_content = "; cat /etc/passwd #"

        return TestPayload(
            id=payload_id,
            protocol=protocol,
            vulnerability_type="command_injection",
            payload=payload_content,
            description=f"Command injection payload for {protocol}://{target}",
            cwe_id="CWE-78",
            success_rate=0.68,
        )

    @staticmethod
    def create_path_traversal_payload(
        protocol: str = "http",
        target: str = "localhost",
        payload_id: Optional[str] = None,
    ) -> TestPayload:
        """Create path traversal test payload."""
        if payload_id is None:
            payload_id = f"path_{protocol}_{id(target)}"

        payload_content = "../../../../etc/passwd"

        return TestPayload(
            id=payload_id,
            protocol=protocol,
            vulnerability_type="path_traversal",
            payload=payload_content,
            description=f"Path traversal payload for {protocol}://{target}",
            cwe_id="CWE-22",
            success_rate=0.72,
        )

    @staticmethod
    def create_xxe_payload(
        protocol: str = "http",
        target: str = "localhost",
        payload_id: Optional[str] = None,
    ) -> TestPayload:
        """Create XXE test payload."""
        if payload_id is None:
            payload_id = f"xxe_{protocol}_{id(target)}"

        payload_content = (
            '<?xml version="1.0"?>'
            '<!DOCTYPE foo ['
            '<!ENTITY xxe SYSTEM "file:///etc/passwd">'
            ']>'
            '<foo>&xxe;</foo>'
        )

        return TestPayload(
            id=payload_id,
            protocol=protocol,
            vulnerability_type="xxe",
            payload=payload_content,
            description=f"XXE payload for {protocol}://{target}",
            cwe_id="CWE-611",
            success_rate=0.65,
        )

    @staticmethod
    def create_custom_payload(
        payload_id: str,
        protocol: str,
        vulnerability_type: str,
        payload_content: str,
        cwe_id: Optional[str] = None,
        success_rate: float = 0.5,
        **kwargs,
    ) -> TestPayload:
        """Create custom test payload."""
        return TestPayload(
            id=payload_id,
            protocol=protocol,
            vulnerability_type=vulnerability_type,
            payload=payload_content,
            cwe_id=cwe_id,
            success_rate=success_rate,
            **kwargs,
        )


class TargetFactory:
    """Factory for creating test targets."""

    @staticmethod
    def create_http_target(
        host: str = "localhost",
        port: int = 8080,
        service: str = "apache",
        version: str = "2.4.41",
    ) -> TestTarget:
        """Create HTTP target."""
        return TestTarget(
            host=host,
            port=port,
            protocol="http",
            service=service,
            version=version,
        )

    @staticmethod
    def create_coap_target(
        host: str = "localhost",
        port: int = 5683,
        service: str = "libcoap",
        version: str = "4.2.1",
    ) -> TestTarget:
        """Create CoAP target."""
        return TestTarget(
            host=host,
            port=port,
            protocol="coap",
            service=service,
            version=version,
        )

    @staticmethod
    def create_mqtt_target(
        host: str = "localhost",
        port: int = 1883,
        service: str = "mosquitto",
        version: str = "2.0.8",
    ) -> TestTarget:
        """Create MQTT target."""
        return TestTarget(
            host=host,
            port=port,
            protocol="mqtt",
            service=service,
            version=version,
        )

    @staticmethod
    def create_custom_target(
        host: str,
        port: int,
        protocol: str,
        service: Optional[str] = None,
        version: Optional[str] = None,
        **metadata,
    ) -> TestTarget:
        """Create custom target."""
        return TestTarget(
            host=host,
            port=port,
            protocol=protocol,
            service=service,
            version=version,
            metadata=metadata,
        )


class SessionFactory:
    """Factory for creating test MCP sessions."""

    @staticmethod
    def create_test_session(
        session_id: Optional[str] = None,
        client_name: str = "test-client",
        client_version: str = "1.0.0",
        protocol_version: str = "2024.01",
    ) -> TestSession:
        """Create test MCP session."""
        if session_id is None:
            session_id = f"test_session_{id(client_name)}"

        return TestSession(
            session_id=session_id,
            protocol_version=protocol_version,
            client_name=client_name,
            client_version=client_version,
            capabilities={
                "payloads": True,
                "knowledge": True,
                "feedback": True,
                "streaming": True,
            },
        )


# ==============================================================================
# Sample Data
# ==============================================================================

def get_sample_cwe_data() -> Dict[str, Any]:
    """Get sample CWE data."""
    return {
        "CWE-79": {
            "id": "CWE-79",
            "name": "Improper Neutralization of Input During Web Page Generation",
            "description": "The software receives input from an upstream component...",
            "severity": "HIGH",
            "affected_protocols": ["http", "https", "websocket"],
            "remediation": "Sanitize and validate all user inputs...",
            "examples": [
                {
                    "code": '<img src=x onerror="alert(\'XSS\')">',
                    "description": "Basic XSS payload",
                    "success_rate": 0.85,
                }
            ],
        },
        "CWE-89": {
            "id": "CWE-89",
            "name": "SQL Injection",
            "description": "The software constructs a SQL command using externally-influenced input...",
            "severity": "CRITICAL",
            "affected_protocols": ["http", "https", "grpc"],
            "remediation": "Use prepared statements and parameterized queries...",
            "examples": [
                {
                    "code": "' OR '1'='1",
                    "description": "Classic SQL injection",
                    "success_rate": 0.90,
                }
            ],
        },
    }


def get_sample_cve_data() -> Dict[str, Any]:
    """Get sample CVE data."""
    return {
        "CVE-2021-3129": {
            "id": "CVE-2021-3129",
            "title": "Laravel Framework RCE",
            "description": "Laravel before 8.4.2 allows unauthenticated remote code execution...",
            "severity": "CRITICAL",
            "cvss_score": 9.8,
            "affected_versions": ["<8.4.2"],
            "cwe_ids": ["CWE-94"],
            "remediation": "Update to Laravel 8.4.2 or later",
        },
        "CVE-2021-21224": {
            "id": "CVE-2021-21224",
            "title": "Chrome V8 RCE",
            "description": "V8 in Google Chrome before 90.0.4430.93 allows remote code execution...",
            "severity": "HIGH",
            "cvss_score": 8.8,
            "affected_versions": ["<90.0.4430.93"],
            "cwe_ids": ["CWE-416"],
            "remediation": "Update Chrome to version 90.0.4430.93 or later",
        },
    }


def get_sample_payloads() -> List[TestPayload]:
    """Get sample payloads for testing."""
    factory = PayloadFactory()
    return [
        factory.create_xss_payload("http"),
        factory.create_sql_injection_payload("http"),
        factory.create_command_injection_payload("http"),
        factory.create_path_traversal_payload("http"),
        factory.create_xss_payload("coap"),
        factory.create_sql_injection_payload("mqtt"),
    ]


def get_sample_targets() -> List[TestTarget]:
    """Get sample targets for testing."""
    factory = TargetFactory()
    return [
        factory.create_http_target(),
        factory.create_coap_target(),
        factory.create_mqtt_target(),
    ]


# ==============================================================================
# Factory Getters
# ==============================================================================

def get_payload_factory() -> type:
    """
    Get payload factory class.

    Returns:
        PayloadFactory class
    """
    return PayloadFactory


def get_target_factory() -> type:
    """
    Get target factory class.

    Returns:
        TargetFactory class
    """
    return TargetFactory


def get_session_factory() -> type:
    """
    Get session factory class.

    Returns:
        SessionFactory class
    """
    return SessionFactory


# ==============================================================================
# Mock Objects
# ==============================================================================

class MockLLMClient:
    """Mock LLM client for testing."""

    def __init__(self, responses: Optional[Dict[str, str]] = None):
        """Initialize mock LLM client."""
        self.responses = responses or {}
        self.call_count = 0
        self.last_prompt = None
        self.call_history: List[Dict[str, Any]] = []

    def generate(self, prompt: str, **kwargs) -> str:
        """Generate mock response (synchronous version)."""
        self.call_count += 1
        self.last_prompt = prompt
        self.call_history.append({"prompt": prompt, "kwargs": kwargs})

        # Return predefined response if available
        for key in self.responses:
            if key.lower() in prompt.lower():
                return self.responses[key]

        # Return default response
        return f"Mock response for: {prompt[:50]}..."

    def generate_payloads(
        self,
        protocol: str,
        vulnerability_type: str,
        count: int = 5,
        **kwargs,
    ) -> List[str]:
        """Generate mock payloads (synchronous version)."""
        factory = PayloadFactory()

        if vulnerability_type == "xss":
            payloads = [
                factory.create_xss_payload(protocol, f"target_{i}").payload
                for i in range(count)
            ]
        elif vulnerability_type == "sql_injection":
            payloads = [
                factory.create_sql_injection_payload(protocol, f"target_{i}").payload
                for i in range(count)
            ]
        else:
            payloads = [f"payload_{i}" for i in range(count)]

        return payloads

    def reset(self) -> None:
        """Reset mock state."""
        self.call_count = 0
        self.last_prompt = None
        self.call_history = []


class MockMCPServer:
    """Mock MCP server for testing."""

    def __init__(self):
        """Initialize mock MCP server."""
        self.sessions: Dict[str, TestSession] = {}
        self.tools_called: List[Dict[str, Any]] = []
        self.resources_created: List[Dict[str, Any]] = []

    def initialize_session(
        self,
        protocol_version: str,
        client_info: Dict[str, Any],
    ) -> str:
        """Initialize mock session (synchronous version)."""
        session = SessionFactory.create_test_session(
            client_name=client_info.get("name", "unknown")
        )
        self.sessions[session.session_id] = session
        return session.session_id

    def call_tool(
        self,
        session_id: str,
        tool_name: str,
        arguments: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Call mock tool (synchronous version)."""
        self.tools_called.append(
            {"session_id": session_id, "tool_name": tool_name, "arguments": arguments}
        )

        return {
            "tool_name": tool_name,
            "status": "success",
            "result": f"Mock result for {tool_name}",
        }

    def generate_payloads(
        self,
        protocol: str,
        vulnerability_type: str,
        count: int = 5,
        **kwargs,
    ) -> List[str]:
        """Generate mock payloads (synchronous version)."""
        factory = PayloadFactory()

        if vulnerability_type == "xss":
            return [
                factory.create_xss_payload(protocol, f"target_{i}").payload
                for i in range(count)
            ]
        elif vulnerability_type == "sql_injection":
            return [
                factory.create_sql_injection_payload(protocol, f"target_{i}").payload
                for i in range(count)
            ]
        else:
            return [f"payload_{i}" for i in range(count)]

    def check_health(self) -> bool:
        """Check health (synchronous version)."""
        return True


# ==============================================================================
# Helper Functions
# ==============================================================================

def load_fixture_file(filename: str) -> Dict[str, Any]:
    """
    Load fixture data from file.

    Args:
        filename: Name of fixture file (with or without path)

    Returns:
        Loaded data dictionary

    Raises:
        FileNotFoundError: If fixture file not found
        ValueError: If file format not supported
    """
    filepath = FIXTURES_DIR / filename
    if not filepath.exists():
        filepath = DATA_DIR / filename

    if not filepath.exists():
        raise FileNotFoundError(f"Fixture file not found: {filename}")

    with open(filepath, "r", encoding="utf-8") as f:
        if filepath.suffix == ".json":
            return json.load(f)
        else:
            raise ValueError(f"Unsupported file format: {filepath.suffix}")


def create_temp_fixture_file(
    name: str,
    data: Dict[str, Any],
    directory: Optional[Path] = None,
) -> Path:
    """
    Create temporary fixture file.

    Args:
        name: File name
        data: Data to write
        directory: Target directory (default: temp dir)

    Returns:
        Path to created file

    Example:
        >>> temp_file = create_temp_fixture_file("test.json", {"key": "value"})
        >>> assert temp_file.exists()
    """
    if directory is None:
        directory = FIXTURES_DIR / ".temp"

    directory.mkdir(parents=True, exist_ok=True)
    filepath: Path = directory / name

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    return filepath


def cleanup_temp_fixtures(directory: Optional[Path] = None) -> None:
    """
    Clean up temporary fixture files.

    Args:
        directory: Directory to clean (default: temp dir)
    """
    if directory is None:
        directory = FIXTURES_DIR / ".temp"

    if directory.exists():
        import shutil
        try:
            shutil.rmtree(directory)
        except Exception as e:
            logger.warning(f"Failed to cleanup temp fixtures: {e}")


# ==============================================================================
# Pytest Fixtures (if pytest available)
# ==============================================================================

if PYTEST_AVAILABLE:

    @pytest.fixture  # type: ignore
    def payload_factory():
        """Pytest fixture for payload factory."""
        return PayloadFactory()

    @pytest.fixture  # type: ignore
    def target_factory():
        """Pytest fixture for target factory."""
        return TargetFactory()

    @pytest.fixture  # type: ignore
    def session_factory():
        """Pytest fixture for session factory."""
        return SessionFactory()

    @pytest.fixture  # type: ignore
    def mock_llm_client():
        """Pytest fixture for mock LLM client."""
        return MockLLMClient()

    @pytest.fixture  # type: ignore
    def mock_mcp_server():
        """Pytest fixture for mock MCP server."""
        return MockMCPServer()

    @pytest.fixture  # type: ignore
    def sample_payloads():
        """Pytest fixture for sample payloads."""
        return get_sample_payloads()

    @pytest.fixture  # type: ignore
    def sample_targets():
        """Pytest fixture for sample targets."""
        return get_sample_targets()

    @pytest.fixture  # type: ignore
    def sample_cwe_data():
        """Pytest fixture for sample CWE data."""
        return get_sample_cwe_data()

    @pytest.fixture  # type: ignore
    def sample_cve_data():
        """Pytest fixture for sample CVE data."""
        return get_sample_cve_data()


# ==============================================================================
# Exports
# ==============================================================================

__all__ = [
    # Constants
    "FIXTURES_DIR",
    "PROJECT_ROOT",
    "DATA_DIR",
    "SUPPORTED_PROTOCOLS",
    "SAMPLE_CWE_IDS",
    "SAMPLE_CVE_IDS",

    # Data Classes
    "TestPayload",
    "TestTarget",
    "TestSession",
    "TestExecutionResult",

    # Factories
    "PayloadFactory",
    "TargetFactory",
    "SessionFactory",

    # Factory Getters
    "get_payload_factory",
    "get_target_factory",
    "get_session_factory",

    # Mock Objects
    "MockLLMClient",
    "MockMCPServer",

    # Sample Data Functions
    "get_sample_cwe_data",
    "get_sample_cve_data",
    "get_sample_payloads",
    "get_sample_targets",

    # Helper Functions
    "load_fixture_file",
    "create_temp_fixture_file",
    "cleanup_temp_fixtures",
]