"""
HyFuzz MCP Server - Mock Models

This module provides mock implementations of Pydantic data models used throughout
the HyFuzz MCP server. These models are used for testing data validation,
serialization, and API contracts without requiring actual model validation.

Key Features:
- Mock message models (MCP protocol)
- Mock LLM models (requests/responses)
- Mock knowledge models (CWE/CVE)
- Mock payload models
- Mock configuration models
- Factory methods for creating test models
- Model validation utilities
- JSON serialization helpers

Usage:
    >>> from tests.fixtures.mock_models import (
    ...     MockPayloadRequest,
    ...     MockPayloadResponse,
    ...     create_mock_payload_request
    ... )
    >>>
    >>> # Create mock model
    >>> request = create_mock_payload_request(
    ...     cwe_id="CWE-79",
    ...     protocol="HTTP"
    ... )
    >>>
    >>> # Convert to dict
    >>> data = request.dict()

Author: HyFuzz Team
Version: 1.0.0
"""

from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
from datetime import datetime, timezone
import json


# ==============================================================================
# Enumerations
# ==============================================================================

class PayloadType(str, Enum):
    """Payload type enumeration."""
    XSS = "xss"
    SQL_INJECTION = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    XXE = "xxe"
    CSRF = "csrf"
    SSRF = "ssrf"
    LDAP_INJECTION = "ldap_injection"
    XML_BOMB = "xml_bomb"
    DESERIALIZATION = "deserialization"


class Severity(str, Enum):
    """Severity level enumeration."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class VulnerabilityStatus(str, Enum):
    """Vulnerability status enumeration."""
    UNVERIFIED = "unverified"
    VERIFIED = "verified"
    EXPLOITABLE = "exploitable"
    MITIGATED = "mitigated"
    PATCHED = "patched"


# ==============================================================================
# MCP Protocol Models
# ==============================================================================

@dataclass
class MockInitializeRequest:
    """Mock MCP initialize request."""
    protocol_version: str
    client_info: Dict[str, Any]
    capabilities: Dict[str, Any] = field(default_factory=dict)

    def dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)

    def json(self) -> str:
        """Convert to JSON."""
        return json.dumps(self.dict())


@dataclass
class MockInitializeResponse:
    """Mock MCP initialize response."""
    protocol_version: str
    server_info: Dict[str, Any]
    capabilities: Dict[str, Any] = field(default_factory=dict)

    def dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)

    def json(self) -> str:
        """Convert to JSON."""
        return json.dumps(self.dict())


@dataclass
class MockCallToolRequest:
    """Mock MCP call tool request."""
    name: str
    arguments: Dict[str, Any]

    def dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)

    def json(self) -> str:
        """Convert to JSON."""
        return json.dumps(self.dict())


@dataclass
class MockCallToolResponse:
    """Mock MCP call tool response."""
    tool_name: str
    success: bool
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

    def dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)

    def json(self) -> str:
        """Convert to JSON."""
        return json.dumps(self.dict())


# ==============================================================================
# Payload Models
# ==============================================================================

@dataclass
class MockPayloadRequest:
    """Mock payload generation request."""
    cwe_id: str
    protocol: str
    count: int = 1
    encoding: str = "none"
    target_version: Optional[str] = None
    target_service: Optional[str] = None
    context: Dict[str, Any] = field(default_factory=dict)

    def dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)

    def json(self) -> str:
        """Convert to JSON."""
        return json.dumps(self.dict())

    def validate(self) -> Tuple[bool, List[str]]:
        """Validate request."""
        errors: List[str] = []

        if not self.cwe_id:
            errors.append("cwe_id is required")
        elif not self.cwe_id.startswith("CWE-"):
            errors.append("cwe_id must start with 'CWE-'")

        if not self.protocol:
            errors.append("protocol is required")

        if self.count < 1:
            errors.append("count must be at least 1")

        if self.count > 100:
            errors.append("count must not exceed 100")

        return len(errors) == 0, errors


@dataclass
class MockPayload:
    """Mock payload data."""
    id: str
    content: str
    type: PayloadType
    protocol: str
    cwe_id: str
    encoding: str = "none"
    effectiveness: float = 0.5
    description: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        data = asdict(self)
        data["type"] = self.type.value
        return data

    def json(self) -> str:
        """Convert to JSON."""
        return json.dumps(self.dict())


@dataclass
class MockPayloadResponse:
    """Mock payload generation response."""
    success: bool
    payloads: List[MockPayload] = field(default_factory=list)
    reasoning_chain: List[str] = field(default_factory=list)
    confidence_score: float = 0.0
    execution_time_ms: float = 0.0
    error: Optional[str] = None

    def dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "success": self.success,
            "payloads": [p.dict() for p in self.payloads],
            "reasoning_chain": self.reasoning_chain,
            "confidence_score": self.confidence_score,
            "execution_time_ms": self.execution_time_ms,
            "error": self.error,
        }

    def json(self) -> str:
        """Convert to JSON."""
        return json.dumps(self.dict())


# ==============================================================================
# Vulnerability Models
# ==============================================================================

@dataclass
class MockCWEData:
    """Mock CWE data model."""
    id: str
    name: str
    description: str
    severity: Severity
    cvss_base_score: float
    affected_protocols: List[str] = field(default_factory=list)
    affected_technologies: List[str] = field(default_factory=list)
    common_consequences: List[str] = field(default_factory=list)
    remediation: List[str] = field(default_factory=list)
    examples: List[Dict[str, Any]] = field(default_factory=list)

    def dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        data = asdict(self)
        data["severity"] = self.severity.value
        return data

    def json(self) -> str:
        """Convert to JSON."""
        return json.dumps(self.dict())


@dataclass
class MockCVEData:
    """Mock CVE data model."""
    id: str
    title: str
    description: str
    severity: Severity
    cvss_v3_score: float
    affected_versions: List[str]
    cwe_ids: List[str] = field(default_factory=list)
    published_date: str = ""
    remediation: str = ""
    affected_component: str = ""

    def dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        data = asdict(self)
        data["severity"] = self.severity.value
        return data

    def json(self) -> str:
        """Convert to JSON."""
        return json.dumps(self.dict())


@dataclass
class MockVulnerabilityAnalysis:
    """Mock vulnerability analysis result."""
    vulnerability_type: PayloadType
    target_url: str
    parameter: str
    status: VulnerabilityStatus = VulnerabilityStatus.UNVERIFIED
    confidence: float = 0.0
    payload_tested: str = ""
    response_code: Optional[int] = None
    response_body: str = ""
    evidence: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)

    def dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        data = asdict(self)
        data["vulnerability_type"] = self.vulnerability_type.value
        data["status"] = self.status.value
        return data

    def json(self) -> str:
        """Convert to JSON."""
        return json.dumps(self.dict())


# ==============================================================================
# LLM Models
# ==============================================================================

@dataclass
class MockLLMConfig:
    """Mock LLM configuration."""
    model: str
    temperature: float = 0.7
    max_tokens: int = 2048
    timeout_seconds: int = 30
    api_endpoint: str = "http://localhost:11434"
    enabled: bool = True

    def dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class MockCoTStep:
    """Mock Chain-of-Thought reasoning step."""
    step_number: int
    description: str
    reasoning: str
    confidence: float = 0.5

    def dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class MockCoTReasoning:
    """Mock Chain-of-Thought reasoning."""
    vulnerability_type: PayloadType
    steps: List[MockCoTStep] = field(default_factory=list)
    generated_payloads: List[str] = field(default_factory=list)
    overall_confidence: float = 0.0
    execution_time_ms: float = 0.0

    def dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        data = asdict(self)
        data["vulnerability_type"] = self.vulnerability_type.value
        return data

    def json(self) -> str:
        """Convert to JSON."""
        return json.dumps(self.dict())


# ==============================================================================
# Configuration Models
# ==============================================================================

@dataclass
class MockServerConfig:
    """Mock server configuration."""
    host: str = "127.0.0.1"
    port: int = 8000
    debug: bool = False
    workers: int = 1
    timeout: int = 30
    reload: bool = False

    def dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class MockKnowledgeConfig:
    """Mock knowledge base configuration."""
    data_dir: str = "data/"
    cache_enabled: bool = True
    cache_ttl: int = 3600
    auto_update: bool = False
    update_interval: int = 86400

    def dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class MockSessionConfig:
    """Mock session configuration."""
    max_sessions: int = 100
    session_timeout: int = 1800
    cleanup_interval: int = 300
    storage_type: str = "memory"

    def dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


# ==============================================================================
# Common Models
# ==============================================================================

@dataclass
class MockTarget:
    """Mock target information."""
    host: str
    port: int
    protocol: str
    service: Optional[str] = None
    version: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class MockSession:
    """Mock session information."""
    session_id: str
    client_name: str
    client_version: str
    protocol_version: str
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    last_activity: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    capabilities: Dict[str, Any] = field(default_factory=dict)

    def dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class MockExecutionResult:
    """Mock execution result."""
    status: str  # success, failure, error
    payload: str
    target: MockTarget
    output: str = ""
    error: Optional[str] = None
    response_code: Optional[int] = None
    response_time_ms: float = 0.0
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        data = asdict(self)
        data["target"] = self.target.dict()
        return data


# ==============================================================================
# Factory Methods
# ==============================================================================

def create_mock_payload_request(
        cwe_id: str = "CWE-79",
        protocol: str = "HTTP",
        count: int = 1,
        encoding: str = "none",
        target_version: Optional[str] = None,
) -> MockPayloadRequest:
    """
    Create mock payload request.

    Args:
        cwe_id: CWE identifier
        protocol: Target protocol
        count: Number of payloads
        encoding: Encoding type
        target_version: Target version

    Returns:
        MockPayloadRequest instance
    """
    return MockPayloadRequest(
        cwe_id=cwe_id,
        protocol=protocol,
        count=count,
        encoding=encoding,
        target_version=target_version,
    )


def create_mock_payload(
        payload_id: str = "payload_1",
        content: str = '<img src=x onerror="alert(1)">',
        payload_type: PayloadType = PayloadType.XSS,
        protocol: str = "HTTP",
        cwe_id: str = "CWE-79",
        effectiveness: float = 0.85,
) -> MockPayload:
    """
    Create mock payload.

    Args:
        payload_id: Payload ID
        content: Payload content
        payload_type: Payload type
        protocol: Target protocol
        cwe_id: CWE ID
        effectiveness: Effectiveness score

    Returns:
        MockPayload instance
    """
    return MockPayload(
        id=payload_id,
        content=content,
        type=payload_type,
        protocol=protocol,
        cwe_id=cwe_id,
        effectiveness=effectiveness,
    )


def create_mock_payload_response(
        success: bool = True,
        payloads: Optional[List[MockPayload]] = None,
        confidence_score: float = 0.85,
        execution_time_ms: float = 150.0,
) -> MockPayloadResponse:
    """
    Create mock payload response.

    Args:
        success: Success status
        payloads: List of payloads
        confidence_score: Confidence score
        execution_time_ms: Execution time in milliseconds

    Returns:
        MockPayloadResponse instance
    """
    if payloads is None:
        payloads = [
            create_mock_payload(f"payload_{i}")
            for i in range(1, 4)
        ]

    return MockPayloadResponse(
        success=success,
        payloads=payloads,
        confidence_score=confidence_score,
        execution_time_ms=execution_time_ms,
        reasoning_chain=[
            "Step 1: Analyze CWE",
            "Step 2: Identify attack vectors",
            "Step 3: Generate payloads",
        ],
    )


def create_mock_cwe_data(
        cwe_id: str = "CWE-79",
        name: str = "Cross-site Scripting",
        severity: Severity = Severity.MEDIUM,
        cvss_score: float = 6.1,
) -> MockCWEData:
    """
    Create mock CWE data.

    Args:
        cwe_id: CWE ID
        name: CWE name
        severity: Severity level
        cvss_score: CVSS score

    Returns:
        MockCWEData instance
    """
    return MockCWEData(
        id=cwe_id,
        name=name,
        description=f"Description for {cwe_id}",
        severity=severity,
        cvss_base_score=cvss_score,
        affected_protocols=["HTTP", "HTTPS"],
        affected_technologies=["Web Applications"],
        remediation=["Sanitize input"],
    )


def create_mock_cve_data(
        cve_id: str = "CVE-2021-3129",
        title: str = "Test CVE",
        severity: Severity = Severity.CRITICAL,
        cvss_score: float = 9.8,
) -> MockCVEData:
    """
    Create mock CVE data.

    Args:
        cve_id: CVE ID
        title: CVE title
        severity: Severity level
        cvss_score: CVSS score

    Returns:
        MockCVEData instance
    """
    return MockCVEData(
        id=cve_id,
        title=title,
        description=f"Description for {cve_id}",
        severity=severity,
        cvss_v3_score=cvss_score,
        affected_versions=["<1.0.0"],
        cwe_ids=["CWE-79"],
    )


def create_mock_cot_reasoning(
        vulnerability_type: PayloadType = PayloadType.XSS,
        num_steps: int = 5,
) -> MockCoTReasoning:
    """
    Create mock CoT reasoning.

    Args:
        vulnerability_type: Vulnerability type
        num_steps: Number of reasoning steps

    Returns:
        MockCoTReasoning instance
    """
    steps = [
        MockCoTStep(
            step_number=i + 1,
            description=f"Step {i + 1}",
            reasoning=f"Reasoning for step {i + 1}",
            confidence=0.7 + (i * 0.05),
        )
        for i in range(num_steps)
    ]

    return MockCoTReasoning(
        vulnerability_type=vulnerability_type,
        steps=steps,
        generated_payloads=[
            '<img src=x onerror="alert(1)">',
            '<svg onload="alert(1)">',
        ],
        overall_confidence=0.92,
        execution_time_ms=245.0,
    )


def create_mock_target(
        host: str = "localhost",
        port: int = 8080,
        protocol: str = "http",
        service: str = "apache",
        version: str = "2.4.41",
) -> MockTarget:
    """
    Create mock target.

    Args:
        host: Target host
        port: Target port
        protocol: Protocol type
        service: Service name
        version: Service version

    Returns:
        MockTarget instance
    """
    return MockTarget(
        host=host,
        port=port,
        protocol=protocol,
        service=service,
        version=version,
    )


def create_mock_session(
        session_id: str = "session_123",
        client_name: str = "test-client",
        client_version: str = "1.0.0",
        protocol_version: str = "2024.01",
) -> MockSession:
    """
    Create mock session.

    Args:
        session_id: Session ID
        client_name: Client name
        client_version: Client version
        protocol_version: Protocol version

    Returns:
        MockSession instance
    """
    return MockSession(
        session_id=session_id,
        client_name=client_name,
        client_version=client_version,
        protocol_version=protocol_version,
        capabilities={
            "payloads": True,
            "knowledge": True,
            "feedback": True,
        },
    )


def create_mock_execution_result(
        status: str = "success",
        payload: str = '<img src=x onerror="alert(1)">',
        response_code: int = 200,
) -> MockExecutionResult:
    """
    Create mock execution result.

    Args:
        status: Execution status
        payload: Test payload
        response_code: Response code

    Returns:
        MockExecutionResult instance
    """
    return MockExecutionResult(
        status=status,
        payload=payload,
        target=create_mock_target(),
        output="Execution output",
        response_code=response_code,
        response_time_ms=156.0,
    )


# ==============================================================================
# Validation Utilities
# ==============================================================================

def validate_payload_request(
        request: MockPayloadRequest,
) -> Tuple[bool, List[str]]:
    """
    Validate payload request.

    Args:
        request: Payload request to validate

    Returns:
        Tuple of (is_valid, errors)
    """
    return request.validate()


def validate_payload(payload: MockPayload) -> Tuple[bool, List[str]]:
    """
    Validate payload.

    Args:
        payload: Payload to validate

    Returns:
        Tuple of (is_valid, errors)
    """
    errors: List[str] = []

    if not payload.id:
        errors.append("Payload ID is required")

    if not payload.content:
        errors.append("Payload content is required")

    if not (0 <= payload.effectiveness <= 1):
        errors.append("Effectiveness must be between 0 and 1")

    return len(errors) == 0, errors


# ==============================================================================
# Exports
# ==============================================================================

__all__ = [
    # Enumerations
    "PayloadType",
    "Severity",
    "VulnerabilityStatus",

    # MCP Models
    "MockInitializeRequest",
    "MockInitializeResponse",
    "MockCallToolRequest",
    "MockCallToolResponse",

    # Payload Models
    "MockPayloadRequest",
    "MockPayload",
    "MockPayloadResponse",

    # Vulnerability Models
    "MockCWEData",
    "MockCVEData",
    "MockVulnerabilityAnalysis",

    # LLM Models
    "MockLLMConfig",
    "MockCoTStep",
    "MockCoTReasoning",

    # Configuration Models
    "MockServerConfig",
    "MockKnowledgeConfig",
    "MockSessionConfig",

    # Common Models
    "MockTarget",
    "MockSession",
    "MockExecutionResult",

    # Factory Functions
    "create_mock_payload_request",
    "create_mock_payload",
    "create_mock_payload_response",
    "create_mock_cwe_data",
    "create_mock_cve_data",
    "create_mock_cot_reasoning",
    "create_mock_target",
    "create_mock_session",
    "create_mock_execution_result",

    # Validation Functions
    "validate_payload_request",
    "validate_payload",
]