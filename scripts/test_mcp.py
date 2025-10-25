#!/usr/bin/env python3
"""
HyFuzz MCP Protocol Tester
Comprehensive test suite for MCP server protocol compliance, message handling,
transport layer validation, and client-server communication.

Features:
    - MCP protocol version validation
    - Message format validation (JSON-RPC 2.0)
    - Transport layer testing (stdio, HTTP, WebSocket simulation)
    - Capability negotiation testing
    - Session lifecycle testing
    - Error handling and edge case testing
    - Performance benchmarking
    - Protocol compliance reporting

Module Dependencies:
    - asyncio: Asynchronous operations
    - json: JSON message serialization
    - logging: Test logging
    - unittest: Test framework
    - typing: Type hints
    - dataclasses: Data model definitions
    - enum: Enumeration types
    - uuid: Unique identifier generation
"""

import asyncio
import json
import logging
import sys
import unittest
from dataclasses import dataclass, asdict, field
from enum import Enum
from typing import Dict, Any, List, Optional, Tuple
from uuid import uuid4
from datetime import datetime
from pathlib import Path


# ============================================================================
# MCP PROTOCOL MODELS AND CONSTANTS
# ============================================================================

class MCPVersion:
    """MCP Protocol Version Information."""

    MAJOR = 1
    MINOR = 0
    PATCH = 0

    @classmethod
    def version_string(cls) -> str:
        """Return version as semantic version string."""
        return f"{cls.MAJOR}.{cls.MINOR}.{cls.PATCH}"

    @classmethod
    def is_compatible(cls, version: str) -> bool:
        """Check if provided version is compatible."""
        try:
            parts = version.split(".")
            major = int(parts[0])
            return major == cls.MAJOR
        except (IndexError, ValueError):
            return False


class MessageType(Enum):
    """MCP Message Types (JSON-RPC 2.0)."""

    REQUEST = "request"
    RESPONSE = "response"
    NOTIFICATION = "notification"
    ERROR = "error"


class TransportType(Enum):
    """Supported MCP Transport Types."""

    STDIO = "stdio"
    HTTP = "http"
    WEBSOCKET = "websocket"


class CapabilityType(Enum):
    """Server Capability Types."""

    ANALYZE_PAYLOAD = "analyze_payload"
    GENERATE_PAYLOAD = "generate_payload"
    EXECUTE_PAYLOAD = "execute_payload"
    GET_CAPABILITIES = "get_capabilities"
    SET_CAPABILITY = "set_capability"
    HEALTH_CHECK = "health_check"
    LIST_RESOURCES = "list_resources"


@dataclass
class MCPMessage:
    """MCP Message Structure (JSON-RPC 2.0 compatible)."""

    jsonrpc: str = "2.0"
    method: Optional[str] = None
    params: Optional[Dict[str, Any]] = None
    result: Optional[Any] = None
    error: Optional[Dict[str, Any]] = None
    id: Optional[str] = field(default_factory=lambda: str(uuid4()))

    def to_dict(self) -> Dict[str, Any]:
        """Convert message to dictionary, excluding None values."""
        result = {"jsonrpc": self.jsonrpc}

        if self.id is not None:
            result["id"] = self.id

        if self.method is not None:
            result["method"] = self.method
        if self.params is not None:
            result["params"] = self.params
        if self.result is not None:
            result["result"] = self.result
        if self.error is not None:
            result["error"] = self.error

        return result

    def to_json(self) -> str:
        """Convert message to JSON string."""
        return json.dumps(self.to_dict())

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "MCPMessage":
        """Create MCPMessage from dictionary."""
        return MCPMessage(
            jsonrpc=data.get("jsonrpc", "2.0"),
            method=data.get("method"),
            params=data.get("params"),
            result=data.get("result"),
            error=data.get("error"),
            id=data.get("id"),
        )


@dataclass
class MCPCapability:
    """MCP Server Capability Description."""

    name: str
    type: CapabilityType
    version: str = "1.0.0"
    description: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert capability to dictionary."""
        return {
            "name": self.name,
            "type": self.type.value,
            "version": self.version,
            "description": self.description,
            "parameters": self.parameters,
        }


@dataclass
class MCPSession:
    """MCP Server Session Information."""

    session_id: str = field(default_factory=lambda: str(uuid4()))
    client_id: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)
    last_activity: datetime = field(default_factory=datetime.now)
    message_count: int = 0
    error_count: int = 0
    capabilities: List[str] = field(default_factory=list)
    transport: TransportType = TransportType.STDIO

    def to_dict(self) -> Dict[str, Any]:
        """Convert session to dictionary."""
        return {
            "session_id": self.session_id,
            "client_id": self.client_id,
            "created_at": self.created_at.isoformat(),
            "last_activity": self.last_activity.isoformat(),
            "message_count": self.message_count,
            "error_count": self.error_count,
            "capabilities": self.capabilities,
            "transport": self.transport.value,
        }


# ============================================================================
# MCP CLIENT SIMULATOR
# ============================================================================

class MCPClientSimulator:
    """Simulates MCP client for server testing."""

    def __init__(self, client_id: str = None, logger: logging.Logger = None):
        """
        Initialize MCP client simulator.

        Args:
            client_id: Unique client identifier
            logger: Logger instance
        """
        self.client_id = client_id or str(uuid4())
        self.logger = logger or self._setup_logger()
        self.message_id_counter = 0
        self.sent_messages: List[MCPMessage] = []
        self.received_messages: List[MCPMessage] = []
        self.pending_responses: Dict[str, asyncio.Future] = {}

    def _setup_logger(self) -> logging.Logger:
        """Setup internal logger."""
        logger = logging.getLogger(f"mcp-client-{self.client_id[:8]}")
        logger.setLevel(logging.DEBUG)
        return logger

    def _generate_message_id(self) -> str:
        """Generate unique message ID."""
        self.message_id_counter += 1
        return f"{self.client_id}:{self.message_id_counter}"

    async def send_request(
        self, method: str, params: Dict[str, Any] = None
    ) -> MCPMessage:
        """
        Send request and wait for response.

        Args:
            method: RPC method name
            params: Request parameters

        Returns:
            Response message
        """
        message_id = self._generate_message_id()
        request = MCPMessage(method=method, params=params or {}, id=message_id)

        self.sent_messages.append(request)
        self.logger.debug(f"Sending request: {method} (id={message_id})")

        # Simulate response reception
        await asyncio.sleep(0.01)

        response = MCPMessage(
            result={"status": "success", "method": method},
            id=message_id,
        )

        self.received_messages.append(response)
        self.logger.debug(f"Received response: id={message_id}")

        return response

    async def send_notification(self, method: str, params: Dict[str, Any] = None):
        """
        Send notification (no response expected).

        Args:
            method: Method name
            params: Notification parameters
        """
        notification = MCPMessage(
            method=method, params=params or {}, id=None
        )

        self.sent_messages.append(notification)
        self.logger.debug(f"Sending notification: {method}")

        await asyncio.sleep(0.01)

    async def initialize(self) -> Dict[str, Any]:
        """
        Initialize MCP session.

        Returns:
            Server capabilities and session info
        """
        response = await self.send_request(
            "initialize",
            {
                "protocolVersion": MCPVersion.version_string(),
                "capabilities": [],
                "clientInfo": {"name": "MCPTestClient", "version": "1.0.0"},
            },
        )
        return response.result

    async def get_capabilities(self) -> List[Dict[str, Any]]:
        """
        Request server capabilities.

        Returns:
            List of available capabilities
        """
        response = await self.send_request("get_capabilities")
        return response.result.get("capabilities", [])

    async def call_method(
        self, method: str, **kwargs
    ) -> Optional[Dict[str, Any]]:
        """
        Call arbitrary server method.

        Args:
            method: Method name
            **kwargs: Method parameters

        Returns:
            Method result or None
        """
        response = await self.send_request(method, kwargs)
        return response.result if response.result else None

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get client communication statistics.

        Returns:
            Statistics dictionary
        """
        return {
            "client_id": self.client_id,
            "messages_sent": len(self.sent_messages),
            "messages_received": len(self.received_messages),
            "pending_responses": len(self.pending_responses),
            "average_response_time": 0.01,
        }


# ============================================================================
# MCP SERVER SIMULATOR
# ============================================================================

class MCPServerSimulator:
    """Simulates MCP server for protocol testing."""

    def __init__(self, transport: TransportType = TransportType.STDIO):
        """
        Initialize MCP server simulator.

        Args:
            transport: Transport protocol type
        """
        self.transport = transport
        self.logger = self._setup_logger()
        self.sessions: Dict[str, MCPSession] = {}
        self.capabilities: List[MCPCapability] = self._initialize_capabilities()
        self.message_handlers: Dict[str, callable] = self._setup_handlers()
        self.is_running = False

    def _setup_logger(self) -> logging.Logger:
        """Setup internal logger."""
        logger = logging.getLogger(f"mcp-server-{self.transport.value}")
        logger.setLevel(logging.DEBUG)
        return logger

    def _initialize_capabilities(self) -> List[MCPCapability]:
        """Initialize server capabilities."""
        return [
            MCPCapability(
                name="analyze_payload",
                type=CapabilityType.ANALYZE_PAYLOAD,
                description="Analyze fuzzing payload",
                parameters={"payload": "string", "format": "string"},
            ),
            MCPCapability(
                name="generate_payload",
                type=CapabilityType.GENERATE_PAYLOAD,
                description="Generate fuzzing payload",
                parameters={"seed": "string", "count": "integer"},
            ),
            MCPCapability(
                name="execute_payload",
                type=CapabilityType.EXECUTE_PAYLOAD,
                description="Execute payload against target",
                parameters={"payload": "string", "target": "string"},
            ),
            MCPCapability(
                name="health_check",
                type=CapabilityType.HEALTH_CHECK,
                description="Server health status",
                parameters={},
            ),
            MCPCapability(
                name="get_capabilities",
                type=CapabilityType.GET_CAPABILITIES,
                description="List available capabilities",
                parameters={},
            ),
        ]

    def _setup_handlers(self) -> Dict[str, callable]:
        """Setup message handlers for different methods."""
        return {
            "initialize": self._handle_initialize,
            "get_capabilities": self._handle_get_capabilities,
            "analyze_payload": self._handle_analyze_payload,
            "generate_payload": self._handle_generate_payload,
            "execute_payload": self._handle_execute_payload,
            "health_check": self._handle_health_check,
        }

    async def _handle_initialize(self, session: MCPSession, params: Dict) -> Dict:
        """Handle initialize request."""
        session.capabilities = [cap.name for cap in self.capabilities]
        self.logger.info(f"Session {session.session_id} initialized")
        return {
            "protocolVersion": MCPVersion.version_string(),
            "capabilities": [cap.to_dict() for cap in self.capabilities],
            "serverInfo": {
                "name": "HyFuzz-MCP-Server",
                "version": "1.0.0",
            },
        }

    async def _handle_get_capabilities(self, session: MCPSession, params: Dict) -> Dict:
        """Handle get_capabilities request."""
        return {
            "capabilities": [cap.to_dict() for cap in self.capabilities]
        }

    async def _handle_analyze_payload(self, session: MCPSession, params: Dict) -> Dict:
        """Handle analyze_payload request."""
        await asyncio.sleep(0.01)
        return {
            "payload": params.get("payload"),
            "format": params.get("format", "binary"),
            "analysis": {
                "size": len(params.get("payload", "")),
                "entropy": 0.75,
                "pattern_detected": True,
            },
        }

    async def _handle_generate_payload(self, session: MCPSession, params: Dict) -> Dict:
        """Handle generate_payload request."""
        await asyncio.sleep(0.01)
        count = params.get("count", 1)
        return {
            "payloads": [f"payload_{i}" for i in range(count)],
            "count": count,
            "generated_at": datetime.now().isoformat(),
        }

    async def _handle_execute_payload(self, session: MCPSession, params: Dict) -> Dict:
        """Handle execute_payload request."""
        await asyncio.sleep(0.02)
        return {
            "payload": params.get("payload"),
            "target": params.get("target"),
            "execution_status": "success",
            "execution_time": 0.025,
            "result": {"crash_detected": False, "coverage": 0.85},
        }

    async def _handle_health_check(self, session: MCPSession, params: Dict) -> Dict:
        """Handle health_check request."""
        return {
            "status": "healthy",
            "uptime": 1000,
            "active_sessions": len(self.sessions),
            "timestamp": datetime.now().isoformat(),
        }

    async def start(self):
        """Start MCP server."""
        self.is_running = True
        self.logger.info(f"MCP Server started ({self.transport.value})")

    async def stop(self):
        """Stop MCP server."""
        self.is_running = False
        self.logger.info("MCP Server stopped")

    async def process_message(self, message_json: str) -> str:
        """
        Process incoming MCP message.

        Args:
            message_json: JSON message string

        Returns:
            JSON response string
        """
        try:
            data = json.loads(message_json)
            message = MCPMessage.from_dict(data)

            # Create or get session
            session_id = message.params.get("session_id") if message.params else None
            if session_id and session_id not in self.sessions:
                self.sessions[session_id] = MCPSession(
                    session_id=session_id, transport=self.transport
                )

            session = self.sessions.get(session_id) or MCPSession(
                transport=self.transport
            )

            # Update session activity
            session.message_count += 1
            session.last_activity = datetime.now()

            # Handle message
            if message.method in self.message_handlers:
                handler = self.message_handlers[message.method]
                result = await handler(session, message.params or {})

                response = MCPMessage(result=result, id=message.id)
            else:
                session.error_count += 1
                response = MCPMessage(
                    error={
                        "code": -32601,
                        "message": f"Method not found: {message.method}",
                    },
                    id=message.id,
                )

            return response.to_json()

        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON: {e}")
            error_response = MCPMessage(
                error={"code": -32700, "message": "Parse error"}
            )
            return error_response.to_json()
        except Exception as e:
            self.logger.error(f"Server error: {e}")
            error_response = MCPMessage(
                error={"code": -32603, "message": f"Internal error: {str(e)}"}
            )
            return error_response.to_json()


# ============================================================================
# MCP PROTOCOL VALIDATOR
# ============================================================================

class MCPProtocolValidator:
    """Validates MCP protocol compliance."""

    def __init__(self, logger: logging.Logger = None):
        self.logger = logger or logging.getLogger("mcp-validator")

    def validate_message_format(self, message: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Validate message JSON-RPC 2.0 format.

        Args:
            message: Message dictionary

        Returns:
            (is_valid, error_message) tuple
        """
        # Check jsonrpc version
        if message.get("jsonrpc") != "2.0":
            return False, "Invalid jsonrpc version"

        # Check for id in requests
        if message.get("method") and "id" not in message:
            return False, "Request must have id field"

        # Check for valid response structure
        if "result" in message and "error" in message:
            return False, "Message cannot have both result and error"

        return True, ""

    def validate_capabilities(self, capabilities: List[Dict]) -> Tuple[bool, str]:
        """
        Validate capability definitions.

        Args:
            capabilities: List of capability dictionaries

        Returns:
            (is_valid, error_message) tuple
        """
        required_fields = {"name", "type", "version"}

        for i, cap in enumerate(capabilities):
            if not isinstance(cap, dict):
                return False, f"Capability {i} is not a dictionary"

            missing = required_fields - set(cap.keys())
            if missing:
                return False, f"Capability {i} missing fields: {missing}"

        return True, ""

    def validate_session(self, session: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Validate session structure.

        Args:
            session: Session dictionary

        Returns:
            (is_valid, error_message) tuple
        """
        required_fields = {
            "session_id",
            "created_at",
            "last_activity",
            "message_count",
        }

        missing = required_fields - set(session.keys())
        if missing:
            return False, f"Session missing fields: {missing}"

        return True, ""


# ============================================================================
# COMPREHENSIVE TEST SUITE
# ============================================================================

class TestMCPProtocolStructure(unittest.TestCase):
    """Test MCP protocol structure and message format."""

    def test_mcp_version(self):
        """Test MCP version constants."""
        self.assertEqual(MCPVersion.MAJOR, 1)
        self.assertEqual(MCPVersion.MINOR, 0)
        self.assertTrue(MCPVersion.is_compatible("1.0.0"))
        self.assertFalse(MCPVersion.is_compatible("2.0.0"))

    def test_message_creation(self):
        """Test MCP message creation."""
        msg = MCPMessage(method="test", params={"key": "value"})
        self.assertEqual(msg.method, "test")
        self.assertIsNotNone(msg.id)

    def test_message_to_json(self):
        """Test message JSON serialization."""
        msg = MCPMessage(method="test", params={"key": "value"}, id="123")
        json_str = msg.to_json()
        data = json.loads(json_str)
        self.assertEqual(data["method"], "test")
        self.assertEqual(data["id"], "123")

    def test_capability_definition(self):
        """Test capability structure."""
        cap = MCPCapability(
            name="test_cap",
            type=CapabilityType.ANALYZE_PAYLOAD,
            description="Test capability",
        )
        cap_dict = cap.to_dict()
        self.assertEqual(cap_dict["name"], "test_cap")
        self.assertEqual(cap_dict["type"], "analyze_payload")

    def test_session_creation(self):
        """Test session creation."""
        session = MCPSession(transport=TransportType.HTTP)
        self.assertIsNotNone(session.session_id)
        self.assertEqual(session.message_count, 0)
        self.assertEqual(session.transport, TransportType.HTTP)


class TestMCPClientSimulator(unittest.IsolatedAsyncioTestCase):
    """Test MCP client simulator functionality."""

    async def asyncSetUp(self):
        self.client = MCPClientSimulator()

    async def test_client_initialization(self):
        """Test client initialization."""
        self.assertIsNotNone(self.client.client_id)
        self.assertEqual(len(self.client.sent_messages), 0)

    async def test_send_request(self):
        """Test sending request."""
        response = await self.client.send_request("test_method", {"param": "value"})
        self.assertIsNotNone(response)
        self.assertEqual(len(self.client.sent_messages), 1)

    async def test_send_notification(self):
        """Test sending notification."""
        await self.client.send_notification("notify_method", {"param": "value"})
        self.assertEqual(len(self.client.sent_messages), 1)

    async def test_initialize(self):
        """Test MCP initialization."""
        result = await self.client.initialize()
        self.assertIn("status", result)

    async def test_get_capabilities(self):
        """Test getting capabilities."""
        capabilities = await self.client.get_capabilities()
        self.assertIsInstance(capabilities, list)

    async def test_client_statistics(self):
        """Test client statistics collection."""
        await self.client.send_request("method1")
        await self.client.send_request("method2")
        stats = self.client.get_statistics()
        self.assertEqual(stats["messages_sent"], 2)


class TestMCPServerSimulator(unittest.IsolatedAsyncioTestCase):
    """Test MCP server simulator functionality."""

    async def asyncSetUp(self):
        self.server = MCPServerSimulator(TransportType.STDIO)
        await self.server.start()

    async def asyncTearDown(self):
        await self.server.stop()

    async def test_server_startup(self):
        """Test server startup."""
        self.assertTrue(self.server.is_running)
        self.assertGreater(len(self.server.capabilities), 0)

    async def test_capability_initialization(self):
        """Test capability initialization."""
        caps = self.server.capabilities
        cap_names = [cap.name for cap in caps]
        self.assertIn("analyze_payload", cap_names)
        self.assertIn("health_check", cap_names)

    async def test_initialize_message(self):
        """Test initialize message handling."""
        msg = MCPMessage(method="initialize", params={}, id="1")
        response_json = await self.server.process_message(msg.to_json())
        response_data = json.loads(response_json)
        self.assertIn("result", response_data)

    async def test_get_capabilities_message(self):
        """Test get_capabilities message."""
        msg = MCPMessage(method="get_capabilities", params={}, id="2")
        response_json = await self.server.process_message(msg.to_json())
        response_data = json.loads(response_json)
        self.assertIn("result", response_data)

    async def test_invalid_method_error(self):
        """Test error handling for invalid method."""
        msg = MCPMessage(method="invalid_method", params={}, id="3")
        response_json = await self.server.process_message(msg.to_json())
        response_data = json.loads(response_json)
        self.assertIn("error", response_data)

    async def test_malformed_json(self):
        """Test error handling for malformed JSON."""
        response_json = await self.server.process_message('{"invalid json"')
        response_data = json.loads(response_json)
        self.assertIn("error", response_data)


class TestProtocolValidator(unittest.TestCase):
    """Test MCP protocol validation."""

    def setUp(self):
        self.validator = MCPProtocolValidator()

    def test_valid_message_format(self):
        """Test valid message format validation."""
        msg = {"jsonrpc": "2.0", "method": "test", "id": "1"}
        valid, error = self.validator.validate_message_format(msg)
        self.assertTrue(valid)

    def test_invalid_jsonrpc_version(self):
        """Test invalid jsonrpc version."""
        msg = {"jsonrpc": "1.0", "method": "test", "id": "1"}
        valid, error = self.validator.validate_message_format(msg)
        self.assertFalse(valid)

    def test_valid_capabilities(self):
        """Test valid capabilities validation."""
        caps = [
            {
                "name": "cap1",
                "type": "analyze_payload",
                "version": "1.0.0",
            }
        ]
        valid, error = self.validator.validate_capabilities(caps)
        self.assertTrue(valid)

    def test_invalid_capabilities_missing_fields(self):
        """Test invalid capabilities with missing fields."""
        caps = [{"name": "cap1"}]
        valid, error = self.validator.validate_capabilities(caps)
        self.assertFalse(valid)


class TestClientServerIntegration(unittest.IsolatedAsyncioTestCase):
    """Test client-server interaction."""

    async def asyncSetUp(self):
        self.server = MCPServerSimulator(TransportType.STDIO)
        self.client = MCPClientSimulator()
        await self.server.start()

    async def asyncTearDown(self):
        await self.server.stop()

    async def test_full_workflow(self):
        """Test complete client-server workflow."""
        # Initialize
        init_result = await self.client.initialize()
        self.assertIsNotNone(init_result)

        # Get capabilities via server message processing
        caps_msg = MCPMessage(method="get_capabilities", params={}, id="1")
        caps_response_json = await self.server.process_message(caps_msg.to_json())
        caps_response = MCPMessage.from_dict(json.loads(caps_response_json))
        caps = caps_response.result.get("capabilities", [])
        self.assertGreater(len(caps), 0)

        # Execute analyze_payload method
        analyze_result = await self.client.call_method(
            "analyze_payload", payload="test_payload", format="binary"
        )
        self.assertIsNotNone(analyze_result)

    async def test_multiple_clients(self):
        """Test multiple concurrent clients."""
        clients = [MCPClientSimulator() for _ in range(3)]

        tasks = [client.initialize() for client in clients]
        results = await asyncio.gather(*tasks)

        self.assertEqual(len(results), 3)
        self.assertTrue(all(r is not None for r in results))

    async def test_concurrent_requests(self):
        """Test concurrent request handling."""
        client = MCPClientSimulator()

        tasks = [
            client.send_request(f"method_{i}", {"param": i})
            for i in range(10)
        ]
        results = await asyncio.gather(*tasks)

        self.assertEqual(len(results), 10)
        self.assertTrue(all(r.result is not None for r in results))


class TestTransportLayers(unittest.IsolatedAsyncioTestCase):
    """Test different transport layer implementations."""

    async def test_stdio_transport(self):
        """Test STDIO transport."""
        server = MCPServerSimulator(TransportType.STDIO)
        await server.start()
        self.assertEqual(server.transport, TransportType.STDIO)
        await server.stop()

    async def test_http_transport(self):
        """Test HTTP transport."""
        server = MCPServerSimulator(TransportType.HTTP)
        await server.start()
        self.assertEqual(server.transport, TransportType.HTTP)
        await server.stop()

    async def test_websocket_transport(self):
        """Test WebSocket transport."""
        server = MCPServerSimulator(TransportType.WEBSOCKET)
        await server.start()
        self.assertEqual(server.transport, TransportType.WEBSOCKET)
        await server.stop()


class TestProtocolCompliance(unittest.IsolatedAsyncioTestCase):
    """Test MCP protocol compliance."""

    async def asyncSetUp(self):
        self.server = MCPServerSimulator()
        await self.server.start()
        self.validator = MCPProtocolValidator()

    async def test_response_structure(self):
        """Test response follows JSON-RPC 2.0 structure."""
        msg = MCPMessage(method="health_check", params={}, id="1")
        response_json = await self.server.process_message(msg.to_json())
        response_data = json.loads(response_json)

        # Validate response structure
        valid, error = self.validator.validate_message_format(response_data)
        self.assertTrue(valid, f"Response validation failed: {error}")

    async def test_error_response_format(self):
        """Test error response follows JSON-RPC 2.0."""
        msg = MCPMessage(method="nonexistent", params={}, id="2")
        response_json = await self.server.process_message(msg.to_json())
        response_data = json.loads(response_json)

        self.assertIn("error", response_data)
        self.assertIn("code", response_data["error"])
        self.assertIn("message", response_data["error"])


# ============================================================================
# PERFORMANCE BENCHMARKING
# ============================================================================

class PerformanceBenchmark:
    """Performance benchmarking utilities."""

    def __init__(self, logger: logging.Logger = None):
        self.logger = logger or logging.getLogger("benchmark")

    async def benchmark_message_throughput(
        self, num_messages: int = 1000
    ) -> Dict[str, float]:
        """
        Benchmark message throughput.

        Args:
            num_messages: Number of messages to process

        Returns:
            Benchmark results dictionary
        """
        server = MCPServerSimulator()
        client = MCPClientSimulator()
        await server.start()

        start_time = datetime.now()

        for i in range(num_messages):
            await client.send_request("health_check")

        elapsed = (datetime.now() - start_time).total_seconds()
        throughput = num_messages / elapsed if elapsed > 0 else 0

        await server.stop()

        return {
            "num_messages": num_messages,
            "elapsed_seconds": elapsed,
            "throughput_msgs_per_sec": throughput,
        }

    async def benchmark_latency(
        self, num_samples: int = 100
    ) -> Dict[str, float]:
        """
        Benchmark message latency.

        Args:
            num_samples: Number of samples

        Returns:
            Latency statistics
        """
        server = MCPServerSimulator()
        client = MCPClientSimulator()
        await server.start()

        latencies = []

        for _ in range(num_samples):
            start = datetime.now()
            await client.send_request("health_check")
            latency = (datetime.now() - start).total_seconds() * 1000
            latencies.append(latency)

        await server.stop()

        return {
            "samples": num_samples,
            "min_latency_ms": min(latencies),
            "max_latency_ms": max(latencies),
            "avg_latency_ms": sum(latencies) / len(latencies),
        }


# ============================================================================
# TEST RUNNER AND REPORTING
# ============================================================================

def run_all_tests() -> bool:
    """
    Run complete MCP test suite.

    Returns:
        True if all tests passed, False otherwise
    """
    print("\n" + "=" * 80)
    print("MCP PROTOCOL TEST SUITE")
    print("=" * 80 + "\n")

    test_suite = unittest.TestSuite()

    # Add test classes
    test_classes = [
        TestMCPProtocolStructure,
        TestMCPClientSimulator,
        TestMCPServerSimulator,
        TestProtocolValidator,
        TestClientServerIntegration,
        TestTransportLayers,
        TestProtocolCompliance,
    ]

    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)

    # Run tests with verbose output
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)

    # Print summary
    print("\n" + "=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)
    print(f"Tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Overall: {'✓ PASSED' if result.wasSuccessful() else '✗ FAILED'}")
    print("=" * 80 + "\n")

    return result.wasSuccessful()


async def run_benchmarks():
    """Run performance benchmarks."""
    print("\n" + "=" * 80)
    print("PERFORMANCE BENCHMARKS")
    print("=" * 80 + "\n")

    benchmark = PerformanceBenchmark()

    # Throughput benchmark
    print("Running throughput benchmark (100 messages)...")
    throughput_result = await benchmark.benchmark_message_throughput(num_messages=100)
    print(f"  Throughput: {throughput_result['throughput_msgs_per_sec']:.2f} msg/sec")
    print(f"  Total time: {throughput_result['elapsed_seconds']:.3f}s\n")

    # Latency benchmark
    print("Running latency benchmark (50 samples)...")
    latency_result = await benchmark.benchmark_latency(num_samples=50)
    print(f"  Min latency: {latency_result['min_latency_ms']:.3f}ms")
    print(f"  Max latency: {latency_result['max_latency_ms']:.3f}ms")
    print(f"  Avg latency: {latency_result['avg_latency_ms']:.3f}ms\n")

    print("=" * 80 + "\n")


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    """Main entry point."""
    import sys

    # Setup logging
    logging.basicConfig(
        level=logging.WARNING,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Parse arguments
    run_benchmarks_flag = "--benchmark" in sys.argv

    # Run tests
    success = run_all_tests()

    # Run benchmarks if requested
    if run_benchmarks_flag:
        asyncio.run(run_benchmarks())

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())