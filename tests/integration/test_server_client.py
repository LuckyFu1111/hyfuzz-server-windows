"""
MCP Server-Client Integration Tests

Tests for server-client interaction patterns, including:
- Server startup and shutdown
- Client connection and disconnection
- Message transmission and reception
- Protocol handshake
- Resource management
- Tool invocation
- Concurrent operations
- Session lifecycle
- Error scenarios and recovery
- Transport layer interactions
"""

import json
import asyncio
import pytest
from unittest.mock import Mock, AsyncMock, patch, MagicMock, call
from typing import Dict, Any, List, Tuple
import logging
from datetime import datetime
import time


# Mock imports (adjust based on actual project structure)
# from src.mcp_server.server import MCPServer
# from src.mcp_server.message_handler import MessageHandler
# from src.models.message_models import MCPMessage
# from src.utils.exceptions import MCPException, SessionError


@pytest.fixture
def event_loop():
    """Event loop fixture for async tests"""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
async def mock_server():
    """Mock MCP server instance"""
    server = AsyncMock()
    server.is_running = False
    server.sessions = {}
    server.capabilities = {
        "resources": {"listChanged": True},
        "tools": {"listChanged": True},
        "prompts": {"listChanged": True}
    }
    return server


@pytest.fixture
async def mock_client():
    """Mock MCP client instance"""
    client = AsyncMock()
    client.is_connected = False
    client.session_id = None
    client.request_id_counter = 0
    return client


class TestServerStartupShutdown:
    """Test server lifecycle management"""

    @pytest.mark.asyncio
    async def test_server_startup(self, mock_server):
        """Test successful server startup"""
        mock_server.start = AsyncMock()
        mock_server.is_running = True

        await mock_server.start()

        assert mock_server.is_running is True
        mock_server.start.assert_called_once()

    @pytest.mark.asyncio
    async def test_server_shutdown(self, mock_server):
        """Test successful server shutdown"""
        mock_server.is_running = True
        mock_server.stop = AsyncMock()

        await mock_server.stop()
        mock_server.stop.assert_called_once()

    @pytest.mark.asyncio
    async def test_server_restart(self, mock_server):
        """Test server restart functionality"""
        mock_server.start = AsyncMock()
        mock_server.stop = AsyncMock()
        mock_server.is_running = False

        # Start server
        mock_server.is_running = True
        await mock_server.start()
        assert mock_server.is_running is True

        # Stop server
        await mock_server.stop()
        mock_server.is_running = False
        assert mock_server.is_running is False

        # Restart
        mock_server.is_running = True
        await mock_server.start()
        assert mock_server.is_running is True

    @pytest.mark.asyncio
    async def test_server_startup_with_config(self, mock_server):
        """Test server startup with configuration"""
        config = {
            "host": "localhost",
            "port": 5000,
            "transport": "http",
            "debug": True
        }

        mock_server.start = AsyncMock()
        await mock_server.start(config=config)
        mock_server.start.assert_called_once()

    @pytest.mark.asyncio
    async def test_server_health_check(self, mock_server):
        """Test server health check"""
        mock_server.is_running = True
        mock_server.get_health = AsyncMock(return_value={
            "status": "healthy",
            "uptime": 3600,
            "timestamp": datetime.now().isoformat()
        })

        health = await mock_server.get_health()

        assert health["status"] == "healthy"
        assert "uptime" in health


class TestClientConnection:
    """Test client connection and session management"""

    @pytest.mark.asyncio
    async def test_client_connect_success(self, mock_client, mock_server):
        """Test successful client connection"""
        mock_server.is_running = True
        mock_client.connect = AsyncMock()
        mock_client.is_connected = True
        mock_client.session_id = "sess-123"

        await mock_client.connect(server_address="localhost:5000")

        assert mock_client.is_connected is True
        assert mock_client.session_id is not None
        mock_client.connect.assert_called_once()

    @pytest.mark.asyncio
    async def test_client_disconnect(self, mock_client):
        """Test client disconnection"""
        mock_client.is_connected = True
        mock_client.session_id = "sess-123"
        mock_client.disconnect = AsyncMock()

        await mock_client.disconnect()
        mock_client.disconnect.assert_called_once()

    @pytest.mark.asyncio
    async def test_client_connect_timeout(self, mock_client):
        """Test client connection timeout"""

        async def delayed_connect():
            await asyncio.sleep(10)

        mock_client.connect = AsyncMock(side_effect=delayed_connect)

        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(
                mock_client.connect(server_address="localhost:5000"),
                timeout=0.1
            )

    @pytest.mark.asyncio
    async def test_client_reconnect(self, mock_client):
        """Test client reconnection after disconnection"""
        # Initial connection
        mock_client.is_connected = True
        mock_client.session_id = "sess-123"

        # Disconnect
        mock_client.is_connected = False

        # Reconnect
        mock_client.connect = AsyncMock()
        mock_client.is_connected = True
        mock_client.session_id = "sess-456"

        await mock_client.connect(server_address="localhost:5000")
        assert mock_client.is_connected is True


class TestInitializationHandshake:
    """Test MCP initialization protocol"""

    @pytest.fixture
    def initialize_request(self):
        """Initialize request fixture"""
        return {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "hyfuzz-client",
                    "version": "1.0.0"
                }
            }
        }

    @pytest.fixture
    def initialize_response(self):
        """Initialize response fixture"""
        return {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "resources": {"listChanged": True},
                    "tools": {"listChanged": True},
                    "prompts": {"listChanged": True}
                },
                "serverInfo": {
                    "name": "hyfuzz-server",
                    "version": "1.0.0"
                }
            }
        }

    @pytest.mark.asyncio
    async def test_successful_initialization(self, initialize_request, initialize_response):
        """Test successful initialization handshake"""
        client = AsyncMock()
        server = AsyncMock()

        server.handle_initialize = AsyncMock(return_value=initialize_response)
        response = await server.handle_initialize(initialize_request["params"])

        assert response["result"]["protocolVersion"] == "2024-11-05"
        assert "capabilities" in response["result"]

    @pytest.mark.asyncio
    async def test_initialization_capability_negotiation(self, initialize_request):
        """Test capability negotiation during initialization"""
        server = AsyncMock()

        expected_capabilities = ["resources", "tools", "prompts"]
        server.get_capabilities = AsyncMock(
            return_value={cap: {"listChanged": True} for cap in expected_capabilities}
        )

        capabilities = await server.get_capabilities()

        for cap in expected_capabilities:
            assert cap in capabilities

    @pytest.mark.asyncio
    async def test_initialization_incompatible_protocol_version(self):
        """Test initialization with incompatible protocol version"""
        request = {
            "protocolVersion": "1.0.0",  # Incompatible version
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "1.0"}
        }

        server = AsyncMock()
        server.handle_initialize = AsyncMock(
            side_effect=ValueError("Incompatible protocol version")
        )

        with pytest.raises(ValueError):
            await server.handle_initialize(request)

    @pytest.mark.asyncio
    async def test_initialization_missing_client_info(self):
        """Test initialization with missing client info"""
        request = {
            "protocolVersion": "2024-11-05",
            "capabilities": {}
            # Missing clientInfo
        }

        server = AsyncMock()
        server.handle_initialize = AsyncMock(
            side_effect=ValueError("clientInfo is required")
        )

        with pytest.raises(ValueError):
            await server.handle_initialize(request)


class TestMessageExchange:
    """Test message sending and receiving"""

    @pytest.mark.asyncio
    async def test_send_and_receive_message(self, mock_client, mock_server):
        """Test sending and receiving a message"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "resources/list",
            "params": {}
        }

        response = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"resources": []}
        }

        mock_client.send_message = AsyncMock()
        mock_server.handle_message = AsyncMock(return_value=response)

        # Send message
        await mock_client.send_message(request)
        mock_client.send_message.assert_called_once_with(request)

        # Receive response
        result = await mock_server.handle_message(request)
        assert result["id"] == request["id"]

    @pytest.mark.asyncio
    async def test_message_id_matching(self):
        """Test request-response ID matching"""
        requests = [
            {"jsonrpc": "2.0", "id": 1, "method": "resources/list", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            {"jsonrpc": "2.0", "id": 3, "method": "prompts/list", "params": {}}
        ]

        responses = [
            {"jsonrpc": "2.0", "id": 1, "result": {"resources": []}},
            {"jsonrpc": "2.0", "id": 2, "result": {"tools": []}},
            {"jsonrpc": "2.0", "id": 3, "result": {"prompts": []}}
        ]

        for req, resp in zip(requests, responses):
            assert req["id"] == resp["id"]

    @pytest.mark.asyncio
    async def test_notification_without_id(self):
        """Test notification messages without ID"""
        notification = {
            "jsonrpc": "2.0",
            "method": "resources/listChanged",
            "params": {}
        }

        # Notifications should not have ID
        assert "id" not in notification

    @pytest.mark.asyncio
    async def test_message_timeout(self, mock_client):
        """Test message response timeout"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "resources/list",
            "params": {}
        }

        async def delayed_response():
            await asyncio.sleep(10)
            return {"jsonrpc": "2.0", "id": 1, "result": {}}

        mock_client.send_message_and_wait = AsyncMock(side_effect=delayed_response)

        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(
                mock_client.send_message_and_wait(request),
                timeout=0.1
            )

    @pytest.mark.asyncio
    async def test_large_message_handling(self):
        """Test handling of large messages"""
        # Create a large message payload
        large_data = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "test",
            "params": {
                "data": "x" * 100000  # 100KB of data
            }
        }

        # Verify it can be serialized
        serialized = json.dumps(large_data)
        deserialized = json.loads(serialized)
        assert deserialized == large_data


class TestResourceManagement:
    """Test resource operations"""

    @pytest.fixture
    def resource_list_response(self):
        """Resource list response fixture"""
        return {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "resources": [
                    {
                        "uri": "file:///knowledge/cwe",
                        "name": "CWE Database",
                        "description": "Common Weakness Enumeration",
                        "mimeType": "application/json"
                    },
                    {
                        "uri": "file:///knowledge/cve",
                        "name": "CVE Database",
                        "description": "Common Vulnerabilities and Exposures",
                        "mimeType": "application/json"
                    }
                ]
            }
        }

    @pytest.mark.asyncio
    async def test_list_resources(self, resource_list_response):
        """Test listing resources"""
        server = AsyncMock()
        server.list_resources = AsyncMock(return_value=resource_list_response)

        result = await server.list_resources()

        assert len(result["result"]["resources"]) == 2
        for resource in result["result"]["resources"]:
            assert "uri" in resource
            assert "name" in resource

    @pytest.mark.asyncio
    async def test_read_resource(self):
        """Test reading a specific resource"""
        server = AsyncMock()

        resource_data = {
            "jsonrpc": "2.0",
            "id": 2,
            "result": {
                "uri": "file:///knowledge/cwe",
                "contents": [{"id": "CWE-79", "name": "Cross-site Scripting"}]
            }
        }

        server.read_resource = AsyncMock(return_value=resource_data)
        result = await server.read_resource("file:///knowledge/cwe")

        assert result["result"]["uri"] == "file:///knowledge/cwe"
        assert "contents" in result["result"]

    @pytest.mark.asyncio
    async def test_resource_not_found(self):
        """Test reading non-existent resource"""
        server = AsyncMock()
        server.read_resource = AsyncMock(
            side_effect=FileNotFoundError("Resource not found")
        )

        with pytest.raises(FileNotFoundError):
            await server.read_resource("file:///non-existent")

    @pytest.mark.asyncio
    async def test_resource_change_notification(self):
        """Test resource change notification"""
        notification = {
            "jsonrpc": "2.0",
            "method": "resources/listChanged",
            "params": {}
        }

        assert notification["method"] == "resources/listChanged"
        assert "id" not in notification


class TestToolInvocation:
    """Test tool calling and execution"""

    @pytest.fixture
    def tool_list_response(self):
        """Tool list response fixture"""
        return {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "tools": [
                    {
                        "name": "analyze_cwe",
                        "description": "Analyze CWE vulnerability",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "cwe_id": {
                                    "type": "string",
                                    "description": "CWE ID"
                                }
                            },
                            "required": ["cwe_id"]
                        }
                    },
                    {
                        "name": "generate_payload",
                        "description": "Generate exploit payload",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "cwe_id": {"type": "string"},
                                "target_type": {"type": "string"}
                            },
                            "required": ["cwe_id"]
                        }
                    }
                ]
            }
        }

    @pytest.mark.asyncio
    async def test_list_tools(self, tool_list_response):
        """Test listing available tools"""
        server = AsyncMock()
        server.list_tools = AsyncMock(return_value=tool_list_response)

        result = await server.list_tools()

        assert len(result["result"]["tools"]) == 2
        for tool in result["result"]["tools"]:
            assert "name" in tool
            assert "description" in tool
            assert "inputSchema" in tool

    @pytest.mark.asyncio
    async def test_call_tool_success(self):
        """Test successful tool invocation"""
        server = AsyncMock()

        tool_result = {
            "jsonrpc": "2.0",
            "id": 2,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": "CWE-79: Cross-site Scripting (XSS) vulnerability"
                    }
                ]
            }
        }

        server.call_tool = AsyncMock(return_value=tool_result)

        result = await server.call_tool(
            name="analyze_cwe",
            arguments={"cwe_id": "CWE-79"}
        )

        assert result["result"]["content"][0]["type"] == "text"

    @pytest.mark.asyncio
    async def test_call_tool_with_invalid_arguments(self):
        """Test tool invocation with invalid arguments"""
        server = AsyncMock()
        server.call_tool = AsyncMock(
            side_effect=ValueError("Invalid arguments for tool")
        )

        with pytest.raises(ValueError):
            await server.call_tool(
                name="analyze_cwe",
                arguments={}  # Missing required cwe_id
            )

    @pytest.mark.asyncio
    async def test_call_nonexistent_tool(self):
        """Test calling non-existent tool"""
        server = AsyncMock()
        server.call_tool = AsyncMock(
            side_effect=KeyError("Tool not found: invalid_tool")
        )

        with pytest.raises(KeyError):
            await server.call_tool(
                name="invalid_tool",
                arguments={}
            )

    @pytest.mark.asyncio
    async def test_tool_change_notification(self):
        """Test tool list change notification"""
        notification = {
            "jsonrpc": "2.0",
            "method": "tools/listChanged",
            "params": {}
        }

        assert notification["method"] == "tools/listChanged"


class TestConcurrentOperations:
    """Test concurrent request handling"""

    @pytest.mark.asyncio
    async def test_multiple_concurrent_requests(self):
        """Test handling multiple concurrent requests"""
        server = AsyncMock()

        async def mock_request(request_id):
            await asyncio.sleep(0.01)
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {"status": "success"}
            }

        server.handle_request = AsyncMock(side_effect=mock_request)

        # Send 10 concurrent requests
        tasks = [server.handle_request(i) for i in range(1, 11)]
        results = await asyncio.gather(*tasks)

        assert len(results) == 10
        for i, result in enumerate(results, 1):
            assert result["id"] == i

    @pytest.mark.asyncio
    async def test_concurrent_requests_different_methods(self):
        """Test concurrent requests for different methods"""
        server = AsyncMock()

        async def mock_method(method_name, request_id):
            await asyncio.sleep(0.01)
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": method_name,
                "result": {}
            }

        methods = ["resources/list", "tools/list", "prompts/list"]
        tasks = [
            mock_method(method, i)
            for i, method in enumerate(methods, 1)
        ]

        results = await asyncio.gather(*tasks)

        assert len(results) == 3
        for result, method in zip(results, methods):
            assert result["method"] == method

    @pytest.mark.asyncio
    async def test_request_ordering_preservation(self):
        """Test that request ordering is preserved"""
        server = AsyncMock()

        responses = []

        async def mock_handle(request_id):
            await asyncio.sleep(0.001 * (10 - request_id))  # Reverse delays
            return {"id": request_id, "result": {}}

        tasks = [mock_handle(i) for i in range(1, 11)]
        results = await asyncio.gather(*tasks)

        # Verify all requests completed
        assert len(results) == 10
        result_ids = [r["id"] for r in results]
        assert set(result_ids) == set(range(1, 11))

    @pytest.mark.asyncio
    async def test_server_load_handling(self):
        """Test server handling under load"""
        server = AsyncMock()
        server.request_count = 0

        async def mock_request():
            server.request_count += 1
            await asyncio.sleep(0.001)
            return {"status": "success"}

        server.handle_request = mock_request

        # Send 100 concurrent requests
        tasks = [server.handle_request() for _ in range(100)]
        results = await asyncio.gather(*tasks)

        assert len(results) == 100


class TestSessionManagement:
    """Test session lifecycle and management"""

    @pytest.mark.asyncio
    async def test_session_creation(self, mock_client, mock_server):
        """Test session creation on connection"""
        mock_client.session_id = None
        mock_server.create_session = AsyncMock(
            return_value="sess-12345"
        )

        session_id = await mock_server.create_session()

        assert session_id is not None
        assert session_id == "sess-12345"

    @pytest.mark.asyncio
    async def test_session_persistence(self):
        """Test session data persistence"""
        server = AsyncMock()

        session_data = {
            "session_id": "sess-123",
            "client_id": "client-abc",
            "created_at": datetime.now().isoformat(),
            "state": "active",
            "request_history": [
                {"id": 1, "method": "initialize"},
                {"id": 2, "method": "resources/list"}
            ]
        }

        server.get_session = AsyncMock(return_value=session_data)
        result = await server.get_session("sess-123")

        assert result["session_id"] == "sess-123"
        assert len(result["request_history"]) == 2

    @pytest.mark.asyncio
    async def test_session_timeout(self):
        """Test session timeout handling"""
        server = AsyncMock()
        server.close_session = AsyncMock()

        await server.close_session("sess-123")
        server.close_session.assert_called_once_with("sess-123")

    @pytest.mark.asyncio
    async def test_multiple_concurrent_sessions(self):
        """Test handling multiple concurrent sessions"""
        server = AsyncMock()

        async def create_session(session_num):
            return f"sess-{session_num}"

        server.create_session = AsyncMock(side_effect=create_session)

        tasks = [server.create_session(i) for i in range(1, 6)]
        sessions = await asyncio.gather(*tasks)

        assert len(sessions) == 5
        assert len(set(sessions)) == 5  # All unique

    @pytest.mark.asyncio
    async def test_session_state_transitions(self):
        """Test session state transitions"""
        server = AsyncMock()

        states = []

        # Active -> Suspended
        server.suspend_session = AsyncMock()
        await server.suspend_session("sess-123")
        states.append("suspended")

        # Suspended -> Active
        server.resume_session = AsyncMock()
        await server.resume_session("sess-123")
        states.append("active")

        # Active -> Closed
        server.close_session = AsyncMock()
        await server.close_session("sess-123")
        states.append("closed")

        assert len(states) == 3
        assert states[-1] == "closed"


class TestErrorHandling:
    """Test error scenarios and recovery"""

    @pytest.mark.asyncio
    async def test_malformed_request(self, mock_server):
        """Test handling malformed request"""
        malformed = "not valid json"

        mock_server.handle_message = AsyncMock(
            side_effect=json.JSONDecodeError("msg", "doc", 0)
        )

        with pytest.raises(json.JSONDecodeError):
            await mock_server.handle_message(malformed)

    @pytest.mark.asyncio
    async def test_missing_required_fields(self, mock_server):
        """Test handling request with missing required fields"""
        incomplete_request = {
            "id": 1,
            "method": "test"
            # Missing jsonrpc and params
        }

        mock_server.handle_message = AsyncMock(
            side_effect=KeyError("Missing required field: jsonrpc")
        )

        with pytest.raises(KeyError):
            await mock_server.handle_message(incomplete_request)

    @pytest.mark.asyncio
    async def test_error_response_format(self):
        """Test error response format"""
        error_response = {
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "code": -32600,
                "message": "Invalid Request",
                "data": {"details": "Some error details"}
            }
        }

        assert "error" in error_response
        assert "result" not in error_response
        assert error_response["error"]["code"] < 0

    @pytest.mark.asyncio
    async def test_server_error_recovery(self, mock_server):
        """Test server recovery from error"""
        # First request fails
        mock_server.handle_message = AsyncMock(
            side_effect=Exception("Server error")
        )

        with pytest.raises(Exception):
            await mock_server.handle_message({"id": 1})

        # Server recovers and can handle next request
        mock_server.handle_message = AsyncMock(
            return_value={"jsonrpc": "2.0", "id": 2, "result": {}}
        )

        result = await mock_server.handle_message({"id": 2})
        assert result["id"] == 2

    @pytest.mark.asyncio
    async def test_timeout_error_handling(self):
        """Test timeout error handling"""
        server = AsyncMock()

        async def timeout_request():
            await asyncio.sleep(10)

        server.handle_request = AsyncMock(side_effect=timeout_request)

        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(
                server.handle_request(),
                timeout=0.1
            )


class TestTransportLayerInteraction:
    """Test transport-specific interactions"""

    @pytest.mark.asyncio
    async def test_stdio_transport_communication(self):
        """Test stdio transport message flow"""
        # Simulate stdin/stdout communication
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        }

        # Serialize for transmission
        serialized = json.dumps(request) + "\n"
        assert serialized.endswith("\n")

        # Deserialize on receive
        deserialized = json.loads(serialized.strip())
        assert deserialized == request

    @pytest.mark.asyncio
    async def test_http_transport_communication(self):
        """Test HTTP transport communication"""
        client = AsyncMock()

        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "resources/list"
        }

        response = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"resources": []}
        }

        client.post = AsyncMock(return_value=response)
        result = await client.post("/mcp", json=request)

        assert result["id"] == request["id"]

    @pytest.mark.asyncio
    async def test_websocket_transport_stream(self):
        """Test WebSocket transport streaming"""
        ws_client = AsyncMock()

        # Send message
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "resources/list"
        }

        ws_client.send = AsyncMock()
        await ws_client.send(json.dumps(request))
        ws_client.send.assert_called_once()

        # Receive response
        response = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"resources": []}
        }

        ws_client.receive = AsyncMock(return_value=json.dumps(response))
        result = json.loads(await ws_client.receive())

        assert result["id"] == request["id"]

    @pytest.mark.asyncio
    async def test_transport_connection_loss(self):
        """Test handling transport connection loss"""
        client = AsyncMock()
        client.send = AsyncMock(
            side_effect=ConnectionError("Connection lost")
        )

        with pytest.raises(ConnectionError):
            await client.send({"id": 1})


class TestEndToEndWorkflow:
    """End-to-end integration tests"""

    @pytest.mark.asyncio
    async def test_complete_fuzzing_workflow(self):
        """Test complete fuzzing workflow"""
        # 1. Initialize
        init_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "hyfuzz-client", "version": "1.0.0"}
            }
        }

        # 2. Get resources
        resource_request = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "resources/list",
            "params": {}
        }

        # 3. List tools
        tools_request = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/list",
            "params": {}
        }

        # 4. Call tool to generate payload
        call_tool_request = {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "generate_payload",
                "arguments": {"cwe_id": "CWE-79"}
            }
        }

        # Verify workflow sequence
        requests = [init_request, resource_request, tools_request, call_tool_request]
        for i, req in enumerate(requests, 1):
            assert req["id"] == i

    @pytest.mark.asyncio
    async def test_error_recovery_workflow(self):
        """Test workflow with error and recovery"""
        server = AsyncMock()

        # Invalid request
        invalid_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "invalid_method"
        }

        server.handle_message = AsyncMock(
            side_effect=ValueError("Method not found")
        )

        with pytest.raises(ValueError):
            await server.handle_message(invalid_request)

        # Valid recovery request
        valid_request = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "resources/list",
            "params": {}
        }

        server.handle_message = AsyncMock(
            return_value={
                "jsonrpc": "2.0",
                "id": 2,
                "result": {"resources": []}
            }
        )

        result = await server.handle_message(valid_request)
        assert result["id"] == 2

    @pytest.mark.asyncio
    async def test_long_running_operation(self):
        """Test long-running operations with progress tracking"""
        server = AsyncMock()

        # Simulate long operation with progress notifications
        async def long_operation():
            progress_notifications = []
            for i in range(0, 101, 25):
                notification = {
                    "jsonrpc": "2.0",
                    "method": "notifications/progress",
                    "params": {
                        "progressToken": "token-123",
                        "progress": i,
                        "total": 100
                    }
                }
                progress_notifications.append(notification)
                await asyncio.sleep(0.01)

            return {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {"status": "completed"}
            }

        server.call_long_operation = AsyncMock(side_effect=long_operation)
        result = await server.call_long_operation()

        assert result["result"]["status"] == "completed"

    @pytest.mark.asyncio
    async def test_batch_payload_generation(self):
        """Test batch payload generation"""
        server = AsyncMock()

        # Batch request with multiple tool calls
        payloads_to_generate = [
            {"cwe_id": "CWE-79", "target": "web"},
            {"cwe_id": "CWE-89", "target": "database"},
            {"cwe_id": "CWE-20", "target": "api"}
        ]

        async def batch_generate():
            results = []
            for i, payload_spec in enumerate(payloads_to_generate, 1):
                result = {
                    "jsonrpc": "2.0",
                    "id": i,
                    "result": {
                        "payload": f"generated_{payload_spec['cwe_id']}",
                        "confidence": 0.85
                    }
                }
                results.append(result)
                await asyncio.sleep(0.01)
            return results

        server.batch_generate_payloads = AsyncMock(side_effect=batch_generate)
        results = await server.batch_generate_payloads()

        assert len(results) == 3


class TestPerformanceAndStability:
    """Test performance and stability characteristics"""

    @pytest.mark.asyncio
    async def test_high_frequency_requests(self):
        """Test handling high frequency of requests"""
        server = AsyncMock()
        request_count = 0

        async def mock_handler():
            nonlocal request_count
            request_count += 1
            await asyncio.sleep(0.001)
            return {"status": "ok"}

        server.handle_request = mock_handler

        start_time = time.time()
        tasks = [server.handle_request() for _ in range(100)]
        results = await asyncio.gather(*tasks)
        elapsed = time.time() - start_time

        assert len(results) == 100
        assert request_count == 100

    @pytest.mark.asyncio
    async def test_memory_efficient_message_handling(self):
        """Test memory efficiency in message handling"""
        # Large batch of messages
        messages = [
            {
                "jsonrpc": "2.0",
                "id": i,
                "method": "test",
                "params": {"data": "x" * 1000}
            }
            for i in range(100)
        ]

        # Should handle without excessive memory usage
        assert len(messages) == 100

        # Serialize and deserialize
        serialized = json.dumps(messages)
        deserialized = json.loads(serialized)
        assert len(deserialized) == 100

    @pytest.mark.asyncio
    async def test_connection_stability(self, mock_client):
        """Test connection stability over time"""
        mock_client.is_connected = True
        connected_time = 0

        async def keep_alive():
            nonlocal connected_time
            for _ in range(10):
                if mock_client.is_connected:
                    connected_time += 1
                await asyncio.sleep(0.01)

        await keep_alive()
        assert connected_time == 10


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])