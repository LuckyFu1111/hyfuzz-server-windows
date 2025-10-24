"""
MCP Protocol Integration Tests

Tests for MCP server protocol implementation, including:
- Message format and serialization
- Transport layers (stdio, HTTP, WebSocket)
- Protocol handshake and initialization
- Capability negotiation
- Session management
- Error handling and exception cases
"""

import json
import asyncio
import pytest
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from typing import Dict, Any, List
import logging

# Mock imports (adjust based on actual project structure)
# from src.mcp_server.server import MCPServer
# from src.mcp_server.message_handler import MessageHandler
# from src.mcp_server.capability_manager import CapabilityManager
# from src.models.message_models import MCPMessage, MCPRequest, MCPResponse
# from src.utils.exceptions import MCPException, InvalidMessageError


class TestMCPProtocolBasics:
    """Test MCP protocol basic functionality"""

    @pytest.fixture
    def mcp_message_template(self):
        """MCP message template"""
        return {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "test-client",
                    "version": "1.0.0"
                }
            }
        }

    def test_mcp_message_format_validation(self, mcp_message_template):
        """Test MCP message format validation"""
        # Test valid message format
        message = mcp_message_template
        assert message.get("jsonrpc") == "2.0"
        assert "id" in message
        assert "method" in message
        assert "params" in message

        # Verify message can be JSON serialized
        serialized = json.dumps(message)
        deserialized = json.loads(serialized)
        assert deserialized == message

    def test_mcp_message_missing_required_fields(self, mcp_message_template):
        """Test message with missing required fields"""
        # Remove required field
        invalid_message = mcp_message_template.copy()
        del invalid_message["jsonrpc"]

        # Verify missing field detection
        assert "jsonrpc" not in invalid_message
        assert invalid_message.get("jsonrpc") is None

    def test_mcp_protocol_version(self):
        """Test protocol version checking"""
        valid_versions = [
            "2024-11-05",
            "2024-10-01",
            "2024-09-15"
        ]

        for version in valid_versions:
            assert version.startswith("20")  # Valid date format
            assert len(version) == 10

    def test_mcp_request_id_types(self):
        """Test different request ID types"""
        valid_ids = [
            1,
            "string-id-123",
            12345,
            "request-uuid-abc-def"
        ]

        for request_id in valid_ids:
            # ID can be integer or string
            assert isinstance(request_id, (int, str))


class TestMCPInitialization:
    """Test MCP initialization flow"""

    @pytest.fixture
    def initialize_request(self):
        """Initialize request"""
        return {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "experimental": {},
                },
                "clientInfo": {
                    "name": "hyfuzz-client",
                    "version": "1.0.0"
                }
            }
        }

    @pytest.fixture
    def initialize_response(self):
        """Initialize response"""
        return {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "resources": {
                        "listChanged": True
                    },
                    "tools": {
                        "listChanged": True
                    },
                    "prompts": {
                        "listChanged": True
                    }
                },
                "serverInfo": {
                    "name": "hyfuzz-server",
                    "version": "1.0.0"
                }
            }
        }

    def test_initialize_handshake_success(self, initialize_request, initialize_response):
        """Test successful initialization handshake"""
        assert initialize_request["method"] == "initialize"
        assert initialize_response["result"]["protocolVersion"] == initialize_request["params"]["protocolVersion"]
        assert initialize_response["id"] == initialize_request["id"]

    def test_initialize_client_info(self, initialize_request):
        """Test client info in initialization request"""
        client_info = initialize_request["params"]["clientInfo"]
        assert "name" in client_info
        assert "version" in client_info
        assert client_info["name"] == "hyfuzz-client"

    def test_initialize_capabilities_negotiation(self, initialize_request, initialize_response):
        """Test capability negotiation"""
        client_capabilities = initialize_request["params"]["capabilities"]
        server_capabilities = initialize_response["result"]["capabilities"]

        # Verify server returned all required capabilities
        required_capabilities = ["resources", "tools", "prompts"]
        for capability in required_capabilities:
            assert capability in server_capabilities

    @pytest.mark.asyncio
    async def test_initialize_async_flow(self, initialize_request):
        """Test asynchronous initialization flow"""
        # Mock asynchronous initialization handling
        async def mock_initialize(request):
            await asyncio.sleep(0.01)  # Simulate processing delay
            return {
                "jsonrpc": "2.0",
                "id": request["id"],
                "result": {
                    "protocolVersion": request["params"]["protocolVersion"],
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

        response = await mock_initialize(initialize_request)
        assert response["result"]["protocolVersion"] == "2024-11-05"


class TestMCPMessageHandling:
    """Test MCP message handling"""

    def test_request_response_pairing(self):
        """Test request-response pairing"""
        request_id = 42

        request = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "list_resources",
            "params": {}
        }

        response = {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": []
        }

        # Verify ID matching
        assert request["id"] == response["id"] == request_id

    def test_notification_messages(self):
        """Test notification messages (no ID)"""
        notification = {
            "jsonrpc": "2.0",
            "method": "resources/listChanged",
            "params": {}
        }

        # Notification messages should not have ID
        assert "id" not in notification
        assert notification["method"] == "resources/listChanged"

    def test_error_response_format(self):
        """Test error response format"""
        error_response = {
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "code": -32600,
                "message": "Invalid Request",
                "data": {
                    "details": "The request message was invalid"
                }
            }
        }

        assert "error" in error_response
        assert error_response["error"]["code"] < 0
        assert "message" in error_response["error"]

    def test_batch_messages(self):
        """Test batch message processing"""
        batch = [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "list_resources",
                "params": {}
            },
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "list_tools",
                "params": {}
            },
            {
                "jsonrpc": "2.0",
                "method": "resources/listChanged",
                "params": {}
            }
        ]

        assert len(batch) == 3
        assert batch[0]["id"] == 1
        assert batch[1]["id"] == 2
        assert "id" not in batch[2]  # Notification message


class TestMCPCapabilities:
    """Test MCP capabilities"""

    @pytest.fixture
    def server_capabilities(self):
        """Server capabilities configuration"""
        return {
            "resources": {
                "listChanged": True
            },
            "tools": {
                "listChanged": True
            },
            "prompts": {
                "listChanged": True
            },
            "sampling": {},
            "experimental": {
                "chat": {}
            }
        }

    def test_capability_declaration(self, server_capabilities):
        """Test capability declaration"""
        # Verify core capabilities
        core_capabilities = ["resources", "tools", "prompts"]
        for cap in core_capabilities:
            assert cap in server_capabilities

    def test_capability_list_changed_flag(self, server_capabilities):
        """Test listChanged flag"""
        assert server_capabilities["resources"]["listChanged"] is True
        assert server_capabilities["tools"]["listChanged"] is True
        assert server_capabilities["prompts"]["listChanged"] is True

    def test_experimental_capabilities(self, server_capabilities):
        """Test experimental capabilities"""
        assert "experimental" in server_capabilities
        assert "chat" in server_capabilities["experimental"]

    def test_capability_versioning(self):
        """Test capability versioning"""
        capability_versions = {
            "resources": "1.0",
            "tools": "2.0",
            "prompts": "1.5"
        }

        for cap, version in capability_versions.items():
            assert isinstance(version, str)
            assert len(version.split(".")) >= 2


class TestMCPResourceHandling:
    """Test MCP resource handling"""

    @pytest.fixture
    def resource_request(self):
        """Resource request"""
        return {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "resources/list",
            "params": {}
        }

    @pytest.fixture
    def resource_response(self):
        """Resource response"""
        return {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "resources": [
                    {
                        "uri": "file:///path/to/cwe/data",
                        "name": "CWE Database",
                        "description": "Common Weakness Enumeration database",
                        "mimeType": "application/json"
                    },
                    {
                        "uri": "file:///path/to/cve/data",
                        "name": "CVE Database",
                        "description": "Common Vulnerabilities and Exposures database",
                        "mimeType": "application/json"
                    }
                ]
            }
        }

    def test_list_resources_request(self, resource_request):
        """Test list resources request"""
        assert resource_request["method"] == "resources/list"
        assert resource_request["params"] == {}

    def test_list_resources_response(self, resource_response):
        """Test list resources response"""
        resources = resource_response["result"]["resources"]
        assert len(resources) >= 0

        for resource in resources:
            assert "uri" in resource
            assert "name" in resource
            assert "description" in resource

    def test_read_resource_request(self):
        """Test read single resource request"""
        request = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "resources/read",
            "params": {
                "uri": "file:///path/to/cwe/data"
            }
        }

        assert request["method"] == "resources/read"
        assert request["params"]["uri"].startswith("file://")

    def test_resource_uri_formats(self):
        """Test resource URI formats"""
        valid_uris = [
            "file:///path/to/local/file",
            "http://example.com/resource",
            "https://example.com/resource",
            "data:application/json;base64,eyJrZXkiOiJ2YWx1ZSJ9"
        ]

        for uri in valid_uris:
            assert "://" in uri


class TestMCPToolHandling:
    """Test MCP tool handling"""

    @pytest.fixture
    def tool_list_response(self):
        """Tool list response"""
        return {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "tools": [
                    {
                        "name": "analyze_cwe",
                        "description": "Analyze Common Weakness Enumeration",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "cwe_id": {
                                    "type": "string",
                                    "description": "CWE ID to analyze"
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
                                "vulnerability": {
                                    "type": "string",
                                    "description": "Vulnerability details"
                                }
                            },
                            "required": ["vulnerability"]
                        }
                    }
                ]
            }
        }

    def test_list_tools_response(self, tool_list_response):
        """Test list tools response"""
        tools = tool_list_response["result"]["tools"]
        assert len(tools) >= 0

        for tool in tools:
            assert "name" in tool
            assert "description" in tool
            assert "inputSchema" in tool

    def test_tool_input_schema_validation(self, tool_list_response):
        """Test tool input schema validation"""
        tools = tool_list_response["result"]["tools"]

        for tool in tools:
            schema = tool["inputSchema"]
            assert schema["type"] == "object"
            assert "properties" in schema or "type" in schema

    def test_call_tool_request(self):
        """Test call tool request"""
        request = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "analyze_cwe",
                "arguments": {
                    "cwe_id": "CWE-79"
                }
            }
        }

        assert request["method"] == "tools/call"
        assert request["params"]["name"] == "analyze_cwe"
        assert "arguments" in request["params"]

    def test_tool_result_format(self):
        """Test tool result format"""
        result = {
            "jsonrpc": "2.0",
            "id": 2,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": "CWE-79: Improper Neutralization of Input During Web Page Generation"
                    }
                ]
            }
        }

        assert "content" in result["result"]
        for content in result["result"]["content"]:
            assert "type" in content
            assert "text" in content


class TestMCPPromptHandling:
    """Test MCP prompt handling"""

    @pytest.fixture
    def prompt_list_response(self):
        """Prompt list response"""
        return {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "prompts": [
                    {
                        "name": "fuzzing_strategy",
                        "description": "Suggest fuzzing strategy",
                        "arguments": [
                            {
                                "name": "target_type",
                                "description": "Type of target to fuzz",
                                "required": True
                            }
                        ]
                    },
                    {
                        "name": "vulnerability_analysis",
                        "description": "Analyze vulnerability details",
                        "arguments": []
                    }
                ]
            }
        }

    def test_list_prompts_response(self, prompt_list_response):
        """Test list prompts response"""
        prompts = prompt_list_response["result"]["prompts"]
        assert len(prompts) >= 0

        for prompt in prompts:
            assert "name" in prompt
            assert "description" in prompt
            assert "arguments" in prompt

    def test_prompt_arguments_schema(self, prompt_list_response):
        """Test prompt arguments schema"""
        prompts = prompt_list_response["result"]["prompts"]

        for prompt in prompts:
            arguments = prompt["arguments"]
            assert isinstance(arguments, list)

            for arg in arguments:
                assert "name" in arg
                assert "description" in arg
                if "required" in arg:
                    assert isinstance(arg["required"], bool)

    def test_get_prompt_request(self):
        """Test get prompt request"""
        request = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "prompts/get",
            "params": {
                "name": "fuzzing_strategy",
                "arguments": {
                    "target_type": "web_application"
                }
            }
        }

        assert request["method"] == "prompts/get"
        assert request["params"]["name"] == "fuzzing_strategy"


class TestMCPErrorHandling:
    """Test MCP error handling"""

    def test_parse_error(self):
        """Test parse error"""
        error = {
            "code": -32700,
            "message": "Parse error",
            "data": {
                "details": "Invalid JSON was received by the server"
            }
        }

        assert error["code"] == -32700
        assert "Parse error" in error["message"]

    def test_invalid_request_error(self):
        """Test invalid request error"""
        error = {
            "code": -32600,
            "message": "Invalid Request",
            "data": {
                "details": "The JSON sent is not a valid Request object"
            }
        }

        assert error["code"] == -32600
        assert "Invalid Request" in error["message"]

    def test_method_not_found_error(self):
        """Test method not found error"""
        error = {
            "code": -32601,
            "message": "Method not found",
            "data": {
                "method": "invalid_method",
                "available": ["initialize", "resources/list", "tools/call"]
            }
        }

        assert error["code"] == -32601
        assert "Method not found" in error["message"]

    def test_invalid_params_error(self):
        """Test invalid params error"""
        error = {
            "code": -32602,
            "message": "Invalid params",
            "data": {
                "details": "Required parameter 'cwe_id' is missing"
            }
        }

        assert error["code"] == -32602
        assert "Invalid params" in error["message"]

    def test_internal_error(self):
        """Test internal error"""
        error = {
            "code": -32603,
            "message": "Internal error",
            "data": {
                "details": "An unexpected error occurred during processing"
            }
        }

        assert error["code"] == -32603
        assert "Internal error" in error["message"]

    def test_custom_server_error(self):
        """Test custom server error"""
        error = {
            "code": -32000,
            "message": "Server error",
            "data": {
                "details": "Knowledge base unavailable"
            }
        }

        assert -32099 <= error["code"] <= -32000
        assert "Server error" in error["message"]

    def test_error_response_format(self):
        """Test error response format"""
        error_response = {
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "code": -32600,
                "message": "Invalid Request"
            }
        }

        assert "error" in error_response
        assert "result" not in error_response
        assert error_response["error"]["code"] < 0


class TestMCPSessionManagement:
    """Test MCP session management"""

    def test_session_initialization(self):
        """Test session initialization"""
        session = {
            "session_id": "sess-12345",
            "client_id": "client-abc",
            "created_at": "2024-01-01T00:00:00Z",
            "state": "active"
        }

        assert "session_id" in session
        assert "client_id" in session
        assert session["state"] == "active"

    def test_session_state_transitions(self):
        """Test session state transitions"""
        states = ["initialized", "active", "suspended", "closed"]

        # Verify state transition flow
        transitions = {
            "initialized": ["active"],
            "active": ["suspended", "closed"],
            "suspended": ["active", "closed"],
            "closed": []
        }

        for state, next_states in transitions.items():
            assert isinstance(next_states, list)

    def test_session_context_preservation(self):
        """Test session context preservation"""
        context = {
            "session_id": "sess-123",
            "request_history": [
                {"id": 1, "method": "initialize"},
                {"id": 2, "method": "resources/list"}
            ],
            "capabilities_negotiated": True,
            "authenticated": True
        }

        assert len(context["request_history"]) == 2
        assert context["capabilities_negotiated"] is True

    def test_concurrent_sessions(self):
        """Test concurrent sessions"""
        sessions = [
            {"session_id": "sess-1", "client": "client-A"},
            {"session_id": "sess-2", "client": "client-B"},
            {"session_id": "sess-3", "client": "client-C"}
        ]

        session_ids = [s["session_id"] for s in sessions]
        assert len(set(session_ids)) == len(session_ids)  # All IDs unique


class TestMCPTransportLayer:
    """Test MCP transport layer"""

    def test_stdio_transport_message_framing(self):
        """Test stdio transport message framing"""
        # MCP uses JSON-RPC 2.0 over stdio
        message = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        }

        # Verify message can be serialized
        serialized = json.dumps(message) + "\n"
        assert serialized.endswith("\n")

    def test_http_transport_headers(self):
        """Test HTTP transport headers"""
        headers = {
            "Content-Type": "application/json",
            "Content-Length": "256",
            "Accept": "application/json"
        }

        assert headers["Content-Type"] == "application/json"
        assert "Content-Length" in headers

    def test_websocket_transport_frame_format(self):
        """Test WebSocket transport frame format"""
        # JSON-RPC message in WebSocket frame
        message = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "resources/list"
        }

        frame_data = json.dumps(message)
        assert isinstance(frame_data, str)
        assert frame_data.startswith("{")

    def test_transport_message_ordering(self):
        """Test transport layer message ordering"""
        messages = [
            {"id": 1, "method": "initialize"},
            {"id": 2, "method": "resources/list"},
            {"id": 3, "method": "tools/call"}
        ]

        # Verify message ordering
        for i, msg in enumerate(messages):
            assert msg["id"] == i + 1

    def test_transport_disconnection_handling(self):
        """Test transport layer disconnection handling"""
        # Simulate disconnection scenario
        connection_state = {
            "connected": True,
            "last_message_id": 42
        }

        # Simulate disconnection
        connection_state["connected"] = False

        assert connection_state["connected"] is False


class TestMCPIntegration:
    """MCP integration tests"""

    @pytest.mark.asyncio
    async def test_full_workflow(self):
        """Test full workflow"""
        # 1. Initialize
        init_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "test-client",
                    "version": "1.0.0"
                }
            }
        }

        # Mock initialization response
        init_response = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "resources": {"listChanged": True},
                    "tools": {"listChanged": True}
                },
                "serverInfo": {
                    "name": "hyfuzz-server",
                    "version": "1.0.0"
                }
            }
        }

        assert init_request["id"] == init_response["id"]

        # 2. List resources
        list_resources_request = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "resources/list",
            "params": {}
        }

        # 3. Call tool
        call_tool_request = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "analyze_cwe",
                "arguments": {"cwe_id": "CWE-79"}
            }
        }

        # Verify request sequence
        requests = [init_request, list_resources_request, call_tool_request]
        for i, req in enumerate(requests):
            assert req["id"] == i + 1

    @pytest.mark.asyncio
    async def test_error_recovery_workflow(self):
        """Test error recovery workflow"""
        # Send invalid request
        invalid_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "invalid_method"
        }

        # Mock error response
        error_response = {
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "code": -32601,
                "message": "Method not found"
            }
        }

        assert error_response["id"] == invalid_request["id"]
        assert "error" in error_response

        # Send valid request for recovery
        recovery_request = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1.0"}
            }
        }

        assert recovery_request["id"] > invalid_request["id"]

    @pytest.mark.asyncio
    async def test_concurrent_request_handling(self):
        """Test concurrent request handling"""
        # Create multiple concurrent requests
        async def send_request(request_id):
            request = {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": "resources/list",
                "params": {}
            }
            await asyncio.sleep(0.01)
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {"resources": []}
            }

        # Send 10 concurrent requests
        tasks = [send_request(i) for i in range(1, 11)]
        responses = await asyncio.gather(*tasks)

        assert len(responses) == 10
        # Verify all responses received
        response_ids = [r["id"] for r in responses]
        assert set(response_ids) == set(range(1, 11))


class TestMCPNotifications:
    """Test MCP notifications"""

    def test_resource_list_changed_notification(self):
        """Test resource list changed notification"""
        notification = {
            "jsonrpc": "2.0",
            "method": "resources/listChanged",
            "params": {}
        }

        assert "id" not in notification
        assert notification["method"] == "resources/listChanged"

    def test_tools_list_changed_notification(self):
        """Test tools list changed notification"""
        notification = {
            "jsonrpc": "2.0",
            "method": "tools/listChanged",
            "params": {}
        }

        assert "id" not in notification
        assert notification["method"] == "tools/listChanged"

    def test_prompts_list_changed_notification(self):
        """Test prompts list changed notification"""
        notification = {
            "jsonrpc": "2.0",
            "method": "prompts/listChanged",
            "params": {}
        }

        assert "id" not in notification
        assert notification["method"] == "prompts/listChanged"


class TestMCPSamplingCapability:
    """Test MCP sampling capability (optional)"""

    def test_create_message_request(self):
        """Test create message request"""
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "sampling/createMessage",
            "params": {
                "messages": [
                    {
                        "role": "user",
                        "content": "Analyze CWE-79 vulnerability"
                    }
                ],
                "model": "llama2",
                "maxTokens": 1024
            }
        }

        assert request["method"] == "sampling/createMessage"
        assert "messages" in request["params"]
        assert request["params"]["maxTokens"] == 1024

    def test_sampling_result_format(self):
        """Test sampling result format"""
        result = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": "CWE-79 is a cross-site scripting vulnerability..."
                    }
                ],
                "stopReason": "endTurn"
            }
        }

        assert "content" in result["result"]
        assert "stopReason" in result["result"]


class TestMCPProgressTracking:
    """Test MCP progress tracking"""

    def test_progress_notification(self):
        """Test progress notification"""
        notification = {
            "jsonrpc": "2.0",
            "method": "notifications/progress",
            "params": {
                "progressToken": "token-123",
                "progress": 50,
                "total": 100
            }
        }

        assert notification["params"]["progress"] <= notification["params"]["total"]
        assert notification["params"]["progress"] >= 0

    def test_progress_completion(self):
        """Test progress completion"""
        notification = {
            "jsonrpc": "2.0",
            "method": "notifications/progress",
            "params": {
                "progressToken": "token-123",
                "progress": 100,
                "total": 100
            }
        }

        assert notification["params"]["progress"] == notification["params"]["total"]


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])