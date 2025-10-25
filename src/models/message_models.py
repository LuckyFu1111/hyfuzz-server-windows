# hyfuzz-server-windows/src/models/message_models.py

from typing import Any, Dict, List, Optional, Union
from datetime import datetime
from enum import Enum
from pydantic import BaseModel, Field, ConfigDict


# ============================================================================
# ENUMS - Protocol and Message Types
# ============================================================================

class MessageType(str, Enum):
    """MCP message types"""
    REQUEST = "request"
    RESPONSE = "response"
    NOTIFICATION = "notification"
    ERROR = "error"


class RequestMethod(str, Enum):
    """MCP request methods"""
    # Protocol initialization
    INITIALIZE = "initialize"
    PING = "ping"

    # Resources
    LIST_RESOURCES = "resources/list"
    READ_RESOURCE = "resources/read"
    SUBSCRIBE_RESOURCE = "resources/subscribe"
    UNSUBSCRIBE_RESOURCE = "resources/unsubscribe"

    # Tools
    LIST_TOOLS = "tools/list"
    CALL_TOOL = "tools/call"

    # Prompts
    LIST_PROMPTS = "prompts/list"
    GET_PROMPT = "prompts/get"

    # Sampling
    CREATE_MESSAGE = "sampling/createMessage"


class RoleType(str, Enum):
    """Role types in messages"""
    USER = "user"
    ASSISTANT = "assistant"
    SYSTEM = "system"


class ContentBlockType(str, Enum):
    """Content block types"""
    TEXT = "text"
    IMAGE = "image"
    TOOL_USE = "tool_use"
    TOOL_RESULT = "tool_result"


class StatusCode(int, Enum):
    """HTTP-like status codes for MCP"""
    OK = 200
    CREATED = 201
    BAD_REQUEST = 400
    UNAUTHORIZED = 401
    FORBIDDEN = 403
    NOT_FOUND = 404
    INTERNAL_ERROR = 500
    SERVICE_UNAVAILABLE = 503


# ============================================================================
# Core Message Models
# ============================================================================

class ContentBlock(BaseModel):
    """Base content block model"""
    model_config = ConfigDict(use_enum_values=True)

    type: ContentBlockType


class TextContentBlock(ContentBlock):
    """Text content block"""
    type: ContentBlockType = ContentBlockType.TEXT
    text: str = Field(..., description="Text content")


class ImageContentBlock(ContentBlock):
    """Image content block"""
    type: ContentBlockType = ContentBlockType.IMAGE
    source: Dict[str, Any] = Field(..., description="Image source details")


class ToolUseContentBlock(ContentBlock):
    """Tool use content block"""
    type: ContentBlockType = ContentBlockType.TOOL_USE
    id: str = Field(..., description="Tool use ID")
    name: str = Field(..., description="Tool name")
    input: Dict[str, Any] = Field(..., description="Tool input parameters")


class ToolResultContentBlock(ContentBlock):
    """Tool result content block"""
    type: ContentBlockType = ContentBlockType.TOOL_RESULT
    tool_use_id: str = Field(..., description="Reference to tool use ID")
    content: str = Field(..., description="Result content")
    is_error: bool = Field(default=False, description="Whether result is an error")


# ============================================================================
# Request/Response Models
# ============================================================================

class MCPRequest(BaseModel):
    """Base MCP request model"""
    model_config = ConfigDict(use_enum_values=True)

    jsonrpc: str = Field(default="2.0", description="JSON-RPC version")
    id: Union[str, int] = Field(..., description="Request ID")
    method: str = Field(..., description="Method name")
    params: Optional[Dict[str, Any]] = Field(default=None, description="Method parameters")


class MCPResponse(BaseModel):
    """Base MCP response model"""
    model_config = ConfigDict(use_enum_values=True)

    jsonrpc: str = Field(default="2.0", description="JSON-RPC version")
    id: Union[str, int] = Field(..., description="Request ID")
    result: Optional[Dict[str, Any]] = Field(default=None, description="Result data")
    error: Optional[Dict[str, Any]] = Field(default=None, description="Error information")


class ErrorDetail(BaseModel):
    """Error detail model"""
    code: StatusCode = Field(..., description="Error code")
    message: str = Field(..., description="Error message")
    data: Optional[Dict[str, Any]] = Field(default=None, description="Additional error data")


class MCPError(BaseModel):
    """MCP error response model"""
    model_config = ConfigDict(use_enum_values=True)

    jsonrpc: str = Field(default="2.0", description="JSON-RPC version")
    id: Union[str, int] = Field(..., description="Request ID")
    error: ErrorDetail = Field(..., description="Error details")


# ============================================================================
# Protocol Initialization Models
# ============================================================================

class ClientInfo(BaseModel):
    """Client information"""
    name: str = Field(..., description="Client name")
    version: str = Field(..., description="Client version")


class ServerInfo(BaseModel):
    """Server information"""
    name: str = Field(..., description="Server name")
    version: str = Field(..., description="Server version")


class InitializeRequest(MCPRequest):
    """Initialize request model"""
    method: str = Field(default=RequestMethod.INITIALIZE, description="Method")
    params: Dict[str, Any] = Field(..., description="Client info and capabilities")


class InitializeResponse(MCPResponse):
    """Initialize response model"""
    result: Dict[str, Any] = Field(..., description="Server capabilities and info")


# ============================================================================
# Tool Models
# ============================================================================

class ToolParameter(BaseModel):
    """Tool parameter definition"""
    name: str = Field(..., description="Parameter name")
    type: str = Field(..., description="Parameter type")
    description: Optional[str] = Field(default=None, description="Parameter description")
    required: bool = Field(default=True, description="Whether parameter is required")


class ToolDefinition(BaseModel):
    """Tool definition model"""
    name: str = Field(..., description="Tool name")
    description: str = Field(..., description="Tool description")
    input_schema: Dict[str, Any] = Field(..., description="Tool input schema")


class ListToolsRequest(MCPRequest):
    """List tools request"""
    method: str = Field(default=RequestMethod.LIST_TOOLS, description="Method")


class ListToolsResponse(MCPResponse):
    """List tools response"""
    result: Dict[str, List[ToolDefinition]] = Field(..., description="Available tools")


class CallToolRequest(MCPRequest):
    """Call tool request"""
    method: str = Field(default=RequestMethod.CALL_TOOL, description="Method")
    params: Dict[str, Any] = Field(..., description="Tool name and arguments")


class CallToolResponse(MCPResponse):
    """Call tool response"""
    result: Dict[str, Any] = Field(..., description="Tool result")


# ============================================================================
# Resource Models
# ============================================================================

class ResourceUri(BaseModel):
    """Resource URI model"""
    uri: str = Field(..., description="Resource URI")
    name: Optional[str] = Field(default=None, description="Resource name")
    description: Optional[str] = Field(default=None, description="Resource description")
    mime_type: Optional[str] = Field(default=None, description="Resource MIME type")


class ListResourcesRequest(MCPRequest):
    """List resources request"""
    method: str = Field(default=RequestMethod.LIST_RESOURCES, description="Method")


class ListResourcesResponse(MCPResponse):
    """List resources response"""
    result: Dict[str, List[ResourceUri]] = Field(..., description="Available resources")


class ReadResourceRequest(MCPRequest):
    """Read resource request"""
    method: str = Field(default=RequestMethod.READ_RESOURCE, description="Method")
    params: Dict[str, str] = Field(..., description="Resource URI")


class ReadResourceResponse(MCPResponse):
    """Read resource response"""
    result: Dict[str, Any] = Field(..., description="Resource content")


# ============================================================================
# Message Models (for sampling/conversation)
# ============================================================================

class ConversationMessage(BaseModel):
    """Conversation message model"""
    model_config = ConfigDict(use_enum_values=True)

    role: RoleType = Field(..., description="Message role")
    content: Union[str, List[ContentBlock]] = Field(..., description="Message content")


class CreateMessageRequest(MCPRequest):
    """Create message request (for sampling)"""
    method: str = Field(default=RequestMethod.CREATE_MESSAGE, description="Method")
    params: Dict[str, Any] = Field(..., description="Message creation parameters")


class CreateMessageResponse(MCPResponse):
    """Create message response"""
    result: Dict[str, Any] = Field(..., description="Generated message")


# ============================================================================
# Prompt Models
# ============================================================================

class PromptDefinition(BaseModel):
    """Prompt definition model"""
    name: str = Field(..., description="Prompt name")
    description: Optional[str] = Field(default=None, description="Prompt description")
    arguments: List[ToolParameter] = Field(default_factory=list, description="Prompt arguments")


class ListPromptsRequest(MCPRequest):
    """List prompts request"""
    method: str = Field(default=RequestMethod.LIST_PROMPTS, description="Method")


class ListPromptsResponse(MCPResponse):
    """List prompts response"""
    result: Dict[str, List[PromptDefinition]] = Field(..., description="Available prompts")


class GetPromptRequest(MCPRequest):
    """Get prompt request"""
    method: str = Field(default=RequestMethod.GET_PROMPT, description="Method")
    params: Dict[str, str] = Field(..., description="Prompt name and arguments")


class GetPromptResponse(MCPResponse):
    """Get prompt response"""
    result: Dict[str, Any] = Field(..., description="Prompt content")


# ============================================================================
# Notification Models
# ============================================================================

class MCPNotification(BaseModel):
    """Base MCP notification model"""
    model_config = ConfigDict(use_enum_values=True)

    jsonrpc: str = Field(default="2.0", description="JSON-RPC version")
    method: str = Field(..., description="Notification method")
    params: Optional[Dict[str, Any]] = Field(default=None, description="Notification parameters")


class PingRequest(MCPRequest):
    """Ping request (keep-alive)"""
    method: str = Field(default=RequestMethod.PING, description="Method")


class PingResponse(MCPResponse):
    """Ping response (keep-alive)"""
    result: Dict[str, str] = Field(default_factory=lambda: {"status": "pong"}, description="Pong response")


# ============================================================================
# Logging and Metadata Models
# ============================================================================

class RequestMetadata(BaseModel):
    """Request metadata for logging"""
    request_id: str = Field(..., description="Unique request ID")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Request timestamp")
    client_info: Optional[Dict[str, str]] = Field(default=None, description="Client information")
    method: str = Field(..., description="Request method")


class ResponseMetadata(BaseModel):
    """Response metadata for logging"""
    response_id: str = Field(..., description="Response ID")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Response timestamp")
    request_id: str = Field(..., description="Corresponding request ID")
    status_code: StatusCode = Field(..., description="Response status code")
    duration_ms: float = Field(..., description="Processing duration in milliseconds")


# ============================================================================
# TESTS
# ============================================================================

if __name__ == "__main__":
    """Test message models"""
    import json

    print("=" * 70)
    print("TESTING MCP MESSAGE MODELS")
    print("=" * 70)

    # Test 1: Create a simple text content block
    print("\n[Test 1] TextContentBlock:")
    text_block = TextContentBlock(text="Hello, MCP!")
    print(f"✓ Created: {text_block.model_dump()}")

    # Test 2: Create a conversation message
    print("\n[Test 2] ConversationMessage:")
    msg = ConversationMessage(
        role=RoleType.USER,
        content="What is a vulnerability?"
    )
    print(f"✓ Created: {msg.model_dump()}")

    # Test 3: Create an MCP request
    print("\n[Test 3] MCPRequest:")
    request = MCPRequest(
        id="req-001",
        method=RequestMethod.LIST_TOOLS,
        params={}
    )
    print(f"✓ Created: {request.model_dump()}")

    # Test 4: Create a successful response
    print("\n[Test 4] MCPResponse (Success):")
    response = MCPResponse(
        id="req-001",
        result={
            "tools": [
                {"name": "analyze_cve", "description": "Analyze CVE vulnerabilities"}
            ]
        }
    )
    print(f"✓ Created: {response.model_dump()}")

    # Test 5: Create an error response
    print("\n[Test 5] MCPError:")
    error = MCPError(
        id="req-002",
        error=ErrorDetail(
            code=StatusCode.BAD_REQUEST,
            message="Invalid tool name"
        )
    )
    print(f"✓ Created: {error.model_dump()}")

    # Test 6: Create a tool definition
    print("\n[Test 6] ToolDefinition:")
    tool = ToolDefinition(
        name="analyze_cve",
        description="Analyze CVE vulnerabilities",
        input_schema={
            "type": "object",
            "properties": {
                "cve_id": {"type": "string", "description": "CVE ID"}
            },
            "required": ["cve_id"]
        }
    )
    print(f"✓ Created: {tool.model_dump()}")

    # Test 7: Create resource URI
    print("\n[Test 7] ResourceUri:")
    resource = ResourceUri(
        uri="cwe://CWE-79",
        name="Improper Neutralization of Input During Web Page Generation",
        mime_type="application/json"
    )
    print(f"✓ Created: {resource.model_dump()}")

    # Test 8: JSON serialization
    print("\n[Test 8] JSON Serialization:")
    request_dict = request.model_dump()
    json_str = json.dumps(request_dict, indent=2)
    print(f"✓ Serialized to JSON:\n{json_str}")

    # Test 9: Request metadata
    print("\n[Test 9] RequestMetadata:")
    metadata = RequestMetadata(
        request_id="req-001",
        method=RequestMethod.CALL_TOOL,
        client_info={"name": "HyFuzz", "version": "1.0"}
    )
    print(f"✓ Created: {metadata.model_dump()}")

    # Test 10: Response metadata
    print("\n[Test 10] ResponseMetadata:")
    resp_metadata = ResponseMetadata(
        response_id="resp-001",
        request_id="req-001",
        status_code=StatusCode.OK,
        duration_ms=45.5
    )
    print(f"✓ Created: {resp_metadata.model_dump()}")

    print("\n" + "=" * 70)
    print("ALL TESTS PASSED ✓")
    print("=" * 70)