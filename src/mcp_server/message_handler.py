"""
HyFuzz MCP Server - Message Handler

This module implements the core message handling logic for the MCP (Model Context Protocol) server.
It processes incoming JSON-RPC 2.0 messages, routes them to appropriate handlers, and returns
formatted responses following the MCP protocol specification.

Key Features:
- Full JSON-RPC 2.0 protocol compliance
- Request/response message handling with ID tracking
- Notification message support (messages without ID)
- Batch message processing
- Comprehensive error handling with standard error codes
- Request validation and parameter extraction
- Method routing and dispatch
- Session-aware message processing
- Message logging and debugging
- Timeout handling for long-running operations

Author: HyFuzz Team
Version: 1.0.0
"""

import asyncio
import json
import logging
import uuid
import time
from typing import Dict, Any, Optional, List, Callable, Coroutine, Union
from dataclasses import dataclass, asdict
from enum import Enum
from datetime import datetime, timezone
from functools import wraps

# Optional imports with fallbacks for compatibility
try:
    from pydantic import BaseModel, Field, validator
except ImportError:
    # Create mock classes if pydantic is not available
    class BaseModel:
        pass


    class Field:
        def __init__(self, **kwargs):
            pass

        def __call__(self, **kwargs):
            return self

# ============================================================================
# Constants and Enumerations
# ============================================================================

# JSON-RPC 2.0 Constants
JSONRPC_VERSION = "2.0"
PROTOCOL_VERSION = "2024-11-05"


# Standard Error Codes (per JSON-RPC 2.0 specification)
class ErrorCode(Enum):
    """Standard JSON-RPC 2.0 error codes"""
    PARSE_ERROR = -32700
    INVALID_REQUEST = -32600
    METHOD_NOT_FOUND = -32601
    INVALID_PARAMS = -32602
    INTERNAL_ERROR = -32603
    SERVER_ERROR_START = -32099
    SERVER_ERROR_END = -32000
    CUSTOM_ERROR = -1


# Message Types
class MessageType(Enum):
    """MCP message types"""
    REQUEST = "request"
    RESPONSE = "response"
    NOTIFICATION = "notification"
    ERROR = "error"
    BATCH = "batch"


# ============================================================================
# Data Models
# ============================================================================

@dataclass
class MCPError:
    """MCP error response data"""
    code: int
    message: str
    data: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert error to dictionary"""
        error_dict = {
            "code": self.code,
            "message": self.message,
        }
        if self.data:
            error_dict["data"] = self.data
        return error_dict


@dataclass
class MCPMessage:
    """
    Represents a single MCP message.
    Can be a request, response, notification, or error.
    """
    jsonrpc: str = JSONRPC_VERSION
    method: Optional[str] = None
    params: Dict[str, Any] = None
    result: Optional[Any] = None
    error: Optional[MCPError] = None
    id: Optional[Union[int, str]] = None
    message_type: MessageType = MessageType.REQUEST

    def __post_init__(self):
        """Validate message after initialization"""
        if self.params is None:
            self.params = {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert message to dictionary for JSON serialization"""
        message_dict = {"jsonrpc": self.jsonrpc}

        if self.method:
            message_dict["method"] = self.method

        if self.params:
            message_dict["params"] = self.params

        if self.result is not None:
            message_dict["result"] = self.result

        if self.error:
            message_dict["error"] = self.error.to_dict()

        if self.id is not None:
            message_dict["id"] = self.id

        return message_dict

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "MCPMessage":
        """Create MCPMessage from dictionary"""
        message = MCPMessage(
            jsonrpc=data.get("jsonrpc", JSONRPC_VERSION),
            method=data.get("method"),
            params=data.get("params", {}),
            result=data.get("result"),
            id=data.get("id"),
        )

        if "error" in data and data["error"]:
            error_data = data["error"]
            message.error = MCPError(
                code=error_data.get("code", ErrorCode.INTERNAL_ERROR.value),
                message=error_data.get("message", "Unknown error"),
                data=error_data.get("data"),
            )
            message.message_type = MessageType.ERROR
        elif "result" in data:
            message.message_type = MessageType.RESPONSE
        elif message.method:
            if message.id is None:
                message.message_type = MessageType.NOTIFICATION
            else:
                message.message_type = MessageType.REQUEST

        return message


@dataclass
class MessageMetrics:
    """Metrics for message processing"""
    message_id: str
    method: str
    start_time: float
    end_time: Optional[float] = None
    request_size: int = 0
    response_size: int = 0
    status: str = "pending"
    error: Optional[str] = None

    @property
    def duration(self) -> float:
        """Get processing duration in milliseconds"""
        if self.end_time is None:
            return (time.time() - self.start_time) * 1000
        return (self.end_time - self.start_time) * 1000


# ============================================================================
# Utility Functions
# ============================================================================

def create_error_response(
        error_code: int,
        error_message: str,
        request_id: Optional[Union[int, str]] = None,
        error_data: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Create a properly formatted error response

    Args:
        error_code: Error code (from ErrorCode enum)
        error_message: Human-readable error message
        request_id: Original request ID if available
        error_data: Additional error data

    Returns:
        Error response dictionary
    """
    response = {
        "jsonrpc": JSONRPC_VERSION,
        "error": {
            "code": error_code,
            "message": error_message,
        }
    }

    if error_data:
        response["error"]["data"] = error_data

    if request_id is not None:
        response["id"] = request_id

    return response


def validate_jsonrpc_message(data: Dict[str, Any]) -> tuple[bool, Optional[Dict[str, Any]]]:
    """
    Validate JSON-RPC 2.0 message format

    Args:
        data: Message data to validate

    Returns:
        Tuple of (is_valid, error_response_or_none)
    """
    # Check jsonrpc field
    if data.get("jsonrpc") != JSONRPC_VERSION:
        return False, create_error_response(
            ErrorCode.INVALID_REQUEST.value,
            f"Invalid jsonrpc version. Expected '{JSONRPC_VERSION}'",
            data.get("id"),
        )

    # Check for method (required for requests and notifications)
    if "method" not in data and "result" not in data and "error" not in data:
        return False, create_error_response(
            ErrorCode.INVALID_REQUEST.value,
            "Request must have 'method', 'result', or 'error' field",
            data.get("id"),
        )

    # If params exist, must be object or array
    if "params" in data and not isinstance(data["params"], (dict, list)):
        return False, create_error_response(
            ErrorCode.INVALID_PARAMS.value,
            "Params must be an object or array",
            data.get("id"),
        )

    return True, None


# ============================================================================
# Logger Setup
# ============================================================================

def get_logger(name: str) -> logging.Logger:
    """Get or create logger"""
    return logging.getLogger(name)


logger = get_logger(__name__)


# ============================================================================
# Message Handler Class
# ============================================================================

class MessageHandler:
    """
    Core message handler for MCP server.

    Handles JSON-RPC 2.0 message processing, method dispatch,
    and response formatting according to the MCP protocol.
    """

    def __init__(
            self,
            session_manager: Optional[Any] = None,
            capability_manager: Optional[Any] = None,
            llm_service: Optional[Any] = None,
            default_timeout: float = 30.0,
    ):
        """
        Initialize message handler

        Args:
            session_manager: Session manager instance
            capability_manager: Capability manager instance
            llm_service: LLM service instance
            default_timeout: Default timeout for operations (seconds)
        """
        self.session_manager = session_manager
        self.capability_manager = capability_manager
        self.llm_service = llm_service
        self.default_timeout = default_timeout

        # Message handlers registry
        self.handlers: Dict[str, Callable] = {}
        self.metrics: List[MessageMetrics] = []

        # Register default handlers
        self._register_default_handlers()

        logger.info("MessageHandler initialized")

    def _register_default_handlers(self) -> None:
        """Register built-in MCP method handlers"""
        self.handlers = {
            # Core methods
            "initialize": self._handle_initialize,
            "shutdown": self._handle_shutdown,
            "ping": self._handle_ping,

            # Resource methods
            "resources/list": self._handle_list_resources,
            "resources/read": self._handle_read_resource,
            "resources/listChanged": self._handle_resources_changed,

            # Tool methods
            "tools/list": self._handle_list_tools,
            "tools/call": self._handle_call_tool,
            "tools/listChanged": self._handle_tools_changed,

            # Prompt methods
            "prompts/list": self._handle_list_prompts,
            "prompts/get": self._handle_get_prompt,
            "prompts/listChanged": self._handle_prompts_changed,

            # Session methods
            "session/info": self._handle_session_info,
            "session/end": self._handle_end_session,

            # Completion methods
            "completion/complete": self._handle_completion,

            # Capability methods
            "capabilities/list": self._handle_list_capabilities,
        }
        logger.debug(f"Registered {len(self.handlers)} default method handlers")

    def register_handler(
            self,
            method: str,
            handler: Callable,
            override: bool = False,
    ) -> None:
        """
        Register a custom method handler

        Args:
            method: Method name
            handler: Handler function
            override: Whether to override existing handler

        Raises:
            ValueError: If handler already exists and override is False
        """
        if method in self.handlers and not override:
            raise ValueError(f"Handler for '{method}' already registered")

        self.handlers[method] = handler
        logger.debug(f"Registered handler for method: {method}")

    async def handle_message(
            self,
            message_data: Union[Dict[str, Any], List[Dict[str, Any]]],
            session_id: Optional[str] = None,
    ) -> Union[Dict[str, Any], List[Dict[str, Any]], None]:
        """
        Handle incoming MCP message(s)

        Args:
            message_data: Single message or batch of messages
            session_id: Associated session ID

        Returns:
            Response message(s) or None for notifications without response
        """
        try:
            # Handle batch messages
            if isinstance(message_data, list):
                return await self._handle_batch(message_data, session_id)

            # Handle single message
            if not isinstance(message_data, dict):
                logger.error(f"Invalid message format: {type(message_data)}")
                return create_error_response(
                    ErrorCode.PARSE_ERROR.value,
                    "Message must be a JSON object",
                )

            return await self._handle_single_message(message_data, session_id)

        except Exception as ex:
            logger.error(f"Error handling message: {str(ex)}", exc_info=True)
            return create_error_response(
                ErrorCode.INTERNAL_ERROR.value,
                f"Internal server error: {str(ex)}",
            )

    async def _handle_batch(
            self,
            messages: List[Dict[str, Any]],
            session_id: Optional[str],
    ) -> List[Dict[str, Any]]:
        """Handle batch of messages"""
        if not messages:
            return create_error_response(
                ErrorCode.INVALID_REQUEST.value,
                "Batch request is empty",
            )

        logger.debug(f"Processing batch of {len(messages)} messages")

        responses = []
        tasks = []

        for message_data in messages:
            task = self._handle_single_message(message_data, session_id)
            tasks.append(task)

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if result is not None:  # Skip notification responses
                if isinstance(result, Exception):
                    logger.error(f"Error in batch message: {str(result)}")
                    responses.append(
                        create_error_response(
                            ErrorCode.INTERNAL_ERROR.value,
                            str(result),
                        )
                    )
                else:
                    responses.append(result)

        return responses if responses else None

    async def _handle_single_message(
            self,
            message_data: Dict[str, Any],
            session_id: Optional[str],
    ) -> Optional[Dict[str, Any]]:
        """Handle single message"""
        message_id = str(uuid.uuid4())
        start_time = time.time()

        try:
            # Validate message format
            is_valid, error_response = validate_jsonrpc_message(message_data)
            if not is_valid:
                logger.warning(f"Invalid message format: {error_response}")
                return error_response

            # Parse message
            message = MCPMessage.from_dict(message_data)
            request_size = len(json.dumps(message_data))

            logger.debug(
                f"Processing {message.message_type.value} message: "
                f"method={message.method}, id={message.id}"
            )

            # Create metrics
            metrics = MessageMetrics(
                message_id=message_id,
                method=message.method or "unknown",
                start_time=start_time,
                request_size=request_size,
            )

            # Handle different message types
            if message.message_type == MessageType.REQUEST:
                response = await self._process_request(message, session_id)
            elif message.message_type == MessageType.NOTIFICATION:
                # Process notification but don't return response
                await self._process_request(message, session_id)
                response = None
            elif message.message_type == MessageType.RESPONSE:
                # Response messages are typically not handled here
                logger.debug(f"Received response message (id={message.id})")
                response = None
            elif message.message_type == MessageType.ERROR:
                logger.warning(f"Received error message: {message.error.message}")
                response = None
            else:
                response = create_error_response(
                    ErrorCode.INVALID_REQUEST.value,
                    "Unknown message type",
                    message.id,
                )

            # Record metrics
            metrics.end_time = time.time()
            if response:
                metrics.response_size = len(json.dumps(response))
                metrics.status = "success"
            else:
                metrics.status = "notification"

            self.metrics.append(metrics)
            self._cleanup_old_metrics()

            return response

        except Exception as ex:
            logger.error(f"Error processing message {message_id}: {str(ex)}", exc_info=True)
            return create_error_response(
                ErrorCode.INTERNAL_ERROR.value,
                f"Message processing error: {str(ex)}",
                message_data.get("id"),
            )

    async def _process_request(
            self,
            message: MCPMessage,
            session_id: Optional[str],
    ) -> Dict[str, Any]:
        """
        Process a request message and dispatch to appropriate handler

        Args:
            message: MCP message object
            session_id: Associated session ID

        Returns:
            Response message dictionary
        """
        # Check if method exists
        if message.method not in self.handlers:
            logger.warning(f"Method not found: {message.method}")
            return create_error_response(
                ErrorCode.METHOD_NOT_FOUND.value,
                f"Method '{message.method}' not found",
                message.id,
            )

        # Get handler
        handler = self.handlers[message.method]

        try:
            # Call handler with timeout
            result = await asyncio.wait_for(
                handler(message.params, session_id),
                timeout=self.default_timeout,
            )

            # Format response
            response = {
                "jsonrpc": JSONRPC_VERSION,
                "result": result,
            }

            if message.id is not None:
                response["id"] = message.id

            logger.debug(f"Method '{message.method}' succeeded")
            return response

        except asyncio.TimeoutError:
            logger.error(f"Method '{message.method}' timed out")
            return create_error_response(
                ErrorCode.SERVER_ERROR_START.value,
                f"Method '{message.method}' timed out",
                message.id,
            )

        except TypeError as ex:
            logger.error(f"Invalid parameters for '{message.method}': {str(ex)}")
            return create_error_response(
                ErrorCode.INVALID_PARAMS.value,
                f"Invalid parameters: {str(ex)}",
                message.id,
            )

        except Exception as ex:
            logger.error(
                f"Error executing method '{message.method}': {str(ex)}",
                exc_info=True
            )
            return create_error_response(
                ErrorCode.INTERNAL_ERROR.value,
                f"Error executing method: {str(ex)}",
                message.id,
            )

    # ========================================================================
    # Default Handler Implementations
    # ========================================================================

    async def _handle_initialize(self, params: Dict, session_id: Optional[str]) -> Dict:
        """Handle initialize method"""
        logger.info("Server initialization request received")
        return {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {
                "resources": {"listChanged": True},
                "tools": {"listChanged": True},
                "prompts": {"listChanged": True},
            },
            "serverInfo": {
                "name": "hyfuzz-mcp-server",
                "version": "1.0.0",
            }
        }

    async def _handle_shutdown(self, params: Dict, session_id: Optional[str]) -> Dict:
        """Handle shutdown method"""
        logger.info("Server shutdown request received")
        return {"status": "shutting_down"}

    async def _handle_ping(self, params: Dict, session_id: Optional[str]) -> Dict:
        """Handle ping/health check"""
        return {
            "status": "pong",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    async def _handle_list_resources(self, params: Dict, session_id: Optional[str]) -> List:
        """Handle list resources method"""
        logger.debug("Listing resources")
        return []

    async def _handle_read_resource(self, params: Dict, session_id: Optional[str]) -> Dict:
        """Handle read resource method"""
        uri = params.get("uri")
        logger.debug(f"Reading resource: {uri}")
        return {"uri": uri, "contents": []}

    async def _handle_resources_changed(self, params: Dict, session_id: Optional[str]) -> None:
        """Handle resources changed notification"""
        logger.debug("Resources changed")
        return None

    async def _handle_list_tools(self, params: Dict, session_id: Optional[str]) -> List:
        """Handle list tools method"""
        logger.debug("Listing tools")
        return []

    async def _handle_call_tool(self, params: Dict, session_id: Optional[str]) -> Dict:
        """Handle tool call method"""
        name = params.get("name")
        tool_params = params.get("arguments", {})
        logger.debug(f"Calling tool: {name} with params: {tool_params}")
        return {"name": name, "result": {}}

    async def _handle_tools_changed(self, params: Dict, session_id: Optional[str]) -> None:
        """Handle tools changed notification"""
        logger.debug("Tools changed")
        return None

    async def _handle_list_prompts(self, params: Dict, session_id: Optional[str]) -> List:
        """Handle list prompts method"""
        logger.debug("Listing prompts")
        return []

    async def _handle_get_prompt(self, params: Dict, session_id: Optional[str]) -> Dict:
        """Handle get prompt method"""
        name = params.get("name")
        logger.debug(f"Getting prompt: {name}")
        return {"name": name, "description": "", "arguments": []}

    async def _handle_prompts_changed(self, params: Dict, session_id: Optional[str]) -> None:
        """Handle prompts changed notification"""
        logger.debug("Prompts changed")
        return None

    async def _handle_session_info(self, params: Dict, session_id: Optional[str]) -> Dict:
        """Handle session info method"""
        return {
            "sessionId": session_id or "unknown",
            "createdAt": datetime.now(timezone.utc).isoformat(),
        }

    async def _handle_end_session(self, params: Dict, session_id: Optional[str]) -> Dict:
        """Handle end session method"""
        logger.info(f"Ending session: {session_id}")
        return {"status": "ended", "sessionId": session_id}

    async def _handle_completion(self, params: Dict, session_id: Optional[str]) -> Dict:
        """Handle completion method"""
        partial = params.get("partial")
        logger.debug(f"Requesting completion for: {partial}")
        return {"completions": []}

    async def _handle_list_capabilities(self, params: Dict, session_id: Optional[str]) -> Dict:
        """Handle list capabilities method"""
        return {
            "resources": True,
            "tools": True,
            "prompts": True,
        }

    # ========================================================================
    # Utility Methods
    # ========================================================================

    def _cleanup_old_metrics(self, max_metrics: int = 1000) -> None:
        """Remove old metrics to prevent memory bloat"""
        if len(self.metrics) > max_metrics:
            self.metrics = self.metrics[-max_metrics:]

    def get_metrics(self) -> List[MessageMetrics]:
        """Get all recorded metrics"""
        return self.metrics.copy()

    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get summary of message metrics"""
        if not self.metrics:
            return {
                "total_messages": 0,
                "total_time_ms": 0,
                "avg_time_ms": 0,
            }

        total_time = sum(m.duration for m in self.metrics)
        avg_time = total_time / len(self.metrics) if self.metrics else 0

        return {
            "total_messages": len(self.metrics),
            "total_time_ms": total_time,
            "avg_time_ms": avg_time,
            "by_method": self._group_metrics_by_method(),
        }

    def _group_metrics_by_method(self) -> Dict[str, Dict[str, Any]]:
        """Group metrics by method"""
        grouped = {}
        for metric in self.metrics:
            if metric.method not in grouped:
                grouped[metric.method] = {
                    "count": 0,
                    "total_time_ms": 0,
                    "errors": 0,
                }
            grouped[metric.method]["count"] += 1
            grouped[metric.method]["total_time_ms"] += metric.duration
            if metric.status == "error":
                grouped[metric.method]["errors"] += 1

        return grouped


# ============================================================================
# Test Suite
# ============================================================================

async def run_tests():
    """Run message handler tests"""

    print("\n" + "=" * 80)
    print("MESSAGE HANDLER TEST SUITE")
    print("=" * 80 + "\n")

    # Test 1: Message validation
    print("[TEST 1] JSON-RPC Message Validation")
    try:
        # Valid message
        valid_msg = {
            "jsonrpc": "2.0",
            "method": "ping",
            "id": 1,
        }
        is_valid, error = validate_jsonrpc_message(valid_msg)
        assert is_valid, "Valid message failed validation"

        # Invalid jsonrpc version
        invalid_msg = {
            "jsonrpc": "1.0",
            "method": "ping",
            "id": 1,
        }
        is_valid, error = validate_jsonrpc_message(invalid_msg)
        assert not is_valid, "Invalid message passed validation"
        assert error is not None, "No error returned for invalid message"

        print("✓ Message validation test passed\n")
    except Exception as e:
        print(f"✗ Message validation test failed: {str(e)}\n")
        return

    # Test 2: Message parsing
    print("[TEST 2] MCP Message Parsing")
    try:
        message_data = {
            "jsonrpc": "2.0",
            "method": "tools/list",
            "params": {"filter": "test"},
            "id": 42,
        }
        message = MCPMessage.from_dict(message_data)
        assert message.method == "tools/list"
        assert message.params == {"filter": "test"}
        assert message.id == 42
        assert message.message_type == MessageType.REQUEST

        print("✓ Message parsing test passed\n")
    except Exception as e:
        print(f"✗ Message parsing test failed: {str(e)}\n")
        return

    # Test 3: Error response creation
    print("[TEST 3] Error Response Creation")
    try:
        error_response = create_error_response(
            ErrorCode.METHOD_NOT_FOUND.value,
            "Method 'invalid_method' not found",
            request_id=123,
        )
        assert error_response["jsonrpc"] == JSONRPC_VERSION
        assert error_response["id"] == 123
        assert error_response["error"]["code"] == ErrorCode.METHOD_NOT_FOUND.value
        assert error_response["error"]["message"] == "Method 'invalid_method' not found"

        print("✓ Error response creation test passed\n")
    except Exception as e:
        print(f"✗ Error response creation test failed: {str(e)}\n")
        return

    # Test 4: Handler registration and dispatch
    print("[TEST 4] Handler Registration and Dispatch")
    try:
        handler = MessageHandler()

        # Check default handlers are registered
        assert "ping" in handler.handlers, "ping handler not registered"
        assert "initialize" in handler.handlers, "initialize handler not registered"
        assert "tools/list" in handler.handlers, "tools/list handler not registered"

        # Register custom handler
        async def custom_handler(params, session_id):
            return {"custom": "response"}

        handler.register_handler("custom/method", custom_handler)
        assert "custom/method" in handler.handlers

        print("✓ Handler registration test passed\n")
    except Exception as e:
        print(f"✗ Handler registration test failed: {str(e)}\n")
        return

    # Test 5: Single message handling
    print("[TEST 5] Single Message Handling")
    try:
        handler = MessageHandler()

        ping_message = {
            "jsonrpc": "2.0",
            "method": "ping",
            "id": 1,
        }

        response = await handler.handle_message(ping_message)
        assert response is not None, "No response received"
        assert response["jsonrpc"] == JSONRPC_VERSION
        assert response["id"] == 1
        assert "result" in response

        print("✓ Single message handling test passed\n")
    except Exception as e:
        print(f"✗ Single message handling test failed: {str(e)}\n")
        return

    # Test 6: Notification message handling
    print("[TEST 6] Notification Message Handling")
    try:
        handler = MessageHandler()

        notification = {
            "jsonrpc": "2.0",
            "method": "resources/listChanged",
            "params": {},
            # Note: No ID field
        }

        response = await handler.handle_message(notification)
        # Notifications should not return a response
        assert response is None, "Notification should not return response"

        print("✓ Notification message handling test passed\n")
    except Exception as e:
        print(f"✗ Notification message handling test failed: {str(e)}\n")
        return

    # Test 7: Batch message handling
    print("[TEST 7] Batch Message Handling")
    try:
        handler = MessageHandler()

        batch_messages = [
            {
                "jsonrpc": "2.0",
                "method": "ping",
                "id": 1,
            },
            {
                "jsonrpc": "2.0",
                "method": "ping",
                "id": 2,
            },
        ]

        responses = await handler.handle_message(batch_messages)
        assert isinstance(responses, list), "Batch response should be list"
        assert len(responses) == 2, "Should return 2 responses"

        print("✓ Batch message handling test passed\n")
    except Exception as e:
        print(f"✗ Batch message handling test failed: {str(e)}\n")
        return

    # Test 8: Method not found handling
    print("[TEST 8] Method Not Found Error")
    try:
        handler = MessageHandler()

        invalid_method = {
            "jsonrpc": "2.0",
            "method": "nonexistent/method",
            "id": 99,
        }

        response = await handler.handle_message(invalid_method)
        assert "error" in response, "Should return error"
        assert response["error"]["code"] == ErrorCode.METHOD_NOT_FOUND.value
        assert response["id"] == 99

        print("✓ Method not found error test passed\n")
    except Exception as e:
        print(f"✗ Method not found error test failed: {str(e)}\n")
        return

    # Test 9: Metrics recording
    print("[TEST 9] Metrics Recording")
    try:
        handler = MessageHandler()

        # Process a message
        message = {
            "jsonrpc": "2.0",
            "method": "ping",
            "id": 1,
        }

        await handler.handle_message(message)

        # Check metrics
        metrics = handler.get_metrics()
        assert len(metrics) > 0, "No metrics recorded"

        summary = handler.get_metrics_summary()
        assert summary["total_messages"] > 0
        assert "ping" in summary["by_method"]

        print("✓ Metrics recording test passed\n")
    except Exception as e:
        print(f"✗ Metrics recording test failed: {str(e)}\n")
        return

    # Test 10: Message serialization
    print("[TEST 10] Message Serialization")
    try:
        message = MCPMessage(
            method="test/method",
            params={"key": "value"},
            id=42,
        )

        serialized = message.to_dict()
        assert serialized["jsonrpc"] == JSONRPC_VERSION
        assert serialized["method"] == "test/method"
        assert serialized["params"] == {"key": "value"}
        assert serialized["id"] == 42

        # Verify it's JSON serializable
        json_str = json.dumps(serialized)
        assert json_str is not None

        print("✓ Message serialization test passed\n")
    except Exception as e:
        print(f"✗ Message serialization test failed: {str(e)}\n")
        return

    print("=" * 80)
    print("ALL TESTS PASSED! ✓")
    print("=" * 80 + "\n")


# ============================================================================
# Main Entry Point
# ============================================================================

if __name__ == "__main__":
    """Run test suite when executed directly"""
    asyncio.run(run_tests())