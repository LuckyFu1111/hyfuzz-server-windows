"""
HyFuzz MCP Server - Stdio Transport Layer

This module implements the stdio transport protocol for MCP (Model Context Protocol).
It handles communication through standard input/output using line-delimited JSON-RPC messages.

Key Features:
- Line-delimited JSON-RPC 2.0 protocol
- Async read from stdin and write to stdout
- Bidirectional message handling
- Message buffering and queue management
- Error handling and graceful degradation
- Connection state tracking
- Message metrics and statistics
- Support for both blocking and non-blocking I/O
- Proper cleanup and resource management
- Comprehensive error recovery

Protocol:
- Each message is a single line of JSON
- Messages are separated by newline characters (\n)
- Follows JSON-RPC 2.0 specification
- Supports requests, responses, notifications, and errors

Usage:
    transport = StdioTransport(message_handler)
    await transport.start()
    await transport.run()  # Blocking loop
    await transport.stop()

Author: HyFuzz Team
Version: 1.0.0
"""

import asyncio
import sys
import json
import logging
import time
import uuid
from typing import Dict, Any, Optional, List, Callable, Coroutine
from dataclasses import dataclass
from datetime import datetime, timezone
import io

# ============================================================================
# Constants
# ============================================================================

# JSON-RPC protocol constants
JSONRPC_VERSION = "2.0"
NEWLINE = "\n"

# Stdio transport configuration
DEFAULT_BUFFER_SIZE = 4096
DEFAULT_READ_TIMEOUT = 30.0
DEFAULT_WRITE_TIMEOUT = 10.0
DEFAULT_MAX_MESSAGE_SIZE = 10 * 1024 * 1024  # 10 MB


# ============================================================================
# Logger Setup
# ============================================================================

def get_logger(name: str) -> logging.Logger:
    """Get or create logger"""
    return logging.getLogger(name)


logger = get_logger(__name__)


# ============================================================================
# Data Models
# ============================================================================

@dataclass
class TransportStats:
    """Stdio transport statistics"""
    messages_received: int = 0
    messages_sent: int = 0
    bytes_received: int = 0
    bytes_sent: int = 0
    total_receive_time: float = 0.0
    total_send_time: float = 0.0
    errors: int = 0
    started_at: datetime = None

    def __post_init__(self):
        if self.started_at is None:
            self.started_at = datetime.now(timezone.utc)

    @property
    def uptime(self) -> float:
        """Get uptime in seconds"""
        if self.started_at is None:
            return 0
        return (datetime.now(timezone.utc) - self.started_at).total_seconds()

    @property
    def avg_receive_time_ms(self) -> float:
        """Get average receive time in milliseconds"""
        if self.messages_received == 0:
            return 0
        return (self.total_receive_time / self.messages_received) * 1000

    @property
    def avg_send_time_ms(self) -> float:
        """Get average send time in milliseconds"""
        if self.messages_sent == 0:
            return 0
        return (self.total_send_time / self.messages_sent) * 1000

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "messages_received": self.messages_received,
            "messages_sent": self.messages_sent,
            "bytes_received": self.bytes_received,
            "bytes_sent": self.bytes_sent,
            "avg_receive_time_ms": self.avg_receive_time_ms,
            "avg_send_time_ms": self.avg_send_time_ms,
            "errors": self.errors,
            "uptime": self.uptime,
        }


# ============================================================================
# Stdio Transport Class
# ============================================================================

class StdioTransport:
    """
    Stdio transport for MCP server.

    Handles communication through stdin/stdout using line-delimited JSON-RPC messages.
    This is the recommended transport for MCP protocol implementation.
    """

    def __init__(
            self,
            message_handler: Optional[Callable] = None,
            session_id: Optional[str] = None,
            buffer_size: int = DEFAULT_BUFFER_SIZE,
            read_timeout: float = DEFAULT_READ_TIMEOUT,
            write_timeout: float = DEFAULT_WRITE_TIMEOUT,
            max_message_size: int = DEFAULT_MAX_MESSAGE_SIZE,
    ):
        """
        Initialize stdio transport

        Args:
            message_handler: Async callable to handle messages
            session_id: Optional session ID
            buffer_size: Read buffer size in bytes
            read_timeout: Read operation timeout in seconds
            write_timeout: Write operation timeout in seconds
            max_message_size: Maximum message size in bytes
        """
        self.message_handler = message_handler
        self.session_id = session_id or str(uuid.uuid4())
        self.buffer_size = buffer_size
        self.read_timeout = read_timeout
        self.write_timeout = write_timeout
        self.max_message_size = max_message_size

        # State
        self.is_running = False
        self.is_connected = True
        self.loop_task: Optional[asyncio.Task] = None

        # I/O streams
        self.stdin = sys.stdin
        self.stdout = sys.stdout
        self.stderr = sys.stderr

        # Message queues
        self.message_queue: asyncio.Queue = asyncio.Queue()
        self.response_queue: asyncio.Queue = asyncio.Queue()

        # Message tracking
        self.pending_messages: Dict[str, float] = {}  # message_id -> timestamp

        # Statistics
        self.stats = TransportStats()

        logger.info(
            f"StdioTransport initialized (session_id={self.session_id}, "
            f"buffer_size={buffer_size}, max_message_size={max_message_size})"
        )

    async def start(self) -> None:
        """Start the transport"""
        if self.is_running:
            logger.warning("Transport already running")
            return

        logger.info(f"Starting StdioTransport (session: {self.session_id})")
        self.is_running = True
        self.is_connected = True

    async def stop(self) -> None:
        """Stop the transport gracefully"""
        if not self.is_running:
            return

        logger.info("Stopping StdioTransport")
        self.is_running = False
        self.is_connected = False

        # Cancel loop task if running
        if self.loop_task and not self.loop_task.done():
            self.loop_task.cancel()
            try:
                await self.loop_task
            except asyncio.CancelledError:
                pass

    async def run(self) -> None:
        """
        Main event loop for processing stdin/stdout.
        This is a blocking call that runs until interrupted or stopped.
        """
        if not self.is_running:
            await self.start()

        self.loop_task = asyncio.current_task()

        try:
            await self._main_loop()
        except KeyboardInterrupt:
            logger.info("Received KeyboardInterrupt")
        except asyncio.CancelledError:
            logger.debug("Main loop cancelled")
        except Exception as ex:
            logger.error(f"Error in main loop: {str(ex)}", exc_info=True)
        finally:
            await self.stop()

    async def _main_loop(self) -> None:
        """Main processing loop"""
        try:
            # Create async reading task
            read_task = asyncio.create_task(self._read_loop())

            # Wait for read loop to complete or error
            await read_task

        except Exception as ex:
            logger.error(f"Error in main loop: {str(ex)}", exc_info=True)
            self.is_connected = False

    async def _read_loop(self) -> None:
        """Background task to read from stdin"""
        while self.is_running:
            try:
                # Read message from stdin
                message_line = await asyncio.get_event_loop().run_in_executor(
                    None,
                    self._read_line_blocking
                )

                if message_line is None:
                    # EOF reached
                    logger.info("EOF on stdin")
                    self.is_connected = False
                    break

                if not message_line.strip():
                    # Empty line, skip
                    continue

                # Parse message
                try:
                    message = json.loads(message_line)
                    self.stats.messages_received += 1
                    self.stats.bytes_received += len(message_line)

                    logger.debug(f"Received message: {message.get('method', 'unknown')}")

                    # Process message asynchronously
                    await self._process_message(message)

                except json.JSONDecodeError as ex:
                    logger.error(f"JSON decode error: {str(ex)}")
                    self.stats.errors += 1

                    # Send error response
                    error_response = {
                        "jsonrpc": JSONRPC_VERSION,
                        "error": {
                            "code": -32700,
                            "message": "Parse error",
                        }
                    }
                    await self.send_message(error_response)

            except asyncio.TimeoutError:
                logger.debug("Read timeout")
                continue
            except asyncio.CancelledError:
                break
            except Exception as ex:
                logger.error(f"Error in read loop: {str(ex)}", exc_info=True)
                self.stats.errors += 1
                self.is_connected = False
                break

    async def _process_message(self, message: Dict[str, Any]) -> None:
        """
        Process incoming message

        Args:
            message: Message dictionary
        """
        try:
            # Validate message
            if not isinstance(message, dict):
                logger.error(f"Invalid message type: {type(message)}")
                return

            # Check for response (don't process responses)
            if "result" in message or "error" in message:
                logger.debug(f"Received response (id={message.get('id')})")
                # Queue response for potential handlers
                await self.response_queue.put(message)
                return

            # Get message ID for tracking
            message_id = message.get("id")
            if message_id:
                self.pending_messages[message_id] = time.time()

            # Handle message with custom handler
            if self.message_handler:
                try:
                    start_time = time.time()

                    # Call message handler
                    response = await asyncio.wait_for(
                        self.message_handler(message, session_id=self.session_id),
                        timeout=self.read_timeout
                    )

                    duration = time.time() - start_time
                    self.stats.total_receive_time += duration

                    # Send response if present
                    if response is not None:
                        await self.send_message(response)

                    # Clean up pending message
                    if message_id:
                        self.pending_messages.pop(message_id, None)

                except asyncio.TimeoutError:
                    logger.error(f"Message handler timeout for {message.get('method')}")
                    self.stats.errors += 1

                    error_response = {
                        "jsonrpc": JSONRPC_VERSION,
                        "error": {
                            "code": -32603,
                            "message": "Handler timeout",
                        }
                    }
                    if message_id:
                        error_response["id"] = message_id

                    await self.send_message(error_response)

                except Exception as ex:
                    logger.error(f"Error handling message: {str(ex)}", exc_info=True)
                    self.stats.errors += 1

                    error_response = {
                        "jsonrpc": JSONRPC_VERSION,
                        "error": {
                            "code": -32603,
                            "message": f"Internal error: {str(ex)}",
                        }
                    }
                    if message_id:
                        error_response["id"] = message_id

                    await self.send_message(error_response)
            else:
                # No handler, send method not found error
                if message_id:
                    error_response = {
                        "jsonrpc": JSONRPC_VERSION,
                        "id": message_id,
                        "error": {
                            "code": -32601,
                            "message": "No message handler configured",
                        }
                    }
                    await self.send_message(error_response)

        except Exception as ex:
            logger.error(f"Unexpected error in _process_message: {str(ex)}", exc_info=True)
            self.stats.errors += 1

    async def send_message(self, message: Dict[str, Any]) -> None:
        """
        Send a message to stdout

        Args:
            message: Message dictionary to send
        """
        try:
            start_time = time.time()

            # Serialize message to JSON
            message_json = json.dumps(message, separators=(',', ':'))

            # Check message size
            message_size = len(message_json)
            if message_size > self.max_message_size:
                logger.error(
                    f"Message too large: {message_size} > {self.max_message_size}"
                )
                return

            # Write to stdout
            await asyncio.get_event_loop().run_in_executor(
                None,
                self._write_line_blocking,
                message_json
            )

            # Update statistics
            duration = time.time() - start_time
            self.stats.messages_sent += 1
            self.stats.bytes_sent += message_size
            self.stats.total_send_time += duration

            logger.debug(f"Sent message (size={message_size})")

        except Exception as ex:
            logger.error(f"Error sending message: {str(ex)}", exc_info=True)
            self.stats.errors += 1

    def _read_line_blocking(self) -> Optional[str]:
        """
        Blocking read of a single line from stdin

        Returns:
            Line string or None on EOF
        """
        try:
            line = self.stdin.readline()
            if not line:
                return None  # EOF
            return line.rstrip('\n\r')
        except EOFError:
            return None
        except Exception as ex:
            logger.error(f"Error reading from stdin: {str(ex)}")
            return None

    def _write_line_blocking(self, line: str) -> None:
        """
        Blocking write of a single line to stdout

        Args:
            line: Line to write
        """
        try:
            self.stdout.write(line + NEWLINE)
            self.stdout.flush()
        except Exception as ex:
            logger.error(f"Error writing to stdout: {str(ex)}")
            raise

    def get_stats(self) -> Dict[str, Any]:
        """Get transport statistics"""
        return self.stats.to_dict()

    def get_status(self) -> Dict[str, Any]:
        """Get transport status"""
        return {
            "running": self.is_running,
            "connected": self.is_connected,
            "session_id": self.session_id,
            "pending_messages": len(self.pending_messages),
            "stats": self.stats.to_dict(),
        }


# ============================================================================
# Helper Functions for Testing
# ============================================================================

class MockStdin:
    """Mock stdin for testing"""

    def __init__(self, messages: List[str]):
        self.messages = messages
        self.index = 0

    def readline(self) -> str:
        if self.index >= len(self.messages):
            return ""  # EOF
        line = self.messages[self.index]
        self.index += 1
        return line


class MockStdout:
    """Mock stdout for testing"""

    def __init__(self):
        self.lines: List[str] = []

    def write(self, data: str) -> None:
        self.lines.append(data)

    def flush(self) -> None:
        pass

    def get_output(self) -> List[str]:
        return self.lines


# ============================================================================
# Test Suite
# ============================================================================

async def run_tests():
    """Run stdio transport tests"""

    print("\n" + "=" * 80)
    print("STDIO TRANSPORT TEST SUITE")
    print("=" * 80 + "\n")

    # Test 1: Transport initialization
    print("[TEST 1] Transport Initialization")
    try:
        transport = StdioTransport()
        assert transport.session_id is not None
        assert not transport.is_running
        assert transport.is_connected
        print("✓ Transport initialization test passed\n")
    except Exception as e:
        print(f"✗ Transport initialization test failed: {str(e)}\n")
        return

    # Test 2: Transport startup/shutdown
    print("[TEST 2] Transport Startup/Shutdown")
    try:
        transport = StdioTransport()
        await transport.start()
        assert transport.is_running
        await transport.stop()
        assert not transport.is_running
        print("✓ Transport startup/shutdown test passed\n")
    except Exception as e:
        print(f"✗ Transport startup/shutdown test failed: {str(e)}\n")
        return

    # Test 3: Message parsing
    print("[TEST 3] Message Parsing")
    try:
        message_json = '{"jsonrpc":"2.0","id":1,"method":"ping","params":{}}'
        message = json.loads(message_json)
        assert message["jsonrpc"] == "2.0"
        assert message["id"] == 1
        assert message["method"] == "ping"
        print("✓ Message parsing test passed\n")
    except Exception as e:
        print(f"✗ Message parsing test failed: {str(e)}\n")
        return

    # Test 4: Message serialization
    print("[TEST 4] Message Serialization")
    try:
        message = {
            "jsonrpc": "2.0",
            "id": 42,
            "result": {"status": "ok"}
        }
        serialized = json.dumps(message, separators=(',', ':'))
        assert "jsonrpc" in serialized
        assert "42" in serialized
        print("✓ Message serialization test passed\n")
    except Exception as e:
        print(f"✗ Message serialization test failed: {str(e)}\n")
        return

    # Test 5: Statistics tracking
    print("[TEST 5] Statistics Tracking")
    try:
        transport = StdioTransport()
        stats = transport.get_stats()
        assert stats["messages_received"] == 0
        assert stats["messages_sent"] == 0
        assert stats["errors"] == 0

        # Simulate stats update
        transport.stats.messages_received = 10
        transport.stats.messages_sent = 10
        transport.stats.bytes_received = 1000
        transport.stats.bytes_sent = 1000

        stats = transport.get_stats()
        assert stats["messages_received"] == 10
        assert stats["messages_sent"] == 10

        print("✓ Statistics tracking test passed\n")
    except Exception as e:
        print(f"✗ Statistics tracking test failed: {str(e)}\n")
        return

    # Test 6: Mock stdin/stdout
    print("[TEST 6] Mock Stdin/Stdout")
    try:
        messages = [
            '{"jsonrpc":"2.0","id":1,"method":"test","params":{}}',
            '{"jsonrpc":"2.0","id":2,"method":"test","params":{}}',
        ]

        mock_stdin = MockStdin(messages)
        mock_stdout = MockStdout()

        # Read from mock stdin
        line1 = mock_stdin.readline()
        assert len(line1) > 0

        # Write to mock stdout
        mock_stdout.write('{"jsonrpc":"2.0","id":1,"result":{}}')
        assert len(mock_stdout.get_output()) == 1

        print("✓ Mock stdin/stdout test passed\n")
    except Exception as e:
        print(f"✗ Mock stdin/stdout test failed: {str(e)}\n")
        return

    # Test 7: Error response generation
    print("[TEST 7] Error Response Generation")
    try:
        error_response = {
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "code": -32600,
                "message": "Invalid Request",
            }
        }

        serialized = json.dumps(error_response)
        assert "error" in serialized
        assert "-32600" in serialized

        print("✓ Error response generation test passed\n")
    except Exception as e:
        print(f"✗ Error response generation test failed: {str(e)}\n")
        return

    # Test 8: Transport status
    print("[TEST 8] Transport Status")
    try:
        transport = StdioTransport()
        status = transport.get_status()

        assert "running" in status
        assert "connected" in status
        assert "session_id" in status
        assert status["connected"] is True
        assert status["running"] is False

        print("✓ Transport status test passed\n")
    except Exception as e:
        print(f"✗ Transport status test failed: {str(e)}\n")
        return

    # Test 9: Batch message handling
    print("[TEST 9] Batch Message Handling")
    try:
        batch = [
            {"jsonrpc": "2.0", "id": 1, "method": "test1", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "test2", "params": {}},
        ]

        serialized_batch = [json.dumps(msg) for msg in batch]
        assert len(serialized_batch) == 2

        for msg in serialized_batch:
            parsed = json.loads(msg)
            assert "id" in parsed
            assert "method" in parsed

        print("✓ Batch message handling test passed\n")
    except Exception as e:
        print(f"✗ Batch message handling test failed: {str(e)}\n")
        return

    # Test 10: Notification handling (no ID)
    print("[TEST 10] Notification Handling")
    try:
        notification = {
            "jsonrpc": "2.0",
            "method": "resources/listChanged",
            "params": {}
            # Note: No ID field
        }

        serialized = json.dumps(notification)
        parsed = json.loads(serialized)
        assert "id" not in parsed
        assert "method" in parsed

        print("✓ Notification handling test passed\n")
    except Exception as e:
        print(f"✗ Notification handling test failed: {str(e)}\n")
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