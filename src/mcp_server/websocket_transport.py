"""
WebSocket Transport Layer for MCP Server.
Provides WebSocket-based communication for MCP protocol with support for
multiple concurrent connections, message routing, and connection lifecycle management.
"""

import asyncio
import json
import logging
import sys
from typing import Dict, List, Optional, Callable, Any, Set, Union
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import uuid
from pathlib import Path

try:
    import websockets
    # Handle both old and new websockets API versions to avoid deprecation warnings
    try:
        # Try newer API (websockets >= 10.0)
        from websockets.asyncio.server import ServerConnection as WebSocketServerProtocol
    except ImportError:
        try:
            # Fallback to older API (websockets < 10.0)
            from websockets.server import WebSocketServerProtocol
        except (ImportError, AttributeError):
            # Final fallback: use Any for type hints
            WebSocketServerProtocol = Any
except ImportError:
    raise ImportError("websockets package required. Install with: pip install websockets")

# Handle relative imports for both direct execution and package import
try:
    from .utils import (
        generate_message_id, get_timestamp, safe_json_dumps, safe_json_loads,
        validate_message_format, create_response_message, mask_sensitive_data
    )
except ImportError:
    # When running directly, add parent directory to path
    sys.path.insert(0, str(Path(__file__).parent))
    try:
        from utils import (
            generate_message_id, get_timestamp, safe_json_dumps, safe_json_loads,
            validate_message_format, create_response_message, mask_sensitive_data
        )
    except ImportError as e:
        print(f"Error: Could not import utils module: {e}")
        print("Make sure utils.py is in the same directory as this script")
        sys.exit(1)

logger = logging.getLogger(__name__)


@dataclass
class ConnectionMetadata:
    """Metadata for WebSocket connection"""
    client_id: str
    connection_time: datetime
    last_heartbeat: datetime = field(default_factory=datetime.utcnow)
    last_message_time: datetime = field(default_factory=datetime.utcnow)
    message_count: int = 0
    bytes_received: int = 0
    bytes_sent: int = 0
    remote_address: Optional[str] = None
    
    def update_activity(self):
        """Update last activity timestamp"""
        self.last_message_time = datetime.utcnow()
        self.message_count += 1
    
    def get_connection_duration(self) -> timedelta:
        """Get connection duration"""
        return datetime.utcnow() - self.connection_time
    
    def get_stats(self) -> Dict[str, Any]:
        """Get connection statistics"""
        return {
            "client_id": self.client_id,
            "connection_duration": str(self.get_connection_duration()),
            "message_count": self.message_count,
            "bytes_received": self.bytes_received,
            "bytes_sent": self.bytes_sent,
            "remote_address": self.remote_address
        }


class WebSocketTransport:
    """
    WebSocket transport implementation for MCP Server.
    
    Features:
        - Multiple concurrent WebSocket connections
        - Automatic connection tracking and cleanup
        - Message routing and broadcasting
        - Heartbeat/ping-pong mechanism
        - Connection lifecycle management
        - Graceful shutdown support
    """
    
    def __init__(self, host: str = "0.0.0.0", port: int = 8765, 
                 heartbeat_interval: float = 30.0, 
                 connection_timeout: float = 300.0,
                 max_message_size: int = 1024 * 1024):
        """
        Initialize WebSocket transport.
        
        Args:
            host: Bind host address
            port: Bind port number
            heartbeat_interval: Seconds between heartbeat messages
            connection_timeout: Seconds before timing out inactive connections
            max_message_size: Maximum allowed message size in bytes
        """
        self.host = host
        self.port = port
        self.heartbeat_interval = heartbeat_interval
        self.connection_timeout = connection_timeout
        self.max_message_size = max_message_size
        
        # Connection management
        self.connections: Dict[str, Any] = {}
        self.connection_metadata: Dict[str, ConnectionMetadata] = {}
        self.server = None
        self.is_running = False
        
        # Message handlers
        self.message_handlers: Dict[str, List[Callable]] = {
            "request": [],
            "notification": [],
            "any": []
        }
        
        # Callbacks
        self.on_client_connect: Optional[Callable[[str], None]] = None
        self.on_client_disconnect: Optional[Callable[[str], None]] = None
        self.on_error: Optional[Callable[[str, Exception], None]] = None
    
    def register_message_handler(self, message_type: str, 
                                handler: Callable[[str, Dict], None]) -> None:
        """
        Register a message handler.
        
        Args:
            message_type: Type of message ("request", "notification", "any")
            handler: Async callable that handles the message
        """
        if message_type not in self.message_handlers:
            self.message_handlers[message_type] = []
        self.message_handlers[message_type].append(handler)
        logger.info(f"Registered handler for message type: {message_type}")
    
    async def start(self) -> None:
        """
        Start WebSocket server.
        
        Raises:
            RuntimeError: If server fails to start
        """
        try:
            self.server = await websockets.serve(
                self._handle_client,
                self.host,
                self.port,
                max_size=self.max_message_size,
                compression=None
            )
            self.is_running = True
            logger.info(f"WebSocket server started on ws://{self.host}:{self.port}")
            
            # Start background tasks
            asyncio.create_task(self._heartbeat_loop())
            asyncio.create_task(self._connection_monitor_loop())
            
        except Exception as e:
            logger.error(f"Failed to start WebSocket server: {e}")
            raise RuntimeError(f"WebSocket server startup failed: {e}")
    
    async def stop(self) -> None:
        """
        Stop WebSocket server and close all connections.
        """
        logger.info("Shutting down WebSocket server...")
        self.is_running = False
        
        # Close all client connections
        for client_id in list(self.connections.keys()):
            await self._close_connection(client_id, "Server shutdown")
        
        # Close server
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        
        logger.info("WebSocket server stopped")
    
    async def _handle_client(self, websocket: Any, path: str) -> None:
        """
        Handle new WebSocket client connection.
        
        Args:
            websocket: WebSocket connection object
            path: Connection path
        """
        client_id = str(uuid.uuid4())
        remote_address = getattr(websocket, 'remote_address', None)
        if remote_address and isinstance(remote_address, tuple):
            remote_address = remote_address[0]
        else:
            remote_address = "unknown"
        
        try:
            # Register connection
            self.connections[client_id] = websocket
            metadata = ConnectionMetadata(
                client_id=client_id,
                connection_time=datetime.utcnow(),
                remote_address=remote_address
            )
            self.connection_metadata[client_id] = metadata
            
            logger.info(f"Client connected: {client_id} from {remote_address}")
            
            # Invoke connection callback
            if self.on_client_connect:
                try:
                    result = self.on_client_connect(client_id)
                    if asyncio.iscoroutine(result):
                        await result
                except Exception as e:
                    logger.error(f"Error in on_client_connect callback: {e}")
            
            # Send welcome message
            welcome = {
                "type": "notification",
                "id": generate_message_id(),
                "event": "connected",
                "data": {"client_id": client_id},
                "timestamp": get_timestamp()
            }
            await websocket.send(safe_json_dumps(welcome))
            
            # Message reception loop
            async for message in websocket:
                try:
                    await self._handle_message(client_id, message)
                except Exception as e:
                    logger.error(f"Error handling message from {client_id}: {e}")
                    if self.on_error:
                        try:
                            result = self.on_error(client_id, e)
                            if asyncio.iscoroutine(result):
                                await result
                        except Exception as err:
                            logger.error(f"Error in error handler: {err}")
        
        except websockets.exceptions.ConnectionClosed:
            logger.debug(f"Connection closed: {client_id}")
        except Exception as e:
            logger.error(f"Error in client handler for {client_id}: {e}")
            if self.on_error:
                try:
                    result = self.on_error(client_id, e)
                    if asyncio.iscoroutine(result):
                        await result
                except Exception as err:
                    logger.error(f"Error in error handler: {err}")
        
        finally:
            await self._close_connection(client_id, "Normal close")
    
    async def _handle_message(self, client_id: str, message_str: str) -> None:
        """
        Handle incoming message from client.
        
        Args:
            client_id: Client identifier
            message_str: Raw message string
        """
        # Parse message
        message = safe_json_loads(message_str)
        if not message:
            logger.warning(f"Invalid JSON from {client_id}")
            return
        
        # Validate format
        if not validate_message_format(message):
            logger.warning(f"Invalid message format from {client_id}")
            return
        
        # Update metadata
        metadata = self.connection_metadata.get(client_id)
        if metadata:
            metadata.update_activity()
            metadata.bytes_received += len(message_str.encode())
        
        logger.debug(f"Message from {client_id}: {mask_sensitive_data(message)}")
        
        # Route to handlers
        message_type = message.get("type")
        
        # Call type-specific handlers
        if message_type in self.message_handlers:
            for handler in self.message_handlers[message_type]:
                try:
                    result = handler(client_id, message)
                    if asyncio.iscoroutine(result):
                        await result
                except Exception as e:
                    logger.error(f"Error in message handler: {e}")
        
        # Call generic handlers
        for handler in self.message_handlers.get("any", []):
            try:
                result = handler(client_id, message)
                if asyncio.iscoroutine(result):
                    await result
            except Exception as e:
                logger.error(f"Error in generic handler: {e}")
    
    async def send_message(self, client_id: str, message: Dict[str, Any]) -> bool:
        """
        Send message to specific client.
        
        Args:
            client_id: Target client identifier
            message: Message dictionary to send
        
        Returns:
            bool: True if message sent successfully
        """
        websocket = self.connections.get(client_id)
        if not websocket:
            logger.warning(f"Client not found: {client_id}")
            return False
        
        try:
            message_str = safe_json_dumps(message)
            await websocket.send(message_str)
            
            # Update metadata
            metadata = self.connection_metadata.get(client_id)
            if metadata:
                metadata.bytes_sent += len(message_str.encode())
            
            return True
        except Exception as e:
            logger.error(f"Error sending message to {client_id}: {e}")
            return False
    
    async def broadcast_message(self, message: Dict[str, Any], 
                               exclude_client: Optional[str] = None) -> int:
        """
        Broadcast message to all connected clients.
        
        Args:
            message: Message dictionary to broadcast
            exclude_client: Optional client ID to exclude
        
        Returns:
            int: Number of clients the message was sent to
        """
        message_str = safe_json_dumps(message)
        sent_count = 0
        
        for client_id, websocket in self.connections.items():
            if exclude_client and client_id == exclude_client:
                continue
            
            try:
                await websocket.send(message_str)
                
                # Update metadata
                metadata = self.connection_metadata.get(client_id)
                if metadata:
                    metadata.bytes_sent += len(message_str.encode())
                
                sent_count += 1
            except Exception as e:
                logger.error(f"Error broadcasting to {client_id}: {e}")
        
        return sent_count
    
    async def send_response(self, client_id: str, request_id: str, 
                           result: Any = None, error: Optional[str] = None) -> bool:
        """
        Send response to client request.
        
        Args:
            client_id: Target client identifier
            request_id: ID of the request being responded to
            result: Response result data
            error: Error message if applicable
        
        Returns:
            bool: True if response sent successfully
        """
        response = create_response_message(request_id, result, error)
        return await self.send_message(client_id, response)
    
    async def _close_connection(self, client_id: str, reason: str = "Unknown") -> None:
        """
        Close connection with a client.
        
        Args:
            client_id: Client identifier
            reason: Reason for closure
        """
        websocket = self.connections.pop(client_id, None)
        metadata = self.connection_metadata.pop(client_id, None)
        
        if websocket:
            try:
                await websocket.close()
            except Exception as e:
                logger.debug(f"Error closing websocket: {e}")
        
        logger.info(f"Client disconnected: {client_id} ({reason})")
        
        # Invoke disconnect callback
        if self.on_client_disconnect:
            try:
                result = self.on_client_disconnect(client_id)
                if asyncio.iscoroutine(result):
                    await result
            except Exception as e:
                logger.error(f"Error in on_client_disconnect callback: {e}")
    
    async def _heartbeat_loop(self) -> None:
        """
        Send periodic heartbeat messages to all connected clients.
        """
        while self.is_running:
            try:
                await asyncio.sleep(self.heartbeat_interval)
                
                heartbeat = {
                    "type": "notification",
                    "id": generate_message_id(),
                    "event": "heartbeat",
                    "timestamp": get_timestamp()
                }
                
                await self.broadcast_message(heartbeat)
            except Exception as e:
                logger.error(f"Error in heartbeat loop: {e}")
    
    async def _connection_monitor_loop(self) -> None:
        """
        Monitor connections for timeouts and cleanup stale connections.
        """
        while self.is_running:
            try:
                await asyncio.sleep(60)  # Check every minute
                
                current_time = datetime.utcnow()
                stale_clients = []
                
                for client_id, metadata in self.connection_metadata.items():
                    idle_time = (current_time - metadata.last_message_time).total_seconds()
                    
                    if idle_time > self.connection_timeout:
                        stale_clients.append(client_id)
                
                # Close stale connections
                for client_id in stale_clients:
                    await self._close_connection(client_id, "Timeout")
                    logger.warning(f"Closed stale connection: {client_id}")
            
            except Exception as e:
                logger.error(f"Error in connection monitor loop: {e}")
    
    def get_connection_count(self) -> int:
        """
        Get number of active connections.
        
        Returns:
            int: Number of connected clients
        """
        return len(self.connections)
    
    def get_connected_clients(self) -> List[str]:
        """
        Get list of connected client IDs.
        
        Returns:
            list: List of client identifiers
        """
        return list(self.connections.keys())
    
    def get_connection_stats(self, client_id: str) -> Optional[Dict[str, Any]]:
        """
        Get statistics for a specific connection.
        
        Args:
            client_id: Client identifier
        
        Returns:
            dict or None: Connection statistics
        """
        metadata = self.connection_metadata.get(client_id)
        if metadata:
            return metadata.get_stats()
        return None
    
    def get_all_stats(self) -> Dict[str, Any]:
        """
        Get statistics for all connections.
        
        Returns:
            dict: Statistics for all connections
        """
        return {
            "active_connections": self.get_connection_count(),
            "clients": {
                client_id: metadata.get_stats()
                for client_id, metadata in self.connection_metadata.items()
            }
        }


# ============================================================================
# TEST SECTION
# ============================================================================

async def run_tests():
    """Run comprehensive tests for WebSocket transport"""
    
    print("=" * 70)
    print("Running WebSocket Transport Tests")
    print("=" * 70)
    
    # Test 1: Initialize transport
    print("\n[TEST 1] Transport Initialization")
    transport = WebSocketTransport(host="127.0.0.1", port=8765)
    assert transport.host == "127.0.0.1"
    assert transport.port == 8765
    assert transport.get_connection_count() == 0
    print("✓ WebSocket transport initialized")
    print(f"  - Host: {transport.host}")
    print(f"  - Port: {transport.port}")
    print(f"  - Max message size: {transport.max_message_size}")
    
    # Test 2: Connection metadata
    print("\n[TEST 2] Connection Metadata")
    metadata = ConnectionMetadata(
        client_id="test_client",
        connection_time=datetime.utcnow()
    )
    metadata.update_activity()
    assert metadata.message_count == 1
    stats = metadata.get_stats()
    assert "client_id" in stats
    print(f"✓ Metadata stats: {stats}")
    
    # Test 3: Message handler registration
    print("\n[TEST 3] Message Handler Registration")
    handler_called = []
    
    async def test_handler(client_id: str, message: Dict):
        handler_called.append((client_id, message))
    
    transport.register_message_handler("request", test_handler)
    assert len(transport.message_handlers["request"]) == 1
    print("✓ Message handler registered")
    print(f"  - Registered handlers: {len(transport.message_handlers['request'])}")
    
    # Test 4: Connection callbacks
    print("\n[TEST 4] Connection Callbacks")
    callbacks_triggered = {"connect": False, "disconnect": False}
    
    def on_connect(client_id: str):
        callbacks_triggered["connect"] = True
    
    def on_disconnect(client_id: str):
        callbacks_triggered["disconnect"] = True
    
    transport.on_client_connect = on_connect
    transport.on_client_disconnect = on_disconnect
    
    if transport.on_client_connect:
        transport.on_client_connect("test_id")
    if transport.on_client_disconnect:
        transport.on_client_disconnect("test_id")
    
    assert callbacks_triggered["connect"] and callbacks_triggered["disconnect"]
    print("✓ Callbacks triggered successfully")
    print(f"  - Connect: {callbacks_triggered['connect']}")
    print(f"  - Disconnect: {callbacks_triggered['disconnect']}")
    
    # Test 5: Statistics tracking
    print("\n[TEST 5] Statistics Tracking")
    transport.connections["test_client_1"] = None
    transport.connections["test_client_2"] = None
    
    count = transport.get_connection_count()
    clients = transport.get_connected_clients()
    
    assert count == 2
    assert len(clients) == 2
    print(f"✓ Connection count: {count}")
    print(f"✓ Connected clients: {clients}")
    
    # Test 6: Message creation utilities
    print("\n[TEST 6] Message Utilities")
    from utils import create_request_message, create_response_message
    
    request = create_request_message("test_method", {"param": "value"})
    response = create_response_message(request["id"], {"result": "success"})
    
    assert request["method"] == "test_method"
    assert response["result"]["result"] == "success"
    print(f"✓ Request message created: {request}")
    print(f"✓ Response message created: {response}")
    
    # Test 7: Connection cleanup
    print("\n[TEST 7] Connection Cleanup")
    transport.connections.clear()
    transport.connection_metadata.clear()
    
    assert transport.get_connection_count() == 0
    print("✓ Connections cleared")
    
    print("\n" + "=" * 70)
    print("All tests passed successfully! ✓")
    print("=" * 70)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    asyncio.run(run_tests())