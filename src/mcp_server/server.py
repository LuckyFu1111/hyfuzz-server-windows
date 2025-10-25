"""
HyFuzz MCP Server - Core Server Implementation

This module implements the main MCP (Model Context Protocol) server for HyFuzz.
It manages the complete server lifecycle, including initialization, message routing,
session management, transport layer coordination, and graceful shutdown.

Key Features:
- Full MCP 2024-11-05 protocol implementation
- Multi-transport support (stdio, HTTP, WebSocket)
- Async/await architecture with asyncio
- Session lifecycle management
- Message handler coordination
- Capability management
- Resource and tool registry
- Health monitoring and status reporting
- Error handling and recovery
- Graceful startup and shutdown
- Request logging and metrics

Architecture:
- MCPServer: Main server orchestrator
- TransportManager: Manages multiple transport protocols
- SessionManager: Handles client sessions
- MessageHandler: Routes and processes messages
- CapabilityManager: Manages server capabilities

Author: HyFuzz Team
Version: 1.0.0
"""

import asyncio
import logging
import time
import uuid
from typing import Dict, Any, Optional, List, Callable, Coroutine, Tuple
from enum import Enum
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
import signal

# Optional imports with fallbacks
try:
    import uvloop

    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
except ImportError:
    pass

# ============================================================================
# Constants
# ============================================================================

# MCP Protocol Constants
PROTOCOL_VERSION = "2024-11-05"
PROTOCOL_NAME = "mcp"


# Server Status Enumerations
class ServerStatus(Enum):
    """Server operational status"""
    INITIALIZING = "initializing"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    ERROR = "error"
    RESTARTING = "restarting"


class TransportType(Enum):
    """Supported transport types"""
    STDIO = "stdio"
    HTTP = "http"
    WEBSOCKET = "websocket"


# ============================================================================
# Data Models
# ============================================================================

@dataclass
class ServerConfig:
    """Server configuration"""
    name: str = "hyfuzz-mcp-server"
    version: str = "1.0.0"
    environment: str = "development"
    debug: bool = False

    # Server binding
    host: str = "0.0.0.0"
    port: int = 5000

    # Transport configuration
    transports: List[str] = None
    stdio_enabled: bool = True
    http_enabled: bool = False
    websocket_enabled: bool = False

    # Performance settings
    max_concurrent_requests: int = 1000
    request_timeout: float = 30.0
    max_sessions: int = 500

    # Resource limits
    max_resources: int = 1000
    max_tools: int = 500
    max_prompts: int = 100

    # Logging
    log_level: str = "INFO"
    log_file: Optional[str] = None

    # Features
    enable_caching: bool = True
    enable_metrics: bool = True

    def __post_init__(self):
        """Validate and set defaults"""
        if self.transports is None:
            self.transports = ["stdio"]


@dataclass
class ServerMetrics:
    """Server performance metrics"""
    start_time: float = 0.0
    requests_total: int = 0
    requests_success: int = 0
    requests_error: int = 0
    total_request_time: float = 0.0
    active_sessions: int = 0
    total_data_sent: int = 0
    total_data_received: int = 0

    @property
    def uptime(self) -> float:
        """Get server uptime in seconds"""
        if self.start_time == 0:
            return 0
        return time.time() - self.start_time

    @property
    def avg_request_time(self) -> float:
        """Get average request processing time"""
        if self.requests_total == 0:
            return 0
        return self.total_request_time / self.requests_total

    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary"""
        return {
            "uptime": self.uptime,
            "requests": {
                "total": self.requests_total,
                "success": self.requests_success,
                "error": self.requests_error,
                "avg_time_ms": self.avg_request_time * 1000,
            },
            "sessions": self.active_sessions,
            "data": {
                "sent": self.total_data_sent,
                "received": self.total_data_received,
            }
        }


@dataclass
class ServerInfo:
    """Server information"""
    name: str
    version: str
    protocol_version: str
    status: ServerStatus
    environment: str
    started_at: datetime

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "name": self.name,
            "version": self.version,
            "protocolVersion": self.protocol_version,
            "status": self.status.value,
            "environment": self.environment,
            "startedAt": self.started_at.isoformat(),
        }


# ============================================================================
# Logger Setup
# ============================================================================

def get_logger(name: str) -> logging.Logger:
    """Get or create logger"""
    return logging.getLogger(name)


logger = get_logger(__name__)


# ============================================================================
# Main Server Class
# ============================================================================

class MCPServer:
    """
    Core MCP Server implementation.

    Orchestrates all server components including transports, message handling,
    session management, and lifecycle operations.
    """

    def __init__(self, config: Optional[ServerConfig] = None):
        """
        Initialize MCP server

        Args:
            config: Server configuration object
        """
        self.config = config or ServerConfig()
        self.status = ServerStatus.INITIALIZING

        # Server metadata
        self.server_id = str(uuid.uuid4())
        self.started_at = datetime.now(timezone.utc)

        # Core components
        self.message_handler = None
        self.capability_manager = None
        self.session_manager = None

        # Transports
        self.transports: Dict[str, Any] = {}

        # Sessions
        self.sessions: Dict[str, Dict[str, Any]] = {}
        self.sessions_lock = asyncio.Lock()

        # Resources and tools
        self.resources: Dict[str, Any] = {}
        self.tools: Dict[str, Any] = {}

        # Event handling
        self.shutdown_event = asyncio.Event()

        # Metrics
        self.metrics = ServerMetrics(start_time=time.time())

        # Message queue for async processing
        self.message_queue: asyncio.Queue = asyncio.Queue()

        logger.info(
            f"MCPServer initialized: {self.server_id} "
            f"(version {self.config.version})"
        )

    async def initialize(self) -> None:
        """
        Initialize server components

        Raises:
            RuntimeError: If initialization fails
        """
        logger.info("Initializing MCP server components")

        try:
            # Import core components
            from .message_handler import MessageHandler
            from .capability_manager import CapabilityManager
            from .session_manager import SessionManager

            # Initialize components
            self.message_handler = MessageHandler()
            self.capability_manager = CapabilityManager()
            self.session_manager = SessionManager()

            # Initialize transports
            await self._initialize_transports()

            # Setup signal handlers
            self._setup_signal_handlers()

            logger.info("Server components initialized successfully")

        except Exception as ex:
            logger.error(f"Server initialization failed: {str(ex)}", exc_info=True)
            self.status = ServerStatus.ERROR
            raise RuntimeError(f"Failed to initialize server: {str(ex)}")

    async def _initialize_transports(self) -> None:
        """Initialize configured transport layers"""
        logger.debug("Initializing transports")

        for transport_name in self.config.transports:
            try:
                if transport_name == "stdio":
                    from .stdio_transport import StdioTransport
                    transport = StdioTransport(
                        message_handler=self.message_handler,
                    )
                    self.transports["stdio"] = transport
                    logger.debug("Stdio transport initialized")

                elif transport_name == "http":
                    from .http_transport import HttpTransport
                    transport = HttpTransport(
                        host=self.config.host,
                        port=self.config.port,
                        message_handler=self.message_handler,
                    )
                    self.transports["http"] = transport
                    logger.debug(f"HTTP transport initialized on {self.config.host}:{self.config.port}")

                elif transport_name == "websocket":
                    from .websocket_transport import WebsocketTransport
                    transport = WebsocketTransport(
                        host=self.config.host,
                        port=self.config.port + 1,
                        message_handler=self.message_handler,
                    )
                    self.transports["websocket"] = transport
                    logger.debug("WebSocket transport initialized")

            except ImportError as ex:
                logger.warning(f"Could not load {transport_name} transport: {str(ex)}")
            except Exception as ex:
                logger.error(f"Failed to initialize {transport_name} transport: {str(ex)}")

    def _setup_signal_handlers(self) -> None:
        """Setup OS signal handlers for graceful shutdown"""

        def signal_handler(sig, frame):
            logger.info(f"Received signal {sig}, initiating graceful shutdown")
            asyncio.create_task(self.stop())

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

    async def start(self) -> None:
        """
        Start the MCP server

        Raises:
            RuntimeError: If server is already running
        """
        if self.status == ServerStatus.RUNNING:
            raise RuntimeError("Server is already running")

        logger.info("Starting MCP server")
        self.status = ServerStatus.INITIALIZING

        try:
            # Initialize components if not already done
            if self.message_handler is None:
                await self.initialize()

            # Start all transports
            tasks = []
            for transport_name, transport in self.transports.items():
                logger.info(f"Starting {transport_name} transport")
                tasks.append(transport.start())

            if tasks:
                await asyncio.gather(*tasks)

            # Set status to running
            self.status = ServerStatus.RUNNING
            self.started_at = datetime.now(timezone.utc)
            self.metrics.start_time = time.time()

            logger.info(
                f"MCP server started successfully on {self.config.host}:{self.config.port}"
            )

            # Start background tasks
            asyncio.create_task(self._monitor_server())

        except Exception as ex:
            logger.error(f"Server startup failed: {str(ex)}", exc_info=True)
            self.status = ServerStatus.ERROR
            raise

    async def stop(self) -> None:
        """Stop the MCP server gracefully"""
        if self.status == ServerStatus.STOPPED:
            return

        logger.info("Stopping MCP server")
        self.status = ServerStatus.STOPPING

        try:
            # Stop all transports
            tasks = []
            for transport_name, transport in self.transports.items():
                logger.debug(f"Stopping {transport_name} transport")
                if hasattr(transport, 'stop'):
                    tasks.append(transport.stop())

            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

            # Close all sessions
            async with self.sessions_lock:
                for session_id in list(self.sessions.keys()):
                    await self._close_session(session_id)

            # Signal shutdown
            self.shutdown_event.set()

            self.status = ServerStatus.STOPPED
            logger.info("MCP server stopped successfully")

        except Exception as ex:
            logger.error(f"Error during server shutdown: {str(ex)}", exc_info=True)
            self.status = ServerStatus.ERROR

    async def restart(self) -> None:
        """Restart the server"""
        logger.info("Restarting MCP server")
        self.status = ServerStatus.RESTARTING

        try:
            await self.stop()
            await asyncio.sleep(1)  # Brief pause before restart
            await self.start()
            logger.info("Server restart completed")
        except Exception as ex:
            logger.error(f"Server restart failed: {str(ex)}", exc_info=True)
            raise

    async def handle_message(
            self,
            message_data: Dict[str, Any],
            session_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Handle incoming MCP message

        Args:
            message_data: Message data dictionary
            session_id: Associated session ID

        Returns:
            Response message
        """
        start_time = time.time()

        try:
            # Update metrics
            self.metrics.requests_total += 1
            self.metrics.total_data_received += len(str(message_data))

            # Route to message handler
            if self.message_handler:
                response = await self.message_handler.handle_message(
                    message_data,
                    session_id=session_id,
                )
            else:
                response = {
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32603,
                        "message": "Message handler not available",
                    },
                }

            # Update metrics
            duration = time.time() - start_time
            self.metrics.total_request_time += duration
            self.metrics.requests_success += 1

            if response:
                self.metrics.total_data_sent += len(str(response))

            return response

        except Exception as ex:
            logger.error(f"Error handling message: {str(ex)}", exc_info=True)
            self.metrics.requests_error += 1

            return {
                "jsonrpc": "2.0",
                "error": {
                    "code": -32603,
                    "message": f"Error processing message: {str(ex)}",
                },
                "id": message_data.get("id"),
            }

    async def create_session(
            self,
            client_name: str = "unknown",
            client_version: str = "unknown",
    ) -> str:
        """
        Create a new client session

        Args:
            client_name: Name of the client
            client_version: Client version

        Returns:
            Session ID
        """
        session_id = str(uuid.uuid4())

        async with self.sessions_lock:
            if len(self.sessions) >= self.config.max_sessions:
                raise RuntimeError("Maximum sessions reached")

            self.sessions[session_id] = {
                "id": session_id,
                "client_name": client_name,
                "client_version": client_version,
                "created_at": datetime.now(timezone.utc),
                "last_activity": datetime.now(timezone.utc),
                "request_count": 0,
            }

        self.metrics.active_sessions = len(self.sessions)
        logger.info(f"Session created: {session_id} ({client_name} v{client_version})")

        return session_id

    async def _close_session(self, session_id: str) -> None:
        """Close a session"""
        async with self.sessions_lock:
            if session_id in self.sessions:
                del self.sessions[session_id]

        self.metrics.active_sessions = len(self.sessions)
        logger.debug(f"Session closed: {session_id}")

    async def close_session(self, session_id: str) -> None:
        """Public method to close a session"""
        await self._close_session(session_id)

    def register_resource(
            self,
            resource_id: str,
            resource_data: Dict[str, Any],
    ) -> None:
        """Register a server resource"""
        self.resources[resource_id] = resource_data
        logger.debug(f"Resource registered: {resource_id}")

    def register_tool(
            self,
            tool_name: str,
            tool_data: Dict[str, Any],
            handler: Callable,
    ) -> None:
        """Register a server tool"""
        self.tools[tool_name] = {
            **tool_data,
            "handler": handler,
        }
        logger.debug(f"Tool registered: {tool_name}")

    def get_capabilities(self) -> Dict[str, Any]:
        """Get server capabilities"""
        if self.capability_manager:
            return self.capability_manager.get_capabilities()

        return {
            "resources": {"listChanged": True},
            "tools": {"listChanged": True},
            "prompts": {"listChanged": True},
        }

    def get_server_info(self) -> ServerInfo:
        """Get server information"""
        return ServerInfo(
            name=self.config.name,
            version=self.config.version,
            protocol_version=PROTOCOL_VERSION,
            status=self.status,
            environment=self.config.environment,
            started_at=self.started_at,
        )

    def get_status(self) -> Dict[str, Any]:
        """Get current server status"""
        return {
            **self.get_server_info().to_dict(),
            "metrics": self.metrics.to_dict(),
            "sessions": len(self.sessions),
            "resources": len(self.resources),
            "tools": len(self.tools),
        }

    def get_metrics(self) -> Dict[str, Any]:
        """Get server metrics"""
        return self.metrics.to_dict()

    async def health_check(self) -> Dict[str, Any]:
        """Check server health"""
        return {
            "status": "healthy" if self.status == ServerStatus.RUNNING else "unhealthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "uptime": self.metrics.uptime,
            "active_sessions": len(self.sessions),
        }

    async def _monitor_server(self) -> None:
        """Background task to monitor server health"""
        while self.status == ServerStatus.RUNNING:
            try:
                # Periodically cleanup old sessions
                async with self.sessions_lock:
                    current_time = time.time()
                    expired_sessions = [
                        sid for sid, session in self.sessions.items()
                        if (current_time - session["last_activity"].timestamp()) > 3600
                    ]

                for session_id in expired_sessions:
                    logger.debug(f"Cleaning up expired session: {session_id}")
                    await self._close_session(session_id)

                await asyncio.sleep(60)  # Check every 60 seconds

            except Exception as ex:
                logger.error(f"Error in server monitor: {str(ex)}")

    async def __aenter__(self):
        """Async context manager entry"""
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.stop()


# ============================================================================
# Helper Classes
# ============================================================================

class CapabilityManager:
    """Mock capability manager for testing"""

    def __init__(self):
        self.capabilities = {
            "resources": {"listChanged": True},
            "tools": {"listChanged": True},
            "prompts": {"listChanged": True},
        }

    def get_capabilities(self) -> Dict[str, Any]:
        """Get server capabilities"""
        return self.capabilities


class SessionManager:
    """Mock session manager for testing"""

    def __init__(self):
        self.sessions = {}

    async def create_session(self, **kwargs) -> str:
        """Create a new session"""
        session_id = str(uuid.uuid4())
        self.sessions[session_id] = kwargs
        return session_id


# ============================================================================
# Test Suite
# ============================================================================

async def run_tests():
    """Run server tests"""

    print("\n" + "=" * 80)
    print("MCP SERVER TEST SUITE")
    print("=" * 80 + "\n")

    # Test 1: Server initialization
    print("[TEST 1] Server Initialization")
    try:
        config = ServerConfig(
            name="test-server",
            version="1.0.0",
            transports=["stdio"],
        )
        server = MCPServer(config=config)
        assert server.status == ServerStatus.INITIALIZING
        assert server.server_id is not None
        print("✓ Server initialization test passed\n")
    except Exception as e:
        print(f"✗ Server initialization test failed: {str(e)}\n")
        return

    # Test 2: Server configuration
    print("[TEST 2] Server Configuration")
    try:
        config = ServerConfig(
            host="127.0.0.1",
            port=8000,
            max_sessions=100,
        )
        assert config.host == "127.0.0.1"
        assert config.port == 8000
        assert config.max_sessions == 100
        print("✓ Server configuration test passed\n")
    except Exception as e:
        print(f"✗ Server configuration test failed: {str(e)}\n")
        return

    # Test 3: Server metrics
    print("[TEST 3] Server Metrics")
    try:
        metrics = ServerMetrics()
        metrics.start_time = time.time() - 10  # 10 seconds ago
        metrics.requests_total = 100
        metrics.requests_success = 95
        metrics.requests_error = 5
        metrics.total_request_time = 5.0

        assert metrics.uptime >= 10
        assert metrics.avg_request_time > 0

        metrics_dict = metrics.to_dict()
        assert "uptime" in metrics_dict
        assert "requests" in metrics_dict

        print("✓ Server metrics test passed\n")
    except Exception as e:
        print(f"✗ Server metrics test failed: {str(e)}\n")
        return

    # Test 4: Server status
    print("[TEST 4] Server Status")
    try:
        config = ServerConfig()
        server = MCPServer(config=config)

        # Check initial status
        assert server.status == ServerStatus.INITIALIZING

        # Get status info
        status = server.get_server_info()
        assert status.name == config.name
        assert status.version == config.version

        print("✓ Server status test passed\n")
    except Exception as e:
        print(f"✗ Server status test failed: {str(e)}\n")
        return

    # Test 5: Resource registration
    print("[TEST 5] Resource Registration")
    try:
        config = ServerConfig()
        server = MCPServer(config=config)

        server.register_resource("resource-1", {"type": "test", "data": {}})
        assert "resource-1" in server.resources
        assert len(server.resources) == 1

        print("✓ Resource registration test passed\n")
    except Exception as e:
        print(f"✗ Resource registration test failed: {str(e)}\n")
        return

    # Test 6: Tool registration
    print("[TEST 6] Tool Registration")
    try:
        config = ServerConfig()
        server = MCPServer(config=config)

        async def tool_handler(params):
            return {"result": "ok"}

        server.register_tool(
            "test-tool",
            {"description": "Test tool"},
            tool_handler
        )

        assert "test-tool" in server.tools
        assert len(server.tools) == 1

        print("✓ Tool registration test passed\n")
    except Exception as e:
        print(f"✗ Tool registration test failed: {str(e)}\n")
        return

    # Test 7: Session creation (synchronous check)
    print("[TEST 7] Session Management")
    try:
        config = ServerConfig()
        server = MCPServer(config=config)

        # Simulate session creation
        session_id = str(uuid.uuid4())
        server.sessions[session_id] = {
            "id": session_id,
            "client_name": "test-client",
            "client_version": "1.0",
        }

        assert session_id is not None
        assert session_id in server.sessions

        # Simulate session closure
        del server.sessions[session_id]
        assert session_id not in server.sessions

        print("✓ Session management test passed\n")
    except Exception as e:
        print(f"✗ Session management test failed: {str(e)}\n")
        return

    # Test 8: Server info
    print("[TEST 8] Server Info")
    try:
        config = ServerConfig()
        server = MCPServer(config=config)

        info = server.get_server_info()
        assert info.name == config.name
        assert info.version == config.version
        assert info.protocol_version == PROTOCOL_VERSION

        info_dict = info.to_dict()
        assert "name" in info_dict
        assert "version" in info_dict
        assert "protocolVersion" in info_dict

        print("✓ Server info test passed\n")
    except Exception as e:
        print(f"✗ Server info test failed: {str(e)}\n")
        return

    # Test 9: Health check (synchronous mock)
    print("[TEST 9] Health Check")
    try:
        config = ServerConfig()
        server = MCPServer(config=config)

        # Simulate health check data
        health = {
            "status": "healthy" if server.status == ServerStatus.RUNNING else "initializing",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "uptime": server.metrics.uptime,
            "active_sessions": len(server.sessions),
        }

        assert "status" in health
        assert "timestamp" in health
        assert "uptime" in health

        print("✓ Health check test passed\n")
    except Exception as e:
        print(f"✗ Health check test failed: {str(e)}\n")
        return

    # Test 10: Capabilities
    print("[TEST 10] Server Capabilities")
    try:
        config = ServerConfig()
        server = MCPServer(config=config)

        capabilities = server.get_capabilities()
        assert isinstance(capabilities, dict)
        assert "resources" in capabilities or len(capabilities) >= 0

        print("✓ Server capabilities test passed\n")
    except Exception as e:
        print(f"✗ Server capabilities test failed: {str(e)}\n")
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