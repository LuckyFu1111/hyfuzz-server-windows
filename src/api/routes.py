"""
HyFuzz MCP Server - API Routes

This module defines all HTTP and MCP protocol endpoints for the HyFuzz server.

Key Features:
- RESTful API endpoints for payload generation and vulnerability analysis
- MCP protocol endpoints for protocol-level operations
- WebSocket support for real-time payload streaming
- Health check and metrics endpoints
- Knowledge base query endpoints
- Comprehensive request validation and error handling

Endpoint Categories:
1. Health & Status: /health, /api/v1/status
2. Payloads: /api/v1/payloads/generate, /api/v1/payloads/refine
3. Knowledge: /api/v1/knowledge/cwe/{id}, /api/v1/knowledge/cve/{id}
4. Feedback: /api/v1/feedback, /api/v1/metrics
5. MCP Protocol: /mcp/initialize, /mcp/tools/list, /mcp/tools/call
6. WebSocket: /api/v1/stream

Author: HyFuzz Team
Version: 1.0.0
"""

import logging
from typing import Dict, Any, Optional, Callable
from functools import wraps
from datetime import datetime, timezone

from ..mcp_server.server import MCPServer
from ..config.settings import Settings
from ..utils.logger import get_logger
from ..utils.exceptions import ValidationError, ServerError
from ..models.message_models import (
    MCPInitializeRequest,
    MCPToolCall,
)

# Initialize logger
logger = get_logger(__name__)


# ==============================================================================
# Route Registry
# ==============================================================================

class RouteRegistry:
    """
    Central registry for all API routes and endpoint metadata.
    
    Attributes:
        routes: Dictionary mapping route paths to handler information
        settings: Application settings
    """

    def __init__(self, settings: Optional[Settings] = None):
        """
        Initialize route registry.
        
        Args:
            settings: Application settings
        """
        self.settings = settings or Settings()
        self.logger = get_logger(__name__)
        self.routes: Dict[str, Dict[str, Any]] = {}
        self._initialize_routes()

    def _initialize_routes(self) -> None:
        """Initialize route metadata."""
        self.routes = {
            # Health & Status
            "GET /health": {
                "handler": "health_check",
                "description": "Server health check",
                "public": True,
                "rate_limit": False,
            },
            "GET /api/v1/status": {
                "handler": "detailed_status",
                "description": "Detailed system status",
                "auth_required": False,
                "rate_limit": True,
            },

            # Payloads
            "POST /api/v1/payloads/generate": {
                "handler": "generate_payloads",
                "description": "Generate fuzzing payloads",
                "auth_required": True,
                "rate_limit": True,
                "methods": ["POST"],
            },
            "POST /api/v1/payloads/refine": {
                "handler": "refine_payloads",
                "description": "Refine payload generation strategy",
                "auth_required": True,
                "rate_limit": True,
            },

            # Knowledge Base
            "GET /api/v1/knowledge/cwe/{cwe_id}": {
                "handler": "get_cwe_info",
                "description": "Get CWE vulnerability information",
                "auth_required": False,
                "rate_limit": True,
                "methods": ["GET"],
            },
            "GET /api/v1/knowledge/cve/{cve_id}": {
                "handler": "get_cve_info",
                "description": "Get CVE vulnerability information",
                "auth_required": False,
                "rate_limit": True,
                "methods": ["GET"],
            },
            "POST /api/v1/knowledge/search": {
                "handler": "search_knowledge",
                "description": "Search knowledge base",
                "auth_required": False,
                "rate_limit": True,
                "methods": ["POST"],
            },

            # Feedback & Metrics
            "POST /api/v1/feedback": {
                "handler": "submit_feedback",
                "description": "Submit payload execution feedback",
                "auth_required": True,
                "rate_limit": True,
                "methods": ["POST"],
            },
            "GET /api/v1/metrics": {
                "handler": "get_metrics",
                "description": "Get performance metrics",
                "auth_required": True,
                "rate_limit": True,
                "methods": ["GET"],
            },

            # MCP Protocol
            "POST /mcp/initialize": {
                "handler": "mcp_initialize",
                "description": "Initialize MCP session",
                "auth_required": False,
                "rate_limit": True,
                "methods": ["POST"],
            },
            "POST /mcp/tools/list": {
                "handler": "mcp_list_tools",
                "description": "List available MCP tools",
                "auth_required": False,
                "rate_limit": True,
                "methods": ["POST"],
            },
            "POST /mcp/tools/call": {
                "handler": "mcp_call_tool",
                "description": "Call MCP tool",
                "auth_required": False,
                "rate_limit": True,
                "methods": ["POST"],
            },

            # WebSocket
            "WS /api/v1/stream": {
                "handler": "websocket_stream",
                "description": "Real-time payload streaming",
                "auth_required": True,
                "rate_limit": False,
                "methods": ["UPGRADE"],
            },
        }

        self.logger.debug(f"Route registry initialized with {len(self.routes)} routes")

    def get_route(self, path: str, method: str) -> Optional[Dict[str, Any]]:
        """
        Get route metadata.
        
        Args:
            path: Route path (may contain path parameters)
            method: HTTP method
            
        Returns:
            Route metadata or None if not found
        """
        route_key = f"{method} {path}"
        return self.routes.get(route_key)

    def get_all_routes(self) -> Dict[str, Dict[str, Any]]:
        """Get all registered routes."""
        return self.routes

    def get_route_info(self) -> Dict[str, Any]:
        """
        Get information about all routes.
        
        Returns:
            Route information organized by category
        """
        categorized = {
            "health": {},
            "payloads": {},
            "knowledge": {},
            "feedback": {},
            "mcp": {},
            "websocket": {},
        }

        for route_path, route_info in self.routes.items():
            if "health" in route_path:
                categorized["health"][route_path] = route_info
            elif "payloads" in route_path:
                categorized["payloads"][route_path] = route_info
            elif "knowledge" in route_path:
                categorized["knowledge"][route_path] = route_info
            elif "feedback" in route_path or "metrics" in route_path:
                categorized["feedback"][route_path] = route_info
            elif "/mcp/" in route_path:
                categorized["mcp"][route_path] = route_info
            elif "/api/v1/stream" in route_path:
                categorized["websocket"][route_path] = route_info

        return categorized


# ==============================================================================
# Route Decorator
# ==============================================================================

def route(
    method: str,
    path: str,
    description: str = "",
    auth_required: bool = False,
    rate_limit: bool = True,
):
    """
    Decorator for route handlers.
    
    Args:
        method: HTTP method (GET, POST, PUT, DELETE, etc.)
        path: URL path
        description: Route description
        auth_required: Whether authentication is required
        rate_limit: Whether rate limiting applies
        
    Returns:
        Decorator function
        
    Example:
        >>> @route("GET", "/api/v1/health", description="Health check")
        ... async def health_check():
        ...     return {"status": "healthy"}
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            return await func(*args, **kwargs)

        # Attach metadata
        wrapper.route_method = method
        wrapper.route_path = path
        wrapper.route_description = description
        wrapper.auth_required = auth_required
        wrapper.rate_limit = rate_limit
        wrapper.handler = func.__name__

        return wrapper

    return decorator


# ==============================================================================
# Route Handlers
# ==============================================================================

class RouteHandlers:
    """
    Central handler class for all API routes.
    Coordinates between HTTP layer and business logic layer.
    """

    def __init__(self, mcp_server: MCPServer, settings: Optional[Settings] = None):
        """
        Initialize route handlers.
        
        Args:
            mcp_server: MCPServer instance
            settings: Application settings
            
        Raises:
            ValueError: If mcp_server is None
        """
        if mcp_server is None:
            raise ValueError("mcp_server cannot be None")

        self.mcp_server = mcp_server
        self.settings = settings or Settings()
        self.logger = get_logger(__name__)
        self.registry = RouteRegistry(settings)

    # ========================================================================
    # Health & Status Endpoints
    # ========================================================================

    async def health_check(self) -> Dict[str, Any]:
        """
        Health check endpoint handler.
        
        Returns:
            Health status response
        """
        self.logger.debug("Health check requested")

        try:
            is_healthy = await self.mcp_server.check_health()

            return {
                "status": "healthy" if is_healthy else "unhealthy",
                "status_code": 200 if is_healthy else 503,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "uptime": await self.mcp_server.get_uptime(),
            }

        except Exception as e:
            self.logger.error(f"Health check failed: {str(e)}")
            return {
                "status": "unhealthy",
                "status_code": 503,
                "error": str(e),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

    async def detailed_status(self) -> Dict[str, Any]:
        """
        Detailed system status endpoint handler.
        
        Returns:
            Detailed system status
        """
        self.logger.debug("Status check requested")

        try:
            status = {
                "status": "ok",
                "status_code": 200,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "server": {
                    "uptime": await self.mcp_server.get_uptime(),
                    "version": getattr(self.settings, 'version', '1.0.0'),
                    "environment": getattr(self.settings, 'environment', 'development'),
                },
                "services": {
                    "mcp_server": "running",
                    "llm": await self._check_llm_service(),
                    "knowledge_base": await self._check_knowledge_service(),
                },
                "metrics": {
                    "total_requests": await self.mcp_server.get_total_requests(),
                    "active_sessions": await self.mcp_server.get_active_sessions(),
                    "cached_payloads": await self.mcp_server.get_cached_payloads_count(),
                },
            }

            return status

        except Exception as e:
            self.logger.error(f"Status check failed: {str(e)}")
            return {
                "status": "error",
                "status_code": 500,
                "error": str(e),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

    # ========================================================================
    # Payload Endpoints
    # ========================================================================

    async def generate_payloads(
        self,
        protocol: str,
        vulnerability_type: str,
        target: Optional[Dict[str, Any]] = None,
        count: int = 5,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Generate payloads endpoint handler.
        
        Args:
            protocol: Target protocol (HTTP, CoAP, gRPC, etc.)
            vulnerability_type: Type of vulnerability (XSS, SQLi, etc.)
            target: Target information
            count: Number of payloads to generate
            **kwargs: Additional arguments
            
        Returns:
            Generated payloads response
            
        Raises:
            ValidationError: If validation fails
        """
        self.logger.info(
            f"Generating {count} payloads for {protocol}://{vulnerability_type}"
        )

        try:
            # Validate inputs
            if not protocol:
                raise ValidationError("protocol is required")
            if not vulnerability_type:
                raise ValidationError("vulnerability_type is required")
            if count < 1 or count > 100:
                raise ValidationError("count must be between 1 and 100")

            # Generate payloads using MCP server
            payloads = await self.mcp_server.generate_payloads(
                protocol=protocol,
                vulnerability_type=vulnerability_type,
                target=target,
                count=count,
                **kwargs
            )

            return {
                "status": "success",
                "status_code": 200,
                "data": {
                    "protocol": protocol,
                    "vulnerability_type": vulnerability_type,
                    "count": len(payloads),
                    "payloads": payloads,
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                },
            }

        except ValidationError as e:
            self.logger.warning(f"Payload generation validation failed: {str(e)}")
            raise
        except Exception as e:
            self.logger.error(f"Payload generation failed: {str(e)}")
            raise ServerError(f"Failed to generate payloads: {str(e)}")

    async def refine_payloads(
        self,
        payloads: list,
        feedback: Dict[str, Any],
        **kwargs
    ) -> Dict[str, Any]:
        """
        Refine payloads endpoint handler.
        
        Args:
            payloads: Existing payloads to refine
            feedback: Execution feedback from previous attempts
            **kwargs: Additional arguments
            
        Returns:
            Refined payloads response
        """
        self.logger.info(f"Refining {len(payloads)} payloads based on feedback")

        try:
            if not payloads:
                raise ValidationError("payloads list cannot be empty")
            if not feedback:
                raise ValidationError("feedback is required")

            # Refine payloads
            refined = await self.mcp_server.refine_payloads(
                payloads=payloads,
                feedback=feedback,
                **kwargs
            )

            return {
                "status": "success",
                "status_code": 200,
                "data": {
                    "original_count": len(payloads),
                    "refined_count": len(refined),
                    "payloads": refined,
                    "refined_at": datetime.now(timezone.utc).isoformat(),
                },
            }

        except ValidationError as e:
            raise
        except Exception as e:
            self.logger.error(f"Payload refinement failed: {str(e)}")
            raise ServerError(f"Failed to refine payloads: {str(e)}")

    # ========================================================================
    # Knowledge Base Endpoints
    # ========================================================================

    async def get_cwe_info(self, cwe_id: str) -> Dict[str, Any]:
        """
        Get CWE information endpoint handler.
        
        Args:
            cwe_id: CWE identifier (e.g., CWE-79)
            
        Returns:
            CWE information
        """
        self.logger.debug(f"Fetching CWE information: {cwe_id}")

        try:
            if not cwe_id:
                raise ValidationError("cwe_id is required")

            cwe_data = await self.mcp_server.get_cwe_info(cwe_id)

            if not cwe_data:
                return {
                    "status": "not_found",
                    "status_code": 404,
                    "message": f"CWE {cwe_id} not found",
                }

            return {
                "status": "success",
                "status_code": 200,
                "data": cwe_data,
            }

        except ValidationError as e:
            raise
        except Exception as e:
            self.logger.error(f"Failed to fetch CWE info: {str(e)}")
            raise ServerError(f"Failed to fetch CWE information: {str(e)}")

    async def get_cve_info(self, cve_id: str) -> Dict[str, Any]:
        """
        Get CVE information endpoint handler.
        
        Args:
            cve_id: CVE identifier (e.g., CVE-2023-1234)
            
        Returns:
            CVE information
        """
        self.logger.debug(f"Fetching CVE information: {cve_id}")

        try:
            if not cve_id:
                raise ValidationError("cve_id is required")

            cve_data = await self.mcp_server.get_cve_info(cve_id)

            if not cve_data:
                return {
                    "status": "not_found",
                    "status_code": 404,
                    "message": f"CVE {cve_id} not found",
                }

            return {
                "status": "success",
                "status_code": 200,
                "data": cve_data,
            }

        except ValidationError as e:
            raise
        except Exception as e:
            self.logger.error(f"Failed to fetch CVE info: {str(e)}")
            raise ServerError(f"Failed to fetch CVE information: {str(e)}")

    async def search_knowledge(
        self,
        query: str,
        filters: Optional[Dict[str, Any]] = None,
        limit: int = 20,
    ) -> Dict[str, Any]:
        """
        Search knowledge base endpoint handler.
        
        Args:
            query: Search query
            filters: Optional search filters
            limit: Maximum results to return
            
        Returns:
            Search results
        """
        self.logger.debug(f"Knowledge base search: {query}")

        try:
            if not query:
                raise ValidationError("query is required")
            if limit < 1 or limit > 100:
                raise ValidationError("limit must be between 1 and 100")

            results = await self.mcp_server.search_knowledge(
                query=query,
                filters=filters,
                limit=limit,
            )

            return {
                "status": "success",
                "status_code": 200,
                "data": {
                    "query": query,
                    "count": len(results),
                    "results": results,
                    "searched_at": datetime.now(timezone.utc).isoformat(),
                },
            }

        except ValidationError as e:
            raise
        except Exception as e:
            self.logger.error(f"Knowledge base search failed: {str(e)}")
            raise ServerError(f"Search failed: {str(e)}")

    # ========================================================================
    # Feedback & Metrics Endpoints
    # ========================================================================

    async def submit_feedback(
        self,
        payload: str,
        execution_result: Dict[str, Any],
        session_id: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Submit payload execution feedback endpoint handler.
        
        Args:
            payload: The payload that was executed
            execution_result: Result of payload execution
            session_id: MCP session identifier
            **kwargs: Additional feedback data
            
        Returns:
            Feedback submission response
        """
        self.logger.info(f"Feedback submitted for session {session_id}")

        try:
            if not payload:
                raise ValidationError("payload is required")
            if not execution_result:
                raise ValidationError("execution_result is required")

            # Process feedback
            feedback_id = await self.mcp_server.submit_feedback(
                payload=payload,
                execution_result=execution_result,
                session_id=session_id,
                **kwargs
            )

            return {
                "status": "success",
                "status_code": 200,
                "data": {
                    "feedback_id": feedback_id,
                    "accepted": True,
                    "processed_at": datetime.now(timezone.utc).isoformat(),
                },
            }

        except ValidationError as e:
            raise
        except Exception as e:
            self.logger.error(f"Feedback submission failed: {str(e)}")
            raise ServerError(f"Failed to submit feedback: {str(e)}")

    async def get_metrics(
        self,
        metric_type: Optional[str] = None,
        time_range: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Get performance metrics endpoint handler.
        
        Args:
            metric_type: Type of metrics (performance, generation, etc.)
            time_range: Time range for metrics (1h, 24h, 7d)
            
        Returns:
            Performance metrics
        """
        self.logger.debug(f"Metrics requested: type={metric_type}, range={time_range}")

        try:
            metrics = await self.mcp_server.get_metrics(
                metric_type=metric_type,
                time_range=time_range,
            )

            return {
                "status": "success",
                "status_code": 200,
                "data": metrics,
            }

        except Exception as e:
            self.logger.error(f"Failed to get metrics: {str(e)}")
            raise ServerError(f"Failed to retrieve metrics: {str(e)}")

    # ========================================================================
    # MCP Protocol Endpoints
    # ========================================================================

    async def mcp_initialize(
        self,
        protocol_version: str,
        client_info: Dict[str, Any],
        capabilities: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        MCP Initialize endpoint handler.
        
        Args:
            protocol_version: MCP protocol version
            client_info: Client information
            capabilities: Client capabilities
            
        Returns:
            MCP initialization response
        """
        self.logger.info(f"MCP Initialize: version={protocol_version}")

        try:
            if not protocol_version:
                raise ValidationError("protocol_version is required")
            if not client_info:
                raise ValidationError("client_info is required")

            session_id = await self.mcp_server.initialize_session(
                protocol_version=protocol_version,
                client_info=client_info,
                capabilities=capabilities,
            )

            return {
                "status": "success",
                "status_code": 200,
                "data": {
                    "session_id": session_id,
                    "server_version": getattr(self.settings, 'version', '1.0.0'),
                    "capabilities": {
                        "payloads": True,
                        "knowledge": True,
                        "feedback": True,
                        "streaming": True,
                    },
                    "initialized_at": datetime.now(timezone.utc).isoformat(),
                },
            }

        except ValidationError as e:
            raise
        except Exception as e:
            self.logger.error(f"MCP initialization failed: {str(e)}")
            raise ServerError(f"MCP initialization failed: {str(e)}")

    async def mcp_list_tools(self, session_id: str) -> Dict[str, Any]:
        """
        MCP List Tools endpoint handler.
        
        Args:
            session_id: MCP session identifier
            
        Returns:
            Available tools list
        """
        self.logger.debug(f"MCP List Tools: session={session_id}")

        try:
            if not session_id:
                raise ValidationError("session_id is required")

            tools = await self.mcp_server.list_tools(session_id)

            return {
                "status": "success",
                "status_code": 200,
                "data": {
                    "session_id": session_id,
                    "tools": tools,
                    "count": len(tools),
                },
            }

        except ValidationError as e:
            raise
        except Exception as e:
            self.logger.error(f"MCP list tools failed: {str(e)}")
            raise ServerError(f"Failed to list tools: {str(e)}")

    async def mcp_call_tool(
        self,
        session_id: str,
        tool_name: str,
        arguments: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        MCP Call Tool endpoint handler.
        
        Args:
            session_id: MCP session identifier
            tool_name: Tool name to call
            arguments: Tool arguments
            
        Returns:
            Tool execution result
        """
        self.logger.info(f"MCP Call Tool: {tool_name} in session {session_id}")

        try:
            if not session_id:
                raise ValidationError("session_id is required")
            if not tool_name:
                raise ValidationError("tool_name is required")
            if arguments is None:
                arguments = {}

            result = await self.mcp_server.call_tool(
                session_id=session_id,
                tool_name=tool_name,
                arguments=arguments,
            )

            return {
                "status": "success",
                "status_code": 200,
                "data": {
                    "session_id": session_id,
                    "tool_name": tool_name,
                    "result": result,
                },
            }

        except ValidationError as e:
            raise
        except Exception as e:
            self.logger.error(f"MCP tool call failed: {str(e)}")
            raise ServerError(f"Tool execution failed: {str(e)}")

    # ========================================================================
    # WebSocket Endpoint
    # ========================================================================

    async def websocket_stream(
        self,
        session_id: str,
        message_handler: Callable,
    ) -> None:
        """
        WebSocket streaming endpoint handler.
        
        Args:
            session_id: MCP session identifier
            message_handler: Async function to handle incoming messages
            
        Raises:
            ValidationError: If session_id is invalid
        """
        self.logger.info(f"WebSocket stream opened: session={session_id}")

        try:
            if not session_id:
                raise ValidationError("session_id is required")

            # Establish streaming connection
            async for message in self.mcp_server.stream_payloads(session_id):
                await message_handler(message)

        except ValidationError as e:
            self.logger.warning(f"WebSocket validation error: {str(e)}")
            raise
        except Exception as e:
            self.logger.error(f"WebSocket streaming error: {str(e)}")
            raise ServerError(f"Streaming failed: {str(e)}")

    # ========================================================================
    # Helper Methods
    # ========================================================================

    async def _check_llm_service(self) -> str:
        """Check LLM service status."""
        try:
            is_healthy = await self.mcp_server.check_llm_health()
            return "running" if is_healthy else "unavailable"
        except Exception:
            return "unavailable"

    async def _check_knowledge_service(self) -> str:
        """Check knowledge base service status."""
        try:
            is_healthy = await self.mcp_server.check_knowledge_health()
            return "running" if is_healthy else "unavailable"
        except Exception:
            return "unavailable"


# ==============================================================================
# Router Setup
# ==============================================================================

class Router:
    """
    Central HTTP router for managing routes and dispatching requests.
    
    Attributes:
        handlers: RouteHandlers instance
        registry: RouteRegistry instance
    """

    def __init__(self, mcp_server: MCPServer, settings: Optional[Settings] = None):
        """
        Initialize router.
        
        Args:
            mcp_server: MCPServer instance
            settings: Application settings
        """
        self.mcp_server = mcp_server
        self.settings = settings or Settings()
        self.logger = get_logger(__name__)
        self.handlers = RouteHandlers(mcp_server, settings)
        self.registry = RouteRegistry(settings)

    async def dispatch(
        self,
        method: str,
        path: str,
        body: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Dispatch request to appropriate handler.
        
        Args:
            method: HTTP method
            path: Request path
            body: Request body
            **kwargs: Additional request context
            
        Returns:
            Response data
            
        Raises:
            ValidationError: If route not found or invalid
        """
        self.logger.debug(f"Dispatching {method} {path}")

        try:
            # Find route
            route = self.registry.get_route(path, method)
            if not route:
                raise ValidationError(f"Route not found: {method} {path}")

            # Get handler
            handler_name = route.get("handler")
            handler_method = getattr(self.handlers, handler_name, None)
            if not handler_method:
                raise ServerError(f"Handler not found: {handler_name}")

            # Call handler
            if body:
                response = await handler_method(**body, **kwargs)
            else:
                response = await handler_method(**kwargs)

            return response

        except (ValidationError, ServerError) as e:
            self.logger.warning(f"Request dispatch failed: {str(e)}")
            raise

    def get_routes(self) -> Dict[str, Any]:
        """Get all registered routes."""
        return self.registry.get_all_routes()

    def get_route_info(self) -> Dict[str, Any]:
        """Get detailed route information."""
        return self.registry.get_route_info()


# ==============================================================================
# Setup Functions
# ==============================================================================

def setup_routes(
    mcp_server: MCPServer,
    settings: Optional[Settings] = None,
) -> Router:
    """
    Initialize and setup all routes.
    
    Args:
        mcp_server: MCPServer instance
        settings: Application settings
        
    Returns:
        Configured Router instance
        
    Raises:
        ValueError: If mcp_server is None
        
    Example:
        >>> from src.mcp_server.server import MCPServer
        >>> from src.config.settings import Settings
        >>> 
        >>> server = MCPServer()
        >>> settings = Settings()
        >>> router = setup_routes(server, settings)
    """
    if mcp_server is None:
        raise ValueError("mcp_server cannot be None")

    logger.info("Setting up API routes...")

    try:
        router = Router(mcp_server, settings)
        
        routes = router.get_routes()
        logger.info(f"Successfully configured {len(routes)} routes")
        
        # Log route categories
        route_info = router.get_route_info()
        for category, routes_dict in route_info.items():
            if routes_dict:
                logger.debug(f"  {category}: {len(routes_dict)} routes")

        return router

    except Exception as e:
        logger.error(f"Failed to setup routes: {str(e)}", exc_info=True)
        raise ServerError(f"Route setup failed: {str(e)}")


def get_route_documentation() -> Dict[str, Any]:
    """
    Get comprehensive route documentation.
    
    Returns:
        Documentation for all routes organized by category
        
    Example:
        >>> docs = get_route_documentation()
        >>> print(docs["health"])
    """
    return {
        "version": "1.0.0",
        "title": "HyFuzz MCP Server API",
        "description": "RESTful API and MCP protocol endpoints for payload generation and vulnerability analysis",
        "categories": {
            "health": {
                "description": "Server health and status endpoints",
                "endpoints": [
                    {
                        "path": "/health",
                        "method": "GET",
                        "description": "Quick health check",
                        "public": True,
                    },
                    {
                        "path": "/api/v1/status",
                        "method": "GET",
                        "description": "Detailed system status",
                    },
                ]
            },
            "payloads": {
                "description": "Payload generation and refinement",
                "endpoints": [
                    {
                        "path": "/api/v1/payloads/generate",
                        "method": "POST",
                        "description": "Generate fuzzing payloads",
                        "auth_required": True,
                    },
                    {
                        "path": "/api/v1/payloads/refine",
                        "method": "POST",
                        "description": "Refine payload strategy",
                        "auth_required": True,
                    },
                ]
            },
            "knowledge": {
                "description": "Vulnerability knowledge base queries",
                "endpoints": [
                    {
                        "path": "/api/v1/knowledge/cwe/{cwe_id}",
                        "method": "GET",
                        "description": "Get CWE information",
                    },
                    {
                        "path": "/api/v1/knowledge/cve/{cve_id}",
                        "method": "GET",
                        "description": "Get CVE information",
                    },
                    {
                        "path": "/api/v1/knowledge/search",
                        "method": "POST",
                        "description": "Search knowledge base",
                    },
                ]
            },
            "feedback": {
                "description": "Feedback and metrics",
                "endpoints": [
                    {
                        "path": "/api/v1/feedback",
                        "method": "POST",
                        "description": "Submit payload execution feedback",
                        "auth_required": True,
                    },
                    {
                        "path": "/api/v1/metrics",
                        "method": "GET",
                        "description": "Get performance metrics",
                        "auth_required": True,
                    },
                ]
            },
            "mcp": {
                "description": "MCP protocol endpoints",
                "endpoints": [
                    {
                        "path": "/mcp/initialize",
                        "method": "POST",
                        "description": "Initialize MCP session",
                    },
                    {
                        "path": "/mcp/tools/list",
                        "method": "POST",
                        "description": "List available tools",
                    },
                    {
                        "path": "/mcp/tools/call",
                        "method": "POST",
                        "description": "Execute tool",
                    },
                ]
            },
            "websocket": {
                "description": "Real-time streaming",
                "endpoints": [
                    {
                        "path": "/api/v1/stream",
                        "method": "UPGRADE",
                        "description": "Real-time payload streaming",
                        "auth_required": True,
                    },
                ]
            },
        }
    }


# ==============================================================================
# Exports
# ==============================================================================

__all__ = [
    "Router",
    "RouteRegistry",
    "RouteHandlers",
    "setup_routes",
    "get_route_documentation",
    "route",
]