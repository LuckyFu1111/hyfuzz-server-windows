"""
HyFuzz MCP Server - API Request Handlers

This module contains all request handler functions for the MCP server API endpoints.
It provides handlers for MCP protocol operations, health checks, and status monitoring.

Key Features:
- Full MCP 2024.01 protocol support
- Async request handling
- Comprehensive error handling and validation
- Request/response logging
- Type-safe implementations with Pydantic models

Author: HyFuzz Team
Version: 1.0.0
"""

import asyncio
import time
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
from functools import wraps

from ..mcp_server.server import MCPServer
from ..mcp_server.message_handler import MessageHandler
from ..mcp_server.capability_manager import CapabilityManager
from ..mcp_server.session_manager import SessionManager

from ..llm.llm_service import LLMService
from ..llm.cot_engine import CoTEngine
from ..llm.cache_manager import CacheManager

from ..knowledge.cwe_repository import CWERepository
from ..knowledge.cve_repository import CVERepository
from ..knowledge.vulnerability_db import VulnerabilityDB

from ..models.message_models import (
    MCPInitializeRequest,
    MCPInitializeResponse,
    MCPToolCall,
    MCPToolResponse,
    MCPResourceList,
    MCPToolList,
)
from ..models.common_models import ErrorResponse

from ..config.settings import Settings

from ..utils.logger import get_logger
from ..utils.exceptions import (
    MCPProtocolError,
    ValidationError,
    AuthenticationError,
    ServerError,
)
from ..utils.validators import validate_request_payload


# Initialize logger
logger = get_logger(__name__)


def async_handler(func):
    """
    Decorator for async request handlers.
    Provides consistent error handling, logging, and timing for all handlers.
    """
    @wraps(func)
    async def wrapper(*args, **kwargs):
        handler_name = func.__name__
        start_time = time.time()

        try:
            logger.debug(f"Handler {handler_name} started", extra={
                "handler": handler_name,
                "timestamp": datetime.now(timezone.utc).isoformat()
            })

            result = await func(*args, **kwargs)

            elapsed_time = time.time() - start_time
            logger.debug(f"Handler {handler_name} completed", extra={
                "handler": handler_name,
                "elapsed_ms": round(elapsed_time * 1000, 2),
                "timestamp": datetime.now(timezone.utc).isoformat()
            })

            return result

        except Exception as e:
            elapsed_time = time.time() - start_time
            logger.error(f"Handler {handler_name} failed", extra={
                "handler": handler_name,
                "error": str(e),
                "elapsed_ms": round(elapsed_time * 1000, 2),
                "timestamp": datetime.now(timezone.utc).isoformat()
            })
            raise

    return wrapper


class RequestHandlers:
    """
    Centralized request handler class for all API endpoints.
    Manages lifecycle of MCP operations and coordinates with service layers.
    """

    def __init__(self, settings: Settings):
        """
        Initialize request handlers with configuration and service instances.

        Args:
            settings: Application configuration object (Settings)

        Raises:
            ServerError: If service initialization fails
        """
        self.settings = settings
        self.logger = get_logger(__name__)

        # Initialize core services
        try:
            self.mcp_server = MCPServer(settings)
            self.message_handler = MessageHandler()
            self.capability_manager = CapabilityManager()
            self.session_manager = SessionManager()

            # Initialize LLM services
            self.llm_service = LLMService(settings)
            self.cot_engine = CoTEngine(settings, self.llm_service)
            self.cache_manager = CacheManager(settings)

            # Initialize knowledge bases
            self.cwe_repo = CWERepository(settings)
            self.cve_repo = CVERepository(settings)
            self.vuln_db = VulnerabilityDB(settings)

            self.logger.info("All services initialized successfully")

        except Exception as e:
            self.logger.error(f"Service initialization failed: {str(e)}")
            raise ServerError(f"Failed to initialize services: {str(e)}")

    # ========================================================================
    # Health & Status Handlers
    # ========================================================================

    @async_handler
    async def handle_health_check(self) -> Dict[str, Any]:
        """
        Health check endpoint handler.
        Returns server health status and component availability.

        Returns:
            Dict containing:
                - status: "healthy" or "degraded"
                - version: Server version
                - timestamp: ISO 8601 timestamp
                - components: Component health status

        Raises:
            ServerError: If health check fails
        """
        try:
            components_health = {
                "mcp_server": await self._check_mcp_server(),
                "llm_service": await self._check_llm_service(),
                "cache": await self._check_cache(),
                "knowledge_base": await self._check_knowledge_base(),
            }

            # Determine overall status
            all_healthy = all(
                status.get("healthy", False)
                for status in components_health.values()
            )

            overall_status = "healthy" if all_healthy else "degraded"

            response = {
                "status": overall_status,
                "version": self.settings.VERSION,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "components": components_health,
                "uptime_seconds": self._get_uptime(),
            }

            self.logger.info(f"Health check completed: {overall_status}")
            return response

        except Exception as e:
            self.logger.error(f"Health check failed: {str(e)}")
            raise ServerError(f"Health check failed: {str(e)}")

    @async_handler
    async def handle_status(self) -> Dict[str, Any]:
        """
        Status endpoint handler.
        Returns detailed server status including sessions, cache, and metrics.

        Returns:
            Dict containing:
                - status: Server operational status
                - active_sessions: Number of active MCP sessions
                - cache_stats: Cache hit/miss statistics
                - memory_usage: Memory consumption details
                - response_time_ms: Average response time

        Raises:
            ServerError: If status retrieval fails
        """
        try:
            active_sessions = self.session_manager.get_active_count()
            cache_stats = self.cache_manager.get_statistics()

            response = {
                "status": "operational",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "server": {
                    "version": self.settings.VERSION,
                    "environment": self.settings.ENVIRONMENT,
                    "debug_mode": self.settings.DEBUG,
                },
                "sessions": {
                    "active": active_sessions,
                    "max_allowed": self.settings.MAX_SESSIONS,
                },
                "cache": {
                    "enabled": self.settings.CACHE_ENABLED,
                    "backend": self.settings.CACHE_BACKEND,
                    "hits": cache_stats.get("hits", 0),
                    "misses": cache_stats.get("misses", 0),
                    "size_mb": cache_stats.get("size_mb", 0),
                },
                "llm": {
                    "provider": self.settings.OLLAMA_BASE_URL,
                    "model": self.settings.OLLAMA_MODEL,
                    "timeout_seconds": self.settings.OLLAMA_TIMEOUT,
                },
            }

            self.logger.info("Status check completed successfully")
            return response

        except Exception as e:
            self.logger.error(f"Status check failed: {str(e)}")
            raise ServerError(f"Status check failed: {str(e)}")

    # ========================================================================
    # MCP Protocol Handlers
    # ========================================================================

    @async_handler
    async def handle_mcp_initialize(
        self, request: MCPInitializeRequest
    ) -> MCPInitializeResponse:
        """
        MCP Initialize endpoint handler (POST /mcp/initialize).
        Establishes new MCP connection with client validation.

        Args:
            request: MCPInitializeRequest containing protocol version and client info

        Returns:
            MCPInitializeResponse with server capabilities and session info

        Raises:
            ValidationError: If request validation fails
            MCPProtocolError: If protocol negotiation fails
            AuthenticationError: If authentication fails
        """
        try:
            # Validate request
            if not request.protocol_version:
                raise ValidationError("Protocol version is required")

            if not request.client_info:
                raise ValidationError("Client info is required")

            self.logger.info(
                f"MCP initialization request from {request.client_info.name} "
                f"v{request.client_info.version}"
            )

            # Check protocol compatibility
            supported_versions = ["2024.01", "2023.12"]
            if request.protocol_version not in supported_versions:
                raise MCPProtocolError(
                    f"Protocol version {request.protocol_version} not supported. "
                    f"Supported: {', '.join(supported_versions)}"
                )

            # Check API key if authentication is enabled
            if self.settings.API_KEY_REQUIRED and request.api_key:
                if request.api_key != self.settings.API_KEY:
                    raise AuthenticationError("Invalid API key")

            # Create new session
            session_id = await self.session_manager.create_session(
                client_name=request.client_info.name,
                client_version=request.client_info.version,
            )

            # Get server capabilities
            capabilities = self.capability_manager.get_capabilities()

            response = MCPInitializeResponse(
                protocol_version=request.protocol_version,
                server_info={
                    "name": "hyfuzz-mcp-server",
                    "version": self.settings.VERSION,
                },
                capabilities=capabilities,
                session_id=session_id,
                timestamp=datetime.now(timezone.utc).isoformat(),
            )

            self.logger.info(f"MCP session created: {session_id}")
            return response

        except (ValidationError, MCPProtocolError, AuthenticationError) as e:
            self.logger.warning(f"Initialization validation failed: {str(e)}")
            raise
        except Exception as e:
            self.logger.error(f"MCP initialization failed: {str(e)}")
            raise ServerError(f"Failed to initialize MCP connection: {str(e)}")

    @async_handler
    async def handle_list_resources(self, session_id: str) -> MCPResourceList:
        """
        List Resources endpoint handler (GET /mcp/resources).
        Returns available resources including knowledge bases and tools.

        Args:
            session_id: MCP session identifier

        Returns:
            MCPResourceList containing available resources

        Raises:
            ValidationError: If session is invalid
            ServerError: If resource enumeration fails
        """
        try:
            # Validate session
            if not await self.session_manager.validate_session(session_id):
                raise ValidationError(f"Invalid session: {session_id}")

            self.logger.debug(f"Listing resources for session {session_id}")

            resources = [
                {
                    "name": "cwe_repository",
                    "description": "CWE (Common Weakness Enumeration) database",
                    "uri": f"cwe://",
                    "type": "knowledge_base",
                    "read_only": True,
                },
                {
                    "name": "cve_repository",
                    "description": "CVE (Common Vulnerabilities and Exposures) database",
                    "uri": f"cve://",
                    "type": "knowledge_base",
                    "read_only": True,
                },
                {
                    "name": "vulnerability_db",
                    "description": "Combined vulnerability database with relationships",
                    "uri": "vuln://",
                    "type": "knowledge_base",
                    "read_only": True,
                },
                {
                    "name": "payload_cache",
                    "description": "Historical payload cache with semantic embeddings",
                    "uri": "cache://payloads",
                    "type": "cache",
                    "read_only": False,
                },
            ]

            response = MCPResourceList(
                resources=resources,
                count=len(resources),
                session_id=session_id,
            )

            self.logger.info(
                f"Listed {len(resources)} resources for session {session_id}"
            )
            return response

        except ValidationError as e:
            self.logger.warning(f"Session validation failed: {str(e)}")
            raise
        except Exception as e:
            self.logger.error(f"Failed to list resources: {str(e)}")
            raise ServerError(f"Failed to list resources: {str(e)}")

    @async_handler
    async def handle_list_tools(self, session_id: str) -> MCPToolList:
        """
        List Tools endpoint handler (GET /mcp/tools).
        Returns available MCP tools and their specifications.

        Args:
            session_id: MCP session identifier

        Returns:
            MCPToolList containing available tools with specifications

        Raises:
            ValidationError: If session is invalid
            ServerError: If tool enumeration fails
        """
        try:
            # Validate session
            if not await self.session_manager.validate_session(session_id):
                raise ValidationError(f"Invalid session: {session_id}")

            self.logger.debug(f"Listing tools for session {session_id}")

            tools = [
                {
                    "name": "generate_payloads",
                    "description": "Generate fuzzing payloads using LLM with CoT reasoning",
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "protocol": {
                                "type": "string",
                                "description": "Target protocol (http, coap, mqtt, etc.)",
                            },
                            "target": {
                                "type": "string",
                                "description": "Target address or hostname",
                            },
                            "vulnerability_type": {
                                "type": "string",
                                "description": "CWE or vulnerability category to target",
                            },
                            "context": {
                                "type": "string",
                                "description": "Additional context for payload generation",
                            },
                            "count": {
                                "type": "integer",
                                "description": "Number of payloads to generate",
                                "default": 5,
                            },
                        },
                        "required": ["protocol", "target"],
                    },
                    "execution_mode": "async",
                    "timeout_seconds": 30,
                },
                {
                    "name": "analyze_vulnerability",
                    "description": "Analyze vulnerability using knowledge base and LLM",
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "cve_id": {
                                "type": "string",
                                "description": "CVE identifier (e.g., CVE-2021-12345)",
                            },
                            "cwe_id": {
                                "type": "string",
                                "description": "CWE identifier (e.g., CWE-89)",
                            },
                            "detailed": {
                                "type": "boolean",
                                "description": "Request detailed analysis",
                                "default": False,
                            },
                        },
                    },
                    "execution_mode": "async",
                    "timeout_seconds": 15,
                },
                {
                    "name": "query_knowledge_base",
                    "description": "Query CWE/CVE knowledge base for information",
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "description": "Search query for vulnerabilities",
                            },
                            "repository": {
                                "type": "string",
                                "enum": ["cwe", "cve", "all"],
                                "description": "Which repository to search",
                                "default": "all",
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Maximum results to return",
                                "default": 10,
                            },
                        },
                        "required": ["query"],
                    },
                    "execution_mode": "async",
                    "timeout_seconds": 10,
                },
                {
                    "name": "cache_payload",
                    "description": "Cache payload with semantic embedding for future retrieval",
                    "input_schema": {
                        "type": "object",
                        "properties": {
                            "payload": {
                                "type": "string",
                                "description": "Payload content to cache",
                            },
                            "metadata": {
                                "type": "object",
                                "description": "Additional metadata",
                            },
                            "tags": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Tags for categorization",
                            },
                        },
                        "required": ["payload"],
                    },
                    "execution_mode": "async",
                    "timeout_seconds": 5,
                },
            ]

            response = MCPToolList(
                tools=tools,
                count=len(tools),
                session_id=session_id,
            )

            self.logger.info(
                f"Listed {len(tools)} tools for session {session_id}"
            )
            return response

        except ValidationError as e:
            self.logger.warning(f"Session validation failed: {str(e)}")
            raise
        except Exception as e:
            self.logger.error(f"Failed to list tools: {str(e)}")
            raise ServerError(f"Failed to list tools: {str(e)}")

    @async_handler
    async def handle_call_tool(
        self, session_id: str, tool_call: MCPToolCall
    ) -> MCPToolResponse:
        """
        Call Tool endpoint handler (POST /mcp/tools/call).
        Executes requested tool with validation and error handling.

        Args:
            session_id: MCP session identifier
            tool_call: Tool call specification with name and arguments

        Returns:
            MCPToolResponse with execution results

        Raises:
            ValidationError: If tool call is invalid
            ServerError: If tool execution fails
        """
        try:
            # Validate session
            if not await self.session_manager.validate_session(session_id):
                raise ValidationError(f"Invalid session: {session_id}")

            # Validate tool call
            if not tool_call.name:
                raise ValidationError("Tool name is required")

            self.logger.info(
                f"Tool call: {tool_call.name} with args {tool_call.arguments}"
            )

            # Route to appropriate tool handler
            if tool_call.name == "generate_payloads":
                result = await self._handle_generate_payloads(
                    tool_call.arguments
                )
            elif tool_call.name == "analyze_vulnerability":
                result = await self._handle_analyze_vulnerability(
                    tool_call.arguments
                )
            elif tool_call.name == "query_knowledge_base":
                result = await self._handle_query_knowledge_base(
                    tool_call.arguments
                )
            elif tool_call.name == "cache_payload":
                result = await self._handle_cache_payload(
                    tool_call.arguments
                )
            else:
                raise ValidationError(f"Unknown tool: {tool_call.name}")

            response = MCPToolResponse(
                tool_name=tool_call.name,
                status="success",
                result=result,
                execution_time_ms=tool_call.metadata.get(
                    "execution_time_ms", 0
                ) if tool_call.metadata else 0,
                session_id=session_id,
            )

            self.logger.info(f"Tool {tool_call.name} executed successfully")
            return response

        except ValidationError as e:
            self.logger.warning(f"Tool call validation failed: {str(e)}")
            return MCPToolResponse(
                tool_name=tool_call.name,
                status="error",
                error=str(e),
                session_id=session_id,
            )
        except Exception as e:
            self.logger.error(f"Tool execution failed: {str(e)}")
            return MCPToolResponse(
                tool_name=tool_call.name,
                status="error",
                error=f"Tool execution failed: {str(e)}",
                session_id=session_id,
            )

    # ========================================================================
    # Tool Implementation Handlers
    # ========================================================================

    async def _handle_generate_payloads(
        self, arguments: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Generate fuzzing payloads using LLM with Chain-of-Thought reasoning.

        Args:
            arguments: Tool arguments including protocol, target, etc.

        Returns:
            Generated payloads with metadata

        Raises:
            ValidationError: If arguments are invalid
        """
        protocol = arguments.get("protocol")
        target = arguments.get("target")
        vulnerability_type = arguments.get("vulnerability_type", "")
        context = arguments.get("context", "")
        count = arguments.get("count", 5)

        if not protocol or not target:
            raise ValidationError("protocol and target are required")

        self.logger.debug(f"Generating payloads for {protocol}://{target}")

        try:
            # Use LLM service with CoT engine for payload generation
            payloads = await self.cot_engine.generate_payloads(
                protocol=protocol,
                target=target,
                vulnerability_type=vulnerability_type,
                context=context,
                count=count,
            )

            return {
                "protocol": protocol,
                "target": target,
                "count": len(payloads),
                "payloads": payloads,
                "generated_at": datetime.now(timezone.utc).isoformat(),
            }

        except Exception as e:
            self.logger.error(f"Payload generation failed: {str(e)}")
            raise ServerError(f"Failed to generate payloads: {str(e)}")

    async def _handle_analyze_vulnerability(
        self, arguments: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Analyze vulnerability using knowledge base and LLM.

        Args:
            arguments: Tool arguments including CVE/CWE IDs

        Returns:
            Vulnerability analysis results

        Raises:
            ValidationError: If arguments are invalid
        """
        cve_id = arguments.get("cve_id", "")
        cwe_id = arguments.get("cwe_id", "")
        detailed = arguments.get("detailed", False)

        if not cve_id and not cwe_id:
            raise ValidationError("Either cve_id or cwe_id is required")

        self.logger.debug(f"Analyzing vulnerability: CVE={cve_id}, CWE={cwe_id}")

        try:
            analysis = {
                "cve_id": cve_id,
                "cwe_id": cwe_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

            # Query knowledge bases
            if cve_id:
                cve_data = await self.cve_repo.get_by_id(cve_id)
                if cve_data:
                    analysis["cve_data"] = cve_data

            if cwe_id:
                cwe_data = await self.cwe_repo.get_by_id(cwe_id)
                if cwe_data:
                    analysis["cwe_data"] = cwe_data

            # Generate detailed analysis with LLM if requested
            if detailed and (cve_id or cwe_id):
                llm_analysis = await self.llm_service.analyze(
                    cve_id=cve_id,
                    cwe_id=cwe_id,
                )
                analysis["llm_analysis"] = llm_analysis

            return analysis

        except Exception as e:
            self.logger.error(f"Vulnerability analysis failed: {str(e)}")
            raise ServerError(f"Failed to analyze vulnerability: {str(e)}")

    async def _handle_query_knowledge_base(
        self, arguments: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Query CWE/CVE knowledge base for information.

        Args:
            arguments: Tool arguments including query and repository

        Returns:
            Query results from knowledge base

        Raises:
            ValidationError: If arguments are invalid
        """
        query = arguments.get("query")
        repository = arguments.get("repository", "all")
        limit = arguments.get("limit", 10)

        if not query:
            raise ValidationError("query is required")

        self.logger.debug(f"Querying knowledge base: {query} in {repository}")

        try:
            results = {
                "query": query,
                "repository": repository,
                "limit": limit,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "items": [],
            }

            # Query appropriate repositories
            if repository in ["cwe", "all"]:
                cwe_results = await self.cwe_repo.search(query, limit)
                results["items"].extend([
                    {"type": "cwe", **item} for item in cwe_results
                ])

            if repository in ["cve", "all"]:
                cve_results = await self.cve_repo.search(query, limit)
                results["items"].extend([
                    {"type": "cve", **item} for item in cve_results
                ])

            results["total"] = len(results["items"])
            return results

        except Exception as e:
            self.logger.error(f"Knowledge base query failed: {str(e)}")
            raise ServerError(f"Failed to query knowledge base: {str(e)}")

    async def _handle_cache_payload(
        self, arguments: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Cache payload with semantic embedding for future retrieval.

        Args:
            arguments: Tool arguments including payload and metadata

        Returns:
            Caching confirmation with payload ID

        Raises:
            ValidationError: If arguments are invalid
        """
        payload = arguments.get("payload")
        metadata = arguments.get("metadata", {})
        tags = arguments.get("tags", [])

        if not payload:
            raise ValidationError("payload is required")

        self.logger.debug(f"Caching payload with {len(tags)} tags")

        try:
            # Cache payload with embedding
            payload_id = await self.cache_manager.cache_payload(
                payload=payload,
                metadata=metadata,
                tags=tags,
            )

            return {
                "payload_id": payload_id,
                "cached_at": datetime.now(timezone.utc).isoformat(),
                "size_bytes": len(payload.encode("utf-8")),
                "tags": tags,
            }

        except Exception as e:
            self.logger.error(f"Payload caching failed: {str(e)}")
            raise ServerError(f"Failed to cache payload: {str(e)}")

    # ========================================================================
    # Helper Methods
    # ========================================================================

    async def _check_mcp_server(self) -> Dict[str, Any]:
        """Check MCP server component health."""
        try:
            return {
                "healthy": True,
                "status": "operational",
                "sessions_active": self.session_manager.get_active_count(),
            }
        except Exception as e:
            self.logger.error(f"MCP server health check failed: {str(e)}")
            return {"healthy": False, "status": "error", "error": str(e)}

    async def _check_llm_service(self) -> Dict[str, Any]:
        """Check LLM service connectivity and availability."""
        try:
            is_available = await self.llm_service.health_check()
            return {
                "healthy": is_available,
                "status": "operational" if is_available else "unavailable",
                "provider": self.settings.OLLAMA_BASE_URL,
                "model": self.settings.OLLAMA_MODEL,
            }
        except Exception as e:
            self.logger.error(f"LLM service health check failed: {str(e)}")
            return {"healthy": False, "status": "error", "error": str(e)}

    async def _check_cache(self) -> Dict[str, Any]:
        """Check cache system health."""
        try:
            stats = self.cache_manager.get_statistics()
            return {
                "healthy": True,
                "status": "operational",
                "backend": self.settings.CACHE_BACKEND,
                "enabled": self.settings.CACHE_ENABLED,
                **stats,
            }
        except Exception as e:
            self.logger.error(f"Cache health check failed: {str(e)}")
            return {"healthy": False, "status": "error", "error": str(e)}

    async def _check_knowledge_base(self) -> Dict[str, Any]:
        """Check knowledge base availability."""
        try:
            cwe_available = await self.cwe_repo.is_available()
            cve_available = await self.cve_repo.is_available()

            return {
                "healthy": cwe_available and cve_available,
                "status": "operational" if (
                    cwe_available and cve_available
                ) else "degraded",
                "cwe_available": cwe_available,
                "cve_available": cve_available,
            }
        except Exception as e:
            self.logger.error(f"Knowledge base health check failed: {str(e)}")
            return {"healthy": False, "status": "error", "error": str(e)}

    def _get_uptime(self) -> float:
        """Get server uptime in seconds."""
        try:
            if hasattr(self.mcp_server, "start_time"):
                return time.time() - self.mcp_server.start_time
        except Exception as e:
            self.logger.debug(f"Could not get uptime: {str(e)}")
        return 0.0


# ============================================================================
# Error Handler Function
# ============================================================================

async def handle_error(error: Exception) -> Dict[str, Any]:
    """
    Global error handler for API errors.
    Converts exceptions to appropriate HTTP responses.

    Args:
        error: Exception that occurred

    Returns:
        Error response dictionary

    Raises:
        None (all exceptions are converted to responses)
    """
    logger.error(f"API error occurred: {str(error)}", exc_info=True)

    if isinstance(error, ValidationError):
        return {
            "error": "validation_error",
            "message": str(error),
            "status_code": 400,
        }
    elif isinstance(error, AuthenticationError):
        return {
            "error": "authentication_error",
            "message": str(error),
            "status_code": 401,
        }
    elif isinstance(error, MCPProtocolError):
        return {
            "error": "protocol_error",
            "message": str(error),
            "status_code": 400,
        }
    elif isinstance(error, ServerError):
        return {
            "error": "server_error",
            "message": str(error),
            "status_code": 500,
        }
    else:
        return {
            "error": "internal_error",
            "message": "An unexpected error occurred",
            "status_code": 500,
        }


__all__ = [
    "RequestHandlers",
    "async_handler",
    "handle_error",
]