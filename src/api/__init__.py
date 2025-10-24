"""
API Module - MCP Server RESTful API Interface Layer

This module provides RESTful API interfaces for communicating with the MCP server.
It includes route definitions, request handling, middleware, and validation functionality.

Structure:
    - routes.py: Defines API routes and endpoints
    - handlers.py: Handles HTTP request business logic
    - middleware.py: Request/response middleware processing
    - validators.py: Request data validation

Dependencies:
    ├─ src.mcp_server: MCP server core functionality
    ├─ src.llm: LLM service and inference engine
    ├─ src.models: Data model definitions
    ├─ src.config: Configuration management
    ├─ src.utils: Logging, exceptions, decorators, and other utilities
    └─ src.knowledge: Knowledge base access
"""

import logging
from typing import TYPE_CHECKING, Optional

# Local imports
from .routes import router, setup_routes
from .handlers import (
    APIHandler,
    HealthCheckHandler,
    LLMHandler,
    KnowledgeHandler,
)
from .middleware import (
    setup_middleware,
    ErrorHandlingMiddleware,
    LoggingMiddleware,
    AuthMiddleware,
    CORSMiddleware,
    RateLimitMiddleware,
)
from .validators import (
    RequestValidator,
    validate_llm_request,
    validate_knowledge_request,
    validate_health_check_request,
)

if TYPE_CHECKING:
    from src.mcp_server.server import MCPServer
    from src.config.settings import Settings

__all__ = [
    # Routes
    "router",
    "setup_routes",

    # Handler classes
    "APIHandler",
    "HealthCheckHandler",
    "LLMHandler",
    "KnowledgeHandler",

    # Middleware
    "setup_middleware",
    "ErrorHandlingMiddleware",
    "LoggingMiddleware",
    "AuthMiddleware",
    "CORSMiddleware",
    "RateLimitMiddleware",

    # Validators
    "RequestValidator",
    "validate_llm_request",
    "validate_knowledge_request",
    "validate_health_check_request",

    # Initialization functions
    "setup_api",
]

logger = logging.getLogger(__name__)


def setup_api(
        mcp_server: "MCPServer",
        settings: Optional["Settings"] = None,
) -> dict:
    """
    Initialize the API module.

    This function performs complete initialization of the API layer, including:
    1. Middleware configuration
    2. Route registration
    3. Handler initialization
    4. Validator configuration

    Args:
        mcp_server: MCPServer instance, the API will communicate with the core server
                   through this instance
        settings: Optional configuration object for customizing API behavior

    Returns:
        A dictionary containing API configuration:
        {
            "router": configured router object,
            "middleware": configured middleware list,
            "handlers": initialized handler instances,
            "validators": validator instance,
        }

    Raises:
        ValueError: If mcp_server is None

    Example:
        >>> from src.mcp_server.server import MCPServer
        >>> from src.config.settings import Settings
        >>>
        >>> server = MCPServer()
        >>> settings = Settings()
        >>> api_config = setup_api(server, settings)
    """
    if mcp_server is None:
        raise ValueError("mcp_server cannot be None")

    logger.info("Initializing API module...")

    try:
        # 1. Setup middleware
        middleware_list = setup_middleware(settings)
        logger.debug(f"Configured {len(middleware_list)} middleware components")

        # 2. Setup routes
        configured_router = setup_routes(mcp_server, settings)
        logger.debug("API routes configured successfully")

        # 3. Initialize handlers
        handlers = {
            "api": APIHandler(mcp_server, settings),
            "health": HealthCheckHandler(mcp_server, settings),
            "llm": LLMHandler(mcp_server, settings),
            "knowledge": KnowledgeHandler(mcp_server, settings),
        }
        logger.debug("Request handlers initialized")

        # 4. Initialize validators
        validator = RequestValidator(settings)
        logger.debug("Request validators initialized")

        api_config = {
            "router": configured_router,
            "middleware": middleware_list,
            "handlers": handlers,
            "validators": validator,
        }

        logger.info("API module initialization completed successfully")
        return api_config

    except Exception as e:
        logger.error(f"API module initialization failed: {e}", exc_info=True)
        raise


def get_api_info() -> dict:
    """
    Get information about the API module.

    Returns:
        A dictionary containing module information
    """
    return {
        "module": "api",
        "version": "1.0.0",
        "description": "MCP Server RESTful API Interface Layer",
        "components": {
            "routes": "API route definitions",
            "handlers": "HTTP request handlers",
            "middleware": "Request/response middleware",
            "validators": "Request data validation",
        },
        "exports": __all__,
    }


# Module-level initialization logging
logger.debug("API module loaded successfully")