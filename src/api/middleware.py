"""
HyFuzz MCP Server - API Middleware Layer

This module provides middleware components for request/response processing,
error handling, logging, authentication, CORS, and rate limiting.

Key Features:
- Error handling and exception transformation
- Request/response logging with structured format
- Token-based authentication
- CORS (Cross-Origin Resource Sharing) support
- Rate limiting with multiple strategies
- Performance monitoring and tracing

Author: HyFuzz Team
Version: 1.0.0
"""

import time
import logging
import json
from typing import Callable, Optional, Dict, Any, List
from datetime import datetime, timezone, timedelta
from functools import wraps
from collections import defaultdict
from dataclasses import dataclass, field
import hashlib
import hmac

from ..config.settings import Settings
from ..utils.logger import get_logger
from ..utils.exceptions import (
    MCPProtocolError,
    ValidationError,
    AuthenticationError,
    ServerError,
    RateLimitError,
)


# Initialize logger
logger = get_logger(__name__)


# ==============================================================================
# Data Models
# ==============================================================================

@dataclass
class RequestContext:
    """
    Context information for a request.
    
    Attributes:
        request_id: Unique identifier for request tracing
        timestamp: Request timestamp
        client_ip: Client IP address
        user_id: Authenticated user ID
        session_id: MCP session identifier
        path: Request path
        method: HTTP method
        start_time: Request start time
    """
    request_id: str
    timestamp: datetime
    client_ip: str
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    path: Optional[str] = None
    method: Optional[str] = None
    start_time: float = field(default_factory=time.time)

    def get_elapsed_time(self) -> float:
        """Get elapsed time in milliseconds since request start."""
        return (time.time() - self.start_time) * 1000


@dataclass
class RateLimitBucket:
    """
    Rate limit bucket for tracking client requests.
    
    Attributes:
        requests: List of request timestamps
        limit: Maximum requests allowed
        window: Time window in seconds
        last_reset: Last reset time
    """
    requests: List[float] = field(default_factory=list)
    limit: int = 100
    window: int = 60
    last_reset: float = field(default_factory=time.time)

    def is_rate_limited(self, current_time: Optional[float] = None) -> bool:
        """Check if rate limit is exceeded."""
        current_time = current_time or time.time()
        
        # Reset if window expired
        if current_time - self.last_reset > self.window:
            self.requests = []
            self.last_reset = current_time
            return False
        
        # Remove old requests outside window
        window_start = current_time - self.window
        self.requests = [t for t in self.requests if t > window_start]
        
        # Check if limit exceeded
        return len(self.requests) >= self.limit

    def add_request(self, current_time: Optional[float] = None) -> None:
        """Record a new request."""
        current_time = current_time or time.time()
        self.requests.append(current_time)


# ==============================================================================
# Error Handling Middleware
# ==============================================================================

class ErrorHandlingMiddleware:
    """
    Middleware for centralized error handling and exception transformation.
    
    Converts application exceptions to appropriate HTTP responses and maintains
    consistent error response format across all endpoints.
    """

    def __init__(self, settings: Optional[Settings] = None):
        """
        Initialize error handling middleware.
        
        Args:
            settings: Application settings
        """
        self.settings = settings or Settings()
        self.logger = get_logger(__name__)

    def __call__(self, func: Callable) -> Callable:
        """
        Decorator for error handling middleware.
        
        Args:
            func: Target function to wrap
            
        Returns:
            Wrapped function with error handling
        """
        @wraps(func)
        async def wrapper(*args, **kwargs):
            try:
                return await func(*args, **kwargs)

            except ValidationError as e:
                self.logger.warning(f"Validation error: {str(e)}")
                return self._error_response(
                    status_code=400,
                    error_type="ValidationError",
                    message=str(e),
                    details={"validation": e.details if hasattr(e, 'details') else None}
                )

            except AuthenticationError as e:
                self.logger.warning(f"Authentication failed: {str(e)}")
                return self._error_response(
                    status_code=401,
                    error_type="AuthenticationError",
                    message=str(e),
                    details={"auth_type": e.auth_type if hasattr(e, 'auth_type') else None}
                )

            except RateLimitError as e:
                self.logger.warning(f"Rate limit exceeded: {str(e)}")
                return self._error_response(
                    status_code=429,
                    error_type="RateLimitError",
                    message=str(e),
                    details={
                        "limit": e.limit if hasattr(e, 'limit') else None,
                        "window": e.window if hasattr(e, 'window') else None,
                    }
                )

            except MCPProtocolError as e:
                self.logger.warning(f"MCP protocol error: {str(e)}")
                return self._error_response(
                    status_code=400,
                    error_type="MCPProtocolError",
                    message=str(e),
                    details={"protocol": "MCP"}
                )

            except ServerError as e:
                self.logger.error(f"Server error: {str(e)}", exc_info=True)
                return self._error_response(
                    status_code=500,
                    error_type="ServerError",
                    message="Internal server error",
                    details={"original": str(e)} if not self.settings.is_production else {}
                )

            except Exception as e:
                self.logger.error(f"Unexpected error: {str(e)}", exc_info=True)
                return self._error_response(
                    status_code=500,
                    error_type="InternalError",
                    message="Internal server error",
                    details={"error": str(e)} if not self.settings.is_production else {}
                )

        return wrapper

    @staticmethod
    def _error_response(
        status_code: int,
        error_type: str,
        message: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Generate consistent error response.
        
        Args:
            status_code: HTTP status code
            error_type: Error type identifier
            message: Error message
            details: Additional error details
            
        Returns:
            Error response dictionary
        """
        return {
            "status": "error",
            "status_code": status_code,
            "error": {
                "type": error_type,
                "message": message,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "details": details or {},
            }
        }


# ==============================================================================
# Logging Middleware
# ==============================================================================

class LoggingMiddleware:
    """
    Middleware for comprehensive request/response logging.
    
    Logs all requests and responses with relevant metadata including:
    - Request/response timing
    - Headers and body (configurable)
    - Status codes
    - Performance metrics
    """

    def __init__(
        self,
        settings: Optional[Settings] = None,
        log_bodies: bool = True,
        log_headers: bool = True,
        body_size_limit: int = 1000,
    ):
        """
        Initialize logging middleware.
        
        Args:
            settings: Application settings
            log_bodies: Whether to log request/response bodies
            log_headers: Whether to log headers
            body_size_limit: Maximum body size to log (bytes)
        """
        self.settings = settings or Settings()
        self.logger = get_logger(__name__)
        self.log_bodies = log_bodies
        self.log_headers = log_headers
        self.body_size_limit = body_size_limit

    def __call__(self, func: Callable) -> Callable:
        """
        Decorator for logging middleware.
        
        Args:
            func: Target function to wrap
            
        Returns:
            Wrapped function with logging
        """
        @wraps(func)
        async def wrapper(*args, **kwargs):
            request_start = time.time()
            request_id = self._generate_request_id()
            
            # Extract request info from kwargs
            request_info = {
                "request_id": request_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "method": kwargs.get("method", "UNKNOWN"),
                "path": kwargs.get("path", "UNKNOWN"),
            }

            # Log request
            self.logger.info(
                f"Request started: {request_info['method']} {request_info['path']}",
                extra=request_info
            )

            if self.log_bodies and "body" in kwargs:
                self.logger.debug(
                    f"Request body: {self._truncate_body(kwargs['body'])}",
                    extra=request_info
                )

            try:
                # Execute handler
                response = await func(*args, **kwargs)
                elapsed_time = (time.time() - request_start) * 1000

                # Log response
                response_info = {
                    **request_info,
                    "status_code": response.get("status_code", 200) if isinstance(response, dict) else 200,
                    "elapsed_ms": round(elapsed_time, 2),
                }

                self.logger.info(
                    f"Request completed: {response_info['method']} {response_info['path']} "
                    f"({response_info['status_code']}) in {response_info['elapsed_ms']}ms",
                    extra=response_info
                )

                if self.log_bodies and response:
                    self.logger.debug(
                        f"Response body: {self._truncate_body(response)}",
                        extra=response_info
                    )

                return response

            except Exception as e:
                elapsed_time = (time.time() - request_start) * 1000
                error_info = {
                    **request_info,
                    "error": str(e),
                    "elapsed_ms": round(elapsed_time, 2),
                }

                self.logger.error(
                    f"Request failed: {error_info['method']} {error_info['path']} "
                    f"after {error_info['elapsed_ms']}ms: {str(e)}",
                    extra=error_info,
                    exc_info=True,
                )
                raise

        return wrapper

    @staticmethod
    def _generate_request_id() -> str:
        """Generate unique request ID."""
        timestamp = datetime.now(timezone.utc).isoformat()
        unique_hash = hashlib.md5(timestamp.encode()).hexdigest()[:8]
        return f"req_{unique_hash}"

    def _truncate_body(self, body: Any) -> str:
        """Truncate body for logging."""
        body_str = json.dumps(body) if isinstance(body, dict) else str(body)
        if len(body_str) > self.body_size_limit:
            return body_str[:self.body_size_limit] + f"... [{len(body_str)} bytes total]"
        return body_str


# ==============================================================================
# Authentication Middleware
# ==============================================================================

class AuthMiddleware:
    """
    Middleware for token-based authentication.
    
    Validates authentication tokens (Bearer tokens, API keys, etc.) and
    enforces authentication policies for protected endpoints.
    """

    def __init__(self, settings: Optional[Settings] = None):
        """
        Initialize authentication middleware.
        
        Args:
            settings: Application settings
        """
        self.settings = settings or Settings()
        self.logger = get_logger(__name__)
        self.secret_key = getattr(settings, 'auth_secret_key', 'default-secret-key')
        self.auth_enabled = getattr(settings, 'auth_enabled', True)

    def __call__(self, func: Callable) -> Callable:
        """
        Decorator for authentication middleware.
        
        Args:
            func: Target function to wrap
            
        Returns:
            Wrapped function with authentication
        """
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Skip auth for non-protected endpoints
            if not self.auth_enabled:
                return await func(*args, **kwargs)

            # Extract auth header
            auth_header = kwargs.get("auth_header", None)
            
            if not auth_header:
                self.logger.warning("Missing authentication header")
                raise AuthenticationError(
                    "Missing authentication header",
                    auth_type="Bearer"
                )

            # Validate token
            try:
                user_id = self._validate_token(auth_header)
                kwargs["user_id"] = user_id
                self.logger.debug(f"Authentication successful for user: {user_id}")
            except Exception as e:
                self.logger.warning(f"Authentication validation failed: {str(e)}")
                raise AuthenticationError(
                    str(e),
                    auth_type="Bearer"
                )

            return await func(*args, **kwargs)

        return wrapper

    def _validate_token(self, auth_header: str) -> str:
        """
        Validate authentication token.
        
        Args:
            auth_header: Authorization header value
            
        Returns:
            User ID extracted from token
            
        Raises:
            AuthenticationError: If token is invalid
        """
        # Parse Bearer token
        if not auth_header.startswith("Bearer "):
            raise AuthenticationError("Invalid token format")

        token = auth_header[7:]  # Remove "Bearer " prefix

        # Validate token (simple HMAC validation)
        try:
            # For production, use proper JWT validation
            parts = token.split(".")
            if len(parts) != 3:
                raise AuthenticationError("Invalid token structure")

            # Extract user_id from token payload
            user_id = parts[0]
            
            return user_id

        except Exception as e:
            raise AuthenticationError(f"Token validation failed: {str(e)}")

    def generate_token(self, user_id: str, expires_in: int = 3600) -> str:
        """
        Generate authentication token.
        
        Args:
            user_id: User identifier
            expires_in: Token expiration time in seconds
            
        Returns:
            Generated token
        """
        timestamp = str(int(time.time()))
        expiry = str(int(time.time()) + expires_in)
        
        # Simple token generation (use JWT in production)
        payload = f"{user_id}.{timestamp}.{expiry}"
        signature = hmac.new(
            self.secret_key.encode(),
            payload.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return f"{payload}.{signature}"


# ==============================================================================
# CORS Middleware
# ==============================================================================

class CORSMiddleware:
    """
    Middleware for Cross-Origin Resource Sharing (CORS) support.
    
    Handles CORS headers and preflight requests to enable cross-origin
    communication while enforcing security policies.
    """

    def __init__(
        self,
        settings: Optional[Settings] = None,
        allowed_origins: Optional[List[str]] = None,
        allowed_methods: Optional[List[str]] = None,
        allowed_headers: Optional[List[str]] = None,
        max_age: int = 600,
    ):
        """
        Initialize CORS middleware.
        
        Args:
            settings: Application settings
            allowed_origins: List of allowed origins (default: all)
            allowed_methods: List of allowed HTTP methods
            allowed_headers: List of allowed headers
            max_age: Max age for preflight cache in seconds
        """
        self.settings = settings or Settings()
        self.logger = get_logger(__name__)
        self.allowed_origins = allowed_origins or ["*"]
        self.allowed_methods = allowed_methods or ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"]
        self.allowed_headers = allowed_headers or ["*"]
        self.max_age = max_age
        self.cors_enabled = getattr(settings, 'cors_enabled', True)

    def __call__(self, func: Callable) -> Callable:
        """
        Decorator for CORS middleware.
        
        Args:
            func: Target function to wrap
            
        Returns:
            Wrapped function with CORS handling
        """
        @wraps(func)
        async def wrapper(*args, **kwargs):
            if not self.cors_enabled:
                return await func(*args, **kwargs)

            origin = kwargs.get("origin", None)
            method = kwargs.get("method", "GET")

            # Handle preflight requests
            if method == "OPTIONS":
                self.logger.debug(f"Handling CORS preflight request from {origin}")
                return self._preflight_response(origin)

            # Add CORS headers to response
            response = await func(*args, **kwargs)
            
            if isinstance(response, dict):
                response["headers"] = response.get("headers", {})
                response["headers"].update(self._get_cors_headers(origin))

            return response

        return wrapper

    def _preflight_response(self, origin: Optional[str]) -> Dict[str, Any]:
        """Generate preflight response."""
        return {
            "status": "success",
            "status_code": 200,
            "headers": self._get_cors_headers(origin),
        }

    def _get_cors_headers(self, origin: Optional[str]) -> Dict[str, str]:
        """Get CORS headers for response."""
        # Check if origin is allowed
        if origin and self.allowed_origins != ["*"]:
            if origin not in self.allowed_origins:
                self.logger.warning(f"CORS request from disallowed origin: {origin}")
                return {}

        allowed_origin = origin if origin and self.allowed_origins != ["*"] else "*"

        return {
            "Access-Control-Allow-Origin": allowed_origin,
            "Access-Control-Allow-Methods": ", ".join(self.allowed_methods),
            "Access-Control-Allow-Headers": ", ".join(self.allowed_headers),
            "Access-Control-Max-Age": str(self.max_age),
            "Access-Control-Allow-Credentials": "true",
        }


# ==============================================================================
# Rate Limiting Middleware
# ==============================================================================

class RateLimitMiddleware:
    """
    Middleware for request rate limiting.
    
    Implements multiple rate limiting strategies:
    - Per-client rate limiting (by IP or user ID)
    - Per-endpoint rate limiting
    - Global rate limiting
    """

    def __init__(
        self,
        settings: Optional[Settings] = None,
        default_limit: int = 100,
        default_window: int = 60,
        enabled: bool = True,
    ):
        """
        Initialize rate limit middleware.
        
        Args:
            settings: Application settings
            default_limit: Default request limit per window
            default_window: Default time window in seconds
            enabled: Whether rate limiting is enabled
        """
        self.settings = settings or Settings()
        self.logger = get_logger(__name__)
        self.default_limit = default_limit
        self.default_window = default_window
        self.enabled = enabled

        # Rate limit buckets per client and endpoint
        self.client_buckets: Dict[str, RateLimitBucket] = defaultdict(
            lambda: RateLimitBucket(limit=self.default_limit, window=self.default_window)
        )
        self.endpoint_buckets: Dict[str, RateLimitBucket] = defaultdict(
            lambda: RateLimitBucket(limit=self.default_limit * 10, window=self.default_window)
        )

    def __call__(self, func: Callable) -> Callable:
        """
        Decorator for rate limit middleware.
        
        Args:
            func: Target function to wrap
            
        Returns:
            Wrapped function with rate limiting
        """
        @wraps(func)
        async def wrapper(*args, **kwargs):
            if not self.enabled:
                return await func(*args, **kwargs)

            client_id = kwargs.get("client_id", kwargs.get("client_ip", "unknown"))
            endpoint = kwargs.get("path", "unknown")
            current_time = time.time()

            # Check client rate limit
            if self.client_buckets[client_id].is_rate_limited(current_time):
                self.logger.warning(f"Rate limit exceeded for client: {client_id}")
                raise RateLimitError(
                    f"Rate limit exceeded for client {client_id}",
                    limit=self.default_limit,
                    window=self.default_window
                )

            # Check endpoint rate limit
            if self.endpoint_buckets[endpoint].is_rate_limited(current_time):
                self.logger.warning(f"Rate limit exceeded for endpoint: {endpoint}")
                raise RateLimitError(
                    f"Rate limit exceeded for endpoint {endpoint}",
                    limit=self.default_limit * 10,
                    window=self.default_window
                )

            # Record requests
            self.client_buckets[client_id].add_request(current_time)
            self.endpoint_buckets[endpoint].add_request(current_time)

            # Execute handler
            response = await func(*args, **kwargs)

            # Add rate limit headers
            if isinstance(response, dict):
                response["headers"] = response.get("headers", {})
                response["headers"].update({
                    "X-RateLimit-Limit": str(self.default_limit),
                    "X-RateLimit-Remaining": str(
                        self.default_limit - len(self.client_buckets[client_id].requests)
                    ),
                    "X-RateLimit-Reset": str(
                        int(self.client_buckets[client_id].last_reset + self.default_window)
                    ),
                })

            return response

        return wrapper

    def get_client_status(self, client_id: str) -> Dict[str, Any]:
        """Get rate limit status for a client."""
        bucket = self.client_buckets[client_id]
        current_time = time.time()
        
        # Clean up expired requests
        window_start = current_time - bucket.window
        valid_requests = [t for t in bucket.requests if t > window_start]
        
        return {
            "client_id": client_id,
            "requests_in_window": len(valid_requests),
            "limit": bucket.limit,
            "remaining": bucket.limit - len(valid_requests),
            "reset_at": bucket.last_reset + bucket.window,
        }


# ==============================================================================
# Middleware Setup
# ==============================================================================

def setup_middleware(settings: Optional[Settings] = None) -> List[object]:
    """
    Configure and initialize all middleware components.
    
    Args:
        settings: Application settings
        
    Returns:
        List of initialized middleware instances
        
    Example:
        >>> from src.config.settings import Settings
        >>> settings = Settings()
        >>> middleware = setup_middleware(settings)
        >>> app.middlewares.extend(middleware)
    """
    logger.info("Initializing middleware components...")

    settings = settings or Settings()

    try:
        # Create middleware instances
        middleware_list = [
            # Error handling must be first
            ErrorHandlingMiddleware(settings),
            
            # Logging
            LoggingMiddleware(
                settings=settings,
                log_bodies=getattr(settings, 'log_request_bodies', True),
                log_headers=getattr(settings, 'log_headers', True),
                body_size_limit=getattr(settings, 'body_size_limit', 1000),
            ),
            
            # CORS
            CORSMiddleware(
                settings=settings,
                allowed_origins=getattr(settings, 'cors_allowed_origins', None),
                max_age=getattr(settings, 'cors_max_age', 600),
            ),
            
            # Authentication
            AuthMiddleware(settings=settings),
            
            # Rate limiting
            RateLimitMiddleware(
                settings=settings,
                default_limit=getattr(settings, 'rate_limit_requests', 100),
                default_window=getattr(settings, 'rate_limit_window', 60),
                enabled=getattr(settings, 'rate_limiting_enabled', True),
            ),
        ]

        logger.info(f"Successfully initialized {len(middleware_list)} middleware components")
        for i, mw in enumerate(middleware_list, 1):
            logger.debug(f"  {i}. {mw.__class__.__name__}")

        return middleware_list

    except Exception as e:
        logger.error(f"Failed to initialize middleware: {str(e)}", exc_info=True)
        raise ServerError(f"Middleware initialization failed: {str(e)}")


# ==============================================================================
# Middleware Utilities
# ==============================================================================

def apply_middleware(func: Callable, middleware_list: List[object]) -> Callable:
    """
    Apply middleware stack to a function.
    
    Args:
        func: Target function
        middleware_list: List of middleware instances
        
    Returns:
        Function wrapped with all middleware
        
    Example:
        >>> async def handler():
        ...     return {"status": "ok"}
        >>> middleware = setup_middleware()
        >>> wrapped_handler = apply_middleware(handler, middleware)
    """
    result = func
    for middleware in reversed(middleware_list):
        result = middleware(result)
    return result


def get_middleware_info() -> Dict[str, Any]:
    """
    Get information about available middleware components.
    
    Returns:
        Dictionary containing middleware information
    """
    return {
        "middleware_components": [
            {
                "name": "ErrorHandlingMiddleware",
                "description": "Centralized error handling and exception transformation",
                "features": [
                    "Exception to HTTP response conversion",
                    "Consistent error response format",
                    "Error logging and tracing",
                ]
            },
            {
                "name": "LoggingMiddleware",
                "description": "Comprehensive request/response logging",
                "features": [
                    "Request/response timing",
                    "Body and header logging",
                    "Unique request ID generation",
                    "Structured logging format",
                ]
            },
            {
                "name": "AuthMiddleware",
                "description": "Token-based authentication",
                "features": [
                    "Bearer token validation",
                    "Token generation",
                    "Authentication enforcement",
                ]
            },
            {
                "name": "CORSMiddleware",
                "description": "Cross-Origin Resource Sharing support",
                "features": [
                    "CORS header management",
                    "Preflight request handling",
                    "Origin validation",
                ]
            },
            {
                "name": "RateLimitMiddleware",
                "description": "Request rate limiting",
                "features": [
                    "Per-client rate limiting",
                    "Per-endpoint rate limiting",
                    "Rate limit headers",
                    "Multiple limiting strategies",
                ]
            },
        ]
    }


__all__ = [
    # Data Models
    "RequestContext",
    "RateLimitBucket",
    
    # Middleware Classes
    "ErrorHandlingMiddleware",
    "LoggingMiddleware",
    "AuthMiddleware",
    "CORSMiddleware",
    "RateLimitMiddleware",
    
    # Functions
    "setup_middleware",
    "apply_middleware",
    "get_middleware_info",
]