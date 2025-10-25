# hyfuzz-server-windows/src/utils/exceptions.py

"""
Exceptions - Custom exception classes for the HyFuzz MCP Server.
Provides structured exception hierarchy for different error scenarios.
"""

from typing import Any, Dict, Optional


# ============================================================================
# Base Exception Classes
# ============================================================================

class MCPException(Exception):
    """
    Base exception for all MCP server exceptions.

    Attributes:
        message: Error message
        code: Error code for categorization
        details: Additional error details
    """

    def __init__(
            self,
            message: str,
            code: str = "UNKNOWN_ERROR",
            details: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize MCP exception.

        Args:
            message: Error message
            code: Error code
            details: Additional error details
        """
        self.message = message
        self.code = code
        self.details = details or {}
        super().__init__(self.message)

    def __str__(self) -> str:
        """Return string representation of exception"""
        return f"[{self.code}] {self.message}"

    def __repr__(self) -> str:
        """Return detailed representation"""
        details_str = ""
        if self.details:
            details_str = f", details={self.details!r}"
        return f"{self.__class__.__name__}(message={self.message!r}, code={self.code!r}{details_str})"

    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary"""
        return {
            "exception_type": self.__class__.__name__,
            "message": self.message,
            "code": self.code,
            "details": self.details,
        }


# ============================================================================
# Server-Related Exceptions
# ============================================================================

class MCPServerException(MCPException):
    """
    Exception raised for MCP server errors.

    Raised when an error occurs in the MCP server core functionality.
    """

    def __init__(
            self,
            message: str,
            code: str = "SERVER_ERROR",
            details: Optional[Dict[str, Any]] = None
    ):
        """Initialize server exception"""
        super().__init__(message, code=code, details=details)


class ServerStartupException(MCPServerException):
    """Raised when MCP server fails to start"""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        """Initialize startup exception"""
        super().__init__(message, code="SERVER_STARTUP_ERROR", details=details)


class ServerShutdownException(MCPServerException):
    """Raised when MCP server fails to shutdown gracefully"""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        """Initialize shutdown exception"""
        super().__init__(message, code="SERVER_SHUTDOWN_ERROR", details=details)


class TransportException(MCPServerException):
    """Raised when transport layer encounters an error"""

    def __init__(self, message: str, transport_type: str = "", details: Optional[Dict[str, Any]] = None):
        """Initialize transport exception"""
        if details is None:
            details = {}
        details["transport_type"] = transport_type
        super().__init__(message, code="TRANSPORT_ERROR", details=details)


class SessionException(MCPServerException):
    """Raised when session management fails"""

    def __init__(self, message: str, session_id: str = "", details: Optional[Dict[str, Any]] = None):
        """Initialize session exception"""
        if details is None:
            details = {}
        details["session_id"] = session_id
        super().__init__(message, code="SESSION_ERROR", details=details)


# ============================================================================
# Client-Related Exceptions
# ============================================================================

class MCPClientException(MCPException):
    """
    Exception raised for MCP client errors.

    Raised when an error occurs in client communication or requests.
    """

    def __init__(
            self,
            message: str,
            code: str = "CLIENT_ERROR",
            details: Optional[Dict[str, Any]] = None
    ):
        """Initialize client exception"""
        super().__init__(message, code=code, details=details)


class ConnectionException(MCPClientException):
    """Raised when client connection fails"""

    def __init__(self, message: str, host: str = "", port: int = 0, details: Optional[Dict[str, Any]] = None):
        """Initialize connection exception"""
        if details is None:
            details = {}
        details.update({"host": host, "port": port})
        super().__init__(message, code="CONNECTION_ERROR", details=details)


class TimeoutException(MCPClientException):
    """Raised when client request times out"""

    def __init__(self, message: str, timeout_seconds: float = 0, details: Optional[Dict[str, Any]] = None):
        """Initialize timeout exception"""
        if details is None:
            details = {}
        details["timeout_seconds"] = timeout_seconds
        super().__init__(message, code="TIMEOUT_ERROR", details=details)


class RequestException(MCPClientException):
    """Raised when client request is invalid or fails"""

    def __init__(self, message: str, request_id: str = "", details: Optional[Dict[str, Any]] = None):
        """Initialize request exception"""
        if details is None:
            details = {}
        details["request_id"] = request_id
        super().__init__(message, code="REQUEST_ERROR", details=details)


# ============================================================================
# Configuration-Related Exceptions
# ============================================================================

class ConfigurationException(MCPException):
    """
    Exception raised for configuration errors.

    Raised when configuration is invalid or missing required values.
    """

    def __init__(
            self,
            message: str,
            code: str = "CONFIG_ERROR",
            details: Optional[Dict[str, Any]] = None
    ):
        """Initialize configuration exception"""
        super().__init__(message, code=code, details=details)


class ConfigLoadException(ConfigurationException):
    """Raised when configuration file fails to load"""

    def __init__(self, message: str, config_path: str = "", details: Optional[Dict[str, Any]] = None):
        """Initialize config load exception"""
        if details is None:
            details = {}
        details["config_path"] = config_path
        super().__init__(message, code="CONFIG_LOAD_ERROR", details=details)


class ConfigValidationException(ConfigurationException):
    """Raised when configuration validation fails"""

    def __init__(self, message: str, field_name: str = "", details: Optional[Dict[str, Any]] = None):
        """Initialize config validation exception"""
        if details is None:
            details = {}
        details["field_name"] = field_name
        super().__init__(message, code="CONFIG_VALIDATION_ERROR", details=details)


class MissingConfigException(ConfigurationException):
    """Raised when required configuration is missing"""

    def __init__(self, message: str, config_key: str = "", details: Optional[Dict[str, Any]] = None):
        """Initialize missing config exception"""
        if details is None:
            details = {}
        details["config_key"] = config_key
        super().__init__(message, code="CONFIG_MISSING_ERROR", details=details)


# ============================================================================
# Validation-Related Exceptions
# ============================================================================

class ValidationException(MCPException):
    """
    Exception raised for validation errors.

    Raised when input validation fails.
    """

    def __init__(
            self,
            message: str,
            code: str = "VALIDATION_ERROR",
            details: Optional[Dict[str, Any]] = None
    ):
        """Initialize validation exception"""
        super().__init__(message, code=code, details=details)


class InvalidInputException(ValidationException):
    """Raised when input is invalid"""

    def __init__(self, message: str, input_field: str = "", details: Optional[Dict[str, Any]] = None):
        """Initialize invalid input exception"""
        if details is None:
            details = {}
        details["input_field"] = input_field
        super().__init__(message, code="INVALID_INPUT_ERROR", details=details)


class SchemaValidationException(ValidationException):
    """Raised when schema validation fails"""

    def __init__(self, message: str, schema_name: str = "", details: Optional[Dict[str, Any]] = None):
        """Initialize schema validation exception"""
        if details is None:
            details = {}
        details["schema_name"] = schema_name
        super().__init__(message, code="SCHEMA_VALIDATION_ERROR", details=details)


class TypeValidationException(ValidationException):
    """Raised when type validation fails"""

    def __init__(
            self,
            message: str,
            expected_type: str = "",
            actual_type: str = "",
            details: Optional[Dict[str, Any]] = None
    ):
        """Initialize type validation exception"""
        if details is None:
            details = {}
        details.update({"expected_type": expected_type, "actual_type": actual_type})
        super().__init__(message, code="TYPE_VALIDATION_ERROR", details=details)


# ============================================================================
# Authentication and Authorization Exceptions
# ============================================================================

class AuthenticationException(MCPException):
    """
    Exception raised for authentication errors.

    Raised when authentication fails or credentials are invalid.
    """

    def __init__(
            self,
            message: str,
            code: str = "AUTH_ERROR",
            details: Optional[Dict[str, Any]] = None
    ):
        """Initialize authentication exception"""
        super().__init__(message, code=code, details=details)


class InvalidCredentialsException(AuthenticationException):
    """Raised when credentials are invalid"""

    def __init__(self, message: str, credential_type: str = "", details: Optional[Dict[str, Any]] = None):
        """Initialize invalid credentials exception"""
        if details is None:
            details = {}
        details["credential_type"] = credential_type
        super().__init__(message, code="INVALID_CREDENTIALS_ERROR", details=details)


class TokenExpiredException(AuthenticationException):
    """Raised when authentication token has expired"""

    def __init__(self, message: str, token_type: str = "", details: Optional[Dict[str, Any]] = None):
        """Initialize token expired exception"""
        if details is None:
            details = {}
        details["token_type"] = token_type
        super().__init__(message, code="TOKEN_EXPIRED_ERROR", details=details)


class AuthorizationException(AuthenticationException):
    """Raised when user lacks required permissions"""

    def __init__(
            self,
            message: str,
            required_permission: str = "",
            details: Optional[Dict[str, Any]] = None
    ):
        """Initialize authorization exception"""
        if details is None:
            details = {}
        details["required_permission"] = required_permission
        super().__init__(message, code="AUTHORIZATION_ERROR", details=details)


# ============================================================================
# LLM-Related Exceptions
# ============================================================================

class LLMException(MCPException):
    """
    Exception raised for LLM service errors.

    Raised when LLM operations fail.
    """

    def __init__(
            self,
            message: str,
            code: str = "LLM_ERROR",
            details: Optional[Dict[str, Any]] = None
    ):
        """Initialize LLM exception"""
        super().__init__(message, code=code, details=details)


class LLMConnectionException(LLMException):
    """Raised when LLM service connection fails"""

    def __init__(self, message: str, service_url: str = "", details: Optional[Dict[str, Any]] = None):
        """Initialize LLM connection exception"""
        if details is None:
            details = {}
        details["service_url"] = service_url
        super().__init__(message, code="LLM_CONNECTION_ERROR", details=details)


class LLMResponseException(LLMException):
    """Raised when LLM returns an error response"""

    def __init__(self, message: str, model_name: str = "", details: Optional[Dict[str, Any]] = None):
        """Initialize LLM response exception"""
        if details is None:
            details = {}
        details["model_name"] = model_name
        super().__init__(message, code="LLM_RESPONSE_ERROR", details=details)


class LLMTimeoutException(LLMException):
    """Raised when LLM request times out"""

    def __init__(self, message: str, timeout_seconds: float = 0, details: Optional[Dict[str, Any]] = None):
        """Initialize LLM timeout exception"""
        if details is None:
            details = {}
        details["timeout_seconds"] = timeout_seconds
        super().__init__(message, code="LLM_TIMEOUT_ERROR", details=details)


class TokenLimitException(LLMException):
    """Raised when token limit is exceeded"""

    def __init__(
            self,
            message: str,
            token_count: int = 0,
            token_limit: int = 0,
            details: Optional[Dict[str, Any]] = None
    ):
        """Initialize token limit exception"""
        if details is None:
            details = {}
        details.update({"token_count": token_count, "token_limit": token_limit})
        super().__init__(message, code="TOKEN_LIMIT_ERROR", details=details)


# ============================================================================
# Knowledge Base Exceptions
# ============================================================================

class KnowledgeException(MCPException):
    """
    Exception raised for knowledge base errors.

    Raised when knowledge base operations fail.
    """

    def __init__(
            self,
            message: str,
            code: str = "KNOWLEDGE_ERROR",
            details: Optional[Dict[str, Any]] = None
    ):
        """Initialize knowledge exception"""
        super().__init__(message, code=code, details=details)


class KnowledgeLoadException(KnowledgeException):
    """Raised when knowledge base fails to load"""

    def __init__(self, message: str, knowledge_type: str = "", details: Optional[Dict[str, Any]] = None):
        """Initialize knowledge load exception"""
        if details is None:
            details = {}
        details["knowledge_type"] = knowledge_type
        super().__init__(message, code="KNOWLEDGE_LOAD_ERROR", details=details)


class DataNotFoundException(KnowledgeException):
    """Raised when requested data is not found"""

    def __init__(self, message: str, data_id: str = "", details: Optional[Dict[str, Any]] = None):
        """Initialize data not found exception"""
        if details is None:
            details = {}
        details["data_id"] = data_id
        super().__init__(message, code="DATA_NOT_FOUND_ERROR", details=details)


class CacheException(KnowledgeException):
    """Raised when cache operations fail"""

    def __init__(self, message: str, cache_type: str = "", details: Optional[Dict[str, Any]] = None):
        """Initialize cache exception"""
        if details is None:
            details = {}
        details["cache_type"] = cache_type
        super().__init__(message, code="CACHE_ERROR", details=details)


# ============================================================================
# Protocol-Related Exceptions
# ============================================================================

class ProtocolException(MCPException):
    """
    Exception raised for protocol-level errors.

    Raised when MCP protocol operations fail.
    """

    def __init__(
            self,
            message: str,
            code: str = "PROTOCOL_ERROR",
            details: Optional[Dict[str, Any]] = None
    ):
        """Initialize protocol exception"""
        super().__init__(message, code=code, details=details)


class MessageParseException(ProtocolException):
    """Raised when message parsing fails"""

    def __init__(self, message: str, message_type: str = "", details: Optional[Dict[str, Any]] = None):
        """Initialize message parse exception"""
        if details is None:
            details = {}
        details["message_type"] = message_type
        super().__init__(message, code="MESSAGE_PARSE_ERROR", details=details)


class MessageFormatException(ProtocolException):
    """Raised when message format is invalid"""

    def __init__(self, message: str, expected_format: str = "", details: Optional[Dict[str, Any]] = None):
        """Initialize message format exception"""
        if details is None:
            details = {}
        details["expected_format"] = expected_format
        super().__init__(message, code="MESSAGE_FORMAT_ERROR", details=details)


class MethodNotFoundException(ProtocolException):
    """Raised when requested method is not found"""

    def __init__(self, message: str, method_name: str = "", details: Optional[Dict[str, Any]] = None):
        """Initialize method not found exception"""
        if details is None:
            details = {}
        details["method_name"] = method_name
        super().__init__(message, code="METHOD_NOT_FOUND_ERROR", details=details)


# ============================================================================
# Resource Exceptions
# ============================================================================

class ResourceException(MCPException):
    """
    Exception raised for resource management errors.

    Raised when resource operations fail.
    """

    def __init__(
            self,
            message: str,
            code: str = "RESOURCE_ERROR",
            details: Optional[Dict[str, Any]] = None
    ):
        """Initialize resource exception"""
        super().__init__(message, code=code, details=details)


class ResourceNotFound(ResourceException):
    """Raised when requested resource is not found"""

    def __init__(self, message: str, resource_uri: str = "", details: Optional[Dict[str, Any]] = None):
        """Initialize resource not found exception"""
        if details is None:
            details = {}
        details["resource_uri"] = resource_uri
        super().__init__(message, code="RESOURCE_NOT_FOUND_ERROR", details=details)


class ResourceAccessException(ResourceException):
    """Raised when resource access is denied"""

    def __init__(self, message: str, resource_uri: str = "", details: Optional[Dict[str, Any]] = None):
        """Initialize resource access exception"""
        if details is None:
            details = {}
        details["resource_uri"] = resource_uri
        super().__init__(message, code="RESOURCE_ACCESS_ERROR", details=details)


# ============================================================================
# TESTS
# ============================================================================

if __name__ == "__main__":
    """Test custom exceptions"""
    import sys

    print("=" * 80)
    print("TESTING CUSTOM EXCEPTIONS")
    print("=" * 80)

    test_results = []

    # Test 1: Base MCPException
    print("\n[Test 1] MCPException:")
    try:
        exc = MCPException("Test error", code="TEST_001")
        assert str(exc) == "[TEST_001] Test error"
        assert exc.code == "TEST_001"
        exc_dict = exc.to_dict()
        assert exc_dict["exception_type"] == "MCPException"
        print(f"✓ {exc}")
        test_results.append(("MCPException", True, None))
    except Exception as e:
        print(f"✗ Failed: {e}")
        test_results.append(("MCPException", False, str(e)))

    # Test 2: ServerStartupException
    print("\n[Test 2] ServerStartupException:")
    try:
        exc = ServerStartupException("Failed to bind port", details={"port": 8000})
        assert exc.code == "SERVER_STARTUP_ERROR"
        assert exc.details["port"] == 8000
        print(f"✓ {exc}")
        test_results.append(("ServerStartupException", True, None))
    except Exception as e:
        print(f"✗ Failed: {e}")
        test_results.append(("ServerStartupException", False, str(e)))

    # Test 3: ConnectionException
    print("\n[Test 3] ConnectionException:")
    try:
        exc = ConnectionException("Connection refused", host="localhost", port=8000)
        assert exc.code == "CONNECTION_ERROR"
        assert exc.details["host"] == "localhost"
        assert exc.details["port"] == 8000
        print(f"✓ {exc}")
        test_results.append(("ConnectionException", True, None))
    except Exception as e:
        print(f"✗ Failed: {e}")
        test_results.append(("ConnectionException", False, str(e)))

    # Test 4: ConfigValidationException
    print("\n[Test 4] ConfigValidationException:")
    try:
        exc = ConfigValidationException(
            "Invalid port number",
            field_name="server_port"
        )
        assert exc.code == "CONFIG_VALIDATION_ERROR"
        assert exc.details["field_name"] == "server_port"
        print(f"✓ {exc}")
        test_results.append(("ConfigValidationException", True, None))
    except Exception as e:
        print(f"✗ Failed: {e}")
        test_results.append(("ConfigValidationException", False, str(e)))

    # Test 5: InvalidInputException
    print("\n[Test 5] InvalidInputException:")
    try:
        exc = InvalidInputException(
            "Email format is invalid",
            input_field="email"
        )
        assert exc.code == "INVALID_INPUT_ERROR"
        assert exc.details["input_field"] == "email"
        print(f"✓ {exc}")
        test_results.append(("InvalidInputException", True, None))
    except Exception as e:
        print(f"✗ Failed: {e}")
        test_results.append(("InvalidInputException", False, str(e)))

    # Test 6: TypeValidationException
    print("\n[Test 6] TypeValidationException:")
    try:
        exc = TypeValidationException(
            "Type mismatch",
            expected_type="string",
            actual_type="integer"
        )
        assert exc.code == "TYPE_VALIDATION_ERROR"
        assert exc.details["expected_type"] == "string"
        assert exc.details["actual_type"] == "integer"
        print(f"✓ {exc}")
        test_results.append(("TypeValidationException", True, None))
    except Exception as e:
        print(f"✗ Failed: {e}")
        test_results.append(("TypeValidationException", False, str(e)))

    # Test 7: InvalidCredentialsException
    print("\n[Test 7] InvalidCredentialsException:")
    try:
        exc = InvalidCredentialsException(
            "Invalid API key",
            credential_type="api_key"
        )
        assert exc.code == "INVALID_CREDENTIALS_ERROR"
        assert exc.details["credential_type"] == "api_key"
        print(f"✓ {exc}")
        test_results.append(("InvalidCredentialsException", True, None))
    except Exception as e:
        print(f"✗ Failed: {e}")
        test_results.append(("InvalidCredentialsException", False, str(e)))

    # Test 8: LLMConnectionException
    print("\n[Test 8] LLMConnectionException:")
    try:
        exc = LLMConnectionException(
            "Failed to connect to LLM service",
            service_url="http://localhost:11434"
        )
        assert exc.code == "LLM_CONNECTION_ERROR"
        assert exc.details["service_url"] == "http://localhost:11434"
        print(f"✓ {exc}")
        test_results.append(("LLMConnectionException", True, None))
    except Exception as e:
        print(f"✗ Failed: {e}")
        test_results.append(("LLMConnectionException", False, str(e)))

    # Test 9: TokenLimitException
    print("\n[Test 9] TokenLimitException:")
    try:
        exc = TokenLimitException(
            "Token limit exceeded",
            token_count=5000,
            token_limit=4096
        )
        assert exc.code == "TOKEN_LIMIT_ERROR"
        assert exc.details["token_count"] == 5000
        assert exc.details["token_limit"] == 4096
        print(f"✓ {exc}")
        test_results.append(("TokenLimitException", True, None))
    except Exception as e:
        print(f"✗ Failed: {e}")
        test_results.append(("TokenLimitException", False, str(e)))

    # Test 10: Exception serialization to dict
    print("\n[Test 10] Exception to_dict() serialization:")
    try:
        exc = MethodNotFoundException(
            "Method not found",
            method_name="unknown_method"
        )
        exc_dict = exc.to_dict()
        assert exc_dict["exception_type"] == "MethodNotFoundException"
        assert exc_dict["code"] == "METHOD_NOT_FOUND_ERROR"
        assert exc_dict["details"]["method_name"] == "unknown_method"
        print(f"✓ Serialization successful: {exc_dict}")
        test_results.append(("Exception serialization", True, None))
    except Exception as e:
        print(f"✗ Failed: {e}")
        test_results.append(("Exception serialization", False, str(e)))

    # Test 11: Exception hierarchy
    print("\n[Test 11] Exception hierarchy:")
    try:
        exc = ServerStartupException("Test")
        assert isinstance(exc, MCPServerException)
        assert isinstance(exc, MCPException)
        assert isinstance(exc, Exception)
        print(f"✓ Exception hierarchy correct")
        test_results.append(("Exception hierarchy", True, None))
    except Exception as e:
        print(f"✗ Failed: {e}")
        test_results.append(("Exception hierarchy", False, str(e)))

    # Test 12: Multiple exceptions
    print("\n[Test 12] Multiple exception types:")
    try:
        exceptions_to_test = [
            MCPClientException("Client error"),
            ConfigLoadException("Config not found"),
            TimeoutException("Request timed out", timeout_seconds=30.0),
            TokenExpiredException("Token expired"),
            DataNotFoundException("Data not found", data_id="cve-001"),
            ResourceNotFound("Resource not found", resource_uri="cwe://CWE-79"),
        ]

        assert len(exceptions_to_test) == 6
        for exc in exceptions_to_test:
            assert isinstance(exc, MCPException)
            assert len(exc.code) > 0

        print(f"✓ All {len(exceptions_to_test)} exceptions created successfully")
        test_results.append(("Multiple exception types", True, None))
    except Exception as e:
        print(f"✗ Failed: {e}")
        test_results.append(("Multiple exception types", False, str(e)))

    # Test 13: Exception string representations
    print("\n[Test 13] Exception string representations:")
    try:
        exc = MissingConfigException("Missing required key", config_key="database.url")
        str_repr = str(exc)
        repr_repr = repr(exc)

        assert "CONFIG_MISSING_ERROR" in str_repr
        assert "MissingConfigException" in repr_repr
        # Check that config_key is in the repr
        assert "config_key" in repr_repr
        assert "database.url" in repr_repr

        print(f"✓ str: {str_repr}")
        print(f"✓ repr: {repr_repr}")
        test_results.append(("String representations", True, None))
    except Exception as e:
        print(f"✗ Failed: {e}")
        test_results.append(("String representations", False, str(e)))

    # Test 14: Exception chaining
    print("\n[Test 14] Exception chaining:")
    try:
        try:
            raise ValueError("Original error")
        except ValueError as original:
            exc = LLMResponseException(
                "LLM processing failed",
                model_name="mistral"
            )
            # In Python 3.10+, we can chain exceptions
            raise exc from original
    except LLMResponseException as e:
        assert e.code == "LLM_RESPONSE_ERROR"
        assert e.details["model_name"] == "mistral"
        print(f"✓ Exception chaining works: {e}")
        test_results.append(("Exception chaining", True, None))
    except Exception as e:
        print(f"✗ Failed: {e}")
        test_results.append(("Exception chaining", False, str(e)))

    # Print summary
    print("\n" + "=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)

    passed = sum(1 for _, success, _ in test_results if success)
    total = len(test_results)

    for test_name, success, error in test_results:
        status = "✓ PASS" if success else "✗ FAIL"
        print(f"{status:8} | {test_name}")
        if error:
            print(f"         | Error: {error}")

    print("\n" + "=" * 80)
    print(f"RESULT: {passed}/{total} tests passed")
    print("=" * 80)

    sys.exit(0 if passed == total else 1)