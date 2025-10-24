"""
HyFuzz MCP Server - API Request Validators

This module provides comprehensive request validation for all API endpoints.
It validates request data, enforces constraints, and ensures data consistency.

Key Features:
- Request payload validation using Pydantic models
- Schema validation and type checking
- Business logic validation
- Protocol-specific validation
- Custom validation rules
- Detailed error messages and diagnostics

Validation Categories:
1. Basic validation: Required fields, data types
2. Format validation: Email, URL, CWE/CVE format
3. Length validation: String length, array size limits
4. Range validation: Numeric bounds
5. Business logic validation: Protocol support, vulnerability types
6. Cross-field validation: Field dependencies

Author: HyFuzz Team
Version: 1.0.0
"""

import re
import logging
from typing import Dict, Any, Optional, List, Tuple, Set
from abc import ABC, abstractmethod
from enum import Enum

from ..config.settings import Settings
from ..utils.logger import get_logger
from ..utils.exceptions import ValidationError


# Initialize logger
logger = get_logger(__name__)


# ==============================================================================
# Enumerations
# ==============================================================================

class SupportedProtocol(str, Enum):
    """Supported network protocols for fuzzing."""
    HTTP = "http"
    HTTPS = "https"
    COAP = "coap"
    MQTT = "mqtt"
    GRPC = "grpc"
    JSON_RPC = "json-rpc"
    XMLRPC = "xmlrpc"
    WEBSOCKET = "websocket"
    MODBUS = "modbus"
    DNS = "dns"
    SSH = "ssh"
    FTP = "ftp"
    TELNET = "telnet"
    CUSTOM = "custom"


class VulnerabilityType(str, Enum):
    """Common vulnerability types and CWE categories."""
    XSS = "xss"  # CWE-79
    SQL_INJECTION = "sql_injection"  # CWE-89
    CODE_INJECTION = "code_injection"  # CWE-94
    COMMAND_INJECTION = "command_injection"  # CWE-78
    PATH_TRAVERSAL = "path_traversal"  # CWE-22
    XXE = "xxe"  # CWE-611
    CSRF = "csrf"  # CWE-352
    BROKEN_AUTH = "broken_auth"  # CWE-287
    BROKEN_ACCESS_CONTROL = "broken_access_control"  # CWE-284
    INSECURE_DESERIALIZATION = "insecure_deserialization"  # CWE-502
    WEAK_CRYPTO = "weak_crypto"  # CWE-327
    BUFFER_OVERFLOW = "buffer_overflow"  # CWE-120
    RACE_CONDITION = "race_condition"  # CWE-362
    CUSTOM = "custom"


# ==============================================================================
# Validation Rules
# ==============================================================================

class ValidationRule(ABC):
    """
    Abstract base class for custom validation rules.
    
    Subclasses should implement the validate method to define
    custom validation logic.
    """

    @abstractmethod
    def validate(self, value: Any) -> Tuple[bool, Optional[str]]:
        """
        Validate a value.
        
        Args:
            value: Value to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        pass


class CWEFormatRule(ValidationRule):
    """Validates CWE ID format (CWE-XXXX)."""

    def validate(self, value: Any) -> Tuple[bool, Optional[str]]:
        """Validate CWE format."""
        if value is None:
            return True, None

        pattern = r"^CWE-\d{1,5}$"
        if not re.match(pattern, str(value)):
            return False, f"Invalid CWE format: {value}. Expected format: CWE-XXXX"
        
        return True, None


class CVEFormatRule(ValidationRule):
    """Validates CVE ID format (CVE-XXXX-XXXXX)."""

    def validate(self, value: Any) -> Tuple[bool, Optional[str]]:
        """Validate CVE format."""
        if value is None:
            return True, None

        pattern = r"^CVE-\d{4}-\d{4,}$"
        if not re.match(pattern, str(value)):
            return False, f"Invalid CVE format: {value}. Expected format: CVE-XXXX-XXXXX"
        
        return True, None


class URLFormatRule(ValidationRule):
    """Validates URL format."""

    def validate(self, value: Any) -> Tuple[bool, Optional[str]]:
        """Validate URL format."""
        if value is None:
            return True, None

        pattern = r"^(https?|wss?|coaps?)://[^\s/$.?#].[^\s]*$"
        if not re.match(pattern, str(value), re.IGNORECASE):
            return False, f"Invalid URL format: {value}"
        
        return True, None


class IPAddressRule(ValidationRule):
    """Validates IP address format."""

    def validate(self, value: Any) -> Tuple[bool, Optional[str]]:
        """Validate IP address format."""
        if value is None:
            return True, None

        # IPv4 pattern
        ipv4_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        
        # IPv6 pattern (simplified)
        ipv6_pattern = r"^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}$|^[0-9a-fA-F]{1,4}::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}$"

        value_str = str(value)
        if not (re.match(ipv4_pattern, value_str) or re.match(ipv6_pattern, value_str)):
            return False, f"Invalid IP address format: {value}"
        
        return True, None


class HostnameRule(ValidationRule):
    """Validates hostname format."""

    def validate(self, value: Any) -> Tuple[bool, Optional[str]]:
        """Validate hostname format."""
        if value is None:
            return True, None

        pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
        if not re.match(pattern, str(value)):
            return False, f"Invalid hostname format: {value}"
        
        return True, None


# ==============================================================================
# Field Validators
# ==============================================================================

class FieldValidator:
    """
    Validates individual fields with type checking and constraints.
    
    Attributes:
        value: The field value to validate
        field_name: Name of the field
        required: Whether the field is required
        field_type: Expected data type
        min_length: Minimum length for strings/lists
        max_length: Maximum length for strings/lists
        min_value: Minimum value for numbers
        max_value: Maximum value for numbers
        pattern: Regex pattern for strings
        allowed_values: Set of allowed values for enum-like validation
    """

    def __init__(
        self,
        value: Any,
        field_name: str,
        required: bool = False,
        field_type: Optional[type] = None,
        min_length: Optional[int] = None,
        max_length: Optional[int] = None,
        min_value: Optional[float] = None,
        max_value: Optional[float] = None,
        pattern: Optional[str] = None,
        allowed_values: Optional[Set[Any]] = None,
    ):
        """Initialize field validator."""
        self.value = value
        self.field_name = field_name
        self.required = required
        self.field_type = field_type
        self.min_length = min_length
        self.max_length = max_length
        self.min_value = min_value
        self.max_value = max_value
        self.pattern = pattern
        self.allowed_values = allowed_values
        self.errors: List[str] = []

    def validate(self) -> bool:
        """
        Validate the field.
        
        Returns:
            True if valid, False otherwise
        """
        # Check if required
        if self.required and self.value is None:
            self.errors.append(f"Field '{self.field_name}' is required")
            return False

        # If not required and None, it's valid
        if not self.required and self.value is None:
            return True

        # Type checking
        if self.field_type and not isinstance(self.value, self.field_type):
            self.errors.append(
                f"Field '{self.field_name}' must be {self.field_type.__name__}, "
                f"got {type(self.value).__name__}"
            )
            return False

        # Length validation (for strings and lists)
        if isinstance(self.value, (str, list)):
            length = len(self.value)
            if self.min_length and length < self.min_length:
                self.errors.append(
                    f"Field '{self.field_name}' must have minimum length {self.min_length}"
                )
                return False
            if self.max_length and length > self.max_length:
                self.errors.append(
                    f"Field '{self.field_name}' must have maximum length {self.max_length}"
                )
                return False

        # Range validation (for numbers)
        if isinstance(self.value, (int, float)):
            if self.min_value is not None and self.value < self.min_value:
                self.errors.append(
                    f"Field '{self.field_name}' must be >= {self.min_value}"
                )
                return False
            if self.max_value is not None and self.value > self.max_value:
                self.errors.append(
                    f"Field '{self.field_name}' must be <= {self.max_value}"
                )
                return False

        # Pattern validation (for strings)
        if isinstance(self.value, str) and self.pattern:
            if not re.match(self.pattern, self.value):
                self.errors.append(
                    f"Field '{self.field_name}' does not match required pattern"
                )
                return False

        # Allowed values validation
        if self.allowed_values and self.value not in self.allowed_values:
            self.errors.append(
                f"Field '{self.field_name}' must be one of: {', '.join(map(str, self.allowed_values))}"
            )
            return False

        return True

    def get_errors(self) -> List[str]:
        """Get validation errors."""
        return self.errors


# ==============================================================================
# Request Validators
# ==============================================================================

class RequestValidator:
    """
    Central request validator for all API endpoints.
    
    Coordinates field validation, business logic validation,
    and comprehensive error reporting.
    """

    def __init__(self, settings: Optional[Settings] = None):
        """
        Initialize request validator.
        
        Args:
            settings: Application settings
        """
        self.settings = settings or Settings()
        self.logger = get_logger(__name__)
        self.cwe_rule = CWEFormatRule()
        self.cve_rule = CVEFormatRule()
        self.url_rule = URLFormatRule()
        self.ip_rule = IPAddressRule()
        self.hostname_rule = HostnameRule()

    def validate_payload_generation_request(
        self,
        protocol: str,
        vulnerability_type: str,
        target: Optional[Dict[str, Any]] = None,
        count: int = 5,
        **kwargs
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Validate payload generation request.
        
        Args:
            protocol: Target protocol
            vulnerability_type: Type of vulnerability
            target: Target information
            count: Number of payloads
            **kwargs: Additional arguments
            
        Returns:
            Tuple of (is_valid, validation_result)
        """
        errors = []

        # Validate protocol
        try:
            SupportedProtocol(protocol.lower())
        except ValueError:
            errors.append(
                f"Unsupported protocol: {protocol}. "
                f"Supported: {', '.join([p.value for p in SupportedProtocol])}"
            )

        # Validate vulnerability type
        try:
            VulnerabilityType(vulnerability_type.lower())
        except ValueError:
            errors.append(
                f"Unsupported vulnerability type: {vulnerability_type}. "
                f"Supported: {', '.join([v.value for v in VulnerabilityType])}"
            )

        # Validate count
        validator = FieldValidator(
            count, "count",
            required=True,
            field_type=int,
            min_value=1,
            max_value=100,
        )
        if not validator.validate():
            errors.extend(validator.get_errors())

        # Validate target if provided
        if target:
            if not isinstance(target, dict):
                errors.append("target must be a dictionary")
            else:
                if "host" in target:
                    host_val = target["host"]
                    is_valid, msg = self.hostname_rule.validate(host_val)
                    if not is_valid:
                        is_valid_ip, _ = self.ip_rule.validate(host_val)
                        if not is_valid_ip:
                            errors.append(f"Invalid target host: {msg}")

                if "port" in target:
                    port_validator = FieldValidator(
                        target["port"], "target.port",
                        field_type=int,
                        min_value=1,
                        max_value=65535,
                    )
                    if not port_validator.validate():
                        errors.extend(port_validator.get_errors())

        return len(errors) == 0, {"errors": errors, "request": kwargs}

    def validate_knowledge_request(
        self,
        query_type: str,
        identifier: str,
        **kwargs
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Validate knowledge base request.
        
        Args:
            query_type: Type of query (cwe, cve, search)
            identifier: CWE/CVE identifier or search query
            **kwargs: Additional arguments
            
        Returns:
            Tuple of (is_valid, validation_result)
        """
        errors = []

        # Validate query type
        if query_type not in ["cwe", "cve", "search"]:
            errors.append(
                f"Invalid query_type: {query_type}. "
                f"Must be one of: cwe, cve, search"
            )

        # Validate identifier based on query type
        if query_type == "cwe":
            is_valid, msg = self.cwe_rule.validate(identifier)
            if not is_valid:
                errors.append(msg)
        elif query_type == "cve":
            is_valid, msg = self.cve_rule.validate(identifier)
            if not is_valid:
                errors.append(msg)
        elif query_type == "search":
            validator = FieldValidator(
                identifier, "search_query",
                required=True,
                field_type=str,
                min_length=1,
                max_length=500,
            )
            if not validator.validate():
                errors.extend(validator.get_errors())

        return len(errors) == 0, {"errors": errors}

    def validate_health_check_request(self, **kwargs) -> Tuple[bool, Dict[str, Any]]:
        """
        Validate health check request.
        
        Args:
            **kwargs: Additional arguments
            
        Returns:
            Tuple of (is_valid, validation_result)
        """
        # Health check has minimal validation requirements
        errors = []

        # Optional detailed parameter
        if "detailed" in kwargs:
            validator = FieldValidator(
                kwargs["detailed"], "detailed",
                field_type=bool,
            )
            if not validator.validate():
                errors.extend(validator.get_errors())

        return len(errors) == 0, {"errors": errors}

    def validate_feedback_request(
        self,
        payload: str,
        execution_result: Dict[str, Any],
        **kwargs
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Validate feedback submission request.
        
        Args:
            payload: The payload that was executed
            execution_result: Result of payload execution
            **kwargs: Additional arguments
            
        Returns:
            Tuple of (is_valid, validation_result)
        """
        errors = []

        # Validate payload
        payload_validator = FieldValidator(
            payload, "payload",
            required=True,
            field_type=str,
            min_length=1,
            max_length=10000,
        )
        if not payload_validator.validate():
            errors.extend(payload_validator.get_errors())

        # Validate execution result
        if not isinstance(execution_result, dict):
            errors.append("execution_result must be a dictionary")
        else:
            # Check required fields in execution result
            if "status" not in execution_result:
                errors.append("execution_result must contain 'status' field")
            elif execution_result["status"] not in ["success", "failure", "error"]:
                errors.append(
                    "execution_result.status must be one of: success, failure, error"
                )

            if "timestamp" not in execution_result:
                errors.append("execution_result must contain 'timestamp' field")

        return len(errors) == 0, {"errors": errors}

    def validate_mcp_initialize_request(
        self,
        protocol_version: str,
        client_info: Dict[str, Any],
        **kwargs
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Validate MCP initialization request.
        
        Args:
            protocol_version: MCP protocol version
            client_info: Client information
            **kwargs: Additional arguments
            
        Returns:
            Tuple of (is_valid, validation_result)
        """
        errors = []

        # Validate protocol version
        version_validator = FieldValidator(
            protocol_version, "protocol_version",
            required=True,
            field_type=str,
            pattern=r"^\d+\.\d+\.\d+$",
        )
        if not version_validator.validate():
            errors.extend(version_validator.get_errors())

        # Validate client info
        if not isinstance(client_info, dict):
            errors.append("client_info must be a dictionary")
        else:
            if "name" not in client_info:
                errors.append("client_info must contain 'name' field")
            if "version" not in client_info:
                errors.append("client_info must contain 'version' field")

        return len(errors) == 0, {"errors": errors}

    def validate_tool_call_request(
        self,
        session_id: str,
        tool_name: str,
        arguments: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Validate MCP tool call request.
        
        Args:
            session_id: MCP session identifier
            tool_name: Name of the tool to call
            arguments: Tool arguments
            **kwargs: Additional arguments
            
        Returns:
            Tuple of (is_valid, validation_result)
        """
        errors = []

        # Validate session ID
        session_validator = FieldValidator(
            session_id, "session_id",
            required=True,
            field_type=str,
            min_length=1,
        )
        if not session_validator.validate():
            errors.extend(session_validator.get_errors())

        # Validate tool name
        valid_tools = ["generate_payloads", "analyze_vulnerability", "query_knowledge_base", "cache_payload"]
        tool_validator = FieldValidator(
            tool_name, "tool_name",
            required=True,
            field_type=str,
            allowed_values=set(valid_tools),
        )
        if not tool_validator.validate():
            errors.extend(tool_validator.get_errors())

        # Validate arguments
        if arguments is not None and not isinstance(arguments, dict):
            errors.append("arguments must be a dictionary or None")

        return len(errors) == 0, {"errors": errors}

    def validate_search_request(
        self,
        query: str,
        limit: int = 20,
        filters: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Validate knowledge base search request.
        
        Args:
            query: Search query
            limit: Maximum results to return
            filters: Optional search filters
            **kwargs: Additional arguments
            
        Returns:
            Tuple of (is_valid, validation_result)
        """
        errors = []

        # Validate query
        query_validator = FieldValidator(
            query, "query",
            required=True,
            field_type=str,
            min_length=1,
            max_length=500,
        )
        if not query_validator.validate():
            errors.extend(query_validator.get_errors())

        # Validate limit
        limit_validator = FieldValidator(
            limit, "limit",
            field_type=int,
            min_value=1,
            max_value=100,
        )
        if not limit_validator.validate():
            errors.extend(limit_validator.get_errors())

        # Validate filters if provided
        if filters is not None:
            if not isinstance(filters, dict):
                errors.append("filters must be a dictionary")

        return len(errors) == 0, {"errors": errors}

    def validate_request(
        self,
        endpoint: str,
        method: str,
        body: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Main request validation dispatcher.
        
        Args:
            endpoint: API endpoint path
            method: HTTP method
            body: Request body
            **kwargs: Additional context
            
        Returns:
            Tuple of (is_valid, validation_result)
            
        Example:
            >>> validator = RequestValidator()
            >>> is_valid, result = validator.validate_request(
            ...     endpoint="/api/v1/payloads/generate",
            ...     method="POST",
            ...     body={"protocol": "http", "vulnerability_type": "xss", "count": 5}
            ... )
        """
        self.logger.debug(f"Validating {method} {endpoint}")

        try:
            if not body:
                body = {}

            # Route to appropriate validator based on endpoint
            if "payloads/generate" in endpoint:
                return self.validate_payload_generation_request(**body, **kwargs)
            elif "knowledge" in endpoint or "cwe" in endpoint or "cve" in endpoint:
                return self.validate_knowledge_request(**body, **kwargs)
            elif "health" in endpoint:
                return self.validate_health_check_request(**body, **kwargs)
            elif "feedback" in endpoint:
                return self.validate_feedback_request(**body, **kwargs)
            elif "/mcp/initialize" in endpoint:
                return self.validate_mcp_initialize_request(**body, **kwargs)
            elif "/mcp/tools/call" in endpoint:
                return self.validate_tool_call_request(**body, **kwargs)
            elif "search" in endpoint:
                return self.validate_search_request(**body, **kwargs)
            else:
                # Generic validation for unknown endpoints
                return True, {"errors": []}

        except Exception as e:
            self.logger.error(f"Validation error: {str(e)}", exc_info=True)
            return False, {"errors": [f"Validation failed: {str(e)}"]}


# ==============================================================================
# Standalone Validation Functions
# ==============================================================================

def validate_llm_request(
    protocol: str,
    vulnerability_type: str,
    target: Optional[Dict[str, Any]] = None,
    **kwargs
) -> bool:
    """
    Validate LLM-based payload generation request.
    
    Args:
        protocol: Target protocol
        vulnerability_type: Vulnerability type
        target: Target information
        **kwargs: Additional arguments
        
    Returns:
        True if valid, False otherwise
        
    Raises:
        ValidationError: If validation fails with detailed error info
    """
    validator = RequestValidator()
    is_valid, result = validator.validate_payload_generation_request(
        protocol=protocol,
        vulnerability_type=vulnerability_type,
        target=target,
        **kwargs
    )

    if not is_valid:
        errors = result.get("errors", [])
        raise ValidationError(
            f"LLM request validation failed: {'; '.join(errors)}",
            details={"errors": errors}
        )

    return True


def validate_knowledge_request(
    query_type: str,
    identifier: str,
    **kwargs
) -> bool:
    """
    Validate knowledge base query request.
    
    Args:
        query_type: Type of query (cwe, cve, search)
        identifier: CWE/CVE ID or search query
        **kwargs: Additional arguments
        
    Returns:
        True if valid, False otherwise
        
    Raises:
        ValidationError: If validation fails
    """
    validator = RequestValidator()
    is_valid, result = validator.validate_knowledge_request(
        query_type=query_type,
        identifier=identifier,
        **kwargs
    )

    if not is_valid:
        errors = result.get("errors", [])
        raise ValidationError(
            f"Knowledge request validation failed: {'; '.join(errors)}",
            details={"errors": errors}
        )

    return True


def validate_health_check_request(**kwargs) -> bool:
    """
    Validate health check request.
    
    Args:
        **kwargs: Additional arguments
        
    Returns:
        True if valid, False otherwise
        
    Raises:
        ValidationError: If validation fails
    """
    validator = RequestValidator()
    is_valid, result = validator.validate_health_check_request(**kwargs)

    if not is_valid:
        errors = result.get("errors", [])
        raise ValidationError(
            f"Health check request validation failed: {'; '.join(errors)}",
            details={"errors": errors}
        )

    return True


def validate_payload_request(
    payload: str,
    execution_result: Dict[str, Any],
    **kwargs
) -> bool:
    """
    Validate payload feedback request.
    
    Args:
        payload: Payload content
        execution_result: Execution result data
        **kwargs: Additional arguments
        
    Returns:
        True if valid, False otherwise
        
    Raises:
        ValidationError: If validation fails
    """
    validator = RequestValidator()
    is_valid, result = validator.validate_feedback_request(
        payload=payload,
        execution_result=execution_result,
        **kwargs
    )

    if not is_valid:
        errors = result.get("errors", [])
        raise ValidationError(
            f"Payload feedback validation failed: {'; '.join(errors)}",
            details={"errors": errors}
        )

    return True


def validate_mcp_request(
    protocol_version: str,
    client_info: Dict[str, Any],
    **kwargs
) -> bool:
    """
    Validate MCP initialization request.
    
    Args:
        protocol_version: MCP protocol version
        client_info: Client information
        **kwargs: Additional arguments
        
    Returns:
        True if valid, False otherwise
        
    Raises:
        ValidationError: If validation fails
    """
    validator = RequestValidator()
    is_valid, result = validator.validate_mcp_initialize_request(
        protocol_version=protocol_version,
        client_info=client_info,
        **kwargs
    )

    if not is_valid:
        errors = result.get("errors", [])
        raise ValidationError(
            f"MCP request validation failed: {'; '.join(errors)}",
            details={"errors": errors}
        )

    return True


# ==============================================================================
# Utility Functions
# ==============================================================================

def get_supported_protocols() -> List[str]:
    """Get list of supported protocols."""
    return [p.value for p in SupportedProtocol]


def get_vulnerability_types() -> List[str]:
    """Get list of supported vulnerability types."""
    return [v.value for v in VulnerabilityType]


def get_validation_info() -> Dict[str, Any]:
    """
    Get comprehensive validation information.
    
    Returns:
        Dictionary containing validation rules and constraints
    """
    return {
        "supported_protocols": get_supported_protocols(),
        "vulnerability_types": get_vulnerability_types(),
        "constraints": {
            "payload_count": {
                "min": 1,
                "max": 100,
            },
            "search_limit": {
                "min": 1,
                "max": 100,
            },
            "payload_size": {
                "min": 1,
                "max": 10000,
            },
            "query_length": {
                "min": 1,
                "max": 500,
            },
        },
        "formats": {
            "cwe": "CWE-XXXX",
            "cve": "CVE-XXXX-XXXXX",
            "version": "X.X.X",
            "url": "protocol://host:port/path",
        },
    }


# ==============================================================================
# Exports
# ==============================================================================

__all__ = [
    # Enumerations
    "SupportedProtocol",
    "VulnerabilityType",

    # Validation Rules
    "ValidationRule",
    "CWEFormatRule",
    "CVEFormatRule",
    "URLFormatRule",
    "IPAddressRule",
    "HostnameRule",

    # Field Validator
    "FieldValidator",

    # Request Validator
    "RequestValidator",

    # Standalone Functions
    "validate_llm_request",
    "validate_knowledge_request",
    "validate_health_check_request",
    "validate_payload_request",
    "validate_mcp_request",

    # Utility Functions
    "get_supported_protocols",
    "get_vulnerability_types",
    "get_validation_info",
]