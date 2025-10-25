# hyfuzz-server-windows/src/mcp_server/utils.py
"""
Utility functions for MCP Server operations.
Provides helper functions for message handling, validation, encoding/decoding,
and common MCP protocol operations.
"""

import json
import uuid
import hashlib
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Callable, TypeVar, Union
from functools import wraps
from enum import Enum
import logging

logger = logging.getLogger(__name__)

T = TypeVar('T')


class MessageType(str, Enum):
    """MCP Protocol Message Types"""
    REQUEST = "request"
    RESPONSE = "response"
    NOTIFICATION = "notification"
    ERROR = "error"


class ProtocolVersion:
    """MCP Protocol Version Management"""
    MAJOR = 1
    MINOR = 0
    PATCH = 0

    @classmethod
    def get_version_string(cls) -> str:
        """Get formatted version string"""
        return f"{cls.MAJOR}.{cls.MINOR}.{cls.PATCH}"


def generate_message_id() -> str:
    """
    Generate a unique message ID using UUID4.

    Returns:
        str: Unique message identifier
    """
    return str(uuid.uuid4())


def generate_request_id() -> str:
    """
    Generate a unique request ID.

    Returns:
        str: Unique request identifier
    """
    return f"req_{uuid.uuid4().hex[:16]}"


def generate_session_id() -> str:
    """
    Generate a unique session ID.

    Returns:
        str: Unique session identifier
    """
    return f"sess_{uuid.uuid4().hex[:16]}_{int(time.time() * 1000)}"


def compute_hash(data: str, algorithm: str = "sha256") -> str:
    """
    Compute hash of data using specified algorithm.

    Args:
        data: String data to hash
        algorithm: Hash algorithm to use (default: sha256)

    Returns:
        str: Hexadecimal hash string
    """
    if algorithm == "sha256":
        return hashlib.sha256(data.encode()).hexdigest()
    elif algorithm == "sha1":
        return hashlib.sha1(data.encode()).hexdigest()
    elif algorithm == "md5":
        return hashlib.md5(data.encode()).hexdigest()
    else:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")


def get_timestamp() -> str:
    """
    Get current timestamp in ISO 8601 format.

    Returns:
        str: ISO formatted timestamp
    """
    return datetime.utcnow().isoformat() + "Z"


def get_timestamp_ms() -> int:
    """
    Get current timestamp in milliseconds.

    Returns:
        int: Timestamp in milliseconds since epoch
    """
    return int(time.time() * 1000)


def safe_json_dumps(data: Any, default_handler: Optional[Callable] = None,
                    pretty: bool = False) -> str:
    """
    Safely serialize data to JSON string.

    Args:
        data: Data to serialize
        default_handler: Custom handler for non-serializable objects
        pretty: Whether to format with indentation

    Returns:
        str: JSON string representation

    Raises:
        TypeError: If data cannot be serialized
    """

    def default(obj):
        if callable(default_handler):
            return default_handler(obj)
        if hasattr(obj, '__dict__'):
            return obj.__dict__
        if isinstance(obj, (set, frozenset)):
            return list(obj)
        return str(obj)

    indent = 2 if pretty else None
    return json.dumps(data, default=default, indent=indent, ensure_ascii=False)


def safe_json_loads(data: str, default_value: Any = None) -> Any:
    """
    Safely deserialize JSON string.

    Args:
        data: JSON string to parse
        default_value: Value to return if parsing fails

    Returns:
        Parsed JSON data or default_value if parsing fails
    """
    try:
        return json.loads(data)
    except (json.JSONDecodeError, TypeError) as e:
        logger.warning(f"JSON parsing error: {e}, returning default value")
        return default_value


def validate_message_format(message: Dict[str, Any]) -> bool:
    """
    Validate MCP message format.

    Args:
        message: Message dictionary to validate

    Returns:
        bool: True if message format is valid
    """
    required_fields = {"type", "id"}
    if not all(field in message for field in required_fields):
        logger.error(f"Missing required fields: {required_fields}")
        return False

    valid_types = {MessageType.REQUEST, MessageType.RESPONSE,
                   MessageType.NOTIFICATION, MessageType.ERROR}
    if message.get("type") not in valid_types:
        logger.error(f"Invalid message type: {message.get('type')}")
        return False

    return True


def validate_request_format(request: Dict[str, Any]) -> bool:
    """
    Validate MCP request format.

    Args:
        request: Request dictionary to validate

    Returns:
        bool: True if request format is valid
    """
    if not validate_message_format(request):
        return False

    required_fields = {"method", "params"}
    if not all(field in request for field in required_fields):
        logger.error(f"Missing request fields: {required_fields}")
        return False

    return True


def validate_response_format(response: Dict[str, Any]) -> bool:
    """
    Validate MCP response format.

    Args:
        response: Response dictionary to validate

    Returns:
        bool: True if response format is valid
    """
    if not validate_message_format(response):
        return False

    if "result" not in response and "error" not in response:
        logger.error("Response must contain either 'result' or 'error'")
        return False

    return True


def create_request_message(method: str, params: Dict[str, Any],
                           message_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Create a properly formatted MCP request message.

    Args:
        method: Request method name
        params: Request parameters
        message_id: Optional message ID (auto-generated if not provided)

    Returns:
        dict: Formatted request message
    """
    return {
        "type": MessageType.REQUEST,
        "id": message_id or generate_message_id(),
        "method": method,
        "params": params or {},
        "timestamp": get_timestamp()
    }


def create_response_message(request_id: str, result: Any = None,
                            error: Optional[str] = None) -> Dict[str, Any]:
    """
    Create a properly formatted MCP response message.

    Args:
        request_id: ID of the request being responded to
        result: Response result data
        error: Error message (if applicable)

    Returns:
        dict: Formatted response message
    """
    response = {
        "type": MessageType.RESPONSE if not error else MessageType.ERROR,
        "id": request_id,
        "timestamp": get_timestamp()
    }

    if error:
        response["error"] = error
    else:
        response["result"] = result

    return response


def create_notification_message(event: str, data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Create a properly formatted MCP notification message.

    Args:
        event: Event name
        data: Event data

    Returns:
        dict: Formatted notification message
    """
    return {
        "type": MessageType.NOTIFICATION,
        "id": generate_message_id(),
        "event": event,
        "data": data or {},
        "timestamp": get_timestamp()
    }


def extract_message_id(message: Dict[str, Any]) -> Optional[str]:
    """
    Safely extract message ID from message.

    Args:
        message: Message dictionary

    Returns:
        str or None: Message ID if present
    """
    return message.get("id")


def extract_method(message: Dict[str, Any]) -> Optional[str]:
    """
    Safely extract method from request message.

    Args:
        message: Message dictionary

    Returns:
        str or None: Method name if present
    """
    return message.get("method")


def extract_params(message: Dict[str, Any]) -> Dict[str, Any]:
    """
    Safely extract parameters from message.

    Args:
        message: Message dictionary

    Returns:
        dict: Parameters dictionary or empty dict
    """
    return message.get("params", {})


def truncate_string(text: str, max_length: int = 100, suffix: str = "...") -> str:
    """
    Truncate string to maximum length with suffix.

    Args:
        text: Text to truncate
        max_length: Maximum length
        suffix: Suffix to append if truncated

    Returns:
        str: Truncated text
    """
    if len(text) <= max_length:
        return text
    return text[:max_length - len(suffix)] + suffix


def mask_sensitive_data(data: Dict[str, Any], sensitive_keys: List[str] = None) -> Dict[str, Any]:
    """
    Mask sensitive data in dictionary.

    Args:
        data: Dictionary containing sensitive data
        sensitive_keys: List of keys to mask (default: common sensitive keys)

    Returns:
        dict: Dictionary with sensitive values masked
    """
    if sensitive_keys is None:
        sensitive_keys = ["password", "token", "api_key", "secret", "authorization"]

    masked = {}
    for key, value in data.items():
        if key.lower() in sensitive_keys:
            masked[key] = "***MASKED***"
        elif isinstance(value, dict):
            masked[key] = mask_sensitive_data(value, sensitive_keys)
        else:
            masked[key] = value

    return masked


def retry_on_exception(max_retries: int = 3, delay: float = 1.0,
                       backoff: float = 2.0, exceptions: tuple = (Exception,)):
    """
    Decorator to retry function on exception.

    Args:
        max_retries: Maximum number of retries
        delay: Initial delay between retries in seconds
        backoff: Multiplier for delay after each retry
        exceptions: Tuple of exceptions to catch

    Returns:
        Decorated function
    """

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            current_delay = delay
            last_exception = None

            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    if attempt < max_retries:
                        logger.warning(
                            f"Attempt {attempt + 1} failed: {e}. "
                            f"Retrying in {current_delay}s..."
                        )
                        time.sleep(current_delay)
                        current_delay *= backoff
                    else:
                        logger.error(f"All {max_retries + 1} attempts failed")

            raise last_exception or Exception("Function failed after retries")

        return wrapper

    return decorator


def timer_decorator(func: Callable[..., T]) -> Callable[..., T]:
    """
    Decorator to measure function execution time.

    Args:
        func: Function to time

    Returns:
        Decorated function
    """

    @wraps(func)
    def wrapper(*args, **kwargs) -> T:
        start_time = time.time()
        try:
            result = func(*args, **kwargs)
            return result
        finally:
            elapsed = time.time() - start_time
            logger.debug(f"{func.__name__} executed in {elapsed:.4f}s")

    return wrapper


def flatten_dict(data: Dict[str, Any], parent_key: str = '',
                 sep: str = '.') -> Dict[str, Any]:
    """
    Flatten nested dictionary.

    Args:
        data: Dictionary to flatten
        parent_key: Parent key prefix
        sep: Separator for nested keys

    Returns:
        dict: Flattened dictionary
    """
    items = []
    for key, value in data.items():
        new_key = f"{parent_key}{sep}{key}" if parent_key else key
        if isinstance(value, dict):
            items.extend(flatten_dict(value, new_key, sep).items())
        else:
            items.append((new_key, value))
    return dict(items)


def deep_merge_dicts(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """
    Deep merge two dictionaries with override taking precedence.

    Args:
        base: Base dictionary
        override: Dictionary to merge in

    Returns:
        dict: Merged dictionary
    """
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge_dicts(result[key], value)
        else:
            result[key] = value
    return result


# ============================================================================
# TEST SECTION
# ============================================================================

def run_tests():
    """Run comprehensive tests for utils module"""

    print("=" * 70)
    print("Running MCP Server Utils Tests")
    print("=" * 70)

    # Test 1: ID Generation
    print("\n[TEST 1] ID Generation Functions")
    msg_id = generate_message_id()
    req_id = generate_request_id()
    sess_id = generate_session_id()
    assert msg_id and len(msg_id) > 0
    assert req_id.startswith("req_")
    assert sess_id.startswith("sess_")
    print(f"✓ Message ID: {msg_id}")
    print(f"✓ Request ID: {req_id}")
    print(f"✓ Session ID: {sess_id}")

    # Test 2: Hash Computation
    print("\n[TEST 2] Hash Computation")
    test_data = "test_string"
    sha256_hash = compute_hash(test_data, "sha256")
    assert len(sha256_hash) == 64
    print(f"✓ SHA256 Hash: {sha256_hash[:16]}...")

    # Test 3: Timestamps
    print("\n[TEST 3] Timestamp Functions")
    ts_iso = get_timestamp()
    ts_ms = get_timestamp_ms()
    assert ts_iso.endswith("Z")
    assert isinstance(ts_ms, int) and ts_ms > 0
    print(f"✓ ISO Timestamp: {ts_iso}")
    print(f"✓ Millisecond Timestamp: {ts_ms}")

    # Test 4: JSON Operations
    print("\n[TEST 4] JSON Operations")
    test_dict = {"key": "value", "nested": {"inner": "data"}}
    json_str = safe_json_dumps(test_dict, pretty=True)
    parsed = safe_json_loads(json_str)
    assert parsed == test_dict
    print(f"✓ JSON Serialization: {json_str[:50]}...")
    print(f"✓ JSON Deserialization successful")

    # Test 5: Message Creation and Validation
    print("\n[TEST 5] Message Creation and Validation")
    request = create_request_message("test_method", {"param": "value"})
    assert validate_request_format(request)
    print(f"✓ Request Message: {request}")

    response = create_response_message(request["id"], {"result": "success"})
    assert validate_response_format(response)
    print(f"✓ Response Message: {response}")

    notification = create_notification_message("test_event", {"data": "value"})
    assert notification["type"] == MessageType.NOTIFICATION
    print(f"✓ Notification Message: {notification}")

    # Test 6: Message Extraction
    print("\n[TEST 6] Message Field Extraction")
    msg_id_extracted = extract_message_id(request)
    method_extracted = extract_method(request)
    params_extracted = extract_params(request)
    assert msg_id_extracted == request["id"]
    assert method_extracted == "test_method"
    assert params_extracted == {"param": "value"}
    print(f"✓ Extracted ID: {msg_id_extracted}")
    print(f"✓ Extracted Method: {method_extracted}")
    print(f"✓ Extracted Params: {params_extracted}")

    # Test 7: String Operations
    print("\n[TEST 7] String Operations")
    long_string = "a" * 200
    truncated = truncate_string(long_string, max_length=50)
    assert len(truncated) == 50
    assert truncated.endswith("...")
    print(f"✓ String Truncation: {truncated}")

    # Test 8: Sensitive Data Masking
    print("\n[TEST 8] Sensitive Data Masking")
    sensitive_dict = {"username": "user", "password": "secret123", "data": "public"}
    masked = mask_sensitive_data(sensitive_dict)
    assert masked["password"] == "***MASKED***"
    assert masked["data"] == "public"
    print(f"✓ Masked Data: {masked}")

    # Test 9: Dictionary Operations
    print("\n[TEST 9] Dictionary Operations")
    nested_dict = {"a": {"b": {"c": "value"}}, "d": "other"}
    flattened = flatten_dict(nested_dict)
    assert "a.b.c" in flattened
    print(f"✓ Flattened Dict: {flattened}")

    base_dict = {"x": 1, "y": {"z": 2}}
    override_dict = {"y": {"z": 3}, "w": 4}
    merged = deep_merge_dicts(base_dict, override_dict)
    assert merged["y"]["z"] == 3
    assert merged["w"] == 4
    print(f"✓ Merged Dict: {merged}")

    # Test 10: Protocol Version
    print("\n[TEST 10] Protocol Version")
    version = ProtocolVersion.get_version_string()
    assert version == "1.0.0"
    print(f"✓ Protocol Version: {version}")

    print("\n" + "=" * 70)
    print("All tests passed successfully! ✓")
    print("=" * 70)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    run_tests()