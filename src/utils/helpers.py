# hyfuzz-server-windows/src/utils/helpers.py

"""
Helpers - General utility helper functions for common operations.
Provides utility functions for string manipulation, data conversion,
input sanitization, and other common tasks.
"""

import json
import logging
import os
import re
import hashlib
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple, Union
from pathlib import Path
from urllib.parse import urlparse, quote, unquote

logger = logging.getLogger(__name__)


# ============================================================================
# String Manipulation Helpers
# ============================================================================

def sanitize_input(value: str, max_length: int = 1000) -> str:
    """
    Sanitize user input by removing dangerous characters.

    Args:
        value: Input string to sanitize
        max_length: Maximum allowed string length

    Returns:
        Sanitized string

    Example:
        sanitized = sanitize_input("<script>alert('xss')</script>")
    """
    if not isinstance(value, str):
        return str(value)

    # Truncate to max length
    value = value[:max_length]

    # Remove control characters
    value = "".join(char for char in value if ord(char) >= 32 or char in "\n\t\r")

    # Remove null bytes
    value = value.replace("\x00", "")

    return value.strip()


def truncate_string(value: str, max_length: int = 100, suffix: str = "...") -> str:
    """
    Truncate string to maximum length with suffix.

    Args:
        value: String to truncate
        max_length: Maximum length
        suffix: Suffix to append if truncated

    Returns:
        Truncated string

    Example:
        truncated = truncate_string("Very long string", max_length=10)
        # Result: "Very lo..."
    """
    if len(value) <= max_length:
        return value

    # Account for suffix length
    truncate_at = max(0, max_length - len(suffix))
    return value[:truncate_at] + suffix


def camel_to_snake(name: str) -> str:
    """
    Convert camelCase to snake_case.

    Args:
        name: CamelCase string

    Returns:
        snake_case string

    Example:
        snake_case = camel_to_snake("myVariableName")
        # Result: "my_variable_name"
    """
    # Insert underscore before uppercase letters (except first)
    s1 = re.sub("(.)([A-Z][a-z]+)", r"\1_\2", name)
    # Insert underscore before uppercase letters preceded by lowercase
    return re.sub("([a-z0-9])([A-Z])", r"\1_\2", s1).lower()


def snake_to_camel(name: str) -> str:
    """
    Convert snake_case to camelCase.

    Args:
        name: snake_case string

    Returns:
        camelCase string

    Example:
        camel_case = snake_to_camel("my_variable_name")
        # Result: "myVariableName"
    """
    components = name.split("_")
    return components[0] + "".join(x.title() for x in components[1:])


def normalize_whitespace(value: str) -> str:
    """
    Normalize whitespace in string (collapse multiple spaces).

    Args:
        value: String to normalize

    Returns:
        Normalized string
    """
    # Replace multiple spaces with single space
    value = re.sub(r"\s+", " ", value)
    return value.strip()


def remove_special_chars(value: str, keep_chars: str = "") -> str:
    """
    Remove special characters from string.

    Args:
        value: String to clean
        keep_chars: Characters to keep (in addition to alphanumeric)

    Returns:
        Cleaned string
    """
    # Create pattern of characters to remove
    pattern = f"[^a-zA-Z0-9{re.escape(keep_chars)}]"
    return re.sub(pattern, "", value)


# ============================================================================
# Validation Helpers
# ============================================================================

def is_valid_email(email: str) -> bool:
    """
    Validate email address format.

    Args:
        email: Email address to validate

    Returns:
        True if valid email format
    """
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(pattern, email))


def is_valid_url(url: str) -> bool:
    """
    Validate URL format.

    Args:
        url: URL to validate

    Returns:
        True if valid URL format
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def is_valid_port(port: Union[int, str]) -> bool:
    """
    Validate port number.

    Args:
        port: Port number to validate

    Returns:
        True if valid port (1-65535)
    """
    try:
        port_num = int(port)
        return 1 <= port_num <= 65535
    except (ValueError, TypeError):
        return False


def is_valid_uuid(uuid_str: str) -> bool:
    """
    Validate UUID format.

    Args:
        uuid_str: UUID string to validate

    Returns:
        True if valid UUID format
    """
    pattern = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    return bool(re.match(pattern, uuid_str.lower()))


# ============================================================================
# Dictionary Helpers
# ============================================================================

def merge_dicts(dict1: Dict[str, Any], dict2: Dict[str, Any], deep: bool = True) -> Dict[str, Any]:
    """
    Merge two dictionaries, with dict2 values overwriting dict1.

    Args:
        dict1: First dictionary
        dict2: Second dictionary
        deep: Whether to perform deep merge

    Returns:
        Merged dictionary

    Example:
        merged = merge_dicts({"a": 1, "b": {"c": 2}}, {"b": {"d": 3}})
        # Result: {"a": 1, "b": {"c": 2, "d": 3}}
    """
    result = dict1.copy()

    for key, value in dict2.items():
        if deep and isinstance(value, dict) and key in result and isinstance(result[key], dict):
            result[key] = merge_dicts(result[key], value, deep=True)
        else:
            result[key] = value

    return result


def flatten_dict(data: Dict[str, Any], parent_key: str = "", separator: str = ".") -> Dict[str, Any]:
    """
    Flatten nested dictionary.

    Args:
        data: Dictionary to flatten
        parent_key: Parent key for recursion
        separator: Key separator

    Returns:
        Flattened dictionary

    Example:
        flat = flatten_dict({"a": {"b": {"c": 1}}})
        # Result: {"a.b.c": 1}
    """
    items = []

    for k, v in data.items():
        new_key = f"{parent_key}{separator}{k}" if parent_key else k

        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, separator).items())
        else:
            items.append((new_key, v))

    return dict(items)


def unflatten_dict(data: Dict[str, Any], separator: str = ".") -> Dict[str, Any]:
    """
    Unflatten dictionary.

    Args:
        data: Flattened dictionary
        separator: Key separator

    Returns:
        Nested dictionary

    Example:
        nested = unflatten_dict({"a.b.c": 1})
        # Result: {"a": {"b": {"c": 1}}}
    """
    result = {}

    for key, value in data.items():
        parts = key.split(separator)
        current = result

        for part in parts[:-1]:
            if part not in current:
                current[part] = {}
            current = current[part]

        current[parts[-1]] = value

    return result


def get_dict_value(data: Dict[str, Any], key_path: str, default: Any = None, separator: str = ".") -> Any:
    """
    Get value from nested dictionary using dot notation.

    Args:
        data: Dictionary to search
        key_path: Key path (e.g., "a.b.c")
        default: Default value if not found
        separator: Key separator

    Returns:
        Value if found, default otherwise

    Example:
        value = get_dict_value({"a": {"b": 1}}, "a.b")
        # Result: 1
    """
    keys = key_path.split(separator)
    current = data

    for key in keys:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return default

    return current


def set_dict_value(data: Dict[str, Any], key_path: str, value: Any, separator: str = ".") -> Dict[str, Any]:
    """
    Set value in nested dictionary using dot notation.

    Args:
        data: Dictionary to modify
        key_path: Key path (e.g., "a.b.c")
        value: Value to set
        separator: Key separator

    Returns:
        Modified dictionary

    Example:
        data = set_dict_value({}, "a.b.c", 1)
        # Result: {"a": {"b": {"c": 1}}}
    """
    keys = key_path.split(separator)
    current = data

    for key in keys[:-1]:
        if key not in current:
            current[key] = {}
        current = current[key]

    current[keys[-1]] = value
    return data


# ============================================================================
# JSON Helpers
# ============================================================================

def safe_json_dumps(data: Any, default_value: str = "{}") -> str:
    """
    Safely convert data to JSON string.

    Args:
        data: Data to serialize
        default_value: Default value if serialization fails

    Returns:
        JSON string
    """
    try:
        return json.dumps(data, default=str)
    except (TypeError, ValueError) as e:
        logger.error(f"JSON serialization failed: {e}")
        return default_value


def parse_json(json_str: str, default_value: Optional[Any] = None) -> Any:
    """
    Safely parse JSON string.

    Args:
        json_str: JSON string to parse
        default_value: Default value if parsing fails

    Returns:
        Parsed data or default value
    """
    try:
        return json.loads(json_str)
    except (json.JSONDecodeError, ValueError) as e:
        logger.error(f"JSON parsing failed: {e}")
        return default_value if default_value is not None else {}


# ============================================================================
# Date/Time Helpers
# ============================================================================

def get_current_timestamp() -> float:
    """
    Get current Unix timestamp.

    Returns:
        Current Unix timestamp
    """
    return datetime.utcnow().timestamp()


def timestamp_to_datetime(timestamp: float) -> datetime:
    """
    Convert Unix timestamp to datetime object.

    Args:
        timestamp: Unix timestamp

    Returns:
        datetime object
    """
    return datetime.utcfromtimestamp(timestamp)


def datetime_to_iso_string(dt: datetime) -> str:
    """
    Convert datetime to ISO format string.

    Args:
        dt: datetime object

    Returns:
        ISO format string (YYYY-MM-DDTHH:MM:SSZ)
    """
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def get_time_difference(start_time: datetime, end_time: Optional[datetime] = None) -> float:
    """
    Get time difference in seconds.

    Args:
        start_time: Start datetime
        end_time: End datetime (defaults to now)

    Returns:
        Time difference in seconds
    """
    if end_time is None:
        end_time = datetime.utcnow()

    diff = end_time - start_time
    return diff.total_seconds()


# ============================================================================
# Hash and Encoding Helpers
# ============================================================================

def hash_string(value: str, algorithm: str = "sha256") -> str:
    """
    Hash a string using specified algorithm.

    Args:
        value: String to hash
        algorithm: Hash algorithm ('md5', 'sha256', 'sha512')

    Returns:
        Hexadecimal hash string
    """
    hash_obj = hashlib.new(algorithm)
    hash_obj.update(value.encode("utf-8"))
    return hash_obj.hexdigest()


def url_encode(value: str, safe: str = "") -> str:
    """
    URL encode a string.

    Args:
        value: String to encode
        safe: Characters not to encode

    Returns:
        URL encoded string
    """
    return quote(value, safe=safe)


def url_decode(value: str) -> str:
    """
    URL decode a string.

    Args:
        value: String to decode

    Returns:
        URL decoded string
    """
    return unquote(value)


# ============================================================================
# File and Path Helpers
# ============================================================================

def ensure_directory(directory: str) -> Path:
    """
    Ensure directory exists, create if needed.

    Args:
        directory: Directory path

    Returns:
        Path object
    """
    path = Path(directory)
    path.mkdir(parents=True, exist_ok=True)
    return path


def get_file_size(file_path: str) -> int:
    """
    Get file size in bytes.

    Args:
        file_path: Path to file

    Returns:
        File size in bytes, or -1 if not found
    """
    try:
        return os.path.getsize(file_path)
    except OSError:
        return -1


def read_text_file(file_path: str, encoding: str = "utf-8") -> Optional[str]:
    """
    Read text file safely.

    Args:
        file_path: Path to file
        encoding: File encoding

    Returns:
        File contents or None if error
    """
    try:
        with open(file_path, "r", encoding=encoding) as f:
            return f.read()
    except Exception as e:
        logger.error(f"Failed to read file {file_path}: {e}")
        return None


def write_text_file(file_path: str, content: str, encoding: str = "utf-8") -> bool:
    """
    Write text file safely.

    Args:
        file_path: Path to file
        content: Content to write
        encoding: File encoding

    Returns:
        True if successful, False otherwise
    """
    try:
        # Ensure directory exists
        ensure_directory(os.path.dirname(file_path) or ".")

        with open(file_path, "w", encoding=encoding) as f:
            f.write(content)
        return True
    except Exception as e:
        logger.error(f"Failed to write file {file_path}: {e}")
        return False


# ============================================================================
# Data Type Helpers
# ============================================================================

def convert_to_bool(value: Any) -> bool:
    """
    Convert value to boolean.

    Args:
        value: Value to convert

    Returns:
        Boolean value
    """
    if isinstance(value, bool):
        return value

    if isinstance(value, str):
        return value.lower() in ("true", "1", "yes", "on", "enabled")

    return bool(value)


def convert_to_int(value: Any, default: int = 0) -> int:
    """
    Convert value to integer safely.

    Args:
        value: Value to convert
        default: Default value if conversion fails

    Returns:
        Integer value
    """
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def convert_to_float(value: Any, default: float = 0.0) -> float:
    """
    Convert value to float safely.

    Args:
        value: Value to convert
        default: Default value if conversion fails

    Returns:
        Float value
    """
    try:
        return float(value)
    except (ValueError, TypeError):
        return default


# ============================================================================
# TESTS
# ============================================================================

if __name__ == "__main__":
    """Test helper functions"""
    import sys

    print("=" * 80)
    print("TESTING HELPER FUNCTIONS")
    print("=" * 80)

    test_results = []

    # Test 1: sanitize_input
    print("\n[Test 1] sanitize_input:")
    try:
        dirty = "  <script>alert('xss')</script>  "
        clean = sanitize_input(dirty)
        # sanitize_input removes control characters and trims whitespace
        # but keeps normal characters like < > = '
        assert clean == "<script>alert('xss')</script>"
        assert len(clean) < len(dirty)  # Should be shorter due to whitespace removal
        print(f"✓ Sanitized: {clean}")
        test_results.append(("sanitize_input", True, None))
    except Exception as e:
        print(f"✗ Failed: {e}")
        test_results.append(("sanitize_input", False, str(e)))

    # Test 2: truncate_string
    print("\n[Test 2] truncate_string:")
    try:
        long_str = "This is a very long string that needs truncation"
        truncated = truncate_string(long_str, max_length=20)
        assert len(truncated) <= 20
        assert "..." in truncated
        print(f"✓ Truncated: {truncated}")
        test_results.append(("truncate_string", True, None))
    except Exception as e:
        print(f"✗ Failed: {e}")
        test_results.append(("truncate_string", False, str(e)))

    # Test 3: camel_to_snake
    print("\n[Test 3] camel_to_snake:")
    try:
        camel = "myVariableName"
        snake = camel_to_snake(camel)
        assert snake == "my_variable_name"
        print(f"✓ {camel} -> {snake}")
        test_results.append(("camel_to_snake", True, None))
    except Exception as e:
        print(f"✗ Failed: {e}")
        test_results.append(("camel_to_snake", False, str(e)))

    # Test 4: snake_to_camel
    print("\n[Test 4] snake_to_camel:")
    try:
        snake = "my_variable_name"
        camel = snake_to_camel(snake)
        assert camel == "myVariableName"
        print(f"✓ {snake} -> {camel}")
        test_results.append(("snake_to_camel", True, None))
    except Exception as e:
        print(f"✗ Failed: {e}")
        test_results.append(("snake_to_camel", False, str(e)))

    # Test 5: merge_dicts
    print("\n[Test 5] merge_dicts:")
    try:
        dict1 = {"a": 1, "b": {"c": 2}}
        dict2 = {"b": {"d": 3}, "e": 4}
        merged = merge_dicts(dict1, dict2)
        assert merged["a"] == 1
        assert merged["b"]["c"] == 2
        assert merged["b"]["d"] == 3
        assert merged["e"] == 4
        print(f"✓ Merged: {merged}")
        test_results.append(("merge_dicts", True, None))
    except Exception as e:
        print(f"✗ Failed: {e}")
        test_results.append(("merge_dicts", False, str(e)))

    # Test 6: flatten_dict
    print("\n[Test 6] flatten_dict:")
    try:
        nested = {"a": {"b": {"c": 1}}, "d": 2}
        flat = flatten_dict(nested)
        assert flat["a.b.c"] == 1
        assert flat["d"] == 2
        print(f"✓ Flattened: {flat}")
        test_results.append(("flatten_dict", True, None))
    except Exception as e:
        print(f"✗ Failed: {e}")
        test_results.append(("flatten_dict", False, str(e)))

    # Test 7: unflatten_dict
    print("\n[Test 7] unflatten_dict:")
    try:
        flat = {"a.b.c": 1, "d": 2}
        nested = unflatten_dict(flat)
        assert nested["a"]["b"]["c"] == 1
        assert nested["d"] == 2
        print(f"✓ Unflattened: {nested}")
        test_results.append(("unflatten_dict", True, None))
    except Exception as e:
        print(f"✗ Failed: {e}")
        test_results.append(("unflatten_dict", False, str(e)))

    # Test 8: get_dict_value
    print("\n[Test 8] get_dict_value:")
    try:
        data = {"a": {"b": {"c": 1}}}
        value = get_dict_value(data, "a.b.c")
        assert value == 1
        default = get_dict_value(data, "x.y.z", default=-1)
        assert default == -1
        print(f"✓ Got value: {value}, default: {default}")
        test_results.append(("get_dict_value", True, None))
    except Exception as e:
        print(f"✗ Failed: {e}")
        test_results.append(("get_dict_value", False, str(e)))

    # Test 9: set_dict_value
    print("\n[Test 9] set_dict_value:")
    try:
        data = {}
        set_dict_value(data, "a.b.c", 1)
        assert data["a"]["b"]["c"] == 1
        print(f"✓ Set value: {data}")
        test_results.append(("set_dict_value", True, None))
    except Exception as e:
        print(f"✗ Failed: {e}")
        test_results.append(("set_dict_value", False, str(e)))

    # Test 10: safe_json_dumps
    print("\n[Test 10] safe_json_dumps:")
    try:
        data = {"key": "value", "number": 42}
        json_str = safe_json_dumps(data)
        assert isinstance(json_str, str)
        assert "key" in json_str
        print(f"✓ JSON: {json_str}")
        test_results.append(("safe_json_dumps", True, None))
    except Exception as e:
        print(f"✗ Failed: {e}")
        test_results.append(("safe_json_dumps", False, str(e)))

    # Test 11: parse_json
    print("\n[Test 11] parse_json:")
    try:
        json_str = '{"key": "value", "number": 42}'
        data = parse_json(json_str)
        assert data["key"] == "value"
        assert data["number"] == 42
        print(f"✓ Parsed: {data}")
        test_results.append(("parse_json", True, None))
    except Exception as e:
        print(f"✗ Failed: {e}")
        test_results.append(("parse_json", False, str(e)))

    # Test 12: is_valid_email
    print("\n[Test 12] is_valid_email:")
    try:
        assert is_valid_email("test@example.com") == True
        assert is_valid_email("invalid.email") == False
        print(f"✓ Email validation working")
        test_results.append(("is_valid_email", True, None))
    except Exception as e:
        print(f"✗ Failed: {e}")
        test_results.append(("is_valid_email", False, str(e)))

    # Test 13: is_valid_url
    print("\n[Test 13] is_valid_url:")
    try:
        assert is_valid_url("http://example.com") == True
        assert is_valid_url("not a url") == False
        print(f"✓ URL validation working")
        test_results.append(("is_valid_url", True, None))
    except Exception as e:
        print(f"✗ Failed: {e}")
        test_results.append(("is_valid_url", False, str(e)))

    # Test 14: is_valid_port
    print("\n[Test 14] is_valid_port:")
    try:
        assert is_valid_port(8000) == True
        assert is_valid_port(65535) == True
        assert is_valid_port(99999) == False
        assert is_valid_port(0) == False
        print(f"✓ Port validation working")
        test_results.append(("is_valid_port", True, None))
    except Exception as e:
        print(f"✗ Failed: {e}")
        test_results.append(("is_valid_port", False, str(e)))

    # Test 15: hash_string
    print("\n[Test 15] hash_string:")
    try:
        hash_val = hash_string("test")
        assert len(hash_val) == 64  # SHA256 produces 64 hex chars
        assert hash_string("test") == hash_string("test")
        assert hash_string("test") != hash_string("test2")
        print(f"✓ Hash: {hash_val}")
        test_results.append(("hash_string", True, None))
    except Exception as e:
        print(f"✗ Failed: {e}")
        test_results.append(("hash_string", False, str(e)))

    # Test 16: url_encode and url_decode
    print("\n[Test 16] url_encode/decode:")
    try:
        original = "hello world & special chars"
        encoded = url_encode(original)
        decoded = url_decode(encoded)
        assert decoded == original
        print(f"✓ Encoded: {encoded}, Decoded: {decoded}")
        test_results.append(("url_encode/decode", True, None))
    except Exception as e:
        print(f"✗ Failed: {e}")
        test_results.append(("url_encode/decode", False, str(e)))

    # Test 17: convert_to_bool
    print("\n[Test 17] convert_to_bool:")
    try:
        assert convert_to_bool("true") == True
        assert convert_to_bool("false") == False
        assert convert_to_bool("1") == True
        assert convert_to_bool("0") == False
        assert convert_to_bool(True) == True
        print(f"✓ Boolean conversion working")
        test_results.append(("convert_to_bool", True, None))
    except Exception as e:
        print(f"✗ Failed: {e}")
        test_results.append(("convert_to_bool", False, str(e)))

    # Test 18: convert_to_int
    print("\n[Test 18] convert_to_int:")
    try:
        assert convert_to_int("42") == 42
        assert convert_to_int("invalid", default=0) == 0
        assert convert_to_int(3.14) == 3
        print(f"✓ Integer conversion working")
        test_results.append(("convert_to_int", True, None))
    except Exception as e:
        print(f"✗ Failed: {e}")
        test_results.append(("convert_to_int", False, str(e)))

    # Test 19: normalize_whitespace
    print("\n[Test 19] normalize_whitespace:")
    try:
        messy = "  hello    world   \n  test  "
        clean = normalize_whitespace(messy)
        assert clean == "hello world test"
        print(f"✓ Whitespace normalized: '{clean}'")
        test_results.append(("normalize_whitespace", True, None))
    except Exception as e:
        print(f"✗ Failed: {e}")
        test_results.append(("normalize_whitespace", False, str(e)))

    # Test 20: datetime_to_iso_string
    print("\n[Test 20] datetime_to_iso_string:")
    try:
        dt = datetime(2024, 1, 15, 10, 30, 45)
        iso_str = datetime_to_iso_string(dt)
        assert iso_str == "2024-01-15T10:30:45Z"
        print(f"✓ ISO string: {iso_str}")
        test_results.append(("datetime_to_iso_string", True, None))
    except Exception as e:
        print(f"✗ Failed: {e}")
        test_results.append(("datetime_to_iso_string", False, str(e)))

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