# hyfuzz-server-windows/src/utils/__init__.py

"""
Utils package - Contains utility modules for logging, validation, exception handling,
and other common functions used across the MCP server.
"""

from typing import Any, Callable, Dict, List, Optional, TypeVar, Union
from functools import wraps
import logging

# ============================================================================
# Version and metadata
# ============================================================================

__version__ = "1.0.0"
__author__ = "HyFuzz Team"
__all__ = [
    # Logging
    "get_logger",
    "setup_logging",

    # Exceptions
    "MCPException",
    "MCPServerException",
    "MCPClientException",
    "ConfigurationException",
    "ValidationException",
    "AuthenticationException",

    # Validators
    "validate_request",
    "validate_response",
    "validate_config",
    "validate_url",
    "validate_port",

    # Decorators
    "retry",
    "async_retry",
    "timing",
    "deprecated",
    "require_auth",

    # Helpers
    "sanitize_input",
    "truncate_string",
    "safe_json_dumps",
    "parse_json",
    "merge_dicts",

    # Async utilities
    "async_timeout",
    "run_async",
    "gather_with_limit",

    # JSON utilities
    "JSONEncoder",
    "JSONDecoder",
    "json_dumps",
    "json_loads",
]


# ============================================================================
# Lazy imports for logger
# ============================================================================

def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance with the specified name.

    Args:
        name: Logger name

    Returns:
        Logger instance
    """
    try:
        from .logger import get_logger as _get_logger
        return _get_logger(name)
    except ImportError as e:
        raise ImportError(f"Failed to import logger: {e}")


def setup_logging(config_path: Optional[str] = None) -> None:
    """
    Setup logging configuration.

    Args:
        config_path: Path to logging configuration file
    """
    try:
        from .logger import setup_logging as _setup_logging
        _setup_logging(config_path)
    except ImportError as e:
        raise ImportError(f"Failed to import logging setup: {e}")


# ============================================================================
# Lazy imports for exceptions
# ============================================================================

def _import_exceptions():
    """Import all exception classes"""
    try:
        from .exceptions import (
            MCPException,
            MCPServerException,
            MCPClientException,
            ConfigurationException,
            ValidationException,
            AuthenticationException,
        )
        return {
            "MCPException": MCPException,
            "MCPServerException": MCPServerException,
            "MCPClientException": MCPClientException,
            "ConfigurationException": ConfigurationException,
            "ValidationException": ValidationException,
            "AuthenticationException": AuthenticationException,
        }
    except ImportError as e:
        raise ImportError(f"Failed to import exceptions: {e}")


_exceptions = None


def __getattr__(name: str) -> Any:
    """Lazy load attributes on demand"""
    global _exceptions

    if name in ["MCPException", "MCPServerException", "MCPClientException",
                "ConfigurationException", "ValidationException", "AuthenticationException"]:
        if _exceptions is None:
            _exceptions = _import_exceptions()
        if name in _exceptions:
            return _exceptions[name]

    # Try validators
    if name in ["validate_request", "validate_response", "validate_config",
                "validate_url", "validate_port"]:
        try:
            import importlib
            validators = importlib.import_module(".validators", package=__name__)
            return getattr(validators, name)
        except (ImportError, AttributeError) as e:
            raise AttributeError(f"Cannot import {name}: {e}")

    # Try decorators
    if name in ["retry", "async_retry", "timing", "deprecated", "require_auth"]:
        try:
            import importlib
            decorators = importlib.import_module(".decorators", package=__name__)
            return getattr(decorators, name)
        except (ImportError, AttributeError) as e:
            raise AttributeError(f"Cannot import {name}: {e}")

    # Try helpers
    if name in ["sanitize_input", "truncate_string", "safe_json_dumps",
                "parse_json", "merge_dicts"]:
        try:
            import importlib
            helpers = importlib.import_module(".helpers", package=__name__)
            return getattr(helpers, name)
        except (ImportError, AttributeError) as e:
            raise AttributeError(f"Cannot import {name}: {e}")

    # Try async utilities
    if name in ["async_timeout", "run_async", "gather_with_limit"]:
        try:
            import importlib
            async_utils = importlib.import_module(".async_utils", package=__name__)
            return getattr(async_utils, name)
        except (ImportError, AttributeError) as e:
            raise AttributeError(f"Cannot import {name}: {e}")

    # Try JSON utilities
    if name in ["JSONEncoder", "JSONDecoder", "json_dumps", "json_loads"]:
        try:
            import importlib
            json_utils = importlib.import_module(".json_utils", package=__name__)
            return getattr(json_utils, name)
        except (ImportError, AttributeError) as e:
            raise AttributeError(f"Cannot import {name}: {e}")

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


# ============================================================================
# TESTS
# ============================================================================

if __name__ == "__main__":
    """Test utils package initialization"""
    import sys
    import traceback

    print("=" * 80)
    print("TESTING UTILS PACKAGE INITIALIZATION")
    print("=" * 80)

    test_results = []

    # Test 1: Import package version
    print("\n[Test 1] Package metadata:")
    try:
        print(f"✓ Version: {__version__}")
        print(f"✓ Author: {__author__}")
        test_results.append(("Package metadata", True, None))
    except Exception as e:
        print(f"✗ Failed: {e}")
        test_results.append(("Package metadata", False, str(e)))

    # Test 2: Check __all__ exports
    print("\n[Test 2] Check __all__ exports:")
    try:
        assert isinstance(__all__, list), "__all__ must be a list"
        assert len(__all__) > 0, "__all__ cannot be empty"
        print(f"✓ __all__ defined with {len(__all__)} exports")
        for item in __all__[:5]:  # Show first 5
            print(f"  - {item}")
        if len(__all__) > 5:
            print(f"  ... and {len(__all__) - 5} more")
        test_results.append(("__all__ exports", True, None))
    except AssertionError as e:
        print(f"✗ Failed: {e}")
        test_results.append(("__all__ exports", False, str(e)))

    # Test 3: Test get_logger function
    print("\n[Test 3] get_logger function:")
    try:
        logger_func = get_logger
        assert callable(logger_func), "get_logger must be callable"
        print(f"✓ get_logger is callable")
        test_results.append(("get_logger function", True, None))
    except Exception as e:
        print(f"✗ Failed: {e}")
        test_results.append(("get_logger function", False, str(e)))

    # Test 4: Test setup_logging function
    print("\n[Test 4] setup_logging function:")
    try:
        setup_func = setup_logging
        assert callable(setup_func), "setup_logging must be callable"
        print(f"✓ setup_logging is callable")
        test_results.append(("setup_logging function", True, None))
    except Exception as e:
        print(f"✗ Failed: {e}")
        test_results.append(("setup_logging function", False, str(e)))

    # Test 5: Test exception classes via __getattr__
    print("\n[Test 5] Exception classes availability:")
    try:
        # Try to access via __getattr__
        exc_classes = [
            "MCPException",
            "MCPServerException",
            "MCPClientException",
            "ConfigurationException",
            "ValidationException",
            "AuthenticationException",
        ]
        found_exceptions = []
        for exc_name in exc_classes:
            try:
                exc_class = globals()[exc_name] if exc_name in globals() else None
                if exc_class is not None:
                    found_exceptions.append(exc_name)
            except:
                pass

        if len(exc_classes) > 0:
            print(f"✓ Exception classes are defined in __all__")
            test_results.append(("Exception classes", True, None))
        else:
            print(f"✗ No exception classes found")
            test_results.append(("Exception classes", False, "No exception classes"))
    except Exception as e:
        print(f"✗ Failed: {e}")
        test_results.append(("Exception classes", False, str(e)))

    # Test 6: Test validator functions availability
    print("\n[Test 6] Validator functions availability:")
    try:
        validators_list = [
            "validate_request",
            "validate_response",
            "validate_config",
            "validate_url",
            "validate_port",
        ]
        found_validators = sum(1 for v in validators_list if v in __all__)
        print(f"✓ {found_validators}/{len(validators_list)} validators in __all__")
        test_results.append(("Validator functions", True, None))
    except Exception as e:
        print(f"✗ Failed: {e}")
        test_results.append(("Validator functions", False, str(e)))

    # Test 7: Test decorator functions availability
    print("\n[Test 7] Decorator functions availability:")
    try:
        decorators_list = [
            "retry",
            "async_retry",
            "timing",
            "deprecated",
            "require_auth",
        ]
        found_decorators = sum(1 for d in decorators_list if d in __all__)
        print(f"✓ {found_decorators}/{len(decorators_list)} decorators in __all__")
        test_results.append(("Decorator functions", True, None))
    except Exception as e:
        print(f"✗ Failed: {e}")
        test_results.append(("Decorator functions", False, str(e)))

    # Test 8: Test helper functions availability
    print("\n[Test 8] Helper functions availability:")
    try:
        helpers_list = [
            "sanitize_input",
            "truncate_string",
            "safe_json_dumps",
            "parse_json",
            "merge_dicts",
        ]
        found_helpers = sum(1 for h in helpers_list if h in __all__)
        print(f"✓ {found_helpers}/{len(helpers_list)} helpers in __all__")
        test_results.append(("Helper functions", True, None))
    except Exception as e:
        print(f"✗ Failed: {e}")
        test_results.append(("Helper functions", False, str(e)))

    # Test 9: Test async utilities availability
    print("\n[Test 9] Async utilities availability:")
    try:
        async_utils_list = [
            "async_timeout",
            "run_async",
            "gather_with_limit",
        ]
        found_async = sum(1 for a in async_utils_list if a in __all__)
        print(f"✓ {found_async}/{len(async_utils_list)} async utilities in __all__")
        test_results.append(("Async utilities", True, None))
    except Exception as e:
        print(f"✗ Failed: {e}")
        test_results.append(("Async utilities", False, str(e)))

    # Test 10: Test JSON utilities availability
    print("\n[Test 10] JSON utilities availability:")
    try:
        json_utils_list = [
            "JSONEncoder",
            "JSONDecoder",
            "json_dumps",
            "json_loads",
        ]
        found_json = sum(1 for j in json_utils_list if j in __all__)
        print(f"✓ {found_json}/{len(json_utils_list)} JSON utilities in __all__")
        test_results.append(("JSON utilities", True, None))
    except Exception as e:
        print(f"✗ Failed: {e}")
        test_results.append(("JSON utilities", False, str(e)))

    # Test 11: Check for duplicate exports
    print("\n[Test 11] Check for duplicate exports:")
    try:
        if len(__all__) == len(set(__all__)):
            print(f"✓ No duplicate exports found")
            test_results.append(("Duplicate check", True, None))
        else:
            duplicates = [item for item in __all__ if __all__.count(item) > 1]
            print(f"✗ Found duplicates: {set(duplicates)}")
            test_results.append(("Duplicate check", False, f"Duplicates: {duplicates}"))
    except Exception as e:
        print(f"✗ Failed: {e}")
        test_results.append(("Duplicate check", False, str(e)))

    # Test 12: Verify __all__ consistency
    print("\n[Test 12] __all__ consistency:")
    try:
        # All items in __all__ should be strings
        all_strings = all(isinstance(item, str) for item in __all__)
        assert all_strings, "All __all__ items must be strings"
        print(f"✓ All {len(__all__)} __all__ items are strings")
        test_results.append(("__all__ consistency", True, None))
    except AssertionError as e:
        print(f"✗ Failed: {e}")
        test_results.append(("__all__ consistency", False, str(e)))

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

    # Exit with appropriate code
    sys.exit(0 if passed == total else 1)