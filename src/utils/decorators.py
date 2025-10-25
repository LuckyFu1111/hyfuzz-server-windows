# hyfuzz-server-windows/src/utils/decorators.py

"""
Decorators - Provides utility decorators for logging, retrying, performance monitoring,
deprecation warnings, and authentication requirements.
"""

import asyncio
import functools
import inspect
import logging
import time
import warnings
from typing import Any, Awaitable, Callable, Optional, TypeVar, Union

# Type variables
F = TypeVar('F', bound=Callable[..., Any])
T = TypeVar('T')

logger = logging.getLogger(__name__)


# ============================================================================
# Retry Decorators
# ============================================================================

def retry(
        max_attempts: int = 3,
        delay: float = 1.0,
        backoff: float = 2.0,
        exceptions: tuple = (Exception,)
):
    """
    Retry decorator for synchronous functions with exponential backoff.

    Args:
        max_attempts: Maximum number of attempts
        delay: Initial delay in seconds between retries
        backoff: Backoff multiplier for exponential backoff
        exceptions: Tuple of exception types to catch and retry

    Returns:
        Decorated function

    Example:
        @retry(max_attempts=3, delay=1.0)
        def flaky_operation():
            # May fail intermittently
            pass
    """

    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            current_delay = delay
            last_exception = None

            for attempt in range(max_attempts):
                try:
                    result = func(*args, **kwargs)
                    if attempt > 0:
                        logger.info(
                            f"{func.__name__} succeeded after {attempt} retries"
                        )
                    return result
                except exceptions as e:
                    last_exception = e
                    if attempt < max_attempts - 1:
                        logger.warning(
                            f"{func.__name__} attempt {attempt + 1} failed: {e}. "
                            f"Retrying in {current_delay}s..."
                        )
                        time.sleep(current_delay)
                        current_delay *= backoff
                    else:
                        logger.error(
                            f"{func.__name__} failed after {max_attempts} attempts"
                        )

            raise last_exception

        return wrapper

    return decorator


def async_retry(
        max_attempts: int = 3,
        delay: float = 1.0,
        backoff: float = 2.0,
        exceptions: tuple = (Exception,)
):
    """
    Retry decorator for async functions with exponential backoff.

    Args:
        max_attempts: Maximum number of attempts
        delay: Initial delay in seconds between retries
        backoff: Backoff multiplier for exponential backoff
        exceptions: Tuple of exception types to catch and retry

    Returns:
        Decorated async function

    Example:
        @async_retry(max_attempts=3, delay=1.0)
        async def flaky_async_operation():
            # May fail intermittently
            pass
    """

    def decorator(func: F) -> F:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            current_delay = delay
            last_exception = None

            for attempt in range(max_attempts):
                try:
                    result = await func(*args, **kwargs)
                    if attempt > 0:
                        logger.info(
                            f"{func.__name__} succeeded after {attempt} retries"
                        )
                    return result
                except exceptions as e:
                    last_exception = e
                    if attempt < max_attempts - 1:
                        logger.warning(
                            f"{func.__name__} attempt {attempt + 1} failed: {e}. "
                            f"Retrying in {current_delay}s..."
                        )
                        await asyncio.sleep(current_delay)
                        current_delay *= backoff
                    else:
                        logger.error(
                            f"{func.__name__} failed after {max_attempts} attempts"
                        )

            raise last_exception

        return wrapper

    return decorator


# ============================================================================
# Timing and Performance Decorators
# ============================================================================

def timing(func: F) -> F:
    """
    Decorator to measure function execution time.

    Args:
        func: Function to measure

    Returns:
        Decorated function

    Example:
        @timing
        def slow_operation():
            time.sleep(1)
    """

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        try:
            result = func(*args, **kwargs)
            return result
        finally:
            end_time = time.time()
            duration_ms = (end_time - start_time) * 1000
            logger.debug(
                f"{func.__name__} took {duration_ms:.2f}ms to execute"
            )

    return wrapper


def async_timing(func: F) -> F:
    """
    Decorator to measure async function execution time.

    Args:
        func: Async function to measure

    Returns:
        Decorated async function
    """

    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        start_time = time.time()
        try:
            result = await func(*args, **kwargs)
            return result
        finally:
            end_time = time.time()
            duration_ms = (end_time - start_time) * 1000
            logger.debug(
                f"{func.__name__} took {duration_ms:.2f}ms to execute"
            )

    return wrapper


# ============================================================================
# Deprecation Decorators
# ============================================================================

def deprecated(
        reason: str = "",
        alternative: Optional[str] = None,
        version: Optional[str] = None
):
    """
    Decorator to mark functions as deprecated.

    Args:
        reason: Reason for deprecation
        alternative: Suggested alternative function
        version: Version when deprecated

    Returns:
        Decorated function

    Example:
        @deprecated(reason="Use new_function instead", version="2.0")
        def old_function():
            pass
    """

    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            message = f"{func.__name__} is deprecated"
            if version:
                message += f" since version {version}"
            if reason:
                message += f": {reason}"
            if alternative:
                message += f". Use {alternative} instead"

            warnings.warn(message, category=DeprecationWarning, stacklevel=2)
            logger.warning(message)

            return func(*args, **kwargs)

        return wrapper

    return decorator


def deprecated_async(
        reason: str = "",
        alternative: Optional[str] = None,
        version: Optional[str] = None
):
    """
    Decorator to mark async functions as deprecated.

    Args:
        reason: Reason for deprecation
        alternative: Suggested alternative function
        version: Version when deprecated

    Returns:
        Decorated async function
    """

    def decorator(func: F) -> F:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            message = f"{func.__name__} is deprecated"
            if version:
                message += f" since version {version}"
            if reason:
                message += f": {reason}"
            if alternative:
                message += f". Use {alternative} instead"

            warnings.warn(message, category=DeprecationWarning, stacklevel=2)
            logger.warning(message)

            return await func(*args, **kwargs)

        return wrapper

    return decorator


# ============================================================================
# Authentication and Authorization Decorators
# ============================================================================

class AuthenticationError(Exception):
    """Raised when authentication fails"""
    pass


class AuthorizationError(Exception):
    """Raised when authorization fails"""
    pass


def require_auth(auth_func: Callable[[Any], bool]):
    """
    Decorator to require authentication before function execution.

    Args:
        auth_func: Function that returns True if authenticated

    Returns:
        Decorated function

    Raises:
        AuthenticationError: If authentication fails

    Example:
        def check_token(request):
            return request.headers.get('Authorization') is not None

        @require_auth(check_token)
        def protected_endpoint(request):
            pass
    """

    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Try to get request object from args or kwargs
            request = None
            if args:
                request = args[0]
            elif 'request' in kwargs:
                request = kwargs['request']

            if auth_func(request):
                logger.debug(f"Authentication passed for {func.__name__}")
                return func(*args, **kwargs)
            else:
                logger.error(f"Authentication failed for {func.__name__}")
                raise AuthenticationError("Authentication required")

        return wrapper

    return decorator


def require_auth_async(auth_func: Callable[[Any], Union[bool, Awaitable[bool]]]):
    """
    Decorator to require authentication before async function execution.

    Args:
        auth_func: Async function or callable that returns True if authenticated

    Returns:
        Decorated async function

    Raises:
        AuthenticationError: If authentication fails
    """

    def decorator(func: F) -> F:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            # Try to get request object from args or kwargs
            request = None
            if args:
                request = args[0]
            elif 'request' in kwargs:
                request = kwargs['request']

            # Check if auth_func is async
            if asyncio.iscoroutinefunction(auth_func):
                auth_result = await auth_func(request)
            else:
                auth_result = auth_func(request)

            if auth_result:
                logger.debug(f"Authentication passed for {func.__name__}")
                return await func(*args, **kwargs)
            else:
                logger.error(f"Authentication failed for {func.__name__}")
                raise AuthenticationError("Authentication required")

        return wrapper

    return decorator


def require_permission(permission: str, permissions_func: Callable[[Any], list]):
    """
    Decorator to require specific permission.

    Args:
        permission: Required permission
        permissions_func: Function that returns list of user permissions

    Returns:
        Decorated function

    Raises:
        AuthorizationError: If permission check fails

    Example:
        def get_permissions(request):
            return request.user.permissions

        @require_permission('admin', get_permissions)
        def admin_endpoint(request):
            pass
    """

    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            request = None
            if args:
                request = args[0]
            elif 'request' in kwargs:
                request = kwargs['request']

            try:
                user_permissions = permissions_func(request)
                if permission in user_permissions:
                    logger.debug(
                        f"Permission '{permission}' granted for {func.__name__}"
                    )
                    return func(*args, **kwargs)
                else:
                    logger.error(
                        f"Permission '{permission}' denied for {func.__name__}"
                    )
                    raise AuthorizationError(
                        f"Permission '{permission}' required"
                    )
            except Exception as e:
                logger.error(f"Permission check failed: {e}")
                raise AuthorizationError(f"Permission check failed: {e}")

        return wrapper

    return decorator


# ============================================================================
# Logging Decorators
# ============================================================================

def log_calls(log_args: bool = True, log_result: bool = True):
    """
    Decorator to log function calls with arguments and results.

    Args:
        log_args: Whether to log function arguments
        log_result: Whether to log function result

    Returns:
        Decorated function

    Example:
        @log_calls(log_args=True, log_result=True)
        def process_data(data):
            return len(data)
    """

    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if log_args:
                logger.debug(
                    f"Calling {func.__name__}() with args={args}, kwargs={kwargs}"
                )

            result = func(*args, **kwargs)

            if log_result:
                logger.debug(f"{func.__name__}() returned {result}")

            return result

        return wrapper

    return decorator


def log_calls_async(log_args: bool = True, log_result: bool = True):
    """
    Decorator to log async function calls with arguments and results.

    Args:
        log_args: Whether to log function arguments
        log_result: Whether to log function result

    Returns:
        Decorated async function
    """

    def decorator(func: F) -> F:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            if log_args:
                logger.debug(
                    f"Calling {func.__name__}() with args={args}, kwargs={kwargs}"
                )

            result = await func(*args, **kwargs)

            if log_result:
                logger.debug(f"{func.__name__}() returned {result}")

            return result

        return wrapper

    return decorator


# ============================================================================
# Caching Decorators
# ============================================================================

def memoize(maxsize: int = 128):
    """
    Decorator to cache function results.

    Args:
        maxsize: Maximum cache size

    Returns:
        Decorated function

    Example:
        @memoize(maxsize=256)
        def expensive_computation(x):
            return x ** 2
    """

    def decorator(func: F) -> F:
        cache = {}
        cache_hits = [0]  # Use list to allow modification in nested function
        cache_misses = [0]  # Use list to allow modification in nested function

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Create cache key from args and kwargs
            cache_key = (args, tuple(sorted(kwargs.items())))

            if cache_key in cache:
                cache_hits[0] += 1
                logger.debug(
                    f"{func.__name__} cache hit (hits: {cache_hits[0]}, misses: {cache_misses[0]})"
                )
                return cache[cache_key]
            else:
                cache_misses[0] += 1
                result = func(*args, **kwargs)

                # Maintain maxsize
                if len(cache) >= maxsize:
                    oldest_key = next(iter(cache))
                    del cache[oldest_key]

                cache[cache_key] = result
                return result

        # Add cache introspection methods
        wrapper.cache_info = lambda: {
            "hits": cache_hits[0],
            "misses": cache_misses[0],
            "size": len(cache),
            "maxsize": maxsize,
        }
        wrapper.cache_clear = lambda: cache.clear()

        return wrapper

    return decorator


# ============================================================================
# Error Handling Decorators
# ============================================================================

def handle_errors(
        default_return: Any = None,
        log_traceback: bool = True
):
    """
    Decorator to handle exceptions and return default value.

    Args:
        default_return: Value to return if exception occurs
        log_traceback: Whether to log full traceback

    Returns:
        Decorated function

    Example:
        @handle_errors(default_return={}, log_traceback=True)
        def risky_operation():
            pass
    """

    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                if log_traceback:
                    logger.exception(
                        f"Error in {func.__name__}: {e}"
                    )
                else:
                    logger.error(
                        f"Error in {func.__name__}: {e}"
                    )
                return default_return

        return wrapper

    return decorator


# ============================================================================
# TESTS
# ============================================================================

if __name__ == "__main__":
    """Test decorators"""
    import sys

    print("=" * 80)
    print("TESTING DECORATORS")
    print("=" * 80)

    test_results = []

    # Test 1: retry decorator
    print("\n[Test 1] @retry decorator:")
    try:
        attempt_count = [0]  # Use list to allow modification in nested function


        @retry(max_attempts=3, delay=0.05, backoff=1.0)
        def flaky_function():
            attempt_count[0] += 1
            if attempt_count[0] < 3:
                raise ValueError("Temporary failure")
            return "success"


        result = flaky_function()
        assert result == "success" and attempt_count[0] == 3
        print(f"✓ Retry succeeded after {attempt_count[0]} attempts")
        test_results.append(("@retry", True, None))
    except Exception as e:
        print(f"✗ Failed: {e}")
        test_results.append(("@retry", False, str(e)))

    # Test 2: timing decorator
    print("\n[Test 2] @timing decorator:")
    try:
        @timing
        def slow_function():
            time.sleep(0.1)
            return "done"


        result = slow_function()
        assert result == "done"
        print(f"✓ Function timed and executed successfully")
        test_results.append(("@timing", True, None))
    except Exception as e:
        print(f"✗ Failed: {e}")
        test_results.append(("@timing", False, str(e)))

    # Test 3: deprecated decorator
    print("\n[Test 3] @deprecated decorator:")
    try:
        @deprecated(reason="Use new_func instead", version="2.0")
        def old_function():
            return "old"


        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = old_function()
            assert result == "old"
            assert len(w) == 1
            assert issubclass(w[0].category, DeprecationWarning)

        print(f"✓ Deprecation warning raised correctly")
        test_results.append(("@deprecated", True, None))
    except Exception as e:
        print(f"✗ Failed: {e}")
        test_results.append(("@deprecated", False, str(e)))

    # Test 4: require_auth decorator
    print("\n[Test 4] @require_auth decorator:")
    try:
        def mock_auth(request):
            return request is not None and hasattr(request, 'token')


        @require_auth(mock_auth)
        def protected_function(request):
            return "protected"


        class MockRequest:
            token = "abc123"


        result = protected_function(MockRequest())
        assert result == "protected"
        print(f"✓ Authentication passed")
        test_results.append(("@require_auth", True, None))
    except Exception as e:
        print(f"✗ Failed: {e}")
        test_results.append(("@require_auth", False, str(e)))

    # Test 5: require_auth decorator with failure
    print("\n[Test 5] @require_auth with failure:")
    try:
        def mock_auth(request):
            return False


        @require_auth(mock_auth)
        def protected_function(request):
            return "protected"


        try:
            protected_function(None)
            print(f"✗ Should have raised AuthenticationError")
            test_results.append(("@require_auth failure", False, "No exception raised"))
        except AuthenticationError:
            print(f"✓ Correctly raised AuthenticationError")
            test_results.append(("@require_auth failure", True, None))
    except Exception as e:
        print(f"✗ Failed: {e}")
        test_results.append(("@require_auth failure", False, str(e)))

    # Test 6: log_calls decorator
    print("\n[Test 6] @log_calls decorator:")
    try:
        @log_calls(log_args=True, log_result=True)
        def add(a, b):
            return a + b


        result = add(5, 3)
        assert result == 8
        print(f"✓ Function logged and executed: {result}")
        test_results.append(("@log_calls", True, None))
    except Exception as e:
        print(f"✗ Failed: {e}")
        test_results.append(("@log_calls", False, str(e)))

    # Test 7: memoize decorator
    print("\n[Test 7] @memoize decorator:")
    try:
        call_count = [0]  # Use list to allow modification in nested function


        @memoize(maxsize=10)
        def expensive_func(x):
            call_count[0] += 1
            return x * 2


        result1 = expensive_func(5)
        result2 = expensive_func(5)  # Should use cache
        result3 = expensive_func(10)

        assert result1 == 10 and result2 == 10 and result3 == 20
        assert call_count[0] == 2  # Only called twice (cache hit on second call)

        cache_info = expensive_func.cache_info()
        print(f"✓ Memoization working: {cache_info}")
        test_results.append(("@memoize", True, None))
    except Exception as e:
        print(f"✗ Failed: {e}")
        test_results.append(("@memoize", False, str(e)))

    # Test 8: handle_errors decorator
    print("\n[Test 8] @handle_errors decorator:")
    try:
        @handle_errors(default_return="error_handled")
        def risky_function():
            raise ValueError("Something went wrong")


        result = risky_function()
        assert result == "error_handled"
        print(f"✓ Error handled and default returned: {result}")
        test_results.append(("@handle_errors", True, None))
    except Exception as e:
        print(f"✗ Failed: {e}")
        test_results.append(("@handle_errors", False, str(e)))

    # Test 9: require_permission decorator
    print("\n[Test 9] @require_permission decorator:")
    try:
        def get_permissions(request):
            return request.permissions if request else []


        @require_permission('admin', get_permissions)
        def admin_function(request):
            return "admin_access"


        class MockUser:
            permissions = ['admin', 'user']


        result = admin_function(MockUser())
        assert result == "admin_access"
        print(f"✓ Permission check passed")
        test_results.append(("@require_permission", True, None))
    except Exception as e:
        print(f"✗ Failed: {e}")
        test_results.append(("@require_permission", False, str(e)))

    # Test 10: require_permission decorator with failure
    print("\n[Test 10] @require_permission with failure:")
    try:
        def get_permissions(request):
            return request.permissions if request else []


        @require_permission('admin', get_permissions)
        def admin_function(request):
            return "admin_access"


        class MockUser:
            permissions = ['user']


        try:
            admin_function(MockUser())
            print(f"✗ Should have raised AuthorizationError")
            test_results.append(("@require_permission failure", False, "No exception raised"))
        except AuthorizationError:
            print(f"✓ Correctly raised AuthorizationError")
            test_results.append(("@require_permission failure", True, None))
    except Exception as e:
        print(f"✗ Failed: {e}")
        test_results.append(("@require_permission failure", False, str(e)))

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