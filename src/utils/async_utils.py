# hyfuzz-server-windows/src/utils/async_utils.py

"""
Async utilities - Provides helper functions for asynchronous programming,
including timeout handling, concurrent task management, and event loop utilities.
"""

import asyncio
import logging
import sys
import time
from contextlib import asynccontextmanager
from functools import wraps
from typing import Any, Awaitable, Callable, List, Optional, TypeVar, Union

# Type variables
T = TypeVar('T')
P = TypeVar('P')

logger = logging.getLogger(__name__)


# ============================================================================
# Timeout Management
# ============================================================================

class AsyncTimeoutError(Exception):
    """Raised when an async operation times out"""
    pass


@asynccontextmanager
async def async_timeout(seconds: float):
    """
    Context manager for async timeout handling.

    Args:
        seconds: Timeout duration in seconds

    Raises:
        AsyncTimeoutError: If operation exceeds timeout

    Example:
        async with async_timeout(5.0):
            await some_async_operation()
    """
    task = asyncio.current_task()
    timer_handle = None

    def timeout_callback():
        if task:
            task.cancel()

    try:
        timer_handle = asyncio.get_event_loop().call_later(
            seconds, timeout_callback
        )
        yield
    except asyncio.CancelledError:
        raise AsyncTimeoutError(f"Operation timed out after {seconds} seconds")
    finally:
        if timer_handle:
            timer_handle.cancel()


async def wait_with_timeout(
        coro: Awaitable[T],
        timeout: float,
        raise_on_timeout: bool = True
) -> Optional[T]:
    """
    Wait for a coroutine with timeout.

    Args:
        coro: Coroutine to await
        timeout: Timeout in seconds
        raise_on_timeout: Whether to raise exception on timeout

    Returns:
        Result of coroutine or None if timed out

    Raises:
        AsyncTimeoutError: If raise_on_timeout is True and timeout occurs
    """
    try:
        return await asyncio.wait_for(coro, timeout=timeout)
    except asyncio.TimeoutError:
        if raise_on_timeout:
            raise AsyncTimeoutError(f"Operation timed out after {timeout} seconds")
        logger.warning(f"Operation timed out after {timeout} seconds")
        return None


# ============================================================================
# Event Loop Management
# ============================================================================

def get_or_create_event_loop() -> asyncio.AbstractEventLoop:
    """
    Get the current event loop or create one if it doesn't exist.

    Returns:
        Event loop instance
    """
    try:
        loop = asyncio.get_running_loop()
        return loop
    except RuntimeError:
        # No running loop in current thread
        try:
            loop = asyncio.get_event_loop()
            if loop.is_closed():
                raise RuntimeError("Event loop is closed")
            return loop
        except RuntimeError:
            # Create new event loop
            if sys.platform == 'win32':
                # Windows requires ProactorEventLoop for subprocess
                loop = asyncio.ProactorEventLoop()
            else:
                loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            return loop


def run_async(coro: Awaitable[T]) -> T:
    """
    Run an async coroutine from synchronous code.

    Args:
        coro: Coroutine to run

    Returns:
        Result of coroutine

    Example:
        result = run_async(async_function())
    """
    try:
        loop = asyncio.get_running_loop()
        # Already in async context, cannot use run_until_complete
        raise RuntimeError(
            "run_async() cannot be called from within an async context. "
            "Use 'await' instead."
        )
    except RuntimeError:
        pass

    loop = get_or_create_event_loop()
    try:
        return loop.run_until_complete(coro)
    except Exception as e:
        logger.error(f"Error running async coroutine: {e}")
        raise


# ============================================================================
# Concurrent Task Management
# ============================================================================

class ConcurrentLimiter:
    """Manages concurrent execution of tasks with a limit"""

    def __init__(self, max_concurrent: int):
        """
        Initialize the limiter.

        Args:
            max_concurrent: Maximum number of concurrent tasks
        """
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.active_tasks = 0
        self.max_concurrent = max_concurrent

    async def acquire(self):
        """Acquire a slot for task execution"""
        await self.semaphore.acquire()
        self.active_tasks += 1

    def release(self):
        """Release a slot for task execution"""
        self.semaphore.release()
        self.active_tasks -= 1

    @asynccontextmanager
    async def limit(self):
        """Context manager for limiting concurrent access"""
        await self.acquire()
        try:
            yield
        finally:
            self.release()

    def get_active_count(self) -> int:
        """Get number of active tasks"""
        return self.active_tasks


async def gather_with_limit(
        *coros: Awaitable[T],
        max_concurrent: int = 5,
        return_exceptions: bool = False
) -> List[T]:
    """
    Execute multiple coroutines with a limit on concurrent execution.

    Args:
        *coros: Coroutines to execute
        max_concurrent: Maximum number of concurrent tasks
        return_exceptions: Whether to return exceptions instead of raising

    Returns:
        List of results

    Example:
        results = await gather_with_limit(
            async_func1(),
            async_func2(),
            async_func3(),
            max_concurrent=2
        )
    """
    limiter = ConcurrentLimiter(max_concurrent)

    async def run_limited(coro):
        async with limiter.limit():
            return await coro

    tasks = [run_limited(coro) for coro in coros]
    return await asyncio.gather(*tasks, return_exceptions=return_exceptions)


async def batch_async_tasks(
        tasks: List[Awaitable[T]],
        batch_size: int,
        delay_between_batches: float = 0.0
) -> List[T]:
    """
    Execute async tasks in batches.

    Args:
        tasks: List of coroutines to execute
        batch_size: Number of tasks per batch
        delay_between_batches: Delay in seconds between batches

    Returns:
        List of results in order
    """
    results = []

    for i in range(0, len(tasks), batch_size):
        batch = tasks[i:i + batch_size]
        logger.debug(f"Executing batch {i // batch_size + 1} with {len(batch)} tasks")

        batch_results = await asyncio.gather(*batch, return_exceptions=True)
        results.extend(batch_results)

        if delay_between_batches > 0 and i + batch_size < len(tasks):
            await asyncio.sleep(delay_between_batches)

    return results


# ============================================================================
# Task Scheduling and Retries
# ============================================================================

async def retry_async(
        coro_func: Callable[..., Awaitable[T]],
        *args,
        max_retries: int = 3,
        delay: float = 1.0,
        backoff: float = 2.0,
        **kwargs
) -> T:
    """
    Retry an async function with exponential backoff.

    Args:
        coro_func: Async function to retry
        *args: Positional arguments for function
        max_retries: Maximum number of retries
        delay: Initial delay in seconds between retries
        backoff: Backoff multiplier for exponential backoff
        **kwargs: Keyword arguments for function

    Returns:
        Result of function call

    Raises:
        Exception: Last exception if all retries fail
    """
    current_delay = delay
    last_exception = None

    for attempt in range(max_retries + 1):
        try:
            result = await coro_func(*args, **kwargs)
            if attempt > 0:
                logger.info(f"Successfully completed after {attempt} retries")
            return result
        except Exception as e:
            last_exception = e
            if attempt < max_retries:
                logger.warning(
                    f"Attempt {attempt + 1} failed: {e}. "
                    f"Retrying in {current_delay}s..."
                )
                await asyncio.sleep(current_delay)
                current_delay *= backoff
            else:
                logger.error(f"All {max_retries + 1} attempts failed")

    raise last_exception


async def timeout_and_retry(
        coro_func: Callable[..., Awaitable[T]],
        *args,
        timeout: float = 5.0,
        max_retries: int = 3,
        **kwargs
) -> T:
    """
    Execute async function with timeout and retry logic.

    Args:
        coro_func: Async function to execute
        *args: Positional arguments
        timeout: Timeout in seconds for each attempt
        max_retries: Maximum retries
        **kwargs: Keyword arguments

    Returns:
        Result of function call
    """

    async def with_timeout(*a, **kw):
        return await wait_with_timeout(
            coro_func(*a, **kw),
            timeout,
            raise_on_timeout=True
        )

    return await retry_async(
        with_timeout,
        *args,
        max_retries=max_retries,
        **kwargs
    )


# ============================================================================
# Task Monitoring and Control
# ============================================================================

class TaskMonitor:
    """Monitor and control async tasks"""

    def __init__(self):
        """Initialize task monitor"""
        self.tasks: List[asyncio.Task] = []
        self.completed = 0
        self.failed = 0

    def create_task(self, coro: Awaitable[T]) -> asyncio.Task[T]:
        """Create and track a task"""
        task = asyncio.create_task(coro)
        self.tasks.append(task)
        return task

    async def wait_all(self, timeout: Optional[float] = None) -> None:
        """Wait for all tasks to complete"""
        if not self.tasks:
            return

        try:
            await asyncio.wait_for(
                asyncio.gather(*self.tasks, return_exceptions=True),
                timeout=timeout
            )
        except asyncio.TimeoutError:
            logger.warning(f"Task timeout after {timeout}s, cancelling remaining tasks")
            self.cancel_all()
        finally:
            self.update_stats()

    def cancel_all(self) -> None:
        """Cancel all pending tasks"""
        for task in self.tasks:
            if not task.done():
                task.cancel()

    def update_stats(self) -> None:
        """Update task statistics"""
        self.completed = sum(1 for t in self.tasks if t.done() and not t.cancelled())
        self.failed = sum(1 for t in self.tasks if t.done() and t.exception())

    def get_stats(self) -> dict:
        """Get task statistics"""
        self.update_stats()
        return {
            "total": len(self.tasks),
            "completed": self.completed,
            "failed": self.failed,
            "pending": len(self.tasks) - self.completed,
        }


async def schedule_periodic(
        func: Callable[..., Awaitable[None]],
        interval: float,
        *args,
        max_iterations: Optional[int] = None,
        **kwargs
) -> None:
    """
    Schedule a function to run periodically.

    Args:
        func: Async function to schedule
        interval: Interval in seconds
        *args: Positional arguments
        max_iterations: Maximum number of iterations (None for infinite)
        **kwargs: Keyword arguments
    """
    iteration = 0

    try:
        while max_iterations is None or iteration < max_iterations:
            try:
                await func(*args, **kwargs)
            except Exception as e:
                logger.error(f"Error in periodic task: {e}")

            iteration += 1
            await asyncio.sleep(interval)
    except asyncio.CancelledError:
        logger.info("Periodic task cancelled")
        raise


# ============================================================================
# TESTS
# ============================================================================

async def _test_async_timeout():
    """Test async timeout"""
    print("\n[Test 1] async_timeout context manager:")
    try:
        async with async_timeout(0.5):
            await asyncio.sleep(1.0)
        print("✗ Should have timed out")
        return False
    except AsyncTimeoutError:
        print("✓ Correctly raised AsyncTimeoutError")
        return True


async def _test_wait_with_timeout():
    """Test wait_with_timeout"""
    print("\n[Test 2] wait_with_timeout:")

    async def quick_task():
        await asyncio.sleep(0.1)
        return "success"

    result = await wait_with_timeout(quick_task(), timeout=1.0)
    if result == "success":
        print("✓ Successfully completed within timeout")
        return True
    else:
        print("✗ Failed to get expected result")
        return False


async def _test_gather_with_limit():
    """Test gather_with_limit"""
    print("\n[Test 3] gather_with_limit:")

    async def worker(n):
        await asyncio.sleep(0.1)
        return n * 2

    tasks = [worker(i) for i in range(5)]
    results = await gather_with_limit(*tasks, max_concurrent=2)

    expected = [0, 2, 4, 6, 8]
    if results == expected:
        print(f"✓ Results: {results}")
        return True
    else:
        print(f"✗ Expected {expected}, got {results}")
        return False


async def _test_batch_async_tasks():
    """Test batch_async_tasks"""
    print("\n[Test 4] batch_async_tasks:")

    async def task(n):
        await asyncio.sleep(0.05)
        return n

    tasks = [task(i) for i in range(10)]
    results = await batch_async_tasks(tasks, batch_size=3, delay_between_batches=0.1)

    if len(results) == 10 and results == list(range(10)):
        print(f"✓ Processed {len(results)} tasks in batches")
        return True
    else:
        print(f"✗ Expected [0-9], got {results}")
        return False


async def _test_retry_async():
    """Test retry_async"""
    print("\n[Test 5] retry_async:")

    attempt = 0

    async def flaky_func():
        nonlocal attempt
        attempt += 1
        if attempt < 3:
            raise ValueError(f"Attempt {attempt} failed")
        return "success"

    try:
        result = await retry_async(flaky_func, max_retries=3, delay=0.05)
        if result == "success" and attempt == 3:
            print(f"✓ Succeeded after {attempt} attempts")
            return True
        else:
            print(f"✗ Unexpected result: {result}, attempts: {attempt}")
            return False
    except Exception as e:
        print(f"✗ Failed with exception: {e}")
        return False


async def _test_concurrent_limiter():
    """Test ConcurrentLimiter"""
    print("\n[Test 6] ConcurrentLimiter:")

    limiter = ConcurrentLimiter(2)
    active_max = 0

    async def task(n):
        nonlocal active_max
        async with limiter.limit():
            active_max = max(active_max, limiter.get_active_count())
            await asyncio.sleep(0.1)
            return n

    tasks = [task(i) for i in range(5)]
    results = await asyncio.gather(*tasks)

    if active_max <= 2 and len(results) == 5:
        print(f"✓ Maintained limit of 2 concurrent tasks (max active: {active_max})")
        return True
    else:
        print(f"✗ Limit not maintained properly (max active: {active_max})")
        return False


async def _test_task_monitor():
    """Test TaskMonitor"""
    print("\n[Test 7] TaskMonitor:")

    monitor = TaskMonitor()

    async def task(n):
        await asyncio.sleep(0.1)
        return n

    for i in range(3):
        monitor.create_task(task(i))

    await monitor.wait_all(timeout=2.0)
    stats = monitor.get_stats()

    if stats["completed"] == 3 and stats["failed"] == 0:
        print(f"✓ Monitor stats: {stats}")
        return True
    else:
        print(f"✗ Unexpected stats: {stats}")
        return False


async def _test_timeout_and_retry():
    """Test timeout_and_retry"""
    print("\n[Test 8] timeout_and_retry:")

    attempt = 0

    async def slow_then_fast():
        nonlocal attempt
        attempt += 1
        if attempt < 2:
            await asyncio.sleep(10)  # Will timeout
        return "success"

    try:
        result = await timeout_and_retry(
            slow_then_fast,
            timeout=0.1,
            max_retries=2,
            delay=0.05
        )
        if result == "success":
            print(f"✓ Succeeded after timeout and retry")
            return True
    except Exception as e:
        print(f"✗ Failed: {e}")
        return False


async def _run_all_async_tests():
    """Run all async tests"""
    tests = [
        _test_async_timeout,
        _test_wait_with_timeout,
        _test_gather_with_limit,
        _test_batch_async_tasks,
        _test_retry_async,
        _test_concurrent_limiter,
        _test_task_monitor,
        _test_timeout_and_retry,
    ]

    results = []
    for test in tests:
        try:
            result = await test()
            results.append(result)
        except Exception as e:
            print(f"✗ Test {test.__name__} failed with exception: {e}")
            results.append(False)

    return results


if __name__ == "__main__":
    print("=" * 80)
    print("TESTING ASYNC UTILITIES")
    print("=" * 80)

    # Run async tests
    results = run_async(_run_all_async_tests())

    # Print summary
    print("\n" + "=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)

    passed = sum(results)
    total = len(results)

    test_names = [
        "async_timeout",
        "wait_with_timeout",
        "gather_with_limit",
        "batch_async_tasks",
        "retry_async",
        "ConcurrentLimiter",
        "TaskMonitor",
        "timeout_and_retry",
    ]

    for name, success in zip(test_names, results):
        status = "✓ PASS" if success else "✗ FAIL"
        print(f"{status:8} | {name}")

    print("\n" + "=" * 80)
    print(f"RESULT: {passed}/{total} tests passed")
    print("=" * 80)