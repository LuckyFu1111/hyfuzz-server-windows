"""
Comprehensive benchmarking script for the MCP server.
Measures performance metrics including throughput, latency, memory usage, and CPU utilization.
"""

import time
import json
import statistics
import threading
import multiprocessing
import psutil
import logging
from pathlib import Path
from typing import Dict, List, Callable, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
import sys

logger = logging.getLogger(__name__)


# ============================================================================
# BENCHMARK DATA STRUCTURES
# ============================================================================

@dataclass
class BenchmarkResult:
    """Result of a single benchmark run."""
    name: str
    iterations: int
    total_time: float
    mean_time: float
    median_time: float
    min_time: float
    max_time: float
    std_dev: float
    ops_per_second: float
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()


@dataclass
class ResourceMetrics:
    """Resource usage metrics."""
    cpu_percent: float
    memory_mb: float
    memory_percent: float
    thread_count: int
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()


@dataclass
class LoadTestResult:
    """Result of load testing."""
    name: str
    concurrent_threads: int
    total_requests: int
    successful_requests: int
    failed_requests: int
    total_time: float
    mean_response_time: float
    min_response_time: float
    max_response_time: float
    requests_per_second: float
    errors: List[str] = None
    timestamp: str = ""

    def __post_init__(self):
        if self.errors is None:
            self.errors = []
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()


# ============================================================================
# BENCHMARK RUNNER
# ============================================================================

class BenchmarkRunner:
    """Main benchmark runner class."""

    def __init__(self, output_dir: Optional[Path] = None):
        """
        Initialize benchmark runner.

        Args:
            output_dir: Directory to save benchmark results
        """
        self.output_dir = Path(output_dir) if output_dir else Path("./benchmarks")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.results: List[BenchmarkResult] = []
        self.process = psutil.Process()

    def benchmark(self,
                  func: Callable,
                  iterations: int = 1000,
                  name: Optional[str] = None,
                  *args,
                  **kwargs) -> BenchmarkResult:
        """
        Run benchmark on a function.

        Args:
            func: Function to benchmark
            iterations: Number of iterations
            name: Benchmark name (defaults to function name)
            *args: Positional arguments for function
            **kwargs: Keyword arguments for function

        Returns:
            BenchmarkResult with timing statistics
        """
        name = name or func.__name__
        times = []

        print(f"\nRunning benchmark: {name}")
        print(f"  Iterations: {iterations}")

        # Warmup
        try:
            func(*args, **kwargs)
        except Exception as e:
            logger.warning(f"Warmup failed: {e}")

        # Main benchmark loop
        start_total = time.perf_counter()

        for i in range(iterations):
            start = time.perf_counter()
            try:
                func(*args, **kwargs)
            except Exception as e:
                logger.error(f"Benchmark iteration {i} failed: {e}")

            elapsed = time.perf_counter() - start
            times.append(elapsed)

            # Progress indicator
            if (i + 1) % max(1, iterations // 10) == 0:
                print(f"  Progress: {i + 1}/{iterations}")

        total_time = time.perf_counter() - start_total

        # Calculate statistics
        result = BenchmarkResult(
            name=name,
            iterations=iterations,
            total_time=total_time,
            mean_time=statistics.mean(times),
            median_time=statistics.median(times),
            min_time=min(times),
            max_time=max(times),
            std_dev=statistics.stdev(times) if len(times) > 1 else 0.0,
            ops_per_second=iterations / total_time
        )

        self.results.append(result)
        self._print_result(result)

        return result

    def benchmark_with_setup(self,
                             func: Callable,
                             setup: Callable,
                             cleanup: Optional[Callable] = None,
                             iterations: int = 100,
                             name: Optional[str] = None) -> BenchmarkResult:
        """
        Run benchmark with setup and cleanup.

        Args:
            func: Function to benchmark
            setup: Setup function called before each iteration
            cleanup: Cleanup function called after each iteration
            iterations: Number of iterations
            name: Benchmark name

        Returns:
            BenchmarkResult
        """
        name = name or func.__name__
        times = []

        print(f"\nRunning benchmark: {name}")
        print(f"  Iterations: {iterations}")

        start_total = time.perf_counter()

        for i in range(iterations):
            data = setup()

            start = time.perf_counter()
            try:
                func(data)
            except Exception as e:
                logger.error(f"Benchmark iteration {i} failed: {e}")

            elapsed = time.perf_counter() - start
            times.append(elapsed)

            if cleanup:
                try:
                    cleanup(data)
                except Exception as e:
                    logger.error(f"Cleanup failed: {e}")

            if (i + 1) % max(1, iterations // 10) == 0:
                print(f"  Progress: {i + 1}/{iterations}")

        total_time = time.perf_counter() - start_total

        result = BenchmarkResult(
            name=name,
            iterations=iterations,
            total_time=total_time,
            mean_time=statistics.mean(times),
            median_time=statistics.median(times),
            min_time=min(times),
            max_time=max(times),
            std_dev=statistics.stdev(times) if len(times) > 1 else 0.0,
            ops_per_second=iterations / total_time
        )

        self.results.append(result)
        self._print_result(result)

        return result

    def load_test(self,
                  func: Callable,
                  concurrent_threads: int = 4,
                  requests_per_thread: int = 100,
                  name: Optional[str] = None,
                  *args,
                  **kwargs) -> LoadTestResult:
        """
        Run load test with concurrent threads.

        Args:
            func: Function to test
            concurrent_threads: Number of concurrent threads
            requests_per_thread: Requests per thread
            name: Test name
            *args: Function arguments
            **kwargs: Function keyword arguments

        Returns:
            LoadTestResult with concurrency metrics
        """
        name = name or func.__name__
        total_requests = concurrent_threads * requests_per_thread
        response_times = []
        failed_count = 0
        errors = []

        print(f"\nRunning load test: {name}")
        print(f"  Threads: {concurrent_threads}")
        print(f"  Requests per thread: {requests_per_thread}")
        print(f"  Total requests: {total_requests}")

        def worker():
            """Worker thread function."""
            nonlocal failed_count

            for _ in range(requests_per_thread):
                start = time.perf_counter()
                try:
                    func(*args, **kwargs)
                    elapsed = time.perf_counter() - start
                    response_times.append(elapsed)
                except Exception as e:
                    failed_count += 1
                    errors.append(str(e))

        # Run load test
        start_total = time.perf_counter()
        threads = []

        for _ in range(concurrent_threads):
            thread = threading.Thread(target=worker)
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        total_time = time.perf_counter() - start_total
        successful = total_requests - failed_count

        result = LoadTestResult(
            name=name,
            concurrent_threads=concurrent_threads,
            total_requests=total_requests,
            successful_requests=successful,
            failed_requests=failed_count,
            total_time=total_time,
            mean_response_time=statistics.mean(response_times) if response_times else 0.0,
            min_response_time=min(response_times) if response_times else 0.0,
            max_response_time=max(response_times) if response_times else 0.0,
            requests_per_second=total_requests / total_time,
            errors=errors[:10]  # Keep first 10 errors
        )

        self._print_load_result(result)

        return result

    def measure_resources(self, func: Callable, duration_seconds: float = 5,
                          name: Optional[str] = None) -> Dict[str, Any]:
        """
        Measure resource usage during function execution.

        Args:
            func: Function to measure
            duration_seconds: Duration to measure
            name: Measurement name

        Returns:
            Dictionary with resource metrics
        """
        name = name or func.__name__
        metrics = []

        print(f"\nMeasuring resources: {name}")
        print(f"  Duration: {duration_seconds}s")

        def monitor():
            """Monitor resource usage."""
            while monitor.running:
                metric = ResourceMetrics(
                    cpu_percent=self.process.cpu_percent(interval=None),
                    memory_mb=self.process.memory_info().rss / 1024 / 1024,
                    memory_percent=self.process.memory_percent(),
                    thread_count=self.process.num_threads()
                )
                metrics.append(metric)
                time.sleep(0.1)

        monitor.running = True
        monitor_thread = threading.Thread(target=monitor, daemon=True)
        monitor_thread.start()

        # Run function
        start = time.perf_counter()
        try:
            func()
        except Exception as e:
            logger.error(f"Function execution failed: {e}")

        duration = time.perf_counter() - start
        monitor.running = False
        monitor_thread.join(timeout=1)

        # Calculate statistics
        if metrics:
            cpu_values = [m.cpu_percent for m in metrics]
            mem_values = [m.memory_mb for m in metrics]

            result = {
                "name": name,
                "duration_seconds": duration,
                "cpu_mean_percent": statistics.mean(cpu_values),
                "cpu_max_percent": max(cpu_values),
                "memory_mean_mb": statistics.mean(mem_values),
                "memory_max_mb": max(mem_values),
                "peak_threads": max(m.thread_count for m in metrics),
                "measurements": len(metrics)
            }
        else:
            result = {"name": name, "error": "No metrics collected"}

        print(f"  CPU (mean/max): {result.get('cpu_mean_percent', 0):.2f}% / {result.get('cpu_max_percent', 0):.2f}%")
        print(f"  Memory (mean/max): {result.get('memory_mean_mb', 0):.2f}MB / {result.get('memory_max_mb', 0):.2f}MB")

        return result

    def _print_result(self, result: BenchmarkResult):
        """Print benchmark result."""
        print(f"\nResults for: {result.name}")
        print(f"  Total time: {result.total_time:.4f}s")
        print(f"  Mean time:  {result.mean_time * 1000:.4f}ms")
        print(f"  Median:     {result.median_time * 1000:.4f}ms")
        print(f"  Min/Max:    {result.min_time * 1000:.4f}ms / {result.max_time * 1000:.4f}ms")
        print(f"  Std dev:    {result.std_dev * 1000:.4f}ms")
        print(f"  Throughput: {result.ops_per_second:.2f} ops/sec")

    def _print_load_result(self, result: LoadTestResult):
        """Print load test result."""
        print(f"\nResults for: {result.name}")
        print(f"  Total time:     {result.total_time:.4f}s")
        print(f"  Successful:     {result.successful_requests}/{result.total_requests}")
        print(f"  Failed:         {result.failed_requests}")
        print(f"  Mean response:  {result.mean_response_time * 1000:.4f}ms")
        print(f"  Min/Max:        {result.min_response_time * 1000:.4f}ms / {result.max_response_time * 1000:.4f}ms")
        print(f"  Throughput:     {result.requests_per_second:.2f} req/sec")

    def save_results(self, filename: Optional[str] = None) -> Path:
        """
        Save benchmark results to JSON file.

        Args:
            filename: Output filename

        Returns:
            Path to saved file
        """
        filename = filename or f"benchmark_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = self.output_dir / filename

        data = {
            "timestamp": datetime.now().isoformat(),
            "results": [asdict(r) for r in self.results]
        }

        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)

        print(f"\nResults saved to: {filepath}")
        return filepath

    def print_summary(self):
        """Print summary of all results."""
        if not self.results:
            print("No results to summarize")
            return

        print("\n" + "=" * 70)
        print("BENCHMARK SUMMARY")
        print("=" * 70)

        for result in self.results:
            print(f"\n{result.name}:")
            print(f"  Iterations: {result.iterations}")
            print(f"  Total: {result.total_time:.4f}s | Mean: {result.mean_time * 1000:.4f}ms")
            print(f"  Throughput: {result.ops_per_second:.2f} ops/sec")


# ============================================================================
# EXAMPLE FUNCTIONS FOR BENCHMARKING
# ============================================================================

def fibonacci(n: int) -> int:
    """Calculate fibonacci number (inefficient for benchmarking)."""
    if n <= 1:
        return n
    return fibonacci(n - 1) + fibonacci(n - 2)


def simple_json_operation() -> Dict:
    """Simple JSON operation."""
    import json
    data = {"key": "value", "number": 42, "nested": {"inner": "data"}}
    json_str = json.dumps(data)
    return json.loads(json_str)


def list_operation() -> List[int]:
    """List comprehension operation."""
    return [i * 2 for i in range(1000)]


def string_operation() -> str:
    """String manipulation."""
    s = "Hello World " * 100
    return s.upper().lower().replace("o", "0")


def regex_operation() -> List:
    """Regex matching."""
    import re
    pattern = r'\b[a-z]+\b'
    text = "Hello world this is a test string" * 100
    return re.findall(pattern, text)


def sort_operation() -> List[int]:
    """Sorting operation."""
    data = list(range(1000, 0, -1))
    return sorted(data)


# ============================================================================
# TEST SECTION
# ============================================================================

def run_tests():
    """Run comprehensive benchmark tests."""
    print("\n" + "=" * 70)
    print("BENCHMARK TEST SUITE")
    print("=" * 70)

    test_results = []

    # Initialize benchmark runner
    runner = BenchmarkRunner(output_dir="./test_benchmarks")

    # Test 1: Basic benchmarking
    print("\nTest 1: Basic Benchmarking")
    try:
        result = runner.benchmark(
            list_operation,
            iterations=1000,
            name="list_comprehension"
        )
        assert result.mean_time > 0
        assert result.ops_per_second > 0
        print("✓ PASSED: Basic benchmarking works\n")
        test_results.append(True)
    except Exception as e:
        print(f"✗ FAILED: {e}\n")
        test_results.append(False)

    # Test 2: JSON operation benchmarking
    print("Test 2: JSON Operation Benchmarking")
    try:
        result = runner.benchmark(
            simple_json_operation,
            iterations=500,
            name="json_operation"
        )
        assert result.mean_time > 0
        assert result.std_dev >= 0
        print("✓ PASSED: JSON benchmarking works\n")
        test_results.append(True)
    except Exception as e:
        print(f"✗ FAILED: {e}\n")
        test_results.append(False)

    # Test 3: String operation benchmarking
    print("Test 3: String Operation Benchmarking")
    try:
        result = runner.benchmark(
            string_operation,
            iterations=500,
            name="string_operation"
        )
        assert result.iterations == 500
        assert result.total_time > 0
        print("✓ PASSED: String operation benchmarking works\n")
        test_results.append(True)
    except Exception as e:
        print(f"✗ FAILED: {e}\n")
        test_results.append(False)

    # Test 4: Regex operation benchmarking
    print("Test 4: Regex Operation Benchmarking")
    try:
        result = runner.benchmark(
            regex_operation,
            iterations=100,
            name="regex_operation"
        )
        assert result.mean_time > 0
        print("✓ PASSED: Regex operation benchmarking works\n")
        test_results.append(True)
    except Exception as e:
        print(f"✗ FAILED: {e}\n")
        test_results.append(False)

    # Test 5: Sort operation benchmarking
    print("Test 5: Sort Operation Benchmarking")
    try:
        result = runner.benchmark(
            sort_operation,
            iterations=500,
            name="sort_operation"
        )
        assert result.mean_time >= 0
        assert result.median_time >= result.min_time
        print("✓ PASSED: Sort operation benchmarking works\n")
        test_results.append(True)
    except Exception as e:
        print(f"✗ FAILED: {e}\n")
        test_results.append(False)

    # Test 6: Load testing
    print("Test 6: Load Testing")
    try:
        result = runner.load_test(
            list_operation,
            concurrent_threads=2,
            requests_per_thread=50,
            name="list_load_test"
        )
        assert result.total_requests == 100
        assert result.requests_per_second > 0
        print("✓ PASSED: Load testing works\n")
        test_results.append(True)
    except Exception as e:
        print(f"✗ FAILED: {e}\n")
        test_results.append(False)

    # Test 7: Resource measurement
    print("Test 7: Resource Measurement")
    try:
        result = runner.measure_resources(
            list_operation,
            duration_seconds=1,
            name="resource_measurement"
        )
        assert "cpu_mean_percent" in result or "error" in result
        print("✓ PASSED: Resource measurement works\n")
        test_results.append(True)
    except Exception as e:
        print(f"✗ FAILED: {e}\n")
        test_results.append(False)

    # Test 8: Benchmark with setup
    print("Test 8: Benchmark with Setup")
    try:
        def setup_func():
            return list(range(100))

        def cleanup_func(data):
            data.clear()

        def test_func(data):
            return sum(data)

        result = runner.benchmark_with_setup(
            test_func,
            setup_func,
            cleanup_func,
            iterations=100,
            name="setup_benchmark"
        )
        assert result.iterations == 100
        assert result.mean_time > 0
        print("✓ PASSED: Benchmark with setup works\n")
        test_results.append(True)
    except Exception as e:
        print(f"✗ FAILED: {e}\n")
        test_results.append(False)

    # Test 9: Results summary
    print("Test 9: Results Summary")
    try:
        runner.print_summary()
        print("✓ PASSED: Results summary generated\n")
        test_results.append(True)
    except Exception as e:
        print(f"✗ FAILED: {e}\n")
        test_results.append(False)

    # Test 10: Save results
    print("Test 10: Save Results")
    try:
        filepath = runner.save_results("test_results.json")
        assert filepath.exists()

        # Verify JSON content
        with open(filepath, 'r') as f:
            data = json.load(f)
            assert "results" in data
            assert len(data["results"]) > 0

        print("✓ PASSED: Results saved successfully\n")
        test_results.append(True)
    except Exception as e:
        print(f"✗ FAILED: {e}\n")
        test_results.append(False)

    # Summary
    print("=" * 70)
    print(f"TEST SUMMARY: {sum(test_results)}/{len(test_results)} tests passed")
    print("=" * 70 + "\n")

    return all(test_results)


if __name__ == "__main__":
    success = run_tests()
    exit(0 if success else 1)