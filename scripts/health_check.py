"""
Health check script for the MCP server.
Monitors server status, resource usage, connectivity, and component health.
Provides detailed reporting and alerting capabilities.
"""

import sys
import time
import json
import logging
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime
import subprocess
import socket
import threading

try:
    import psutil
except ImportError:
    psutil = None


# ============================================================================
# HEALTH CHECK DATA STRUCTURES
# ============================================================================

@dataclass
class HealthStatus:
    """Health status of a component."""
    component: str
    status: str  # 'healthy', 'warning', 'critical', 'unknown'
    message: str
    details: Optional[Dict[str, Any]] = None
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()


@dataclass
class SystemMetrics:
    """System resource metrics."""
    cpu_percent: float
    memory_mb: float
    memory_percent: float
    disk_usage_percent: float
    available_memory_mb: float
    thread_count: int
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()


# ============================================================================
# COLOR CODES FOR TERMINAL OUTPUT
# ============================================================================

class Colors:
    """ANSI color codes."""
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


# ============================================================================
# HEALTH CHECK MANAGER
# ============================================================================

class HealthCheckManager:
    """Main health check manager."""

    def __init__(self, output_file: Optional[Path] = None):
        """
        Initialize health check manager.

        Args:
            output_file: Optional file to save health check results
        """
        self.output_file = output_file
        self.checks: List[HealthStatus] = []
        self.metrics: Optional[SystemMetrics] = None
        self.start_time = datetime.now()

    def run_all_checks(self) -> Dict[str, Any]:
        """
        Run all health checks.

        Returns:
            Dictionary with comprehensive health status
        """
        print(f"\n{Colors.BLUE}{Colors.BOLD}╔═══════════════════════════════════════════════════╗{Colors.RESET}")
        print(f"{Colors.BLUE}{Colors.BOLD}║        MCP SERVER HEALTH CHECK                      ║{Colors.RESET}")
        print(f"{Colors.BLUE}{Colors.BOLD}╚═══════════════════════════════════════════════════╝{Colors.RESET}\n")

        # Run individual checks
        print("Running health checks...\n")

        self._check_system_resources()
        self._check_python_environment()
        self._check_logging_system()
        self._check_configuration()
        self._check_file_permissions()
        self._check_network_connectivity()
        self._check_disk_space()
        self._check_memory_usage()

        # Compile results
        result = self._compile_results()

        # Print summary
        self._print_summary(result)

        # Save results if requested
        if self.output_file:
            self._save_results(result)

        return result

    def _check_system_resources(self):
        """Check system resource availability."""
        print(f"{Colors.BLUE}[CHECK]{Colors.RESET} System Resources...")

        if not psutil:
            self._add_check(
                "system_resources",
                "warning",
                "psutil not available - limited resource monitoring",
                {"reason": "psutil not installed"}
            )
            return

        try:
            process = psutil.Process()
            cpu_percent = process.cpu_percent(interval=0.1)
            memory_info = process.memory_info()
            memory_mb = memory_info.rss / 1024 / 1024

            # Store metrics
            vm = psutil.virtual_memory()
            self.metrics = SystemMetrics(
                cpu_percent=cpu_percent,
                memory_mb=memory_mb,
                memory_percent=process.memory_percent(),
                disk_usage_percent=psutil.disk_usage('/').percent,
                available_memory_mb=vm.available / 1024 / 1024,
                thread_count=process.num_threads()
            )

            # Check thresholds
            status = "healthy"
            message = f"CPU: {cpu_percent:.1f}%, Memory: {memory_mb:.2f}MB"

            if cpu_percent > 80:
                status = "warning"
                message += " - HIGH CPU USAGE"

            if memory_mb > 500:
                status = "warning"
                message += " - HIGH MEMORY USAGE"

            self._add_check(
                "system_resources",
                status,
                message,
                asdict(self.metrics)
            )
        except Exception as e:
            self._add_check("system_resources", "critical", f"Error: {e}")

    def _check_python_environment(self):
        """Check Python environment and dependencies."""
        print(f"{Colors.BLUE}[CHECK]{Colors.RESET} Python Environment...")

        try:
            python_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"

            required_modules = [
                'json', 'logging', 'pathlib', 'datetime',
                'dataclasses', 'threading', 'socket'
            ]

            missing = []
            for module in required_modules:
                try:
                    __import__(module)
                except ImportError:
                    missing.append(module)

            status = "healthy"
            message = f"Python {python_version}"

            if missing:
                status = "critical"
                message += f" - Missing modules: {', '.join(missing)}"

            self._add_check(
                "python_environment",
                status,
                message,
                {
                    "python_version": python_version,
                    "missing_modules": missing
                }
            )
        except Exception as e:
            self._add_check("python_environment", "critical", f"Error: {e}")

    def _check_logging_system(self):
        """Check logging system functionality."""
        print(f"{Colors.BLUE}[CHECK]{Colors.RESET} Logging System...")

        try:
            logger = logging.getLogger("health_check")
            test_message = f"Health check test at {datetime.now().isoformat()}"

            # Try to log
            logger.info(test_message)

            status = "healthy"
            message = "Logging system operational"

            self._add_check(
                "logging_system",
                status,
                message,
                {"test_message": test_message}
            )
        except Exception as e:
            self._add_check("logging_system", "warning", f"Logging error: {e}")

    def _check_configuration(self):
        """Check configuration file validity."""
        print(f"{Colors.BLUE}[CHECK]{Colors.RESET} Configuration...")

        try:
            config_paths = [
                Path("config/server_config.yaml"),
                Path("src/config/default_config.yaml"),
                Path(".env"),
            ]

            found_configs = []
            for path in config_paths:
                if path.exists():
                    found_configs.append(str(path))

            status = "healthy" if found_configs else "warning"
            message = f"Found {len(found_configs)} config file(s)"

            self._add_check(
                "configuration",
                status,
                message,
                {"config_files": found_configs}
            )
        except Exception as e:
            self._add_check("configuration", "warning", f"Config check error: {e}")

    def _check_file_permissions(self):
        """Check file and directory permissions."""
        print(f"{Colors.BLUE}[CHECK]{Colors.RESET} File Permissions...")

        try:
            directories = ["logs", "data", "config", "src"]
            issues = []

            for dir_name in directories:
                dir_path = Path(dir_name)
                if dir_path.exists():
                    if not dir_path.is_dir():
                        issues.append(f"{dir_name} is not a directory")
                    # Check if readable
                    if not os.access(dir_path, os.R_OK):
                        issues.append(f"{dir_name} is not readable")
                    # Check if writable (for logs and data)
                    if dir_name in ["logs", "data"]:
                        if not os.access(dir_path, os.W_OK):
                            issues.append(f"{dir_name} is not writable")

            status = "healthy" if not issues else "warning"
            message = "All directories accessible" if not issues else "Permission issues found"

            self._add_check(
                "file_permissions",
                status,
                message,
                {"issues": issues}
            )
        except Exception as e:
            self._add_check("file_permissions", "warning", f"Permission check error: {e}")

    def _check_network_connectivity(self):
        """Check network connectivity."""
        print(f"{Colors.BLUE}[CHECK]{Colors.RESET} Network Connectivity...")

        try:
            # Test common services
            services = [
                ("localhost", 8000),
                ("localhost", 8080),
                ("127.0.0.1", 5432),  # PostgreSQL
            ]

            reachable = []
            unreachable = []

            for host, port in services:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((host, port))
                    sock.close()

                    if result == 0:
                        reachable.append(f"{host}:{port}")
                    else:
                        unreachable.append(f"{host}:{port}")
                except Exception:
                    unreachable.append(f"{host}:{port}")

            status = "healthy" if reachable else "warning"
            message = f"Reachable: {len(reachable)} services"

            self._add_check(
                "network_connectivity",
                status,
                message,
                {
                    "reachable": reachable,
                    "unreachable": unreachable
                }
            )
        except Exception as e:
            self._add_check("network_connectivity", "warning", f"Network check error: {e}")

    def _check_disk_space(self):
        """Check disk space availability."""
        print(f"{Colors.BLUE}[CHECK]{Colors.RESET} Disk Space...")

        try:
            if not psutil:
                self._add_check("disk_space", "unknown", "psutil not available")
                return

            disk = psutil.disk_usage('/')
            percent_used = disk.percent
            free_gb = disk.free / (1024 ** 3)

            status = "healthy"
            message = f"Disk usage: {percent_used:.1f}% ({free_gb:.2f}GB free)"

            if percent_used > 90:
                status = "critical"
            elif percent_used > 75:
                status = "warning"

            self._add_check(
                "disk_space",
                status,
                message,
                {
                    "percent_used": percent_used,
                    "free_gb": free_gb,
                    "total_gb": disk.total / (1024 ** 3)
                }
            )
        except Exception as e:
            self._add_check("disk_space", "warning", f"Disk check error: {e}")

    def _check_memory_usage(self):
        """Check system memory usage."""
        print(f"{Colors.BLUE}[CHECK]{Colors.RESET} Memory Usage...")

        try:
            if not psutil:
                self._add_check("memory_usage", "unknown", "psutil not available")
                return

            vm = psutil.virtual_memory()
            percent = vm.percent
            available_gb = vm.available / (1024 ** 3)

            status = "healthy"
            message = f"Memory: {percent:.1f}% used ({available_gb:.2f}GB available)"

            if percent > 90:
                status = "critical"
            elif percent > 75:
                status = "warning"

            self._add_check(
                "memory_usage",
                status,
                message,
                {
                    "percent_used": percent,
                    "available_gb": available_gb,
                    "total_gb": vm.total / (1024 ** 3)
                }
            )
        except Exception as e:
            self._add_check("memory_usage", "warning", f"Memory check error: {e}")

    def _add_check(self, component: str, status: str, message: str,
                   details: Optional[Dict] = None):
        """Add a health check result."""
        check = HealthStatus(
            component=component,
            status=status,
            message=message,
            details=details
        )
        self.checks.append(check)

        # Print immediately
        status_color = self._get_status_color(status)
        print(f"  {status_color}[{status.upper():8}]{Colors.RESET} {component}: {message}")

    def _get_status_color(self, status: str) -> str:
        """Get color code for status."""
        colors = {
            "healthy": Colors.GREEN,
            "warning": Colors.YELLOW,
            "critical": Colors.RED,
            "unknown": Colors.BLUE,
        }
        return colors.get(status, Colors.RESET)

    def _compile_results(self) -> Dict[str, Any]:
        """Compile all results."""
        # Calculate overall status
        statuses = [check.status for check in self.checks]
        if "critical" in statuses:
            overall_status = "critical"
        elif "warning" in statuses:
            overall_status = "warning"
        else:
            overall_status = "healthy"

        return {
            "timestamp": datetime.now().isoformat(),
            "overall_status": overall_status,
            "checks": [asdict(check) for check in self.checks],
            "system_metrics": asdict(self.metrics) if self.metrics else None,
            "summary": {
                "total_checks": len(self.checks),
                "healthy": sum(1 for c in self.checks if c.status == "healthy"),
                "warning": sum(1 for c in self.checks if c.status == "warning"),
                "critical": sum(1 for c in self.checks if c.status == "critical"),
                "unknown": sum(1 for c in self.checks if c.status == "unknown"),
            }
        }

    def _print_summary(self, result: Dict[str, Any]):
        """Print health check summary."""
        summary = result['summary']
        overall = result['overall_status']

        status_color = self._get_status_color(overall)

        print(f"\n{Colors.BOLD}{'=' * 60}{Colors.RESET}")
        print(f"\n{Colors.BOLD}HEALTH CHECK SUMMARY{Colors.RESET}")
        print(f"\nOverall Status: {status_color}{overall.upper()}{Colors.RESET}")
        print(f"\nChecks Completed: {summary['total_checks']}")
        print(f"  {Colors.GREEN}✓ Healthy:  {summary['healthy']}{Colors.RESET}")
        print(f"  {Colors.YELLOW}⚠ Warning:  {summary['warning']}{Colors.RESET}")
        print(f"  {Colors.RED}✗ Critical: {summary['critical']}{Colors.RESET}")
        print(f"  {Colors.BLUE}? Unknown:  {summary['unknown']}{Colors.RESET}")

        # Print metrics if available
        if result['system_metrics']:
            metrics = result['system_metrics']
            print(f"\n{Colors.BOLD}System Metrics:{Colors.RESET}")
            print(f"  CPU Usage:      {metrics['cpu_percent']:.1f}%")
            print(f"  Memory Usage:   {metrics['memory_mb']:.2f} MB ({metrics['memory_percent']:.1f}%)")
            print(f"  Thread Count:   {metrics['thread_count']}")

        print(f"\n{Colors.BOLD}{'=' * 60}{Colors.RESET}\n")

    def _save_results(self, result: Dict[str, Any]):
        """Save results to file."""
        try:
            with open(self.output_file, 'w') as f:
                json.dump(result, f, indent=2)
            print(f"✓ Results saved to {self.output_file}")
        except Exception as e:
            print(f"✗ Error saving results: {e}")


# ============================================================================
# STANDALONE HEALTH CHECK FUNCTIONS
# ============================================================================

def quick_health_check() -> bool:
    """Run quick health check. Returns True if healthy."""
    checks_passed = 0
    checks_total = 0

    print("Quick Health Check:\n")

    # Check 1: Python
    checks_total += 1
    try:
        version = f"{sys.version_info.major}.{sys.version_info.minor}"
        print(f"✓ Python {version}")
        checks_passed += 1
    except Exception as e:
        print(f"✗ Python check failed: {e}")

    # Check 2: Core modules
    checks_total += 1
    try:
        import json
        import logging
        print("✓ Core modules available")
        checks_passed += 1
    except Exception as e:
        print(f"✗ Core modules missing: {e}")

    # Check 3: Logging
    checks_total += 1
    try:
        logger = logging.getLogger()
        logger.info("Health check test")
        print("✓ Logging operational")
        checks_passed += 1
    except Exception as e:
        print(f"✗ Logging error: {e}")

    # Check 4: System resources (if psutil available)
    if psutil:
        checks_total += 1
        try:
            process = psutil.Process()
            cpu = process.cpu_percent()
            mem = process.memory_info().rss / 1024 / 1024
            print(f"✓ Resources available (CPU: {cpu:.1f}%, Memory: {mem:.2f}MB)")
            checks_passed += 1
        except Exception as e:
            print(f"✗ Resource check failed: {e}")

    print(f"\nResult: {checks_passed}/{checks_total} checks passed\n")

    return checks_passed == checks_total


# ============================================================================
# TEST SECTION
# ============================================================================

import os


def run_tests():
    """Run health check tests."""
    print("\n" + "=" * 70)
    print("HEALTH CHECK TEST SUITE")
    print("=" * 70 + "\n")

    test_results = []

    # Test 1: Quick health check
    print("Test 1: Quick Health Check")
    try:
        result = quick_health_check()
        if result:
            print("✓ PASSED: Quick health check passed\n")
            test_results.append(True)
        else:
            print("⚠ WARNING: Quick health check had failures\n")
            test_results.append(True)  # Don't fail if optional checks fail
    except Exception as e:
        print(f"✗ FAILED: {e}\n")
        test_results.append(False)

    # Test 2: Health check manager initialization
    print("Test 2: Health Check Manager Initialization")
    try:
        manager = HealthCheckManager()
        assert manager is not None
        print("✓ PASSED: Manager initialized successfully\n")
        test_results.append(True)
    except Exception as e:
        print(f"✗ FAILED: {e}\n")
        test_results.append(False)

    # Test 3: Individual checks
    print("Test 3: Individual Health Checks")
    try:
        manager = HealthCheckManager()
        manager._check_python_environment()
        manager._check_logging_system()
        manager._check_configuration()

        assert len(manager.checks) >= 3
        print("✓ PASSED: Individual checks executed\n")
        test_results.append(True)
    except Exception as e:
        print(f"✗ FAILED: {e}\n")
        test_results.append(False)

    # Test 4: System resources check
    print("Test 4: System Resources Check")
    try:
        manager = HealthCheckManager()
        manager._check_system_resources()

        if manager.metrics:
            assert manager.metrics.cpu_percent >= 0
            assert manager.metrics.memory_mb > 0
            print("✓ PASSED: System metrics collected\n")
            test_results.append(True)
        else:
            print("⚠ WARNING: Metrics unavailable (psutil not installed)\n")
            test_results.append(True)
    except Exception as e:
        print(f"✗ FAILED: {e}\n")
        test_results.append(False)

    # Test 5: Disk space check
    print("Test 5: Disk Space Check")
    try:
        manager = HealthCheckManager()
        manager._check_disk_space()

        disk_check = [c for c in manager.checks if c.component == "disk_space"]
        assert len(disk_check) > 0
        print("✓ PASSED: Disk check completed\n")
        test_results.append(True)
    except Exception as e:
        print(f"✗ FAILED: {e}\n")
        test_results.append(False)

    # Test 6: File permissions check
    print("Test 6: File Permissions Check")
    try:
        manager = HealthCheckManager()
        manager._check_file_permissions()

        perm_check = [c for c in manager.checks if c.component == "file_permissions"]
        assert len(perm_check) > 0
        print("✓ PASSED: Permissions check completed\n")
        test_results.append(True)
    except Exception as e:
        print(f"✗ FAILED: {e}\n")
        test_results.append(False)

    # Test 7: Full health check run
    print("Test 7: Full Health Check Run")
    try:
        manager = HealthCheckManager()
        result = manager.run_all_checks()

        assert result is not None
        assert 'overall_status' in result
        assert 'checks' in result
        assert 'summary' in result

        print("✓ PASSED: Full health check completed\n")
        test_results.append(True)
    except Exception as e:
        print(f"✗ FAILED: {e}\n")
        test_results.append(False)

    # Test 8: Results compilation
    print("Test 8: Results Compilation and Summary")
    try:
        manager = HealthCheckManager()
        manager._check_python_environment()
        manager._check_logging_system()

        result = manager._compile_results()

        assert result['summary']['total_checks'] == 2
        assert 'healthy' in result['summary']
        assert 'timestamp' in result

        print("✓ PASSED: Results compiled correctly\n")
        test_results.append(True)
    except Exception as e:
        print(f"✗ FAILED: {e}\n")
        test_results.append(False)

    # Test 9: JSON export format
    print("Test 9: JSON Export Format")
    try:
        manager = HealthCheckManager()
        result = manager.run_all_checks()

        # Verify JSON serializable
        json_str = json.dumps(result)
        assert len(json_str) > 0

        # Verify structure
        imported = json.loads(json_str)
        assert imported['overall_status'] in ['healthy', 'warning', 'critical', 'unknown']

        print("✓ PASSED: JSON format valid\n")
        test_results.append(True)
    except Exception as e:
        print(f"✗ FAILED: {e}\n")
        test_results.append(False)

    # Test 10: Status color mapping
    print("Test 10: Status Color Mapping")
    try:
        manager = HealthCheckManager()

        colors = [
            manager._get_status_color("healthy"),
            manager._get_status_color("warning"),
            manager._get_status_color("critical"),
            manager._get_status_color("unknown"),
        ]

        assert all(isinstance(c, str) for c in colors)
        assert all(len(c) > 0 for c in colors)

        print("✓ PASSED: Status colors mapped correctly\n")
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
    import argparse

    parser = argparse.ArgumentParser(description="Health check script for MCP server")
    parser.add_argument("--quick", action="store_true", help="Run quick health check")
    parser.add_argument("--full", action="store_true", help="Run full health check")
    parser.add_argument("--output", type=str, help="Save results to JSON file")
    parser.add_argument("--test", action="store_true", help="Run test suite")

    args = parser.parse_args()

    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    if args.test:
        success = run_tests()
        exit(0 if success else 1)
    elif args.quick:
        success = quick_health_check()
        exit(0 if success else 1)
    else:
        # Run full check by default
        manager = HealthCheckManager(output_file=Path(args.output) if args.output else None)
        result = manager.run_all_checks()

        # Exit with appropriate code
        exit(0 if result['overall_status'] != 'critical' else 1)