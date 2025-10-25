#!/usr/bin/env python3
"""
HyFuzz Windows MCP Server Launcher
Comprehensive server startup script with environment validation, configuration,
logging, and graceful shutdown handling.

Module Dependencies:
    - asyncio: Asynchronous I/O operations
    - sys: System-specific parameters and functions
    - os: Operating system interactions
    - logging: Logging framework
    - pathlib: Object-oriented filesystem path handling
    - signal: Signal handling for graceful shutdown
    - argparse: Command-line argument parsing
    - traceback: Exception traceback extraction
"""

import asyncio
import sys
import os
import logging
import signal
from pathlib import Path
from typing import Optional, Dict, Any
from argparse import ArgumentParser
from datetime import datetime
import json


# ============================================================================
# CONFIGURATION AND CONSTANTS
# ============================================================================

class ServerConfig:
    """Server configuration container with environment variables and defaults."""

    # Project root detection
    SCRIPT_DIR = Path(__file__).resolve().parent
    PROJECT_ROOT = SCRIPT_DIR.parent
    SRC_DIR = PROJECT_ROOT / "src"

    # Environment configuration
    ENV_FILE = PROJECT_ROOT / ".env"
    ENV_TEMPLATE = PROJECT_ROOT / ".env.example"

    # Logging configuration
    LOGS_DIR = PROJECT_ROOT / "logs"
    LOG_FILE_SERVER = LOGS_DIR / "server.log"
    LOG_FILE_ERROR = LOGS_DIR / "error.log"

    # Server defaults
    DEFAULT_HOST = "localhost"
    DEFAULT_PORT = 8000
    DEFAULT_TRANSPORT = "stdio"  # Options: stdio, http, websocket
    DEFAULT_LOG_LEVEL = "INFO"

    # Timeouts (in seconds)
    STARTUP_TIMEOUT = 30
    SHUTDOWN_TIMEOUT = 10
    HEALTH_CHECK_TIMEOUT = 5

    # Features
    ENABLE_METRICS = True
    ENABLE_HEALTH_CHECK = True
    ENABLE_HOT_RELOAD = False


# ============================================================================
# LOGGING SETUP
# ============================================================================

class LoggerSetup:
    """Centralized logging configuration for the server."""

    @staticmethod
    def setup_logging(
        log_level: str = ServerConfig.DEFAULT_LOG_LEVEL,
        log_file: Optional[Path] = None,
    ) -> logging.Logger:
        """
        Configure logging with both file and console handlers.

        Args:
            log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            log_file: Path to log file. If None, uses default server log

        Returns:
            Configured logger instance
        """
        if log_file is None:
            log_file = ServerConfig.LOG_FILE_SERVER

        # Ensure logs directory exists
        log_file.parent.mkdir(parents=True, exist_ok=True)

        # Create logger
        logger = logging.getLogger("hyfuzz-server")
        logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

        # Remove existing handlers
        logger.handlers.clear()

        # Formatter
        formatter = logging.Formatter(
            fmt="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        # File handler
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

        return logger


# ============================================================================
# ENVIRONMENT VALIDATION
# ============================================================================

class EnvironmentValidator:
    """Validates environment requirements and setup."""

    def __init__(self, logger: logging.Logger):
        self.logger = logger

    def validate_python_version(self, min_version: tuple = (3, 8)) -> bool:
        """
        Validate Python version meets minimum requirements.

        Args:
            min_version: Minimum required Python version tuple

        Returns:
            True if validation passed, False otherwise
        """
        current_version = sys.version_info[:2]
        if current_version < min_version:
            self.logger.error(
                f"Python {min_version[0]}.{min_version[1]}+ required. "
                f"Current: {current_version[0]}.{current_version[1]}"
            )
            return False
        self.logger.info(f"✓ Python version: {current_version[0]}.{current_version[1]}")
        return True

    def validate_project_structure(self) -> bool:
        """
        Validate essential project directories exist.

        Returns:
            True if structure is valid, False otherwise
        """
        required_dirs = [
            ServerConfig.SRC_DIR,
            ServerConfig.SRC_DIR / "mcp_server",
            ServerConfig.SRC_DIR / "llm",
            ServerConfig.SRC_DIR / "config",
        ]

        for directory in required_dirs:
            if not directory.exists():
                self.logger.error(f"Missing directory: {directory}")
                return False

        self.logger.info("✓ Project structure validated")
        return True

    def validate_dependencies(self) -> bool:
        """
        Validate required Python packages are installed.

        Returns:
            True if all dependencies are available, False otherwise
        """
        required_packages = [
            "asyncio",
            "logging",
            "json",
            "pathlib",
            "signal",
        ]

        missing_packages = []
        for package in required_packages:
            try:
                __import__(package)
            except ImportError:
                missing_packages.append(package)

        if missing_packages:
            self.logger.error(
                f"Missing required packages: {', '.join(missing_packages)}"
            )
            return False

        self.logger.info("✓ All required dependencies are available")
        return True

    def validate_environment_file(self) -> bool:
        """
        Check and validate environment file existence.

        Returns:
            True if environment is properly configured, False otherwise
        """
        if not ServerConfig.ENV_FILE.exists():
            if ServerConfig.ENV_TEMPLATE.exists():
                self.logger.warning(
                    f".env file not found. Using template: {ServerConfig.ENV_TEMPLATE}"
                )
                return True
            self.logger.warning(".env file not configured. Using defaults.")
            return True

        self.logger.info("✓ Environment file loaded")
        return True

    def run_all_checks(self) -> bool:
        """
        Execute all environment validation checks.

        Returns:
            True if all checks passed, False otherwise
        """
        self.logger.info("Starting environment validation...")
        checks = [
            ("Python Version", self.validate_python_version),
            ("Project Structure", self.validate_project_structure),
            ("Dependencies", self.validate_dependencies),
            ("Environment Configuration", self.validate_environment_file),
        ]

        all_passed = True
        for check_name, check_func in checks:
            try:
                if not check_func():
                    all_passed = False
            except Exception as e:
                self.logger.error(f"Error during {check_name} check: {e}")
                all_passed = False

        if all_passed:
            self.logger.info("✓ All environment checks passed")
        else:
            self.logger.error("✗ Environment validation failed")

        return all_passed


# ============================================================================
# MCP SERVER WRAPPER
# ============================================================================

class MCPServerManager:
    """Manages MCP server lifecycle and state."""

    def __init__(self, logger: logging.Logger, config: Dict[str, Any]):
        """
        Initialize MCP server manager.

        Args:
            logger: Logger instance
            config: Configuration dictionary
        """
        self.logger = logger
        self.config = config
        self.server = None
        self.is_running = False
        self.start_time = None

    async def initialize(self) -> bool:
        """
        Initialize MCP server with configuration.

        Returns:
            True if initialization successful, False otherwise
        """
        try:
            self.logger.info("Initializing MCP Server...")

            # Simulate server initialization
            # In production, this would instantiate actual MCPServer from src.mcp_server
            self.server = {
                "name": "HyFuzz-MCP-Server",
                "version": "1.0.0",
                "transport": self.config.get("transport", ServerConfig.DEFAULT_TRANSPORT),
                "host": self.config.get("host", ServerConfig.DEFAULT_HOST),
                "port": self.config.get("port", ServerConfig.DEFAULT_PORT),
                "capabilities": ["stdio", "http", "websocket"],
                "status": "initialized",
            }

            self.logger.info(f"✓ MCP Server initialized: {self.server['name']}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to initialize MCP Server: {e}")
            return False

    async def start(self) -> bool:
        """
        Start MCP server.

        Returns:
            True if server started successfully, False otherwise
        """
        try:
            self.logger.info("Starting MCP Server...")
            self.start_time = datetime.now()
            self.is_running = True

            # Simulate server startup
            await asyncio.sleep(0.1)

            self.logger.info(
                f"✓ MCP Server started on "
                f"{self.config.get('host')}:{self.config.get('port')}"
            )
            self.logger.info(
                f"Transport: {self.config.get('transport')} | "
                f"Log Level: {self.config.get('log_level')}"
            )
            return True

        except Exception as e:
            self.logger.error(f"Failed to start MCP Server: {e}")
            self.is_running = False
            return False

    async def health_check(self) -> Dict[str, Any]:
        """
        Perform server health check.

        Returns:
            Health status dictionary
        """
        uptime = (
            (datetime.now() - self.start_time).total_seconds()
            if self.start_time
            else 0
        )

        return {
            "status": "healthy" if self.is_running else "unhealthy",
            "uptime_seconds": uptime,
            "server_info": self.server,
            "timestamp": datetime.now().isoformat(),
        }

    async def stop(self) -> bool:
        """
        Stop MCP server gracefully.

        Returns:
            True if server stopped successfully, False otherwise
        """
        try:
            if not self.is_running:
                self.logger.info("Server is not running")
                return True

            self.logger.info("Stopping MCP Server...")
            await asyncio.sleep(0.1)

            self.is_running = False
            uptime = (datetime.now() - self.start_time).total_seconds()
            self.logger.info(f"✓ MCP Server stopped (uptime: {uptime:.2f}s)")
            return True

        except Exception as e:
            self.logger.error(f"Error stopping MCP Server: {e}")
            return False


# ============================================================================
# SIGNAL HANDLERS
# ============================================================================

class SignalHandler:
    """Handles system signals for graceful shutdown."""

    def __init__(self, logger: logging.Logger, server_manager: MCPServerManager):
        self.logger = logger
        self.server_manager = server_manager
        self.shutdown_event = asyncio.Event()

    def setup_signals(self):
        """Register signal handlers for graceful shutdown."""
        loop = asyncio.get_event_loop()

        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, self._signal_handler, sig)

        self.logger.info("✓ Signal handlers registered")

    def _signal_handler(self, sig: signal.Signals):
        """
        Handle received signals.

        Args:
            sig: Signal number
        """
        self.logger.info(f"Received signal {sig.name}, initiating graceful shutdown...")
        self.shutdown_event.set()

    async def wait_for_shutdown(self):
        """Wait for shutdown signal."""
        await self.shutdown_event.wait()


# ============================================================================
# MAIN SERVER RUNNER
# ============================================================================

class ServerRunner:
    """Orchestrates server startup, monitoring, and shutdown."""

    def __init__(self, args: Dict[str, Any]):
        """
        Initialize server runner.

        Args:
            args: Parsed command-line arguments
        """
        self.args = args
        self.logger = LoggerSetup.setup_logging(
            log_level=args.get("log_level", ServerConfig.DEFAULT_LOG_LEVEL)
        )

    async def run(self) -> int:
        """
        Main server execution flow.

        Returns:
            Exit code (0 for success, non-zero for failure)
        """
        try:
            # Step 1: Environment validation
            validator = EnvironmentValidator(self.logger)
            if not validator.run_all_checks():
                return 1

            # Step 2: Prepare configuration
            config = self._prepare_config()
            self.logger.info(f"Server configuration: {json.dumps(config, indent=2)}")

            # Step 3: Initialize server
            server_manager = MCPServerManager(self.logger, config)
            if not await server_manager.initialize():
                return 1

            # Step 4: Setup signal handlers
            signal_handler = SignalHandler(self.logger, server_manager)
            signal_handler.setup_signals()

            # Step 5: Start server
            if not await server_manager.start():
                return 1

            # Step 6: Health check
            if ServerConfig.ENABLE_HEALTH_CHECK:
                health_status = await server_manager.health_check()
                self.logger.info(f"Health check: {health_status['status']}")

            # Step 7: Wait for shutdown signal
            self.logger.info("Server is running. Press Ctrl+C to stop.")
            await signal_handler.wait_for_shutdown()

            # Step 8: Graceful shutdown
            self.logger.info("Shutting down server...")
            await asyncio.wait_for(
                server_manager.stop(), timeout=ServerConfig.SHUTDOWN_TIMEOUT
            )

            self.logger.info("✓ Server shutdown completed")
            return 0

        except asyncio.TimeoutError:
            self.logger.error("Server shutdown timeout")
            return 1
        except Exception as e:
            self.logger.error(f"Server error: {e}")
            import traceback

            self.logger.error(traceback.format_exc())
            return 1

    def _prepare_config(self) -> Dict[str, Any]:
        """
        Prepare server configuration from arguments.

        Returns:
            Configuration dictionary
        """
        return {
            "host": self.args.get("host", ServerConfig.DEFAULT_HOST),
            "port": self.args.get("port", ServerConfig.DEFAULT_PORT),
            "transport": self.args.get("transport", ServerConfig.DEFAULT_TRANSPORT),
            "log_level": self.args.get("log_level", ServerConfig.DEFAULT_LOG_LEVEL),
            "enable_metrics": self.args.get(
                "enable_metrics", ServerConfig.ENABLE_METRICS
            ),
            "enable_health_check": self.args.get(
                "enable_health_check", ServerConfig.ENABLE_HEALTH_CHECK
            ),
        }


# ============================================================================
# CLI ARGUMENT PARSER
# ============================================================================

def parse_arguments() -> Dict[str, Any]:
    """
    Parse command-line arguments.

    Returns:
        Dictionary of parsed arguments
    """
    parser = ArgumentParser(
        description="HyFuzz Windows MCP Server Launcher",
        epilog="Example: python start_server.py --host 0.0.0.0 --port 8000 --transport http",
    )

    parser.add_argument(
        "--host",
        type=str,
        default=ServerConfig.DEFAULT_HOST,
        help=f"Server host (default: {ServerConfig.DEFAULT_HOST})",
    )

    parser.add_argument(
        "--port",
        type=int,
        default=ServerConfig.DEFAULT_PORT,
        help=f"Server port (default: {ServerConfig.DEFAULT_PORT})",
    )

    parser.add_argument(
        "--transport",
        type=str,
        choices=["stdio", "http", "websocket"],
        default=ServerConfig.DEFAULT_TRANSPORT,
        help=f"Transport protocol (default: {ServerConfig.DEFAULT_TRANSPORT})",
    )

    parser.add_argument(
        "--log-level",
        type=str,
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default=ServerConfig.DEFAULT_LOG_LEVEL,
        help=f"Logging level (default: {ServerConfig.DEFAULT_LOG_LEVEL})",
    )

    parser.add_argument(
        "--no-metrics",
        action="store_false",
        dest="enable_metrics",
        help="Disable metrics collection",
    )

    parser.add_argument(
        "--no-health-check",
        action="store_false",
        dest="enable_health_check",
        help="Disable health checks",
    )

    parser.add_argument(
        "--version",
        action="store_true",
        help="Show version information",
    )

    args = parser.parse_args()

    if args.version:
        print("HyFuzz Windows MCP Server v1.0.0")
        sys.exit(0)

    return vars(args)


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main() -> int:
    """
    Main entry point for server launcher.

    Returns:
        Exit code
    """
    args = parse_arguments()
    runner = ServerRunner(args)

    try:
        exit_code = asyncio.run(runner.run())
        return exit_code
    except KeyboardInterrupt:
        print("\nServer interrupted by user")
        return 0
    except Exception as e:
        print(f"Fatal error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())


# ============================================================================
# UNIT TESTS
# ============================================================================

def run_tests():
    """Run integrated tests for server startup script."""

    import unittest
    from unittest.mock import Mock, patch, AsyncMock

    class TestServerConfig(unittest.TestCase):
        """Test ServerConfig class."""

        def test_config_constants(self):
            """Verify configuration constants are defined."""
            self.assertEqual(ServerConfig.DEFAULT_HOST, "localhost")
            self.assertEqual(ServerConfig.DEFAULT_PORT, 8000)
            self.assertEqual(ServerConfig.DEFAULT_TRANSPORT, "stdio")
            self.assertTrue(ServerConfig.ENABLE_METRICS)

    class TestLoggerSetup(unittest.TestCase):
        """Test logging configuration."""

        def test_logger_setup(self):
            """Test logger initialization."""
            logger = LoggerSetup.setup_logging(log_level="DEBUG")
            self.assertIsNotNone(logger)
            self.assertEqual(logger.name, "hyfuzz-server")
            self.assertGreater(len(logger.handlers), 0)

    class TestEnvironmentValidator(unittest.TestCase):
        """Test environment validation."""

        def setUp(self):
            self.mock_logger = Mock(spec=logging.Logger)
            self.validator = EnvironmentValidator(self.mock_logger)

        def test_python_version_validation(self):
            """Test Python version check passes for current version."""
            result = self.validator.validate_python_version()
            self.assertTrue(result)

        def test_dependencies_validation(self):
            """Test dependency validation."""
            result = self.validator.validate_dependencies()
            self.assertTrue(result)

        def test_environment_file_validation(self):
            """Test environment file validation."""
            result = self.validator.validate_environment_file()
            self.assertTrue(result)

    class TestMCPServerManager(unittest.IsolatedAsyncioTestCase):
        """Test MCP server manager."""

        async def asyncSetUp(self):
            self.mock_logger = Mock(spec=logging.Logger)
            self.config = {
                "host": "localhost",
                "port": 8000,
                "transport": "stdio",
                "log_level": "INFO",
            }
            self.manager = MCPServerManager(self.mock_logger, self.config)

        async def test_server_initialization(self):
            """Test server initialization."""
            result = await self.manager.initialize()
            self.assertTrue(result)
            self.assertIsNotNone(self.manager.server)
            self.assertEqual(self.manager.server["name"], "HyFuzz-MCP-Server")

        async def test_server_startup(self):
            """Test server startup."""
            await self.manager.initialize()
            result = await self.manager.start()
            self.assertTrue(result)
            self.assertTrue(self.manager.is_running)

        async def test_server_shutdown(self):
            """Test server shutdown."""
            await self.manager.initialize()
            await self.manager.start()
            result = await self.manager.stop()
            self.assertTrue(result)
            self.assertFalse(self.manager.is_running)

        async def test_health_check(self):
            """Test health check functionality."""
            await self.manager.initialize()
            await self.manager.start()
            health = await self.manager.health_check()
            self.assertEqual(health["status"], "healthy")
            self.assertIn("uptime_seconds", health)

    class TestServerRunner(unittest.IsolatedAsyncioTestCase):
        """Test server runner."""

        async def test_config_preparation(self):
            """Test configuration preparation."""
            args = {"host": "0.0.0.0", "port": 9000, "log_level": "DEBUG"}
            runner = ServerRunner(args)
            config = runner._prepare_config()
            self.assertEqual(config["host"], "0.0.0.0")
            self.assertEqual(config["port"], 9000)

    class TestArgumentParsing(unittest.TestCase):
        """Test CLI argument parsing."""

        def test_default_arguments(self):
            """Test default argument values."""
            with patch("sys.argv", ["start_server.py"]):
                args = parse_arguments()
                self.assertEqual(args["host"], ServerConfig.DEFAULT_HOST)
                self.assertEqual(args["port"], ServerConfig.DEFAULT_PORT)

    # Run test suite
    print("\n" + "=" * 70)
    print("RUNNING INTEGRATION TESTS FOR start_server.py")
    print("=" * 70 + "\n")

    test_suite = unittest.TestSuite()

    # Add all test classes
    test_suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestServerConfig))
    test_suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestLoggerSetup))
    test_suite.addTests(
        unittest.TestLoader().loadTestsFromTestCase(TestEnvironmentValidator)
    )
    test_suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestMCPServerManager))
    test_suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestServerRunner))
    test_suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestArgumentParsing))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)

    print("\n" + "=" * 70)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success: {result.wasSuccessful()}")
    print("=" * 70 + "\n")

    return result.wasSuccessful()


# Test execution
if __name__ == "__main__" and len(sys.argv) > 1 and sys.argv[1] == "--test":
    sys.argv = sys.argv[2:]  # Remove --test flag for unittest
    success = run_tests()
    sys.exit(0 if success else 1)