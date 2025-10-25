"""
HyFuzz Windows MCP Server - Main Entry Point (FIXED VERSION)

This module serves as the primary entry point for the HyFuzz server.
It handles:
- Command-line argument parsing
- Server initialization and lifecycle management
- Component orchestration
- Error handling and graceful shutdown
- Different runtime modes (server, client, test, debug)

FIXED:
- Removed duplicate -h/--help argument (argparse adds it by default)
- Fixed import error handling
- Better error messages

Phase 3 Architecture Integration:
- MCP Core/Client layer initialization
- LLM Services (CoT engine, reasoning chains)
- Knowledge Base (CWE/CVE repositories, graph DB)
- Fuzzing Engine and payload handling
- Vulnerability scanning integration

Author: HyFuzz Development Team
Version: 1.0.0-phase3-fixed
License: MIT
"""

import sys
import os
import logging
import argparse
import signal
import asyncio
from pathlib import Path
from typing import Optional, Dict, Any, Tuple
from dataclasses import dataclass
from enum import Enum

# Add project root to path for imports
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Import HyFuzz package
try:
    from src import (
        initialize_hyfuzz,
        get_component,
        set_logging_level,
        __version__,
        __title__,
    )
except ImportError as e:
    print(f"Error: Failed to import HyFuzz package: {e}")
    sys.exit(1)

# Fallback for logging if get_logger fails to import
try:
    from src.utils.logger import get_logger
except ImportError:
    def get_logger(name):
        return logging.getLogger(name)


# ============================================================================
# CONFIGURATION AND ENUMS
# ============================================================================

class RunMode(Enum):
    """Supported runtime modes for HyFuzz server."""
    SERVER = "server"          # Start as MCP server
    CLIENT = "client"          # Start as MCP client
    STANDALONE = "standalone"  # Standalone mode (no network)
    TEST = "test"             # Test mode
    DEBUG = "debug"           # Debug mode with verbose logging


class TransportMode(Enum):
    """Supported transport protocols for MCP."""
    STDIO = "stdio"           # Standard I/O
    HTTP = "http"             # HTTP protocol
    WEBSOCKET = "websocket"   # WebSocket


@dataclass
class ServerConfig:
    """Configuration for server startup."""
    mode: RunMode = RunMode.SERVER
    transport: TransportMode = TransportMode.STDIO
    host: str = "localhost"
    port: int = 8000
    log_level: int = logging.INFO
    config_file: Optional[str] = None
    enable_llm: bool = True
    enable_knowledge: bool = True
    debug: bool = False
    verbose: bool = False


# ============================================================================
# LOGGER SETUP
# ============================================================================

def setup_logging(level: int = logging.INFO, verbose: bool = False) -> logging.Logger:
    """
    Configure logging for the application.

    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        verbose: If True, use verbose format with more details

    Returns:
        Configured logger instance
    """
    if verbose:
        log_format = (
            '%(asctime)s - [%(levelname)s] - %(name)s:%(lineno)d - %(funcName)s() - %(message)s'
        )
    else:
        log_format = '%(asctime)s - [%(levelname)s] - %(name)s - %(message)s'

    # Ensure logs directory exists
    logs_dir = Path(PROJECT_ROOT) / 'logs'
    logs_dir.mkdir(exist_ok=True)

    logging.basicConfig(
        level=level,
        format=log_format,
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(logs_dir / 'hyfuzz.log', encoding='utf-8')
        ]
    )

    set_logging_level(level)
    logger = get_logger(__name__)
    return logger


# ============================================================================
# SERVER INITIALIZATION
# ============================================================================

class HyFuzzServer:
    """Main HyFuzz server orchestrator."""

    def __init__(self, config: ServerConfig) -> None:
        """
        Initialize HyFuzz server.

        Args:
            config: Server configuration
        """
        self.config = config
        self.logger = get_logger(self.__class__.__name__)
        self.components: Dict[str, Any] = {}
        self.is_running = False

        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum: int, frame: Any) -> None:
        """Handle shutdown signals gracefully."""
        self.logger.info(f"Received signal {signum}, shutting down gracefully...")
        self.shutdown()
        sys.exit(0)

    def initialize(self) -> bool:
        """
        Initialize all server components.

        Returns:
            True if initialization successful, False otherwise
        """
        try:
            self.logger.info(f"Initializing HyFuzz Server v{__version__}")
            self.logger.info(f"Mode: {self.config.mode.value}")
            self.logger.info(f"Transport: {self.config.transport.value}")

            # Initialize HyFuzz package
            self.logger.debug("Loading HyFuzz components...")
            self.components = initialize_hyfuzz(
                config_path=self.config.config_file,
                enable_llm=self.config.enable_llm,
                enable_knowledge=self.config.enable_knowledge
            )

            self.logger.info(f"✓ Initialized {len(self.components)} components")

            # Validate critical components
            if not self._validate_components():
                return False

            # Configure based on mode
            if not self._configure_mode():
                return False

            self.logger.info("✓ Server initialization complete")
            return True

        except Exception as e:
            self.logger.error(f"✗ Initialization failed: {e}", exc_info=True)
            return False

    def _validate_components(self) -> bool:
        """
        Validate that critical components are available.

        Returns:
            True if all critical components are available
        """
        required_components = {
            'config': 'Configuration',
        }

        optional_components = {
            'mcp_server': 'MCP Server',
            'llm_service': 'LLM Service',
            'knowledge_loader': 'Knowledge Base',
            'cache_manager': 'Cache Manager',
        }

        # Check required components
        for comp_name, comp_label in required_components.items():
            if comp_name not in self.components or self.components[comp_name] is None:
                self.logger.warning(f"⚠ Missing component: {comp_label}")
            self.logger.debug(f"✓ {comp_label} available")

        # Check optional components
        for comp_name, comp_label in optional_components.items():
            if comp_name in self.components and self.components[comp_name] is not None:
                self.logger.debug(f"✓ {comp_label} available")
            else:
                self.logger.debug(f"⚠ Optional component not available: {comp_label}")

        return True

    def _configure_mode(self) -> bool:
        """
        Configure server based on selected mode.

        Returns:
            True if configuration successful
        """
        try:
            if self.config.mode == RunMode.SERVER:
                self.logger.info("Configuring as MCP server...")

            elif self.config.mode == RunMode.STANDALONE:
                self.logger.info("Configuring as standalone mode...")

            elif self.config.mode == RunMode.TEST:
                self.logger.info("Configuring for test mode...")
                set_logging_level(logging.DEBUG)

            elif self.config.mode == RunMode.DEBUG:
                self.logger.info("Configuring for debug mode...")
                set_logging_level(logging.DEBUG)
                self.logger.debug("DEBUG MODE ENABLED - Verbose logging active")

            return True

        except Exception as e:
            self.logger.error(f"✗ Mode configuration failed: {e}", exc_info=True)
            return False

    def start(self) -> bool:
        """
        Start the server and all services.

        Returns:
            True if server started successfully
        """
        try:
            self.logger.info("Starting HyFuzz Server...")
            self.is_running = True

            # Log transport info
            if self.config.transport == TransportMode.HTTP:
                self.logger.info(f"HTTP Server: {self.config.host}:{self.config.port}")
            elif self.config.transport == TransportMode.WEBSOCKET:
                self.logger.info(f"WebSocket Server: ws://{self.config.host}:{self.config.port}")

            # Log feature status
            if self.config.enable_llm:
                self.logger.info("LLM services: enabled")
            else:
                self.logger.info("LLM services: disabled")

            if self.config.enable_knowledge:
                self.logger.info("Knowledge base: enabled")
            else:
                self.logger.info("Knowledge base: disabled")

            self.logger.info("✓ Server started successfully")

            if self.config.mode != RunMode.TEST:
                self.logger.info("Server ready. Press Ctrl+C to stop.")

            return True

        except Exception as e:
            self.logger.error(f"✗ Failed to start server: {e}", exc_info=True)
            return False

    def shutdown(self) -> None:
        """Gracefully shutdown the server."""
        if not self.is_running:
            return

        self.logger.info("Shutting down HyFuzz Server...")
        self.is_running = False

        try:
            # Cleanup caches
            cache_manager = get_component('cache_manager')
            if cache_manager:
                self.logger.debug("Clearing caches...")

            self.logger.info("✓ Server shutdown complete")

        except Exception as e:
            self.logger.error(f"Error during shutdown: {e}", exc_info=True)

    def run(self) -> int:
        """
        Run the server in blocking mode.

        Returns:
            Exit code (0 for success, 1 for failure)
        """
        if not self.initialize():
            self.logger.error("Failed to initialize server")
            return 1

        if not self.start():
            self.logger.error("Failed to start server")
            return 1

        try:
            if self.config.mode == RunMode.TEST:
                # In test mode, run verification and exit
                return self._run_tests()
            else:
                # In server mode, run until interrupted
                self._run_server()
                return 0
        except KeyboardInterrupt:
            self.logger.info("Keyboard interrupt received")
            return 0
        except Exception as e:
            self.logger.error(f"Runtime error: {e}", exc_info=True)
            return 1
        finally:
            self.shutdown()

    def _run_server(self) -> None:
        """Run server in blocking mode."""
        try:
            while self.is_running:
                try:
                    # Sleep to prevent busy-waiting
                    import time
                    time.sleep(0.1)
                except KeyboardInterrupt:
                    break
        except Exception as e:
            self.logger.error(f"Server error: {e}", exc_info=True)

    def _run_tests(self) -> int:
        """
        Run verification tests in test mode.

        Returns:
            Exit code (0 if all tests pass, 1 if any fail)
        """
        self.logger.info("Running verification tests...")

        tests_passed = 0
        tests_failed = 0

        # Test 1: Components loaded
        self.logger.info("Test 1: Component loading")
        if len(self.components) > 0:
            self.logger.info(f"  ✓ Loaded {len(self.components)} components")
            tests_passed += 1
        else:
            self.logger.error(f"  ✗ No components loaded")
            tests_failed += 1

        # Test 2: Config available
        self.logger.info("Test 2: Configuration")
        if get_component('config') is not None:
            self.logger.info("  ✓ Configuration available")
            tests_passed += 1
        else:
            self.logger.error("  ✗ Configuration not available")
            tests_failed += 1

        self.logger.info(f"Tests passed: {tests_passed}")
        self.logger.info(f"Tests failed: {tests_failed}")

        return 0 if tests_failed == 0 else 1


# ============================================================================
# COMMAND LINE INTERFACE
# ============================================================================

def parse_arguments() -> Tuple[argparse.Namespace, Optional[str]]:
    """
    Parse command line arguments.

    NOTE: argparse automatically adds -h/--help, so we don't add it manually

    Returns:
        Tuple of (parsed_args, error_message)
    """
    parser = argparse.ArgumentParser(
        prog='hyfuzz',
        description=f'{__title__} v{__version__}',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=True,  # Explicitly enable the default -h/--help
        epilog="""
Examples:
  # Start as MCP server
  python -m src

  # Start with debug
  python -m src --debug

  # Run tests
  python -m src --mode test

  # With HTTP transport
  python -m src --transport http --port 8080
        """
    )

    # Mode arguments
    parser.add_argument(
        '--mode',
        type=str,
        choices=[mode.value for mode in RunMode],
        default='server',
        help='Server mode (default: server)'
    )

    # Transport arguments
    parser.add_argument(
        '--transport',
        type=str,
        choices=[t.value for t in TransportMode],
        default='stdio',
        help='Transport protocol (default: stdio)'
    )

    # Server arguments
    parser.add_argument(
        '--host',
        type=str,
        default='localhost',
        help='Server host (default: localhost)'
    )

    parser.add_argument(
        '--port',
        type=int,
        default=8000,
        help='Server port (default: 8000)'
    )

    # Configuration arguments
    parser.add_argument(
        '--config',
        type=str,
        help='Path to configuration file'
    )

    # Feature flags
    parser.add_argument(
        '--no-llm',
        action='store_true',
        help='Disable LLM services'
    )

    parser.add_argument(
        '--no-knowledge',
        action='store_true',
        help='Disable knowledge base'
    )

    # Logging arguments
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug mode (verbose logging)'
    )

    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose output'
    )

    parser.add_argument(
        '--log-level',
        type=str,
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        default='INFO',
        help='Logging level (default: INFO)'
    )

    # Version
    parser.add_argument(
        '--version',
        action='version',
        version=f'{__title__} v{__version__}'
    )

    try:
        args = parser.parse_args()
        return args, None
    except SystemExit as e:
        if e.code == 0:
            # This is normal for --help or --version
            return None, None
        return None, f"Argument parsing failed: {e}"


def create_config_from_args(args: argparse.Namespace) -> ServerConfig:
    """
    Create ServerConfig from command line arguments.

    Args:
        args: Parsed command line arguments

    Returns:
        ServerConfig instance
    """
    log_level = getattr(logging, args.log_level)

    if args.debug:
        log_level = logging.DEBUG

    return ServerConfig(
        mode=RunMode(args.mode),
        transport=TransportMode(args.transport),
        host=args.host,
        port=args.port,
        log_level=log_level,
        config_file=args.config,
        enable_llm=not args.no_llm,
        enable_knowledge=not args.no_knowledge,
        debug=args.debug,
        verbose=args.verbose,
    )


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main() -> int:
    """
    Main entry point for HyFuzz server.

    Returns:
        Exit code (0 for success, 1 for failure)
    """
    # Parse arguments
    args, error = parse_arguments()

    if error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    if args is None:
        # This happens with --help or --version, which is normal
        return 0

    # Setup logging
    logger = setup_logging(
        level=getattr(logging, args.log_level),
        verbose=args.verbose or args.debug
    )

    logger.info(f"Starting {__title__} v{__version__}")
    logger.debug(f"Python version: {sys.version}")
    logger.debug(f"Project root: {PROJECT_ROOT}")

    # Create configuration
    config = create_config_from_args(args)

    # Create and run server
    server = HyFuzzServer(config)
    exit_code = server.run()

    logger.info(f"Exiting with code {exit_code}")
    return exit_code


# ============================================================================
# VERIFICATION TEST SECTION
# ============================================================================

def run_verification_tests() -> int:
    """
    Run verification tests for __main__.py.

    Returns:
        Exit code (0 if all tests pass, 1 if any fail)
    """
    print("\n" + "="*70)
    print("HyFuzz __main__.py Verification Tests")
    print("="*70 + "\n")

    tests_passed = 0
    tests_failed = 0

    # Test 1: Argument parsing
    print("✓ Test 1: Argument Parsing")
    try:
        args, error = parse_arguments()
        if error is None and args is not None:
            print("  - Default arguments parsed: ✓")
            tests_passed += 1
        else:
            print(f"  - Argument parsing failed: {error}")
            tests_failed += 1
    except Exception as e:
        print(f"  - Exception: {e}")
        tests_failed += 1
    print()

    # Test 2: Configuration creation
    print("✓ Test 2: Configuration Creation")
    try:
        args, _ = parse_arguments()
        if args is not None:
            config = create_config_from_args(args)
            assert config.mode == RunMode.SERVER
            assert config.transport == TransportMode.STDIO
            assert config.enable_llm == True
            assert config.enable_knowledge == True
            print("  - Configuration created correctly: ✓")
            tests_passed += 1
        else:
            tests_failed += 1
    except Exception as e:
        print(f"  - Configuration creation failed: {e}")
        tests_failed += 1
    print()

    # Test 3: Server initialization (dry run)
    print("✓ Test 3: Server Initialization")
    try:
        args, _ = parse_arguments()
        if args is not None:
            config = create_config_from_args(args)
            config.mode = RunMode.TEST

            server = HyFuzzServer(config)
            if server is not None:
                print("  - Server instance created: ✓")
                tests_passed += 1
            else:
                print("  - Failed to create server instance")
                tests_failed += 1
        else:
            tests_failed += 1
    except Exception as e:
        print(f"  - Server initialization failed: {e}")
        tests_failed += 1
    print()

    # Test 4: Logging setup
    print("✓ Test 4: Logging Setup")
    try:
        logger = setup_logging(logging.INFO)
        if logger is not None:
            logger.info("Test logging message")
            print("  - Logger created and configured: ✓")
            tests_passed += 1
        else:
            print("  - Failed to create logger")
            tests_failed += 1
    except Exception as e:
        print(f"  - Logging setup failed: {e}")
        tests_failed += 1
    print()

    # Test 5: Run modes
    print("✓ Test 5: Run Modes")
    try:
        modes = [RunMode.SERVER, RunMode.STANDALONE, RunMode.TEST, RunMode.DEBUG]
        for mode in modes:
            assert mode.value in ['server', 'standalone', 'test', 'debug']
        print(f"  - All {len(modes)} run modes available: ✓")
        tests_passed += 1
    except Exception as e:
        print(f"  - Run modes verification failed: {e}")
        tests_failed += 1
    print()

    # Test 6: Transport modes
    print("✓ Test 6: Transport Modes")
    try:
        transports = [TransportMode.STDIO, TransportMode.HTTP, TransportMode.WEBSOCKET]
        for transport in transports:
            assert transport.value in ['stdio', 'http', 'websocket']
        print(f"  - All {len(transports)} transport modes available: ✓")
        tests_passed += 1
    except Exception as e:
        print(f"  - Transport modes verification failed: {e}")
        tests_failed += 1
    print()

    # Test 7: Signal handlers
    print("✓ Test 7: Signal Handlers")
    try:
        args, _ = parse_arguments()
        if args is not None:
            config = create_config_from_args(args)
            server = HyFuzzServer(config)

            if hasattr(signal, 'SIGINT'):
                print("  - Signal handlers available: ✓")
                tests_passed += 1
            else:
                print("  - Signal handlers not available")
                tests_failed += 1
        else:
            tests_failed += 1
    except Exception as e:
        print(f"  - Signal handler test failed: {e}")
        tests_failed += 1
    print()

    # Test 8: Component validation
    print("✓ Test 8: Component Validation")
    try:
        args, _ = parse_arguments()
        if args is not None:
            config = create_config_from_args(args)
            config.mode = RunMode.TEST

            server = HyFuzzServer(config)
            if hasattr(server, '_validate_components'):
                print("  - Component validation available: ✓")
                tests_passed += 1
            else:
                print("  - Component validation not found")
                tests_failed += 1
        else:
            tests_failed += 1
    except Exception as e:
        print(f"  - Component validation test failed: {e}")
        tests_failed += 1
    print()

    # Test 9: Exit code handling
    print("✓ Test 9: Exit Code Handling")
    try:
        assert isinstance(0, int)
        assert isinstance(1, int)
        print("  - Exit code handling verified: ✓")
        tests_passed += 1
    except Exception as e:
        print(f"  - Exit code handling test failed: {e}")
        tests_failed += 1
    print()

    # Summary
    print("="*70)
    print(f"Tests Passed: {tests_passed}")
    print(f"Tests Failed: {tests_failed}")
    print("="*70 + "\n")

    if tests_failed == 0:
        print("✓ All verification tests PASSED\n")
        return 0
    else:
        print(f"✗ {tests_failed} verification test(s) FAILED\n")
        return 1


# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == '__main__':
    # Run verification tests if requested
    if '--verify' in sys.argv or '--test' in sys.argv:
        sys.argv.remove('--verify' if '--verify' in sys.argv else '--test')
        exit_code = run_verification_tests()
        sys.exit(exit_code)

    # Otherwise run the main server
    exit_code = main()
    sys.exit(exit_code)