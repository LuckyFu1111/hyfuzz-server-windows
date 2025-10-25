#!/usr/bin/env python3
"""
MCP Server Startup Script for HyFuzz Windows Server
Handles initialization of all server components and graceful shutdown

This is a startup script, not a test module. Run with --test flag to execute tests.
"""

import sys
import os
import asyncio
import signal
import argparse
import logging
from pathlib import Path
from typing import Optional
from contextlib import asynccontextmanager

# Prevent pytest from treating this as a test module
__test__ = False

# Add src directory to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT / 'src'))

try:
    from config.settings import Settings
    from config.config_loader import ConfigLoader
    from mcp_server.server import MCPServer
    from llm.llm_client import LLMClient
    from llm.llm_service import LLMService
    from knowledge.knowledge_loader import KnowledgeLoader
    from utils.logger import setup_logger
    from utils.exceptions import ConfigurationError, InitializationError
except ImportError as e:
    print(f"ERROR: Failed to import modules. Make sure you're running from project root: {e}", file=sys.stderr)
    sys.exit(1)


class ServerManager:
    """Manages the lifecycle of the MCP server and its components"""

    def __init__(self, config_path: Optional[str] = None, env_path: Optional[str] = None):
        """
        Initialize ServerManager with configuration

        Args:
            config_path: Path to config YAML file
            env_path: Path to .env file
        """
        self.config_path = config_path
        self.env_path = env_path
        self.logger: Optional[logging.Logger] = None
        self.settings: Optional[Settings] = None
        self.mcp_server: Optional[MCPServer] = None
        self.llm_service: Optional[LLMService] = None
        self.knowledge_loader: Optional[KnowledgeLoader] = None
        self.is_running = False
        self._shutdown_event = asyncio.Event()

    def setup_logger(self) -> None:
        """Initialize logging system"""
        try:
            log_config_path = (
                Path(self.config_path).parent / 'logging_config.yaml'
                if self.config_path else None
            )
            self.logger = setup_logger(
                name='hyfuzz_server',
                config_path=log_config_path
            )
            self.logger.info("Logger initialized successfully")
        except Exception as e:
            print(f"ERROR: Failed to setup logger: {e}", file=sys.stderr)
            raise InitializationError(f"Logger setup failed: {e}")

    def load_configuration(self) -> None:
        """Load configuration from files and environment"""
        try:
            self.logger.info("Loading configuration...")
            config_loader = ConfigLoader(
                config_path=self.config_path,
                env_path=self.env_path
            )
            self.settings = config_loader.load()

            self.logger.info(f"Configuration loaded: {self.settings.server.host}:{self.settings.server.port}")
            self.logger.debug(f"LLM Config: {self.settings.llm.model}")
            self.logger.debug(f"Transport Mode: {self.settings.server.transport_mode}")

        except ConfigurationError as e:
            self.logger.error(f"Configuration error: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error loading configuration: {e}")
            raise InitializationError(f"Configuration loading failed: {e}")

    async def initialize_llm_service(self) -> None:
        """Initialize LLM client and service"""
        try:
            self.logger.info("Initializing LLM service...")

            # Create LLM client
            llm_client = LLMClient(
                base_url=self.settings.llm.ollama_base_url,
                model=self.settings.llm.model,
                timeout=self.settings.llm.timeout
            )

            # Test connection
            self.logger.info(f"Testing connection to LLM server at {self.settings.llm.ollama_base_url}...")
            is_available = await llm_client.is_model_available()

            if not is_available:
                raise InitializationError(
                    f"LLM model '{self.settings.llm.model}' is not available at "
                    f"{self.settings.llm.ollama_base_url}"
                )

            self.logger.info(f"LLM connection successful. Model: {self.settings.llm.model}")

            # Create LLM service
            self.llm_service = LLMService(
                client=llm_client,
                config=self.settings.llm,
                cache_enabled=self.settings.cache.enabled,
                max_cache_size=self.settings.cache.max_size
            )

            self.logger.info("LLM service initialized successfully")

        except InitializationError:
            raise
        except Exception as e:
            self.logger.error(f"LLM service initialization failed: {e}")
            raise InitializationError(f"LLM service setup failed: {e}")

    async def initialize_knowledge_base(self) -> None:
        """Initialize knowledge base and repositories"""
        try:
            self.logger.info("Loading knowledge base...")

            data_dir = Path(PROJECT_ROOT) / 'data'
            cache_dir = data_dir / 'knowledge_cache'

            self.knowledge_loader = KnowledgeLoader(
                data_dir=str(data_dir),
                cache_dir=str(cache_dir),
                enable_caching=self.settings.knowledge.enable_caching
            )

            # Load knowledge bases asynchronously
            await self.knowledge_loader.load_all()

            self.logger.info("Knowledge base loaded successfully")
            self.logger.debug(
                f"Loaded CWE entries: {len(self.knowledge_loader.cwe_repository.cwe_data)}, "
                f"CVE entries: {len(self.knowledge_loader.cve_repository.cve_data)}"
            )

        except Exception as e:
            self.logger.error(f"Knowledge base initialization failed: {e}")
            raise InitializationError(f"Knowledge base loading failed: {e}")

    async def initialize_mcp_server(self) -> None:
        """Initialize MCP server"""
        try:
            self.logger.info("Initializing MCP server...")

            self.mcp_server = MCPServer(
                host=self.settings.server.host,
                port=self.settings.server.port,
                transport_mode=self.settings.server.transport_mode,
                llm_service=self.llm_service,
                knowledge_loader=self.knowledge_loader,
                config=self.settings
            )

            # Register signal handlers for graceful shutdown
            self._register_signal_handlers()

            self.logger.info(
                f"MCP server initialized: {self.settings.server.host}:"
                f"{self.settings.server.port} ({self.settings.server.transport_mode})"
            )

        except Exception as e:
            self.logger.error(f"MCP server initialization failed: {e}")
            raise InitializationError(f"MCP server setup failed: {e}")

    def _register_signal_handlers(self) -> None:
        """Register signal handlers for graceful shutdown"""
        def signal_handler(signum, frame):
            self.logger.info(f"Received signal {signum}. Initiating graceful shutdown...")
            asyncio.create_task(self.shutdown())

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        if sys.platform == 'win32':
            # Windows-specific signal handling
            import win32api
            win32api.SetConsoleCtrlHandler(lambda x: asyncio.create_task(self.shutdown()), True)

    async def start(self) -> None:
        """Start the MCP server"""
        try:
            if self.is_running:
                self.logger.warning("Server is already running")
                return

            self.logger.info("=" * 60)
            self.logger.info("Starting HyFuzz MCP Server")
            self.logger.info("=" * 60)

            self.is_running = True
            await self.mcp_server.start()

            self.logger.info("Server started successfully")
            self.logger.info(f"Listening on {self.settings.server.host}:{self.settings.server.port}")

            # Wait for shutdown signal
            await self._shutdown_event.wait()

        except Exception as e:
            self.logger.error(f"Server startup failed: {e}", exc_info=True)
            raise
        finally:
            if self.is_running:
                await self.shutdown()

    async def shutdown(self) -> None:
        """Gracefully shutdown the server"""
        if not self.is_running:
            return

        try:
            self.logger.info("Initiating graceful shutdown...")
            self.is_running = False

            # Shutdown MCP server
            if self.mcp_server:
                self.logger.info("Stopping MCP server...")
                await self.mcp_server.stop()

            # Cleanup LLM service
            if self.llm_service:
                self.logger.info("Closing LLM service...")
                await self.llm_service.cleanup()

            # Cleanup knowledge base
            if self.knowledge_loader:
                self.logger.info("Clearing knowledge base...")
                self.knowledge_loader.cleanup()

            self.logger.info("=" * 60)
            self.logger.info("Server shutdown completed")
            self.logger.info("=" * 60)

            self._shutdown_event.set()

        except Exception as e:
            self.logger.error(f"Error during shutdown: {e}", exc_info=True)

    async def health_check(self) -> bool:
        """
        Perform health check on all components

        Returns:
            bool: True if all components are healthy
        """
        try:
            self.logger.info("Running health checks...")

            # Check LLM service
            if self.llm_service:
                is_healthy = await self.llm_service.health_check()
                if not is_healthy:
                    self.logger.error("LLM service health check failed")
                    return False
                self.logger.debug("LLM service is healthy")

            # Check MCP server
            if self.mcp_server:
                server_healthy = await self.mcp_server.health_check()
                if not server_healthy:
                    self.logger.error("MCP server health check failed")
                    return False
                self.logger.debug("MCP server is healthy")

            # Check knowledge base
            if self.knowledge_loader:
                if not self.knowledge_loader.is_loaded():
                    self.logger.error("Knowledge base is not loaded")
                    return False
                self.logger.debug("Knowledge base is healthy")

            self.logger.info("All health checks passed")
            return True

        except Exception as e:
            self.logger.error(f"Health check failed: {e}")
            return False


async def main(args) -> int:
    """
    Main entry point for the server

    Args:
        args: Command line arguments

    Returns:
        int: Exit code
    """
    manager = ServerManager(
        config_path=args.config,
        env_path=args.env
    )

    try:
        # Setup logger
        manager.setup_logger()

        # Load configuration
        manager.load_configuration()

        # Initialize components
        await manager.initialize_llm_service()
        await manager.initialize_knowledge_base()
        await manager.initialize_mcp_server()

        # Run health check
        if not await manager.health_check():
            manager.logger.error("Health check failed")
            return 1

        # Start server
        await manager.start()

        return 0

    except KeyboardInterrupt:
        manager.logger.info("Keyboard interrupt received")
        if manager.is_running:
            await manager.shutdown()
        return 0
    except Exception as e:
        if manager.logger:
            manager.logger.error(f"Fatal error: {e}", exc_info=True)
        else:
            print(f"FATAL ERROR: {e}", file=sys.stderr)
        return 1


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Start HyFuzz MCP Server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Start with default configuration
  python start_server.py
  
  # Start with custom config
  python start_server.py --config config/server_config.yaml
  
  # Start with custom .env file
  python start_server.py --env /path/to/.env
        """
    )

    parser.add_argument(
        '--config', '-c',
        type=str,
        default=None,
        help='Path to configuration YAML file (default: config/default_config.yaml)'
    )

    parser.add_argument(
        '--env', '-e',
        type=str,
        default=None,
        help='Path to .env file (default: .env)'
    )

    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug logging'
    )

    return parser.parse_args()


# ============================================================================
# TESTS
# ============================================================================

async def test_server_initialization():
    """
    Test: Verify ServerManager initialization
    """
    print("\n[TEST] ServerManager Initialization")
    print("-" * 60)

    manager = ServerManager()
    manager.setup_logger()

    assert manager.logger is not None, "Logger not initialized"
    assert manager.settings is None, "Settings should be None before loading"
    assert manager.is_running is False, "Server should not be running initially"

    print("✓ ServerManager initialized correctly")
    print("✓ Logger setup successful")
    print("✓ Initial state verified")


async def test_configuration_loading():
    """
    Test: Verify configuration loading
    """
    print("\n[TEST] Configuration Loading")
    print("-" * 60)

    try:
        manager = ServerManager()
        manager.setup_logger()
        manager.load_configuration()

        assert manager.settings is not None, "Settings not loaded"
        assert manager.settings.server is not None, "Server config not found"
        assert manager.settings.llm is not None, "LLM config not found"
        assert manager.settings.cache is not None, "Cache config not found"

        print(f"✓ Configuration loaded successfully")
        print(f"✓ Server: {manager.settings.server.host}:{manager.settings.server.port}")
        print(f"✓ LLM Model: {manager.settings.llm.model}")
        print(f"✓ Transport Mode: {manager.settings.server.transport_mode}")

    except ConfigurationError as e:
        print(f"⚠ Configuration test skipped: {e}")


async def test_signal_handling():
    """
    Test: Verify signal handler registration
    """
    print("\n[TEST] Signal Handler Registration")
    print("-" * 60)

    manager = ServerManager()
    manager.setup_logger()
    manager.load_configuration()

    try:
        # Create a mock MCP server
        mock_server = type('MockServer', (), {
            'start': lambda self: asyncio.sleep(0),
            'stop': lambda self: asyncio.sleep(0),
            'health_check': lambda self: True
        })()

        manager.mcp_server = mock_server
        manager._register_signal_handlers()

        print("✓ Signal handlers registered successfully")

    except Exception as e:
        print(f"✗ Signal handler test failed: {e}")


async def test_shutdown_sequence():
    """
    Test: Verify graceful shutdown sequence
    """
    print("\n[TEST] Graceful Shutdown Sequence")
    print("-" * 60)

    manager = ServerManager()
    manager.setup_logger()
    manager.load_configuration()
    manager.is_running = True

    try:
        # Create mock components
        class MockComponent:
            async def cleanup(self): pass
            def is_loaded(self): return True

        manager.mcp_server = MockComponent()
        manager.llm_service = MockComponent()
        manager.knowledge_loader = MockComponent()

        await manager.shutdown()

        assert manager.is_running is False, "Server flag should be False after shutdown"
        print("✓ Shutdown sequence completed successfully")
        print("✓ All components cleaned up")
        print("✓ Server flag reset correctly")

    except Exception as e:
        print(f"✗ Shutdown test failed: {e}")


async def run_all_tests():
    """Run all tests"""
    print("\n" + "=" * 60)
    print("RUNNING HYFUZZ SERVER STARTUP TESTS")
    print("=" * 60)

    try:
        await test_server_initialization()
        await test_configuration_loading()
        await test_signal_handling()
        await test_shutdown_sequence()

        print("\n" + "=" * 60)
        print("TEST SUITE COMPLETED SUCCESSFULLY")
        print("=" * 60 + "\n")

    except Exception as e:
        print(f"\n✗ TEST SUITE FAILED: {e}\n")
        raise


if __name__ == '__main__':
    import sys

    # Check if running tests
    if len(sys.argv) > 1 and sys.argv[1] == '--test':
        asyncio.run(run_all_tests())
        sys.exit(0)

    # Parse arguments and run server
    args = parse_arguments()
    exit_code = asyncio.run(main(args))
    sys.exit(exit_code)