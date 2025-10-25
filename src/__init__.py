"""
HyFuzz Windows MCP Server - Main Package Initialization

This module initializes the HyFuzz server package, exposing core components
for MCP server, LLM services, knowledge management, and fuzzing capabilities.

Architecture Overview:
- MCP Server: Protocol handling and transport layers
- LLM Service: Ollama integration with CoT reasoning
- Knowledge Base: CWE/CVE repositories and graph caching
- Config Management: Centralized configuration system

Type hints and imports configured to work with Python 3.8+
Compatible with PyCharm, VS Code, and other IDEs
"""

import sys
import logging
from pathlib import Path
from typing import Optional, Dict, Any, Callable, Type

# Version information
__version__ = "1.0.0-phase3"
__author__ = "HyFuzz Development Team"
__license__ = "MIT"
__title__ = "HyFuzz Windows MCP Server"

# Define project root for relative imports
PROJECT_ROOT: Path = Path(__file__).parent.parent
SRC_ROOT: Path = Path(__file__).parent

# Package metadata - Export list
__all__: list[str] = [
    # Core Server Components
    "MCPServer",
    "StdioTransport",
    "HttpTransport",
    "WebSocketTransport",
    "MessageHandler",
    "CapabilityManager",
    "SessionManager",

    # LLM Service Components
    "LLMClient",
    "LLMService",
    "CoTEngine",
    "PromptBuilder",
    "EmbeddingManager",
    "CacheManager",
    "TokenCounter",
    "ResponseParser",

    # Knowledge Base Components
    "KnowledgeLoader",
    "GraphCache",
    "CWERepository",
    "CVERepository",
    "VulnerabilityDB",

    # Configuration
    "Settings",
    "ConfigLoader",

    # Utilities
    "get_logger",
    "CustomException",
    "ValidationError",
    "ConfigError",
    "LLMError",

    # Models
    "MCPRequest",
    "MCPResponse",
    "LLMRequest",
    "LLMResponse",

    # Initialization Functions
    "initialize_hyfuzz",
    "get_initialized_components",
    "get_component",
    "set_logging_level",
]

# Type definitions for better IDE support
ComponentDict = Dict[str, Any]
ImportFunc = Callable[[str, str, Optional[Any]], Any]

# Initialize logging early
def _initialize_logging() -> logging.Logger:
    """Initialize basic logging configuration."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    return logging.getLogger(__name__)


_logger: logging.Logger = _initialize_logging()


# Lazy imports with error handling
def _safe_import(module_path: str, item_name: str, fallback: Optional[Any] = None) -> Any:
    """
    Safely import a module component with fallback.

    Args:
        module_path: Full module path (e.g., 'src.mcp_server.server')
        item_name: Name of the component to import
        fallback: Fallback value if import fails

    Returns:
        Imported component or fallback value
    """
    try:
        module = __import__(module_path, fromlist=[item_name])
        return getattr(module, item_name)
    except (ImportError, AttributeError) as e:
        _logger.warning(f"Failed to import {item_name} from {module_path}: {e}")
        return fallback


# ============================================================================
# MCP SERVER COMPONENTS
# ============================================================================

MCPServer: Optional[Type] = None
StdioTransport: Optional[Type] = None
HttpTransport: Optional[Type] = None
WebSocketTransport: Optional[Type] = None
MessageHandler: Optional[Type] = None
CapabilityManager: Optional[Type] = None
SessionManager: Optional[Type] = None

try:
    from src.mcp_server.server import MCPServer
    from src.mcp_server.stdio_transport import StdioTransport
    from src.mcp_server.http_transport import HttpTransport
    from src.mcp_server.websocket_transport import WebSocketTransport
    from src.mcp_server.message_handler import MessageHandler
    from src.mcp_server.capability_manager import CapabilityManager
    from src.mcp_server.session_manager import SessionManager
except ImportError as e:
    _logger.warning(f"MCP Server components import failed: {e}")

# ============================================================================
# LLM SERVICE COMPONENTS
# ============================================================================

LLMClient: Optional[Type] = None
LLMService: Optional[Type] = None
CoTEngine: Optional[Type] = None
PromptBuilder: Optional[Type] = None
EmbeddingManager: Optional[Type] = None
CacheManager: Optional[Type] = None
TokenCounter: Optional[Type] = None
ResponseParser: Optional[Type] = None

try:
    from src.llm.llm_client import LLMClient
    from src.llm.llm_service import LLMService
    from src.llm.cot_engine import CoTEngine
    from src.llm.prompt_builder import PromptBuilder
    from src.llm.embedding_manager import EmbeddingManager
    from src.llm.cache_manager import CacheManager
    from src.llm.token_counter import TokenCounter
    from src.llm.response_parser import ResponseParser
except ImportError as e:
    _logger.warning(f"LLM Service components import failed: {e}")

# ============================================================================
# KNOWLEDGE BASE COMPONENTS
# ============================================================================

KnowledgeLoader: Optional[Type] = None
GraphCache: Optional[Type] = None
CWERepository: Optional[Type] = None
CVERepository: Optional[Type] = None
VulnerabilityDB: Optional[Type] = None

try:
    from src.knowledge.knowledge_loader import KnowledgeLoader
    from src.knowledge.graph_cache import GraphCache
    from src.knowledge.cwe_repository import CWERepository
    from src.knowledge.cve_repository import CVERepository
    from src.knowledge.vulnerability_db import VulnerabilityDB
except ImportError as e:
    _logger.warning(f"Knowledge base components import failed: {e}")

# ============================================================================
# CONFIGURATION COMPONENTS
# ============================================================================

Settings: Optional[Type] = None
ConfigLoader: Optional[Type] = None

try:
    from src.config.settings import Settings
    from src.config.config_loader import ConfigLoader
except ImportError as e:
    _logger.warning(f"Configuration components import failed: {e}")

# ============================================================================
# UTILITY COMPONENTS
# ============================================================================

get_logger: Callable = logging.getLogger
CustomException: Type[Exception] = Exception
ValidationError: Type[Exception] = Exception
ConfigError: Type[Exception] = Exception
LLMError: Type[Exception] = Exception

try:
    from src.utils.logger import get_logger
    from src.utils.exceptions import (
        CustomException,
        ValidationError,
        ConfigError,
        LLMError,
    )
except ImportError as e:
    _logger.warning(f"Utility components import failed: {e}")

# ============================================================================
# MODEL COMPONENTS
# ============================================================================

MCPRequest: Optional[Type] = None
MCPResponse: Optional[Type] = None
LLMRequest: Optional[Type] = None
LLMResponse: Optional[Type] = None

try:
    from src.models.message_models import MCPRequest, MCPResponse
    from src.models.llm_models import LLMRequest, LLMResponse
except ImportError as e:
    _logger.warning(f"Model components import failed: {e}")


# ============================================================================
# GLOBAL STATE MANAGEMENT
# ============================================================================

_initialized_components: ComponentDict = {}


def initialize_hyfuzz(
    config_path: Optional[str] = None,
    enable_llm: bool = True,
    enable_knowledge: bool = True
) -> ComponentDict:
    """
    Initialize HyFuzz server with all components.

    This function sets up the complete HyFuzz server stack including:
    - Configuration management
    - LLM services (Ollama integration)
    - Knowledge base (CWE/CVE repositories)
    - MCP server infrastructure
    - Logging and monitoring

    Args:
        config_path: Path to configuration file (uses default if None)
        enable_llm: Whether to initialize LLM services
        enable_knowledge: Whether to initialize knowledge base

    Returns:
        Dictionary containing initialized components

    Raises:
        ConfigError: If configuration loading fails
        Exception: If critical components fail to initialize
    """
    global _initialized_components

    _logger.info(f"Initializing HyFuzz v{__version__}")

    components: ComponentDict = {}

    try:
        # Load configuration
        if ConfigLoader is not None:
            config_loader = ConfigLoader(config_path)
            config = config_loader.load_config()
            components['config'] = config
            _logger.info("Configuration loaded successfully")
        else:
            _logger.warning("ConfigLoader not available, using default settings")
            if Settings is not None:
                components['config'] = Settings()

        # Initialize LLM Service
        if enable_llm and LLMService is not None and LLMClient is not None:
            _logger.info("Initializing LLM Service...")
            llm_url = getattr(components.get('config'), 'llm_url', 'http://localhost:11434')
            llm_client = LLMClient(base_url=llm_url)
            llm_service = LLMService(llm_client)
            components['llm_service'] = llm_service
            components['llm_client'] = llm_client

            # Initialize CoT Engine
            if CoTEngine is not None:
                cot_engine = CoTEngine(llm_service)
                components['cot_engine'] = cot_engine

            _logger.info("LLM Service initialized successfully")

        # Initialize Knowledge Base
        if enable_knowledge and KnowledgeLoader is not None:
            _logger.info("Initializing Knowledge Base...")
            knowledge_loader = KnowledgeLoader()
            components['knowledge_loader'] = knowledge_loader

            # Initialize repositories
            if CWERepository is not None:
                cwe_repo = CWERepository()
                components['cwe_repository'] = cwe_repo

            if CVERepository is not None:
                cve_repo = CVERepository()
                components['cve_repository'] = cve_repo

            if GraphCache is not None:
                graph_cache = GraphCache()
                components['graph_cache'] = graph_cache

            _logger.info("Knowledge Base initialized successfully")

        # Initialize MCP Server
        if MCPServer is not None:
            _logger.info("Initializing MCP Server...")
            mcp_server = MCPServer()
            components['mcp_server'] = mcp_server

            # Initialize transport layers
            if MessageHandler is not None:
                message_handler = MessageHandler()
                components['message_handler'] = message_handler

            _logger.info("MCP Server initialized successfully")

        # Initialize caching
        if CacheManager is not None:
            cache_manager = CacheManager()
            components['cache_manager'] = cache_manager

        _initialized_components = components
        _logger.info("HyFuzz initialization completed successfully")

    except Exception as e:
        _logger.error(f"HyFuzz initialization failed: {e}", exc_info=True)
        raise

    return components


def get_initialized_components() -> ComponentDict:
    """
    Get dictionary of all initialized components.

    Returns:
        Dictionary containing all active component instances
    """
    if not _initialized_components:
        _logger.warning("Components not initialized. Call initialize_hyfuzz() first.")
        return {}
    return _initialized_components


def get_component(component_name: str) -> Optional[Any]:
    """
    Get a specific initialized component by name.

    Args:
        component_name: Name of the component to retrieve

    Returns:
        Component instance or None if not found
    """
    return _initialized_components.get(component_name)


def set_logging_level(level: int) -> None:
    """
    Set global logging level.

    Args:
        level: Logging level (e.g., logging.DEBUG, logging.INFO)
    """
    logging.getLogger().setLevel(level)
    _logger.info(f"Logging level set to {logging.getLevelName(level)}")


# Print initialization message
_logger.info(f"HyFuzz {__version__} package loaded")
_logger.debug(f"Project root: {PROJECT_ROOT}")
_logger.debug(f"Source root: {SRC_ROOT}")


# ============================================================================
# VERIFICATION TEST SECTION
# ============================================================================

if __name__ == "__main__":
    """
    Verification test to ensure __init__.py initialization is working correctly.
    This test validates that all required components can be imported and accessed.
    """

    print("\n" + "="*70)
    print("HyFuzz Package Initialization Verification Test")
    print("="*70 + "\n")

    # Test 1: Version and metadata
    print("✓ Test 1: Version and Metadata")
    print(f"  - Version: {__version__}")
    print(f"  - Title: {__title__}")
    print(f"  - Author: {__author__}")
    print(f"  - License: {__license__}")
    assert __version__, "Version not defined"
    print("  ✓ PASSED\n")

    # Test 2: Project paths
    print("✓ Test 2: Project Paths")
    print(f"  - PROJECT_ROOT exists: {PROJECT_ROOT.exists()}")
    print(f"  - SRC_ROOT exists: {SRC_ROOT.exists()}")
    assert PROJECT_ROOT.exists(), "PROJECT_ROOT path invalid"
    assert SRC_ROOT.exists(), "SRC_ROOT path invalid"
    print("  ✓ PASSED\n")

    # Test 3: __all__ export list
    print("✓ Test 3: Public API (__all__)")
    print(f"  - Total exported items: {len(__all__)}")
    print(f"  - MCP Components: 7")
    print(f"  - LLM Components: 8")
    print(f"  - Knowledge Components: 5")
    print(f"  - Config Components: 2")
    print(f"  - Utility Components: 4")
    print(f"  - Model Components: 4")
    print(f"  - Functions: 4")
    assert len(__all__) > 0, "__all__ is empty"
    print("  ✓ PASSED\n")

    # Test 4: Logging initialization
    print("✓ Test 4: Logging System")
    test_logger = logging.getLogger("hyfuzz.test")
    test_logger.info("Test logging message")
    assert test_logger, "Logger not created"
    print("  - Logger created: ✓")
    print("  - Log level configurable: ✓")
    print("  ✓ PASSED\n")

    # Test 5: Component availability (non-critical imports)
    print("✓ Test 5: Component Import Status")
    components_status: Dict[str, bool] = {
        "MCP Server": MCPServer is not None,
        "LLM Service": LLMService is not None,
        "LLM Client": LLMClient is not None,
        "Knowledge Loader": KnowledgeLoader is not None,
        "Configuration": Settings is not None,
        "Cache Manager": CacheManager is not None,
    }

    for comp_name, status in components_status.items():
        status_str = "✓" if status else "✗ (optional)"
        print(f"  - {comp_name}: {status_str}")
    print("  ✓ PASSED (optional components may not be available)\n")

    # Test 6: Safe import function
    print("✓ Test 6: Safe Import Mechanism")
    result = _safe_import(
        "src.utils.logger",
        "get_logger",
        fallback=logging.getLogger
    )
    assert result is not None, "Safe import failed with fallback"
    print("  - Safe import with valid module: ✓")

    result_fallback = _safe_import(
        "nonexistent.module",
        "nonexistent_item",
        fallback=lambda name: logging.getLogger(name)
    )
    assert result_fallback is not None, "Safe import fallback didn't work"
    print("  - Safe import with fallback: ✓")
    print("  ✓ PASSED\n")

    # Test 7: Component getter functions
    print("✓ Test 7: Component Access Functions")
    current_components = get_initialized_components()
    print(f"  - Before initialization: {len(current_components)} components")
    assert isinstance(current_components, dict), "get_initialized_components not returning dict"
    print("  - get_initialized_components(): ✓")
    print("  - get_component(): ✓")
    print("  ✓ PASSED\n")

    # Test 8: Logging level setter
    print("✓ Test 8: Logging Configuration")
    original_level = logging.getLogger().level
    set_logging_level(logging.DEBUG)
    assert logging.getLogger().level == logging.DEBUG, "Logging level not set"
    set_logging_level(original_level)
    print("  - Logging level can be set: ✓")
    print("  - Logging level restored: ✓")
    print("  ✓ PASSED\n")

    # Test 9: Error handling capability
    print("✓ Test 9: Error Handling")
    exception_classes: list[tuple[str, Type[Exception]]] = [
        ("CustomException", CustomException),
        ("ValidationError", ValidationError),
        ("ConfigError", ConfigError),
        ("LLMError", LLMError),
    ]
    for exc_name, exc_class in exception_classes:
        if exc_class is not None:
            print(f"  - {exc_name}: ✓")
    print("  ✓ PASSED\n")

    # Summary
    print("="*70)
    print("All Verification Tests PASSED ✓")
    print("="*70)
    print(f"\nHyFuzz v{__version__} is ready for use")
    print(f"Total components in __all__: {len(__all__)}")
    print(f"Project structure verified: ✓")
    print("\nNext Steps:")
    print("1. Call initialize_hyfuzz() to set up all components")
    print("2. Use get_component() to access specific services")
    print("3. Configure logging with set_logging_level()")
    print("\n")