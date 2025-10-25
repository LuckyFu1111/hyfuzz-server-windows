# ==============================================================================
# HyFuzz Server - LLM Module Initialization
# File: src/llm/__init__.py
# ==============================================================================
"""
LLM Integration Module

This module provides comprehensive Large Language Model (LLM) integration
for the HyFuzz vulnerability detection framework, including:

Core Components:
- LLMClient: Ollama-based LLM client for model inference
- LLMService: High-level service layer for LLM operations
- CoTEngine: Chain-of-Thought reasoning engine for intelligent payload generation
- PromptBuilder: Structured prompt construction with template support
- EmbeddingManager: Vector embedding generation and similarity search
- CacheManager: Response caching for performance optimization
- TokenCounter: Token estimation and cost calculation
- ResponseParser: Structured output parsing and validation

Features:
- Async/await support for non-blocking operations
- Multi-model support (Mistral, Llama2, Neural-Chat, Dolphin)
- Intelligent caching with TTL support
- Chain-of-Thought reasoning for complex problem solving
- Vector embeddings for semantic search
- Token counting and cost estimation
- Comprehensive error handling and logging
- Performance monitoring and metrics

Usage:
    from src.llm import LLMService, CoTEngine, PromptBuilder

    # Initialize LLM service
    llm_service = LLMService()

    # Generate payload with CoT reasoning
    response = await llm_service.generate_payload(
        cwe_id="CWE-79",
        protocol="http",
        context={"target_version": "1.0"}
    )

    # Search semantic embeddings
    similar = await llm_service.search_similar_payloads(
        query_embedding=[...],
        limit=10
    )

Example - Full Workflow:
    from src.llm import LLMService, PromptBuilder, CoTEngine
    from src.knowledge import VulnerabilityDB

    # Setup
    db = VulnerabilityDB()
    llm_service = LLMService()

    # Get vulnerability info
    cwe = await db.get_cwe("CWE-79")

    # Build CoT prompt
    prompt = await PromptBuilder.build_cot_prompt(
        vulnerability=cwe,
        context={"protocol": "http"}
    )

    # Generate payload with reasoning
    payload, reasoning = await CoTEngine.reason(prompt)

    # Cache result
    await llm_service.cache_payload(payload)

Performance Notes:
- First inference ~2-5 seconds (model loading)
- Subsequent inferences ~0.5-2 seconds (cached model)
- Embedding generation ~0.1-0.5 seconds per text
- Cache hit rate typically 70-80% in fuzzing scenarios

Compatibility:
- Python 3.9+
- Ollama 0.1.0+
- CUDA/ROCm optional but recommended for GPU acceleration
- CPU-only inference supported (slower)

See Also:
- docs/LLM_INTEGRATION.md - Detailed integration guide
- tests/integration/test_llm_pipeline.py - Integration tests
- tests/unit/test_llm_*.py - Unit tests

Author: HyFuzz Team
Version: 1.0.0
License: MIT
"""

import logging
import sys
from typing import Dict, List, Optional, Any, Tuple, Union
from pathlib import Path
from enum import Enum

# ==============================================================================
# VERSION INFORMATION
# ==============================================================================

__version__ = "1.0.0"
__author__ = "HyFuzz Contributors"
__email__ = "support@hyfuzz.ai"
__license__ = "MIT"
__copyright__ = "Copyright (c) 2025 HyFuzz Contributors"

# Module metadata
__title__ = "hyfuzz-llm"
__description__ = "LLM Integration Module for HyFuzz Vulnerability Detection Framework"
__url__ = "https://github.com/your-org/hyfuzz-server-windows"
__docs_url__ = "https://github.com/your-org/hyfuzz-server-windows/tree/main/docs"

# ==============================================================================
# EXPORTS AND PUBLIC API
# ==============================================================================

# Core LLM components (imported from submodules)
__all__ = [
    # Version and metadata
    "__version__",
    "__author__",
    "__email__",
    "__license__",
    "__title__",
    "__description__",

    # Main service classes
    "LLMClient",
    "LLMService",
    "CoTEngine",
    "PromptBuilder",
    "EmbeddingManager",
    "CacheManager",
    "TokenCounter",
    "ResponseParser",

    # Data models
    "PayloadRequest",
    "PayloadResponse",
    "CoTReasoning",
    "EmbeddingResult",

    # Enums and constants
    "LLMProvider",
    "ModelType",
    "CacheStrategy",
    "ResponseFormat",

    # Utility functions
    "get_llm_logger",
    "initialize_llm_service",
    "create_llm_client",

    # Configuration
    "LLM_CONFIG",
    "SUPPORTED_MODELS",
    "DEFAULT_SETTINGS",
]


# ==============================================================================
# LAZY IMPORTS - Import on demand to improve startup time
# ==============================================================================

def __getattr__(name: str) -> Any:
    """
    Lazy import handler for LLM module components

    Allows for on-demand imports without blocking startup time.
    Components are imported only when first accessed.

    Args:
        name: Name of the attribute to import

    Returns:
        The imported module or class

    Raises:
        AttributeError: If attribute cannot be found
    """

    # Lazy imports mapping
    lazy_imports = {
        "LLMClient": "src.llm.llm_client",
        "LLMService": "src.llm.llm_service",
        "CoTEngine": "src.llm.cot_engine",
        "PromptBuilder": "src.llm.prompt_builder",
        "EmbeddingManager": "src.llm.embedding_manager",
        "CacheManager": "src.llm.cache_manager",
        "TokenCounter": "src.llm.token_counter",
        "ResponseParser": "src.llm.response_parser",
        "PayloadRequest": "src.models.llm_models",
        "PayloadResponse": "src.models.llm_models",
        "CoTReasoning": "src.models.llm_models",
        "EmbeddingResult": "src.models.llm_models",
    }

    if name in lazy_imports:
        module_path = lazy_imports[name]
        module_name, class_name = module_path.rsplit(".", 1)

        try:
            module = __import__(module_path, fromlist=[class_name])
            return getattr(module, class_name, None)
        except (ImportError, AttributeError) as e:
            logger = logging.getLogger(__name__)
            logger.warning(f"Failed to lazy import {name} from {module_path}: {e}")
            raise AttributeError(f"module '{__name__}' has no attribute '{name}'")

    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")


# ==============================================================================
# ENUMS AND CONSTANTS
# ==============================================================================

class LLMProvider(str, Enum):
    """Supported LLM providers"""
    OLLAMA = "ollama"
    OPENAI = "openai"
    LOCAL = "local"
    CUSTOM = "custom"


class ModelType(str, Enum):
    """Supported LLM model types"""
    MISTRAL = "mistral"
    LLAMA2 = "llama2"
    NEURAL_CHAT = "neural-chat"
    DOLPHIN = "dolphin"
    GPT_35_TURBO = "gpt-3.5-turbo"
    GPT_4 = "gpt-4"


class CacheStrategy(str, Enum):
    """Caching strategies for LLM responses"""
    NO_CACHE = "no_cache"
    TTL_BASED = "ttl_based"
    LRU = "lru"
    LFU = "lfu"


class ResponseFormat(str, Enum):
    """Response format options"""
    TEXT = "text"
    JSON = "json"
    STRUCTURED = "structured"
    STREAMING = "streaming"


# Model configuration and support
SUPPORTED_MODELS = {
    "mistral": {
        "provider": LLMProvider.OLLAMA,
        "parameters": 7,  # 7B parameters
        "context_length": 32768,
        "recommended": True,
        "description": "Mistral 7B - Fast and efficient model"
    },
    "llama2": {
        "provider": LLMProvider.OLLAMA,
        "parameters": 13,  # 13B parameters
        "context_length": 4096,
        "recommended": False,
        "description": "Llama 2 13B - Balanced performance"
    },
    "neural-chat": {
        "provider": LLMProvider.OLLAMA,
        "parameters": 7,  # 7B parameters
        "context_length": 8192,
        "recommended": True,
        "description": "Neural Chat 7B - Good for reasoning"
    },
    "dolphin": {
        "provider": LLMProvider.OLLAMA,
        "parameters": 7,  # 7B parameters
        "context_length": 16384,
        "recommended": True,
        "description": "Dolphin 7B - Excellent reasoning capabilities"
    },
    "gpt-3.5-turbo": {
        "provider": LLMProvider.OPENAI,
        "parameters": None,  # Proprietary
        "context_length": 4096,
        "recommended": False,
        "description": "OpenAI GPT-3.5 Turbo"
    },
    "gpt-4": {
        "provider": LLMProvider.OPENAI,
        "parameters": None,  # Proprietary
        "context_length": 8192,
        "recommended": False,
        "description": "OpenAI GPT-4"
    },
}

# Default configuration
DEFAULT_SETTINGS = {
    "provider": LLMProvider.OLLAMA,
    "model": ModelType.MISTRAL,
    "temperature": 0.7,
    "top_p": 0.9,
    "top_k": 40,
    "max_tokens": 2048,
    "min_tokens": 100,
    "timeout": 120,
    "retry_count": 3,
    "cache_enabled": True,
    "cache_strategy": CacheStrategy.TTL_BASED,
    "cache_ttl": 3600,  # 1 hour
    "max_cache_size": 1000,
    "embedding_model": "nomic-embed-text",
    "embedding_dimension": 768,
    "batch_size": 32,
    "num_workers": 4,
}

# LLM configuration (can be overridden via config files)
LLM_CONFIG: Dict[str, Any] = DEFAULT_SETTINGS.copy()

# ==============================================================================
# LOGGING SETUP
# ==============================================================================

# Get module logger
logger = logging.getLogger(__name__)

# Configure logging if not already configured
if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


def get_llm_logger(name: str) -> logging.Logger:
    """
    Get a logger instance for LLM submodules

    Args:
        name: Logger name (typically module name)

    Returns:
        Configured logger instance
    """
    return logging.getLogger(f"src.llm.{name}")


# ==============================================================================
# UTILITY FUNCTIONS
# ==============================================================================

async def initialize_llm_service(
        provider: str = "ollama",
        model: str = "mistral",
        **kwargs
) -> "LLMService":
    """
    Initialize LLM service with specified configuration

    This is the recommended way to initialize the LLM service with
    proper error handling and logging.

    Args:
        provider: LLM provider name (ollama, openai, etc.)
        model: Model name to use
        **kwargs: Additional configuration options

    Returns:
        Initialized LLMService instance

    Raises:
        ValueError: If provider or model is not supported
        ConnectionError: If connection to LLM provider fails

    Example:
        service = await initialize_llm_service(
            provider="ollama",
            model="mistral",
            temperature=0.8
        )
    """
    from src.llm.llm_service import LLMService

    logger.info(f"Initializing LLM service with {provider}/{model}")

    # Validate provider and model
    if model not in SUPPORTED_MODELS:
        raise ValueError(
            f"Model '{model}' not supported. "
            f"Supported models: {', '.join(SUPPORTED_MODELS.keys())}"
        )

    config = LLM_CONFIG.copy()
    config.update(kwargs)
    config["provider"] = provider
    config["model"] = model

    try:
        service = LLMService(**config)
        await service.initialize()
        logger.info(f"LLM service initialized successfully")
        return service
    except Exception as e:
        logger.error(f"Failed to initialize LLM service: {e}")
        raise


def create_llm_client(
        provider: str = "ollama",
        model: str = "mistral",
        base_url: str = "http://localhost:11434",
        **kwargs
) -> "LLMClient":
    """
    Create and configure an LLM client

    Args:
        provider: LLM provider (ollama, openai, etc.)
        model: Model name to use
        base_url: Base URL for the LLM service
        **kwargs: Additional configuration

    Returns:
        Configured LLMClient instance

    Example:
        client = create_llm_client(
            provider="ollama",
            model="mistral",
            base_url="http://localhost:11434"
        )
    """
    from src.llm.llm_client import LLMClient

    logger.info(f"Creating LLM client: {provider}/{model} at {base_url}")

    config = DEFAULT_SETTINGS.copy()
    config.update(kwargs)
    config["provider"] = provider
    config["model"] = model
    config["base_url"] = base_url

    try:
        client = LLMClient(**config)
        logger.info("LLM client created successfully")
        return client
    except Exception as e:
        logger.error(f"Failed to create LLM client: {e}")
        raise


def get_model_info(model_name: str) -> Dict[str, Any]:
    """
    Get information about a specific model

    Args:
        model_name: Name of the model

    Returns:
        Model information dictionary

    Raises:
        ValueError: If model not found
    """
    if model_name not in SUPPORTED_MODELS:
        raise ValueError(
            f"Model '{model_name}' not found. "
            f"Available models: {', '.join(SUPPORTED_MODELS.keys())}"
        )

    return SUPPORTED_MODELS[model_name].copy()


def list_supported_models() -> Dict[str, Dict[str, Any]]:
    """
    List all supported models with their information

    Returns:
        Dictionary of model information keyed by model name
    """
    return {
        name: info.copy()
        for name, info in SUPPORTED_MODELS.items()
    }


def list_recommended_models() -> List[str]:
    """
    Get list of recommended models for fuzzing

    Returns:
        List of recommended model names
    """
    return [
        name
        for name, info in SUPPORTED_MODELS.items()
        if info.get("recommended", False)
    ]


# ==============================================================================
# MODULE INITIALIZATION
# ==============================================================================

def _initialize_module():
    """
    Initialize the LLM module on import

    This is called automatically when the module is imported.
    """
    logger.debug(f"Initializing LLM module v{__version__}")
    logger.debug(f"Supported models: {', '.join(SUPPORTED_MODELS.keys())}")
    logger.debug(f"Default provider: {DEFAULT_SETTINGS['provider'].value}")


# Initialize on import
_initialize_module()


# ==============================================================================
# UNIT TESTS
# ==============================================================================

async def run_tests():
    """
    Comprehensive test suite for LLM module initialization and API
    """
    import asyncio
    from datetime import datetime

    print("\n" + "=" * 70)
    print("LLM MODULE INITIALIZATION TESTS")
    print("=" * 70 + "\n")

    test_passed = 0
    test_failed = 0

    try:
        # Test 1: Version information
        print("[TEST 1] Checking version information...")
        if __version__ and __author__ and __license__:
            print(f"✓ PASSED: Version {__version__}, Author: {__author__}\n")
            test_passed += 1
        else:
            print("✗ FAILED: Missing version information\n")
            test_failed += 1

        # Test 2: Enum definitions
        print("[TEST 2] Checking Enum definitions...")
        try:
            assert LLMProvider.OLLAMA.value == "ollama"
            assert ModelType.MISTRAL.value == "mistral"
            assert CacheStrategy.TTL_BASED.value == "ttl_based"
            assert ResponseFormat.TEXT.value == "text"
            print("✓ PASSED: All Enums properly defined\n")
            test_passed += 1
        except Exception as e:
            print(f"✗ FAILED: Enum error - {e}\n")
            test_failed += 1

        # Test 3: Supported models
        print("[TEST 3] Checking supported models...")
        try:
            models = list_supported_models()
            if len(models) >= 4:
                print(f"✓ PASSED: Found {len(models)} supported models")
                for model_name in list(models.keys())[:3]:
                    print(f"  - {model_name}")
                print()
                test_passed += 1
            else:
                print(f"✗ FAILED: Expected at least 4 models, found {len(models)}\n")
                test_failed += 1
        except Exception as e:
            print(f"✗ FAILED: {e}\n")
            test_failed += 1

        # Test 4: Get model info
        print("[TEST 4] Getting model information...")
        try:
            info = get_model_info("mistral")
            assert info["provider"] == LLMProvider.OLLAMA
            assert info["context_length"] == 32768
            print(f"✓ PASSED: Retrieved model info for 'mistral'")
            print(f"  - Parameters: {info['parameters']}B")
            print(f"  - Context Length: {info['context_length']}\n")
            test_passed += 1
        except Exception as e:
            print(f"✗ FAILED: {e}\n")
            test_failed += 1

        # Test 5: Recommended models
        print("[TEST 5] Getting recommended models...")
        try:
            recommended = list_recommended_models()
            if len(recommended) >= 2:
                print(f"✓ PASSED: Found {len(recommended)} recommended models:")
                for model in recommended:
                    print(f"  - {model}")
                print()
                test_passed += 1
            else:
                print(f"✗ FAILED: Expected at least 2 recommended models\n")
                test_failed += 1
        except Exception as e:
            print(f"✗ FAILED: {e}\n")
            test_failed += 1

        # Test 6: Logger creation
        print("[TEST 6] Testing logger functionality...")
        try:
            test_logger = get_llm_logger("test_module")
            assert test_logger.name == "src.llm.test_module"
            print(f"✓ PASSED: Logger created with name '{test_logger.name}'\n")
            test_passed += 1
        except Exception as e:
            print(f"✗ FAILED: {e}\n")
            test_failed += 1

        # Test 7: Default settings
        print("[TEST 7] Checking default settings...")
        try:
            assert LLM_CONFIG["provider"] == LLMProvider.OLLAMA
            assert LLM_CONFIG["model"] == ModelType.MISTRAL
            assert LLM_CONFIG["temperature"] == 0.7
            assert LLM_CONFIG["max_tokens"] == 2048
            print(f"✓ PASSED: Default settings properly configured")
            print(f"  - Provider: {LLM_CONFIG['provider'].value}")
            print(f"  - Model: {LLM_CONFIG['model'].value}")
            print(f"  - Temperature: {LLM_CONFIG['temperature']}\n")
            test_passed += 1
        except Exception as e:
            print(f"✗ FAILED: {e}\n")
            test_failed += 1

        # Test 8: Invalid model error handling
        print("[TEST 8] Testing error handling for invalid model...")
        try:
            info = get_model_info("invalid-model")
            print("✗ FAILED: Should have raised ValueError for invalid model\n")
            test_failed += 1
        except ValueError as e:
            print(f"✓ PASSED: Correctly raised ValueError")
            print(f"  - Error message: {str(e)[:50]}...\n")
            test_passed += 1
        except Exception as e:
            print(f"✗ FAILED: Wrong exception type - {e}\n")
            test_failed += 1

        # Test 9: Public API exports
        print("[TEST 9] Checking public API exports...")
        try:
            exports_present = all(item in __all__ for item in [
                "LLMClient", "LLMService", "CoTEngine", "PromptBuilder",
                "EmbeddingManager", "CacheManager", "TokenCounter",
                "ResponseParser", "__version__"
            ])
            if exports_present:
                print(f"✓ PASSED: All major components in __all__")
                print(f"  - Total exports: {len(__all__)}\n")
                test_passed += 1
            else:
                print("✗ FAILED: Missing exports in __all__\n")
                test_failed += 1
        except Exception as e:
            print(f"✗ FAILED: {e}\n")
            test_failed += 1

        # Test 10: Module metadata
        print("[TEST 10] Verifying module metadata...")
        try:
            assert __title__
            assert __description__
            assert __url__
            assert __docs_url__
            print(f"✓ PASSED: Module metadata complete")
            print(f"  - Title: {__title__}")
            print(f"  - License: {__license__}\n")
            test_passed += 1
        except Exception as e:
            print(f"✗ FAILED: {e}\n")
            test_failed += 1

    except Exception as e:
        print(f"✗ TEST ERROR: {e}\n")
        test_failed += 1

    # Summary
    print("=" * 70)
    print(f"TEST SUMMARY: {test_passed} PASSED, {test_failed} FAILED")
    print(f"Success Rate: {(test_passed / (test_passed + test_failed) * 100):.1f}%")
    print("=" * 70 + "\n")

    return test_passed, test_failed


# ==============================================================================
# ENTRY POINT
# ==============================================================================

if __name__ == "__main__":
    import asyncio

    # Run tests
    asyncio.run(run_tests())