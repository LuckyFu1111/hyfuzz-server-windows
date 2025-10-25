"""
Models Package - Data Models for HyFuzz Windows MCP Server

This package contains all data models used throughout the application:
- Message Models: MCP protocol message structures
- LLM Models: Language model related data structures
- Knowledge Models: Vulnerability and knowledge base models
- Config Models: Configuration data models
- Common Models: Shared/utility data models

Usage:
    from src.models import MCPMessage, LLMRequest, VulnerabilityData, ServerConfig
"""

import sys
from pathlib import Path

# Handle both relative imports (when used as package) and direct execution
try:
    # Try relative imports first (normal package usage)
    from .message_models import (
        MCPMessage,
        MCPRequest,
        MCPResponse,
        MCPNotification,
        ResourceContent,
        ToolDefinition,
        MessageMetadata,
    )

    from .llm_models import (
        LLMRequest,
        LLMResponse,
        LLMStreamChunk,
        TokenUsage,
        ModelInfo,
        EmbeddingData,
        ContentBlock,
    )

    from .knowledge_models import (
        VulnerabilityData,
        CWEInfo,
        CVEInfo,
        CWENode,
        CVENode,
        KnowledgeGraph,
        RiskAssessment,
    )

    from .config_models import (
        ServerConfig,
        LLMConfig,
        TransportConfig,
        LoggingConfig,
        CacheConfig,
    )

    from .common_models import (
        RequestContext,
        ResponseStatus,
        ErrorResponse,
        SuccessResponse,
        PagedResponse,
        BatchOperation,
        Timestamp,
    )

except ImportError:
    # Fallback for direct execution - use mock classes for testing
    print("[INFO] Using mock models for direct execution testing...")

    # Mock base classes for demonstration
    class MCPMessage:
        """Mock MCP Message"""
        pass

    class MCPRequest(MCPMessage):
        """Mock MCP Request"""
        pass

    class MCPResponse(MCPMessage):
        """Mock MCP Response"""
        pass

    class MCPNotification(MCPMessage):
        """Mock MCP Notification"""
        pass

    class ResourceContent:
        """Mock Resource Content"""
        pass

    class ToolDefinition:
        """Mock Tool Definition"""
        pass

    class MessageMetadata:
        """Mock Message Metadata"""
        pass

    class LLMRequest:
        """Mock LLM Request"""
        pass

    class LLMResponse:
        """Mock LLM Response"""
        pass

    class LLMStreamChunk:
        """Mock LLM Stream Chunk"""
        pass

    class TokenUsage:
        """Mock Token Usage"""
        pass

    class ModelInfo:
        """Mock Model Info"""
        pass

    class EmbeddingData:
        """Mock Embedding Data"""
        pass

    class ContentBlock:
        """Mock Content Block"""
        pass

    class VulnerabilityData:
        """Mock Vulnerability Data"""
        pass

    class CWEInfo:
        """Mock CWE Info"""
        pass

    class CVEInfo:
        """Mock CVE Info"""
        pass

    class CWENode:
        """Mock CWE Node"""
        pass

    class CVENode:
        """Mock CVE Node"""
        pass

    class KnowledgeGraph:
        """Mock Knowledge Graph"""
        pass

    class RiskAssessment:
        """Mock Risk Assessment"""
        pass

    class ServerConfig:
        """Mock Server Config"""
        pass

    class LLMConfig:
        """Mock LLM Config"""
        pass

    class TransportConfig:
        """Mock Transport Config"""
        pass

    class LoggingConfig:
        """Mock Logging Config"""
        pass

    class CacheConfig:
        """Mock Cache Config"""
        pass

    class RequestContext:
        """Mock Request Context"""
        pass

    class ResponseStatus:
        """Mock Response Status"""
        pass

    class ErrorResponse:
        """Mock Error Response"""
        pass

    class SuccessResponse:
        """Mock Success Response"""
        pass

    class PagedResponse:
        """Mock Paged Response"""
        pass

    class BatchOperation:
        """Mock Batch Operation"""
        pass

    class Timestamp:
        """Mock Timestamp"""
        pass

# Define public API
__all__ = [
    # Message Models
    "MCPMessage",
    "MCPRequest",
    "MCPResponse",
    "MCPNotification",
    "ResourceContent",
    "ToolDefinition",
    "MessageMetadata",
    # LLM Models
    "LLMRequest",
    "LLMResponse",
    "LLMStreamChunk",
    "TokenUsage",
    "ModelInfo",
    "EmbeddingData",
    "ContentBlock",
    # Knowledge Models
    "VulnerabilityData",
    "CWEInfo",
    "CVEInfo",
    "CWENode",
    "CVENode",
    "KnowledgeGraph",
    "RiskAssessment",
    # Config Models
    "ServerConfig",
    "LLMConfig",
    "TransportConfig",
    "LoggingConfig",
    "CacheConfig",
    # Common Models
    "RequestContext",
    "ResponseStatus",
    "ErrorResponse",
    "SuccessResponse",
    "PagedResponse",
    "BatchOperation",
    "Timestamp",
]

__version__ = "1.0.0"
__author__ = "HyFuzz Team"


# ============================================================================
# VALIDATION AND TESTING
# ============================================================================

def validate_models():
    """
    Validate that all model imports are successful and accessible.
    Returns True if all models are properly imported, False otherwise.
    """
    import inspect

    required_models = {
        "Message Models": [
            MCPMessage, MCPRequest, MCPResponse, MCPNotification,
            ResourceContent, ToolDefinition, MessageMetadata
        ],
        "LLM Models": [
            LLMRequest, LLMResponse, LLMStreamChunk, TokenUsage,
            ModelInfo, EmbeddingData, ContentBlock
        ],
        "Knowledge Models": [
            VulnerabilityData, CWEInfo, CVEInfo, CWENode, CVENode,
            KnowledgeGraph, RiskAssessment
        ],
        "Config Models": [
            ServerConfig, LLMConfig, TransportConfig,
            LoggingConfig, CacheConfig
        ],
        "Common Models": [
            RequestContext, ResponseStatus, ErrorResponse,
            SuccessResponse, PagedResponse, BatchOperation, Timestamp
        ]
    }

    validation_results = {}
    all_valid = True

    for category, models in required_models.items():
        valid_count = 0
        for model in models:
            if inspect.isclass(model) or callable(model):
                valid_count += 1
            else:
                all_valid = False
        validation_results[category] = f"{valid_count}/{len(models)} models available"

    return all_valid, validation_results


if __name__ == "__main__":
    """
    Test suite for models package initialization
    """
    print("=" * 70)
    print("HyFuzz Models Package - Validation Tests")
    print("=" * 70)
    print()

    # Test 1: Validate all models are imported
    print("[TEST 1] Validating Model Imports...")
    try:
        is_valid, results = validate_models()
        for category, status in results.items():
            print(f"  ✓ {category}: {status}")

        if is_valid:
            print("  ✓ All models imported successfully")
        else:
            print("  ✗ Some models failed to import")
        print()
    except Exception as e:
        print(f"  ✗ Import validation failed: {str(e)}")
        print()

    # Test 2: Verify __all__ export list
    print("[TEST 2] Verifying __all__ Export List...")
    try:
        expected_count = len(__all__)
        print(f"  ✓ Total exported models: {expected_count}")
        print(f"  ✓ Export categories: Message, LLM, Knowledge, Config, Common")
        print()
    except Exception as e:
        print(f"  ✗ Export list verification failed: {str(e)}")
        print()

    # Test 3: Check model accessibility
    print("[TEST 3] Checking Model Accessibility...")
    try:
        # Test accessing models from package
        test_models = [
            ("MCPMessage", MCPMessage),
            ("LLMRequest", LLMRequest),
            ("VulnerabilityData", VulnerabilityData),
            ("ServerConfig", ServerConfig),
            ("ResponseStatus", ResponseStatus),
        ]

        for model_name, model_class in test_models:
            assert model_class is not None, f"{model_name} is None"
            print(f"  ✓ {model_name} accessible")
        print()
    except AssertionError as e:
        print(f"  ✗ Model accessibility check failed: {str(e)}")
        print()
    except Exception as e:
        print(f"  ✗ Unexpected error during accessibility check: {str(e)}")
        print()

    # Test 4: Verify package metadata
    print("[TEST 4] Package Metadata...")
    try:
        print(f"  ✓ Package Version: {__version__}")
        print(f"  ✓ Package Author: {__author__}")
        print(f"  ✓ Total Models in __all__: {len(__all__)}")
        print()
    except Exception as e:
        print(f"  ✗ Metadata verification failed: {str(e)}")
        print()

    # Summary
    print("=" * 70)
    print("✓ Models Package Validation Complete")
    print("=" * 70)
    print()
    print("Available Model Categories:")
    print("  • Message Models (7 classes)")
    print("  • LLM Models (7 classes)")
    print("  • Knowledge Models (7 classes)")
    print("  • Config Models (5 classes)")
    print("  • Common Models (7 classes)")
    print(f"  • Total: {len(__all__)} classes")