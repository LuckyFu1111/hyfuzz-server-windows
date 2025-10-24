"""
HyFuzz MCP Server - Mock LLM Module

This module provides comprehensive mock implementations of LLM-related components
for testing the HyFuzz MCP server without requiring actual Ollama/LLM service.

Key Features:
- MockLLMClient: Simulates Ollama LLM client
- MockLLMService: Simulates LLM service layer
- MockEmbeddingManager: Simulates embedding generation
- MockCacheManager: Simulates LLM response caching
- MockCoTEngine: Simulates Chain-of-Thought reasoning
- Deterministic responses with configurable behavior
- Token counting simulation
- Response parsing utilities

Usage:
    >>> from tests.fixtures.mock_llm import MockLLMClient, create_mock_response
    >>> 
    >>> # Create mock client
    >>> client = MockLLMClient(model="mistral")
    >>> 
    >>> # Generate response
    >>> response = client.generate_payload(
    ...     cwe_id="CWE-79",
    ...     protocol="http"
    ... )
    >>> 
    >>> # Get cached response
    >>> cached = client.get_cached_response("CWE-79-http")

Author: HyFuzz Team
Version: 1.0.0
"""

import json
import time
import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timezone
import hashlib

try:
    import tiktoken
    TIKTOKEN_AVAILABLE = True
except ImportError:
    TIKTOKEN_AVAILABLE = False


# Initialize logger
logger = logging.getLogger(__name__)


# ==============================================================================
# Constants
# ==============================================================================

# Default mock responses
DEFAULT_MODELS = ["mistral", "llama2", "neural-chat"]
DEFAULT_TEMPERATURE = 0.7
DEFAULT_MAX_TOKENS = 2048

# Response generation parameters
MIN_RESPONSE_TIME_MS = 50
MAX_RESPONSE_TIME_MS = 300
DETERMINISTIC_SEED = 42


# ==============================================================================
# Enumerations
# ==============================================================================

class ModelType(str, Enum):
    """Supported LLM model types."""
    MISTRAL = "mistral"
    LLAMA2 = "llama2"
    NEURAL_CHAT = "neural-chat"
    DOLPHIN = "dolphin"


class ResponseType(str, Enum):
    """Type of mock response."""
    SUCCESS = "success"
    PARTIAL = "partial"
    ERROR = "error"
    TIMEOUT = "timeout"


# ==============================================================================
# Data Classes
# ==============================================================================

@dataclass
class MockLLMResponse:
    """Mock LLM response data structure."""
    text: str
    model: str
    tokens_used: int
    completion_tokens: int
    prompt_tokens: int
    response_time_ms: float
    stop_reason: str = "stop"
    finish_time: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    response_type: ResponseType = ResponseType.SUCCESS

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "text": self.text,
            "model": self.model,
            "tokens_used": self.tokens_used,
            "completion_tokens": self.completion_tokens,
            "prompt_tokens": self.prompt_tokens,
            "response_time_ms": self.response_time_ms,
            "stop_reason": self.stop_reason,
            "finish_time": self.finish_time,
            "response_type": self.response_type.value,
        }


@dataclass
class MockCacheEntry:
    """Cached mock LLM response."""
    key: str
    response: MockLLMResponse
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    access_count: int = 0
    last_accessed: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def update_access(self) -> None:
        """Update access information."""
        self.access_count += 1
        self.last_accessed = datetime.now(timezone.utc).isoformat()


# ==============================================================================
# Mock LLM Client
# ==============================================================================

class MockLLMClient:
    """
    Mock LLM client that simulates Ollama API responses.
    
    Provides deterministic responses for testing without requiring actual LLM.
    """

    def __init__(
        self,
        model: str = "mistral",
        temperature: float = DEFAULT_TEMPERATURE,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        enable_cache: bool = True,
        response_delay_ms: int = 100,
        seed: int = DETERMINISTIC_SEED,
    ):
        """
        Initialize mock LLM client.
        
        Args:
            model: Model name
            temperature: Temperature for response generation
            max_tokens: Maximum tokens in response
            enable_cache: Enable response caching
            response_delay_ms: Simulated response delay
            seed: Random seed for deterministic responses
        """
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.enable_cache = enable_cache
        self.response_delay_ms = response_delay_ms
        self.seed = seed

        # Cache management
        self.cache: Dict[str, MockCacheEntry] = {}
        self.call_count = 0
        self.cache_hits = 0

        # Request history
        self.request_history: List[Dict[str, Any]] = []

        logger.info(
            f"MockLLMClient initialized: model={model}, "
            f"cache={'enabled' if enable_cache else 'disabled'}"
        )

    # ========================================================================
    # Public Methods
    # ========================================================================

    def generate(
        self,
        prompt: str,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        use_cache: bool = True,
    ) -> MockLLMResponse:
        """
        Generate mock LLM response.
        
        Args:
            prompt: Input prompt
            temperature: Override temperature
            max_tokens: Override max tokens
            use_cache: Use cache if available
            
        Returns:
            MockLLMResponse with generated content
        """
        self.call_count += 1

        # Check cache first
        cache_key = self._generate_cache_key(prompt)
        if use_cache and self.enable_cache and cache_key in self.cache:
            self.cache_hits += 1
            entry = self.cache[cache_key]
            entry.update_access()
            logger.debug(f"Cache hit for prompt: {prompt[:50]}...")
            return entry.response

        # Generate response
        temp = temperature or self.temperature
        tokens = max_tokens or self.max_tokens

        response = self._generate_response(prompt, temp, tokens)

        # Cache result
        if self.enable_cache:
            self._cache_response(cache_key, response)

        # Record request
        self._record_request(prompt, response)

        return response

    def generate_payload(
        self,
        cwe_id: str,
        protocol: str,
        target_version: Optional[str] = None,
        encoding: str = "none",
        count: int = 1,
    ) -> Dict[str, Any]:
        """
        Generate mock payloads for given CWE and protocol.
        
        Args:
            cwe_id: CWE identifier
            protocol: Target protocol
            target_version: Target service version
            encoding: Payload encoding type
            count: Number of payloads to generate
            
        Returns:
            Dictionary with generated payloads
        """
        prompt = self._build_payload_prompt(
            cwe_id, protocol, target_version, encoding, count
        )

        response = self.generate(prompt)

        # Parse payloads from response
        payloads = self._parse_payloads(response.text, count)

        return {
            "payloads": payloads,
            "cwe_id": cwe_id,
            "protocol": protocol,
            "encoding": encoding,
            "count": count,
            "response_time_ms": response.response_time_ms,
            "tokens_used": response.tokens_used,
        }

    def generate_cot_reasoning(
        self,
        cwe_id: str,
        protocol: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Generate Chain-of-Thought reasoning.
        
        Args:
            cwe_id: CWE identifier
            protocol: Target protocol
            context: Additional context
            
        Returns:
            Dictionary with reasoning chain
        """
        prompt = self._build_cot_prompt(cwe_id, protocol, context)
        response = self.generate(prompt)

        reasoning_chain = self._parse_reasoning_chain(response.text)

        return {
            "vulnerability": cwe_id,
            "protocol": protocol,
            "reasoning_chain": reasoning_chain,
            "response_time_ms": response.response_time_ms,
            "confidence_score": self._calculate_confidence(reasoning_chain),
        }

    def get_cached_response(self, cache_key: str) -> Optional[MockLLMResponse]:
        """
        Get cached response by key.
        
        Args:
            cache_key: Cache key
            
        Returns:
            Cached response or None
        """
        if cache_key in self.cache:
            entry = self.cache[cache_key]
            entry.update_access()
            return entry.response
        return None

    def clear_cache(self) -> None:
        """Clear all cached responses."""
        count = len(self.cache)
        self.cache.clear()
        logger.debug(f"Cleared cache: {count} entries removed")

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get client statistics.
        
        Returns:
            Dictionary with statistics
        """
        total_requests = self.call_count
        hit_rate = (
            (self.cache_hits / total_requests * 100) 
            if total_requests > 0 else 0
        )

        return {
            "total_requests": total_requests,
            "cache_hits": self.cache_hits,
            "cache_misses": total_requests - self.cache_hits,
            "hit_rate_percent": round(hit_rate, 2),
            "cached_entries": len(self.cache),
            "model": self.model,
            "temperature": self.temperature,
        }

    # ========================================================================
    # Private Methods
    # ========================================================================

    def _generate_response(
        self,
        prompt: str,
        temperature: float,
        max_tokens: int,
    ) -> MockLLMResponse:
        """Generate mock response."""
        # Simulate response delay
        start_time = time.time()
        time.sleep(self.response_delay_ms / 1000.0)

        # Generate deterministic response based on prompt
        response_text = self._generate_content(prompt, temperature)

        # Calculate tokens
        prompt_tokens = self._count_tokens(prompt)
        completion_tokens = self._count_tokens(response_text)
        tokens_used = prompt_tokens + completion_tokens

        response_time_ms = (time.time() - start_time) * 1000

        return MockLLMResponse(
            text=response_text,
            model=self.model,
            tokens_used=tokens_used,
            completion_tokens=completion_tokens,
            prompt_tokens=prompt_tokens,
            response_time_ms=response_time_ms,
        )

    def _generate_content(self, prompt: str, temperature: float) -> str:
        """Generate response content based on prompt."""
        prompt_lower = prompt.lower()

        # XSS payload generation
        if "xss" in prompt_lower or "cwe-79" in prompt_lower:
            return (
                "Generated XSS payloads:\n"
                '1. <img src=x onerror="alert(\'XSS\')">\n'
                '2. <svg onload=alert("XSS")>\n'
                '3. <iframe onload="alert(\'XSS\')">\n'
                "Reasoning: These payloads exploit improper input sanitization "
                "in the application by injecting JavaScript event handlers."
            )

        # SQL injection payload generation
        elif "sql" in prompt_lower or "cwe-89" in prompt_lower:
            return (
                "Generated SQL injection payloads:\n"
                "1. ' OR '1'='1\n"
                "2. 1; DROP TABLE users; --\n"
                "3. ' UNION SELECT NULL,username,password FROM users--\n"
                "Reasoning: These payloads break out of the SQL context and "
                "inject malicious SQL commands."
            )

        # Command injection payload generation
        elif "command" in prompt_lower or "cwe-78" in prompt_lower:
            return (
                "Generated command injection payloads:\n"
                "1. ; cat /etc/passwd #\n"
                "2. | whoami\n"
                "3. & ipconfig\n"
                "Reasoning: These payloads use shell metacharacters to chain "
                "commands after the original input."
            )

        # Path traversal payload generation
        elif "path" in prompt_lower or "cwe-22" in prompt_lower:
            return (
                "Generated path traversal payloads:\n"
                "1. ../../../../etc/passwd\n"
                "2. ..\\..\\..\\windows\\system32\\config\\sam\n"
                "3. ..%2f..%2f..%2fetc%2fpasswd\n"
                "Reasoning: These payloads traverse directory structure to access "
                "files outside the intended directory."
            )

        # Default response
        else:
            return (
                f"This is a mock LLM response for prompt: {prompt[:100]}...\n"
                f"Model: {self.model}\n"
                f"Temperature: {self.temperature}\n"
                "This is a deterministic response for testing purposes."
            )

    def _build_payload_prompt(
        self,
        cwe_id: str,
        protocol: str,
        target_version: Optional[str],
        encoding: str,
        count: int,
    ) -> str:
        """Build prompt for payload generation."""
        return (
            f"Generate {count} {protocol} payloads for {cwe_id} "
            f"(target version: {target_version or 'any'}) "
            f"with {encoding} encoding."
        )

    def _build_cot_prompt(
        self,
        cwe_id: str,
        protocol: str,
        context: Optional[Dict[str, Any]],
    ) -> str:
        """Build Chain-of-Thought reasoning prompt."""
        ctx_str = json.dumps(context) if context else "no context"
        return (
            f"Generate Chain-of-Thought reasoning for exploiting {cwe_id} "
            f"via {protocol} protocol. Context: {ctx_str}"
        )

    def _parse_payloads(self, text: str, count: int) -> List[str]:
        """Extract payloads from response text."""
        payloads = []
        lines = text.split("\n")

        payload_count = 0
        for line in lines:
            line = line.strip()
            # Extract numbered payloads
            if line and any(line.startswith(f"{i}.") for i in range(1, count + 1)):
                payload = line.split(".", 1)[1].strip()
                if payload:
                    payloads.append(payload)
                    payload_count += 1
                    if payload_count >= count:
                        break

        # Fallback if parsing failed
        if not payloads:
            payloads = [f"payload_{i}" for i in range(1, count + 1)]

        return payloads

    def _parse_reasoning_chain(self, text: str) -> List[str]:
        """Extract reasoning chain from response text."""
        reasoning_steps = []
        lines = text.split("\n")

        for line in lines:
            line = line.strip()
            if line.startswith("Step") or line.startswith("step"):
                reasoning_steps.append(line)

        # Add text if no steps found
        if not reasoning_steps:
            reasoning_steps = [text]

        return reasoning_steps

    def _calculate_confidence(self, reasoning_chain: List[str]) -> float:
        """Calculate confidence based on reasoning chain."""
        # Longer chains = higher confidence
        base_confidence = 0.7
        chain_bonus = min(len(reasoning_chain) * 0.05, 0.25)
        return min(base_confidence + chain_bonus, 0.99)

    def _count_tokens(self, text: str) -> int:
        """Estimate token count."""
        if TIKTOKEN_AVAILABLE:
            try:
                encoding = tiktoken.get_encoding("cl100k_base")
                return len(encoding.encode(text))
            except Exception:
                pass

        # Fallback: simple estimation
        return len(text.split()) + len(text) // 50

    def _generate_cache_key(self, prompt: str) -> str:
        """Generate cache key from prompt."""
        return hashlib.md5(prompt.encode()).hexdigest()

    def _cache_response(self, key: str, response: MockLLMResponse) -> None:
        """Cache response."""
        entry = MockCacheEntry(key=key, response=response)
        self.cache[key] = entry
        logger.debug(f"Cached response with key: {key}")

    def _record_request(
        self,
        prompt: str,
        response: MockLLMResponse,
    ) -> None:
        """Record request in history."""
        self.request_history.append({
            "prompt": prompt,
            "model": self.model,
            "response_time_ms": response.response_time_ms,
            "tokens_used": response.tokens_used,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })


# ==============================================================================
# Mock LLM Service
# ==============================================================================

class MockLLMService:
    """
    Mock LLM service that wraps the mock client.
    
    Provides higher-level functionality for payload generation and analysis.
    """

    def __init__(
        self,
        client: Optional[MockLLMClient] = None,
        enable_caching: bool = True,
    ):
        """
        Initialize mock LLM service.
        
        Args:
            client: MockLLMClient instance (creates new if None)
            enable_caching: Enable response caching
        """
        self.client = client or MockLLMClient(enable_cache=enable_caching)
        self.enable_caching = enable_caching
        self.generated_payloads: Dict[str, List[str]] = {}

    def generate_payloads(
        self,
        cwe_id: str,
        protocol: str,
        count: int = 5,
        target_version: Optional[str] = None,
    ) -> List[str]:
        """
        Generate payloads for vulnerability.
        
        Args:
            cwe_id: CWE identifier
            protocol: Target protocol
            count: Number of payloads
            target_version: Target version
            
        Returns:
            List of payloads
        """
        result = self.client.generate_payload(
            cwe_id=cwe_id,
            protocol=protocol,
            target_version=target_version,
            count=count,
        )

        payloads = result["payloads"]

        # Store for reference
        key = f"{cwe_id}_{protocol}"
        self.generated_payloads[key] = payloads

        return payloads

    def analyze_cot(
        self,
        cwe_id: str,
        protocol: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Analyze using Chain-of-Thought reasoning.
        
        Args:
            cwe_id: CWE identifier
            protocol: Target protocol
            context: Additional context
            
        Returns:
            CoT analysis result
        """
        return self.client.generate_cot_reasoning(
            cwe_id=cwe_id,
            protocol=protocol,
            context=context,
        )

    def health_check(self) -> bool:
        """Check service health."""
        return True


# ==============================================================================
# Mock Embedding Manager
# ==============================================================================

class MockEmbeddingManager:
    """Mock embedding manager for vector operations."""

    def __init__(self, embedding_dim: int = 384):
        """Initialize mock embedding manager."""
        self.embedding_dim = embedding_dim
        self.embeddings: Dict[str, List[float]] = {}

    def embed(self, text: str) -> List[float]:
        """Generate mock embedding for text."""
        if text in self.embeddings:
            return self.embeddings[text]

        # Generate deterministic embedding
        hash_val = hash(text)
        embedding = [
            float((hash_val + i) % 100) / 100.0
            for i in range(self.embedding_dim)
        ]

        self.embeddings[text] = embedding
        return embedding

    def similarity(self, text1: str, text2: str) -> float:
        """Calculate similarity between two texts."""
        emb1 = self.embed(text1)
        emb2 = self.embed(text2)

        # Simple dot product
        dot_product = sum(a * b for a, b in zip(emb1, emb2))
        return dot_product


# ==============================================================================
# Mock Cache Manager
# ==============================================================================

class MockCacheManager:
    """Mock cache manager for LLM responses."""

    def __init__(self, ttl_seconds: int = 3600):
        """Initialize mock cache manager."""
        self.ttl_seconds = ttl_seconds
        self.cache: Dict[str, Tuple[Any, float]] = {}

    def get(self, key: str) -> Optional[Any]:
        """Get value from cache."""
        if key not in self.cache:
            return None

        value, timestamp = self.cache[key]

        # Check if expired
        if time.time() - timestamp > self.ttl_seconds:
            del self.cache[key]
            return None

        return value

    def set(self, key: str, value: Any) -> None:
        """Set value in cache."""
        self.cache[key] = (value, time.time())

    def clear(self) -> None:
        """Clear all cache entries."""
        self.cache.clear()


# ==============================================================================
# Helper Functions
# ==============================================================================

def create_mock_response(
    text: str,
    model: str = "mistral",
    tokens_used: int = 100,
    response_time_ms: float = 150.0,
) -> MockLLMResponse:
    """
    Create a mock LLM response.
    
    Args:
        text: Response text
        model: Model name
        tokens_used: Token count
        response_time_ms: Response time in milliseconds
        
    Returns:
        MockLLMResponse instance
    """
    return MockLLMResponse(
        text=text,
        model=model,
        tokens_used=tokens_used,
        completion_tokens=tokens_used // 2,
        prompt_tokens=tokens_used - (tokens_used // 2),
        response_time_ms=response_time_ms,
    )


def create_mock_client(
    model: str = "mistral",
    enable_cache: bool = True,
) -> MockLLMClient:
    """
    Create a mock LLM client.
    
    Args:
        model: Model name
        enable_cache: Enable caching
        
    Returns:
        MockLLMClient instance
    """
    return MockLLMClient(
        model=model,
        enable_cache=enable_cache,
    )


def create_mock_service(
    enable_caching: bool = True,
) -> MockLLMService:
    """
    Create a mock LLM service.
    
    Args:
        enable_caching: Enable caching
        
    Returns:
        MockLLMService instance
    """
    client = create_mock_client(enable_cache=enable_caching)
    return MockLLMService(client=client, enable_caching=enable_caching)


# ==============================================================================
# Pytest Fixtures
# ==============================================================================

try:
    import pytest

    @pytest.fixture  # type: ignore
    def mock_llm_client():
        """Pytest fixture for mock LLM client."""
        return create_mock_client()

    @pytest.fixture  # type: ignore
    def mock_llm_service():
        """Pytest fixture for mock LLM service."""
        return create_mock_service()

    @pytest.fixture  # type: ignore
    def mock_embedding_manager():
        """Pytest fixture for mock embedding manager."""
        return MockEmbeddingManager()

    @pytest.fixture  # type: ignore
    def mock_cache_manager():
        """Pytest fixture for mock cache manager."""
        return MockCacheManager()

except ImportError:
    logger.debug("pytest not available, skipping pytest fixtures")


# ==============================================================================
# Exports
# ==============================================================================

__all__ = [
    # Main Classes
    "MockLLMClient",
    "MockLLMService",
    "MockEmbeddingManager",
    "MockCacheManager",

    # Data Classes
    "MockLLMResponse",
    "MockCacheEntry",

    # Enumerations
    "ModelType",
    "ResponseType",

    # Helper Functions
    "create_mock_response",
    "create_mock_client",
    "create_mock_service",

    # Constants
    "DEFAULT_MODELS",
    "DEFAULT_TEMPERATURE",
    "DEFAULT_MAX_TOKENS",
]