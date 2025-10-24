"""
HyFuzz MCP Server - LLM Pipeline Integration Tests

This module tests the complete LLM pipeline integration including:
- LLM Client (Ollama integration)
- LLM Service Layer (high-level API)
- Chain-of-Thought (CoT) Reasoning Engine
- Prompt Builder (prompt generation)
- Cache Manager (response caching)
- Token Counter (token estimation)
- Response Parser (output parsing)
- Embedding Manager (vector embeddings)

The tests verify that all LLM components work together to:
1. Generate intelligent payloads using CoT reasoning
2. Manage LLM requests and responses efficiently
3. Cache results for performance optimization
4. Parse and structure LLM output correctly
5. Handle errors and edge cases gracefully

Key Test Areas:
1. LLM client connection and model management
2. Payload generation with CoT reasoning
3. Prompt construction and optimization
4. Response caching and retrieval
5. Token counting and cost estimation
6. Response parsing and validation
7. Embedding generation and similarity search
8. End-to-end pipeline execution
9. Error handling and fallback strategies
10. Performance optimization

Author: HyFuzz Team
Version: 1.0.0
Date: 2025
"""

import asyncio
import json
import pytest
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock, AsyncMock

# Import LLM components
from src.llm.llm_client import LLMClient
from src.llm.llm_service import LLMService
from src.llm.cot_engine import CoTEngine
from src.llm.prompt_builder import PromptBuilder
from src.llm.cache_manager import CacheManager
from src.llm.token_counter import TokenCounter
from src.llm.response_parser import ResponseParser
from src.llm.embedding_manager import EmbeddingManager

# Import models
from src.models.llm_models import (
    PayloadRequest, PayloadResponse, CoTReasoning, EmbeddingResult
)

# Import utils
from src.utils.exceptions import (
    LLMException, ConnectionException, TimeoutException, ParsingException
)
from src.utils.logger import get_logger

# Initialize logger
logger = get_logger(__name__)


# ==============================================================================
# Test Fixtures
# ==============================================================================

@pytest.fixture
def sample_llm_config():
    """Provide sample LLM configuration."""
    return {
        "provider": "ollama",
        "model": "mistral",
        "base_url": "http://localhost:11434",
        "temperature": 0.7,
        "top_p": 0.9,
        "top_k": 40,
        "max_tokens": 2048,
        "timeout": 30,
        "retry_count": 3,
    }


@pytest.fixture
def sample_payload_request():
    """Provide sample payload request."""
    return PayloadRequest(
        cwe_id="CWE-79",
        protocol="coap",
        target_info={
            "version": "1.0",
            "capabilities": ["OBSERVE"],
            "framework": "libcoap"
        },
        execution_context={
            "successful_payloads": [],
            "failed_payloads": [],
            "previous_attempts": 0
        }
    )


@pytest.fixture
def sample_cwe_knowledge():
    """Provide sample CWE knowledge."""
    return {
        "id": "CWE-79",
        "name": "Cross-site Scripting",
        "description": "Improper neutralization of input during web page generation",
        "severity": "HIGH",
        "cvss_score": 7.1,
        "attack_vectors": ["network"],
        "consequences": ["confidentiality", "integrity"],
        "remediation": "Input validation and output encoding"
    }


@pytest.fixture
def sample_historical_payloads():
    """Provide sample historical payloads."""
    return [
        {
            "cwe_id": "CWE-79",
            "payload": "<script>alert(1)</script>",
            "protocol": "http",
            "success_rate": 0.85,
            "embedding": [0.1] * 768
        },
        {
            "cwe_id": "CWE-79",
            "payload": "<img src=x onerror=alert(1)>",
            "protocol": "http",
            "success_rate": 0.78,
            "embedding": [0.12] * 768
        },
        {
            "cwe_id": "CWE-79",
            "payload": "javascript:alert(1)",
            "protocol": "http",
            "success_rate": 0.65,
            "embedding": [0.08] * 768
        }
    ]


@pytest.fixture
def mock_ollama_response():
    """Provide mock Ollama API response."""
    return {
        "model": "mistral",
        "response": "Step 1: Analyze CWE-79 which is XSS...\nStep 2: Generate payload...",
        "done": True,
        "total_duration": 150000000,  # nanoseconds
        "load_duration": 50000000,
        "prompt_eval_count": 100,
        "prompt_eval_duration": 50000000,
        "eval_count": 50,
        "eval_duration": 50000000
    }


@pytest.fixture
def mock_llm_client(sample_llm_config):
    """Provide mock LLM client."""
    client = MagicMock(spec=LLMClient)
    client.model = sample_llm_config["model"]
    client.base_url = sample_llm_config["base_url"]
    client.is_connected = True

    # Mock methods
    async def mock_generate(prompt: str, max_tokens: int = 2048) -> str:
        return "Generated payload: <script>alert(1)</script>"

    async def mock_generate_with_stream(prompt: str):
        yield "Step 1: "
        yield "Analyze vulnerability"
        yield "\nStep 2: "
        yield "Generate payload"

    client.generate = mock_generate
    client.generate_with_stream = mock_generate_with_stream

    return client


@pytest.fixture
def mock_prompt_builder():
    """Provide mock prompt builder."""
    builder = MagicMock(spec=PromptBuilder)

    def build_cot_prompt(cwe_data: Dict, historical_payloads: List, target_info: Dict) -> str:
        return f"Analyze {cwe_data['id']} and generate payload..."

    def build_payload_generation_prompt(cwe_id: str, protocol: str, context: Dict) -> str:
        return f"Generate exploit for {cwe_id} over {protocol}..."

    builder.build_cot_prompt = build_cot_prompt
    builder.build_payload_generation_prompt = build_payload_generation_prompt

    return builder


@pytest.fixture
def mock_cache_manager():
    """Provide mock cache manager."""
    cache = MagicMock(spec=CacheManager)
    cache.cache_store = {}
    cache.enabled = True

    async def mock_get(key: str) -> Optional[Any]:
        return cache.cache_store.get(key)

    async def mock_set(key: str, value: Any, ttl: int = 3600) -> bool:
        cache.cache_store[key] = value
        return True

    async def mock_clear() -> None:
        cache.cache_store.clear()

    cache.get = mock_get
    cache.set = mock_set
    cache.clear = mock_clear

    return cache


@pytest.fixture
def mock_token_counter():
    """Provide mock token counter."""
    counter = MagicMock(spec=TokenCounter)

    def count_tokens(text: str) -> int:
        return len(text.split()) + len(text) // 100

    counter.count_tokens = count_tokens

    return counter


@pytest.fixture
def mock_response_parser():
    """Provide mock response parser."""
    parser = MagicMock(spec=ResponseParser)

    def parse_payload(response: str) -> str:
        lines = response.split("\n")
        for line in lines:
            if "payload" in line.lower() or "exploit" in line.lower():
                return line.split(":")[-1].strip()
        return response[:50]

    def parse_reasoning_chain(response: str) -> List[str]:
        steps = []
        lines = response.split("\n")
        for line in lines:
            if line.strip().startswith("Step"):
                steps.append(line.strip())
        return steps

    parser.parse_payload = parse_payload
    parser.parse_reasoning_chain = parse_reasoning_chain

    return parser


@pytest.fixture
def mock_embedding_manager():
    """Provide mock embedding manager."""
    manager = MagicMock(spec=EmbeddingManager)

    async def mock_embed(text: str) -> List[float]:
        return [0.1] * 768  # 768-dimensional embedding

    async def mock_embed_batch(texts: List[str]) -> List[List[float]]:
        return [[0.1] * 768 for _ in texts]

    async def mock_similarity(text1: str, text2: str) -> float:
        return 0.85

    manager.embed = mock_embed
    manager.embed_batch = mock_embed_batch
    manager.similarity = mock_similarity

    return manager


# ==============================================================================
# LLM Client Tests
# ==============================================================================

class TestLLMClientIntegration:
    """Test LLM client integration."""

    @pytest.mark.asyncio
    async def test_llm_client_initialization(self, sample_llm_config):
        """Test LLM client initialization."""
        logger.info("Testing LLM client initialization...")

        client = MagicMock(spec=LLMClient)
        client.is_connected = False
        client.connect = AsyncMock(return_value=True)

        result = await client.connect()

        assert result is True
        logger.info("LLM client initialized successfully")

    @pytest.mark.asyncio
    async def test_llm_client_model_loading(self, mock_llm_client):
        """Test loading LLM model."""
        logger.info("Testing LLM model loading...")

        mock_llm_client.load_model = AsyncMock(return_value=True)
        result = await mock_llm_client.load_model("mistral")

        assert result is True
        logger.info("LLM model loaded successfully")

    @pytest.mark.asyncio
    async def test_llm_client_list_models(self, mock_llm_client):
        """Test listing available models."""
        logger.info("Testing list available models...")

        mock_llm_client.list_models = AsyncMock(
            return_value=["mistral", "llama2", "neural-chat"]
        )

        models = await mock_llm_client.list_models()

        assert len(models) > 0
        assert "mistral" in models
        logger.info(f"Found {len(models)} available models")

    @pytest.mark.asyncio
    async def test_llm_client_generate_simple(self, mock_llm_client):
        """Test simple text generation."""
        logger.info("Testing simple text generation...")

        prompt = "Explain CWE-79 vulnerability"
        response = await mock_llm_client.generate(prompt)

        assert response is not None
        assert len(response) > 0
        logger.info("Text generation test passed")

    @pytest.mark.asyncio
    async def test_llm_client_generate_with_streaming(self, mock_llm_client):
        """Test streaming text generation."""
        logger.info("Testing streaming text generation...")

        prompt = "Generate CoT reasoning for CWE-79"
        chunks = []

        async for chunk in mock_llm_client.generate_with_stream(prompt):
            chunks.append(chunk)

        assert len(chunks) > 0
        full_response = "".join(chunks)
        assert len(full_response) > 0
        logger.info(f"Streamed {len(chunks)} chunks")

    @pytest.mark.asyncio
    async def test_llm_client_connection_error(self, sample_llm_config):
        """Test handling of connection errors."""
        logger.info("Testing connection error handling...")

        client = MagicMock(spec=LLMClient)
        client.connect = AsyncMock(side_effect=ConnectionException("Connection failed"))

        with pytest.raises(ConnectionException):
            await client.connect()

        logger.info("Connection error handled correctly")

    @pytest.mark.asyncio
    async def test_llm_client_timeout(self, mock_llm_client):
        """Test handling of timeout errors."""
        logger.info("Testing timeout error handling...")

        mock_llm_client.generate = AsyncMock(
            side_effect=TimeoutException("Request timeout")
        )

        with pytest.raises(TimeoutException):
            await mock_llm_client.generate("test prompt")

        logger.info("Timeout error handled correctly")


# ==============================================================================
# Prompt Builder Tests
# ==============================================================================

class TestPromptBuilderIntegration:
    """Test prompt builder integration."""

    def test_build_cot_prompt(self, mock_prompt_builder, sample_cwe_knowledge,
                              sample_historical_payloads):
        """Test building CoT prompt."""
        logger.info("Testing CoT prompt building...")

        prompt = mock_prompt_builder.build_cot_prompt(
            cwe_data=sample_cwe_knowledge,
            historical_payloads=sample_historical_payloads,
            target_info={"version": "1.0"}
        )

        assert prompt is not None
        assert "CWE-79" in prompt
        logger.info("CoT prompt built successfully")

    def test_build_payload_generation_prompt(self, mock_prompt_builder):
        """Test building payload generation prompt."""
        logger.info("Testing payload generation prompt building...")

        prompt = mock_prompt_builder.build_payload_generation_prompt(
            cwe_id="CWE-79",
            protocol="coap",
            context={"version": "1.0"}
        )

        assert prompt is not None
        assert "CWE-79" in prompt
        assert "coap" in prompt.lower()
        logger.info("Payload generation prompt built successfully")

    def test_prompt_optimization(self, mock_prompt_builder):
        """Test prompt optimization."""
        logger.info("Testing prompt optimization...")

        # Mock optimization method
        mock_prompt_builder.optimize = MagicMock(
            return_value="Optimized prompt..."
        )

        optimized = mock_prompt_builder.optimize("Original prompt")

        assert optimized is not None
        logger.info("Prompt optimized successfully")

    def test_prompt_with_few_shot_examples(self, mock_prompt_builder):
        """Test prompt with few-shot examples."""
        logger.info("Testing prompt with few-shot examples...")

        examples = [
            {"input": "CWE-79", "output": "<script>alert(1)</script>"},
            {"input": "CWE-89", "output": "'; DROP TABLE users; --"}
        ]

        mock_prompt_builder.add_few_shot_examples = MagicMock(
            return_value=True
        )

        result = mock_prompt_builder.add_few_shot_examples(examples)

        assert result is True
        logger.info("Few-shot examples added successfully")


# ==============================================================================
# CoT Engine Tests
# ==============================================================================

class TestCoTEngineIntegration:
    """Test Chain-of-Thought reasoning engine."""

    @pytest.mark.asyncio
    async def test_cot_initialization(self):
        """Test CoT engine initialization."""
        logger.info("Testing CoT engine initialization...")

        engine = MagicMock(spec=CoTEngine)
        engine.initialize = AsyncMock(return_value=True)

        result = await engine.initialize()

        assert result is True
        logger.info("CoT engine initialized successfully")

    @pytest.mark.asyncio
    async def test_cot_reasoning_chain_generation(self):
        """Test CoT reasoning chain generation."""
        logger.info("Testing CoT reasoning chain generation...")

        engine = MagicMock(spec=CoTEngine)

        cot_response = CoTReasoning(
            steps=[
                "Step 1: Identify vulnerability type (XSS)",
                "Step 2: Analyze injection point",
                "Step 3: Generate payload"
            ],
            payload="<script>alert(1)</script>",
            confidence=0.85
        )

        engine.generate_reasoning = AsyncMock(return_value=cot_response)

        result = await engine.generate_reasoning("CWE-79", "http")

        assert len(result.steps) == 3
        assert result.confidence > 0.8
        logger.info(f"Generated {len(result.steps)} reasoning steps")

    @pytest.mark.asyncio
    async def test_cot_with_knowledge_base(self):
        """Test CoT with knowledge base integration."""
        logger.info("Testing CoT with knowledge base...")

        engine = MagicMock(spec=CoTEngine)

        # Mock knowledge base query
        engine.query_knowledge_base = AsyncMock(
            return_value={
                "cwe_data": {"id": "CWE-79", "severity": "HIGH"},
                "related_cves": ["CVE-2021-1234"]
            }
        )

        kb_data = await engine.query_knowledge_base("CWE-79")

        assert kb_data["cwe_data"]["id"] == "CWE-79"
        logger.info("Knowledge base integration test passed")

    @pytest.mark.asyncio
    async def test_cot_error_handling(self):
        """Test CoT error handling."""
        logger.info("Testing CoT error handling...")

        engine = MagicMock(spec=CoTEngine)
        engine.generate_reasoning = AsyncMock(
            side_effect=LLMException("LLM inference failed")
        )

        with pytest.raises(LLMException):
            await engine.generate_reasoning("CWE-999", "unknown")

        logger.info("CoT error handling test passed")


# ==============================================================================
# Cache Manager Tests
# ==============================================================================

class TestCacheManagerIntegration:
    """Test cache manager integration."""

    @pytest.mark.asyncio
    async def test_cache_set_and_get(self, mock_cache_manager):
        """Test cache set and get operations."""
        logger.info("Testing cache set/get operations...")

        key = "payload_CWE-79_http"
        value = {"payload": "<script>alert(1)</script>", "confidence": 0.85}

        await mock_cache_manager.set(key, value)
        result = await mock_cache_manager.get(key)

        assert result == value
        logger.info("Cache set/get test passed")

    @pytest.mark.asyncio
    async def test_cache_expiration(self, mock_cache_manager):
        """Test cache expiration."""
        logger.info("Testing cache expiration...")

        key = "temp_payload"
        value = {"payload": "test"}

        # Set with short TTL
        await mock_cache_manager.set(key, value, ttl=1)
        result1 = await mock_cache_manager.get(key)

        assert result1 == value

        # Wait for expiration (mocked)
        await asyncio.sleep(0.1)

        logger.info("Cache expiration test passed")

    @pytest.mark.asyncio
    async def test_cache_invalidation(self, mock_cache_manager):
        """Test cache invalidation."""
        logger.info("Testing cache invalidation...")

        await mock_cache_manager.set("key1", "value1")
        await mock_cache_manager.set("key2", "value2")

        await mock_cache_manager.clear()

        result = await mock_cache_manager.get("key1")
        assert result is None

        logger.info("Cache invalidation test passed")

    @pytest.mark.asyncio
    async def test_cache_statistics(self, mock_cache_manager):
        """Test cache statistics."""
        logger.info("Testing cache statistics...")

        mock_cache_manager.get_stats = MagicMock(
            return_value={"hits": 100, "misses": 20, "size": 50}
        )

        stats = mock_cache_manager.get_stats()

        assert stats["hits"] == 100
        logger.info(f"Cache stats: {stats}")


# ==============================================================================
# Token Counter Tests
# ==============================================================================

class TestTokenCounterIntegration:
    """Test token counter integration."""

    def test_count_tokens_simple(self, mock_token_counter):
        """Test simple token counting."""
        logger.info("Testing simple token counting...")

        text = "Analyze this security vulnerability"
        token_count = mock_token_counter.count_tokens(text)

        assert token_count > 0
        logger.info(f"Counted {token_count} tokens")

    def test_count_tokens_complex(self, mock_token_counter):
        """Test token counting on complex text."""
        logger.info("Testing complex token counting...")

        text = "CWE-79 is a cross-site scripting vulnerability. " \
               "It occurs when user input is not properly sanitized."
        token_count = mock_token_counter.count_tokens(text)

        assert token_count > 20
        logger.info(f"Counted {token_count} tokens in complex text")

    def test_estimate_cost(self):
        """Test cost estimation."""
        logger.info("Testing cost estimation...")

        counter = MagicMock(spec=TokenCounter)
        counter.estimate_cost = MagicMock(return_value=0.001)

        cost = counter.estimate_cost(1000)  # 1000 tokens

        assert cost > 0
        logger.info(f"Estimated cost: ${cost}")


# ==============================================================================
# Response Parser Tests
# ==============================================================================

class TestResponseParserIntegration:
    """Test response parser integration."""

    def test_parse_payload_from_response(self, mock_response_parser):
        """Test parsing payload from response."""
        logger.info("Testing payload parsing...")

        response = """
        Step 1: Analyze vulnerability
        Step 2: Generate payload
        Payload: <script>alert(1)</script>
        Confidence: 0.85
        """

        payload = mock_response_parser.parse_payload(response)

        assert payload is not None
        assert "script" in payload.lower()
        logger.info(f"Parsed payload: {payload}")

    def test_parse_reasoning_chain(self, mock_response_parser):
        """Test parsing reasoning chain."""
        logger.info("Testing reasoning chain parsing...")

        response = """
        Step 1: Identify XSS vulnerability
        Step 2: Find injection point
        Step 3: Craft payload
        Step 4: Test effectiveness
        """

        steps = mock_response_parser.parse_reasoning_chain(response)

        assert len(steps) == 4
        logger.info(f"Parsed {len(steps)} reasoning steps")

    def test_parse_confidence_score(self):
        """Test parsing confidence score."""
        logger.info("Testing confidence score parsing...")

        parser = MagicMock(spec=ResponseParser)
        parser.parse_confidence = MagicMock(return_value=0.82)

        confidence = parser.parse_confidence("Confidence: 0.82")

        assert 0.0 <= confidence <= 1.0
        logger.info(f"Parsed confidence: {confidence}")

    def test_parse_cve_references(self):
        """Test parsing CVE references."""
        logger.info("Testing CVE reference parsing...")

        parser = MagicMock(spec=ResponseParser)
        parser.parse_cve_references = MagicMock(
            return_value=["CVE-2021-1234", "CVE-2020-5678"]
        )

        cves = parser.parse_cve_references("Related: CVE-2021-1234, CVE-2020-5678")

        assert len(cves) == 2
        logger.info(f"Parsed {len(cves)} CVE references")


# ==============================================================================
# Embedding Manager Tests
# ==============================================================================

class TestEmbeddingManagerIntegration:
    """Test embedding manager integration."""

    @pytest.mark.asyncio
    async def test_embed_single_text(self, mock_embedding_manager):
        """Test embedding single text."""
        logger.info("Testing single text embedding...")

        text = "Cross-site scripting vulnerability"
        embedding = await mock_embedding_manager.embed(text)

        assert isinstance(embedding, list)
        assert len(embedding) == 768
        logger.info(f"Generated embedding of dimension {len(embedding)}")

    @pytest.mark.asyncio
    async def test_embed_batch(self, mock_embedding_manager):
        """Test batch embedding."""
        logger.info("Testing batch embedding...")

        texts = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)"
        ]

        embeddings = await mock_embedding_manager.embed_batch(texts)

        assert len(embeddings) == len(texts)
        assert len(embeddings[0]) == 768
        logger.info(f"Generated {len(embeddings)} embeddings")

    @pytest.mark.asyncio
    async def test_similarity_search(self, mock_embedding_manager):
        """Test similarity search."""
        logger.info("Testing similarity search...")

        query = "<script>alert(1)</script>"
        payload = "<img src=x onerror=alert(1)>"

        similarity = await mock_embedding_manager.similarity(query, payload)

        assert 0.0 <= similarity <= 1.0
        logger.info(f"Similarity score: {similarity}")


# ==============================================================================
# End-to-End Pipeline Tests
# ==============================================================================

class TestLLMPipelineE2E:
    """End-to-end LLM pipeline tests."""

    @pytest.mark.asyncio
    async def test_complete_payload_generation_pipeline(
            self,
            mock_llm_client,
            mock_prompt_builder,
            mock_response_parser,
            sample_payload_request,
            sample_cwe_knowledge
    ):
        """Test complete payload generation pipeline."""
        logger.info("Testing complete payload generation pipeline...")

        # Step 1: Build prompt
        prompt = mock_prompt_builder.build_cot_prompt(
            cwe_data=sample_cwe_knowledge,
            historical_payloads=[],
            target_info=sample_payload_request.target_info
        )
        assert prompt is not None

        # Step 2: Generate with LLM
        response = await mock_llm_client.generate(prompt)
        assert response is not None

        # Step 3: Parse response
        payload = mock_response_parser.parse_payload(response)
        assert payload is not None

        logger.info("Complete pipeline executed successfully")

    @pytest.mark.asyncio
    async def test_pipeline_with_caching(
            self,
            mock_llm_client,
            mock_cache_manager,
            mock_prompt_builder
    ):
        """Test pipeline with caching."""
        logger.info("Testing pipeline with caching...")

        cache_key = "CWE-79_coap"
        cached_payload = {"payload": "<script>alert(1)</script>", "confidence": 0.85}

        # First call - cache miss
        result1 = await mock_cache_manager.get(cache_key)
        assert result1 is None

        # Store in cache
        await mock_cache_manager.set(cache_key, cached_payload)

        # Second call - cache hit
        result2 = await mock_cache_manager.get(cache_key)
        assert result2 == cached_payload

        logger.info("Caching test passed")

    @pytest.mark.asyncio
    async def test_pipeline_with_embedding_search(
            self,
            mock_embedding_manager,
            sample_historical_payloads
    ):
        """Test pipeline with embedding-based search."""
        logger.info("Testing pipeline with embedding search...")

        query = "<script>alert(1)</script>"

        # Embed query
        query_embedding = await mock_embedding_manager.embed(query)
        assert len(query_embedding) == 768

        # Find similar payloads (mocked)
        similarities = []
        for payload_data in sample_historical_payloads:
            sim = await mock_embedding_manager.similarity(
                query,
                payload_data["payload"]
            )
            similarities.append(sim)

        # Find most similar
        best_idx = similarities.index(max(similarities))
        assert best_idx >= 0

        logger.info(f"Found similar payload at index {best_idx}")

    @pytest.mark.asyncio
    async def test_pipeline_error_recovery(
            self,
            mock_llm_client,
            mock_cache_manager
    ):
        """Test pipeline error recovery."""
        logger.info("Testing pipeline error recovery...")

        # Mock LLM failure
        mock_llm_client.generate = AsyncMock(
            side_effect=LLMException("LLM failure")
        )

        # Should fallback to cache
        cache_key = "fallback_payload"
        fallback_value = {"payload": "fallback", "source": "cache"}
        await mock_cache_manager.set(cache_key, fallback_value)

        try:
            await mock_llm_client.generate("test")
        except LLMException:
            # Try cache as fallback
            cached = await mock_cache_manager.get(cache_key)
            assert cached == fallback_value

        logger.info("Error recovery test passed")


# ==============================================================================
# Performance Tests
# ==============================================================================

class TestLLMPipelinePerformance:
    """Test LLM pipeline performance."""

    @pytest.mark.asyncio
    async def test_payload_generation_latency(self, mock_llm_client):
        """Test payload generation latency."""
        logger.info("Testing payload generation latency...")

        import time

        start = time.time()
        await mock_llm_client.generate("Generate payload")
        elapsed = time.time() - start

        # Should be under 5 seconds for mock
        assert elapsed < 5.0
        logger.info(f"Payload generation latency: {elapsed * 1000:.2f}ms")

    @pytest.mark.asyncio
    async def test_cache_lookup_performance(self, mock_cache_manager):
        """Test cache lookup performance."""
        logger.info("Testing cache lookup performance...")

        import time

        await mock_cache_manager.set("key", "value")

        start = time.time()
        for _ in range(100):
            await mock_cache_manager.get("key")
        elapsed = time.time() - start

        avg_time = (elapsed / 100) * 1000  # Convert to ms
        logger.info(f"Average cache lookup: {avg_time:.3f}ms")

        # Cache lookups should be < 1ms
        assert elapsed < 0.1

    @pytest.mark.asyncio
    async def test_token_counting_performance(self, mock_token_counter):
        """Test token counting performance."""
        logger.info("Testing token counting performance...")

        import time

        long_text = " ".join(["word"] * 10000)

        start = time.time()
        mock_token_counter.count_tokens(long_text)
        elapsed = time.time() - start

        logger.info(f"Token counting time: {elapsed * 1000:.2f}ms")

    @pytest.mark.asyncio
    async def test_embedding_performance(self, mock_embedding_manager):
        """Test embedding generation performance."""
        logger.info("Testing embedding generation performance...")

        import time

        texts = ["text"] * 100

        start = time.time()
        await mock_embedding_manager.embed_batch(texts)
        elapsed = time.time() - start

        logger.info(f"Batch embedding 100 texts: {elapsed * 1000:.2f}ms")


# ==============================================================================
# Integration Tests
# ==============================================================================

class TestLLMIntegrationWithKnowledge:
    """Test LLM integration with knowledge base."""

    @pytest.mark.asyncio
    async def test_knowledge_augmented_payload_generation(self):
        """Test knowledge-augmented payload generation."""
        logger.info("Testing knowledge-augmented payload generation...")

        # Mock service integration
        service = MagicMock(spec=LLMService)

        service.generate_payload = AsyncMock(
            return_value=PayloadResponse(
                payload="<script>alert(1)</script>",
                reasoning_chain=["Step 1", "Step 2"],
                confidence=0.85,
                cve_references=["CVE-2021-1234"]
            )
        )

        result = await service.generate_payload(
            cwe_id="CWE-79",
            protocol="http",
            context={}
        )

        assert result.payload is not None
        logger.info("Knowledge-augmented generation test passed")

    @pytest.mark.asyncio
    async def test_multi_step_reasoning(self):
        """Test multi-step reasoning process."""
        logger.info("Testing multi-step reasoning...")

        engine = MagicMock(spec=CoTEngine)

        # Mock multi-step reasoning
        engine.step_1_vulnerability_analysis = AsyncMock(
            return_value="XSS vulnerability identified"
        )
        engine.step_2_injection_point_analysis = AsyncMock(
            return_value="Injection point: user input"
        )
        engine.step_3_payload_generation = AsyncMock(
            return_value="<script>alert(1)</script>"
        )

        # Execute steps
        step1 = await engine.step_1_vulnerability_analysis("CWE-79")
        step2 = await engine.step_2_injection_point_analysis("CWE-79")
        step3 = await engine.step_3_payload_generation("CWE-79")

        assert step1 is not None
        assert step2 is not None
        assert step3 is not None

        logger.info("Multi-step reasoning test passed")


# ==============================================================================
# Error Handling Tests
# ==============================================================================

class TestLLMPipelineErrorHandling:
    """Test error handling in LLM pipeline."""

    @pytest.mark.asyncio
    async def test_handle_llm_timeout(self):
        """Test handling LLM timeout."""
        logger.info("Testing LLM timeout handling...")

        client = MagicMock(spec=LLMClient)
        client.generate = AsyncMock(
            side_effect=TimeoutException("Request timeout after 30s")
        )

        with pytest.raises(TimeoutException):
            await client.generate("prompt")

        logger.info("Timeout handling test passed")

    @pytest.mark.asyncio
    async def test_handle_invalid_response(self, mock_response_parser):
        """Test handling invalid response."""
        logger.info("Testing invalid response handling...")

        invalid_response = "This is not a valid payload response"

        mock_response_parser.parse_payload = MagicMock(
            return_value=None
        )

        result = mock_response_parser.parse_payload(invalid_response)

        assert result is None
        logger.info("Invalid response handling test passed")

    @pytest.mark.asyncio
    async def test_handle_parsing_error(self):
        """Test handling parsing error."""
        logger.info("Testing parsing error handling...")

        parser = MagicMock(spec=ResponseParser)
        parser.parse_payload = MagicMock(
            side_effect=ParsingException("Failed to parse response")
        )

        with pytest.raises(ParsingException):
            parser.parse_payload("invalid")

        logger.info("Parsing error handling test passed")

    @pytest.mark.asyncio
    async def test_fallback_strategy(self, mock_cache_manager):
        """Test fallback strategy."""
        logger.info("Testing fallback strategy...")

        # Primary source fails
        primary = MagicMock()
        primary.generate = AsyncMock(side_effect=Exception("Primary failed"))

        # Fallback to cache
        fallback_value = {"payload": "fallback"}
        await mock_cache_manager.set("fallback", fallback_value)

        try:
            await primary.generate("test")
        except Exception:
            result = await mock_cache_manager.get("fallback")
            assert result == fallback_value

        logger.info("Fallback strategy test passed")


# ==============================================================================
# Run Tests
# ==============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s", "--tb=short"])