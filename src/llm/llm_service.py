"""
LLM Service Layer for HyFuzz Windows MCP Server

This module provides a unified interface for LLM operations including:
- Ollama client integration
- Chain-of-Thought (CoT) reasoning
- Prompt building and response parsing
- Caching and embedding management
- Token counting and optimization
"""

import asyncio
import json
import logging
import hashlib
from typing import Optional, Dict, List, Any, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from abc import ABC, abstractmethod
from enum import Enum

# ============================================================================
# Data Models and Enums
# ============================================================================

class ReasoningStrategy(Enum):
    """Supported reasoning strategies for LLM inference"""
    STANDARD = "standard"  # Direct response
    COT = "cot"  # Chain-of-Thought
    COT_WITH_VERIFICATION = "cot_verify"  # CoT with verification step


class CacheStrategy(Enum):
    """Cache management strategies"""
    NONE = "none"
    LRU = "lru"  # Least Recently Used
    TTL = "ttl"  # Time-To-Live


@dataclass
class LLMConfig:
    """Configuration for LLM service"""
    model_name: str = "mistral"
    ollama_base_url: str = "http://localhost:11434"
    temperature: float = 0.7
    top_p: float = 0.95
    top_k: int = 40
    num_predict: int = 512
    timeout: int = 300
    reasoning_strategy: ReasoningStrategy = ReasoningStrategy.COT
    cache_strategy: CacheStrategy = CacheStrategy.LRU
    cache_size: int = 1000
    cache_ttl_seconds: int = 3600
    max_retries: int = 3
    retry_delay: float = 1.0


@dataclass
class CotChain:
    """Chain-of-Thought reasoning chain"""
    thought_steps: List[str] = field(default_factory=list)
    reasoning: str = ""
    conclusion: str = ""
    confidence: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_step(self, step: str) -> None:
        """Add a thought step to the chain"""
        self.thought_steps.append(step)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)


@dataclass
class LLMResponse:
    """Structured LLM response"""
    content: str
    model: str
    tokens_used: int
    inference_time: float
    strategy_used: ReasoningStrategy
    cot_chain: Optional[CotChain] = None
    cache_hit: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        data['strategy_used'] = self.strategy_used.value
        if self.cot_chain:
            data['cot_chain'] = self.cot_chain.to_dict()
        return data


# ============================================================================
# Cache Manager Implementation
# ============================================================================

@dataclass
class CacheEntry:
    """Individual cache entry with metadata"""
    key: str
    value: LLMResponse
    created_at: datetime = field(default_factory=datetime.now)
    accessed_at: datetime = field(default_factory=datetime.now)
    access_count: int = 0

    def is_expired(self, ttl_seconds: int) -> bool:
        """Check if cache entry has expired"""
        if ttl_seconds <= 0:
            return False
        expiry_time = self.created_at + timedelta(seconds=ttl_seconds)
        return datetime.now() > expiry_time


class CacheManager:
    """Manages LLM response caching"""

    def __init__(self, strategy: CacheStrategy, size: int = 1000, ttl_seconds: int = 3600):
        self.strategy = strategy
        self.max_size = size
        self.ttl_seconds = ttl_seconds
        self.cache: Dict[str, CacheEntry] = {}
        self.logger = logging.getLogger(__name__)

    def _generate_key(self, prompt: str, model: str, params: Dict[str, Any]) -> str:
        """Generate cache key from prompt and parameters"""
        key_data = f"{prompt}:{model}:{json.dumps(params, sort_keys=True)}"
        return hashlib.md5(key_data.encode()).hexdigest()

    def get(self, prompt: str, model: str, params: Dict[str, Any]) -> Optional[LLMResponse]:
        """Retrieve cached response"""
        if self.strategy == CacheStrategy.NONE:
            return None

        key = self._generate_key(prompt, model, params)
        entry = self.cache.get(key)

        if entry is None:
            return None

        # Check TTL expiration
        if entry.is_expired(self.ttl_seconds):
            self.cache.pop(key, None)
            return None

        # Update access metadata
        entry.accessed_at = datetime.now()
        entry.access_count += 1
        self.logger.debug(f"Cache hit for key: {key}")

        response = entry.value
        response.cache_hit = True
        return response

    def set(self, prompt: str, model: str, params: Dict[str, Any], response: LLMResponse) -> None:
        """Store response in cache"""
        if self.strategy == CacheStrategy.NONE:
            return

        # Enforce LRU eviction if cache is full
        if len(self.cache) >= self.max_size:
            self._evict_lru_entry()

        key = self._generate_key(prompt, model, params)
        self.cache[key] = CacheEntry(key=key, value=response)
        self.logger.debug(f"Cached response for key: {key}")

    def _evict_lru_entry(self) -> None:
        """Evict least recently used entry"""
        if not self.cache:
            return

        lru_key = min(
            self.cache.keys(),
            key=lambda k: self.cache[k].accessed_at
        )
        self.cache.pop(lru_key)
        self.logger.debug(f"Evicted LRU entry: {lru_key}")

    def clear(self) -> None:
        """Clear all cache entries"""
        self.cache.clear()
        self.logger.info("Cache cleared")

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        return {
            "size": len(self.cache),
            "max_size": self.max_size,
            "strategy": self.strategy.value,
            "utilization": len(self.cache) / self.max_size if self.max_size > 0 else 0
        }


# ============================================================================
# Prompt Builder
# ============================================================================

class PromptBuilder:
    """Builds optimized prompts for LLM inference"""

    def __init__(self, context_retriever: Optional['ContextRetriever'] = None):
        self.context_retriever = context_retriever
        self.logger = logging.getLogger(__name__)

    def build_cot_prompt(self, query: str, context: Optional[str] = None) -> str:
        """Build Chain-of-Thought prompt"""
        prompt_parts = [
            "You are a security expert analyzing vulnerabilities.",
            f"\nQuestion: {query}",
            "\nThink step by step:",
            "1. First, analyze the problem",
            "2. Identify key components",
            "3. Consider security implications",
            "4. Provide your conclusion"
        ]

        if context:
            prompt_parts.insert(2, f"\nContext: {context}")

        return "\n".join(prompt_parts)

    def build_verification_prompt(self, original_query: str, initial_response: str) -> str:
        """Build verification prompt for CoT responses"""
        return (
            f"Original Question: {original_query}\n"
            f"Initial Analysis: {initial_response}\n"
            f"Verify the analysis above and identify any potential issues or improvements.\n"
            f"Provide your verification result."
        )

    def build_embedding_prompt(self, text: str) -> str:
        """Build prompt for semantic embedding"""
        return f"Analyze and embed the following security information: {text}"


# ============================================================================
# CoT Engine
# ============================================================================

class CotEngine:
    """Chain-of-Thought reasoning engine"""

    def __init__(self, llm_client: 'LLMClient', prompt_builder: PromptBuilder):
        self.llm_client = llm_client
        self.prompt_builder = prompt_builder
        self.logger = logging.getLogger(__name__)

    async def generate_cot_chain(
        self,
        query: str,
        context: Optional[str] = None,
        max_steps: int = 5
    ) -> CotChain:
        """Generate a Chain-of-Thought reasoning chain"""
        cot_chain = CotChain()

        try:
            # Step 1: Problem Analysis
            analysis_prompt = self.prompt_builder.build_cot_prompt(query, context)
            response = await self.llm_client.generate(analysis_prompt)
            cot_chain.add_step("Problem Analysis: " + response[:200])

            # Step 2: Extract reasoning components
            reasoning_prompt = f"Extract key reasoning points from:\n{response}"
            reasoning = await self.llm_client.generate(reasoning_prompt)
            cot_chain.add_step("Reasoning Extraction: " + reasoning[:200])

            # Step 3: Reach conclusion
            conclusion_prompt = f"Based on the analysis, provide final conclusion:\n{reasoning}"
            conclusion = await self.llm_client.generate(conclusion_prompt)
            cot_chain.conclusion = conclusion
            cot_chain.add_step("Conclusion: " + conclusion[:200])

            # Set confidence based on reasoning quality
            cot_chain.confidence = min(1.0, len(cot_chain.thought_steps) / max_steps)
            cot_chain.reasoning = reasoning

            self.logger.info(f"Generated CoT chain with {len(cot_chain.thought_steps)} steps")
            return cot_chain

        except Exception as e:
            self.logger.error(f"Error generating CoT chain: {str(e)}")
            raise

    async def verify_response(self, query: str, response: str) -> Tuple[bool, str]:
        """Verify response quality"""
        verification_prompt = self.prompt_builder.build_verification_prompt(query, response)
        verification_result = await self.llm_client.generate(verification_prompt)

        # Simple verification heuristic
        is_valid = any(
            keyword in verification_result.lower()
            for keyword in ["valid", "correct", "good", "accurate"]
        )

        return is_valid, verification_result


# ============================================================================
# Stub LLM Client (for interface definition)
# ============================================================================

class LLMClient(ABC):
    """Abstract LLM Client interface"""

    @abstractmethod
    async def generate(self, prompt: str, **kwargs) -> str:
        """Generate response from LLM"""
        pass

    @abstractmethod
    async def generate_with_tokens(self, prompt: str, **kwargs) -> Tuple[str, int]:
        """Generate response and return token count"""
        pass


# ============================================================================
# Context Retriever Stub
# ============================================================================

class ContextRetriever:
    """Retrieves context from knowledge base"""

    def __init__(self, graph_db_path: str = ""):
        self.graph_db_path = graph_db_path
        self.logger = logging.getLogger(__name__)

    async def retrieve_context(self, query: str, top_k: int = 3) -> Optional[str]:
        """Retrieve relevant context from knowledge base"""
        self.logger.debug(f"Retrieving context for query: {query}")
        # Stub implementation
        return None


# ============================================================================
# LLM Service - Main Implementation
# ============================================================================

class LLMService:
    """
    Main LLM Service providing unified interface for:
    - LLM inference with multiple strategies
    - Chain-of-Thought reasoning
    - Response caching
    - Token counting
    - Error handling and retries
    """

    def __init__(
        self,
        llm_client: LLMClient,
        config: Optional[LLMConfig] = None,
        context_retriever: Optional[ContextRetriever] = None
    ):
        self.config = config or LLMConfig()
        self.llm_client = llm_client
        self.context_retriever = context_retriever or ContextRetriever()

        # Initialize components
        self.cache_manager = CacheManager(
            strategy=self.config.cache_strategy,
            size=self.config.cache_size,
            ttl_seconds=self.config.cache_ttl_seconds
        )
        self.prompt_builder = PromptBuilder(self.context_retriever)
        self.cot_engine = CotEngine(self.llm_client, self.prompt_builder)

        self.logger = logging.getLogger(__name__)
        self._request_count = 0
        self._total_tokens_used = 0

    async def infer(
        self,
        query: str,
        strategy: Optional[ReasoningStrategy] = None,
        include_context: bool = True,
        **kwargs
    ) -> LLMResponse:
        """
        Main inference method with automatic strategy selection

        Args:
            query: Input query for LLM
            strategy: Reasoning strategy (defaults to config setting)
            include_context: Whether to retrieve context from knowledge base
            **kwargs: Additional parameters for LLM

        Returns:
            LLMResponse with content and metadata
        """
        strategy = strategy or self.config.reasoning_strategy
        start_time = datetime.now()

        try:
            # Step 1: Try cache lookup
            cache_params = {"strategy": strategy.value, **kwargs}
            cached_response = self.cache_manager.get(
                query,
                self.config.model_name,
                cache_params
            )
            if cached_response:
                self.logger.info(f"Cache hit for query: {query[:50]}")
                return cached_response

            # Step 2: Retrieve context if requested
            context = None
            if include_context:
                context = await self.context_retriever.retrieve_context(query)

            # Step 3: Generate response based on strategy
            if strategy == ReasoningStrategy.STANDARD:
                response = await self._infer_standard(query, context, **kwargs)
            elif strategy == ReasoningStrategy.COT:
                response = await self._infer_cot(query, context, **kwargs)
            elif strategy == ReasoningStrategy.COT_WITH_VERIFICATION:
                response = await self._infer_cot_with_verification(query, context, **kwargs)
            else:
                response = await self._infer_standard(query, context, **kwargs)

            # Step 4: Update metrics
            response.inference_time = (datetime.now() - start_time).total_seconds()
            response.strategy_used = strategy
            self._request_count += 1
            self._total_tokens_used += response.tokens_used

            # Step 5: Cache result
            self.cache_manager.set(query, self.config.model_name, cache_params, response)

            self.logger.info(
                f"Inference completed - Strategy: {strategy.value}, "
                f"Tokens: {response.tokens_used}, Time: {response.inference_time:.2f}s"
            )
            return response

        except Exception as e:
            self.logger.error(f"Inference failed: {str(e)}")
            raise

    async def _infer_standard(
        self,
        query: str,
        context: Optional[str] = None,
        **kwargs
    ) -> LLMResponse:
        """Standard inference without reasoning chain"""
        prompt = self.prompt_builder.build_cot_prompt(query, context)

        for attempt in range(self.config.max_retries):
            try:
                content, tokens = await self.llm_client.generate_with_tokens(
                    prompt,
                    temperature=self.config.temperature,
                    top_p=self.config.top_p,
                    top_k=self.config.top_k,
                    num_predict=self.config.num_predict,
                    **kwargs
                )

                return LLMResponse(
                    content=content,
                    model=self.config.model_name,
                    tokens_used=tokens,
                    inference_time=0.0,
                    strategy_used=ReasoningStrategy.STANDARD
                )

            except Exception as e:
                if attempt < self.config.max_retries - 1:
                    await asyncio.sleep(self.config.retry_delay)
                    self.logger.warning(f"Retry {attempt + 1}/{self.config.max_retries}")
                else:
                    raise

    async def _infer_cot(
        self,
        query: str,
        context: Optional[str] = None,
        **kwargs
    ) -> LLMResponse:
        """Chain-of-Thought inference"""
        cot_chain = await self.cot_engine.generate_cot_chain(query, context)

        content, tokens = await self.llm_client.generate_with_tokens(
            cot_chain.conclusion,
            **kwargs
        )

        return LLMResponse(
            content=content,
            model=self.config.model_name,
            tokens_used=tokens,
            inference_time=0.0,
            strategy_used=ReasoningStrategy.COT,
            cot_chain=cot_chain
        )

    async def _infer_cot_with_verification(
        self,
        query: str,
        context: Optional[str] = None,
        **kwargs
    ) -> LLMResponse:
        """Chain-of-Thought with verification step"""
        # Generate initial CoT response
        initial_response = await self._infer_cot(query, context, **kwargs)

        # Verify response
        is_valid, verification = await self.cot_engine.verify_response(
            query,
            initial_response.content
        )

        # Update response metadata
        if initial_response.cot_chain:
            initial_response.cot_chain.metadata["verified"] = is_valid
            initial_response.cot_chain.metadata["verification"] = verification

        return initial_response

    def get_service_stats(self) -> Dict[str, Any]:
        """Get service statistics"""
        return {
            "total_requests": self._request_count,
            "total_tokens_used": self._total_tokens_used,
            "average_tokens_per_request": (
                self._total_tokens_used / self._request_count
                if self._request_count > 0 else 0
            ),
            "cache_stats": self.cache_manager.get_stats(),
            "config": asdict(self.config)
        }

    async def clear_cache(self) -> None:
        """Clear response cache"""
        self.cache_manager.clear()
        self.logger.info("Cache cleared")


# ============================================================================
# TESTING SECTION
# ============================================================================

class MockLLMClient(LLMClient):
    """Mock LLM Client for testing"""

    def __init__(self, responses: Optional[List[str]] = None):
        self.responses = responses or ["Mock response from LLM"]
        self.call_count = 0
        self.logger = logging.getLogger(__name__)

    async def generate(self, prompt: str, **kwargs) -> str:
        """Generate mock response"""
        self.call_count += 1
        response = self.responses[self.call_count % len(self.responses)]
        self.logger.info(f"Mock generation call #{self.call_count}")
        return response

    async def generate_with_tokens(self, prompt: str, **kwargs) -> Tuple[str, int]:
        """Generate mock response with token count"""
        response = await self.generate(prompt, **kwargs)
        # Mock token counting: roughly 1 token per 4 characters
        token_count = len(response) // 4
        return response, token_count


# ============================================================================
# Quick Test Suite
# ============================================================================

async def run_tests():
    """Run comprehensive tests for LLM Service"""

    print("\n" + "="*70)
    print("LLM SERVICE COMPREHENSIVE TEST SUITE")
    print("="*70 + "\n")

    # Setup logging
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Test 1: Cache Manager
    print("[TEST 1] Cache Manager")
    print("-" * 70)
    cache = CacheManager(CacheStrategy.LRU, size=10, ttl_seconds=3600)
    mock_response = LLMResponse(
        content="Test response",
        model="test-model",
        tokens_used=50,
        inference_time=1.5,
        strategy_used=ReasoningStrategy.STANDARD
    )
    cache.set("test_query", "test-model", {"temp": 0.7}, mock_response)
    retrieved = cache.get("test_query", "test-model", {"temp": 0.7})
    assert retrieved is not None, "Cache retrieval failed"
    assert retrieved.cache_hit == True, "Cache hit flag not set"
    print("✓ Cache storage and retrieval working\n")

    # Test 2: Prompt Builder
    print("[TEST 2] Prompt Builder")
    print("-" * 70)
    builder = PromptBuilder()
    cot_prompt = builder.build_cot_prompt("What is a buffer overflow?")
    assert "Think step by step" in cot_prompt, "CoT prompt format incorrect"
    verification_prompt = builder.build_verification_prompt(
        "Question",
        "Initial response"
    )
    assert "Verify" in verification_prompt, "Verification prompt format incorrect"
    print("✓ Prompt building working\n")

    # Test 3: LLM Service with Mock Client
    print("[TEST 3] LLM Service Inference")
    print("-" * 70)

    mock_client = MockLLMClient([
        "Analysis: This is a test analysis",
        "Reasoning: Key points identified",
        "Conclusion: Final verdict reached"
    ])

    config = LLMConfig(
        model_name="test-model",
        reasoning_strategy=ReasoningStrategy.COT,
        cache_strategy=CacheStrategy.LRU,
        cache_size=100
    )

    service = LLMService(mock_client, config)

    # Test standard inference
    response = await service.infer(
        "Test vulnerability analysis",
        strategy=ReasoningStrategy.STANDARD,
        include_context=False
    )
    assert response is not None, "Response is None"
    assert response.model == "test-model", "Model name mismatch"
    assert response.tokens_used > 0, "Token count incorrect"
    print(f"✓ Standard inference working - Response: {response.content[:50]}...\n")

    # Test 4: Cache Hit
    print("[TEST 4] Cache Hit Detection")
    print("-" * 70)
    same_query = "Test vulnerability analysis"
    response2 = await service.infer(
        same_query,
        strategy=ReasoningStrategy.STANDARD,
        include_context=False
    )
    assert response2.cache_hit == True, "Cache hit not detected"
    print("✓ Cache hit properly detected\n")

    # Test 5: Service Statistics
    print("[TEST 5] Service Statistics")
    print("-" * 70)
    stats = service.get_service_stats()
    print(f"Total requests: {stats['total_requests']}")
    print(f"Total tokens used: {stats['total_tokens_used']}")
    print(f"Cache utilization: {stats['cache_stats']['utilization']:.2%}")
    assert stats['total_requests'] > 0, "Statistics not tracked"
    print("✓ Service statistics working\n")

    # Test 6: Cache Expiration (TTL)
    print("[TEST 6] Cache TTL Expiration")
    print("-" * 70)
    short_cache = CacheManager(CacheStrategy.TTL, size=10, ttl_seconds=1)
    short_cache.set("expiring_query", "model", {}, mock_response)
    retrieved_before = short_cache.get("expiring_query", "model", {})
    assert retrieved_before is not None, "Cache entry should exist"
    await asyncio.sleep(1.5)  # Wait for expiration
    retrieved_after = short_cache.get("expiring_query", "model", {})
    assert retrieved_after is None, "Expired cache entry should not be retrieved"
    print("✓ Cache TTL expiration working\n")

    # Test 7: CoT Chain Generation
    print("[TEST 7] CoT Chain Generation")
    print("-" * 70)
    cot_chain = CotChain()
    cot_chain.add_step("Step 1: Initial analysis")
    cot_chain.add_step("Step 2: Identify components")
    cot_chain.add_step("Step 3: Draw conclusions")
    assert len(cot_chain.thought_steps) == 3, "CoT chain steps incorrect"
    chain_dict = cot_chain.to_dict()
    assert "thought_steps" in chain_dict, "CoT to_dict conversion failed"
    print(f"✓ CoT chain with {len(cot_chain.thought_steps)} steps working\n")

    # Test 8: Response Serialization
    print("[TEST 8] Response Serialization")
    print("-" * 70)
    test_response = LLMResponse(
        content="Test content",
        model="test-model",
        tokens_used=100,
        inference_time=2.5,
        strategy_used=ReasoningStrategy.COT_WITH_VERIFICATION
    )
    response_dict = test_response.to_dict()
    assert "timestamp" in response_dict, "Timestamp not in serialized response"
    assert response_dict["strategy_used"] == "cot_verify", "Strategy not serialized correctly"
    assert "cache_hit" in response_dict, "Cache hit not in serialized response"
    print("✓ Response serialization working\n")

    print("="*70)
    print("ALL TESTS PASSED ✓")
    print("="*70 + "\n")

    return True


# ============================================================================
# Main Entry Point
# ============================================================================

if __name__ == "__main__":
    # Run test suite
    success = asyncio.run(run_tests())
    if success:
        print("LLM Service is ready for integration!")