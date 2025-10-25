"""
LLM Models - Language Model Data Models and Structures

This module contains data models for managing language model interactions,
prompts, completions, embeddings, and inference results in the HyFuzz
Windows MCP Server.

Models:
    - LLMPrompt: Prompt configuration and metadata
    - LLMCompletion: Model completion/response
    - EmbeddingData: Vector embedding information
    - TokenUsage: Token counting and usage tracking
    - CoTReasoning: Chain-of-Thought reasoning steps
    - LLMInferenceResult: Complete inference result
    - LLMCache: Cached inference results

Author: HyFuzz Team
Version: 1.0.0
"""

from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timezone
from enum import Enum
import json


# ============================================================================
# ENUMS
# ============================================================================

class PromptType(str, Enum):
    """Enumeration of prompt types."""
    QUESTION = "question"
    INSTRUCTION = "instruction"
    CONTEXT = "context"
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"


class CompletionStatus(str, Enum):
    """Enumeration of completion status."""
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ReasoningType(str, Enum):
    """Enumeration of reasoning types."""
    CHAIN_OF_THOUGHT = "chain_of_thought"
    STEP_BY_STEP = "step_by_step"
    ANALYTICAL = "analytical"
    HEURISTIC = "heuristic"
    HYBRID = "hybrid"


# ============================================================================
# 1. LLMPrompt DATA MODEL
# ============================================================================

@dataclass
class LLMPrompt:
    """
    Prompt configuration and metadata for LLM inference.

    Attributes:
        prompt_id: Unique prompt identifier
        prompt_type: Type of prompt (question, instruction, etc.)
        content: Prompt text content
        system_prompt: System-level instructions
        context: Additional context information
        parameters: LLM inference parameters
        template_variables: Variables in template prompts
        max_tokens: Maximum tokens for response
        temperature: Temperature parameter (0.0-2.0)
        top_p: Top-p sampling parameter
        top_k: Top-k sampling parameter
        created_at: Creation timestamp
        metadata: Additional metadata
        tags: Classification tags
    """
    prompt_id: str
    prompt_type: PromptType = PromptType.QUESTION
    content: str = ""
    system_prompt: Optional[str] = None
    context: Optional[str] = None
    parameters: Dict[str, Any] = field(default_factory=dict)
    template_variables: Dict[str, str] = field(default_factory=dict)
    max_tokens: int = 512
    temperature: float = 0.7
    top_p: float = 0.9
    top_k: int = 40
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)

    def __post_init__(self):
        """Validate and normalize prompt data."""
        if self.temperature < 0.0:
            self.temperature = 0.0
        elif self.temperature > 2.0:
            self.temperature = 2.0

        if self.top_p < 0.0 or self.top_p > 1.0:
            self.top_p = 0.9

        if self.top_k < 1:
            self.top_k = 40

        if self.max_tokens < 1:
            self.max_tokens = 512

    def render(self) -> str:
        """Render prompt with template variables."""
        rendered = self.content
        for var, value in self.template_variables.items():
            placeholder = f"{{{{{var}}}}}"
            rendered = rendered.replace(placeholder, str(value))
        return rendered

    def add_tag(self, tag: str) -> None:
        """Add classification tag."""
        if tag not in self.tags:
            self.tags.append(tag)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "prompt_id": self.prompt_id,
            "prompt_type": self.prompt_type.value,
            "content": self.content,
            "system_prompt": self.system_prompt,
            "context": self.context,
            "parameters": self.parameters,
            "template_variables": self.template_variables,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "top_p": self.top_p,
            "top_k": self.top_k,
            "created_at": self.created_at.isoformat(),
            "metadata": self.metadata,
            "tags": self.tags
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'LLMPrompt':
        """Create LLMPrompt from dictionary."""
        return LLMPrompt(
            prompt_id=data.get("prompt_id", ""),
            prompt_type=PromptType(data.get("prompt_type", "question")),
            content=data.get("content", ""),
            system_prompt=data.get("system_prompt"),
            context=data.get("context"),
            parameters=data.get("parameters", {}),
            template_variables=data.get("template_variables", {}),
            max_tokens=data.get("max_tokens", 512),
            temperature=data.get("temperature", 0.7),
            top_p=data.get("top_p", 0.9),
            top_k=data.get("top_k", 40),
            created_at=datetime.fromisoformat(data.get("created_at")) if data.get("created_at") else datetime.now(timezone.utc),
            metadata=data.get("metadata", {}),
            tags=data.get("tags", [])
        )


# ============================================================================
# 2. TokenUsage DATA MODEL
# ============================================================================

@dataclass
class TokenUsage:
    """
    Token usage and counting information.

    Attributes:
        prompt_tokens: Number of tokens in prompt
        completion_tokens: Number of tokens in completion
        total_tokens: Total tokens used
        cached_tokens: Number of cached tokens (if applicable)
        input_cost: Cost for input tokens
        output_cost: Cost for output tokens
        total_cost: Total cost
        efficiency_score: Efficiency score (0-100)
    """
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    cached_tokens: int = 0
    input_cost: float = 0.0
    output_cost: float = 0.0
    total_cost: float = 0.0
    efficiency_score: float = 100.0

    def __post_init__(self):
        """Calculate totals."""
        self.total_tokens = self.prompt_tokens + self.completion_tokens
        self.total_cost = self.input_cost + self.output_cost

    def calculate_efficiency(self, target_tokens: int = 1000) -> float:
        """Calculate efficiency score."""
        if target_tokens == 0:
            return 100.0
        efficiency = (target_tokens / max(self.total_tokens, 1)) * 100
        self.efficiency_score = min(efficiency, 100.0)
        return self.efficiency_score

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "cached_tokens": self.cached_tokens,
            "input_cost": self.input_cost,
            "output_cost": self.output_cost,
            "total_cost": self.total_cost,
            "efficiency_score": self.efficiency_score
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)


# ============================================================================
# 3. LLMCompletion DATA MODEL
# ============================================================================

@dataclass
class LLMCompletion:
    """
    Model completion/response from LLM inference.

    Attributes:
        completion_id: Unique completion identifier
        prompt_id: Associated prompt ID
        model_name: Name of model used
        content: Generated completion text
        status: Completion status
        finish_reason: Why generation stopped
        confidence_score: Confidence in response (0-1)
        token_usage: Token usage information
        generation_time_ms: Time taken to generate
        created_at: Creation timestamp
        metadata: Additional metadata
    """
    completion_id: str
    prompt_id: str
    model_name: str = ""
    content: str = ""
    status: CompletionStatus = CompletionStatus.COMPLETED
    finish_reason: str = "stop"
    confidence_score: float = 1.0
    token_usage: TokenUsage = field(default_factory=TokenUsage)
    generation_time_ms: int = 0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Validate completion data."""
        if self.confidence_score < 0.0:
            self.confidence_score = 0.0
        elif self.confidence_score > 1.0:
            self.confidence_score = 1.0

    def is_successful(self) -> bool:
        """Check if completion was successful."""
        return self.status == CompletionStatus.COMPLETED

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "completion_id": self.completion_id,
            "prompt_id": self.prompt_id,
            "model_name": self.model_name,
            "content": self.content,
            "status": self.status.value,
            "finish_reason": self.finish_reason,
            "confidence_score": self.confidence_score,
            "token_usage": self.token_usage.to_dict(),
            "generation_time_ms": self.generation_time_ms,
            "created_at": self.created_at.isoformat(),
            "metadata": self.metadata
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'LLMCompletion':
        """Create LLMCompletion from dictionary."""
        token_data = data.get("token_usage", {})
        token_usage = TokenUsage(**token_data) if token_data else TokenUsage()

        return LLMCompletion(
            completion_id=data.get("completion_id", ""),
            prompt_id=data.get("prompt_id", ""),
            model_name=data.get("model_name", ""),
            content=data.get("content", ""),
            status=CompletionStatus(data.get("status", "completed")),
            finish_reason=data.get("finish_reason", "stop"),
            confidence_score=data.get("confidence_score", 1.0),
            token_usage=token_usage,
            generation_time_ms=data.get("generation_time_ms", 0),
            created_at=datetime.fromisoformat(data.get("created_at")) if data.get("created_at") else datetime.now(timezone.utc),
            metadata=data.get("metadata", {})
        )


# ============================================================================
# 4. EmbeddingData DATA MODEL
# ============================================================================

@dataclass
class EmbeddingData:
    """
    Vector embedding information for text.

    Attributes:
        embedding_id: Unique embedding identifier
        text: Original text
        embedding_model: Model used for embedding
        vector: Embedding vector
        dimension: Vector dimension
        norm: L2 norm of vector
        similarity_scores: Similarity scores with other embeddings
        created_at: Creation timestamp
        metadata: Additional metadata
    """
    embedding_id: str
    text: str
    embedding_model: str = "default"
    vector: List[float] = field(default_factory=list)
    dimension: int = 0
    norm: float = 0.0
    similarity_scores: Dict[str, float] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Calculate embedding properties."""
        if self.vector:
            self.dimension = len(self.vector)
            # Calculate L2 norm
            sum_sq = sum(v * v for v in self.vector)
            self.norm = sum_sq ** 0.5

    def cosine_similarity(self, other: 'EmbeddingData') -> float:
        """Calculate cosine similarity with another embedding."""
        if not self.vector or not other.vector:
            return 0.0

        if len(self.vector) != len(other.vector):
            return 0.0

        dot_product = sum(a * b for a, b in zip(self.vector, other.vector))
        norm_product = self.norm * other.norm

        if norm_product == 0.0:
            return 0.0

        return dot_product / norm_product

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "embedding_id": self.embedding_id,
            "text": self.text,
            "embedding_model": self.embedding_model,
            "vector": self.vector,
            "dimension": self.dimension,
            "norm": self.norm,
            "similarity_scores": self.similarity_scores,
            "created_at": self.created_at.isoformat(),
            "metadata": self.metadata
        }

    def to_json(self) -> str:
        """Convert to JSON string (without vector for brevity)."""
        data = self.to_dict()
        data["vector"] = f"[vector with {len(self.vector)} dimensions]"
        return json.dumps(data, indent=2)


# ============================================================================
# 5. CoTReasoning DATA MODEL
# ============================================================================

@dataclass
class CoTReasoning:
    """
    Chain-of-Thought reasoning steps and intermediate results.

    Attributes:
        reasoning_id: Unique reasoning identifier
        prompt_id: Associated prompt ID
        reasoning_type: Type of reasoning
        steps: List of reasoning steps
        intermediate_results: Results after each step
        final_answer: Final reasoning answer
        reasoning_quality_score: Quality assessment (0-100)
        total_steps: Total number of steps
        execution_time_ms: Execution time
        created_at: Creation timestamp
    """
    reasoning_id: str
    prompt_id: str
    reasoning_type: ReasoningType = ReasoningType.CHAIN_OF_THOUGHT
    steps: List[str] = field(default_factory=list)
    intermediate_results: List[str] = field(default_factory=list)
    final_answer: str = ""
    reasoning_quality_score: float = 0.0
    total_steps: int = 0
    execution_time_ms: int = 0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self):
        """Calculate properties."""
        self.total_steps = len(self.steps)
        if self.reasoning_quality_score < 0.0 or self.reasoning_quality_score > 100.0:
            self.reasoning_quality_score = 0.0

    def add_step(self, step: str, result: str = "") -> None:
        """Add reasoning step."""
        self.steps.append(step)
        if result:
            self.intermediate_results.append(result)
        self.total_steps = len(self.steps)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "reasoning_id": self.reasoning_id,
            "prompt_id": self.prompt_id,
            "reasoning_type": self.reasoning_type.value,
            "steps": self.steps,
            "intermediate_results": self.intermediate_results,
            "final_answer": self.final_answer,
            "reasoning_quality_score": self.reasoning_quality_score,
            "total_steps": self.total_steps,
            "execution_time_ms": self.execution_time_ms,
            "created_at": self.created_at.isoformat()
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'CoTReasoning':
        """Create CoTReasoning from dictionary."""
        return CoTReasoning(
            reasoning_id=data.get("reasoning_id", ""),
            prompt_id=data.get("prompt_id", ""),
            reasoning_type=ReasoningType(data.get("reasoning_type", "chain_of_thought")),
            steps=data.get("steps", []),
            intermediate_results=data.get("intermediate_results", []),
            final_answer=data.get("final_answer", ""),
            reasoning_quality_score=data.get("reasoning_quality_score", 0.0),
            total_steps=data.get("total_steps", 0),
            execution_time_ms=data.get("execution_time_ms", 0),
            created_at=datetime.fromisoformat(data.get("created_at")) if data.get("created_at") else datetime.now(timezone.utc)
        )


# ============================================================================
# 6. LLMInferenceResult DATA MODEL
# ============================================================================

@dataclass
class LLMInferenceResult:
    """
    Complete inference result combining prompt, completion, and metadata.

    Attributes:
        inference_id: Unique inference identifier
        prompt: LLMPrompt used
        completion: LLMCompletion result
        cot_reasoning: Chain-of-Thought reasoning (optional)
        embeddings: Associated embeddings (optional)
        model_name: Model used
        success: Whether inference succeeded
        error_message: Error message if failed
        latency_ms: Total latency in milliseconds
        created_at: Creation timestamp
        metadata: Additional metadata
    """
    inference_id: str
    prompt: Optional[LLMPrompt] = None
    completion: Optional[LLMCompletion] = None
    cot_reasoning: Optional[CoTReasoning] = None
    embeddings: List[EmbeddingData] = field(default_factory=list)
    model_name: str = ""
    success: bool = True
    error_message: str = ""
    latency_ms: int = 0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)

    def get_output(self) -> str:
        """Get inference output text."""
        if self.completion:
            return self.completion.content
        elif self.cot_reasoning:
            return self.cot_reasoning.final_answer
        return ""

    def get_total_tokens(self) -> int:
        """Get total tokens used."""
        if self.completion and self.completion.token_usage:
            return self.completion.token_usage.total_tokens
        return 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "inference_id": self.inference_id,
            "prompt": self.prompt.to_dict() if self.prompt else None,
            "completion": self.completion.to_dict() if self.completion else None,
            "cot_reasoning": self.cot_reasoning.to_dict() if self.cot_reasoning else None,
            "embeddings": [e.to_dict() for e in self.embeddings],
            "model_name": self.model_name,
            "success": self.success,
            "error_message": self.error_message,
            "latency_ms": self.latency_ms,
            "created_at": self.created_at.isoformat(),
            "metadata": self.metadata
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2, default=str)

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'LLMInferenceResult':
        """Create LLMInferenceResult from dictionary."""
        prompt = LLMPrompt.from_dict(data.get("prompt")) if data.get("prompt") else None
        completion = LLMCompletion.from_dict(data.get("completion")) if data.get("completion") else None
        cot = CoTReasoning.from_dict(data.get("cot_reasoning")) if data.get("cot_reasoning") else None

        return LLMInferenceResult(
            inference_id=data.get("inference_id", ""),
            prompt=prompt,
            completion=completion,
            cot_reasoning=cot,
            embeddings=data.get("embeddings", []),
            model_name=data.get("model_name", ""),
            success=data.get("success", True),
            error_message=data.get("error_message", ""),
            latency_ms=data.get("latency_ms", 0),
            created_at=datetime.fromisoformat(data.get("created_at")) if data.get("created_at") else datetime.now(timezone.utc),
            metadata=data.get("metadata", {})
        )


# ============================================================================
# 7. LLMCache DATA MODEL
# ============================================================================

@dataclass
class LLMCache:
    """
    Cached inference results for reuse.

    Attributes:
        cache_id: Unique cache identifier
        prompt_hash: Hash of the prompt
        inference_result: Cached inference result
        cache_hits: Number of cache hits
        hit_rate: Cache hit rate (0-1)
        created_at: Cache creation timestamp
        last_accessed: Last access timestamp
        expires_at: Cache expiration timestamp
        ttl_seconds: Time-to-live in seconds
        size_bytes: Cache size in bytes
    """
    cache_id: str
    prompt_hash: str
    inference_result: Optional[LLMInferenceResult] = None
    cache_hits: int = 0
    hit_rate: float = 0.0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_accessed: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    ttl_seconds: int = 3600
    size_bytes: int = 0

    def is_expired(self) -> bool:
        """Check if cache entry has expired."""
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at

    def update_access(self) -> None:
        """Update last accessed time and increment hit counter."""
        self.last_accessed = datetime.now(timezone.utc)
        self.cache_hits += 1

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "cache_id": self.cache_id,
            "prompt_hash": self.prompt_hash,
            "inference_result": self.inference_result.to_dict() if self.inference_result else None,
            "cache_hits": self.cache_hits,
            "hit_rate": self.hit_rate,
            "created_at": self.created_at.isoformat(),
            "last_accessed": self.last_accessed.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "ttl_seconds": self.ttl_seconds,
            "size_bytes": self.size_bytes
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2, default=str)


# ============================================================================
# VALIDATION AND TESTING
# ============================================================================

def run_validation_tests():
    """
    Run validation tests for all LLM models.
    """
    print("=" * 70)
    print("LLM Models - Validation Tests")
    print("=" * 70)
    print()

    # Test 1: LLMPrompt
    print("[TEST 1] LLMPrompt Model...")
    try:
        prompt = LLMPrompt(
            prompt_id="PROMPT-001",
            prompt_type=PromptType.QUESTION,
            content="What is the capital of France?",
            max_tokens=50,
            temperature=0.5
        )
        prompt.add_tag("geography")
        assert prompt.prompt_id == "PROMPT-001"
        assert len(prompt.tags) == 1
        assert prompt.to_dict() is not None
        print("  ✓ LLMPrompt creation successful")
        print(f"  ✓ Prompt ID: {prompt.prompt_id}")
        print(f"  ✓ Temperature: {prompt.temperature}")
        print()
    except Exception as e:
        print(f"  ✗ LLMPrompt test failed: {str(e)}")
        print()

    # Test 2: TokenUsage
    print("[TEST 2] TokenUsage Model...")
    try:
        tokens = TokenUsage(
            prompt_tokens=50,
            completion_tokens=30,
            input_cost=0.001,
            output_cost=0.002
        )
        assert tokens.total_tokens == 80
        assert tokens.total_cost == 0.003
        efficiency = tokens.calculate_efficiency(100)
        assert efficiency > 0
        print("  ✓ TokenUsage creation successful")
        print(f"  ✓ Total tokens: {tokens.total_tokens}")
        print(f"  ✓ Total cost: {tokens.total_cost}")
        print(f"  ✓ Efficiency: {efficiency:.1f}%")
        print()
    except Exception as e:
        print(f"  ✗ TokenUsage test failed: {str(e)}")
        print()

    # Test 3: LLMCompletion
    print("[TEST 3] LLMCompletion Model...")
    try:
        tokens = TokenUsage(prompt_tokens=50, completion_tokens=25)
        completion = LLMCompletion(
            completion_id="COMP-001",
            prompt_id="PROMPT-001",
            model_name="llama2",
            content="Paris is the capital of France.",
            status=CompletionStatus.COMPLETED,
            confidence_score=0.95,
            token_usage=tokens,
            generation_time_ms=1500
        )
        assert completion.is_successful()
        assert completion.confidence_score == 0.95
        print("  ✓ LLMCompletion creation successful")
        print(f"  ✓ Model: {completion.model_name}")
        print(f"  ✓ Confidence: {completion.confidence_score}")
        print(f"  ✓ Generation time: {completion.generation_time_ms}ms")
        print()
    except Exception as e:
        print(f"  ✗ LLMCompletion test failed: {str(e)}")
        print()

    # Test 4: EmbeddingData
    print("[TEST 4] EmbeddingData Model...")
    try:
        embedding = EmbeddingData(
            embedding_id="EMB-001",
            text="Hello world",
            embedding_model="nomic-embed-text",
            vector=[0.1, 0.2, 0.3, 0.4, 0.5]
        )
        assert embedding.dimension == 5
        assert embedding.norm > 0

        embedding2 = EmbeddingData(
            embedding_id="EMB-002",
            text="Hello there",
            embedding_model="nomic-embed-text",
            vector=[0.1, 0.2, 0.3, 0.4, 0.5]
        )
        similarity = embedding.cosine_similarity(embedding2)
        assert similarity == 1.0  # Identical vectors
        print("  ✓ EmbeddingData creation successful")
        print(f"  ✓ Dimension: {embedding.dimension}")
        print(f"  ✓ Norm: {embedding.norm:.3f}")
        print(f"  ✓ Similarity: {similarity:.3f}")
        print()
    except Exception as e:
        print(f"  ✗ EmbeddingData test failed: {str(e)}")
        print()

    # Test 5: CoTReasoning
    print("[TEST 5] CoTReasoning Model...")
    try:
        cot = CoTReasoning(
            reasoning_id="COT-001",
            prompt_id="PROMPT-001",
            reasoning_type=ReasoningType.CHAIN_OF_THOUGHT
        )
        cot.add_step("Step 1: Identify the question", "Question is about capitals")
        cot.add_step("Step 2: Recall knowledge", "France -> Paris")
        cot.final_answer = "Paris"
        cot.reasoning_quality_score = 95.0
        assert cot.total_steps == 2
        assert len(cot.intermediate_results) == 2
        print("  ✓ CoTReasoning creation successful")
        print(f"  ✓ Total steps: {cot.total_steps}")
        print(f"  ✓ Quality score: {cot.reasoning_quality_score}")
        print(f"  ✓ Final answer: {cot.final_answer}")
        print()
    except Exception as e:
        print(f"  ✗ CoTReasoning test failed: {str(e)}")
        print()

    # Test 6: LLMInferenceResult
    print("[TEST 6] LLMInferenceResult Model...")
    try:
        prompt = LLMPrompt(
            prompt_id="PROMPT-001",
            content="What is AI?",
            max_tokens=100
        )
        tokens = TokenUsage(prompt_tokens=10, completion_tokens=50)
        completion = LLMCompletion(
            completion_id="COMP-001",
            prompt_id="PROMPT-001",
            model_name="llama2",
            content="AI is artificial intelligence...",
            token_usage=tokens,
            generation_time_ms=2000
        )
        result = LLMInferenceResult(
            inference_id="INF-001",
            prompt=prompt,
            completion=completion,
            model_name="llama2",
            success=True,
            latency_ms=2100
        )
        assert result.get_output() == "AI is artificial intelligence..."
        assert result.get_total_tokens() == 60
        print("  ✓ LLMInferenceResult creation successful")
        print(f"  ✓ Output length: {len(result.get_output())} chars")
        print(f"  ✓ Total tokens: {result.get_total_tokens()}")
        print(f"  ✓ Latency: {result.latency_ms}ms")
        print()
    except Exception as e:
        print(f"  ✗ LLMInferenceResult test failed: {str(e)}")
        print()

    # Test 7: LLMCache
    print("[TEST 7] LLMCache Model...")
    try:
        prompt = LLMPrompt(prompt_id="PROMPT-001", content="Test")
        tokens = TokenUsage(prompt_tokens=10, completion_tokens=20)
        completion = LLMCompletion(
            completion_id="COMP-001",
            prompt_id="PROMPT-001",
            content="Test response",
            token_usage=tokens
        )
        result = LLMInferenceResult(
            inference_id="INF-001",
            prompt=prompt,
            completion=completion
        )

        cache = LLMCache(
            cache_id="CACHE-001",
            prompt_hash="abc123def456",
            inference_result=result,
            ttl_seconds=3600
        )
        assert not cache.is_expired()
        cache.update_access()
        assert cache.cache_hits == 1
        print("  ✓ LLMCache creation successful")
        print(f"  ✓ Cache hits: {cache.cache_hits}")
        print(f"  ✓ Expired: {cache.is_expired()}")
        print(f"  ✓ TTL: {cache.ttl_seconds}s")
        print()
    except Exception as e:
        print(f"  ✗ LLMCache test failed: {str(e)}")
        print()

    # Summary
    print("=" * 70)
    print("✓ LLM Models Validation Complete")
    print("=" * 70)
    print()
    print("Available Models:")
    print("  • LLMPrompt (Prompt configuration)")
    print("  • TokenUsage (Token counting)")
    print("  • LLMCompletion (Model responses)")
    print("  • EmbeddingData (Vector embeddings)")
    print("  • CoTReasoning (Chain-of-Thought)")
    print("  • LLMInferenceResult (Complete inference)")
    print("  • LLMCache (Cached results)")


if __name__ == "__main__":
    run_validation_tests()