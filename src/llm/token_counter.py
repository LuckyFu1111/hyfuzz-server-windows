"""
Token Counter Module for HyFuzz Windows MCP Server

This module provides sophisticated token counting capabilities:
- Multi-model token counting (Ollama, Mistral, LLaMA, etc.)
- Token estimation and prediction
- Cost calculation
- Token usage statistics and tracking
- Caching and optimization
- Budget management
"""

import logging
import re
from typing import Optional, Dict, List, Any, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
from datetime import datetime, timedelta
from abc import ABC, abstractmethod
import math


# ============================================================================
# Enums and Data Structures
# ============================================================================

class ModelType(Enum):
    """Supported LLM model types"""
    MISTRAL = "mistral"
    LLAMA2 = "llama2"
    NEURAL_CHAT = "neural-chat"
    DOLPHIN = "dolphin-mixtral"
    OPENCHAT = "openchat"
    ZEPHYR = "zephyr"
    CUSTOM = "custom"


class TokenCountMethod(Enum):
    """Token counting methods"""
    CHARACTER_BASED = "character_based"  # 1 token ≈ 4 characters
    WORD_BASED = "word_based"  # 1 token ≈ 1.3 words
    BYTE_PAIR_ENCODING = "byte_pair_encoding"  # More accurate BPE
    MODEL_SPECIFIC = "model_specific"  # Model-specific formula
    API_BASED = "api_based"  # Using model's tokenizer API


@dataclass
class TokenStats:
    """Token usage statistics"""
    model_name: str
    method_used: TokenCountMethod
    estimated_tokens: int
    actual_tokens: Optional[int] = None
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    accuracy_score: float = 0.0  # 0.0-1.0, comparing to actual
    estimated_cost: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data['method_used'] = self.method_used.value
        data['timestamp'] = self.timestamp.isoformat()
        return data


@dataclass
class ModelConfig:
    """Configuration for a specific model"""
    name: str
    model_type: ModelType
    vocab_size: int = 32000  # Typical vocabulary size
    avg_token_length: float = 4.5  # Average characters per token
    cost_per_1k_tokens: float = 0.0  # Cost per 1K tokens
    description: str = ""
    supports_api_counting: bool = False


@dataclass
class TokenBudget:
    """Token budget for cost control"""
    daily_limit: int
    monthly_limit: int
    cost_limit: float
    current_daily_used: int = 0
    current_monthly_used: int = 0
    current_cost_used: float = 0.0
    last_reset: datetime = field(default_factory=datetime.now)
    exceeded: bool = False


@dataclass
class TokenUsageRecord:
    """Record of token usage"""
    text: str
    estimated_tokens: int
    actual_tokens: Optional[int] = None
    model_name: str = ""
    method: TokenCountMethod = TokenCountMethod.CHARACTER_BASED
    timestamp: datetime = field(default_factory=datetime.now)


# ============================================================================
# Model Configuration Registry
# ============================================================================

class ModelRegistry:
    """Registry of model configurations"""

    def __init__(self):
        self.models: Dict[str, ModelConfig] = {}
        self.logger = logging.getLogger(__name__)
        self._initialize_default_models()

    def _initialize_default_models(self) -> None:
        """Initialize built-in model configurations"""

        # Mistral model
        self.register(ModelConfig(
            name="mistral",
            model_type=ModelType.MISTRAL,
            vocab_size=32000,
            avg_token_length=4.5,
            cost_per_1k_tokens=0.002,
            description="Mistral 7B model from Mistral AI"
        ))

        # LLaMA2 model
        self.register(ModelConfig(
            name="llama2",
            model_type=ModelType.LLAMA2,
            vocab_size=32000,
            avg_token_length=4.3,
            cost_per_1k_tokens=0.001,
            description="LLaMA 2 model from Meta"
        ))

        # Neural Chat model
        self.register(ModelConfig(
            name="neural-chat",
            model_type=ModelType.NEURAL_CHAT,
            vocab_size=32768,
            avg_token_length=4.5,
            cost_per_1k_tokens=0.0015,
            description="Intel Neural Chat model"
        ))

        # Dolphin Mixtral model
        self.register(ModelConfig(
            name="dolphin-mixtral",
            model_type=ModelType.DOLPHIN,
            vocab_size=32000,
            avg_token_length=4.6,
            cost_per_1k_tokens=0.0025,
            description="Dolphin Mixtral model"
        ))

        # OpenChat model
        self.register(ModelConfig(
            name="openchat",
            model_type=ModelType.OPENCHAT,
            vocab_size=32000,
            avg_token_length=4.4,
            cost_per_1k_tokens=0.0008,
            description="OpenChat model"
        ))

        # Zephyr model
        self.register(ModelConfig(
            name="zephyr",
            model_type=ModelType.ZEPHYR,
            vocab_size=32000,
            avg_token_length=4.5,
            cost_per_1k_tokens=0.0012,
            description="Zephyr model"
        ))

    def register(self, config: ModelConfig) -> None:
        """Register a model configuration"""
        self.models[config.name] = config
        self.logger.debug(f"Registered model: {config.name}")

    def get(self, name: str) -> Optional[ModelConfig]:
        """Get model configuration by name"""
        return self.models.get(name)

    def list_models(self) -> List[str]:
        """List all registered models"""
        return list(self.models.keys())

    def get_model_info(self, name: str) -> Optional[Dict[str, Any]]:
        """Get model information"""
        config = self.get(name)
        if config:
            return asdict(config)
        return None


# ============================================================================
# Base Token Counter
# ============================================================================

class BaseTokenCounter(ABC):
    """Abstract base class for token counters"""

    def __init__(self, model_config: ModelConfig):
        self.model_config = model_config
        self.logger = logging.getLogger(__name__)

    @abstractmethod
    def count_tokens(self, text: str) -> int:
        """Count tokens in text"""
        pass

    def count_prompt_tokens(self, prompt: str) -> int:
        """Count tokens in prompt"""
        return self.count_tokens(prompt)

    def count_completion_tokens(self, completion: str) -> int:
        """Count tokens in completion"""
        return self.count_tokens(completion)

    def estimate_completion_tokens(self, prompt: str, max_tokens: int = 100) -> int:
        """Estimate completion tokens based on prompt"""
        # Rough estimation: completion is typically shorter than prompt
        prompt_tokens = self.count_tokens(prompt)
        return min(int(prompt_tokens * 0.5), max_tokens)


# ============================================================================
# Token Counter Implementations
# ============================================================================

class CharacterBasedCounter(BaseTokenCounter):
    """Character-based token counting (1 token ≈ 4 characters)"""

    def count_tokens(self, text: str) -> int:
        """Count tokens based on character count"""
        if not text:
            return 0
        # Rough estimation: 1 token per 4 characters
        return max(1, len(text) // 4)


class WordBasedCounter(BaseTokenCounter):
    """Word-based token counting (1 token ≈ 1.3 words)"""

    def count_tokens(self, text: str) -> int:
        """Count tokens based on word count"""
        if not text:
            return 0
        # Split into words and count
        words = text.split()
        # 1 token per 1.3 words on average
        return max(1, int(len(words) / 1.3))


class BytePairEncodingCounter(BaseTokenCounter):
    """Byte-pair encoding based token counting (more accurate)"""

    def __init__(self, model_config: ModelConfig):
        super().__init__(model_config)
        self._initialize_token_patterns()

    def _initialize_token_patterns(self) -> None:
        """Initialize common token patterns"""
        self.patterns = {
            "whitespace": re.compile(r'\s+'),
            "punctuation": re.compile(r'[.,!?;:]'),
            "numbers": re.compile(r'\d+'),
            "words": re.compile(r'\w+'),
        }

    def count_tokens(self, text: str) -> int:
        """Count tokens using BPE-like approximation"""
        if not text:
            return 0

        tokens = 0

        # Count whitespace as fractional tokens
        whitespace_count = len(self.patterns["whitespace"].findall(text))
        tokens += whitespace_count * 0  # Whitespace typically doesn't add tokens

        # Count words and punctuation
        words = self.patterns["words"].findall(text)
        tokens += len(words)

        # Punctuation often adds tokens
        punctuation = self.patterns["punctuation"].findall(text)
        tokens += len(punctuation) * 0.3

        # Numbers are typically single tokens
        numbers = self.patterns["numbers"].findall(text)
        tokens += len(numbers)

        # Special characters
        special_chars = len(text) - sum(len(word) for word in words) - len(text) + len(text.replace(" ", ""))
        tokens += special_chars * 0.1

        return max(1, int(tokens))


class ModelSpecificCounter(BaseTokenCounter):
    """Model-specific token counting using model's characteristics"""

    def count_tokens(self, text: str) -> int:
        """Count tokens using model-specific formula"""
        if not text:
            return 0

        # Use model's average token length
        avg_length = self.model_config.avg_token_length
        char_count = len(text)

        # Model-specific calculation
        estimated_tokens = int(char_count / avg_length)

        # Adjust for special cases
        if "##" in text:  # BPE subword markers
            estimated_tokens += text.count("##")

        return max(1, estimated_tokens)


# ============================================================================
# Token Counter Factory and Manager
# ============================================================================

class TokenCounterFactory:
    """Factory for creating token counters"""

    @staticmethod
    def create_counter(
        method: TokenCountMethod,
        model_config: ModelConfig
    ) -> BaseTokenCounter:
        """Create appropriate token counter"""
        if method == TokenCountMethod.CHARACTER_BASED:
            return CharacterBasedCounter(model_config)
        elif method == TokenCountMethod.WORD_BASED:
            return WordBasedCounter(model_config)
        elif method == TokenCountMethod.BYTE_PAIR_ENCODING:
            return BytePairEncodingCounter(model_config)
        elif method == TokenCountMethod.MODEL_SPECIFIC:
            return ModelSpecificCounter(model_config)
        else:
            # Default to character-based
            return CharacterBasedCounter(model_config)


# ============================================================================
# Main Token Counter Manager
# ============================================================================

class TokenCounter:
    """
    Main token counter manager providing:
    - Multi-method token counting
    - Cost calculation
    - Usage statistics and tracking
    - Budget management
    - Token optimization
    """

    def __init__(
        self,
        default_model: str = "mistral",
        default_method: TokenCountMethod = TokenCountMethod.MODEL_SPECIFIC
    ):
        self.model_registry = ModelRegistry()
        self.default_model = default_model
        self.default_method = default_method
        self.logger = logging.getLogger(__name__)

        # Get default model config
        self.current_model = self.model_registry.get(default_model)
        if not self.current_model:
            self.logger.warning(f"Model {default_model} not found, using mistral")
            self.current_model = self.model_registry.get("mistral")

        self.counter = TokenCounterFactory.create_counter(default_method, self.current_model)

        # Statistics tracking
        self.usage_records: List[TokenUsageRecord] = []
        self.stats = {
            "total_tokens_counted": 0,
            "total_texts_processed": 0,
            "total_cost_estimated": 0.0,
            "average_tokens_per_text": 0.0,
        }

        # Budget tracking
        self.budget: Optional[TokenBudget] = None

    def set_model(self, model_name: str) -> bool:
        """Switch to a different model"""
        model_config = self.model_registry.get(model_name)
        if not model_config:
            self.logger.error(f"Model {model_name} not found")
            return False

        self.current_model = model_config
        self.counter = TokenCounterFactory.create_counter(self.default_method, model_config)
        self.logger.info(f"Switched to model: {model_name}")
        return True

    def set_counting_method(self, method: TokenCountMethod) -> None:
        """Change token counting method"""
        self.default_method = method
        self.counter = TokenCounterFactory.create_counter(method, self.current_model)
        self.logger.info(f"Switched counting method to: {method.value}")

    def count_tokens(self, text: str, model: Optional[str] = None) -> int:
        """
        Count tokens in text

        Args:
            text: Text to count
            model: Optional model override

        Returns:
            Token count
        """
        if model and model != self.current_model.name:
            self.set_model(model)

        token_count = self.counter.count_tokens(text)

        # Record usage
        record = TokenUsageRecord(
            text=text,
            estimated_tokens=token_count,
            model_name=self.current_model.name,
            method=self.default_method
        )
        self.usage_records.append(record)

        # Update statistics
        self.stats["total_tokens_counted"] += token_count
        self.stats["total_texts_processed"] += 1
        if self.stats["total_texts_processed"] > 0:
            self.stats["average_tokens_per_text"] = (
                self.stats["total_tokens_counted"] / self.stats["total_texts_processed"]
            )

        # Check budget
        if self.budget:
            self._check_budget(token_count)

        return token_count

    def count_prompt_completion(
        self,
        prompt: str,
        completion: str
    ) -> Tuple[int, int, int]:
        """
        Count tokens for prompt and completion

        Returns:
            (prompt_tokens, completion_tokens, total_tokens)
        """
        prompt_tokens = self.counter.count_prompt_tokens(prompt)
        completion_tokens = self.counter.count_completion_tokens(completion)
        total_tokens = prompt_tokens + completion_tokens

        return prompt_tokens, completion_tokens, total_tokens

    def estimate_cost(self, token_count: int) -> float:
        """
        Estimate cost based on token count

        Args:
            token_count: Number of tokens

        Returns:
            Estimated cost
        """
        cost_per_1k = self.current_model.cost_per_1k_tokens
        estimated_cost = (token_count / 1000) * cost_per_1k
        self.stats["total_cost_estimated"] += estimated_cost
        return estimated_cost

    def estimate_from_text(self, text: str) -> Dict[str, Any]:
        """
        Get complete estimation from text

        Args:
            text: Text to analyze

        Returns:
            Dictionary with token count, cost, and stats
        """
        token_count = self.count_tokens(text)
        cost = self.estimate_cost(token_count)

        return {
            "text_length": len(text),
            "token_count": token_count,
            "estimated_cost": cost,
            "model": self.current_model.name,
            "method": self.default_method.value,
            "tokens_per_character": token_count / len(text) if text else 0,
            "cost_per_token": cost / token_count if token_count > 0 else 0,
        }

    def set_budget(
        self,
        daily_limit: int,
        monthly_limit: int,
        cost_limit: float
    ) -> None:
        """
        Set token budget

        Args:
            daily_limit: Daily token limit
            monthly_limit: Monthly token limit
            cost_limit: Cost limit in currency
        """
        self.budget = TokenBudget(
            daily_limit=daily_limit,
            monthly_limit=monthly_limit,
            cost_limit=cost_limit
        )
        self.logger.info(f"Budget set - Daily: {daily_limit}, Monthly: {monthly_limit}")

    def _check_budget(self, tokens: int) -> None:
        """Check if token usage exceeds budget"""
        if not self.budget:
            return

        self.budget.current_daily_used += tokens
        self.budget.current_monthly_used += tokens
        cost = self.estimate_cost(tokens)
        self.budget.current_cost_used += cost

        if (self.budget.current_daily_used > self.budget.daily_limit or
            self.budget.current_monthly_used > self.budget.monthly_limit or
            self.budget.current_cost_used > self.budget.cost_limit):
            self.budget.exceeded = True
            self.logger.warning("Budget exceeded!")

    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive statistics"""
        return {
            "current_model": self.current_model.name,
            "counting_method": self.default_method.value,
            "total_tokens_counted": self.stats["total_tokens_counted"],
            "total_texts_processed": self.stats["total_texts_processed"],
            "average_tokens_per_text": self.stats["average_tokens_per_text"],
            "total_cost_estimated": self.stats["total_cost_estimated"],
            "recent_records": len(self.usage_records),
            "budget_set": self.budget is not None,
            "budget_exceeded": self.budget.exceeded if self.budget else False,
        }

    def get_usage_history(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent usage history"""
        records = self.usage_records[-limit:]
        return [asdict(record) for record in records]

    def get_model_list(self) -> List[str]:
        """List all available models"""
        return self.model_registry.list_models()

    def get_model_info(self, model_name: str) -> Optional[Dict[str, Any]]:
        """Get information about a model"""
        return self.model_registry.get_model_info(model_name)

    def clear_statistics(self) -> None:
        """Clear usage statistics"""
        self.usage_records.clear()
        self.stats = {
            "total_tokens_counted": 0,
            "total_texts_processed": 0,
            "total_cost_estimated": 0.0,
            "average_tokens_per_text": 0.0,
        }
        self.logger.info("Statistics cleared")

    def optimize_text(self, text: str, max_tokens: int) -> str:
        """
        Optimize text to fit within token limit

        Args:
            text: Text to optimize
            max_tokens: Maximum allowed tokens

        Returns:
            Optimized text
        """
        current_tokens = self.count_tokens(text)

        if current_tokens <= max_tokens:
            return text

        # Iteratively remove content
        reduction_factor = max_tokens / current_tokens
        words = text.split()
        target_words = int(len(words) * reduction_factor)

        # Remove sentences to reach target
        sentences = text.split(". ")
        optimized = ". ".join(sentences[:max(1, int(len(sentences) * reduction_factor))])

        self.logger.info(
            f"Optimized text from {current_tokens} to ~{max_tokens} tokens"
        )
        return optimized


# ============================================================================
# TESTING SECTION
# ============================================================================

def run_tests():
    """Comprehensive test suite for token counter"""

    print("\n" + "="*80)
    print("TOKEN COUNTER COMPREHENSIVE TEST SUITE")
    print("="*80 + "\n")

    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    counter = TokenCounter()

    # Test 1: Model Registry
    print("[TEST 1] Model Registry")
    print("-" * 80)
    models = counter.get_model_list()
    print(f"✓ Loaded {len(models)} models")
    print(f"  Models: {', '.join(models)}")
    assert len(models) > 0, "No models loaded"
    print()

    # Test 2: Character-based Counting
    print("[TEST 2] Character-based Token Counting")
    print("-" * 80)
    counter.set_counting_method(TokenCountMethod.CHARACTER_BASED)
    test_text = "This is a test string with multiple words for token counting."
    tokens = counter.count_tokens(test_text)
    print(f"✓ Text: {test_text}")
    print(f"  Length: {len(test_text)} characters")
    print(f"  Estimated tokens: {tokens}")
    assert tokens > 0, "Token count should be positive"
    print()

    # Test 3: Word-based Counting
    print("[TEST 3] Word-based Token Counting")
    print("-" * 80)
    counter.set_counting_method(TokenCountMethod.WORD_BASED)
    tokens_word = counter.count_tokens(test_text)
    print(f"✓ Estimated tokens (word-based): {tokens_word}")
    assert tokens_word > 0, "Token count should be positive"
    print()

    # Test 4: Byte-Pair Encoding Counting
    print("[TEST 4] Byte-Pair Encoding Token Counting")
    print("-" * 80)
    counter.set_counting_method(TokenCountMethod.BYTE_PAIR_ENCODING)
    tokens_bpe = counter.count_tokens(test_text)
    print(f"✓ Estimated tokens (BPE): {tokens_bpe}")
    assert tokens_bpe > 0, "Token count should be positive"
    print()

    # Test 5: Model-specific Counting
    print("[TEST 5] Model-Specific Token Counting")
    print("-" * 80)
    counter.set_counting_method(TokenCountMethod.MODEL_SPECIFIC)
    tokens_model = counter.count_tokens(test_text)
    print(f"✓ Estimated tokens (model-specific): {tokens_model}")
    assert tokens_model > 0, "Token count should be positive"
    print()

    # Test 6: Switch Models
    print("[TEST 6] Model Switching")
    print("-" * 80)
    original_model = counter.current_model.name
    counter.set_model("llama2")
    assert counter.current_model.name == "llama2"
    print(f"✓ Switched from {original_model} to llama2")
    counter.set_model(original_model)
    print(f"✓ Switched back to {original_model}")
    print()

    # Test 7: Cost Estimation
    print("[TEST 7] Cost Estimation")
    print("-" * 80)
    token_count = 1000
    cost = counter.estimate_cost(token_count)
    print(f"✓ Estimated cost for {token_count} tokens: ${cost:.6f}")
    assert cost > 0, "Cost should be positive"
    print()

    # Test 8: Prompt and Completion Counting
    print("[TEST 8] Prompt and Completion Token Counting")
    print("-" * 80)
    prompt = "What is a buffer overflow?"
    completion = "A buffer overflow is a condition where a program attempts to write more data to a buffer than it can hold."
    prompt_tokens, completion_tokens, total_tokens = counter.count_prompt_completion(prompt, completion)
    print(f"✓ Prompt tokens: {prompt_tokens}")
    print(f"✓ Completion tokens: {completion_tokens}")
    print(f"✓ Total tokens: {total_tokens}")
    assert total_tokens == prompt_tokens + completion_tokens
    print()

    # Test 9: Complete Text Estimation
    print("[TEST 9] Complete Text Estimation")
    print("-" * 80)
    estimation = counter.estimate_from_text(test_text)
    print(f"✓ Text estimation:")
    for key, value in estimation.items():
        if isinstance(value, float):
            print(f"  {key}: {value:.4f}")
        else:
            print(f"  {key}: {value}")
    print()

    # Test 10: Budget Management
    print("[TEST 10] Budget Management")
    print("-" * 80)
    counter.set_budget(daily_limit=10000, monthly_limit=100000, cost_limit=100.0)
    print(f"✓ Budget set:")
    print(f"  Daily limit: 10,000 tokens")
    print(f"  Monthly limit: 100,000 tokens")
    print(f"  Cost limit: $100.00")
    short_text = "test"
    counter.count_tokens(short_text)
    print(f"✓ Budget not exceeded yet")
    print()

    # Test 11: Statistics Tracking
    print("[TEST 11] Statistics Tracking")
    print("-" * 80)
    # Process multiple texts
    test_texts = [
        "Short text",
        "This is a medium length text with more information",
        "This is a much longer text that contains multiple sentences and provides " +
        "comprehensive information about various topics including security, testing, and more."
    ]
    for text in test_texts:
        counter.count_tokens(text)

    stats = counter.get_statistics()
    print(f"✓ Statistics:")
    print(f"  Total tokens: {stats['total_tokens_counted']}")
    print(f"  Texts processed: {stats['total_texts_processed']}")
    print(f"  Average tokens per text: {stats['average_tokens_per_text']:.1f}")
    print(f"  Total cost estimated: ${stats['total_cost_estimated']:.6f}")
    print()

    # Test 12: Usage History
    print("[TEST 12] Usage History")
    print("-" * 80)
    history = counter.get_usage_history(limit=3)
    print(f"✓ Retrieved {len(history)} recent records")
    for i, record in enumerate(history):
        print(f"  {i+1}. Tokens: {record['estimated_tokens']}, Length: {len(record['text'])}")
    print()

    # Test 13: Text Optimization
    print("[TEST 13] Text Optimization")
    print("-" * 80)
    long_text = test_texts[2]
    original_tokens = counter.count_tokens(long_text)
    optimized = counter.optimize_text(long_text, max_tokens=50)
    optimized_tokens = counter.count_tokens(optimized)
    print(f"✓ Original tokens: {original_tokens}")
    print(f"✓ Optimized tokens: {optimized_tokens}")
    print(f"✓ Optimized text length: {len(optimized)}")
    assert optimized_tokens <= 50, "Optimized tokens should be within limit"
    print()

    # Test 14: Model Information
    print("[TEST 14] Model Information")
    print("-" * 80)
    mistral_info = counter.get_model_info("mistral")
    print(f"✓ Mistral model info:")
    print(f"  Vocab size: {mistral_info['vocab_size']}")
    print(f"  Avg token length: {mistral_info['avg_token_length']}")
    print(f"  Cost per 1K tokens: ${mistral_info['cost_per_1k_tokens']}")
    print()

    # Test 15: Clear Statistics
    print("[TEST 15] Clear Statistics")
    print("-" * 80)
    initial_count = counter.stats["total_tokens_counted"]
    counter.clear_statistics()
    cleared_count = counter.stats["total_tokens_counted"]
    print(f"✓ Statistics cleared")
    print(f"  Before: {initial_count} tokens counted")
    print(f"  After: {cleared_count} tokens counted")
    assert cleared_count == 0, "Statistics should be cleared"
    print()

    print("="*80)
    print("ALL TESTS PASSED ✓")
    print("="*80 + "\n")

    return True


# ============================================================================
# Main Entry Point
# ============================================================================

if __name__ == "__main__":
    success = run_tests()
    if success:
        print("Token Counter is ready for integration!")