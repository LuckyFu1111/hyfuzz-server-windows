"""
Utilities Module for HyFuzz LLM Service

This module provides utility functions for:
- Text processing and normalization
- Format conversion and validation
- JSON handling
- Time and performance tracking
- String manipulation
- Error handling and logging
- Caching and memoization
"""

import json
import logging
import time
import hashlib
import re
import math
from typing import Optional, Dict, List, Any, Callable, TypeVar, Tuple
from functools import wraps, lru_cache
from datetime import datetime, timedelta
from dataclasses import dataclass, field, asdict
from enum import Enum
import asyncio


# ============================================================================
# Enums
# ============================================================================

class TextNormalizationLevel(Enum):
    """Levels of text normalization"""
    MINIMAL = "minimal"  # Only basic whitespace cleanup
    STANDARD = "standard"  # Normalize whitespace, case
    AGGRESSIVE = "aggressive"  # Deep normalization with stemming


class LogLevel(Enum):
    """Logging levels"""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


# ============================================================================
# Data Structures
# ============================================================================

@dataclass
class PerformanceMetrics:
    """Metrics for performance tracking"""
    function_name: str
    execution_time: float
    memory_used: int = 0
    called_at: datetime = field(default_factory=datetime.now)
    parameters: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)


@dataclass
class CacheStats:
    """Statistics for caching"""
    hits: int = 0
    misses: int = 0
    size: int = 0
    max_size: int = 0

    @property
    def hit_rate(self) -> float:
        """Calculate hit rate"""
        total = self.hits + self.misses
        return self.hits / total if total > 0 else 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)


# ============================================================================
# Text Processing Utilities
# ============================================================================

class TextProcessor:
    """Text processing utilities"""

    @staticmethod
    def clean_whitespace(text: str) -> str:
        """Remove excessive whitespace"""
        # Remove leading/trailing whitespace
        text = text.strip()
        # Replace multiple spaces with single space
        text = re.sub(r'\s+', ' ', text)
        # Remove tabs and newlines
        text = text.replace('\t', ' ').replace('\r', '')
        return text

    @staticmethod
    def normalize_text(
        text: str,
        level: TextNormalizationLevel = TextNormalizationLevel.STANDARD
    ) -> str:
        """
        Normalize text based on level

        Args:
            text: Text to normalize
            level: Normalization level

        Returns:
            Normalized text
        """
        if level == TextNormalizationLevel.MINIMAL:
            return TextProcessor.clean_whitespace(text)

        # Standard normalization
        text = TextProcessor.clean_whitespace(text)
        # Convert to lowercase for comparison purposes
        # (but keep original case by default)

        if level == TextNormalizationLevel.AGGRESSIVE:
            # Additional aggressive normalization
            # Remove special characters except punctuation
            text = re.sub(r'[^\w\s\.\,\!\?\;\:\-]', '', text)
            # Normalize unicode
            text = text.encode('ascii', 'ignore').decode('ascii')

        return text

    @staticmethod
    def extract_sentences(text: str) -> List[str]:
        """Extract sentences from text"""
        # Split on sentence-ending punctuation
        sentences = re.split(r'[.!?]+', text)
        # Clean and filter
        sentences = [s.strip() for s in sentences if s.strip()]
        return sentences

    @staticmethod
    def extract_keywords(text: str, top_k: int = 10) -> List[str]:
        """Extract keywords from text"""
        # Convert to lowercase and split
        words = text.lower().split()

        # Filter out stopwords and short words
        stopwords = {
            'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for',
            'of', 'with', 'by', 'from', 'is', 'are', 'was', 'be', 'been'
        }

        keywords = [
            w.strip('.,!?;:') for w in words
            if len(w) > 3 and w not in stopwords
        ]

        # Count frequencies
        freq = {}
        for kw in keywords:
            freq[kw] = freq.get(kw, 0) + 1

        # Sort by frequency and return top-k
        sorted_kw = sorted(freq.items(), key=lambda x: x[1], reverse=True)
        return [kw for kw, _ in sorted_kw[:top_k]]

    @staticmethod
    def truncate_text(text: str, max_length: int, suffix: str = "...") -> str:
        """Truncate text to maximum length"""
        if len(text) <= max_length:
            return text

        # Leave room for suffix
        available = max_length - len(suffix)
        if available <= 0:
            return text[:max_length]

        return text[:available] + suffix

    @staticmethod
    def count_words(text: str) -> int:
        """Count words in text"""
        return len(text.split())

    @staticmethod
    def count_sentences(text: str) -> int:
        """Count sentences in text"""
        return len(TextProcessor.extract_sentences(text))

    @staticmethod
    def calculate_readability_score(text: str) -> float:
        """
        Calculate readability score (0.0 to 1.0)
        Higher score means more readable
        """
        if not text:
            return 0.0

        sentences = TextProcessor.extract_sentences(text)
        words = text.split()

        if len(sentences) == 0 or len(words) == 0:
            return 0.0

        # Average word length
        avg_word_length = sum(len(w) for w in words) / len(words)
        # Average sentence length
        avg_sentence_length = len(words) / len(sentences)

        # Flesch Reading Ease approximation
        score = 206.835 - 1.015 * avg_sentence_length - 84.6 * avg_word_length / 100
        # Normalize to 0-1 range
        return max(0.0, min(1.0, score / 100))


# ============================================================================
# JSON Utilities
# ============================================================================

class JSONProcessor:
    """JSON processing utilities"""

    @staticmethod
    def safe_loads(json_str: str, default: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Safely load JSON with default fallback

        Args:
            json_str: JSON string
            default: Default value if parsing fails

        Returns:
            Parsed JSON or default
        """
        try:
            return json.loads(json_str)
        except (json.JSONDecodeError, ValueError):
            return default or {}

    @staticmethod
    def safe_dumps(obj: Any, indent: Optional[int] = 2) -> str:
        """
        Safely dump object to JSON string

        Args:
            obj: Object to serialize
            indent: JSON indentation

        Returns:
            JSON string
        """
        try:
            return json.dumps(obj, indent=indent, default=str)
        except (TypeError, ValueError):
            return "{}"

    @staticmethod
    def extract_json_objects(text: str) -> List[Dict[str, Any]]:
        """
        Extract JSON objects from text

        Args:
            text: Text containing JSON

        Returns:
            List of parsed JSON objects
        """
        json_objects = []

        # Find all JSON-like patterns
        pattern = r'\{[^{}]*\}'
        matches = re.finditer(pattern, text)

        for match in matches:
            try:
                obj = json.loads(match.group())
                json_objects.append(obj)
            except json.JSONDecodeError:
                continue

        return json_objects

    @staticmethod
    def merge_json_objects(*objects: Dict[str, Any]) -> Dict[str, Any]:
        """
        Merge multiple JSON objects

        Args:
            objects: JSON objects to merge

        Returns:
            Merged object
        """
        merged = {}
        for obj in objects:
            if isinstance(obj, dict):
                merged.update(obj)
        return merged

    @staticmethod
    def flatten_json(obj: Dict[str, Any], parent_key: str = '', sep: str = '.') -> Dict[str, Any]:
        """
        Flatten nested JSON object

        Args:
            obj: Object to flatten
            parent_key: Parent key prefix
            sep: Separator for keys

        Returns:
            Flattened object
        """
        items = []

        for k, v in obj.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k

            if isinstance(v, dict):
                items.extend(JSONProcessor.flatten_json(v, new_key, sep).items())
            elif isinstance(v, list):
                for i, item in enumerate(v):
                    if isinstance(item, dict):
                        items.extend(
                            JSONProcessor.flatten_json(
                                {f"{new_key}[{i}]": item},
                                '',
                                sep
                            ).items()
                        )
                    else:
                        items.append((f"{new_key}[{i}]", item))
            else:
                items.append((new_key, v))

        return dict(items)


# ============================================================================
# Hash and Checksum Utilities
# ============================================================================

class HashUtils:
    """Hash and checksum utilities"""

    @staticmethod
    def md5_hash(text: str) -> str:
        """Generate MD5 hash of text"""
        return hashlib.md5(text.encode()).hexdigest()

    @staticmethod
    def sha256_hash(text: str) -> str:
        """Generate SHA256 hash of text"""
        return hashlib.sha256(text.encode()).hexdigest()

    @staticmethod
    def sha1_hash(text: str) -> str:
        """Generate SHA1 hash of text"""
        return hashlib.sha1(text.encode()).hexdigest()

    @staticmethod
    def quick_hash(text: str) -> str:
        """Generate quick hash for comparison"""
        return HashUtils.md5_hash(text)

    @staticmethod
    def verify_hash(text: str, hash_value: str, algorithm: str = "md5") -> bool:
        """Verify if text matches hash"""
        if algorithm == "md5":
            return HashUtils.md5_hash(text) == hash_value
        elif algorithm == "sha256":
            return HashUtils.sha256_hash(text) == hash_value
        elif algorithm == "sha1":
            return HashUtils.sha1_hash(text) == hash_value
        return False


# ============================================================================
# Validation Utilities
# ============================================================================

class Validator:
    """Input and format validation utilities"""

    @staticmethod
    def is_valid_json(text: str) -> bool:
        """Check if text is valid JSON"""
        try:
            json.loads(text)
            return True
        except (json.JSONDecodeError, ValueError):
            return False

    @staticmethod
    def is_valid_email(email: str) -> bool:
        """Check if email is valid"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))

    @staticmethod
    def is_valid_url(url: str) -> bool:
        """Check if URL is valid"""
        pattern = r'^https?://[^\s/$.?#].[^\s]*$'
        return bool(re.match(pattern, url, re.IGNORECASE))

    @staticmethod
    def is_valid_cve_id(cve_id: str) -> bool:
        """Check if CVE ID is valid"""
        pattern = r'^CVE-\d{4}-\d{4,7}$'
        return bool(re.match(pattern, cve_id, re.IGNORECASE))

    @staticmethod
    def is_valid_cwe_id(cwe_id: str) -> bool:
        """Check if CWE ID is valid"""
        pattern = r'^CWE-\d{1,4}$'
        return bool(re.match(pattern, cwe_id, re.IGNORECASE))

    @staticmethod
    def validate_required_fields(data: Dict[str, Any], required: List[str]) -> Tuple[bool, Optional[str]]:
        """
        Validate required fields in dictionary

        Args:
            data: Data dictionary
            required: List of required field names

        Returns:
            (is_valid, error_message)
        """
        for field in required:
            if field not in data or data[field] is None:
                return False, f"Missing required field: {field}"

        return True, None

    @staticmethod
    def validate_field_types(
        data: Dict[str, Any],
        type_map: Dict[str, type]
    ) -> Tuple[bool, Optional[str]]:
        """
        Validate field types in dictionary

        Args:
            data: Data dictionary
            type_map: Mapping of field names to expected types

        Returns:
            (is_valid, error_message)
        """
        for field, expected_type in type_map.items():
            if field in data:
                if not isinstance(data[field], expected_type):
                    return False, f"Field '{field}' has wrong type: {type(data[field])}"

        return True, None


# ============================================================================
# Caching Utilities
# ============================================================================

class CacheDecorator:
    """Caching decorator for functions"""

    def __init__(self, max_size: int = 128, ttl_seconds: Optional[int] = None):
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self.cache: Dict[str, Tuple[Any, datetime]] = {}
        self.stats = CacheStats(max_size=max_size)

    def __call__(self, func: Callable) -> Callable:
        """Decorate function with caching"""
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Generate cache key
            key = self._generate_key(func.__name__, args, kwargs)

            # Check cache
            if key in self.cache:
                value, timestamp = self.cache[key]

                # Check TTL
                if self.ttl_seconds is None or \
                   (datetime.now() - timestamp).total_seconds() < self.ttl_seconds:
                    self.stats.hits += 1
                    return value
                else:
                    # Expired, remove from cache
                    del self.cache[key]

            # Cache miss
            self.stats.misses += 1

            # Call function
            result = func(*args, **kwargs)

            # Store in cache
            if len(self.cache) >= self.max_size:
                # Remove oldest entry
                oldest_key = min(self.cache.keys(),
                               key=lambda k: self.cache[k][1])
                del self.cache[oldest_key]

            self.cache[key] = (result, datetime.now())
            self.stats.size = len(self.cache)

            return result

        return wrapper

    @staticmethod
    def _generate_key(func_name: str, args: Tuple, kwargs: Dict) -> str:
        """Generate cache key from function arguments"""
        key_str = f"{func_name}_{str(args)}_{str(kwargs)}"
        return HashUtils.md5_hash(key_str)


# ============================================================================
# Performance Tracking Utilities
# ============================================================================

class PerformanceTracker:
    """Track function performance"""

    def __init__(self):
        self.metrics: List[PerformanceMetrics] = []
        self.logger = logging.getLogger(__name__)

    def track(self, func: Callable) -> Callable:
        """Decorator to track function performance"""
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()

            try:
                result = func(*args, **kwargs)
                execution_time = time.time() - start_time

                metric = PerformanceMetrics(
                    function_name=func.__name__,
                    execution_time=execution_time
                )
                self.metrics.append(metric)

                if execution_time > 1.0:
                    self.logger.warning(
                        f"Slow function: {func.__name__} "
                        f"took {execution_time:.2f}s"
                    )

                return result

            except Exception as e:
                self.logger.error(f"Error in {func.__name__}: {str(e)}")
                raise

        return wrapper

    def get_stats(self) -> Dict[str, Any]:
        """Get performance statistics"""
        if not self.metrics:
            return {}

        times = [m.execution_time for m in self.metrics]
        return {
            "total_calls": len(self.metrics),
            "avg_time": sum(times) / len(times),
            "min_time": min(times),
            "max_time": max(times),
            "total_time": sum(times),
        }

    def clear_metrics(self) -> None:
        """Clear metrics"""
        self.metrics.clear()


# ============================================================================
# String Utilities
# ============================================================================

class StringUtils:
    """String manipulation utilities"""

    @staticmethod
    def capitalize_words(text: str) -> str:
        """Capitalize first letter of each word"""
        return ' '.join(word.capitalize() for word in text.split())

    @staticmethod
    def remove_special_chars(text: str, keep_chars: str = "") -> str:
        """Remove special characters"""
        pattern = rf'[^a-zA-Z0-9\s{re.escape(keep_chars)}]'
        return re.sub(pattern, '', text)

    @staticmethod
    def extract_numbers(text: str) -> List[int]:
        """Extract numbers from text"""
        numbers = re.findall(r'-?\d+', text)
        return [int(n) for n in numbers]

    @staticmethod
    def extract_urls(text: str) -> List[str]:
        """Extract URLs from text"""
        pattern = r'https?://[^\s]+'
        return re.findall(pattern, text)

    @staticmethod
    def extract_emails(text: str) -> List[str]:
        """Extract email addresses from text"""
        pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        return re.findall(pattern, text)

    @staticmethod
    def camel_case_to_snake_case(text: str) -> str:
        """Convert camelCase to snake_case"""
        s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', text)
        return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()

    @staticmethod
    def snake_case_to_camel_case(text: str) -> str:
        """Convert snake_case to camelCase"""
        components = text.split('_')
        return components[0] + ''.join(x.title() for x in components[1:])


# ============================================================================
# Time and Date Utilities
# ============================================================================

class TimeUtils:
    """Time and date utilities"""

    @staticmethod
    def get_iso_timestamp() -> str:
        """Get current timestamp in ISO format"""
        return datetime.now().isoformat()

    @staticmethod
    def get_readable_timestamp() -> str:
        """Get readable current timestamp"""
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    @staticmethod
    def format_duration(seconds: float) -> str:
        """Format duration in seconds to readable string"""
        if seconds < 1:
            return f"{seconds*1000:.1f}ms"
        elif seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            return f"{seconds/60:.1f}m"
        else:
            return f"{seconds/3600:.1f}h"

    @staticmethod
    def calculate_time_diff(start: datetime, end: datetime) -> float:
        """Calculate time difference in seconds"""
        return (end - start).total_seconds()

    @staticmethod
    def is_within_timeframe(
        timestamp: datetime,
        start: datetime,
        end: datetime
    ) -> bool:
        """Check if timestamp is within timeframe"""
        return start <= timestamp <= end


# ============================================================================
# Error Handling Utilities
# ============================================================================

class ErrorHandler:
    """Error handling utilities"""

    @staticmethod
    def safe_execute(
        func: Callable,
        *args,
        default_return: Any = None,
        logger: Optional[logging.Logger] = None,
        **kwargs
    ) -> Any:
        """
        Safely execute function with error handling

        Args:
            func: Function to execute
            default_return: Return value if function fails
            logger: Logger instance
            *args, **kwargs: Function arguments

        Returns:
            Function result or default
        """
        try:
            return func(*args, **kwargs)
        except Exception as e:
            if logger:
                logger.error(f"Error executing {func.__name__}: {str(e)}")
            return default_return

    @staticmethod
    def retry(max_attempts: int = 3, delay: float = 1.0):
        """Decorator for retry logic"""
        def decorator(func: Callable) -> Callable:
            @wraps(func)
            def wrapper(*args, **kwargs):
                for attempt in range(max_attempts):
                    try:
                        return func(*args, **kwargs)
                    except Exception as e:
                        if attempt == max_attempts - 1:
                            raise
                        time.sleep(delay)

            return wrapper

        return decorator


# ============================================================================
# TESTING SECTION
# ============================================================================

def run_tests():
    """Comprehensive test suite for utilities"""

    print("\n" + "="*80)
    print("LLM UTILITIES COMPREHENSIVE TEST SUITE")
    print("="*80 + "\n")

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Test 1: Text Processing
    print("[TEST 1] Text Processing")
    print("-" * 80)
    test_text = "  Hello   WORLD  !  This  is   a   test.  "
    cleaned = TextProcessor.clean_whitespace(test_text)
    assert "   " not in cleaned
    print(f"✓ Whitespace cleaning: '{test_text}' → '{cleaned}'")

    keywords = TextProcessor.extract_keywords("security vulnerability patch update")
    print(f"✓ Keyword extraction: {keywords}")

    sentences = TextProcessor.extract_sentences("First sentence. Second sentence! Third?")
    assert len(sentences) == 3
    print(f"✓ Sentence extraction: {len(sentences)} sentences found")

    truncated = TextProcessor.truncate_text("This is a very long text", max_length=10)
    assert len(truncated) <= 10
    print(f"✓ Text truncation: '{truncated}'")

    readability = TextProcessor.calculate_readability_score(test_text)
    print(f"✓ Readability score: {readability:.2f}")
    print()

    # Test 2: JSON Processing
    print("[TEST 2] JSON Processing")
    print("-" * 80)
    json_str = '{"key": "value", "number": 42}'
    parsed = JSONProcessor.safe_loads(json_str)
    assert parsed["key"] == "value"
    print(f"✓ Safe JSON parsing: {parsed}")

    dumped = JSONProcessor.safe_dumps({"test": "data"})
    assert "test" in dumped
    print(f"✓ Safe JSON dumping: {dumped}")

    flattened = JSONProcessor.flatten_json({"outer": {"inner": "value"}})
    assert "outer.inner" in flattened
    print(f"✓ JSON flattening: {flattened}")
    print()

    # Test 3: Hash Utilities
    print("[TEST 3] Hash Utilities")
    print("-" * 80)
    text = "test string"
    md5 = HashUtils.md5_hash(text)
    assert len(md5) == 32
    print(f"✓ MD5 hash: {md5}")

    sha256 = HashUtils.sha256_hash(text)
    assert len(sha256) == 64
    print(f"✓ SHA256 hash: {sha256[:32]}...")

    verified = HashUtils.verify_hash(text, md5, "md5")
    assert verified
    print(f"✓ Hash verification: {verified}")
    print()

    # Test 4: Validation
    print("[TEST 4] Validation")
    print("-" * 80)
    assert Validator.is_valid_json('{"key": "value"}')
    print(f"✓ JSON validation: True")

    assert Validator.is_valid_email("test@example.com")
    print(f"✓ Email validation: True")

    assert Validator.is_valid_url("https://example.com")
    print(f"✓ URL validation: True")

    assert Validator.is_valid_cve_id("CVE-2023-12345")
    print(f"✓ CVE ID validation: True")

    assert Validator.is_valid_cwe_id("CWE-78")
    print(f"✓ CWE ID validation: True")

    is_valid, error = Validator.validate_required_fields(
        {"name": "John", "age": 30},
        ["name", "age"]
    )
    assert is_valid
    print(f"✓ Required fields validation: {is_valid}")
    print()

    # Test 5: Caching
    print("[TEST 5] Caching")
    print("-" * 80)
    cache = CacheDecorator(max_size=10)

    @cache
    def fibonacci(n):
        if n <= 1:
            return n
        return fibonacci(n-1) + fibonacci(n-2)

    result = fibonacci(5)
    assert result == 5
    print(f"✓ Cache working: fibonacci(5) = {result}")
    print(f"✓ Cache stats: {cache.stats.to_dict()}")
    print()

    # Test 6: Performance Tracking
    print("[TEST 6] Performance Tracking")
    print("-" * 80)
    tracker = PerformanceTracker()

    @tracker.track
    def slow_function():
        time.sleep(0.1)
        return "done"

    result = slow_function()
    assert result == "done"
    stats = tracker.get_stats()
    print(f"✓ Function executed: {result}")
    print(f"✓ Performance stats: {stats}")
    print()

    # Test 7: String Utilities
    print("[TEST 7] String Utilities")
    print("-" * 80)
    capitalized = StringUtils.capitalize_words("hello world test")
    assert capitalized == "Hello World Test"
    print(f"✓ Capitalize words: '{capitalized}'")

    numbers = StringUtils.extract_numbers("The value is 42 and 100")
    assert 42 in numbers and 100 in numbers
    print(f"✓ Extract numbers: {numbers}")

    urls = StringUtils.extract_urls("Visit https://example.com or https://test.org")
    assert len(urls) == 2
    print(f"✓ Extract URLs: {urls}")

    emails = StringUtils.extract_emails("Contact user@example.com or admin@test.org")
    assert len(emails) == 2
    print(f"✓ Extract emails: {emails}")

    snake = StringUtils.camel_case_to_snake_case("camelCaseExample")
    assert snake == "camel_case_example"
    print(f"✓ CamelCase to snake_case: {snake}")

    camel = StringUtils.snake_case_to_camel_case("snake_case_example")
    assert camel == "snakeCaseExample"
    print(f"✓ snake_case to CamelCase: {camel}")
    print()

    # Test 8: Time Utilities
    print("[TEST 8] Time Utilities")
    print("-" * 80)
    iso_ts = TimeUtils.get_iso_timestamp()
    print(f"✓ ISO timestamp: {iso_ts}")

    readable_ts = TimeUtils.get_readable_timestamp()
    print(f"✓ Readable timestamp: {readable_ts}")

    formatted = TimeUtils.format_duration(125.5)
    print(f"✓ Format duration: 125.5s → {formatted}")

    timeframe_valid = TimeUtils.is_within_timeframe(
        datetime.now(),
        datetime.now() - timedelta(hours=1),
        datetime.now() + timedelta(hours=1)
    )
    assert timeframe_valid
    print(f"✓ Timeframe check: {timeframe_valid}")
    print()

    # Test 9: Error Handling
    print("[TEST 9] Error Handling")
    print("-" * 80)

    def error_func():
        raise ValueError("Test error")

    result = ErrorHandler.safe_execute(error_func, default_return="safe_default")
    assert result == "safe_default"
    print(f"✓ Safe execution with default: {result}")

    @ErrorHandler.retry(max_attempts=3, delay=0.1)
    def retry_func():
        return "success"

    result = retry_func()
    assert result == "success"
    print(f"✓ Retry execution: {result}")
    print()

    # Test 10: Text Normalization Levels
    print("[TEST 10] Text Normalization Levels")
    print("-" * 80)
    raw_text = "  This IS a $pecial Test!  "

    minimal = TextProcessor.normalize_text(raw_text, TextNormalizationLevel.MINIMAL)
    print(f"✓ Minimal: '{minimal}'")

    standard = TextProcessor.normalize_text(raw_text, TextNormalizationLevel.STANDARD)
    print(f"✓ Standard: '{standard}'")

    aggressive = TextProcessor.normalize_text(raw_text, TextNormalizationLevel.AGGRESSIVE)
    print(f"✓ Aggressive: '{aggressive}'")
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
        print("LLM Utilities module is ready for integration!")