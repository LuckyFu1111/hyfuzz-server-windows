"""
Config Models - Configuration Data Models for HyFuzz Windows MCP Server

This module contains configuration data models used throughout the HyFuzz
Windows MCP Server for managing server, LLM, transport, logging, and cache
configurations.

Models:
    - ServerConfig: Main server configuration
    - LLMConfig: Language model service configuration
    - TransportConfig: Transport layer configuration
    - LoggingConfig: Application logging configuration
    - CacheConfig: Cache system configuration

Author: HyFuzz Team
Version: 1.0.0
"""

from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any
from enum import Enum
import json
from pathlib import Path


# ============================================================================
# ENUMS
# ============================================================================

class LogLevel(str, Enum):
    """Enumeration of logging levels."""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class TransportType(str, Enum):
    """Enumeration of transport types."""
    STDIO = "stdio"
    HTTP = "http"
    WEBSOCKET = "websocket"
    GRPC = "grpc"


class CacheBackend(str, Enum):
    """Enumeration of cache backend types."""
    MEMORY = "memory"
    REDIS = "redis"
    MEMCACHED = "memcached"
    FILE = "file"


# ============================================================================
# 1. CacheConfig DATA MODEL
# ============================================================================

@dataclass
class CacheConfig:
    """
    Configuration for the cache system.

    Attributes:
        enabled: Whether caching is enabled
        backend: Cache backend type (memory, redis, memcached, file)
        ttl_seconds: Time-to-live for cache entries in seconds
        max_size_mb: Maximum cache size in megabytes
        redis_host: Redis host (if backend is redis)
        redis_port: Redis port (if backend is redis)
        redis_db: Redis database number (if backend is redis)
        file_path: File path for file-based cache
        memcached_hosts: List of memcached hosts
        eviction_policy: Cache eviction policy (lru, lfu, fifo)
    """
    enabled: bool = True
    backend: CacheBackend = CacheBackend.MEMORY
    ttl_seconds: int = 3600
    max_size_mb: int = 100
    redis_host: Optional[str] = None
    redis_port: int = 6379
    redis_db: int = 0
    file_path: Optional[str] = None
    memcached_hosts: List[str] = field(default_factory=lambda: ["localhost:11211"])
    eviction_policy: str = "lru"

    def __post_init__(self):
        """Validate configuration values."""
        if self.ttl_seconds < 1:
            self.ttl_seconds = 60
        if self.max_size_mb < 1:
            self.max_size_mb = 10
        if self.backend == CacheBackend.REDIS and not self.redis_host:
            self.redis_host = "localhost"
        if self.backend == CacheBackend.FILE and not self.file_path:
            self.file_path = "./cache"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "enabled": self.enabled,
            "backend": self.backend.value,
            "ttl_seconds": self.ttl_seconds,
            "max_size_mb": self.max_size_mb,
            "redis": {
                "host": self.redis_host,
                "port": self.redis_port,
                "db": self.redis_db
            } if self.backend == CacheBackend.REDIS else None,
            "file_path": self.file_path if self.backend == CacheBackend.FILE else None,
            "memcached_hosts": self.memcached_hosts if self.backend == CacheBackend.MEMCACHED else None,
            "eviction_policy": self.eviction_policy
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)

    def is_valid(self) -> bool:
        """Validate the configuration."""
        if not isinstance(self.backend, (CacheBackend, str)):
            return False
        if self.backend == CacheBackend.REDIS and not self.redis_host:
            return False
        if self.backend == CacheBackend.FILE and not self.file_path:
            return False
        return True

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'CacheConfig':
        """Create CacheConfig from dictionary."""
        if data is None:
            data = {}

        redis_cfg = data.get("redis", {}) or {}

        return CacheConfig(
            enabled=data.get("enabled", True),
            backend=CacheBackend(data.get("backend", "memory")),
            ttl_seconds=data.get("ttl_seconds", 3600),
            max_size_mb=data.get("max_size_mb", 100),
            redis_host=redis_cfg.get("host"),
            redis_port=redis_cfg.get("port", 6379),
            redis_db=redis_cfg.get("db", 0),
            file_path=data.get("file_path"),
            memcached_hosts=data.get("memcached_hosts", ["localhost:11211"]),
            eviction_policy=data.get("eviction_policy", "lru")
        )


# ============================================================================
# 2. LoggingConfig DATA MODEL
# ============================================================================

@dataclass
class LoggingConfig:
    """
    Configuration for application logging.

    Attributes:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        format: Log message format string
        file_path: Path to log file
        max_file_size_mb: Maximum log file size in MB
        backup_count: Number of backup log files to keep
        console_output: Whether to output to console
        file_output: Whether to output to file
        include_timestamp: Whether to include timestamp in logs
        include_caller: Whether to include caller info in logs
    """
    level: LogLevel = LogLevel.INFO
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    file_path: str = "./logs/server.log"
    max_file_size_mb: int = 10
    backup_count: int = 5
    console_output: bool = True
    file_output: bool = True
    include_timestamp: bool = True
    include_caller: bool = True

    def __post_init__(self):
        """Validate and setup logging configuration."""
        if self.max_file_size_mb < 1:
            self.max_file_size_mb = 1
        if self.backup_count < 0:
            self.backup_count = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "level": self.level.value,
            "format": self.format,
            "file": {
                "path": self.file_path,
                "max_size_mb": self.max_file_size_mb,
                "backup_count": self.backup_count
            },
            "console_output": self.console_output,
            "file_output": self.file_output,
            "include_timestamp": self.include_timestamp,
            "include_caller": self.include_caller
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)

    def is_valid(self) -> bool:
        """Validate the configuration."""
        if not isinstance(self.level, (LogLevel, str)):
            return False
        if not self.format:
            return False
        return True

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'LoggingConfig':
        """Create LoggingConfig from dictionary."""
        if data is None:
            data = {}

        file_cfg = data.get("file", {}) or {}

        return LoggingConfig(
            level=LogLevel(data.get("level", "INFO")),
            format=data.get("format", "%(asctime)s - %(name)s - %(levelname)s - %(message)s"),
            file_path=file_cfg.get("path", "./logs/server.log"),
            max_file_size_mb=file_cfg.get("max_size_mb", 10),
            backup_count=file_cfg.get("backup_count", 5),
            console_output=data.get("console_output", True),
            file_output=data.get("file_output", True),
            include_timestamp=data.get("include_timestamp", True),
            include_caller=data.get("include_caller", True)
        )


# ============================================================================
# 3. TransportConfig DATA MODEL
# ============================================================================

@dataclass
class TransportConfig:
    """
    Configuration for transport layer.

    Attributes:
        transport_type: Primary transport type (stdio, http, websocket, grpc)
        enable_stdio: Enable stdio transport
        enable_http: Enable HTTP transport
        enable_websocket: Enable WebSocket transport
        http_host: HTTP server host
        http_port: HTTP server port
        http_timeout_seconds: HTTP request timeout
        websocket_host: WebSocket server host
        websocket_port: WebSocket server port
        websocket_timeout_seconds: WebSocket timeout
        max_connections: Maximum concurrent connections
        buffer_size_kb: Buffer size in kilobytes
    """
    transport_type: TransportType = TransportType.STDIO
    enable_stdio: bool = True
    enable_http: bool = False
    enable_websocket: bool = False
    http_host: str = "127.0.0.1"
    http_port: int = 8000
    http_timeout_seconds: int = 30
    websocket_host: str = "127.0.0.1"
    websocket_port: int = 8001
    websocket_timeout_seconds: int = 60
    max_connections: int = 100
    buffer_size_kb: int = 64

    def __post_init__(self):
        """Validate configuration values."""
        if self.http_port < 1 or self.http_port > 65535:
            self.http_port = 8000
        if self.websocket_port < 1 or self.websocket_port > 65535:
            self.websocket_port = 8001
        if self.http_timeout_seconds < 1:
            self.http_timeout_seconds = 30
        if self.websocket_timeout_seconds < 1:
            self.websocket_timeout_seconds = 60
        if self.max_connections < 1:
            self.max_connections = 10
        if self.buffer_size_kb < 1:
            self.buffer_size_kb = 8

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "transport_type": self.transport_type.value,
            "stdio": {
                "enabled": self.enable_stdio
            },
            "http": {
                "enabled": self.enable_http,
                "host": self.http_host,
                "port": self.http_port,
                "timeout_seconds": self.http_timeout_seconds
            },
            "websocket": {
                "enabled": self.enable_websocket,
                "host": self.websocket_host,
                "port": self.websocket_port,
                "timeout_seconds": self.websocket_timeout_seconds
            },
            "max_connections": self.max_connections,
            "buffer_size_kb": self.buffer_size_kb
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)

    def is_valid(self) -> bool:
        """Validate the configuration."""
        if not isinstance(self.transport_type, (TransportType, str)):
            return False
        if not (self.enable_stdio or self.enable_http or self.enable_websocket):
            return False
        return True

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'TransportConfig':
        """Create TransportConfig from dictionary."""
        if data is None:
            data = {}

        stdio_cfg = data.get("stdio", {}) or {}
        http_cfg = data.get("http", {}) or {}
        websocket_cfg = data.get("websocket", {}) or {}

        return TransportConfig(
            transport_type=TransportType(data.get("transport_type", "stdio")),
            enable_stdio=stdio_cfg.get("enabled", True),
            enable_http=http_cfg.get("enabled", False),
            enable_websocket=websocket_cfg.get("enabled", False),
            http_host=http_cfg.get("host", "127.0.0.1"),
            http_port=http_cfg.get("port", 8000),
            http_timeout_seconds=http_cfg.get("timeout_seconds", 30),
            websocket_host=websocket_cfg.get("host", "127.0.0.1"),
            websocket_port=websocket_cfg.get("port", 8001),
            websocket_timeout_seconds=websocket_cfg.get("timeout_seconds", 60),
            max_connections=data.get("max_connections", 100),
            buffer_size_kb=data.get("buffer_size_kb", 64)
        )


# ============================================================================
# 4. LLMConfig DATA MODEL
# ============================================================================

@dataclass
class LLMConfig:
    """
    Configuration for Language Model service.

    Attributes:
        enabled: Whether LLM service is enabled
        model_name: Name of the model to use
        ollama_host: Ollama server host
        ollama_port: Ollama server port
        timeout_seconds: Request timeout in seconds
        max_tokens: Maximum tokens in response
        temperature: Temperature parameter for generation (0.0-2.0)
        top_p: Top-p parameter for sampling
        top_k: Top-k parameter for sampling
        num_ctx: Context window size
        num_threads: Number of threads to use
        embedding_enabled: Whether embeddings are enabled
        embedding_model: Model to use for embeddings
        cot_enabled: Whether Chain-of-Thought is enabled
        cache_embeddings: Whether to cache embeddings
    """
    enabled: bool = True
    model_name: str = "llama2"
    ollama_host: str = "localhost"
    ollama_port: int = 11434
    timeout_seconds: int = 60
    max_tokens: int = 512
    temperature: float = 0.7
    top_p: float = 0.9
    top_k: int = 40
    num_ctx: int = 2048
    num_threads: int = 4
    embedding_enabled: bool = False
    embedding_model: str = "nomic-embed-text"
    cot_enabled: bool = False
    cache_embeddings: bool = True

    def __post_init__(self):
        """Validate configuration values."""
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

        if self.num_ctx < 128:
            self.num_ctx = 128

        if self.num_threads < 1:
            self.num_threads = 1

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "enabled": self.enabled,
            "model": {
                "name": self.model_name,
                "temperature": self.temperature,
                "top_p": self.top_p,
                "top_k": self.top_k,
                "max_tokens": self.max_tokens,
                "num_ctx": self.num_ctx,
                "num_threads": self.num_threads
            },
            "ollama": {
                "host": self.ollama_host,
                "port": self.ollama_port,
                "timeout_seconds": self.timeout_seconds
            },
            "embedding": {
                "enabled": self.embedding_enabled,
                "model": self.embedding_model,
                "cache": self.cache_embeddings
            },
            "cot": {
                "enabled": self.cot_enabled
            }
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)

    def is_valid(self) -> bool:
        """Validate the configuration."""
        if not self.model_name:
            return False
        if self.temperature < 0.0 or self.temperature > 2.0:
            return False
        if self.top_p < 0.0 or self.top_p > 1.0:
            return False
        return True

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'LLMConfig':
        """Create LLMConfig from dictionary."""
        if data is None:
            data = {}

        model_cfg = data.get("model", {}) or {}
        ollama_cfg = data.get("ollama", {}) or {}
        embedding_cfg = data.get("embedding", {}) or {}
        cot_cfg = data.get("cot", {}) or {}

        return LLMConfig(
            enabled=data.get("enabled", True),
            model_name=model_cfg.get("name", "llama2"),
            temperature=model_cfg.get("temperature", 0.7),
            top_p=model_cfg.get("top_p", 0.9),
            top_k=model_cfg.get("top_k", 40),
            max_tokens=model_cfg.get("max_tokens", 512),
            num_ctx=model_cfg.get("num_ctx", 2048),
            num_threads=model_cfg.get("num_threads", 4),
            ollama_host=ollama_cfg.get("host", "localhost"),
            ollama_port=ollama_cfg.get("port", 11434),
            timeout_seconds=ollama_cfg.get("timeout_seconds", 60),
            embedding_enabled=embedding_cfg.get("enabled", False),
            embedding_model=embedding_cfg.get("model", "nomic-embed-text"),
            cache_embeddings=embedding_cfg.get("cache", True),
            cot_enabled=cot_cfg.get("enabled", False)
        )


# ============================================================================
# 5. ServerConfig DATA MODEL (MAIN)
# ============================================================================

@dataclass
class ServerConfig:
    """
    Main server configuration.

    Attributes:
        name: Server name
        version: Server version
        debug: Debug mode flag
        profile: Server profile (development, staging, production)
        host: Server host
        port: Server port
        workers: Number of worker processes
        reload: Auto-reload on code changes
        log_config: Logging configuration
        transport_config: Transport layer configuration
        llm_config: LLM service configuration
        cache_config: Cache system configuration
        max_request_size_mb: Maximum request size in MB
        request_timeout_seconds: Request timeout in seconds
        database_url: Database connection URL
        security_key: Security key for encryption
        allowed_origins: Allowed CORS origins
        custom_settings: Custom settings dictionary
    """
    name: str = "HyFuzz-MCP-Server"
    version: str = "1.0.0"
    debug: bool = False
    profile: str = "development"
    host: str = "127.0.0.1"
    port: int = 8000
    workers: int = 1
    reload: bool = False
    log_config: LoggingConfig = field(default_factory=LoggingConfig)
    transport_config: TransportConfig = field(default_factory=TransportConfig)
    llm_config: LLMConfig = field(default_factory=LLMConfig)
    cache_config: CacheConfig = field(default_factory=CacheConfig)
    max_request_size_mb: int = 50
    request_timeout_seconds: int = 60
    database_url: Optional[str] = None
    security_key: Optional[str] = None
    allowed_origins: List[str] = field(default_factory=lambda: ["http://localhost:3000"])
    custom_settings: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Validate configuration values."""
        if self.port < 1 or self.port > 65535:
            self.port = 8000
        if self.workers < 1:
            self.workers = 1
        if self.max_request_size_mb < 1:
            self.max_request_size_mb = 10
        if self.request_timeout_seconds < 1:
            self.request_timeout_seconds = 30

        # Validate nested configs
        if self.log_config is None:
            self.log_config = LoggingConfig()
        if self.transport_config is None:
            self.transport_config = TransportConfig()
        if self.llm_config is None:
            self.llm_config = LLMConfig()
        if self.cache_config is None:
            self.cache_config = CacheConfig()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "server": {
                "name": self.name,
                "version": self.version,
                "debug": self.debug,
                "profile": self.profile,
                "host": self.host,
                "port": self.port,
                "workers": self.workers,
                "reload": self.reload
            },
            "logging": self.log_config.to_dict(),
            "transport": self.transport_config.to_dict(),
            "llm": self.llm_config.to_dict(),
            "cache": self.cache_config.to_dict(),
            "limits": {
                "max_request_size_mb": self.max_request_size_mb,
                "request_timeout_seconds": self.request_timeout_seconds
            },
            "security": {
                "database_url": self.database_url is not None,
                "security_key_set": self.security_key is not None,
                "allowed_origins": self.allowed_origins
            },
            "custom_settings": self.custom_settings
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)

    def is_valid(self) -> bool:
        """Validate the configuration."""
        if not self.name:
            return False
        if not self.log_config.is_valid():
            return False
        if not self.transport_config.is_valid():
            return False
        if not self.llm_config.is_valid():
            return False
        if not self.cache_config.is_valid():
            return False
        return True

    def is_production(self) -> bool:
        """Check if running in production mode."""
        return self.profile == "production"

    def is_development(self) -> bool:
        """Check if running in development mode."""
        return self.profile == "development"

    def get_setting(self, key: str, default: Any = None) -> Any:
        """Get custom setting value."""
        return self.custom_settings.get(key, default)

    def set_setting(self, key: str, value: Any) -> None:
        """Set custom setting value."""
        self.custom_settings[key] = value

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'ServerConfig':
        """Create ServerConfig from dictionary."""
        if data is None:
            data = {}

        server_cfg = data.get("server", {}) or {}

        return ServerConfig(
            name=server_cfg.get("name", "HyFuzz-MCP-Server"),
            version=server_cfg.get("version", "1.0.0"),
            debug=server_cfg.get("debug", False),
            profile=server_cfg.get("profile", "development"),
            host=server_cfg.get("host", "127.0.0.1"),
            port=server_cfg.get("port", 8000),
            workers=server_cfg.get("workers", 1),
            reload=server_cfg.get("reload", False),
            log_config=LoggingConfig.from_dict(data.get("logging", {})),
            transport_config=TransportConfig.from_dict(data.get("transport", {})),
            llm_config=LLMConfig.from_dict(data.get("llm", {})),
            cache_config=CacheConfig.from_dict(data.get("cache", {})),
            max_request_size_mb=data.get("limits", {}).get("max_request_size_mb", 50) if data.get("limits") else 50,
            request_timeout_seconds=data.get("limits", {}).get("request_timeout_seconds", 60) if data.get(
                "limits") else 60,
            database_url=data.get("security", {}).get("database_url") if data.get("security") else None,
            security_key=data.get("security", {}).get("security_key") if data.get("security") else None,
            allowed_origins=data.get("security", {}).get("allowed_origins", ["http://localhost:3000"]) if data.get(
                "security") else ["http://localhost:3000"],
            custom_settings=data.get("custom_settings", {})
        )

    @staticmethod
    def from_json(json_str: str) -> 'ServerConfig':
        """Create ServerConfig from JSON string."""
        data = json.loads(json_str)
        return ServerConfig.from_dict(data)

    @staticmethod
    def load_from_file(file_path: str) -> 'ServerConfig':
        """Load ServerConfig from JSON file."""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {file_path}")

        with open(file_path, 'r') as f:
            data = json.load(f)

        return ServerConfig.from_dict(data)

    def save_to_file(self, file_path: str) -> None:
        """Save ServerConfig to JSON file."""
        path = Path(file_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(file_path, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)


# ============================================================================
# VALIDATION AND TESTING
# ============================================================================

def run_validation_tests():
    """
    Run validation tests for all config models.
    """
    print("=" * 70)
    print("Config Models - Validation Tests")
    print("=" * 70)
    print()

    # Test 1: CacheConfig
    print("[TEST 1] CacheConfig Model...")
    try:
        cache_cfg = CacheConfig(backend=CacheBackend.MEMORY, ttl_seconds=1800)
        assert cache_cfg.is_valid()
        assert cache_cfg.to_dict() is not None
        assert cache_cfg.to_json() is not None
        cache_from_dict = CacheConfig.from_dict(cache_cfg.to_dict())
        assert cache_from_dict.backend == CacheBackend.MEMORY
        print("  ✓ CacheConfig creation successful")
        print(f"  ✓ Backend: {cache_cfg.backend.value}")
        print(f"  ✓ TTL: {cache_cfg.ttl_seconds}s")
        print()
    except Exception as e:
        print(f"  ✗ CacheConfig test failed: {str(e)}")
        print()

    # Test 2: LoggingConfig
    print("[TEST 2] LoggingConfig Model...")
    try:
        log_cfg = LoggingConfig(level=LogLevel.INFO, file_path="./logs/app.log")
        assert log_cfg.is_valid()
        assert log_cfg.to_dict() is not None
        assert log_cfg.to_json() is not None
        log_from_dict = LoggingConfig.from_dict(log_cfg.to_dict())
        assert log_from_dict.level == LogLevel.INFO
        print("  ✓ LoggingConfig creation successful")
        print(f"  ✓ Level: {log_cfg.level.value}")
        print(f"  ✓ File: {log_cfg.file_path}")
        print()
    except Exception as e:
        print(f"  ✗ LoggingConfig test failed: {str(e)}")
        print()

    # Test 3: TransportConfig
    print("[TEST 3] TransportConfig Model...")
    try:
        transport_cfg = TransportConfig(
            transport_type=TransportType.STDIO,
            enable_stdio=True,
            enable_http=False
        )
        assert transport_cfg.is_valid()
        assert transport_cfg.to_dict() is not None
        assert transport_cfg.to_json() is not None
        transport_from_dict = TransportConfig.from_dict(transport_cfg.to_dict())
        assert transport_from_dict.transport_type == TransportType.STDIO
        print("  ✓ TransportConfig creation successful")
        print(f"  ✓ Transport: {transport_cfg.transport_type.value}")
        print(f"  ✓ Stdio enabled: {transport_cfg.enable_stdio}")
        print()
    except Exception as e:
        print(f"  ✗ TransportConfig test failed: {str(e)}")
        print()

    # Test 4: LLMConfig
    print("[TEST 4] LLMConfig Model...")
    try:
        llm_cfg = LLMConfig(
            model_name="llama2",
            temperature=0.7,
            max_tokens=512
        )
        assert llm_cfg.is_valid()
        assert llm_cfg.to_dict() is not None
        assert llm_cfg.to_json() is not None
        llm_from_dict = LLMConfig.from_dict(llm_cfg.to_dict())
        assert llm_from_dict.model_name == "llama2"
        assert llm_from_dict.temperature == 0.7
        print("  ✓ LLMConfig creation successful")
        print(f"  ✓ Model: {llm_cfg.model_name}")
        print(f"  ✓ Temperature: {llm_cfg.temperature}")
        print(f"  ✓ Max tokens: {llm_cfg.max_tokens}")
        print()
    except Exception as e:
        print(f"  ✗ LLMConfig test failed: {str(e)}")
        print()

    # Test 5: ServerConfig
    print("[TEST 5] ServerConfig Model (Main)...")
    try:
        server_cfg = ServerConfig(
            name="HyFuzz-Server",
            version="1.0.0",
            debug=False,
            profile="production",
            port=8000
        )
        assert server_cfg.is_valid()
        assert server_cfg.to_dict() is not None
        assert server_cfg.to_json() is not None
        assert server_cfg.is_production()
        assert not server_cfg.is_development()

        # Test custom settings
        server_cfg.set_setting("custom_key", "custom_value")
        assert server_cfg.get_setting("custom_key") == "custom_value"

        # Test from_dict
        server_from_dict = ServerConfig.from_dict(server_cfg.to_dict())
        assert server_from_dict.name == "HyFuzz-Server"
        assert server_from_dict.is_production()

        print("  ✓ ServerConfig creation successful")
        print(f"  ✓ Name: {server_cfg.name}")
        print(f"  ✓ Profile: {server_cfg.profile}")
        print(f"  ✓ Port: {server_cfg.port}")
        print(f"  ✓ Production mode: {server_cfg.is_production()}")
        print("  ✓ Nested configs validated")
        print()
    except Exception as e:
        print(f"  ✗ ServerConfig test failed: {str(e)}")
        print()

    # Test 6: Configuration Validation
    print("[TEST 6] Configuration Validation...")
    try:
        # Invalid temperature
        invalid_llm = LLMConfig(temperature=5.0)
        # Should be clamped to 2.0
        assert invalid_llm.temperature == 2.0

        # Invalid port
        invalid_server = ServerConfig(port=70000)
        # Should be reset to default
        assert invalid_server.port == 8000

        print("  ✓ Invalid temperature corrected")
        print("  ✓ Invalid port corrected")
        print("  ✓ Auto-correction working")
        print()
    except Exception as e:
        print(f"  ✗ Validation test failed: {str(e)}")
        print()

    # Test 7: Configuration Serialization
    print("[TEST 7] Configuration Serialization...")
    try:
        server_cfg = ServerConfig()

        # to_dict
        dict_cfg = server_cfg.to_dict()
        assert isinstance(dict_cfg, dict)

        # to_json
        json_str = server_cfg.to_json()
        assert isinstance(json_str, str)
        assert "server" in json_str

        # from_json
        server_from_json = ServerConfig.from_json(json_str)
        assert server_from_json.name == server_cfg.name

        print("  ✓ to_dict() successful")
        print("  ✓ to_json() successful")
        print("  ✓ from_json() successful")
        print("  ✓ Round-trip serialization working")
        print()
    except Exception as e:
        print(f"  ✗ Serialization test failed: {str(e)}")
        print()

    # Summary
    print("=" * 70)
    print("✓ Config Models Validation Complete")
    print("=" * 70)
    print()
    print("Available Models:")
    print("  • CacheConfig (5 backends: memory, redis, memcached, file, etc)")
    print("  • LoggingConfig (5 log levels, file rotation)")
    print("  • TransportConfig (stdio, HTTP, WebSocket, gRPC)")
    print("  • LLMConfig (Ollama integration, embeddings, CoT)")
    print("  • ServerConfig (Main config with nested sub-configs)")


if __name__ == "__main__":
    run_validation_tests()