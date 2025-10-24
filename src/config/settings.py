"""
Settings Module for HyFuzz MCP Server

This module provides the Settings class for managing application configuration.
It integrates with ConfigLoader to load configurations from multiple sources
and provides type-safe access to configuration values.

Features:
- Configuration loading from YAML, environment, .env
- Type validation and conversion
- Nested attribute access (e.g., settings.server.port)
- Environment-aware configuration overrides
- Comprehensive validation
- Default values and fallbacks
- Configuration caching
- Debug and development modes

Example:
    >>> from src.config.settings import Settings
    >>> settings = Settings()
    >>> print(settings.server_host)
    'localhost'
    >>> print(settings.server_port)
    5000
"""

import os
import logging
from typing import Dict, Any, Optional, List, Type, Union
from pathlib import Path
from dataclasses import dataclass, field, asdict
from enum import Enum
import json

from .config_loader import ConfigLoader, EnvironmentType

# ==============================================================================
# LOGGER SETUP
# ==============================================================================

logger = logging.getLogger(__name__)


# ==============================================================================
# NESTED CONFIGURATION CLASSES (using dataclasses)
# ==============================================================================


@dataclass
class ServerConfig:
    """Server configuration"""

    host: str = "0.0.0.0"
    port: int = 5000
    debug: bool = False
    reload: bool = False
    workers: int = 1
    worker_timeout: int = 60
    request_timeout: int = 30
    response_timeout: int = 60
    max_concurrent_requests: int = 1000
    buffer_size: int = 8192
    max_message_size: int = 1048576
    name: str = "hyfuzz-server"
    version: str = "1.0.0"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)


@dataclass
class TransportConfig:
    """Transport layer configuration"""

    default: str = "stdio"
    stdio_enabled: bool = True
    http_enabled: bool = False
    http_endpoint: str = "/mcp"
    http_port: int = 5000
    websocket_enabled: bool = False
    websocket_endpoint: str = "/ws/mcp"
    websocket_ping_interval: int = 20

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)


@dataclass
class SessionConfig:
    """Session management configuration"""

    enabled: bool = True
    max_sessions: int = 100
    timeout: int = 3600
    storage_type: str = "memory"
    storage_path: str = "data/sessions"
    cleanup_enabled: bool = True
    cleanup_interval: int = 300
    preserve_context: bool = True
    max_history: int = 100

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)


@dataclass
class LLMConfig:
    """LLM service configuration"""

    provider: str = "ollama"
    base_url: str = "http://localhost:11434"
    timeout: int = 300
    retries: int = 3
    backoff_factor: float = 2.0
    primary_model: str = "mistral"
    temperature: float = 0.7
    top_p: float = 0.95
    max_tokens: int = 2048
    cot_enabled: bool = True
    cot_max_steps: int = 10
    cache_enabled: bool = True
    cache_ttl: int = 3600

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)


@dataclass
class KnowledgeConfig:
    """Knowledge base configuration"""

    data_dir: str = "data"
    cache_dir: str = "data/cache"
    cwe_enabled: bool = True
    cwe_source: str = "local"
    cwe_cache_enabled: bool = True
    cve_enabled: bool = True
    cve_source: str = "local"
    cve_cache_enabled: bool = True
    db_type: str = "sqlite"
    db_path: str = "data/vulnerability.db"
    max_cache_size: int = 50000

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)


@dataclass
class CacheConfig:
    """Cache configuration"""

    type: str = "memory"
    memory_max_size: int = 10000
    memory_ttl: int = 3600
    eviction_policy: str = "lru"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)


@dataclass
class LoggingConfig:
    """Logging configuration"""

    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    date_format: str = "%Y-%m-%d %H:%M:%S"
    console_enabled: bool = True
    console_level: str = "INFO"
    file_enabled: bool = True
    file_path: str = "logs/server.log"
    file_level: str = "DEBUG"
    file_max_bytes: int = 10485760
    file_backup_count: int = 5

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)


@dataclass
class SecurityConfig:
    """Security configuration"""

    auth_enabled: bool = False
    auth_type: str = "api_key"
    rate_limit_enabled: bool = False
    rate_limit_requests_per_minute: int = 60
    input_validation_enabled: bool = True
    sanitize_input: bool = False
    tls_enabled: bool = False
    cors_enabled: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)


@dataclass
class MonitoringConfig:
    """Monitoring and health check configuration"""

    health_check_enabled: bool = True
    health_check_interval: int = 30
    metrics_enabled: bool = True
    metrics_interval: int = 60
    tracing_enabled: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)


# ==============================================================================
# SETTINGS CLASS
# ==============================================================================


class Settings:
    """
    Main settings class for HyFuzz MCP Server.

    Provides centralized configuration management with support for:
    - Multiple configuration sources (file, environment, .env)
    - Type validation and conversion
    - Nested attribute access
    - Environment-specific overrides
    - Configuration caching

    Example:
        >>> settings = Settings()
        >>> print(settings.environment)
        'development'
        >>> print(settings.server.port)
        5000
    """

    def __init__(
        self,
        config_path: Optional[Union[str, Path]] = None,
        environment: Optional[str] = None,
    ):
        """
        Initialize settings.

        Args:
            config_path: Path to configuration file
            environment: Override environment (development, testing, production)
        """
        self.logger = logger
        self._loader = ConfigLoader()
        self._raw_config: Dict[str, Any] = {}
        self._validated = False

        # Load configuration
        self._load_configuration(config_path, environment)

        # Initialize subsystem configurations
        self._init_subsystems()

        # Validate configuration
        self.validate()

        self.logger.info(f"Settings initialized for environment: {self.environment}")

    # ========================================================================
    # CONFIGURATION LOADING
    # ========================================================================

    def _load_configuration(
        self,
        config_path: Optional[Union[str, Path]] = None,
        environment: Optional[str] = None,
    ) -> None:
        """
        Load configuration from multiple sources with priority handling.

        Priority (high to low):
        1. Environment variables
        2. .env file
        3. Configuration file
        4. Defaults
        """
        try:
            # Load with priority
            self._raw_config = self._loader.load_with_priority(
                file_path=config_path,
                include_env=True,
                include_env_file=True,
            )

            # Override environment if provided
            if environment:
                self._raw_config["environment"] = environment

            self.logger.debug("Configuration loaded successfully")

        except Exception as e:
            self.logger.error(f"Failed to load configuration: {e}")
            raise

    def _init_subsystems(self) -> None:
        """Initialize subsystem configurations"""
        # Server
        self.server = self._create_config_object(
            ServerConfig,
            self._raw_config.get("server", {}),
        )

        # Transport
        self.transport = self._create_config_object(
            TransportConfig,
            self._raw_config.get("transport", {}),
        )

        # Session
        self.session = self._create_config_object(
            SessionConfig,
            self._raw_config.get("session", {}),
        )

        # LLM
        self.llm = self._create_config_object(
            LLMConfig,
            self._raw_config.get("llm", {}),
        )

        # Knowledge
        self.knowledge = self._create_config_object(
            KnowledgeConfig,
            self._raw_config.get("knowledge", {}),
        )

        # Cache
        self.cache = self._create_config_object(
            CacheConfig,
            self._raw_config.get("cache", {}),
        )

        # Logging
        self.logging = self._create_config_object(
            LoggingConfig,
            self._raw_config.get("logging", {}),
        )

        # Security
        self.security = self._create_config_object(
            SecurityConfig,
            self._raw_config.get("security", {}),
        )

        # Monitoring
        self.monitoring = self._create_config_object(
            MonitoringConfig,
            self._raw_config.get("monitoring", {}),
        )

    def _create_config_object(
        self,
        config_class: Type,
        config_dict: Dict[str, Any],
    ) -> Any:
        """
        Create configuration object from dictionary.

        Handles nested keys and type conversion.
        """
        try:
            # Extract relevant fields for the class
            kwargs = {}
            for field_name in config_class.__dataclass_fields__:
                # Try nested key first
                nested_key = field_name.replace("_", ".")
                value = self._loader.get(config_dict, nested_key)

                # Try direct key
                if value is None:
                    value = config_dict.get(field_name)

                # Use field value if found
                if value is not None:
                    kwargs[field_name] = value

            return config_class(**kwargs)

        except Exception as e:
            self.logger.warning(
                f"Error creating {config_class.__name__}: {e}. Using defaults."
            )
            return config_class()

    # ========================================================================
    # PROPERTIES
    # ========================================================================

    @property
    def environment(self) -> str:
        """Get current environment"""
        return self._raw_config.get("environment", "development")

    @property
    def is_development(self) -> bool:
        """Check if development environment"""
        return self.environment == "development"

    @property
    def is_testing(self) -> bool:
        """Check if testing environment"""
        return self.environment == "testing"

    @property
    def is_production(self) -> bool:
        """Check if production environment"""
        return self.environment == "production"

    @property
    def debug(self) -> bool:
        """Get debug mode"""
        return self.server.debug

    @property
    def server_host(self) -> str:
        """Get server host"""
        return self.server.host

    @property
    def server_port(self) -> int:
        """Get server port"""
        return self.server.port

    @property
    def log_level(self) -> str:
        """Get log level"""
        return self.logging.level

    @property
    def llm_provider(self) -> str:
        """Get LLM provider"""
        return self.llm.provider

    @property
    def llm_model(self) -> str:
        """Get primary LLM model"""
        return self.llm.primary_model

    @property
    def ollama_url(self) -> str:
        """Get Ollama base URL"""
        return self.llm.base_url

    @property
    def knowledge_data_dir(self) -> str:
        """Get knowledge data directory"""
        return self.knowledge.data_dir

    @property
    def cache_type(self) -> str:
        """Get cache type"""
        return self.cache.type

    # ========================================================================
    # VALIDATION
    # ========================================================================

    def validate(self) -> bool:
        """
        Validate configuration.

        Returns:
            True if valid

        Raises:
            ValueError: If validation fails
        """
        try:
            # Validate server config
            if not (0 < self.server.port < 65536):
                raise ValueError(f"Invalid server port: {self.server.port}")

            # Validate environment
            valid_envs = ["development", "testing", "staging", "production"]
            if self.environment not in valid_envs:
                raise ValueError(f"Invalid environment: {self.environment}")

            # Validate LLM config
            if not self.llm.temperature or not (0 <= self.llm.temperature <= 2.0):
                raise ValueError(f"Invalid LLM temperature: {self.llm.temperature}")

            # Validate timeout values
            if self.llm.timeout <= 0:
                raise ValueError(f"Invalid LLM timeout: {self.llm.timeout}")

            # Validate cache settings
            if self.cache.memory_ttl <= 0:
                raise ValueError(f"Invalid cache TTL: {self.cache.memory_ttl}")

            self._validated = True
            self.logger.debug("Configuration validation passed")
            return True

        except ValueError as e:
            self.logger.error(f"Configuration validation failed: {e}")
            raise

    # ========================================================================
    # CONFIGURATION ACCESS AND MANIPULATION
    # ========================================================================

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value with nested key support.

        Args:
            key: Key path (e.g., "server.port")
            default: Default value if not found

        Returns:
            Configuration value
        """
        return self._loader.get(self._raw_config, key, default)

    def set(self, key: str, value: Any) -> None:
        """
        Set configuration value.

        Args:
            key: Key path
            value: Value to set
        """
        self._loader.set(self._raw_config, key, value)
        self.logger.debug(f"Configuration updated: {key} = {value}")

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert all settings to dictionary.

        Returns:
            Dictionary representation of settings
        """
        return {
            "environment": self.environment,
            "server": self.server.to_dict(),
            "transport": self.transport.to_dict(),
            "session": self.session.to_dict(),
            "llm": self.llm.to_dict(),
            "knowledge": self.knowledge.to_dict(),
            "cache": self.cache.to_dict(),
            "logging": self.logging.to_dict(),
            "security": self.security.to_dict(),
            "monitoring": self.monitoring.to_dict(),
        }

    def to_json(self, indent: int = 2) -> str:
        """
        Convert settings to JSON string.

        Args:
            indent: JSON indentation

        Returns:
            JSON string
        """
        return json.dumps(self.to_dict(), indent=indent)

    # ========================================================================
    # INFORMATION AND DEBUGGING
    # ========================================================================

    def get_info(self) -> Dict[str, Any]:
        """
        Get settings information for debugging.

        Returns:
            Information dictionary
        """
        return {
            "environment": self.environment,
            "debug": self.debug,
            "server": {
                "host": self.server.host,
                "port": self.server.port,
            },
            "llm": {
                "provider": self.llm.provider,
                "model": self.llm.primary_model,
                "base_url": self.llm.base_url,
            },
            "logging": {
                "level": self.logging.level,
            },
            "validated": self._validated,
        }

    def print_settings(self) -> None:
        """Print current settings (for debugging)"""
        info = self.get_info()
        self.logger.info(f"Settings: {json.dumps(info, indent=2)}")

    def __repr__(self) -> str:
        """String representation"""
        return (
            f"Settings(environment={self.environment}, "
            f"host={self.server.host}, port={self.server.port})"
        )


# ==============================================================================
# CONVENIENCE FUNCTIONS
# ==============================================================================


def get_settings(
    config_path: Optional[Union[str, Path]] = None,
    environment: Optional[str] = None,
) -> Settings:
    """
    Create and return a Settings instance.

    Args:
        config_path: Path to configuration file
        environment: Override environment

    Returns:
        Settings instance
    """
    return Settings(config_path=config_path, environment=environment)


def load_settings_from_file(filepath: Union[str, Path]) -> Settings:
    """Load settings from configuration file"""
    return Settings(config_path=filepath)


def load_settings_from_environment() -> Settings:
    """Load settings from environment variables and .env"""
    return Settings()


# ==============================================================================
# CONFIGURATION PROFILE
# ==============================================================================

class SettingsProfile:
    """
    Predefined settings profiles for different environments.

    Usage:
        >>> profile = SettingsProfile.development()
        >>> settings = Settings(**profile.to_dict())
    """

    @staticmethod
    def development() -> Dict[str, Any]:
        """Development profile"""
        return {
            "environment": "development",
            "config_path": "config/example_configs/config_dev.yaml",
        }

    @staticmethod
    def testing() -> Dict[str, Any]:
        """Testing profile"""
        return {
            "environment": "testing",
            "config_path": "config/example_configs/config_test.yaml",
        }

    @staticmethod
    def staging() -> Dict[str, Any]:
        """Staging profile"""
        return {
            "environment": "staging",
            "config_path": "config/example_configs/config_staging.yaml",
        }

    @staticmethod
    def production() -> Dict[str, Any]:
        """Production profile"""
        return {
            "environment": "production",
            "config_path": "config/example_configs/config_prod.yaml",
        }


# ==============================================================================
# MODULE INITIALIZATION
# ==============================================================================

# Log module initialization
logger.debug("Settings module loaded")