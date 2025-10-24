"""
Configuration Module for HyFuzz MCP Server

This module provides centralized configuration management for the MCP server,
including settings loading, validation, and access patterns.

Features:
- Environment-based configuration (development, testing, production)
- YAML configuration file support
- Environment variable override support
- Configuration validation and type checking
- Logging configuration management
- Multiple transport protocol configuration
- LLM service configuration
- Knowledge base management configuration
"""

import os
import sys
import logging
from typing import Dict, Any, Optional, Type, List
from pathlib import Path
from enum import Enum

__version__ = "1.0.0"
__author__ = "HyFuzz Team"
__all__ = [
    "Settings",
    "ConfigLoader",
    "get_settings",
    "load_config",
    "get_config_path",
    "Environment",
    "TransportType",
    "LogLevel",
    "CONFIG_DIR",
    "DEFAULT_CONFIG_PATH",
]

# ==============================================================================
# PATHS AND CONSTANTS
# ==============================================================================

# Determine the config directory relative to this module
CONFIG_DIR = Path(__file__).parent
PROJECT_ROOT = CONFIG_DIR.parent.parent
DEFAULT_CONFIG_PATH = CONFIG_DIR / "default_config.yaml"
LOGGING_CONFIG_PATH = CONFIG_DIR / "logging_config.yaml"

# ==============================================================================
# ENUMERATIONS
# ==============================================================================


class Environment(str, Enum):
    """Server environment enumeration"""

    DEVELOPMENT = "development"
    TESTING = "testing"
    STAGING = "staging"
    PRODUCTION = "production"

    def __str__(self):
        return self.value


class TransportType(str, Enum):
    """Supported transport protocol types"""

    STDIO = "stdio"
    HTTP = "http"
    WEBSOCKET = "websocket"

    def __str__(self):
        return self.value


class LogLevel(str, Enum):
    """Logging level enumeration"""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

    def __str__(self):
        return self.value


# ==============================================================================
# CONFIGURATION CLASSES (IMPORTS)
# ==============================================================================

try:
    from .settings import Settings
except ImportError:
    # Fallback if settings module not available
    Settings = None  # type: ignore

try:
    from .config_loader import ConfigLoader
except ImportError:
    # Fallback if config_loader module not available
    ConfigLoader = None  # type: ignore


# ==============================================================================
# LOGGER SETUP
# ==============================================================================

logger = logging.getLogger(__name__)


# ==============================================================================
# GLOBAL CONFIGURATION INSTANCE
# ==============================================================================

_global_settings: Optional[Any] = None


# ==============================================================================
# PUBLIC INTERFACE FUNCTIONS
# ==============================================================================


def get_settings(reload: bool = False) -> Any:
    """
    Get or create the global settings instance.

    This function maintains a singleton pattern for configuration access
    throughout the application.

    Args:
        reload: Force reload configuration from files

    Returns:
        Settings instance

    Example:
        >>> settings = get_settings()
        >>> print(settings.server_host)
        'localhost'
    """
    global _global_settings

    if _global_settings is None or reload:
        if Settings is None:
            raise ImportError("Settings class not available. Check settings.py")
        _global_settings = Settings()
        logger.debug(f"Settings loaded from environment: {_global_settings.environment}")

    return _global_settings


def load_config(
    config_path: Optional[str] = None,
    environment: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Load configuration from file or environment.

    Args:
        config_path: Path to configuration file (YAML)
        environment: Override environment (development, testing, production)

    Returns:
        Configuration dictionary

    Raises:
        FileNotFoundError: If config file not found
        ValueError: If configuration is invalid

    Example:
        >>> config = load_config("config/config_dev.yaml")
        >>> print(config["server"]["port"])
        5000
    """
    if ConfigLoader is None:
        raise ImportError("ConfigLoader class not available. Check config_loader.py")

    loader = ConfigLoader()

    if config_path:
        config_path = Path(config_path)
        if not config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
        config = loader.load_from_file(config_path)
    else:
        config = loader.load_from_environment()

    if environment:
        config["environment"] = environment

    logger.debug(f"Configuration loaded successfully")
    return config


def get_config_path(environment: Optional[str] = None) -> Path:
    """
    Get the configuration file path for given environment.

    Args:
        environment: Environment name (uses current env if None)

    Returns:
        Path to configuration file

    Example:
        >>> config_path = get_config_path("development")
        >>> print(config_path)
        Path('/project/config/example_configs/config_dev.yaml')
    """
    if environment is None:
        environment = os.getenv("ENVIRONMENT", "development")

    env_map = {
        "development": CONFIG_DIR / "example_configs" / "config_dev.yaml",
        "testing": CONFIG_DIR / "example_configs" / "config_test.yaml",
        "staging": CONFIG_DIR / "example_configs" / "config_staging.yaml",
        "production": CONFIG_DIR / "example_configs" / "config_prod.yaml",
    }

    return env_map.get(environment, DEFAULT_CONFIG_PATH)


def reset_settings() -> None:
    """
    Reset global settings instance.

    Useful for testing or reconfiguration.

    Example:
        >>> reset_settings()
        >>> settings = get_settings()  # Fresh instance
    """
    global _global_settings
    _global_settings = None
    logger.debug("Settings instance reset")


def validate_configuration() -> bool:
    """
    Validate current configuration.

    Returns:
        True if configuration is valid

    Raises:
        ValueError: If configuration is invalid
    """
    try:
        settings = get_settings()
        # Perform validation checks
        if Settings and hasattr(settings, "validate"):
            settings.validate()
        logger.debug("Configuration validation passed")
        return True
    except Exception as e:
        logger.error(f"Configuration validation failed: {e}")
        raise ValueError(f"Invalid configuration: {e}") from e


# ==============================================================================
# CONFIGURATION UTILITY FUNCTIONS
# ==============================================================================


def get_environment() -> str:
    """
    Get current environment.

    Returns:
        Current environment string (development, testing, production)
    """
    return os.getenv("ENVIRONMENT", "development")


def is_debug_enabled() -> bool:
    """
    Check if debug mode is enabled.

    Returns:
        True if debug mode is enabled
    """
    debug_str = os.getenv("DEBUG", "false").lower()
    return debug_str in ("true", "1", "yes", "on")


def is_development() -> bool:
    """Check if running in development environment"""
    return get_environment() == "development"


def is_testing() -> bool:
    """Check if running in testing environment"""
    return get_environment() == "testing"


def is_production() -> bool:
    """Check if running in production environment"""
    return get_environment() == "production"


def get_log_level() -> str:
    """
    Get configured log level.

    Returns:
        Log level string (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    """
    return os.getenv("LOG_LEVEL", "INFO")


def get_server_host() -> str:
    """Get server host configuration"""
    return os.getenv("SERVER_HOST", "0.0.0.0")


def get_server_port() -> int:
    """Get server port configuration"""
    try:
        return int(os.getenv("SERVER_PORT", "5000"))
    except ValueError:
        logger.warning("Invalid SERVER_PORT, using default 5000")
        return 5000


def get_ollama_url() -> str:
    """Get Ollama API URL"""
    return os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")


def get_llm_model() -> str:
    """Get configured LLM model name"""
    return os.getenv("OLLAMA_MODEL", "mistral")


# ==============================================================================
# CONFIGURATION FACTORY FUNCTIONS
# ==============================================================================


def create_server_config(
    host: Optional[str] = None,
    port: Optional[int] = None,
    debug: Optional[bool] = None,
) -> Dict[str, Any]:
    """
    Create server configuration dictionary.

    Args:
        host: Server host (uses env var if None)
        port: Server port (uses env var if None)
        debug: Debug mode (uses env var if None)

    Returns:
        Server configuration dictionary
    """
    return {
        "host": host or get_server_host(),
        "port": port or get_server_port(),
        "debug": debug if debug is not None else is_debug_enabled(),
        "environment": get_environment(),
    }


def create_transport_config(transport_type: str) -> Dict[str, Any]:
    """
    Create transport configuration for specified type.

    Args:
        transport_type: Type of transport (stdio, http, websocket)

    Returns:
        Transport configuration dictionary
    """
    base_config = {
        "type": transport_type,
        "enabled": True,
    }

    if transport_type == "http":
        base_config.update({
            "endpoint": "/mcp",
            "host": get_server_host(),
            "port": get_server_port(),
        })
    elif transport_type == "websocket":
        base_config.update({
            "endpoint": "/ws/mcp",
            "ping_interval": 20,
            "ping_timeout": 10,
        })
    elif transport_type == "stdio":
        base_config.update({
            "buffering": True,
            "encoding": "utf-8",
        })

    return base_config


def create_llm_config() -> Dict[str, Any]:
    """
    Create LLM configuration dictionary.

    Returns:
        LLM configuration dictionary
    """
    return {
        "provider": "ollama",
        "base_url": get_ollama_url(),
        "model": get_llm_model(),
        "temperature": float(os.getenv("LLM_TEMPERATURE", "0.7")),
        "top_p": float(os.getenv("LLM_TOP_P", "0.95")),
        "max_tokens": int(os.getenv("LLM_MAX_TOKENS", "2048")),
        "timeout": int(os.getenv("LLM_TIMEOUT", "300")),
    }


def create_knowledge_config() -> Dict[str, Any]:
    """
    Create knowledge base configuration dictionary.

    Returns:
        Knowledge base configuration dictionary
    """
    return {
        "data_dir": os.getenv("KNOWLEDGE_DATA_DIR", "data"),
        "cache_dir": os.getenv("KNOWLEDGE_CACHE_DIR", "data/cache"),
        "cache_enabled": os.getenv("KNOWLEDGE_CACHE_ENABLED", "true").lower() == "true",
        "max_cache_size": int(os.getenv("KNOWLEDGE_CACHE_SIZE", "1000")),
        "update_interval": int(os.getenv("KNOWLEDGE_UPDATE_INTERVAL", "3600")),
    }


# ==============================================================================
# CONFIGURATION VALIDATION
# ==============================================================================


def validate_server_config(config: Dict[str, Any]) -> bool:
    """
    Validate server configuration.

    Args:
        config: Server configuration dictionary

    Returns:
        True if valid

    Raises:
        ValueError: If configuration is invalid
    """
    required_keys = {"host", "port"}
    if not required_keys.issubset(config.keys()):
        raise ValueError(f"Missing required keys: {required_keys - set(config.keys())}")

    if not isinstance(config["port"], int) or not (0 < config["port"] < 65536):
        raise ValueError("Port must be integer between 1 and 65535")

    return True


def validate_transport_config(config: Dict[str, Any]) -> bool:
    """
    Validate transport configuration.

    Args:
        config: Transport configuration dictionary

    Returns:
        True if valid

    Raises:
        ValueError: If configuration is invalid
    """
    valid_types = {t.value for t in TransportType}
    if config.get("type") not in valid_types:
        raise ValueError(f"Invalid transport type: {config.get('type')}")

    return True


def validate_llm_config(config: Dict[str, Any]) -> bool:
    """
    Validate LLM configuration.

    Args:
        config: LLM configuration dictionary

    Returns:
        True if valid

    Raises:
        ValueError: If configuration is invalid
    """
    required_keys = {"provider", "model"}
    if not required_keys.issubset(config.keys()):
        raise ValueError(f"Missing required LLM config keys: {required_keys}")

    if not (0 <= config.get("temperature", 0.7) <= 2.0):
        raise ValueError("Temperature must be between 0 and 2")

    return True


# ==============================================================================
# MODULE INITIALIZATION
# ==============================================================================


def _initialize_module() -> None:
    """Initialize configuration module on import"""
    try:
        # Validate that required configuration files exist
        if not DEFAULT_CONFIG_PATH.exists():
            logger.warning(f"Default config not found: {DEFAULT_CONFIG_PATH}")

        # Log configuration directory
        logger.debug(f"Configuration directory: {CONFIG_DIR}")
        logger.debug(f"Project root: {PROJECT_ROOT}")

    except Exception as e:
        logger.warning(f"Error during config module initialization: {e}")


# ==============================================================================
# CONFIGURATION CLASSES EXPORT
# ==============================================================================

# Make Settings and ConfigLoader available at module level
__all__.extend(["Settings", "ConfigLoader"])

# Re-export enums
__all__.extend(["Environment", "TransportType", "LogLevel"])

# Re-export utility functions
__all__.extend([
    "get_environment",
    "is_debug_enabled",
    "is_development",
    "is_testing",
    "is_production",
    "get_log_level",
    "get_server_host",
    "get_server_port",
    "get_ollama_url",
    "get_llm_model",
])

# Re-export factory functions
__all__.extend([
    "create_server_config",
    "create_transport_config",
    "create_llm_config",
    "create_knowledge_config",
])

# Re-export validation functions
__all__.extend([
    "validate_configuration",
    "validate_server_config",
    "validate_transport_config",
    "validate_llm_config",
])

# Re-export utility
__all__.extend([
    "reset_settings",
    "get_config_path",
])


# ==============================================================================
# MODULE-LEVEL METADATA
# ==============================================================================

__meta__ = {
    "name": "config",
    "version": __version__,
    "description": "Configuration management for HyFuzz MCP Server",
    "author": __author__,
    "python_requires": ">=3.9",
    "config_dir": str(CONFIG_DIR),
    "project_root": str(PROJECT_ROOT),
}


# ==============================================================================
# INITIALIZATION
# ==============================================================================

_initialize_module()


# ==============================================================================
# CONVENIENCE ALIASES
# ==============================================================================

# Allow direct access to common functions
settings = get_settings
config = load_config
env = get_environment
debug = is_debug_enabled
prod = is_production


# ==============================================================================
# MODULE DOCSTRING EXAMPLES
# ==============================================================================

"""
Usage Examples:

Basic Configuration Access:
    >>> from src.config import get_settings
    >>> settings = get_settings()
    >>> print(settings.server_host)
    'localhost'

Load Custom Configuration:
    >>> from src.config import load_config
    >>> config = load_config("config/config_dev.yaml")
    >>> print(config["server"]["port"])
    5000

Environment Checks:
    >>> from src.config import is_development, is_production
    >>> if is_development():
    ...     print("Running in development mode")

Create Subsystem Configurations:
    >>> from src.config import create_llm_config
    >>> llm_cfg = create_llm_config()
    >>> print(llm_cfg["model"])
    'mistral'

Configuration Validation:
    >>> from src.config import validate_configuration
    >>> if validate_configuration():
    ...     print("Configuration is valid")

Environment Variables:
    Set in .env or system:
    - ENVIRONMENT: development|testing|production
    - SERVER_HOST: 0.0.0.0
    - SERVER_PORT: 5000
    - DEBUG: true|false
    - LOG_LEVEL: DEBUG|INFO|WARNING|ERROR|CRITICAL
    - OLLAMA_BASE_URL: http://localhost:11434
    - OLLAMA_MODEL: mistral
"""