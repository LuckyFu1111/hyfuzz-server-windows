"""
Configuration Loader for HyFuzz MCP Server

This module provides flexible configuration loading from multiple sources:
- YAML configuration files
- Environment variables (.env)
- System environment
- Command-line arguments
- In-memory defaults

Features:
- Multi-source configuration merging with priority handling
- Nested configuration access (e.g., config.get("server.port"))
- Environment variable substitution and override
- Configuration validation
- Caching for performance
- Type conversion and defaults
- Comprehensive error handling
- Deep merge capability for complex configurations
"""

import os
import sys
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List, Union, Tuple
from dataclasses import dataclass, field
from enum import Enum
from copy import deepcopy
import json
from urllib.parse import urlparse

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
    yaml = None  # type: ignore

# ==============================================================================
# LOGGER SETUP
# ==============================================================================

logger = logging.getLogger(__name__)


# ==============================================================================
# CONSTANTS
# ==============================================================================

# Configuration file paths
CONFIG_DIR = Path(__file__).parent
DEFAULT_CONFIG = CONFIG_DIR / "default_config.yaml"
LOGGING_CONFIG = CONFIG_DIR / "logging_config.yaml"
ENV_FILE = CONFIG_DIR.parent.parent / ".env"

# Environment variable prefix
ENV_PREFIX = "HYFUZZ_"
ENV_SEPARATOR = "__"  # Use __ for nested keys (e.g., SERVER__PORT)

# Priority order for configuration sources (lower = higher priority)
CONFIG_PRIORITY = {
    "command_line": 0,
    "environment": 1,
    "env_file": 2,
    "file": 3,
    "defaults": 4,
}


# ==============================================================================
# ENUMERATIONS
# ==============================================================================

class ConfigSource(str, Enum):
    """Configuration source enumeration"""

    DEFAULTS = "defaults"
    FILE = "file"
    ENV_FILE = "env_file"
    ENVIRONMENT = "environment"
    COMMAND_LINE = "command_line"


class EnvironmentType(str, Enum):
    """Environment type enumeration"""

    DEVELOPMENT = "development"
    TESTING = "testing"
    STAGING = "staging"
    PRODUCTION = "production"


# ==============================================================================
# DATA CLASSES
# ==============================================================================

@dataclass
class ConfigMetadata:
    """Metadata for loaded configuration"""

    source: ConfigSource
    path: Optional[Path] = None
    timestamp: Optional[str] = None
    version: str = "1.0.0"
    environment: Optional[str] = None
    merged_from: List[ConfigSource] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "source": str(self.source),
            "path": str(self.path) if self.path else None,
            "timestamp": self.timestamp,
            "version": self.version,
            "environment": self.environment,
            "merged_from": [str(s) for s in self.merged_from],
        }


# ==============================================================================
# CONFIGURATION LOADER
# ==============================================================================

class ConfigLoader:
    """
    Flexible configuration loader supporting multiple sources.

    Features:
    - Load from YAML files
    - Load from environment variables
    - Load from .env files
    - Merge configurations with priority handling
    - Nested configuration access
    - Type conversion and validation
    - Caching for performance

    Example:
        >>> loader = ConfigLoader()
        >>> config = loader.load_from_file("config.yaml")
        >>> value = config.get("server.port", 5000)
    """

    def __init__(self, use_cache: bool = True):
        """
        Initialize configuration loader.

        Args:
            use_cache: Enable configuration caching
        """
        self.use_cache = use_cache
        self._cache: Dict[str, Any] = {}
        self._metadata: Optional[ConfigMetadata] = None
        self.logger = logger

    # ========================================================================
    # PRIMARY LOADING METHODS
    # ========================================================================

    def load_from_file(self, filepath: Union[str, Path]) -> Dict[str, Any]:
        """
        Load configuration from YAML file.

        Args:
            filepath: Path to configuration file

        Returns:
            Configuration dictionary

        Raises:
            FileNotFoundError: If file not found
            ValueError: If file format invalid
        """
        filepath = Path(filepath)

        if not filepath.exists():
            raise FileNotFoundError(f"Configuration file not found: {filepath}")

        # Check cache
        cache_key = f"file_{filepath}"
        if self.use_cache and cache_key in self._cache:
            self.logger.debug(f"Loading cached config from {filepath}")
            return self._cache[cache_key]

        # Load file
        if filepath.suffix in (".yaml", ".yml"):
            if not YAML_AVAILABLE:
                raise ImportError("PyYAML not installed. Install with: pip install pyyaml")
            config = self._load_yaml(filepath)
        elif filepath.suffix == ".json":
            config = self._load_json(filepath)
        else:
            raise ValueError(f"Unsupported file format: {filepath.suffix}")

        # Cache and return
        if self.use_cache:
            self._cache[cache_key] = config
        self._metadata = ConfigMetadata(
            source=ConfigSource.FILE,
            path=filepath,
            environment=config.get("environment"),
        )

        self.logger.info(f"Configuration loaded from {filepath}")
        return config

    def load_from_environment(self) -> Dict[str, Any]:
        """
        Load configuration from environment variables.

        Looks for variables prefixed with HYFUZZ_ (e.g., HYFUZZ_SERVER__PORT).

        Returns:
            Configuration dictionary
        """
        cache_key = "env_vars"
        if self.use_cache and cache_key in self._cache:
            return self._cache[cache_key]

        config: Dict[str, Any] = {}

        for key, value in os.environ.items():
            if not key.startswith(ENV_PREFIX):
                continue

            # Remove prefix
            key = key[len(ENV_PREFIX):]

            # Convert to nested dict
            parts = key.lower().split(ENV_SEPARATOR)
            current = config
            for part in parts[:-1]:
                if part not in current:
                    current[part] = {}
                current = current[part]

            # Set value
            current[parts[-1]] = self._convert_value(value)

        if self.use_cache:
            self._cache[cache_key] = config

        self._metadata = ConfigMetadata(source=ConfigSource.ENVIRONMENT)
        self.logger.debug(f"Loaded {len(config)} environment variables")

        return config

    def load_from_env_file(self, filepath: Optional[Path] = None) -> Dict[str, Any]:
        """
        Load configuration from .env file.

        Args:
            filepath: Path to .env file (uses default if None)

        Returns:
            Configuration dictionary
        """
        if filepath is None:
            filepath = ENV_FILE

        filepath = Path(filepath)

        # Return empty dict if .env doesn't exist
        if not filepath.exists():
            self.logger.debug(f".env file not found: {filepath}")
            return {}

        cache_key = f"env_file_{filepath}"
        if self.use_cache and cache_key in self._cache:
            return self._cache[cache_key]

        config: Dict[str, Any] = {}

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()

                    # Skip comments and empty lines
                    if not line or line.startswith("#"):
                        continue

                    # Parse KEY=VALUE
                    if "=" not in line:
                        continue

                    key, value = line.split("=", 1)
                    key = key.strip()
                    value = value.strip()

                    # Remove quotes
                    if value and value[0] in ('"', "'"):
                        value = value[1:-1]

                    # Convert to nested dict
                    parts = key.lower().split(ENV_SEPARATOR)
                    current = config
                    for part in parts[:-1]:
                        if part not in current:
                            current[part] = {}
                        current = current[part]

                    current[parts[-1]] = self._convert_value(value)

            if self.use_cache:
                self._cache[cache_key] = config

            self._metadata = ConfigMetadata(
                source=ConfigSource.ENV_FILE,
                path=filepath,
            )
            self.logger.info(f"Configuration loaded from {filepath}")

        except Exception as e:
            self.logger.error(f"Error reading .env file: {e}")
            raise

        return config

    # ========================================================================
    # MERGING AND COMBINING
    # ========================================================================

    def merge_configs(self, *configs: Dict[str, Any]) -> Dict[str, Any]:
        """
        Deep merge multiple configuration dictionaries.

        Later configs override earlier ones.

        Args:
            *configs: Configuration dictionaries to merge

        Returns:
            Merged configuration
        """
        merged: Dict[str, Any] = {}

        for config in configs:
            merged = self._deep_merge(merged, config)

        return merged

    def load_with_priority(
        self,
        file_path: Optional[Union[str, Path]] = None,
        include_env: bool = True,
        include_env_file: bool = True,
    ) -> Dict[str, Any]:
        """
        Load configuration from multiple sources with priority.

        Priority (highest to lowest):
        1. Environment variables
        2. .env file
        3. Configuration file
        4. Defaults

        Args:
            file_path: Configuration file path
            include_env: Include environment variables
            include_env_file: Include .env file

        Returns:
            Merged configuration
        """
        configs: List[Tuple[Dict[str, Any], ConfigSource]] = []

        # Load defaults
        defaults = self._get_defaults()
        configs.append((defaults, ConfigSource.DEFAULTS))

        # Load file
        if file_path:
            try:
                file_config = self.load_from_file(file_path)
                configs.append((file_config, ConfigSource.FILE))
            except Exception as e:
                self.logger.warning(f"Failed to load config file: {e}")

        # Load .env file
        if include_env_file:
            try:
                env_file_config = self.load_from_env_file()
                if env_file_config:
                    configs.append((env_file_config, ConfigSource.ENV_FILE))
            except Exception as e:
                self.logger.warning(f"Failed to load .env file: {e}")

        # Load environment variables
        if include_env:
            try:
                env_config = self.load_from_environment()
                if env_config:
                    configs.append((env_config, ConfigSource.ENVIRONMENT))
            except Exception as e:
                self.logger.warning(f"Failed to load environment config: {e}")

        # Merge configs in reverse order (so higher priority overrides lower)
        merged = {}
        sources = []

        for config, source in reversed(configs):
            merged = self._deep_merge(merged, config)
            sources.insert(0, source)

        self._metadata = ConfigMetadata(
            source=ConfigSource.ENVIRONMENT,
            merged_from=sources,
        )

        return merged

    # ========================================================================
    # CONFIGURATION ACCESS AND MANIPULATION
    # ========================================================================

    def get(
        self,
        config: Dict[str, Any],
        key: str,
        default: Any = None,
        type_convert: Optional[type] = None,
    ) -> Any:
        """
        Get configuration value with support for nested keys.

        Args:
            config: Configuration dictionary
            key: Key path (e.g., "server.port" or "db.connection.host")
            default: Default value if key not found
            type_convert: Type to convert value to

        Returns:
            Configuration value
        """
        parts = key.split(".")
        current = config

        for part in parts:
            if isinstance(current, dict):
                current = current.get(part)
                if current is None:
                    return default
            else:
                return default

        if type_convert and current is not None:
            try:
                return type_convert(current)
            except (ValueError, TypeError) as e:
                self.logger.warning(f"Failed to convert {key} to {type_convert}: {e}")
                return default

        return current if current is not None else default

    def set(self, config: Dict[str, Any], key: str, value: Any) -> Dict[str, Any]:
        """
        Set configuration value with support for nested keys.

        Creates intermediate dicts as needed.

        Args:
            config: Configuration dictionary (will be modified)
            key: Key path (e.g., "server.port")
            value: Value to set

        Returns:
            Modified configuration
        """
        parts = key.split(".")
        current = config

        for part in parts[:-1]:
            if part not in current:
                current[part] = {}
            current = current[part]

        current[parts[-1]] = value
        return config

    def flatten(
        self,
        config: Dict[str, Any],
        parent_key: str = "",
        separator: str = ".",
    ) -> Dict[str, Any]:
        """
        Flatten nested configuration dictionary.

        Args:
            config: Configuration dictionary
            parent_key: Parent key prefix
            separator: Separator for nested keys

        Returns:
            Flattened configuration
        """
        items: Dict[str, Any] = {}

        for key, value in config.items():
            new_key = f"{parent_key}{separator}{key}" if parent_key else key

            if isinstance(value, dict):
                items.update(self.flatten(value, new_key, separator))
            else:
                items[new_key] = value

        return items

    # ========================================================================
    # VALIDATION
    # ========================================================================

    def validate(self, config: Dict[str, Any], schema: Optional[Dict[str, Any]] = None) -> bool:
        """
        Validate configuration.

        Args:
            config: Configuration to validate
            schema: Validation schema (optional)

        Returns:
            True if valid

        Raises:
            ValueError: If validation fails
        """
        # Basic validation
        if not isinstance(config, dict):
            raise ValueError("Configuration must be a dictionary")

        # Check required keys
        required_keys = ["server"]
        for key in required_keys:
            if key not in config:
                raise ValueError(f"Missing required config key: {key}")

        # Server config validation
        server_config = config.get("server", {})
        if "port" in server_config:
            port = server_config["port"]
            if not isinstance(port, int) or not (0 < port < 65536):
                raise ValueError(f"Invalid server port: {port}")

        self.logger.debug("Configuration validation passed")
        return True

    # ========================================================================
    # PRIVATE METHODS
    # ========================================================================

    def _load_yaml(self, filepath: Path) -> Dict[str, Any]:
        """Load YAML configuration file"""
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                config = yaml.safe_load(f)
                if config is None:
                    return {}
                return config
        except Exception as e:
            self.logger.error(f"Error loading YAML: {e}")
            raise

    def _load_json(self, filepath: Path) -> Dict[str, Any]:
        """Load JSON configuration file"""
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            self.logger.error(f"Error loading JSON: {e}")
            raise

    def _deep_merge(
        self,
        base: Dict[str, Any],
        override: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Deep merge override into base.

        Override values take precedence.
        """
        result = deepcopy(base)

        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value

        return result

    def _convert_value(self, value: str) -> Any:
        """
        Convert string value to appropriate type.

        Handles: bool, int, float, list, dict
        """
        if isinstance(value, str):
            # Boolean
            if value.lower() in ("true", "yes", "1", "on"):
                return True
            if value.lower() in ("false", "no", "0", "off"):
                return False

            # Integer
            try:
                if "." not in value:
                    return int(value)
            except ValueError:
                pass

            # Float
            try:
                return float(value)
            except ValueError:
                pass

            # List (comma-separated)
            if "," in value:
                return [v.strip() for v in value.split(",")]

        return value

    def _get_defaults(self) -> Dict[str, Any]:
        """Get default configuration"""
        return {
            "server": {
                "host": "0.0.0.0",
                "port": 5000,
                "debug": False,
                "workers": 1,
            },
            "environment": "development",
            "logging": {
                "level": "INFO",
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            },
            "transport": {
                "type": "stdio",
                "enabled": True,
            },
            "llm": {
                "provider": "ollama",
                "base_url": "http://localhost:11434",
                "model": "mistral",
                "temperature": 0.7,
            },
            "knowledge": {
                "cache_enabled": True,
                "cache_size": 1000,
            },
        }

    # ========================================================================
    # CACHE MANAGEMENT
    # ========================================================================

    def clear_cache(self) -> None:
        """Clear configuration cache"""
        self._cache.clear()
        self.logger.debug("Configuration cache cleared")

    def get_metadata(self) -> Optional[ConfigMetadata]:
        """Get configuration metadata"""
        return self._metadata

    def get_cache_info(self) -> Dict[str, Any]:
        """Get cache information"""
        return {
            "enabled": self.use_cache,
            "entries": len(self._cache),
            "keys": list(self._cache.keys()),
        }


# ==============================================================================
# CONVENIENCE FUNCTIONS
# ==============================================================================

def load_config(
    config_path: Optional[Union[str, Path]] = None,
    use_env: bool = True,
    use_env_file: bool = True,
) -> Dict[str, Any]:
    """
    Load configuration with priority handling.

    Args:
        config_path: Configuration file path
        use_env: Include environment variables
        use_env_file: Include .env file

    Returns:
        Merged configuration
    """
    loader = ConfigLoader()
    return loader.load_with_priority(
        file_path=config_path,
        include_env=use_env,
        include_env_file=use_env_file,
    )


def load_yaml_config(filepath: Union[str, Path]) -> Dict[str, Any]:
    """Load YAML configuration file"""
    loader = ConfigLoader()
    return loader.load_from_file(filepath)


def load_env_config() -> Dict[str, Any]:
    """Load environment variable configuration"""
    loader = ConfigLoader()
    return loader.load_from_environment()


def get_config_value(
    config: Dict[str, Any],
    key: str,
    default: Any = None,
) -> Any:
    """Get configuration value with nested key support"""
    loader = ConfigLoader()
    return loader.get(config, key, default)


# ==============================================================================
# MODULE INITIALIZATION
# ==============================================================================

logger.debug("Configuration loader module loaded")