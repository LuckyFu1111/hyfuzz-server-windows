"""
Capability Manager Module for HyFuzz MCP Server

This module provides capability management for MCP server features:
- Capability registration and discovery
- Feature enable/disable control
- Dependency management
- Version tracking
- Usage statistics and monitoring
- Capability validation and constraints
"""

import logging
from typing import Optional, Dict, List, Any, Set, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
from datetime import datetime
import json


# ============================================================================
# Enums and Data Structures
# ============================================================================

class CapabilityStatus(Enum):
    """Status of a capability"""
    AVAILABLE = "available"
    ENABLED = "enabled"
    DISABLED = "disabled"
    DEPRECATED = "deprecated"
    EXPERIMENTAL = "experimental"
    MAINTENANCE = "maintenance"


class CapabilityLevel(Enum):
    """Capability importance levels"""
    CORE = "core"  # Essential functionality
    STANDARD = "standard"  # Regular functionality
    EXTENDED = "extended"  # Additional functionality
    OPTIONAL = "optional"  # Optional features
    EXPERIMENTAL = "experimental"  # Experimental features


@dataclass
class Capability:
    """Represents a single capability"""
    name: str
    version: str = "1.0.0"
    status: CapabilityStatus = CapabilityStatus.AVAILABLE
    level: CapabilityLevel = CapabilityLevel.STANDARD
    description: str = ""
    enabled: bool = True
    dependencies: List[str] = field(default_factory=list)
    requirements: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    usage_count: int = 0
    last_used: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data['status'] = self.status.value
        data['level'] = self.level.value
        data['created_at'] = self.created_at.isoformat()
        data['updated_at'] = self.updated_at.isoformat()
        data['last_used'] = self.last_used.isoformat() if self.last_used else None
        return data

    def is_available(self) -> bool:
        """Check if capability is available for use"""
        return self.enabled and self.status != CapabilityStatus.DISABLED

    def get_dependency_chain(self) -> List[str]:
        """Get all direct dependencies"""
        return self.dependencies.copy()


@dataclass
class CapabilityRequirement:
    """Requirement for a capability"""
    name: str
    version: Optional[str] = None
    min_version: Optional[str] = None
    max_version: Optional[str] = None
    optional: bool = False
    description: str = ""


@dataclass
class CapabilityStats:
    """Statistics for capability usage"""
    total_capabilities: int = 0
    enabled_capabilities: int = 0
    disabled_capabilities: int = 0
    deprecated_capabilities: int = 0
    core_capabilities: int = 0
    total_usage: int = 0
    last_updated: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)


# ============================================================================
# Version Comparison Utilities
# ============================================================================

class VersionUtils:
    """Utility functions for version comparison"""

    @staticmethod
    def parse_version(version: str) -> Tuple[int, int, int]:
        """
        Parse semantic version string to tuple

        Args:
            version: Version string (e.g., "1.2.3")

        Returns:
            Tuple of (major, minor, patch)
        """
        try:
            parts = version.split('.')
            return (
                int(parts[0]) if len(parts) > 0 else 0,
                int(parts[1]) if len(parts) > 1 else 0,
                int(parts[2]) if len(parts) > 2 else 0,
            )
        except (ValueError, IndexError):
            return (0, 0, 0)

    @staticmethod
    def compare_versions(v1: str, v2: str) -> int:
        """
        Compare two semantic versions

        Args:
            v1: First version
            v2: Second version

        Returns:
            -1 if v1 < v2, 0 if equal, 1 if v1 > v2
        """
        ver1 = VersionUtils.parse_version(v1)
        ver2 = VersionUtils.parse_version(v2)

        if ver1 < ver2:
            return -1
        elif ver1 > ver2:
            return 1
        return 0

    @staticmethod
    def is_compatible(required: str, actual: str) -> bool:
        """Check if actual version meets requirement"""
        return VersionUtils.compare_versions(actual, required) >= 0

    @staticmethod
    def is_version_in_range(
        version: str,
        min_version: Optional[str] = None,
        max_version: Optional[str] = None
    ) -> bool:
        """Check if version is within range"""
        if min_version and VersionUtils.compare_versions(version, min_version) < 0:
            return False
        if max_version and VersionUtils.compare_versions(version, max_version) > 0:
            return False
        return True


# ============================================================================
# Capability Manager
# ============================================================================

class CapabilityManager:
    """
    Main capability manager for MCP server.

    Features:
    - Register and discover capabilities
    - Enable/disable capabilities
    - Manage dependencies
    - Track usage statistics
    - Version management
    - Constraint validation
    """

    def __init__(self):
        self.capabilities: Dict[str, Capability] = {}
        self.logger = logging.getLogger(__name__)
        self.stats = CapabilityStats()
        self._initialize_default_capabilities()

    def _initialize_default_capabilities(self) -> None:
        """Initialize core capabilities"""

        # Core message handling capability
        self.register(Capability(
            name="message_handling",
            version="1.0.0",
            status=CapabilityStatus.AVAILABLE,
            level=CapabilityLevel.CORE,
            description="Core message handling and routing",
            enabled=True
        ))

        # Session management capability
        self.register(Capability(
            name="session_management",
            version="1.0.0",
            status=CapabilityStatus.AVAILABLE,
            level=CapabilityLevel.CORE,
            description="Session creation and management",
            enabled=True,
            dependencies=["message_handling"]
        ))

        # LLM integration capability
        self.register(Capability(
            name="llm_integration",
            version="1.0.0",
            status=CapabilityStatus.AVAILABLE,
            level=CapabilityLevel.STANDARD,
            description="LLM service integration",
            enabled=True,
            dependencies=["message_handling"]
        ))

        # Knowledge base capability
        self.register(Capability(
            name="knowledge_base",
            version="1.0.0",
            status=CapabilityStatus.AVAILABLE,
            level=CapabilityLevel.STANDARD,
            description="Knowledge base access and querying",
            enabled=True,
            dependencies=["message_handling"]
        ))

        # Caching capability
        self.register(Capability(
            name="caching",
            version="1.0.0",
            status=CapabilityStatus.AVAILABLE,
            level=CapabilityLevel.EXTENDED,
            description="Response and data caching",
            enabled=True
        ))

        # Logging and monitoring capability
        self.register(Capability(
            name="logging",
            version="1.0.0",
            status=CapabilityStatus.AVAILABLE,
            level=CapabilityLevel.CORE,
            description="Logging and monitoring",
            enabled=True
        ))

    def register(self, capability: Capability) -> bool:
        """
        Register a new capability

        Args:
            capability: Capability to register

        Returns:
            True if successful
        """
        if capability.name in self.capabilities:
            self.logger.warning(f"Capability already exists: {capability.name}")
            return False

        self.capabilities[capability.name] = capability
        self._update_stats()
        self.logger.debug(f"Registered capability: {capability.name} v{capability.version}")
        return True

    def unregister(self, name: str) -> bool:
        """Unregister a capability"""
        if name not in self.capabilities:
            return False

        del self.capabilities[name]
        self._update_stats()
        self.logger.debug(f"Unregistered capability: {name}")
        return True

    def enable(self, name: str) -> bool:
        """
        Enable a capability

        Args:
            name: Capability name

        Returns:
            True if successful
        """
        if name not in self.capabilities:
            self.logger.error(f"Capability not found: {name}")
            return False

        capability = self.capabilities[name]

        # Check dependencies
        if not self._check_dependencies_enabled(capability):
            self.logger.error(f"Cannot enable {name}: dependencies not met")
            return False

        capability.enabled = True
        capability.status = CapabilityStatus.ENABLED
        capability.updated_at = datetime.now()

        self._update_stats()
        self.logger.info(f"Enabled capability: {name}")
        return True

    def disable(self, name: str) -> bool:
        """Disable a capability"""
        if name not in self.capabilities:
            return False

        capability = self.capabilities[name]

        # Check if other capabilities depend on this
        dependents = self._get_dependent_capabilities(name)
        if dependents and any(self.capabilities[d].enabled for d in dependents):
            self.logger.warning(
                f"Cannot disable {name}: other capabilities depend on it"
            )
            return False

        capability.enabled = False
        capability.status = CapabilityStatus.DISABLED
        capability.updated_at = datetime.now()

        self._update_stats()
        self.logger.info(f"Disabled capability: {name}")
        return True

    def get(self, name: str) -> Optional[Capability]:
        """Get capability by name"""
        return self.capabilities.get(name)

    def list_capabilities(
        self,
        enabled_only: bool = False,
        level: Optional[CapabilityLevel] = None,
        status: Optional[CapabilityStatus] = None
    ) -> List[Capability]:
        """
        List capabilities with optional filtering

        Args:
            enabled_only: Only return enabled capabilities
            level: Filter by capability level
            status: Filter by capability status

        Returns:
            List of capabilities matching filters
        """
        result = []

        for capability in self.capabilities.values():
            if enabled_only and not capability.enabled:
                continue
            if level and capability.level != level:
                continue
            if status and capability.status != status:
                continue

            result.append(capability)

        return result

    def check_capability(self, name: str) -> bool:
        """
        Check if capability is available (registered and enabled)

        Args:
            name: Capability name

        Returns:
            True if available
        """
        capability = self.get(name)
        return capability is not None and capability.is_available()

    def check_capabilities(self, names: List[str]) -> Tuple[bool, List[str]]:
        """
        Check if all capabilities in list are available

        Args:
            names: List of capability names

        Returns:
            (all_available, unavailable_list)
        """
        unavailable = []

        for name in names:
            if not self.check_capability(name):
                unavailable.append(name)

        return len(unavailable) == 0, unavailable

    def record_usage(self, name: str) -> bool:
        """
        Record capability usage

        Args:
            name: Capability name

        Returns:
            True if recorded
        """
        capability = self.get(name)
        if not capability:
            return False

        capability.usage_count += 1
        capability.last_used = datetime.now()
        self.stats.total_usage += 1

        return True

    def get_capability_info(self, name: str) -> Optional[Dict[str, Any]]:
        """Get capability information as dictionary"""
        capability = self.get(name)
        if not capability:
            return None

        return capability.to_dict()

    def get_all_capabilities_info(self) -> Dict[str, Any]:
        """Get all capabilities information"""
        return {
            name: capability.to_dict()
            for name, capability in self.capabilities.items()
        }

    def _check_dependencies_enabled(self, capability: Capability) -> bool:
        """Check if all dependencies are enabled"""
        for dep_name in capability.dependencies:
            dep = self.get(dep_name)
            if not dep or not dep.enabled:
                return False

        return True

    def _get_dependent_capabilities(self, name: str) -> List[str]:
        """Get capabilities that depend on this one"""
        dependents = []

        for cap_name, capability in self.capabilities.items():
            if name in capability.dependencies:
                dependents.append(cap_name)

        return dependents

    def _update_stats(self) -> None:
        """Update capability statistics"""
        self.stats.total_capabilities = len(self.capabilities)
        self.stats.enabled_capabilities = sum(
            1 for cap in self.capabilities.values() if cap.enabled
        )
        self.stats.disabled_capabilities = sum(
            1 for cap in self.capabilities.values() if not cap.enabled
        )
        self.stats.deprecated_capabilities = sum(
            1 for cap in self.capabilities.values()
            if cap.status == CapabilityStatus.DEPRECATED
        )
        self.stats.core_capabilities = sum(
            1 for cap in self.capabilities.values()
            if cap.level == CapabilityLevel.CORE
        )
        self.stats.last_updated = datetime.now()

    def get_statistics(self) -> Dict[str, Any]:
        """Get capability statistics"""
        return self.stats.to_dict()

    def validate_version_requirement(
        self,
        name: str,
        required_version: str
    ) -> bool:
        """
        Validate if capability version meets requirement

        Args:
            name: Capability name
            required_version: Required version

        Returns:
            True if version is compatible
        """
        capability = self.get(name)
        if not capability:
            return False

        return VersionUtils.is_compatible(required_version, capability.version)

    def export_capabilities(self) -> str:
        """Export all capabilities as JSON"""
        data = self.get_all_capabilities_info()
        return json.dumps(data, indent=2, default=str)

    def import_capabilities(self, json_str: str) -> bool:
        """
        Import capabilities from JSON

        Args:
            json_str: JSON string with capabilities

        Returns:
            True if import successful
        """
        try:
            data = json.loads(json_str)

            for cap_name, cap_data in data.items():
                # Reconstruct capability from data
                cap = Capability(
                    name=cap_data.get('name', cap_name),
                    version=cap_data.get('version', '1.0.0'),
                    status=CapabilityStatus(cap_data.get('status', 'available')),
                    level=CapabilityLevel(cap_data.get('level', 'standard')),
                    description=cap_data.get('description', ''),
                    enabled=cap_data.get('enabled', True),
                    dependencies=cap_data.get('dependencies', []),
                )

                self.register(cap)

            return True

        except Exception as e:
            self.logger.error(f"Failed to import capabilities: {str(e)}")
            return False

    def get_dependency_graph(self, name: str) -> Dict[str, List[str]]:
        """
        Get dependency graph for a capability

        Args:
            name: Capability name

        Returns:
            Dictionary representing dependency graph
        """
        capability = self.get(name)
        if not capability:
            return {}

        graph = {name: capability.dependencies}

        # Recursively add dependencies
        for dep_name in capability.dependencies:
            dep_graph = self.get_dependency_graph(dep_name)
            graph.update(dep_graph)

        return graph

    def get_summary(self) -> Dict[str, Any]:
        """Get summary of capabilities"""
        return {
            "total": self.stats.total_capabilities,
            "enabled": self.stats.enabled_capabilities,
            "disabled": self.stats.disabled_capabilities,
            "core": self.stats.core_capabilities,
            "deprecated": self.stats.deprecated_capabilities,
            "usage": self.stats.total_usage,
            "capabilities": [
                {
                    "name": name,
                    "version": cap.version,
                    "status": cap.status.value,
                    "enabled": cap.enabled
                }
                for name, cap in self.capabilities.items()
            ]
        }


# ============================================================================
# TESTING SECTION
# ============================================================================

def run_tests():
    """Comprehensive test suite for capability manager"""

    print("\n" + "="*80)
    print("CAPABILITY MANAGER COMPREHENSIVE TEST SUITE")
    print("="*80 + "\n")

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    manager = CapabilityManager()

    # Test 1: Default Capabilities
    print("[TEST 1] Default Capabilities")
    print("-" * 80)
    capabilities = manager.list_capabilities()
    print(f"✓ Loaded {len(capabilities)} default capabilities")
    for cap in capabilities:
        print(f"  - {cap.name} v{cap.version} ({cap.level.value})")
    assert len(capabilities) > 0, "Should have default capabilities"
    print()

    # Test 2: Check Capability Status
    print("[TEST 2] Check Capability Status")
    print("-" * 80)
    available = manager.check_capability("message_handling")
    assert available, "message_handling should be available"
    print(f"✓ message_handling is available: {available}")

    available = manager.check_capability("nonexistent")
    assert not available, "nonexistent should not be available"
    print(f"✓ nonexistent is available: {available}")
    print()

    # Test 3: Enable/Disable Capabilities
    print("[TEST 3] Enable/Disable Capabilities")
    print("-" * 80)
    success = manager.disable("caching")
    assert success, "Should disable caching"
    print(f"✓ Disabled caching capability")

    available = manager.check_capability("caching")
    assert not available, "caching should be disabled"
    print(f"✓ caching is now unavailable")

    success = manager.enable("caching")
    assert success, "Should enable caching"
    print(f"✓ Re-enabled caching capability")
    print()

    # Test 4: Register New Capability
    print("[TEST 4] Register New Capability")
    print("-" * 80)
    new_cap = Capability(
        name="custom_feature",
        version="1.0.0",
        description="Custom test feature",
        level=CapabilityLevel.OPTIONAL
    )
    success = manager.register(new_cap)
    assert success, "Should register new capability"
    print(f"✓ Registered new capability: custom_feature")

    retrieved = manager.get("custom_feature")
    assert retrieved is not None, "Should retrieve registered capability"
    print(f"✓ Retrieved capability: {retrieved.name}")
    print()

    # Test 5: List Capabilities with Filters
    print("[TEST 5] List Capabilities with Filters")
    print("-" * 80)
    core_caps = manager.list_capabilities(level=CapabilityLevel.CORE)
    print(f"✓ Core capabilities: {len(core_caps)}")
    for cap in core_caps:
        print(f"  - {cap.name}")

    optional_caps = manager.list_capabilities(level=CapabilityLevel.OPTIONAL)
    print(f"✓ Optional capabilities: {len(optional_caps)}")
    print()

    # Test 6: Check Multiple Capabilities
    print("[TEST 6] Check Multiple Capabilities")
    print("-" * 80)
    required = ["message_handling", "session_management", "logging"]
    all_available, unavailable = manager.check_capabilities(required)
    assert all_available, "All required capabilities should be available"
    print(f"✓ All required capabilities available: {all_available}")

    required_with_missing = ["message_handling", "nonexistent"]
    all_available, unavailable = manager.check_capabilities(required_with_missing)
    assert not all_available, "Should have missing capability"
    assert "nonexistent" in unavailable, "Should identify missing capability"
    print(f"✓ Correctly identified missing: {unavailable}")
    print()

    # Test 7: Usage Tracking
    print("[TEST 7] Usage Tracking")
    print("-" * 80)
    manager.record_usage("message_handling")
    manager.record_usage("message_handling")
    manager.record_usage("llm_integration")

    cap = manager.get("message_handling")
    assert cap.usage_count == 2, "Should track usage count"
    print(f"✓ message_handling usage count: {cap.usage_count}")

    stats = manager.get_statistics()
    assert stats['total_usage'] >= 3, "Should track total usage"
    print(f"✓ Total usage tracked: {stats['total_usage']}")
    print()

    # Test 8: Version Comparison
    print("[TEST 8] Version Comparison")
    print("-" * 80)
    assert VersionUtils.compare_versions("1.0.0", "2.0.0") < 0
    assert VersionUtils.compare_versions("2.0.0", "1.0.0") > 0
    assert VersionUtils.compare_versions("1.0.0", "1.0.0") == 0
    print(f"✓ Version comparison working correctly")

    compatible = VersionUtils.is_compatible("1.0.0", "1.5.0")
    assert compatible, "1.5.0 should meet 1.0.0 requirement"
    print(f"✓ Version compatibility check working")
    print()

    # Test 9: Dependency Management
    print("[TEST 9] Dependency Management")
    print("-" * 80)
    llm_cap = manager.get("llm_integration")
    deps = llm_cap.get_dependency_chain()
    print(f"✓ llm_integration depends on: {deps}")

    dep_graph = manager.get_dependency_graph("llm_integration")
    print(f"✓ Dependency graph: {dep_graph}")
    print()

    # Test 10: Statistics
    print("[TEST 10] Statistics")
    print("-" * 80)
    stats = manager.get_statistics()
    print(f"✓ Capability statistics:")
    print(f"  Total: {stats['total_capabilities']}")
    print(f"  Enabled: {stats['enabled_capabilities']}")
    print(f"  Disabled: {stats['disabled_capabilities']}")
    print(f"  Core: {stats['core_capabilities']}")
    print(f"  Total usage: {stats['total_usage']}")
    print()

    # Test 11: Export/Import
    print("[TEST 11] Export/Import Capabilities")
    print("-" * 80)
    exported = manager.export_capabilities()
    assert len(exported) > 0, "Should export capabilities"
    print(f"✓ Exported {len(exported)} characters")

    # Test import
    new_manager = CapabilityManager()
    initial_count = len(new_manager.capabilities)
    success = new_manager.import_capabilities(exported)
    assert success, "Should import capabilities"
    print(f"✓ Successfully imported capabilities")
    print()

    # Test 12: Capability Info
    print("[TEST 12] Capability Information")
    print("-" * 80)
    info = manager.get_capability_info("message_handling")
    assert info is not None, "Should get capability info"
    print(f"✓ Capability info retrieved:")
    for key, value in list(info.items())[:5]:
        print(f"  {key}: {value}")
    print()

    # Test 13: Summary
    print("[TEST 13] Capability Summary")
    print("-" * 80)
    summary = manager.get_summary()
    print(f"✓ Capability summary:")
    print(f"  Total: {summary['total']}")
    print(f"  Enabled: {summary['enabled']}")
    print(f"  Core: {summary['core']}")
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
        print("Capability Manager is ready for integration!")