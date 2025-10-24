# ==============================================================================
# HyFuzz Server - Windows MCP Server Setup Configuration
# ==============================================================================
# This file configures the package for distribution and installation
# Usage: python setup.py install
#        or: pip install -e .
# ==============================================================================

from setuptools import setup, find_packages  # type: ignore
from pathlib import Path
from typing import List

# Get the project root directory
PROJECT_ROOT: Path = Path(__file__).resolve().parent


# Read long description from README
def read_file(filename: str) -> str:
    """
    Read file content safely.

    Args:
        filename: Path to file relative to project root

    Returns:
        File content as string, or empty string if file not found
    """
    try:
        with open(PROJECT_ROOT / filename, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return ""


# Read version from package __init__.py
def get_version() -> str:
    """
    Extract version from package __init__.py.

    Returns:
        Version string in format X.Y.Z
    """
    version_file = PROJECT_ROOT / "src" / "__init__.py"
    try:
        with open(version_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("__version__"):
                    # Parse: __version__ = "1.0.0"
                    return line.split('"')[1]
    except FileNotFoundError:
        pass
    return "1.0.0"  # Default version if not found


# Read requirements from requirements.txt
def read_requirements(filename: str) -> List[str]:
    """
    Parse requirements from file, excluding comments and empty lines.

    Args:
        filename: Path to requirements file

    Returns:
        List of requirement strings
    """
    requirements: List[str] = []
    try:
        with open(PROJECT_ROOT / filename, "r", encoding="utf-8") as f:
            for line in f:
                # Strip whitespace
                line = line.strip()
                # Skip comments and empty lines
                if line and not line.startswith("#"):
                    requirements.append(line)
    except FileNotFoundError:
        pass
    return requirements


# Configure setup parameters
setup(
    # ==================================================================
    # BASIC PROJECT METADATA
    # ==================================================================
    name="hyfuzz-server",
    version=get_version(),
    description="HyFuzz Server - Hybrid AI-Enhanced Vulnerability Detection Framework (Windows MCP Server)",
    long_description=read_file("README.md"),
    long_description_content_type="text/markdown",

    # ==================================================================
    # AUTHOR AND PROJECT INFORMATION
    # ==================================================================
    author="HyFuzz Contributors",
    author_email="support@hyfuzz.ai",
    maintainer="HyFuzz Development Team",
    maintainer_email="dev@hyfuzz.ai",
    url="https://github.com/your-org/hyfuzz-server-windows",
    project_urls={
        "Bug Tracker": "https://github.com/your-org/hyfuzz-server-windows/issues",
        "Documentation": "https://github.com/your-org/hyfuzz-server-windows/tree/main/docs",
        "Source Code": "https://github.com/your-org/hyfuzz-server-windows",
        "Changelog": "https://github.com/your-org/hyfuzz-server-windows/releases",
    },

    # ==================================================================
    # LICENSE AND LEGAL
    # ==================================================================
    license="MIT",

    # ==================================================================
    # CLASSIFIERS
    # ==================================================================
    classifiers=[
        # Development status
        "Development Status :: 4 - Beta",

        # License
        "License :: OSI Approved :: MIT License",

        # Programming languages
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",

        # Operating systems
        "Operating System :: Microsoft :: Windows",
        "Operating System :: Microsoft :: Windows :: Windows 10",
        "Operating System :: Microsoft :: Windows :: Windows 11",

        # Topics
        "Topic :: Security",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development",
        "Topic :: Software Development :: Libraries",
        "Topic :: Software Development :: Libraries :: Application Frameworks",
        "Topic :: System :: Networking",
        "Topic :: Internet",

        # Intended audience
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Telecommunications Industry",

        # Environment
        "Environment :: No Input/Output (Daemon)",
        "Environment :: Win32 (MS Windows)",

        # Typing
        "Typing :: Typed",
    ],

    # ==================================================================
    # KEYWORDS
    # ==================================================================
    keywords=[
        "security",
        "vulnerability",
        "fuzzing",
        "llm",
        "ai",
        "detection",
        "exploit",
        "cot",
        "coap",
        "modbus",
        "mcp",
    ],

    # ==================================================================
    # PYTHON REQUIREMENTS
    # ==================================================================
    python_requires=">=3.9,<4.0",

    # ==================================================================
    # PACKAGE DISCOVERY
    # ==================================================================
    # Find all packages under src directory
    packages=find_packages(
        where="src",
        include=["*"],
        exclude=["tests", "tests.*"],
    ),

    # Package data root - maps packages to source directory
    package_dir={"": "src"},

    # ==================================================================
    # PACKAGE DATA
    # ==================================================================
    package_data={
        "": [
            "config/*.yaml",
            "config/.env.template",
            "data/*.json",
        ],
    },

    # Include non-Python files from MANIFEST.in
    include_package_data=True,

    # ==================================================================
    # DATA FILES
    # ==================================================================
    data_files=[
        ("config", [
            "config/default_config.yaml",
            "config/logging_config.yaml",
            "config/example_configs/config_dev.yaml",
            "config/example_configs/config_prod.yaml",
            "config/example_configs/config_test.yaml",
        ]),
        ("data", [
            "data/sample_cwe.json",
            "data/sample_cve.json",
        ]),
        ("docs", [
            "docs/README.md",
            "docs/SETUP.md",
            "docs/API.md",
            "docs/ARCHITECTURE.md",
            "docs/LLM_INTEGRATION.md",
            "docs/TROUBLESHOOTING.md",
        ]),
    ],

    # ==================================================================
    # DEPENDENCIES (修复版本兼容性问题)
    # ==================================================================
    install_requires=[
        # Core dependencies with flexible versioning
        "aiohttp>=3.9.0,<4.0.0",
        "starlette>=0.35.0,<1.0.0",
        "requests>=2.31.0,<3.0.0",
        "pydantic>=2.5.0,<3.0.0",
        "pydantic-settings>=2.1.0,<3.0.0",
        "typing-extensions>=4.9.0",
        "python-dotenv>=1.0.0",
        "pyyaml>=6.0.1",
        "ollama>=0.1.0",
    ],

    # ==================================================================
    # OPTIONAL DEPENDENCIES (Extra Features) - 修复安全漏洞
    # ==================================================================
    extras_require={
        # Development and testing dependencies
        "dev": [
            "pytest>=7.4.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.1.0",
            "black>=23.0.0",
            "isort>=5.12.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
            "pre-commit>=3.0.0",
        ],

        # Optional: GPU acceleration
        "gpu": [
            "torch>=2.1.0",
            "faiss-gpu>=1.7.4",
        ],

        # Optional: Advanced monitoring (修复 CVE-2024-40847)
        "monitoring": [
            "sentry-sdk>=1.43.0",  # 升级到安全版本
            "datadog>=0.47.0",
        ],

        # Optional: Distributed processing
        "distributed": [
            "celery>=5.3.4",
            "kombu>=5.3.4",
        ],

        # All optional features
        "all": [
            "torch>=2.1.0",
            "faiss-gpu>=1.7.4",
            "sentry-sdk>=1.43.0",
            "datadog>=0.47.0",
            "celery>=5.3.4",
            "kombu>=5.3.4",
            "pytest>=7.4.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.1.0",
        ],
    },

    # ==================================================================
    # ENTRY POINTS (修复路径引用)
    # ==================================================================
    entry_points={
        "console_scripts": [
            # Main server startup command
            "hyfuzz-server=mcp_server.server:main",

            # Health check command
            "hyfuzz-health=scripts.health_check:main",

            # Setup command
            "hyfuzz-setup=scripts.setup_env:main",

            # Testing command
            "hyfuzz-test=scripts.test_mcp:main",
        ],
    },

    # ==================================================================
    # BUILD OPTIONS
    # ==================================================================
    # Zip_safe: Whether the package can be safely installed as a zipped egg
    zip_safe=False,

    # ==================================================================
    # SETUPTOOLS OPTIONS
    # ==================================================================
    options={
        "bdist_wheel": {
            "universal": False,  # Not universal (Windows only)
        },
    },
)

# ==============================================================================
# ADDITIONAL SETUP INFORMATION
# ==============================================================================
"""
Installation and Distribution Guide:

LOCAL INSTALLATION:
-------------------
1. Development mode (editable install):
   pip install -e .

2. With development tools:
   pip install -e ".[dev]"

3. With GPU support:
   pip install -e ".[gpu]"

4. With all optional features:
   pip install -e ".[all]"


BUILDING DISTRIBUTIONS:
-----------------------
1. Build source distribution:
   python setup.py sdist

2. Build wheel distribution:
   python setup.py bdist_wheel

3. Using build module (recommended):
   pip install build
   python -m build


TROUBLESHOOTING:
----------------
1. "未解析的引用" errors in IDE:
   - These are IDE warnings, not actual errors
   - Solution: pip install setuptools
   - Or: Configure IDE Python interpreter

2. Module import errors:
   - Ensure all __init__.py files exist in packages
   - Verify src/ structure matches setup.py configuration

3. Entry points not working:
   - Reinstall: pip install -e . --force-reinstall
   - Check function exists: python -c "from mcp_server.server import main"


KEY CHANGES IN THIS VERSION:
----------------------------
✓ Fixed 'find_packages()' include pattern to match actual package names
✓ Updated entry_points to use correct module paths (removed 'src.' prefix)
✓ Fixed dependency version constraints for compatibility
✓ Updated sentry-sdk from 1.39.1 to 1.43.0 (fixes CVE-2024-40847)
✓ Added type hints for better IDE support
✓ Improved package_data configuration
✓ Python 3.12 support added
✓ Better documentation

PACKAGE STRUCTURE:
------------------
Expected directory layout for this setup.py:

hyfuzz-server-windows/
├── src/
│   ├── __init__.py
│   ├── __main__.py
│   ├── mcp_server/
│   │   ├── __init__.py
│   │   ├── server.py
│   │   └── ...
│   ├── llm/
│   │   ├── __init__.py
│   │   └── ...
│   ├── knowledge/
│   │   ├── __init__.py
│   │   └── ...
│   ├── models/
│   ├── config/
│   ├── utils/
│   └── api/
├── tests/
├── config/
├── data/
├── docs/
├── scripts/
├── setup.py
├── README.md
├── requirements.txt
└── requirements-dev.txt
"""

# ==============================================================================
# END OF SETUP.PY
# ==============================================================================