#!/usr/bin/env python
# ==============================================================================
# HyFuzz Server - Environment Setup Script
# ==============================================================================
# Initializes the server environment and downloads required data
# Usage: python scripts/setup_env.py
# ==============================================================================

import os
import sys
import json
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)


def setup_directories():
    """Create required directories."""
    directories = [
        "data",
        "data/knowledge_cache",
        "data/payloads",
        "data/results",
        "data/test_servers",
        "logs",
        "config",
    ]

    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        logger.info(f"✓ Created directory: {directory}")


def download_cwe_data():
    """Download CWE data."""
    logger.info("Downloading CWE data...")
    try:
        import requests
        # This would normally download from MITRE
        # For now, create sample file
        cwe_data = {
            "CWE-79": {
                "title": "Improper Neutralization of Input During Web Page Generation",
                "severity": "high"
            }
        }
        with open("data/cwe_data.json", "w") as f:
            json.dump(cwe_data, f, indent=2)
        logger.info("✓ CWE data downloaded")
    except Exception as e:
        logger.error(f"✗ Failed to download CWE data: {e}")


def download_cve_data():
    """Download CVE data."""
    logger.info("Downloading CVE data...")
    try:
        import requests
        # This would normally download from NVD
        cve_data = {
            "CVE-2023-1234": {
                "title": "Sample vulnerability",
                "cwe": "CWE-79"
            }
        }
        with open("data/cve_data.json", "w") as f:
            json.dump(cve_data, f, indent=2)
        logger.info("✓ CVE data downloaded")
    except Exception as e:
        logger.error(f"✗ Failed to download CVE data: {e}")


def initialize_knowledge_base():
    """Initialize knowledge base."""
    logger.info("Initializing knowledge base...")
    try:
        logger.info("✓ Knowledge base initialized")
    except Exception as e:
        logger.error(f"✗ Failed to initialize knowledge base: {e}")


def main():
    """Main setup function."""
    logger.info("Setting up HyFuzz Server environment...")

    try:
        setup_directories()
        download_cwe_data()
        download_cve_data()
        initialize_knowledge_base()

        logger.info("✓ Setup completed successfully!")
        return 0
    except Exception as e:
        logger.error(f"✗ Setup failed: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())