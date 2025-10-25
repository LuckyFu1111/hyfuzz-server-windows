"""
Ollama setup script for the MCP server.
Handles installation, configuration, model download, and verification of Ollama.
"""

import os
import sys
import json
import logging
import subprocess
import platform
import time
import socket
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime
import urllib.request
import urllib.error

logger = logging.getLogger(__name__)


# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class SetupStep:
    """Represents a setup step result."""
    name: str
    status: str  # 'success', 'warning', 'error', 'skipped'
    message: str
    details: Optional[Dict[str, Any]] = None
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()


@dataclass
class OllamaSetupResult:
    """Result of Ollama setup."""
    overall_status: str  # 'success', 'partial', 'failed'
    ollama_installed: bool
    ollama_version: Optional[str]
    ollama_running: bool
    models_available: List[str]
    steps: List[SetupStep]
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()


# ============================================================================
# COLOR CODES
# ============================================================================

class Colors:
    """ANSI color codes."""
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


# ============================================================================
# OLLAMA SETUP MANAGER
# ============================================================================

class OllamaSetupManager:
    """Manages Ollama installation and setup."""

    # Ollama configuration
    OLLAMA_VERSION = "latest"
    DEFAULT_MODELS = ["mistral", "neural-chat"]  # Lightweight models for testing
    OLLAMA_PORT = 11434
    OLLAMA_HOST = "127.0.0.1"
    OLLAMA_TIMEOUT = 30

    # URLs
    OLLAMA_DOWNLOAD_URLS = {
        "Darwin": "https://ollama.ai/download/ollama-darwin.zip",
        "Linux": "https://ollama.ai/install.sh",
        "Windows": "https://ollama.ai/download/OllamaSetup.exe",
    }

    def __init__(self, config_dir: Optional[Path] = None):
        """
        Initialize setup manager.

        Args:
            config_dir: Directory for storing configuration
        """
        self.config_dir = config_dir or Path.home() / ".ollama"
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.steps: List[SetupStep] = []

    def run_full_setup(self, skip_model_download: bool = False) -> OllamaSetupResult:
        """
        Run complete Ollama setup.

        Args:
            skip_model_download: Skip downloading models

        Returns:
            Setup result with status
        """
        print(f"\n{Colors.BLUE}{Colors.BOLD}╔════════════════════════════════════════╗{Colors.RESET}")
        print(f"{Colors.BLUE}{Colors.BOLD}║     OLLAMA SETUP FOR MCP SERVER         ║{Colors.RESET}")
        print(f"{Colors.BLUE}{Colors.BOLD}╚════════════════════════════════════════╝{Colors.RESET}\n")

        print(f"{Colors.BOLD}Step 1: Checking Ollama Installation{Colors.RESET}\n")
        installed, version = self._check_ollama_installed()

        if not installed:
            print(f"{Colors.BOLD}Step 2: Installing Ollama{Colors.RESET}\n")
            installed = self._install_ollama()

            if not installed:
                print(f"{Colors.RED}✗ Failed to install Ollama{Colors.RESET}\n")
                return self._compile_results(
                    installed, version, False, [], "failed"
                )

        print(f"{Colors.BOLD}Step 2: Starting Ollama Service{Colors.RESET}\n")
        running = self._start_ollama_service()

        print(f"{Colors.BOLD}Step 3: Configuring Ollama{Colors.RESET}\n")
        self._configure_ollama()

        print(f"{Colors.BOLD}Step 4: Verifying Installation{Colors.RESET}\n")
        verified = self._verify_ollama()

        models = []
        if not skip_model_download and installed and running:
            print(f"{Colors.BOLD}Step 5: Downloading Models{Colors.RESET}\n")
            models = self._download_models()

        # Compile results
        overall_status = "success" if verified and running else "partial"
        if not installed:
            overall_status = "failed"

        result = self._compile_results(
            installed, version, running, models, overall_status
        )

        self._print_summary(result)

        return result

    def _check_ollama_installed(self) -> Tuple[bool, Optional[str]]:
        """Check if Ollama is installed."""
        print("Checking for Ollama installation...")

        try:
            result = subprocess.run(
                ["ollama", "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0:
                version = result.stdout.strip()
                self._add_step("check_installation", "success",
                               f"Ollama found: {version}",
                               {"version": version})
                print(f"  {Colors.GREEN}✓ Ollama installed: {version}{Colors.RESET}\n")
                return True, version
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        self._add_step("check_installation", "warning",
                       "Ollama not found in PATH")
        print(f"  {Colors.YELLOW}⚠ Ollama not found in PATH{Colors.RESET}\n")
        return False, None

    def _install_ollama(self) -> bool:
        """Install Ollama."""
        print("Attempting to install Ollama...\n")

        system = platform.system()

        if system == "Windows":
            return self._install_ollama_windows()
        elif system == "Darwin":
            return self._install_ollama_macos()
        elif system == "Linux":
            return self._install_ollama_linux()
        else:
            self._add_step("install", "error",
                           f"Unsupported system: {system}")
            print(f"  {Colors.RED}✗ Unsupported system: {system}{Colors.RESET}\n")
            return False

    def _install_ollama_windows(self) -> bool:
        """Install Ollama on Windows."""
        print("Installing Ollama on Windows...\n")

        try:
            # Download installer
            print("  Downloading Ollama installer...")
            url = self.OLLAMA_DOWNLOAD_URLS["Windows"]
            installer_path = Path(self.config_dir) / "OllamaSetup.exe"

            self._download_file(url, installer_path)
            print(f"  {Colors.GREEN}✓ Downloaded to {installer_path}{Colors.RESET}")

            # Run installer
            print("  Running installer (this may take a few minutes)...")
            subprocess.run([str(installer_path)], check=True)

            self._add_step("install_windows", "success",
                           "Ollama installed via installer")
            print(f"  {Colors.GREEN}✓ Ollama installed successfully{Colors.RESET}\n")
            return True

        except Exception as e:
            self._add_step("install_windows", "error", f"Installation failed: {e}")
            print(f"  {Colors.RED}✗ Installation failed: {e}{Colors.RESET}\n")
            return False

    def _install_ollama_macos(self) -> bool:
        """Install Ollama on macOS."""
        print("Installing Ollama on macOS...\n")

        try:
            # macOS installation typically uses Homebrew or direct download
            print("  Checking for Homebrew...")
            result = subprocess.run(
                ["brew", "install", "ollama"],
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode == 0:
                self._add_step("install_macos", "success",
                               "Ollama installed via Homebrew")
                print(f"  {Colors.GREEN}✓ Ollama installed via Homebrew{Colors.RESET}\n")
                return True

        except FileNotFoundError:
            print("  Homebrew not found. Manual installation required.")
        except Exception as e:
            print(f"  Error: {e}")

        self._add_step("install_macos", "warning",
                       "Please install Ollama manually from ollama.ai")
        print(f"  {Colors.YELLOW}⚠ Please install Ollama manually from https://ollama.ai{Colors.RESET}\n")
        return False

    def _install_ollama_linux(self) -> bool:
        """Install Ollama on Linux."""
        print("Installing Ollama on Linux...\n")

        try:
            print("  Running installation script...")
            result = subprocess.run(
                ["curl", "-fsSL", "https://ollama.ai/install.sh", "|", "sh"],
                capture_output=True,
                text=True,
                timeout=120,
                shell=True
            )

            if result.returncode == 0:
                self._add_step("install_linux", "success",
                               "Ollama installed successfully")
                print(f"  {Colors.GREEN}✓ Ollama installed successfully{Colors.RESET}\n")
                return True

        except Exception as e:
            self._add_step("install_linux", "error", f"Installation failed: {e}")
            print(f"  {Colors.RED}✗ Installation failed: {e}{Colors.RESET}\n")

        return False

    def _download_file(self, url: str, destination: Path):
        """Download a file from URL."""
        try:
            urllib.request.urlretrieve(url, destination)
        except urllib.error.URLError as e:
            raise Exception(f"Failed to download from {url}: {e}")

    def _start_ollama_service(self) -> bool:
        """Start Ollama service."""
        print("Starting Ollama service...\n")

        try:
            # Check if already running
            if self._is_ollama_running():
                self._add_step("start_service", "success",
                               "Ollama service already running")
                print(f"  {Colors.GREEN}✓ Ollama service already running{Colors.RESET}\n")
                return True

            # Start service based on OS
            system = platform.system()

            if system == "Windows":
                # Windows: Start Ollama service
                subprocess.Popen(["ollama", "serve"],
                                 stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)
            elif system == "Darwin":
                # macOS: Use launchctl
                subprocess.run(["launchctl", "start", "ai.ollama.ollama"],
                               capture_output=True)
            elif system == "Linux":
                # Linux: Use systemctl or manual start
                try:
                    subprocess.run(["systemctl", "start", "ollama"],
                                   capture_output=True)
                except:
                    subprocess.Popen(["ollama", "serve"],
                                     stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL)

            # Wait for service to start
            print("  Waiting for Ollama to start...")
            for i in range(30):
                if self._is_ollama_running():
                    self._add_step("start_service", "success",
                                   "Ollama service started")
                    print(f"  {Colors.GREEN}✓ Ollama service started{Colors.RESET}\n")
                    return True
                time.sleep(1)

            self._add_step("start_service", "warning",
                           "Ollama not responding after 30 seconds")
            print(f"  {Colors.YELLOW}⚠ Ollama not responding{Colors.RESET}\n")
            return False

        except Exception as e:
            self._add_step("start_service", "error", f"Failed to start: {e}")
            print(f"  {Colors.RED}✗ Failed to start service: {e}{Colors.RESET}\n")
            return False

    def _is_ollama_running(self) -> bool:
        """Check if Ollama service is running."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.OLLAMA_HOST, self.OLLAMA_PORT))
            sock.close()
            return result == 0
        except:
            return False

    def _configure_ollama(self):
        """Configure Ollama settings."""
        print("Configuring Ollama...\n")

        try:
            config = {
                "port": self.OLLAMA_PORT,
                "host": self.OLLAMA_HOST,
                "models_dir": str(self.config_dir / "models"),
                "keep_alive": "5m",
            }

            config_file = self.config_dir / "config.json"
            with open(config_file, 'w') as f:
                json.dump(config, f, indent=2)

            self._add_step("configure", "success",
                           f"Configuration saved to {config_file}")
            print(f"  {Colors.GREEN}✓ Configuration saved{Colors.RESET}\n")

        except Exception as e:
            self._add_step("configure", "warning", f"Configuration error: {e}")
            print(f"  {Colors.YELLOW}⚠ Configuration warning: {e}{Colors.RESET}\n")

    def _verify_ollama(self) -> bool:
        """Verify Ollama installation."""
        print("Verifying Ollama installation...\n")

        try:
            # Test API endpoint
            print("  Testing API endpoint...")
            import urllib.request
            import json as json_lib

            url = f"http://{self.OLLAMA_HOST}:{self.OLLAMA_PORT}/api/tags"

            try:
                with urllib.request.urlopen(url, timeout=5) as response:
                    data = json_lib.loads(response.read())
                    self._add_step("verify", "success",
                                   "Ollama API responding")
                    print(f"  {Colors.GREEN}✓ Ollama API responding{Colors.RESET}\n")
                    return True
            except urllib.error.URLError:
                pass

            self._add_step("verify", "warning",
                           "Ollama API not responding")
            print(f"  {Colors.YELLOW}⚠ Ollama API not responding yet{Colors.RESET}\n")
            return False

        except Exception as e:
            self._add_step("verify", "error", f"Verification failed: {e}")
            print(f"  {Colors.RED}✗ Verification error: {e}{Colors.RESET}\n")
            return False

    def _download_models(self) -> List[str]:
        """Download default models."""
        print("Downloading models...\n")

        downloaded = []

        for model in self.DEFAULT_MODELS:
            try:
                print(f"  Downloading {model}...")
                result = subprocess.run(
                    ["ollama", "pull", model],
                    capture_output=True,
                    text=True,
                    timeout=300
                )

                if result.returncode == 0:
                    downloaded.append(model)
                    print(f"    {Colors.GREEN}✓ {model} downloaded{Colors.RESET}")
                else:
                    print(f"    {Colors.YELLOW}⚠ Failed to download {model}{Colors.RESET}")

            except subprocess.TimeoutExpired:
                print(f"    {Colors.YELLOW}⚠ Download timeout for {model}{Colors.RESET}")
            except Exception as e:
                print(f"    {Colors.RED}✗ Error downloading {model}: {e}{Colors.RESET}")

        if downloaded:
            self._add_step("download_models", "success",
                           f"Downloaded models: {', '.join(downloaded)}")
        else:
            self._add_step("download_models", "warning",
                           "No models downloaded")

        print()
        return downloaded

    def _add_step(self, name: str, status: str, message: str,
                  details: Optional[Dict] = None):
        """Add a setup step."""
        step = SetupStep(name, status, message, details)
        self.steps.append(step)
        logger.info(f"{name}: {status} - {message}")

    def _compile_results(self, installed: bool, version: Optional[str],
                         running: bool, models: List[str],
                         overall_status: str) -> OllamaSetupResult:
        """Compile setup results."""
        return OllamaSetupResult(
            overall_status=overall_status,
            ollama_installed=installed,
            ollama_version=version,
            ollama_running=running,
            models_available=models,
            steps=self.steps
        )

    def _print_summary(self, result: OllamaSetupResult):
        """Print setup summary."""
        status_color = Colors.GREEN if result.overall_status == "success" else \
            Colors.YELLOW if result.overall_status == "partial" else \
                Colors.RED

        print(f"{Colors.BOLD}{'=' * 50}{Colors.RESET}\n")
        print(f"{Colors.BOLD}OLLAMA SETUP SUMMARY{Colors.RESET}\n")
        print(f"Status: {status_color}{result.overall_status.upper()}{Colors.RESET}\n")

        print("Installation Status:")
        print(f"  Installed: {Colors.GREEN if result.ollama_installed else Colors.RED}" +
              f"{'Yes' if result.ollama_installed else 'No'}{Colors.RESET}")
        if result.ollama_version:
            print(f"  Version: {result.ollama_version}")
        print(f"  Running: {Colors.GREEN if result.ollama_running else Colors.YELLOW}" +
              f"{'Yes' if result.ollama_running else 'No'}{Colors.RESET}")

        if result.models_available:
            print(f"\nModels Available: {len(result.models_available)}")
            for model in result.models_available:
                print(f"  • {model}")

        print(f"\n{Colors.BOLD}{'=' * 50}{Colors.RESET}\n")


# ============================================================================
# TEST SECTION
# ============================================================================

def run_tests():
    """Run setup tests."""
    print("\n" + "=" * 70)
    print("OLLAMA SETUP TEST SUITE")
    print("=" * 70 + "\n")

    test_results = []

    # Test 1: Manager initialization
    print("Test 1: Manager Initialization")
    try:
        manager = OllamaSetupManager()
        assert manager is not None
        assert manager.config_dir.exists()
        print("✓ PASSED: Manager initialized successfully\n")
        test_results.append(True)
    except Exception as e:
        print(f"✗ FAILED: {e}\n")
        test_results.append(False)

    # Test 2: Check Ollama installed
    print("Test 2: Check Ollama Installation")
    try:
        manager = OllamaSetupManager()
        installed, version = manager._check_ollama_installed()
        print(f"  Installed: {installed}")
        if version:
            print(f"  Version: {version}")
        print("✓ PASSED: Installation check completed\n")
        test_results.append(True)
    except Exception as e:
        print(f"✗ FAILED: {e}\n")
        test_results.append(False)

    # Test 3: Check if running
    print("Test 3: Check If Ollama Running")
    try:
        manager = OllamaSetupManager()
        running = manager._is_ollama_running()
        print(f"  Running: {running}")
        print("✓ PASSED: Running check completed\n")
        test_results.append(True)
    except Exception as e:
        print(f"✗ FAILED: {e}\n")
        test_results.append(False)

    # Test 4: Platform detection
    print("Test 4: Platform Detection")
    try:
        system = platform.system()
        print(f"  System: {system}")
        assert system in ["Windows", "Darwin", "Linux"]
        print("✓ PASSED: Platform detected correctly\n")
        test_results.append(True)
    except Exception as e:
        print(f"✗ FAILED: {e}\n")
        test_results.append(False)

    # Test 5: Setup step tracking
    print("Test 5: Setup Step Tracking")
    try:
        manager = OllamaSetupManager()
        manager._add_step("test_step", "success", "Test message", {"detail": "value"})
        assert len(manager.steps) == 1
        step = manager.steps[0]
        assert step.name == "test_step"
        assert step.status == "success"
        print("✓ PASSED: Steps tracked correctly\n")
        test_results.append(True)
    except Exception as e:
        print(f"✗ FAILED: {e}\n")
        test_results.append(False)

    # Test 6: Results compilation
    print("Test 6: Results Compilation")
    try:
        manager = OllamaSetupManager()
        manager._add_step("test", "success", "test")
        result = manager._compile_results(True, "0.1.0", False, [], "partial")
        assert result.ollama_installed == True
        assert result.ollama_version == "0.1.0"
        assert result.overall_status == "partial"
        print("✓ PASSED: Results compiled correctly\n")
        test_results.append(True)
    except Exception as e:
        print(f"✗ FAILED: {e}\n")
        test_results.append(False)

    # Test 7: Configuration file creation
    print("Test 7: Configuration File Creation")
    try:
        manager = OllamaSetupManager()
        manager._configure_ollama()
        config_file = manager.config_dir / "config.json"
        assert config_file.exists()
        with open(config_file, 'r') as f:
            config = json.load(f)
        assert "port" in config
        print("✓ PASSED: Configuration file created\n")
        test_results.append(True)
    except Exception as e:
        print(f"✗ FAILED: {e}\n")
        test_results.append(False)

    # Test 8: JSON serialization
    print("Test 8: JSON Serialization")
    try:
        manager = OllamaSetupManager()
        manager._add_step("test", "success", "message")
        result = manager._compile_results(True, "0.1.0", True, ["model1"], "success")

        # Convert to JSON
        json_str = json.dumps(asdict(result), default=str)
        assert len(json_str) > 0

        # Verify structure
        parsed = json.loads(json_str)
        assert parsed["overall_status"] == "success"
        print("✓ PASSED: JSON serialization works\n")
        test_results.append(True)
    except Exception as e:
        print(f"✗ FAILED: {e}\n")
        test_results.append(False)

    # Summary
    print("=" * 70)
    print(f"TEST SUMMARY: {sum(test_results)}/{len(test_results)} tests passed")
    print("=" * 70 + "\n")

    return all(test_results)


if __name__ == "__main__":
    import argparse

    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    parser = argparse.ArgumentParser(description="Setup Ollama for MCP Server")
    parser.add_argument("--skip-models", action="store_true",
                        help="Skip downloading models")
    parser.add_argument("--check-only", action="store_true",
                        help="Only check current status")
    parser.add_argument("--test", action="store_true",
                        help="Run test suite")

    args = parser.parse_args()

    if args.test:
        success = run_tests()
        exit(0 if success else 1)

    manager = OllamaSetupManager()

    if args.check_only:
        installed, version = manager._check_ollama_installed()
        running = manager._is_ollama_running()
        print(f"\nOllama Status:")
        print(f"  Installed: {installed}")
        if version:
            print(f"  Version: {version}")
        print(f"  Running: {running}")
        exit(0 if installed and running else 1)

    result = manager.run_full_setup(skip_model_download=args.skip_models)
    exit(0 if result.overall_status in ["success", "partial"] else 1)