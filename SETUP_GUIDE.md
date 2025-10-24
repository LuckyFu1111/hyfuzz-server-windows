# HyFuzz Server - Windows Setup Guide

A comprehensive step-by-step guide for setting up the HyFuzz Server on Windows 10/11. This guide covers environment preparation, dependency installation, model configuration, and verification.

**Last Updated**: October 2025  
**Target Platform**: Windows 10 (Build 19041+) / Windows 11  
**Estimated Setup Time**: 30-45 minutes

---

## 📋 Table of Contents

- [Prerequisites Checklist](#prerequisites-checklist)
- [Part 1: Environment Preparation](#part-1-environment-preparation)
- [Part 2: Python Setup](#part-2-python-setup)
- [Part 3: Repository Configuration](#part-3-repository-configuration)
- [Part 4: Ollama LLM Setup](#part-4-ollama-llm-setup)
- [Part 5: Dependency Installation](#part-5-dependency-installation)
- [Part 6: Knowledge Base Initialization](#part-6-knowledge-base-initialization)
- [Part 7: Server Configuration](#part-7-server-configuration)
- [Part 8: Verification & Testing](#part-8-verification--testing)
- [Part 9: Client Connection](#part-9-client-connection)
- [Troubleshooting](#troubleshooting)
- [Performance Tuning](#performance-tuning)
- [Advanced Configuration](#advanced-configuration)

---

## ✅ Prerequisites Checklist

Before starting, verify you have:

- [ ] **Windows 10 (Build 19041+) or Windows 11**
  - Check: `winver` in command prompt

- [ ] **Administrator Access**
  - Required for firewall configuration

- [ ] **Disk Space**
  - [ ] 5GB free for Python/dependencies
  - [ ] 5-10GB free for LLM models
  - [ ] 2GB free for knowledge base cache

- [ ] **RAM Available**
  - [ ] Minimum 8GB installed
  - [ ] At least 6GB free during runtime
  - [ ] 16GB+ recommended for optimal performance

- [ ] **Internet Connection**
  - [ ] Required for downloading models (one-time)
  - [ ] Stable connection recommended (models can be large)

- [ ] **Processor**
  - [ ] 4+ cores (8+ recommended)
  - [ ] AVX/AVX2 support for optimization
  - Check with: `wmic cpu get Name`

---

## Part 1: Environment Preparation

### Step 1.1: Check System Information
```bash
# Open Command Prompt as Administrator
# Press: Win + X, then A

# Verify Windows version
winver
# Expected: Windows 10 (Build 19041+) or Windows 11

# Check RAM
wmic OS get TotalVisibleMemorySize /value
# Convert to GB: divide by 1048576

# Check free disk space
dir C:\
# Or use: Get-Volume (in PowerShell)

# Verify processor
wmic cpu get Name
# Expected output: Intel Core i5/i7 or AMD Ryzen 5/7+
```

### Step 1.2: Disable Antivirus Interference (Optional)

Some antivirus software may slow down Python module loading:
```bash
# Windows Defender - Add Python/Ollama to exclusions:
# 1. Settings → Virus & threat protection
# 2. Manage settings → Add exclusions
# 3. Add folder: C:\Users\<username>\AppData\Local\Programs\Python
# 4. Add folder: C:\Users\<username>\.ollama
# 5. Add folder: <project-path>\venv
```

### Step 1.3: Configure Firewall
```bash
# Open Windows Defender Firewall with Advanced Security
# (Press: Win + R, type: wf.msc)

# Allow Python and Ollama through firewall:
# 1. Inbound Rules → New Rule
# 2. Program → Next
# 3. Browse to: C:\Users\<username>\AppData\Local\Programs\Python\Python<version>\python.exe
# 4. Allow the connection
# 5. Repeat for Ollama installation directory

# Or use PowerShell:
netsh advfirewall firewall add rule name="Python" dir=in action=allow program="C:\...\python.exe" enable=yes
netsh advfirewall firewall add rule name="Ollama" dir=in action=allow program="C:\...\ollama.exe" enable=yes
```

---

## Part 2: Python Setup

### Step 2.1: Download Python

Visit https://www.python.org/downloads/ and download **Python 3.9, 3.10, or 3.11**
```
Recommended: Python 3.11.x (Latest stable)
```

### Step 2.2: Install Python
```
1. Run the installer
2. ✓ Check: "Add Python 3.11 to PATH"
3. Choose: "Install for all users" (requires admin)
4. Click: "Install Now"
5. Wait for completion
```

**Important**: Make sure "Add Python to PATH" is checked!

### Step 2.3: Verify Python Installation
```bash
# Open new Command Prompt (important!)
python --version
# Expected: Python 3.11.x

python -m pip --version
# Expected: pip x.x.x from ... (python 3.11)

# Verify pip is functional
python -m pip list
# Should show list of packages
```

### Step 2.4: Update pip
```bash
# Update pip to latest version
python -m pip install --upgrade pip setuptools wheel

# Verify upgrade
python -m pip --version
# Should show latest version
```

---

## Part 3: Repository Configuration

### Step 3.1: Clone Repository
```bash
# Choose installation directory (example: C:\dev\)
cd C:\dev

# Clone the repository
git clone https://github.com/your-org/hyfuzz-server-windows.git

# Navigate to project
cd hyfuzz-server-windows

# Verify structure
dir

# Expected folders:
# - src/
# - tests/
# - config/
# - data/
# - scripts/
# - docs/
```

### Step 3.2: Create Virtual Environment
```bash
# Create Python virtual environment
python -m venv venv

# Expected output:
# - venv\ folder created
# - Contains: Scripts\, Lib\, pyvenv.cfg

# Verify virtual environment
dir venv\Scripts\

# Should contain: python.exe, pip.exe, activate.bat
```

### Step 3.3: Activate Virtual Environment
```bash
# Activate in Command Prompt
venv\Scripts\activate

# Expected output:
# (venv) C:\dev\hyfuzz-server-windows>

# Verify activation
python --version
which python  # Should show path in venv\

# For PowerShell (if using):
venv\Scripts\Activate.ps1
# If error: Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**Important**: Always activate virtual environment before working with the project!

---

## Part 4: Ollama LLM Setup

### Step 4.1: Download Ollama

Visit https://ollama.ai and download for Windows
```
Steps:
1. Go to https://ollama.ai
2. Click "Download"
3. Select "Windows"
4. Run OllamaSetup.exe
5. Follow installation wizard
6. Accept default installation path: C:\Users\<username>\AppData\Local\Programs\Ollama
```

### Step 4.2: Verify Ollama Installation
```bash
# Open new Command Prompt (important!)
ollama --version
# Expected: ollama version 0.1.x

# Check Ollama is accessible
ollama list
# Expected: "NAME    ID    SIZE    MODIFIED"
# (Empty list initially)
```

### Step 4.3: Start Ollama Service

Ollama runs as a background service. Two ways to ensure it's running:

**Option A: Automatic (Recommended)**
```bash
# Ollama auto-starts on Windows 11
# Verify it's running:
ollama serve

# Should show:
# Listening on 127.0.0.1:11434
# (Keep this terminal open)
```

**Option B: Manual Command**
```bash
# Open Command Prompt
cd %USERPROFILE%\AppData\Local\Programs\Ollama

# Start service
ollama serve

# Expected output:
# 2025-01-15 10:23:45 INFO Listening on 127.0.0.1:11434
```

**Keep Ollama running in background throughout setup!**

### Step 4.4: Download LLM Models

Open a **new** Command Prompt (Ollama runs in other terminal) and download models:
```bash
# Download Mistral 7B (recommended - fast & capable)
ollama pull mistral

# Expected output:
# pulling manifest
# pulling 2ae6f2ed3f1e... (continued until 100%)
# digest: sha256:...
# total time: ~2-5 minutes (depending on internet)

# Verify download
ollama list

# Expected:
# NAME        ID              SIZE    MODIFIED
# mistral     2ae6f2ed3f1e    4.1GB   Just now
```

**Model Selection Guide:**

| Model | Size | Speed | Quality | RAM Required | Best For |
|-------|------|-------|---------|--------------|----------|
| mistral | 7B | Fast | Good | 8GB | General use ⭐ |
| neural-chat | 7B | Fast | Good | 8GB | Chat-optimized |
| dolphin-mixtral | 8x7B | Slower | Better | 16GB+ | High quality |
| openhermes-2.5-mistral | 7B | Fast | Good | 8GB | Multi-task |
| llama2-uncensored | 7B | Fast | Good | 8GB | Less filtered |

**Recommendation**: Start with `mistral` for balanced performance.

### Step 4.5: Optional: Download Additional Models
```bash
# If you have 16GB+ RAM and want better quality:
ollama pull neural-chat
# or
ollama pull dolphin-mixtral

# If you have slower internet, use lighter model:
ollama pull tinyllama  # Only 1.1GB

# Verify all models
ollama list
```

### Step 4.6: Test Ollama API

Open PowerShell or new Command Prompt:
```bash
# Test Ollama API endpoint (with Ollama service running)
curl http://localhost:11434/api/tags

# Expected JSON output:
# {
#   "models": [
#     {
#       "name": "mistral:latest",
#       "modified_at": "2025-01-15T10:30:00.000Z",
#       "size": 4406837760,
#       "digest": "2ae6f2ed3f1e..."
#     }
#   ]
# }
```

---

## Part 5: Dependency Installation

### Step 5.1: Activate Virtual Environment
```bash
# Make sure venv is activated
venv\Scripts\activate

# Verify (should show (venv) prefix):
# (venv) C:\dev\hyfuzz-server-windows>
```

### Step 5.2: Upgrade pip & Setuptools
```bash
# Upgrade packaging tools
python -m pip install --upgrade pip setuptools wheel

# Expected:
# Successfully installed pip-x.x.x setuptools-x.x.x wheel-x.x.x
```

### Step 5.3: Install Required Dependencies
```bash
# Install core dependencies
pip install -r requirements.txt

# This will install:
# - aiohttp (async HTTP)
# - pydantic (data validation)
# - requests (HTTP client)
# - ollama (LLM client)
# - numpy (numerical computing)
# - And 20+ other packages

# Expected output:
# Successfully installed package1 package2 ...
# (total: ~25 packages)
```

**Installation Time**: 3-8 minutes depending on internet speed

### Step 5.4: Install Development Dependencies (Optional)

For testing and development:
```bash
# Install dev dependencies
pip install -r requirements-dev.txt

# This adds:
# - pytest (testing framework)
# - pytest-cov (coverage)
# - black (code formatter)
# - pylint (linter)
# - mypy (type checker)
```

### Step 5.5: Verify Installation
```bash
# List all installed packages
pip list

# Should show 25-35 packages including:
# - aiohttp
# - pydantic
# - requests
# - ollama
# - numpy
# etc.

# Test imports
python -c "import aiohttp, pydantic, requests, ollama; print('All imports successful!')"

# Expected: All imports successful!
```

---

## Part 6: Knowledge Base Initialization

### Step 6.1: Create Data Directories
```bash
# Create required directories
mkdir data
mkdir data\knowledge_cache
mkdir logs

# Verify creation
dir data\
dir logs\

# Expected structure:
# data\
#   ├─ knowledge_cache\
#   ├─ payloads\
#   ├─ results\
#   └─ test_data\
# logs\
```

### Step 6.2: Download Knowledge Base Data

The setup script will download CWE and CVE data:
```bash
# Make sure venv is activated
venv\Scripts\activate

# Run setup script
python scripts\setup_env.py

# Expected output:
# [INFO] Setting up HyFuzz Server environment...
# [INFO] Downloading CWE data...
# [INFO] Downloading CVE data...
# [INFO] Creating knowledge cache...
# [INFO] Setup completed successfully!

# This will create:
# - data/cwe_data.json (~2MB)
# - data/cve_data.json (~10MB)
# - data/knowledge_cache/cwe_graph.pkl
# - data/knowledge_cache/cve_graph.pkl
```

**Time Required**: 5-10 minutes (depends on internet)

### Step 6.3: Verify Knowledge Base
```bash
# Check if files were created
dir data\

# Expected files:
# - cwe_data.json
# - cve_data.json
# - knowledge_cache\ (directory)

# Check knowledge cache
dir data\knowledge_cache\

# Expected files:
# - cwe_graph.pkl
# - cve_graph.pkl
# - embeddings.npy (may not exist yet)

# Verify JSON files are valid
python -c "import json; json.load(open('data/cwe_data.json')); print('CWE data OK')"
python -c "import json; json.load(open('data/cve_data.json')); print('CVE data OK')"
```

---

## Part 7: Server Configuration

### Step 7.1: Create .env File
```bash
# Copy environment template
copy .env.example .env

# Verify .env was created
dir | find ".env"
```

### Step 7.2: Edit .env Configuration

Open `.env` with your text editor (Notepad, VS Code, etc.):
```bash
# Using Notepad
notepad .env

# Or VS Code
code .env
```

Configure with appropriate values:
```bash
# ============ Server Configuration ============
SERVER_HOST=0.0.0.0              # Accept connections from anywhere
SERVER_PORT=5000                 # MCP Server port
SERVER_LOG_LEVEL=INFO            # Logging level
SERVER_WORKERS=4                 # Number of worker processes

# ============ LLM Configuration ============
LLM_PROVIDER=ollama              # Use local Ollama
LLM_MODEL_NAME=mistral           # Model to use (match your download)
OLLAMA_API_URL=http://localhost:11434  # Ollama service URL
LLM_TEMPERATURE=0.7              # Creativity level (0.0-1.0)
LLM_MAX_TOKENS=2048              # Max response tokens
LLM_CACHE_ENABLED=true           # Enable response caching
LLM_CACHE_TTL=3600               # Cache lifetime in seconds

# ============ Knowledge Base Configuration ============
KNOWLEDGE_BASE_PATH=./data/knowledge_cache
GRAPH_DB_PATH=./data/knowledge_cache/graph_db.pkl
VECTOR_DB_PATH=./data/knowledge_cache/vector_db.pkl
EMBEDDING_MODEL=sentence-transformers/all-MiniLM-L6-v2

# ============ Database Configuration ============
DB_ENABLE=false                  # Disable for simple setup
DB_TYPE=sqlite                   # Would use SQLite if enabled
DB_PATH=./data/hyfuzz.db

# ============ Cache Configuration ============
CACHE_BACKEND=memory             # Use in-memory cache
CACHE_TTL_SECONDS=3600

# ============ Logging Configuration ============
LOG_FILE=./logs/server.log
LOG_LEVEL=INFO
LOG_FORMAT=standard
LOG_MAX_SIZE=10485760            # 10MB
LOG_BACKUP_COUNT=5

# ============ Performance Tuning ============
BATCH_SIZE=32
EMBEDDING_CACHE_SIZE=10000
QUERY_TIMEOUT=30
CONCURRENT_REQUESTS=10
```

### Step 7.3: Save Configuration

Save the `.env` file (Ctrl+S in most editors)

Verify configuration:
```bash
# Display .env content
type .env

# Or verify with Python
python -c "from dotenv import load_dotenv; load_dotenv(); import os; print('Config loaded:', len(os.environ))"
```

### Step 7.4: Create config/default_config.yaml

Ensure config/default_config.yaml exists:
```bash
# Check if file exists
dir config\

# If not, create it:
type config\default_config.yaml  # View if exists

# Or copy from example:
copy config\default_config.yaml config\default_config.yaml
```

---

## Part 8: Verification & Testing

### Step 8.1: Health Check

Ensure virtual environment is activated:
```bash
(venv) C:\dev\hyfuzz-server-windows> python scripts\health_check.py

# Expected output:
# [✓] Python version: 3.11.x
# [✓] Virtual environment: Active
# [✓] Ollama service: Connected
# [✓] Ollama model loaded: mistral
# [✓] Knowledge base: Loaded (5000+ CWE, 100000+ CVE)
# [✓] Configuration: Valid
# [✓] All systems ready!
```

### Step 8.2: Start Server
```bash
# Method 1: Using startup script
python scripts\start_server.py

# Method 2: Direct invocation
python -m src

# Expected output:
# [INFO] 2025-01-15 10:45:30 Starting MCP Server...
# [INFO] Server configuration loaded from .env
# [INFO] Initializing LLM service with model: mistral
# [INFO] Connecting to Ollama at http://localhost:11434
# [INFO] Loading knowledge base from ./data/knowledge_cache
# [INFO] Knowledge base loaded: 5000+ CWE entries, 100000+ CVE entries
# [INFO] Initializing MCP transport (stdio)
# [INFO] Server ready on 0.0.0.0:5000
# [INFO] Waiting for client connections...
```

**Keep this terminal open for server to run!**

### Step 8.3: Test API in New Terminal

Open new Command Prompt, activate venv, and test:
```bash
# Activate venv in new terminal
venv\Scripts\activate

# Test health endpoint
python -c "import requests; r = requests.get('http://localhost:5000/health'); print(r.json())"

# Expected output:
# {'status': 'healthy', 'model': 'mistral', 'uptime_seconds': 12}

# Test payload generation
python -c """
import requests
import json

payload = {
    'cwe_id': 'CWE-79',
    'protocol': 'coap',
    'target_info': {'version': '1.0'}
}

response = requests.post('http://localhost:5000/api/v1/payloads/generate', json=payload)
result = response.json()
print(json.dumps(result, indent=2))
"""

# Expected output:
# {
#   "payload": "coap://target/uri?q=%3Cscript%3E...",
#   "reasoning_chain": ["Step 1: ...", "Step 2: ..."],
#   "confidence_score": 0.82,
#   "success_probability": 0.78
# }
```

### Step 8.4: Run Unit Tests

In terminal with activated venv:
```bash
# Run all unit tests
pytest tests\unit\ -v

# Expected output:
# tests\unit\test_server.py::test_initialization PASSED
# tests\unit\test_llm_client.py::test_connection PASSED
# tests\unit\test_cot_engine.py::test_reasoning PASSED
# ...
# ======================== 12 passed in 3.45s ========================

# Run with coverage
pytest tests\unit\ --cov=src --cov-report=term-missing

# Expected:
# src\mcp_server\server.py          95%
# src\llm\llm_service.py            91%
# src\knowledge\knowledge_loader.py 88%
# ...
# Total coverage: 82%
```

### Step 8.5: Performance Benchmark
```bash
# Run performance tests
python scripts\benchmark.py

# Expected output:
# ========== Performance Benchmark ==========
#
# LLM Response Time:
#   - Cold start: 2.3s
#   - Warm (cached): 0.15s
#   - Average: 0.8s
#
# Knowledge Retrieval:
#   - Graph DB query: 0.05s
#   - Vector DB query: 0.12s
#   - Fusion layer: 0.08s
#
# Overall throughput: 4.2 requests/second
# Memory usage: 245MB (peak)
```

---

## Part 9: Client Connection

### Step 9.1: Prepare Ubuntu Client

On your Ubuntu machine (or WSL), follow the Ubuntu client setup guide.

### Step 9.2: Get Server IP Address

From Windows (if Server and Client on different machines):
```bash
# Find local IP address
ipconfig

# Look for IPv4 Address under your network adapter
# Example: 192.168.1.100

# Or get public IP (if on different networks):
curl ipinfo.io
```

### Step 9.3: Configure Client Connection

On Ubuntu client, edit `.env`:
```bash
# Edit client .env
nano .env

# Set server connection
MCP_SERVER_HOST=<your-server-ip>      # Or localhost if same machine
MCP_SERVER_PORT=5000
MCP_TRANSPORT=http                    # or stdio, websocket
```

### Step 9.4: Test Connection

From Ubuntu client:
```bash
# Test connection to Windows server
python scripts\test_connection.py --host <server-ip> --port 5000

# Expected output:
# Testing connection to 192.168.1.100:5000...
# [✓] TCP connection established
# [✓] MCP handshake successful
# [✓] LLM service responding
# [✓] Knowledge base accessible
# [✓] Ready for fuzzing operations
```

### Step 9.5: Start End-to-End Test
```bash
# From Ubuntu client, run integration test
pytest tests/integration/test_end_to_end.py -v

# Expected output:
# test_complete_fuzzing_workflow PASSED
# test_payload_generation PASSED
# test_feedback_loop PASSED
# ======================== 3 passed in 15.23s ========================
```

---

## 🔧 Troubleshooting

### Problem: Python Not Found
```
Error: 'python' is not recognized as an internal or external command
```

**Solution:**
```bash
# Verify Python is installed
where python

# If not found:
# 1. Check: C:\Users\<username>\AppData\Local\Programs\Python\Python311\
# 2. Add to PATH:
#    - Right-click This PC → Properties
#    - Advanced system settings → Environment Variables
#    - Edit PATH variable, add: C:\Users\<username>\AppData\Local\Programs\Python\Python311\

# Restart Command Prompt and try again
python --version
```

### Problem: Ollama Service Not Running
```
Error: HTTPConnectionPool(host='localhost', port=11434): Connection refused
```

**Solution:**
```bash
# Check if Ollama is running
netstat -ano | findstr :11434

# If not running, start it:
ollama serve

# Or check Windows Services:
# 1. Press: Win + R
# 2. Type: services.msc
# 3. Look for "Ollama"
# 4. If present, right-click → Start
```

### Problem: Model Loading Fails
```
Error: Failed to load model 'mistral'
```

**Solution:**
```bash
# Verify model is downloaded
ollama list

# If missing, download:
ollama pull mistral

# Check model file size (should be ~4GB)
dir %USERPROFILE%\.ollama\models\blobs\

# If corrupted, delete and re-download:
ollama rm mistral
ollama pull mistral
```

### Problem: Out of Memory
```
Error: MemoryError or "CUDA out of memory"
```

**Solution:**
```bash
# In .env, reduce batch size
BATCH_SIZE=1              # Instead of 32
EMBEDDING_CACHE_SIZE=1000 # Instead of 10000

# Use smaller model
ollama pull tinyllama     # 1.1GB instead of 4GB

# Close unnecessary applications
# Check Task Manager: Ctrl+Shift+Esc
# End processes using >50% memory
```

### Problem: Firewall Blocking
```
Error: Connection refused from client
```

**Solution:**
```bash
# Add Windows Firewall exception:
# 1. Settings → Privacy & Security → Windows Security
# 2. Firewall & network protection
# 3. Allow an app through firewall
# 4. Click "Change settings"
# 5. Click "Allow another app"
# 6. Browse to Python installation
# 7. Click "Add"

# Or use command:
netsh advfirewall firewall add rule name="HyFuzz Server" dir=in action=allow program="C:\...\python.exe" enable=yes
```

### Problem: Knowledge Base Won't Load
```
Error: Failed to load knowledge base from ./data/knowledge_cache
```

**Solution:**
```bash
# Regenerate knowledge base
python scripts\setup_env.py

# Or manually initialize:
python -c """
from src.knowledge import KnowledgeLoader
KnowledgeLoader.initialize()
print('Knowledge base initialized')
"""

# Check file permissions
dir data\knowledge_cache\
# All files should be readable
```

### Problem: Configuration Not Loading
```
Error: Configuration validation failed
```

**Solution:**
```bash
# Verify .env syntax
type .env

# Check for quotes and special characters
# Each line should be: KEY=VALUE

# Reload configuration
python -c "from dotenv import load_dotenv; load_dotenv(override=True); print('Config reloaded')"

# Or regenerate from template
copy .env.example .env
# Edit again with correct values
```

### Problem: Import Errors
```
Error: ModuleNotFoundError: No module named 'aiohttp'
```

**Solution:**
```bash
# Verify virtual environment is activated
# Should show (venv) prefix in terminal

# Reinstall dependencies
pip install -r requirements.txt --force-reinstall

# Verify installation
pip list | grep aiohttp
```

---

## ⚡ Performance Tuning

### Windows-Specific Optimizations
```bash
# Edit .env for performance

# 1. Increase worker processes (if you have 8+ cores)
SERVER_WORKERS=8           # Default: 4

# 2. Increase batch size (if you have 16GB+ RAM)
BATCH_SIZE=64             # Default: 32

# 3. Enable aggressive caching
LLM_CACHE_ENABLED=true
CACHE_TTL_SECONDS=7200    # 2 hours

# 4. Disable unnecessary logging
LOG_LEVEL=WARNING         # Instead of INFO

# 5. Increase timeouts (for slower systems)
QUERY_TIMEOUT=60          # Instead of 30
```

### Enable GPU Acceleration (Optional)

If you have NVIDIA GPU:
```bash
# Install CUDA support for Ollama
# 1. Download NVIDIA CUDA Toolkit
# 2. Install
# 3. Ollama will auto-detect and use GPU

# Verify GPU is used:
ollama serve  # Should show "GPU enabled" in logs

# Check GPU memory usage:
nvidia-smi  # If installed
```

### CPU Optimization
```bash
# Disable CPU frequency scaling (Admin PowerShell):
powercfg /setactive 8c5e7fda-e8bf-45a6-a6cc-0ba265e7d108

# Set to high performance mode:
# Settings → System → Power & battery → Power mode
# Select: Best performance

# Or via PowerShell:
powercfg /change monitor-timeout-ac 0  # Never sleep
powercfg /change disk-timeout-ac 0     # Disable disk spindown
```

---

## 🔐 Advanced Configuration

### Custom Prompt Templates

Create `config/prompts_custom.yaml`:
```yaml
payloads:
  xss_coap: |
    You are analyzing CoAP protocol for XSS vulnerabilities.
    
    Target: {target}
    CWE: {cwe_description}
    Known patterns: {similar_payloads}
    
    Generate a CoAP-formatted XSS payload:
    
  sql_injection: |
    You are analyzing SQL injection vulnerabilities.
    
    Database: {db_type}
    Input vector: {input_vector}
    
    Generate a SQL injection payload:
```

Configure in `.env`:
```bash
CUSTOM_PROMPTS_PATH=config/prompts_custom.yaml
```

### Database Integration

For persistent storage:
```bash
# Install PostgreSQL support
pip install psycopg2-binary

# Update .env:
DB_ENABLE=true
DB_TYPE=postgresql
DB_HOST=localhost
DB_PORT=5432
DB_USER=hyfuzz
DB_PASSWORD=<secure-password>
DB_NAME=hyfuzz_prod

# Create database:
# psql -U postgres -c "CREATE DATABASE hyfuzz_prod"
# psql -U postgres -c "GRANT ALL PRIVILEGES ON DATABASE hyfuzz_prod TO hyfuzz"
```

### Redis Caching

For distributed caching:
```bash
# Install Redis
# Download from: https://github.com/microsoftarchive/redis/releases

# Update .env:
CACHE_BACKEND=redis
REDIS_URL=redis://localhost:6379
CACHE_TTL_SECONDS=7200

# Start Redis:
redis-server.exe
```

### Logging to File

Configure advanced logging:
```bash
# Update .env:
LOG_FILE=./logs/hyfuzz.log
LOG_LEVEL=DEBUG
LOG_FORMAT=json
LOG_MAX_SIZE=52428800       # 50MB
LOG_BACKUP_COUNT=10
LOG_COMPRESSION=gzip

# Logs will rotate when reaching 50MB
# Old logs compressed to .gz files
```

### Multi-Worker Configuration

For production setup:
```bash
# Use Gunicorn (web server)
pip install gunicorn

# Start with multiple workers:
gunicorn src.mcp_server.server:app --workers 8 --worker-class aiohttp.GunicornWebWorker --bind 0.0.0.0:5000

# Or update .env:
SERVER_WORKERS=8
SERVER_WORKER_CLASS=aiohttp.GunicornWebWorker
```

---

## 📊 Verification Checklist

After setup, verify all components:

- [ ] **Python**
  - [ ] Version 3.9+
  - [ ] Virtual environment active
  - [ ] pip functioning

- [ ] **Ollama**
  - [ ] Service running
  - [ ] Model downloaded (e.g., mistral)
  - [ ] API responding on port 11434

- [ ] **Dependencies**
  - [ ] All packages installed
  - [ ] Imports working
  - [ ] No version conflicts

- [ ] **Configuration**
  - [ ] .env file created
  - [ ] All required variables set
  - [ ] Paths valid

- [ ] **Knowledge Base**
  - [ ] CWE data loaded
  - [ ] CVE data loaded
  - [ ] Cache files present

- [ ] **Server**
  - [ ] Starts without errors
  - [ ] Health check passes
  - [ ] API responding

- [ ] **Firewall**
  - [ ] Python allowed through
  - [ ] Port 5000 accessible
  - [ ] Ollama port 11434 accessible

- [ ] **Client Connection**
  - [ ] TCP connection works
  - [ ] MCP handshake succeeds
  - [ ] Payload generation works

---

## 🚀 Next Steps

Once setup is complete:

1. **Read Documentation**
   - Review `docs/README.md`
   - Study `docs/ARCHITECTURE.md`
   - Learn `docs/API.md`

2. **Run Integration Tests**
   - Complete `tests/integration/` suite
   - Verify end-to-end workflow

3. **Connect Client**
   - Start Ubuntu MCP Client
   - Run client tests
   - Execute first fuzzing campaign

4. **Tune Performance**
   - Monitor resource usage
   - Adjust configuration per results
   - Optimize for your hardware

5. **Develop**
   - Review code structure
   - Study core modules
   - Start contributing

---

## 📞 Support

If you encounter issues:

1. **Check This Guide**
   - Search for your error
   - Review Troubleshooting section

2. **Check Logs**
```bash
   type logs\server.log
   tail -f logs\server.log (in PowerShell)
```

3. **Test Components**
```bash
   python scripts\health_check.py
```

4. **Search Issues**
   - GitHub Issues: https://github.com/your-org/hyfuzz-server-windows/issues
   - Stack Overflow: tag "hyfuzz"

5. **Contact Support**
   - Email: support@hyfuzz.ai
   - Discord: [link to Discord server]

---

## 📝 Setup Summary

| Step | Component | Status |
|------|-----------|--------|
| 1 | System verification | ✓ |
| 2 | Python 3.9+ | ✓ |
| 3 | Virtual environment | ✓ |
| 4 | Ollama installation | ✓ |
| 5 | Ollama models | ✓ |
| 6 | Dependencies | ✓ |
| 7 | Knowledge base | ✓ |
| 8 | Configuration | ✓ |
| 9 | Server startup | ✓ |
| 10 | Tests passing | ✓ |
| 11 | Client connection | ✓ |
| 12 | Ready for production | ✓ |

**Total Time**: 30-45 minutes  
**Estimated**: You are now ready to run HyFuzz Server!

---

## 📈 System Readiness Indicators

After successful setup, you should see:
```
✓ Server listens on 0.0.0.0:5000
✓ Ollama model 'mistral' loaded in memory
✓ 5000+ CWE entries indexed
✓ 100000+ CVE entries indexed
✓ Vector DB with 10000+ embeddings
✓ Avg response time: <1 second
✓ Memory usage: 200-300MB (baseline)
✓ CPU usage: <5% (idle)
✓ All unit tests passing
✓ Health check: OK
✓ Ready for Ubuntu client connection
```

---

**Congratulations!** Your HyFuzz Server is now operational. 🎉

For the next step, proceed to connect the Ubuntu MCP Client.

**Last Updated**: October 2025  
**Version**: 1.0.0  
**Platform**: Windows 10/11  
**License**: MIT