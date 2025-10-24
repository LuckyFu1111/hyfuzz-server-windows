# HyFuzz Server - Installation Methods

## Method 1: Standard Installation
```bash
# Clone repository
git clone https://github.com/your-org/hyfuzz-server-windows.git
cd hyfuzz-server-windows

# Create virtual environment
python -m venv venv
venv\Scripts\activate

# Install package
pip install .
```

## Method 2: Development Installation (Editable)
```bash
# Install in development mode (changes reflected immediately)
pip install -e .

# Install with development dependencies
pip install -e ".[dev]"
```

## Method 3: With Optional Features
```bash
# GPU acceleration
pip install ".[gpu]"

# Advanced monitoring
pip install ".[monitoring]"

# Distributed processing
pip install ".[distributed]"

# All features
pip install ".[all]"
```

## Method 4: From PyPI (Future)
```bash
# Once published to PyPI
pip install hyfuzz-server
```

## Verify Installation
```bash
# Check entry point
hyfuzz-server --help

# Or run directly
hyfuzz-health
```

## Build Distribution Packages
```bash
# Build source and wheel
pip install build
python -m build

# Check build artifacts
dir dist\
```

---

For detailed setup instructions, see [SETUP_GUIDE.md](SETUP_GUIDE.md)