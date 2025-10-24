# HyFuzz Server - Building and Distribution Guide

## Overview

This guide explains how to build, test, and distribute the HyFuzz Server package.

## Prerequisites
```bash
# Install build tools
pip install build twine wheel

# Optional: Install development dependencies
pip install -r requirements-dev.txt
```

## Building Distributions

### Using build (Recommended)
```bash
# Build both source and wheel distributions
python -m build

# Output in dist/ directory
# - hyfuzz-server-1.0.0.tar.gz (source)
# - hyfuzz_server-1.0.0-py3-none-any.whl (wheel)
```

### Using setup.py (Legacy)
```bash
# Build source distribution
python setup.py sdist

# Build wheel distribution
python setup.py bdist_wheel

# Build both
python setup.py sdist bdist_wheel
```

## Testing Distributions
```bash
# Extract and test source distribution
tar xzf dist/hyfuzz-server-1.0.0.tar.gz
cd hyfuzz-server-1.0.0
pip install .

# Test wheel
pip install dist/hyfuzz_server-1.0.0-py3-none-any.whl
```

## Publishing to PyPI

### Test PyPI (Recommended First)
```bash
# Upload to test PyPI
twine upload --repository testpypi dist/*

# Verify in browser
# https://test.pypi.org/project/hyfuzz-server/

# Test installation
pip install --index-url https://test.pypi.org/simple/ hyfuzz-server
```

### Production PyPI
```bash
# Upload to production PyPI
twine upload dist/*

# Verify in browser
# https://pypi.org/project/hyfuzz-server/
```

## Version Management

When releasing a new version:

1. Update version in `src/__init__.py`
2. Update `pyproject.toml` if needed
3. Build: `python -m build`
4. Upload: `twine upload dist/*`

## Cleanup
```bash
# Remove build artifacts
rm -r build/ dist/ *.egg-info

# Or use
python setup.py clean --all
```

---

For more information, see [setup.py](setup.py) and [pyproject.toml](pyproject.toml)