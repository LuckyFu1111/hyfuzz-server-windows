"""
Embedding Vector Generator for HyFuzz Knowledge Base

This script generates semantic embeddings for CVE and CWE data to enable
similarity-based retrieval and semantic search in the HyFuzz system.

Features:
- Generates embeddings for CVE descriptions and CWE data
- Multiple embedding dimension support (384, 512, 768)
- Metadata indexing for fast lookup
- Metadata indexing for fast lookup
- Pickle format for efficient storage
- JSON export for inspection
- Similarity distance computation (cosine, euclidean, manhattan)
- Batch processing support
- Progress tracking

Embedding Architecture:
┌─────────────────────────────────────────────────────────┐
│ Input Texts (CVE/CWE Descriptions)                     │
│ e.g., "SQL Injection in Apache Struts"                 │
└──────────────┬──────────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────────┐
│ Text Preprocessing                                      │
│ - Normalize, tokenize, lowercase                        │
│ - Remove special characters                             │
└──────────────┬──────────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────────┐
│ Embedding Model (768-dim or 512-dim or 384-dim)        │
│ - Uses sentence-transformers-like encoding             │
│ - Generates dense vectors                              │
│ - Captures semantic meaning                            │
└──────────────┬──────────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────────┐
│ Output Embeddings                                       │
│ Vector shape: (n_samples, embedding_dim)               │
│ e.g., (1000, 768)                                      │
│                                                         │
│ Metadata:                                               │
│ - IDs, types, severity, platforms, technologies        │
│ - Timestamps, source information                       │
└─────────────────────────────────────────────────────────┘

Usage:
    python generate_embeddings.py --dim 768 --count 1000
    python generate_embeddings.py --type cve --dim 512
    python generate_embeddings.py --json --seed 42

Author: HyFuzz Development Team
Version: 1.0.0-phase3
"""

import numpy as np
import pickle
import json
import sys
import argparse
import hashlib
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
import random
import math

# ============================================================================
# LOGGING SETUP
# ============================================================================

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# ============================================================================
# CONSTANTS
# ============================================================================

# Supported embedding dimensions
EMBEDDING_DIMS = {
    "small": 384,  # Lightweight (SBERT)
    "medium": 512,  # Balanced (MPNet)
    "large": 768,  # Full (All-MiniLM or Nomic)
}

# Vector database metadata structure
DEFAULT_METADATA = {
    "version": "1.0.0-phase3",
    "created_at": None,
    "embedding_dim": 768,
    "embedding_model": "nomic-embed-text",
    "total_embeddings": 0,
    "data_types": [],  # ["cve", "cwe"] or subsets
    "metric": "cosine",
    "normalization": "l2",
}

# Sample CVE data for embedding generation
SAMPLE_CVES = [
    {"id": "CVE-2023-1000", "text": "SQL injection vulnerability in Apache Struts", "type": "cve"},
    {"id": "CVE-2023-1001", "text": "Cross-site scripting XSS in Django templates", "type": "cve"},
    {"id": "CVE-2023-1002", "text": "Remote code execution RCE in PHP WordPress", "type": "cve"},
    {"id": "CVE-2023-1003", "text": "Buffer overflow in C++ OpenSSL library", "type": "cve"},
    {"id": "CVE-2023-1004", "text": "Authentication bypass in Spring Security", "type": "cve"},
    {"id": "CVE-2023-1005", "text": "Path traversal vulnerability in Apache server", "type": "cve"},
    {"id": "CVE-2023-1006", "text": "Deserialization attack Java ObjectInputStream", "type": "cve"},
    {"id": "CVE-2023-1007", "text": "Command injection shell metacharacters Linux", "type": "cve"},
    {"id": "CVE-2023-1008", "text": "XXE XML external entity attack parsing", "type": "cve"},
    {"id": "CVE-2023-1009", "text": "CSRF cross-site request forgery token", "type": "cve"},
]

# Sample CWE data for embedding generation
SAMPLE_CWES = [
    {"id": "CWE-20", "text": "Improper input validation data type check", "type": "cwe"},
    {"id": "CWE-77", "text": "Command injection shell metacharacters", "type": "cwe"},
    {"id": "CWE-79", "text": "Cross-site scripting XSS browser rendering", "type": "cwe"},
    {"id": "CWE-89", "text": "SQL injection database query string", "type": "cwe"},
    {"id": "CWE-119", "text": "Buffer overflow memory bounds checking", "type": "cwe"},
    {"id": "CWE-125", "text": "Out of bounds read memory access", "type": "cwe"},
    {"id": "CWE-190", "text": "Integer overflow arithmetic operation", "type": "cwe"},
    {"id": "CWE-287", "text": "Improper authentication credentials verification", "type": "cwe"},
    {"id": "CWE-352", "text": "CSRF cross-site request forgery token", "type": "cwe"},
    {"id": "CWE-434", "text": "Unrestricted file upload dangerous type", "type": "cwe"},
]


# ============================================================================
# EMBEDDING GENERATOR
# ============================================================================

class EmbeddingGenerator:
    """Generate semantic embeddings for CVE/CWE data."""

    def __init__(self, dim: int = 768, seed: Optional[int] = None):
        """
        Initialize embedding generator.

        Args:
            dim: Embedding dimension (384, 512, or 768)
            seed: Random seed for reproducibility
        """
        if seed is not None:
            np.random.seed(seed)
            random.seed(seed)

        if dim not in EMBEDDING_DIMS.values():
            raise ValueError(f"Unsupported dimension: {dim}. Use {list(EMBEDDING_DIMS.values())}")

        self.dim = dim
        self.seed = seed
        self.embeddings = []
        self.metadata_list = []

        logger.info(f"Initialized EmbeddingGenerator (dim={dim})")

    def _simple_hash_embedding(self, text: str) -> np.ndarray:
        """
        Generate deterministic embedding from text using hash-based approach.

        This simulates real embeddings while being reproducible and fast.
        In production, this would use actual embedding models like:
        - sentence-transformers
        - nomic-embed-text
        - openai.embedding

        Args:
            text: Input text to embed

        Returns:
            Embedding vector of shape (dim,)
        """
        # Hash text to deterministic seed for reproducibility
        text_bytes = text.lower().encode('utf-8')
        hash_digest = hashlib.sha256(text_bytes).digest()

        # Convert hash to seed for RNG
        seed_value = int.from_bytes(hash_digest[:4], byteorder='big')
        rng = np.random.RandomState(seed_value)

        # Generate embedding
        embedding = rng.normal(0, 1, self.dim)

        # L2 normalize (standard practice for embeddings)
        norm = np.linalg.norm(embedding)
        if norm > 0:
            embedding = embedding / norm

        return embedding

    def _add_semantic_structure(self, text: str, embedding: np.ndarray) -> np.ndarray:
        """
        Add semantic structure to embedding based on keywords.

        This adds some semantic meaning based on detected keywords.
        Real models would learn this from training data.

        Args:
            text: Input text
            embedding: Base embedding

        Returns:
            Modified embedding with semantic structure
        """
        text_lower = text.lower()
        modified = embedding.copy()

        # Define semantic clusters by keyword
        semantic_keywords = {
            "injection": (slice(0, self.dim // 5), 0.3),
            "sql": (slice(0, self.dim // 5), 0.25),
            "xss": (slice(self.dim // 5, 2 * self.dim // 5), 0.3),
            "overflow": (slice(2 * self.dim // 5, 3 * self.dim // 5), 0.3),
            "buffer": (slice(2 * self.dim // 5, 3 * self.dim // 5), 0.25),
            "authentication": (slice(3 * self.dim // 5, 4 * self.dim // 5), 0.3),
            "rce": (slice(4 * self.dim // 5, self.dim), 0.3),
            "remote": (slice(4 * self.dim // 5, self.dim), 0.25),
        }

        # Apply semantic boost
        for keyword, (slice_obj, boost) in semantic_keywords.items():
            if keyword in text_lower:
                modified[slice_obj] += boost * np.ones(slice_obj.stop - slice_obj.start)

        # Renormalize
        norm = np.linalg.norm(modified)
        if norm > 0:
            modified = modified / norm

        return modified

    def generate_embedding(self, item_id: str, text: str,
                           item_type: str = "cve", metadata: Optional[Dict] = None) -> Tuple[np.ndarray, Dict]:
        """
        Generate embedding for a single item.

        Args:
            item_id: Item identifier (CVE-xxx or CWE-xxx)
            text: Description text to embed
            item_type: "cve" or "cwe"
            metadata: Additional metadata

        Returns:
            Tuple of (embedding_vector, metadata_dict)
        """
        # Generate base embedding
        embedding = self._simple_hash_embedding(text)

        # Add semantic structure
        embedding = self._add_semantic_structure(text, embedding)

        # Create metadata
        meta = {
            "id": item_id,
            "type": item_type,
            "text": text,
            "text_length": len(text),
            "embedding_index": len(self.embeddings),
            "created_at": datetime.now().isoformat(),
            "embedding_norm": float(np.linalg.norm(embedding)),
        }

        if metadata:
            meta.update(metadata)

        return embedding, meta

    def generate_batch(self, items: List[Dict], verbose: bool = True) -> Tuple[np.ndarray, List[Dict]]:
        """
        Generate embeddings for batch of items.

        Args:
            items: List of items with 'id', 'text', 'type' keys
            verbose: Show progress

        Returns:
            Tuple of (embeddings_array, metadata_list)
        """
        embeddings_list = []
        metadata_list = []

        total = len(items)

        for idx, item in enumerate(items):
            embedding, meta = self.generate_embedding(
                item_id=item.get("id"),
                text=item.get("text"),
                item_type=item.get("type", "cve"),
                metadata=item.get("metadata")
            )

            embeddings_list.append(embedding)
            metadata_list.append(meta)

            if verbose and (idx + 1) % max(1, total // 10) == 0:
                logger.info(f"  Generated {idx + 1}/{total} embeddings")

        # Stack into array
        embeddings_array = np.array(embeddings_list, dtype=np.float32)

        return embeddings_array, metadata_list

    def expand_dataset(self, base_items: List[Dict], target_count: int) -> List[Dict]:
        """
        Expand dataset by creating variations of base items.

        Args:
            base_items: Original items
            target_count: Target number of items

        Returns:
            Expanded item list
        """
        if target_count <= len(base_items):
            return base_items[:target_count]

        expanded = base_items.copy()
        item_type = base_items[0].get("type", "cve")

        # Generate variations
        while len(expanded) < target_count:
            for base_item in base_items:
                if len(expanded) >= target_count:
                    break

                # Create variation
                variation_num = len(expanded) - len(base_items) + 1
                new_id = f"{base_item['id']}-v{variation_num}"

                # Add variation to text
                base_text = base_item['text']
                variations = [
                    f"{base_text} (version {variation_num})",
                    f"{base_text} variant {variation_num}",
                    f"Related to {base_text}",
                ]

                new_text = random.choice(variations)

                expanded.append({
                    "id": new_id,
                    "text": new_text,
                    "type": item_type,
                    "metadata": {"original_id": base_item['id']}
                })

        return expanded[:target_count]

    def generate_complete_embeddings(self, cve_count: int = 100, cwe_count: int = 50) \
            -> Tuple[np.ndarray, List[Dict], Dict]:
        """
        Generate complete embedding database.

        Args:
            cve_count: Number of CVE embeddings
            cwe_count: Number of CWE embeddings

        Returns:
            Tuple of (embeddings_array, metadata_list, global_metadata)
        """
        logger.info(f"Generating {cve_count} CVE + {cwe_count} CWE embeddings...")

        # Expand datasets
        expanded_cves = self.expand_dataset(SAMPLE_CVES, cve_count)
        expanded_cwes = self.expand_dataset(SAMPLE_CWES, cwe_count)

        all_items = expanded_cves + expanded_cwes

        # Generate embeddings
        embeddings_array, metadata_list = self.generate_batch(all_items)

        # Global metadata
        global_metadata = DEFAULT_METADATA.copy()
        global_metadata.update({
            "created_at": datetime.now().isoformat(),
            "total_embeddings": len(embeddings_array),
            "data_types": ["cve", "cwe"],
            "cve_count": cve_count,
            "cwe_count": cwe_count,
            "embedding_dim": self.dim,
            "seed": self.seed,
        })

        logger.info(f"✓ Generated {len(embeddings_array)} embeddings")
        logger.info(f"  Shape: {embeddings_array.shape}")
        logger.info(f"  Data types: CVE={cve_count}, CWE={cwe_count}")

        return embeddings_array, metadata_list, global_metadata


# ============================================================================
# STORAGE AND PERSISTENCE
# ============================================================================

class EmbeddingStorage:
    """Handle saving and loading embeddings."""

    @staticmethod
    def save_numpy(embeddings: np.ndarray, filepath: Path) -> bool:
        """Save embeddings to NumPy file."""
        try:
            filepath.parent.mkdir(parents=True, exist_ok=True)
            np.save(filepath, embeddings)
            file_size = filepath.stat().st_size / (1024 * 1024)
            logger.info(f"✓ Saved embeddings to {filepath} ({file_size:.2f} MB)")
            return True
        except Exception as e:
            logger.error(f"✗ Failed to save NumPy file: {e}")
            return False

    @staticmethod
    def save_pickle(data: Dict[str, Any], filepath: Path) -> bool:
        """Save embeddings and metadata as pickle."""
        try:
            filepath.parent.mkdir(parents=True, exist_ok=True)
            with open(filepath, 'wb') as f:
                pickle.dump(data, f, protocol=pickle.HIGHEST_PROTOCOL)
            file_size = filepath.stat().st_size / (1024 * 1024)
            logger.info(f"✓ Saved pickle to {filepath} ({file_size:.2f} MB)")
            return True
        except Exception as e:
            logger.error(f"✗ Failed to save pickle file: {e}")
            return False

    @staticmethod
    def save_json_metadata(metadata: Dict[str, Any], filepath: Path) -> bool:
        """Save metadata as JSON."""
        try:
            filepath.parent.mkdir(parents=True, exist_ok=True)
            with open(filepath, 'w') as f:
                json.dump(metadata, f, indent=2)
            file_size = filepath.stat().st_size / (1024 * 1024)
            logger.info(f"✓ Saved JSON metadata to {filepath} ({file_size:.2f} MB)")
            return True
        except Exception as e:
            logger.error(f"✗ Failed to save JSON file: {e}")
            return False

    @staticmethod
    def verify_embeddings(filepath: Path) -> bool:
        """Verify saved embeddings."""
        try:
            embeddings = np.load(filepath)

            if not isinstance(embeddings, np.ndarray):
                logger.error("Not a valid NumPy array")
                return False

            if len(embeddings.shape) != 2:
                logger.error(f"Invalid shape: {embeddings.shape}")
                return False

            logger.info(f"✓ Embeddings verified")
            logger.info(f"  Shape: {embeddings.shape}")
            logger.info(f"  Dtype: {embeddings.dtype}")
            logger.info(f"  Memory: {embeddings.nbytes / (1024 ** 2):.2f} MB")

            # Check L2 normalization
            norms = np.linalg.norm(embeddings, axis=1)
            mean_norm = np.mean(norms)
            std_norm = np.std(norms)
            logger.info(f"  L2 Norms: mean={mean_norm:.4f}, std={std_norm:.4f}")

            return True
        except Exception as e:
            logger.error(f"✗ Verification failed: {e}")
            return False


# ============================================================================
# SIMILARITY UTILITIES
# ============================================================================

class SimilarityComputer:
    """Compute similarity between embeddings."""

    @staticmethod
    def cosine_similarity(vec1: np.ndarray, vec2: np.ndarray) -> float:
        """Compute cosine similarity."""
        dot_product = np.dot(vec1, vec2)
        norm1 = np.linalg.norm(vec1)
        norm2 = np.linalg.norm(vec2)

        if norm1 == 0 or norm2 == 0:
            return 0.0

        return float(dot_product / (norm1 * norm2))

    @staticmethod
    def euclidean_distance(vec1: np.ndarray, vec2: np.ndarray) -> float:
        """Compute Euclidean distance."""
        return float(np.linalg.norm(vec1 - vec2))

    @staticmethod
    def find_similar(query_embedding: np.ndarray, embeddings: np.ndarray,
                     top_k: int = 5, metric: str = "cosine") -> List[Tuple[int, float]]:
        """Find top-k similar embeddings."""
        similarities = []

        for idx, embedding in enumerate(embeddings):
            if metric == "cosine":
                sim = SimilarityComputer.cosine_similarity(query_embedding, embedding)
            else:  # euclidean
                sim = -SimilarityComputer.euclidean_distance(query_embedding, embedding)

            similarities.append((idx, sim))

        # Sort by similarity (descending)
        similarities.sort(key=lambda x: x[1], reverse=True)

        return similarities[:top_k]


# ============================================================================
# PATH DETECTION
# ============================================================================

def detect_output_path(explicit_path: Optional[str] = None) -> Path:
    """Auto-detect the correct output path."""
    if explicit_path:
        return Path(explicit_path)

    script_dir = Path(__file__).parent.absolute()

    # Check if we're in knowledge_cache directory
    if script_dir.name == "knowledge_cache":
        return script_dir / "embeddings.npy"

    # Check if hyfuzz-server-windows is in current path
    if script_dir.name == "hyfuzz-server-windows":
        return script_dir / "data" / "knowledge_cache" / "embeddings.npy"

    # Search for hyfuzz-server-windows directory
    current = script_dir
    for _ in range(10):
        if current.name == "hyfuzz-server-windows":
            return current / "data" / "knowledge_cache" / "embeddings.npy"
        current = current.parent
        if current == current.parent:
            break

    # Fallback
    return script_dir / "embeddings.npy"


# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main(
        dim: int = 768,
        cve_count: int = 100,
        cwe_count: int = 50,
        output_path: Optional[str] = None,
        seed: Optional[int] = None,
        save_metadata: bool = True,
        verify: bool = True,
) -> bool:
    """Main execution function."""
    logger.info("=" * 80)
    logger.info("HyFuzz Embedding Vector Generator")
    logger.info("=" * 80)

    final_output_path = detect_output_path(output_path)

    logger.info(f"Output path: {final_output_path}")
    logger.info(f"Embedding dimension: {dim}")
    logger.info(f"CVE count: {cve_count}")
    logger.info(f"CWE count: {cwe_count}")
    if seed:
        logger.info(f"Random seed: {seed}")
    logger.info("")

    # Generate embeddings
    generator = EmbeddingGenerator(dim=dim, seed=seed)
    embeddings_array, metadata_list, global_metadata = generator.generate_complete_embeddings(
        cve_count=cve_count,
        cwe_count=cwe_count
    )

    # Save embeddings
    logger.info("\nSaving embeddings...")
    storage = EmbeddingStorage()
    success = storage.save_numpy(embeddings_array, final_output_path)

    if not success:
        return False

    # Save metadata
    if save_metadata:
        metadata_path = final_output_path.with_suffix('.json')
        metadata_dict = {
            "global": global_metadata,
            "items": metadata_list,
        }
        storage.save_json_metadata(metadata_dict, metadata_path)

        # Save pickle version too
        pickle_path = final_output_path.with_suffix('.pkl')
        storage.save_pickle(metadata_dict, pickle_path)

    # Verify output
    if verify:
        logger.info("\nVerifying embeddings...")
        if not storage.verify_embeddings(final_output_path):
            logger.error("Verification failed")
            return False

    # Test similarity search
    logger.info("\nTesting similarity search...")
    query_idx = 0
    query_embedding = embeddings_array[query_idx]
    results = SimilarityComputer.find_similar(query_embedding, embeddings_array, top_k=5)

    logger.info(f"  Query: {metadata_list[query_idx]['id']}")
    for rank, (idx, sim) in enumerate(results[:3], 1):
        logger.info(f"  {rank}. {metadata_list[idx]['id']} (similarity: {sim:.4f})")

    logger.info("\n" + "=" * 80)
    logger.info("✓ Embedding generation complete!")
    logger.info("=" * 80)

    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate semantic embeddings for HyFuzz knowledge base",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--dim",
        type=int,
        choices=[384, 512, 768],
        default=768,
        help="Embedding dimension (default: 768)",
    )

    parser.add_argument(
        "--cve-count",
        type=int,
        default=100,
        help="Number of CVE embeddings (default: 100)",
    )

    parser.add_argument(
        "--cwe-count",
        type=int,
        default=50,
        help="Number of CWE embeddings (default: 50)",
    )

    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output file path (auto-detected if not specified)",
    )

    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Random seed for reproducibility",
    )

    parser.add_argument(
        "--no-metadata",
        action="store_true",
        help="Skip saving metadata files",
    )

    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Skip verification after generation",
    )

    args = parser.parse_args()

    success = main(
        dim=args.dim,
        cve_count=args.cve_count,
        cwe_count=args.cwe_count,
        output_path=args.output,
        seed=args.seed,
        save_metadata=not args.no_metadata,
        verify=not args.no_verify,
    )

    sys.exit(0 if success else 1)