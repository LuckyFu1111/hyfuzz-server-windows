"""
CVE Graph Generator Script for HyFuzz - FIXED VERSION

This script generates the cve_graph.pkl file containing CVE vulnerability data,
relationships, and graph structures for Phase 3 Knowledge Base integration.

FIXED: Path handling to work from any directory

Features:
- Generates realistic CVE data with CVSS scores and severity levels
- Creates CVE-to-CWE relationships (vulnerability to weakness mappings)
- Builds graph structures with nodes and edges
- Supports both in-memory and pickled storage
- Includes metadata for knowledge base tracking
- Handles batch processing for large datasets
- Smart path detection (works from any directory)

Usage:
    # From project root
    python generate_cve_graph.py
    python generate_cve_graph.py --count 1000

    # From anywhere with explicit path
    python generate_cve_graph.py --output /path/to/cve_graph.pkl

    # With options
    python generate_cve_graph.py --count 5000 --seed 42 --json

Author: HyFuzz Development Team
Version: 1.0.1-FIXED
License: MIT
"""

import pickle
import json
import sys
import argparse
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict, field
import random
import logging

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
# DATA CLASSES
# ============================================================================

@dataclass
class CVENode:
    """Represents a CVE node in the graph."""
    cve_id: str
    title: str
    description: str
    severity: str
    cvss_v3_score: Optional[float] = None
    cvss_v2_score: Optional[float] = None
    publish_date: str = ""
    update_date: str = ""
    affected_products: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class CVEEdge:
    """Represents an edge in the CVE graph."""
    source: str      # CVE ID
    target: str      # CWE ID
    relationship: str
    confidence: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class CVEGraph:
    """Complete CVE graph structure."""
    nodes: Dict[str, Dict[str, Any]]
    edges: List[Dict[str, Any]]
    metadata: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "nodes": self.nodes,
            "edges": self.edges,
            "metadata": self.metadata,
        }


# ============================================================================
# SAMPLE DATA
# ============================================================================

class SampleCVEData:
    """Sample CVE data for testing and development."""

    # Sample CWE IDs for relationships
    CWE_IDS = [
        "CWE-20",   # Improper Input Validation
        "CWE-79",   # Cross-site Scripting (XSS)
        "CWE-89",   # SQL Injection
        "CWE-119",  # Buffer Overflow
        "CWE-125",  # Out-of-bounds Read
        "CWE-190",  # Integer Overflow
        "CWE-287",  # Improper Authentication
        "CWE-352",  # CSRF
        "CWE-434",  # Unrestricted File Upload
        "CWE-502",  # Deserialization of Untrusted Data
    ]

    # Sample products/components
    PRODUCTS = [
        "Apache HTTP Server",
        "Nginx",
        "OpenSSL",
        "PHP",
        "Python",
        "Java",
        "Node.js",
        "Windows",
        "Linux Kernel",
        "Google Chrome",
        "Firefox",
        "PostgreSQL",
        "MySQL",
        "MongoDB",
    ]

    # Sample vulnerability types
    VULN_TYPES = [
        "Remote Code Execution (RCE)",
        "Cross-site Scripting (XSS)",
        "SQL Injection",
        "Buffer Overflow",
        "Denial of Service (DoS)",
        "Authentication Bypass",
        "Privilege Escalation",
        "Information Disclosure",
        "Path Traversal",
        "XXE Injection",
        "SSRF",
        "Insecure Deserialization",
    ]


# ============================================================================
# CVE GRAPH GENERATOR
# ============================================================================

class CVEGraphGenerator:
    """Generates CVE graph data structures."""

    def __init__(self, seed: Optional[int] = None):
        """
        Initialize generator.

        Args:
            seed: Random seed for reproducibility
        """
        if seed is not None:
            random.seed(seed)
        self.cve_count = 0
        self.edge_count = 0

    def generate_cve_node(self, cve_id: str, year: int = 2023) -> CVENode:
        """
        Generate a single CVE node.

        Args:
            cve_id: CVE identifier
            year: CVE year

        Returns:
            CVENode instance
        """
        severity = random.choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])

        # CVSS scores typically range from 0 to 10
        cvss_v3_score = round(random.uniform(0, 10), 1)
        cvss_v2_score = round(random.uniform(0, 10), 1)

        # Random publish and update dates
        base_date = datetime(year, 1, 1)
        publish_offset = random.randint(0, 365)
        publish_date = base_date + timedelta(days=publish_offset)
        update_offset = random.randint(publish_offset, 365)
        update_date = base_date + timedelta(days=update_offset)

        # Select random products
        affected_products = random.sample(
            SampleCVEData.PRODUCTS,
            k=random.randint(1, 4)
        )

        # Select random CWEs
        cwe_ids = random.sample(
            SampleCVEData.CWE_IDS,
            k=random.randint(1, 3)
        )

        # Generate title and description
        vuln_type = random.choice(SampleCVEData.VULN_TYPES)
        product = random.choice(affected_products)

        title = f"{vuln_type} in {product}"
        description = (
            f"A {vuln_type} vulnerability was discovered in {product}. "
            f"This vulnerability allows attackers to execute arbitrary code "
            f"with {product} privileges. Affected versions: all versions before 2024. "
            f"Severity: {severity}. CVSS v3.1 Score: {cvss_v3_score}."
        )

        # Sample references
        references = [
            f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}",
            f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            f"https://security-tracker.debian.org/tracker/{cve_id}",
        ]

        return CVENode(
            cve_id=cve_id,
            title=title,
            description=description,
            severity=severity,
            cvss_v3_score=cvss_v3_score,
            cvss_v2_score=cvss_v2_score,
            publish_date=publish_date.isoformat(),
            update_date=update_date.isoformat(),
            affected_products=affected_products,
            cwe_ids=cwe_ids,
            references=references,
        )

    def generate_cve_nodes(self, count: int = 100) -> Dict[str, Dict[str, Any]]:
        """
        Generate multiple CVE nodes.

        Args:
            count: Number of CVE nodes to generate

        Returns:
            Dictionary of CVE nodes
        """
        nodes = {}

        for i in range(count):
            year = 2020 + (i % 5)  # Mix of years 2020-2024
            cve_id = f"CVE-{year}-{random.randint(10000, 99999)}"

            # Avoid duplicate CVE IDs
            while cve_id in nodes:
                cve_id = f"CVE-{year}-{random.randint(10000, 99999)}"

            node = self.generate_cve_node(cve_id, year)
            nodes[cve_id] = node.to_dict()

            if (i + 1) % 10 == 0:
                logger.info(f"Generated {i + 1}/{count} CVE nodes")

        self.cve_count = count
        return nodes

    def generate_edges(self, nodes: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Generate edges between CVE and CWE.

        Args:
            nodes: Dictionary of CVE nodes

        Returns:
            List of edges
        """
        edges = []

        for cve_id, cve_data in nodes.items():
            # Get CWE IDs from the CVE node
            cwe_ids = cve_data.get("cwe_ids", [])

            for cwe_id in cwe_ids:
                edge = {
                    "source": cve_id,
                    "target": cwe_id,
                    "relationship": "exploits",
                    "confidence": round(random.uniform(0.7, 1.0), 2),
                }
                edges.append(edge)

        self.edge_count = len(edges)
        logger.info(f"Generated {len(edges)} edges")
        return edges

    def generate_metadata(self) -> Dict[str, Any]:
        """
        Generate metadata.

        Returns:
            Metadata dictionary
        """
        # Calculate severity distribution
        severity_dist = {
            "CRITICAL": int(self.cve_count * 0.1),
            "HIGH": int(self.cve_count * 0.2),
            "MEDIUM": int(self.cve_count * 0.35),
            "LOW": int(self.cve_count * 0.25),
            "INFO": int(self.cve_count * 0.1),
        }

        return {
            "created_at": datetime.now().isoformat(),
            "generated_at": datetime.now().isoformat(),
            "version": "1.0.1-phase3-fixed",
            "source": "HyFuzz CVE Generator",
            "cve_count": self.cve_count,
            "edge_count": self.edge_count,
            "cwe_count": len(SampleCVEData.CWE_IDS),
            "severity_distribution": severity_dist,
        }

    def generate_graph(self, count: int = 100) -> CVEGraph:
        """
        Generate complete CVE graph.

        Args:
            count: Number of CVE nodes

        Returns:
            CVEGraph instance
        """
        logger.info(f"Generating CVE graph with {count} nodes...")

        # Generate nodes
        nodes = self.generate_cve_nodes(count)
        logger.info(f"Generated {len(nodes)} nodes")

        # Generate edges
        edges = self.generate_edges(nodes)
        logger.info(f"Generated {len(edges)} edges")

        # Generate metadata
        metadata = self.generate_metadata()
        logger.info("Generated metadata")

        graph = CVEGraph(
            nodes=nodes,
            edges=edges,
            metadata=metadata,
        )

        logger.info(f"✓ CVE graph generation complete")
        return graph


# ============================================================================
# FILE OPERATIONS
# ============================================================================

class CVEGraphPersistence:
    """Handles saving and loading CVE graphs."""

    @staticmethod
    def save_pickle(
        graph: CVEGraph,
        filepath: Path,
        compression: bool = False,
    ) -> bool:
        """
        Save graph to pickle file.

        Args:
            graph: CVEGraph instance
            filepath: Output file path
            compression: Whether to use compression

        Returns:
            True if successful
        """
        try:
            filepath.parent.mkdir(parents=True, exist_ok=True)

            with open(filepath, 'wb') as f:
                pickle.dump(graph.to_dict(), f, protocol=pickle.HIGHEST_PROTOCOL)

            file_size = filepath.stat().st_size / (1024 * 1024)  # MB
            logger.info(f"✓ Saved CVE graph to {filepath} ({file_size:.2f} MB)")
            return True

        except Exception as e:
            logger.error(f"✗ Failed to save pickle file: {e}")
            return False

    @staticmethod
    def save_json(
        graph: CVEGraph,
        filepath: Path,
        pretty: bool = True,
    ) -> bool:
        """
        Save graph to JSON file (for inspection).

        Args:
            graph: CVEGraph instance
            filepath: Output file path
            pretty: Whether to pretty-print

        Returns:
            True if successful
        """
        try:
            filepath.parent.mkdir(parents=True, exist_ok=True)

            data = graph.to_dict()
            with open(filepath, 'w') as f:
                if pretty:
                    json.dump(data, f, indent=2)
                else:
                    json.dump(data, f)

            file_size = filepath.stat().st_size / (1024 * 1024)  # MB
            logger.info(f"✓ Saved CVE graph JSON to {filepath} ({file_size:.2f} MB)")
            return True

        except Exception as e:
            logger.error(f"✗ Failed to save JSON file: {e}")
            return False

    @staticmethod
    def load_pickle(filepath: Path) -> Optional[Dict[str, Any]]:
        """
        Load graph from pickle file.

        Args:
            filepath: Input file path

        Returns:
            Graph dictionary or None
        """
        try:
            with open(filepath, 'rb') as f:
                data = pickle.load(f)

            logger.info(f"✓ Loaded CVE graph from {filepath}")
            return data

        except Exception as e:
            logger.error(f"✗ Failed to load pickle file: {e}")
            return None

    @staticmethod
    def verify_pickle(filepath: Path) -> bool:
        """
        Verify pickle file integrity.

        Args:
            filepath: Pickle file path

        Returns:
            True if valid
        """
        try:
            data = CVEGraphPersistence.load_pickle(filepath)

            if data is None:
                return False

            # Check required keys
            required_keys = {"nodes", "edges", "metadata"}
            if not required_keys.issubset(data.keys()):
                logger.error(f"Missing required keys in pickle file")
                return False

            # Check data structure
            if not isinstance(data["nodes"], dict):
                logger.error("Nodes should be a dictionary")
                return False

            if not isinstance(data["edges"], list):
                logger.error("Edges should be a list")
                return False

            if not isinstance(data["metadata"], dict):
                logger.error("Metadata should be a dictionary")
                return False

            logger.info(f"✓ Pickle file verified")
            logger.info(f"  Nodes: {len(data['nodes'])}")
            logger.info(f"  Edges: {len(data['edges'])}")
            logger.info(f"  Metadata: {len(data['metadata'])} keys")

            return True

        except Exception as e:
            logger.error(f"✗ Verification failed: {e}")
            return False


# ============================================================================
# PATH DETECTION (FIXED)
# ============================================================================

def detect_output_path(explicit_path: Optional[str] = None) -> Path:
    """
    Detect the correct output path automatically.

    FIXED: Works from any directory and avoids path duplication

    Args:
        explicit_path: Explicit path provided by user

    Returns:
        Path object for output file
    """
    if explicit_path:
        return Path(explicit_path)

    # Get script directory
    script_dir = Path(__file__).parent.absolute()
    logger.info(f"Script directory: {script_dir}")

    # Determine output location based on current directory structure
    possible_paths = [
        # Already in knowledge_cache directory
        script_dir / "cve_graph.pkl" if script_dir.name == "knowledge_cache" else None,

        # In hyfuzz-server-windows root
        script_dir / "data" / "knowledge_cache" / "cve_graph.pkl"
        if script_dir.name == "hyfuzz-server-windows" else None,

        # In project root (one level up)
        script_dir.parent / "hyfuzz-server-windows" / "data" / "knowledge_cache" / "cve_graph.pkl"
        if script_dir.parent.name != "hyfuzz-server-windows" else None,

        # Search up the tree for hyfuzz-server-windows
        None,  # Will handle with walk
    ]

    # Try each possible path
    for path in possible_paths:
        if path and path.parent.exists():
            logger.info(f"Using output path: {path}")
            return path

    # Fallback: search for hyfuzz-server-windows directory
    current = script_dir
    for _ in range(10):  # Search up to 10 levels
        if current.name == "hyfuzz-server-windows":
            output = current / "data" / "knowledge_cache" / "cve_graph.pkl"
            logger.info(f"Found hyfuzz-server-windows, using: {output}")
            return output
        current = current.parent
        if current == current.parent:  # Root directory
            break

    # Final fallback: use script directory
    output = script_dir / "cve_graph.pkl"
    logger.warning(f"Using fallback path: {output}")
    return output


# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main(
    count: int = 100,
    output_path: Optional[str] = None,
    seed: Optional[int] = None,
    generate_json: bool = False,
    verify: bool = True,
) -> bool:
    """
    Main execution function.

    Args:
        count: Number of CVE nodes to generate
        output_path: Output file path
        seed: Random seed
        generate_json: Whether to also generate JSON file
        verify: Whether to verify output

    Returns:
        True if successful
    """
    logger.info("=" * 80)
    logger.info("HyFuzz CVE Graph Generator (FIXED)")
    logger.info("=" * 80)

    # Auto-detect output path
    final_output_path = detect_output_path(output_path)

    logger.info(f"Output path: {final_output_path}")
    logger.info(f"CVE count: {count}")
    if seed:
        logger.info(f"Random seed: {seed}")
    logger.info("")

    # Generate graph
    generator = CVEGraphGenerator(seed=seed)
    graph = generator.generate_graph(count=count)

    # Save pickle file
    logger.info("\nSaving pickle file...")
    persistence = CVEGraphPersistence()
    success = persistence.save_pickle(graph, final_output_path, compression=False)

    if not success:
        return False

    # Optionally save JSON file
    if generate_json:
        json_path = final_output_path.with_suffix('.json')
        logger.info(f"\nSaving JSON file...")
        persistence.save_json(graph, json_path, pretty=True)

    # Verify output
    if verify:
        logger.info("\nVerifying pickle file...")
        if not persistence.verify_pickle(final_output_path):
            logger.error("Verification failed")
            return False

    logger.info("\n" + "=" * 80)
    logger.info("✓ CVE graph generation complete!")
    logger.info("=" * 80)

    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate CVE graph pickle file for HyFuzz",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Default (100 CVEs)
  python generate_cve_graph.py
  
  # Generate 1000 CVEs with seed
  python generate_cve_graph.py --count 1000 --seed 42
  
  # Generate and export JSON
  python generate_cve_graph.py --count 5000 --json
  
  # Custom output path
  python generate_cve_graph.py --output /custom/path/cve_graph.pkl
        """,
    )

    parser.add_argument(
        "--count",
        type=int,
        default=100,
        help="Number of CVE nodes to generate (default: 100)",
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
        "--json",
        action="store_true",
        help="Also generate JSON file for inspection",
    )

    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Skip verification after generation",
    )

    args = parser.parse_args()

    success = main(
        count=args.count,
        output_path=args.output,
        seed=args.seed,
        generate_json=args.json,
        verify=not args.no_verify,
    )

    sys.exit(0 if success else 1)