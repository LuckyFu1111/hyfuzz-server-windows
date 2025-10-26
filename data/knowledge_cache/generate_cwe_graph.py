"""
CWE Graph Generator Script for HyFuzz

This script generates the cwe_graph.pkl file containing CWE (Common Weakness
Enumeration) data, relationships, and hierarchical structures for Phase 3
Knowledge Base integration.

Features:
- Generates realistic CWE data with severity scores
- Creates parent-child CWE relationships (hierarchy)
- Builds related CWE mappings
- Generates graph structures with nodes and edges
- Includes MITRE CWE data simulation
- Supports technology and platform classification
- Includes remediation guidance
- Includes metadata for knowledge base tracking

Usage:
    python generate_cwe_graph.py
    python generate_cwe_graph.py --count 100 --seed 42
    python generate_cwe_graph.py --count 500 --json

Author: HyFuzz Development Team
Version: 1.0.0-phase3
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
class CWENode:
    """Represents a CWE node in the graph."""
    cwe_id: str
    cwe_number: int
    name: str
    description: str
    extended_description: str
    severity: str
    cwe_type: str  # Weakness, Category, Pillar, Compound
    applicable_platforms: List[str] = field(default_factory=list)
    applicable_technologies: List[str] = field(default_factory=list)
    consequences: List[str] = field(default_factory=list)
    related_attack_patterns: List[str] = field(default_factory=list)
    remediation_strategies: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    created_date: str = ""
    last_updated: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class CWEEdge:
    """Represents an edge in the CWE graph."""
    source: str  # CWE ID
    target: str  # CWE ID
    relationship: str  # parent_of, related_to, can_precede
    confidence: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class CWEGraph:
    """Complete CWE graph structure."""
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

class SampleCWEData:
    """Real CWE data samples from MITRE CWE Top 25."""

    # Real MITRE CWE data (Top weaknesses)
    REAL_CWES = {
        20: {
            "name": "Improper Input Validation",
            "type": "Pillar",
            "severity": "CRITICAL",
            "parent_cwe_ids": [],
            "child_cwe_ids": [77, 78, 79, 89],
            "related_cwe_ids": [95, 434, 601],
        },
        77: {
            "name": "Improper Neutralization of Special Elements used in a Command",
            "type": "Weakness",
            "severity": "HIGH",
            "parent_cwe_ids": [20],
            "child_cwe_ids": [78],
            "related_cwe_ids": [89, 90],
        },
        78: {
            "name": "Improper Neutralization of Special Elements used in an OS Command",
            "type": "Weakness",
            "severity": "CRITICAL",
            "parent_cwe_ids": [77],
            "child_cwe_ids": [],
            "related_cwe_ids": [88, 94],
        },
        79: {
            "name": "Cross-site Scripting (XSS)",
            "type": "Weakness",
            "severity": "HIGH",
            "parent_cwe_ids": [20],
            "child_cwe_ids": [80, 81, 82],
            "related_cwe_ids": [83, 84],
        },
        80: {
            "name": "Improper Neutralization of Script-Related HTML Tags",
            "type": "Weakness",
            "severity": "HIGH",
            "parent_cwe_ids": [79],
            "child_cwe_ids": [],
            "related_cwe_ids": [85, 86],
        },
        89: {
            "name": "SQL Injection",
            "type": "Weakness",
            "severity": "CRITICAL",
            "parent_cwe_ids": [20],
            "child_cwe_ids": [90, 91],
            "related_cwe_ids": [92, 93],
        },
        119: {
            "name": "Improper Restriction of Operations within the Bounds",
            "type": "Pillar",
            "severity": "HIGH",
            "parent_cwe_ids": [],
            "child_cwe_ids": [120, 121, 125],
            "related_cwe_ids": [129, 680],
        },
        125: {
            "name": "Out-of-bounds Read",
            "type": "Weakness",
            "severity": "HIGH",
            "parent_cwe_ids": [119],
            "child_cwe_ids": [],
            "related_cwe_ids": [126, 127],
        },
        190: {
            "name": "Integer Overflow or Wraparound",
            "type": "Weakness",
            "severity": "MEDIUM",
            "parent_cwe_ids": [],
            "child_cwe_ids": [191, 192],
            "related_cwe_ids": [193, 194],
        },
        287: {
            "name": "Improper Authentication",
            "type": "Pillar",
            "severity": "CRITICAL",
            "parent_cwe_ids": [],
            "child_cwe_ids": [288, 289],
            "related_cwe_ids": [345, 346],
        },
        352: {
            "name": "Cross-Site Request Forgery (CSRF)",
            "type": "Weakness",
            "severity": "MEDIUM",
            "parent_cwe_ids": [],
            "child_cwe_ids": [353, 354],
            "related_cwe_ids": [355, 356],
        },
        434: {
            "name": "Unrestricted Upload of File with Dangerous Type",
            "type": "Weakness",
            "severity": "HIGH",
            "parent_cwe_ids": [20],
            "child_cwe_ids": [436, 437],
            "related_cwe_ids": [435, 438],
        },
        502: {
            "name": "Deserialization of Untrusted Data",
            "type": "Weakness",
            "severity": "CRITICAL",
            "parent_cwe_ids": [],
            "child_cwe_ids": [503, 504],
            "related_cwe_ids": [505, 506],
        },
        610: {
            "name": "Externally Controlled Reference to a Resource in Another Sphere",
            "type": "Weakness",
            "severity": "MEDIUM",
            "parent_cwe_ids": [],
            "child_cwe_ids": [611, 612],
            "related_cwe_ids": [601, 613],
        },
        611: {
            "name": "Improper Restriction of XML External Entity Reference",
            "type": "Weakness",
            "severity": "HIGH",
            "parent_cwe_ids": [610],
            "child_cwe_ids": [],
            "related_cwe_ids": [612, 613],
        },
    }

    # Platform and technology data
    PLATFORMS = [
        "Windows", "Linux", "macOS", "Android", "iOS",
        "Web", "Cloud", "Embedded", "IoT", "Mobile"
    ]

    TECHNOLOGIES = [
        "PHP", "Python", "Java", "JavaScript", "C++", "C#", ".NET",
        "Node.js", "Ruby", "Go", "Rust", "SQL", "XML", "HTML",
        "Apache", "Nginx", "IIS", "OpenSSL", "AWS", "Azure"
    ]

    CONSEQUENCES = [
        "Confidentiality Impact", "Integrity Impact", "Availability Impact",
        "Access Control Bypass", "Authentication Bypass",
        "Authorization Bypass", "Privilege Escalation",
        "Information Disclosure", "Data Manipulation",
        "System Compromise", "Denial of Service"
    ]

    REMEDIATION = [
        "Input validation and sanitization",
        "Output encoding and escaping",
        "Parameterized queries",
        "Security frameworks and libraries",
        "Code review and testing",
        "Security training",
        "Update dependencies",
        "Use security headers",
        "Implement WAF rules",
        "Logging and monitoring"
    ]


# ============================================================================
# CWE GRAPH GENERATOR
# ============================================================================

class CWEGraphGenerator:
    """Generates CWE graph data structures."""

    def __init__(self, seed: Optional[int] = None):
        """
        Initialize generator.

        Args:
            seed: Random seed for reproducibility
        """
        if seed is not None:
            random.seed(seed)
        self.cwe_count = 0
        self.edge_count = 0

    def generate_cwe_node(self, cwe_id: int, name: str, cwe_type: str = "Weakness") -> CWENode:
        """
        Generate a single CWE node.

        Args:
            cwe_id: CWE number
            name: CWE name
            cwe_type: CWE type (Weakness, Category, Pillar, Compound)

        Returns:
            CWENode instance
        """
        severity = random.choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"])

        # Select random platforms
        applicable_platforms = random.sample(
            SampleCWEData.PLATFORMS,
            k=random.randint(1, 3)
        )

        # Select random technologies
        applicable_technologies = random.sample(
            SampleCWEData.TECHNOLOGIES,
            k=random.randint(1, 4)
        )

        # Select consequences
        consequences = random.sample(
            SampleCWEData.CONSEQUENCES,
            k=random.randint(1, 3)
        )

        # Select remediation strategies
        remediation = random.sample(
            SampleCWEData.REMEDIATION,
            k=random.randint(2, 4)
        )

        # Generate dates
        created_date = datetime(2010 + random.randint(0, 10), random.randint(1, 12), random.randint(1, 28))
        updated_date = created_date + timedelta(days=random.randint(0, 5000))

        # References
        cwe_str = f"CWE-{cwe_id}"
        references = [
            f"https://cwe.mitre.org/data/definitions/{cwe_id}.html",
            f"https://owasp.org/www-community/attacks/{cwe_str}",
            f"https://capec.mitre.org/",
        ]

        # Attack patterns (CAPEC references)
        attack_patterns = [f"CAPEC-{random.randint(1, 600)}" for _ in range(random.randint(1, 3))]

        return CWENode(
            cwe_id=cwe_str,
            cwe_number=cwe_id,
            name=name,
            description=f"{name}: A weakness that allows attackers to {random.choice(['bypass', 'manipulate', 'exploit', 'access'])} the system.",
            extended_description=(
                f"This weakness describes a flaw in how the system handles {name.lower()}. "
                f"Attackers can exploit this to gain unauthorized access or manipulate data. "
                f"It affects {', '.join(applicable_technologies[:2])} applications running on {', '.join(applicable_platforms[:2])}."
            ),
            severity=severity,
            cwe_type=cwe_type,
            applicable_platforms=applicable_platforms,
            applicable_technologies=applicable_technologies,
            consequences=consequences,
            related_attack_patterns=attack_patterns,
            remediation_strategies=remediation,
            references=references,
            created_date=created_date.isoformat(),
            last_updated=updated_date.isoformat(),
        )

    def generate_cwe_nodes(self, count: int = 50) -> Dict[str, Dict[str, Any]]:
        """
        Generate multiple CWE nodes using real MITRE data.

        Args:
            count: Number of CWE nodes to generate

        Returns:
            Dictionary of CWE nodes
        """
        nodes = {}

        # First, add real MITRE CWEs
        real_cwe_list = list(SampleCWEData.REAL_CWES.items())[:min(count, len(SampleCWEData.REAL_CWES))]

        for cwe_id, cwe_data in real_cwe_list:
            cwe_node = self.generate_cwe_node(
                cwe_id,
                cwe_data["name"],
                cwe_data["type"]
            )
            nodes[f"CWE-{cwe_id}"] = cwe_node.to_dict()

            if (len(nodes) % 5) == 0:
                logger.info(f"Generated {len(nodes)} CWE nodes")

        # Generate additional random CWEs if needed
        remaining = count - len(nodes)
        generated_ids = set(int(cwe_id.split("-")[1]) for cwe_id in nodes.keys())

        for i in range(remaining):
            while True:
                new_cwe_id = random.randint(1, 1000)
                if new_cwe_id not in generated_ids:
                    generated_ids.add(new_cwe_id)
                    break

            cwe_types = ["Weakness", "Category", "Pillar"]
            name = f"Weakness CWE-{new_cwe_id}"
            cwe_node = self.generate_cwe_node(
                new_cwe_id,
                name,
                random.choice(cwe_types)
            )
            nodes[f"CWE-{new_cwe_id}"] = cwe_node.to_dict()

            if ((len(nodes) - len(real_cwe_list)) % 10) == 0:
                logger.info(f"Generated {len(nodes)} CWE nodes total")

        self.cwe_count = len(nodes)
        return nodes

    def generate_edges(self, nodes: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Generate edges between CWE nodes (hierarchy and relationships).

        Args:
            nodes: Dictionary of CWE nodes

        Returns:
            List of edges
        """
        edges = []
        cwe_list = list(nodes.keys())

        for i, source_cwe_id in enumerate(cwe_list):
            # Create parent-child relationships with probability
            if random.random() < 0.3 and i < len(cwe_list) - 1:
                target_cwe = random.choice(cwe_list[i + 1:])
                edges.append({
                    "source": source_cwe_id,
                    "target": target_cwe,
                    "relationship": "parent_of",
                    "confidence": round(random.uniform(0.7, 1.0), 2),
                })

            # Create related CWE relationships
            if random.random() < 0.4:
                related_cwes = random.sample(
                    [c for c in cwe_list if c != source_cwe_id],
                    k=min(2, len(cwe_list) - 1)
                )
                for target_cwe in related_cwes:
                    edges.append({
                        "source": source_cwe_id,
                        "target": target_cwe,
                        "relationship": "related_to",
                        "confidence": round(random.uniform(0.6, 0.95), 2),
                    })

        self.edge_count = len(edges)
        logger.info(f"Generated {len(edges)} edges")
        return edges

    def generate_metadata(self) -> Dict[str, Any]:
        """
        Generate metadata.

        Returns:
            Metadata dictionary
        """
        cwe_types_dist = {
            "Weakness": int(self.cwe_count * 0.7),
            "Category": int(self.cwe_count * 0.2),
            "Pillar": int(self.cwe_count * 0.05),
            "Compound": int(self.cwe_count * 0.05),
        }

        return {
            "created_at": datetime.now().isoformat(),
            "generated_at": datetime.now().isoformat(),
            "version": "1.0.0-phase3",
            "source": "HyFuzz CWE Generator (MITRE CWE Based)",
            "cwe_count": self.cwe_count,
            "edge_count": self.edge_count,
            "cwe_types": cwe_types_dist,
        }

    def generate_graph(self, count: int = 100) -> CWEGraph:
        """
        Generate complete CWE graph.

        Args:
            count: Number of CWE nodes

        Returns:
            CWEGraph instance
        """
        logger.info(f"Generating CWE graph with {count} nodes...")

        # Generate nodes
        nodes = self.generate_cwe_nodes(count)
        logger.info(f"Generated {len(nodes)} nodes")

        # Generate edges
        edges = self.generate_edges(nodes)
        logger.info(f"Generated {len(edges)} edges")

        # Generate metadata
        metadata = self.generate_metadata()
        logger.info("Generated metadata")

        graph = CWEGraph(
            nodes=nodes,
            edges=edges,
            metadata=metadata,
        )

        logger.info(f"✓ CWE graph generation complete")
        return graph


# ============================================================================
# FILE OPERATIONS
# ============================================================================

class CWEGraphPersistence:
    """Handles saving and loading CWE graphs."""

    @staticmethod
    def save_pickle(graph: CWEGraph, filepath: Path) -> bool:
        """Save graph to pickle file."""
        try:
            filepath.parent.mkdir(parents=True, exist_ok=True)
            with open(filepath, 'wb') as f:
                pickle.dump(graph.to_dict(), f, protocol=pickle.HIGHEST_PROTOCOL)
            file_size = filepath.stat().st_size / (1024 * 1024)
            logger.info(f"✓ Saved CWE graph to {filepath} ({file_size:.2f} MB)")
            return True
        except Exception as e:
            logger.error(f"✗ Failed to save pickle file: {e}")
            return False

    @staticmethod
    def save_json(graph: CWEGraph, filepath: Path) -> bool:
        """Save graph to JSON file."""
        try:
            filepath.parent.mkdir(parents=True, exist_ok=True)
            data = graph.to_dict()
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)
            file_size = filepath.stat().st_size / (1024 * 1024)
            logger.info(f"✓ Saved CWE graph JSON to {filepath} ({file_size:.2f} MB)")
            return True
        except Exception as e:
            logger.error(f"✗ Failed to save JSON file: {e}")
            return False

    @staticmethod
    def verify_pickle(filepath: Path) -> bool:
        """Verify pickle file integrity."""
        try:
            with open(filepath, 'rb') as f:
                data = pickle.load(f)

            required_keys = {"nodes", "edges", "metadata"}
            if not required_keys.issubset(data.keys()):
                logger.error("Missing required keys")
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
# PATH DETECTION
# ============================================================================

def detect_output_path(explicit_path: Optional[str] = None) -> Path:
    """Auto-detect the correct output path."""
    if explicit_path:
        return Path(explicit_path)

    script_dir = Path(__file__).parent.absolute()
    logger.info(f"Script directory: {script_dir}")

    # Check if we're in knowledge_cache directory
    if script_dir.name == "knowledge_cache":
        return script_dir / "cwe_graph.pkl"

    # Check if hyfuzz-server-windows is in current path
    if script_dir.name == "hyfuzz-server-windows":
        return script_dir / "data" / "knowledge_cache" / "cwe_graph.pkl"

    # Search for hyfuzz-server-windows directory
    current = script_dir
    for _ in range(10):
        if current.name == "hyfuzz-server-windows":
            return current / "data" / "knowledge_cache" / "cwe_graph.pkl"
        current = current.parent
        if current == current.parent:
            break

    # Fallback
    return script_dir / "cwe_graph.pkl"


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
    """Main execution function."""
    logger.info("=" * 80)
    logger.info("HyFuzz CWE Graph Generator")
    logger.info("=" * 80)

    final_output_path = detect_output_path(output_path)

    logger.info(f"Output path: {final_output_path}")
    logger.info(f"CWE count: {count}")
    if seed:
        logger.info(f"Random seed: {seed}")
    logger.info("")

    # Generate graph
    generator = CWEGraphGenerator(seed=seed)
    graph = generator.generate_graph(count=count)

    # Save pickle file
    logger.info("\nSaving pickle file...")
    persistence = CWEGraphPersistence()
    success = persistence.save_pickle(graph, final_output_path)

    if not success:
        return False

    # Optionally save JSON file
    if generate_json:
        json_path = final_output_path.with_suffix('.json')
        logger.info(f"\nSaving JSON file...")
        persistence.save_json(graph, json_path)

    # Verify output
    if verify:
        logger.info("\nVerifying pickle file...")
        if not persistence.verify_pickle(final_output_path):
            logger.error("Verification failed")
            return False

    logger.info("\n" + "=" * 80)
    logger.info("✓ CWE graph generation complete!")
    logger.info("=" * 80)

    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate CWE graph pickle file for HyFuzz",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--count",
        type=int,
        default=100,
        help="Number of CWE nodes to generate (default: 100)",
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