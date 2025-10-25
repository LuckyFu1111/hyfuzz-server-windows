"""
Knowledge Models - Vulnerability and Knowledge Base Data Models

This module contains data models for managing vulnerability and knowledge base
information in the HyFuzz Windows MCP Server, including CWE/CVE data, graph
structures, and risk assessments.

Models:
    - VulnerabilityData: Composite vulnerability information
    - CWEInfo: Common Weakness Enumeration information
    - CVEInfo: Common Vulnerabilities and Exposures information
    - CWENode: Graph node for CWE relationships
    - CVENode: Graph node for CVE relationships
    - KnowledgeGraph: Knowledge graph structure
    - RiskAssessment: Risk assessment results

Author: HyFuzz Team
Version: 1.0.0
"""

from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any, Set
from datetime import datetime, timezone
from enum import Enum
import json


# ============================================================================
# ENUMS
# ============================================================================

class SeverityLevel(str, Enum):
    """Enumeration of severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class VulnerabilityStatus(str, Enum):
    """Enumeration of vulnerability status."""
    DISCOVERED = "DISCOVERED"
    ANALYZED = "ANALYZED"
    EXPLOITED = "EXPLOITED"
    PATCHED = "PATCHED"
    DEPRECATED = "DEPRECATED"


# ============================================================================
# 1. CWEInfo DATA MODEL
# ============================================================================

@dataclass
class CWEInfo:
    """
    Common Weakness Enumeration (CWE) information.

    Attributes:
        cwe_id: CWE identifier (e.g., CWE-79)
        name: CWE name/title
        description: Detailed description
        severity: Severity level
        status: Status of the weakness
        related_cwe_ids: List of related CWE IDs
        affected_technologies: Technologies that can be affected
        consequence: Potential consequences of the weakness
        mitigation: Recommended mitigation strategies
        resources: External resources/references
        last_updated: Last update timestamp
    """
    cwe_id: str
    name: str
    description: str
    severity: SeverityLevel = SeverityLevel.MEDIUM
    status: VulnerabilityStatus = VulnerabilityStatus.DISCOVERED
    related_cwe_ids: List[str] = field(default_factory=list)
    affected_technologies: List[str] = field(default_factory=list)
    consequence: Optional[str] = None
    mitigation: Optional[str] = None
    resources: List[str] = field(default_factory=list)
    last_updated: Optional[datetime] = None

    def __post_init__(self):
        """Validate CWE data."""
        if not self.cwe_id.startswith("CWE-"):
            self.cwe_id = f"CWE-{self.cwe_id}"
        if self.last_updated is None:
            self.last_updated = datetime.now(timezone.utc)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "cwe_id": self.cwe_id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity.value,
            "status": self.status.value,
            "related_cwe_ids": self.related_cwe_ids,
            "affected_technologies": self.affected_technologies,
            "consequence": self.consequence,
            "mitigation": self.mitigation,
            "resources": self.resources,
            "last_updated": self.last_updated.isoformat() if self.last_updated else None
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'CWEInfo':
        """Create CWEInfo from dictionary."""
        return CWEInfo(
            cwe_id=data.get("cwe_id", ""),
            name=data.get("name", ""),
            description=data.get("description", ""),
            severity=SeverityLevel(data.get("severity", "MEDIUM")),
            status=VulnerabilityStatus(data.get("status", "DISCOVERED")),
            related_cwe_ids=data.get("related_cwe_ids", []),
            affected_technologies=data.get("affected_technologies", []),
            consequence=data.get("consequence"),
            mitigation=data.get("mitigation"),
            resources=data.get("resources", []),
            last_updated=datetime.fromisoformat(data.get("last_updated")) if data.get("last_updated") else None
        )


# ============================================================================
# 2. CVEInfo DATA MODEL
# ============================================================================

@dataclass
class CVEInfo:
    """
    Common Vulnerabilities and Exposures (CVE) information.

    Attributes:
        cve_id: CVE identifier (e.g., CVE-2021-1234)
        title: Vulnerability title
        description: Detailed description
        severity: CVSS severity score (0-10)
        affected_products: List of affected products/versions
        cwe_ids: Associated CWE IDs
        cvss_score: CVSS score
        cvss_vector: CVSS vector string
        published_date: Publication date
        modified_date: Last modification date
        exploited: Whether actively exploited
        attack_vector: Attack vector (e.g., network, local)
        mitigation: Mitigation information
        references: External references/links
    """
    cve_id: str
    title: str
    description: str
    severity: SeverityLevel = SeverityLevel.MEDIUM
    affected_products: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    cvss_score: float = 0.0
    cvss_vector: str = ""
    published_date: Optional[datetime] = None
    modified_date: Optional[datetime] = None
    exploited: bool = False
    attack_vector: str = "unknown"
    mitigation: Optional[str] = None
    references: List[str] = field(default_factory=list)

    def __post_init__(self):
        """Validate CVE data."""
        if not self.cve_id.startswith("CVE-"):
            self.cve_id = f"CVE-{self.cve_id}"
        if self.cvss_score < 0.0 or self.cvss_score > 10.0:
            self.cvss_score = 5.0
        if self.published_date is None:
            self.published_date = datetime.now(timezone.utc)
        if self.modified_date is None:
            self.modified_date = self.published_date

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "cve_id": self.cve_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "affected_products": self.affected_products,
            "cwe_ids": self.cwe_ids,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "published_date": self.published_date.isoformat() if self.published_date else None,
            "modified_date": self.modified_date.isoformat() if self.modified_date else None,
            "exploited": self.exploited,
            "attack_vector": self.attack_vector,
            "mitigation": self.mitigation,
            "references": self.references
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'CVEInfo':
        """Create CVEInfo from dictionary."""
        return CVEInfo(
            cve_id=data.get("cve_id", ""),
            title=data.get("title", ""),
            description=data.get("description", ""),
            severity=SeverityLevel(data.get("severity", "MEDIUM")),
            affected_products=data.get("affected_products", []),
            cwe_ids=data.get("cwe_ids", []),
            cvss_score=data.get("cvss_score", 0.0),
            cvss_vector=data.get("cvss_vector", ""),
            published_date=datetime.fromisoformat(data.get("published_date")) if data.get("published_date") else None,
            modified_date=datetime.fromisoformat(data.get("modified_date")) if data.get("modified_date") else None,
            exploited=data.get("exploited", False),
            attack_vector=data.get("attack_vector", "unknown"),
            mitigation=data.get("mitigation"),
            references=data.get("references", [])
        )


# ============================================================================
# 3. CWENode DATA MODEL
# ============================================================================

@dataclass
class CWENode:
    """
    Graph node representing a CWE in the knowledge graph.

    Attributes:
        cwe_id: CWE identifier
        cwe_info: Associated CWEInfo object
        parent_ids: Parent CWE IDs (more general weaknesses)
        child_ids: Child CWE IDs (more specific weaknesses)
        related_ids: Related CWE IDs (lateral relationships)
        occurrence_count: Number of times this CWE appears in CVEs
        confidence_score: Confidence score for this node (0-1)
    """
    cwe_id: str
    cwe_info: Optional[CWEInfo] = None
    parent_ids: Set[str] = field(default_factory=set)
    child_ids: Set[str] = field(default_factory=set)
    related_ids: Set[str] = field(default_factory=set)
    occurrence_count: int = 0
    confidence_score: float = 1.0

    def add_parent(self, parent_id: str) -> None:
        """Add parent CWE relationship."""
        self.parent_ids.add(parent_id)

    def add_child(self, child_id: str) -> None:
        """Add child CWE relationship."""
        self.child_ids.add(child_id)

    def add_related(self, related_id: str) -> None:
        """Add related CWE relationship."""
        self.related_ids.add(related_id)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "cwe_id": self.cwe_id,
            "cwe_info": self.cwe_info.to_dict() if self.cwe_info else None,
            "parent_ids": list(self.parent_ids),
            "child_ids": list(self.child_ids),
            "related_ids": list(self.related_ids),
            "occurrence_count": self.occurrence_count,
            "confidence_score": self.confidence_score
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2, default=str)


# ============================================================================
# 4. CVENode DATA MODEL
# ============================================================================

@dataclass
class CVENode:
    """
    Graph node representing a CVE in the knowledge graph.

    Attributes:
        cve_id: CVE identifier
        cve_info: Associated CVEInfo object
        cwe_nodes: Related CWE nodes
        severity_score: Calculated severity score (0-10)
        exploitability_score: Exploitability score (0-10)
        connected_cves: IDs of related CVEs
        confidence_score: Confidence score for this node (0-1)
    """
    cve_id: str
    cve_info: Optional[CVEInfo] = None
    cwe_nodes: List[str] = field(default_factory=list)
    severity_score: float = 5.0
    exploitability_score: float = 0.0
    connected_cves: Set[str] = field(default_factory=set)
    confidence_score: float = 1.0

    def add_cwe_node(self, cwe_id: str) -> None:
        """Add CWE node relationship."""
        if cwe_id not in self.cwe_nodes:
            self.cwe_nodes.append(cwe_id)

    def add_connected_cve(self, cve_id: str) -> None:
        """Add connected CVE relationship."""
        self.connected_cves.add(cve_id)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "cve_id": self.cve_id,
            "cve_info": self.cve_info.to_dict() if self.cve_info else None,
            "cwe_nodes": self.cwe_nodes,
            "severity_score": self.severity_score,
            "exploitability_score": self.exploitability_score,
            "connected_cves": list(self.connected_cves),
            "confidence_score": self.confidence_score
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2, default=str)


# ============================================================================
# 5. VulnerabilityData DATA MODEL
# ============================================================================

@dataclass
class VulnerabilityData:
    """
    Composite vulnerability data combining CVE and CWE information.

    Attributes:
        vulnerability_id: Unique identifier
        cve_info: Associated CVE information
        cwe_infos: Associated CWE information
        overall_severity: Overall severity assessment
        risk_score: Calculated risk score (0-100)
        affected_systems: List of affected systems/components
        discovered_date: Date of discovery
        patches_available: Whether patches are available
        remediation_steps: Recommended remediation steps
        related_advisories: Security advisories
        tags: Classification tags
    """
    vulnerability_id: str
    cve_info: Optional[CVEInfo] = None
    cwe_infos: List[CWEInfo] = field(default_factory=list)
    overall_severity: SeverityLevel = SeverityLevel.MEDIUM
    risk_score: float = 50.0
    affected_systems: List[str] = field(default_factory=list)
    discovered_date: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    patches_available: bool = False
    remediation_steps: List[str] = field(default_factory=list)
    related_advisories: List[str] = field(default_factory=list)
    tags: Set[str] = field(default_factory=set)

    def __post_init__(self):
        """Validate vulnerability data."""
        if self.risk_score < 0.0 or self.risk_score > 100.0:
            self.risk_score = 50.0

    def add_tag(self, tag: str) -> None:
        """Add classification tag."""
        self.tags.add(tag)

    def add_cwe(self, cwe_info: CWEInfo) -> None:
        """Add CWE information."""
        if cwe_info not in self.cwe_infos:
            self.cwe_infos.append(cwe_info)

    def add_remediation_step(self, step: str) -> None:
        """Add remediation step."""
        if step not in self.remediation_steps:
            self.remediation_steps.append(step)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "vulnerability_id": self.vulnerability_id,
            "cve_info": self.cve_info.to_dict() if self.cve_info else None,
            "cwe_infos": [cwe.to_dict() for cwe in self.cwe_infos],
            "overall_severity": self.overall_severity.value,
            "risk_score": self.risk_score,
            "affected_systems": self.affected_systems,
            "discovered_date": self.discovered_date.isoformat(),
            "patches_available": self.patches_available,
            "remediation_steps": self.remediation_steps,
            "related_advisories": self.related_advisories,
            "tags": list(self.tags)
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2, default=str)

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'VulnerabilityData':
        """Create VulnerabilityData from dictionary."""
        cve = CVEInfo.from_dict(data.get("cve_info")) if data.get("cve_info") else None
        cwes = [CWEInfo.from_dict(c) for c in data.get("cwe_infos", [])]

        return VulnerabilityData(
            vulnerability_id=data.get("vulnerability_id", ""),
            cve_info=cve,
            cwe_infos=cwes,
            overall_severity=SeverityLevel(data.get("overall_severity", "MEDIUM")),
            risk_score=data.get("risk_score", 50.0),
            affected_systems=data.get("affected_systems", []),
            discovered_date=datetime.fromisoformat(data.get("discovered_date")) if data.get("discovered_date") else datetime.now(timezone.utc),
            patches_available=data.get("patches_available", False),
            remediation_steps=data.get("remediation_steps", []),
            related_advisories=data.get("related_advisories", []),
            tags=set(data.get("tags", []))
        )


# ============================================================================
# 6. KnowledgeGraph DATA MODEL
# ============================================================================

@dataclass
class KnowledgeGraph:
    """
    Knowledge graph structure for managing CWE/CVE relationships.

    Attributes:
        name: Name of the knowledge graph
        version: Version of the graph
        cwe_nodes: Dictionary of CWE nodes
        cve_nodes: Dictionary of CVE nodes
        total_nodes: Total number of nodes
        total_edges: Total number of edges/relationships
        last_updated: Last update timestamp
    """
    name: str = "HyFuzz-Knowledge-Graph"
    version: str = "1.0.0"
    cwe_nodes: Dict[str, CWENode] = field(default_factory=dict)
    cve_nodes: Dict[str, CVENode] = field(default_factory=dict)
    total_nodes: int = 0
    total_edges: int = 0
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def add_cwe_node(self, node: CWENode) -> None:
        """Add CWE node to graph."""
        self.cwe_nodes[node.cwe_id] = node
        self.total_nodes += 1
        self.last_updated = datetime.now(timezone.utc)

    def add_cve_node(self, node: CVENode) -> None:
        """Add CVE node to graph."""
        self.cve_nodes[node.cve_id] = node
        self.total_nodes += 1
        self.last_updated = datetime.now(timezone.utc)

    def add_edge(self, from_id: str, to_id: str, edge_type: str = "related") -> bool:
        """Add edge between nodes. Returns True if successful."""
        # Check if from_id exists in cwe_nodes
        if from_id in self.cwe_nodes and to_id in self.cwe_nodes:
            if edge_type == "parent":
                self.cwe_nodes[from_id].add_parent(to_id)
            elif edge_type == "child":
                self.cwe_nodes[from_id].add_child(to_id)
            else:
                self.cwe_nodes[from_id].add_related(to_id)
            self.total_edges += 1
            return True
        return False

    def get_cwe_node(self, cwe_id: str) -> Optional[CWENode]:
        """Get CWE node by ID."""
        return self.cwe_nodes.get(cwe_id)

    def get_cve_node(self, cve_id: str) -> Optional[CVENode]:
        """Get CVE node by ID."""
        return self.cve_nodes.get(cve_id)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "name": self.name,
            "version": self.version,
            "cwe_nodes": {k: v.to_dict() for k, v in self.cwe_nodes.items()},
            "cve_nodes": {k: v.to_dict() for k, v in self.cve_nodes.items()},
            "total_nodes": self.total_nodes,
            "total_edges": self.total_edges,
            "last_updated": self.last_updated.isoformat()
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2, default=str)


# ============================================================================
# 7. RiskAssessment DATA MODEL
# ============================================================================

@dataclass
class RiskAssessment:
    """
    Risk assessment results for vulnerabilities.

    Attributes:
        assessment_id: Unique assessment identifier
        vulnerability_id: Associated vulnerability ID
        risk_level: Overall risk level
        likelihood_score: Likelihood of exploitation (0-10)
        impact_score: Impact if exploited (0-10)
        exploitability_score: Current exploitability (0-10)
        affected_count: Number of affected systems
        mitigation_score: Effectiveness of mitigations (0-10)
        recommendation: Risk mitigation recommendation
        priority: Priority level (Critical, High, Medium, Low)
        assessment_date: Assessment date
        reassessment_date: Next reassessment date
        details: Additional assessment details
    """
    assessment_id: str
    vulnerability_id: str
    risk_level: SeverityLevel = SeverityLevel.MEDIUM
    likelihood_score: float = 5.0
    impact_score: float = 5.0
    exploitability_score: float = 5.0
    affected_count: int = 0
    mitigation_score: float = 0.0
    recommendation: str = ""
    priority: str = "MEDIUM"
    assessment_date: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    reassessment_date: Optional[datetime] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Validate assessment data."""
        for score in [self.likelihood_score, self.impact_score,
                     self.exploitability_score, self.mitigation_score]:
            if score < 0.0 or score > 10.0:
                score = 5.0

    def calculate_risk_score(self) -> float:
        """Calculate overall risk score."""
        base_risk = (self.likelihood_score + self.impact_score +
                    self.exploitability_score) / 3.0
        mitigated_risk = base_risk * (1.0 - self.mitigation_score / 10.0)
        return round(mitigated_risk * 10, 2)

    def get_risk_level(self) -> SeverityLevel:
        """Get risk level based on scores."""
        risk_score = self.calculate_risk_score()
        if risk_score >= 80:
            return SeverityLevel.CRITICAL
        elif risk_score >= 60:
            return SeverityLevel.HIGH
        elif risk_score >= 40:
            return SeverityLevel.MEDIUM
        elif risk_score >= 20:
            return SeverityLevel.LOW
        else:
            return SeverityLevel.INFO

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "assessment_id": self.assessment_id,
            "vulnerability_id": self.vulnerability_id,
            "risk_level": self.risk_level.value,
            "likelihood_score": self.likelihood_score,
            "impact_score": self.impact_score,
            "exploitability_score": self.exploitability_score,
            "affected_count": self.affected_count,
            "mitigation_score": self.mitigation_score,
            "calculated_risk_score": self.calculate_risk_score(),
            "recommendation": self.recommendation,
            "priority": self.priority,
            "assessment_date": self.assessment_date.isoformat(),
            "reassessment_date": self.reassessment_date.isoformat() if self.reassessment_date else None,
            "details": self.details
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2, default=str)

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'RiskAssessment':
        """Create RiskAssessment from dictionary."""
        return RiskAssessment(
            assessment_id=data.get("assessment_id", ""),
            vulnerability_id=data.get("vulnerability_id", ""),
            risk_level=SeverityLevel(data.get("risk_level", "MEDIUM")),
            likelihood_score=data.get("likelihood_score", 5.0),
            impact_score=data.get("impact_score", 5.0),
            exploitability_score=data.get("exploitability_score", 5.0),
            affected_count=data.get("affected_count", 0),
            mitigation_score=data.get("mitigation_score", 0.0),
            recommendation=data.get("recommendation", ""),
            priority=data.get("priority", "MEDIUM"),
            assessment_date=datetime.fromisoformat(data.get("assessment_date")) if data.get("assessment_date") else datetime.now(timezone.utc),
            reassessment_date=datetime.fromisoformat(data.get("reassessment_date")) if data.get("reassessment_date") else None,
            details=data.get("details", {})
        )


# ============================================================================
# VALIDATION AND TESTING
# ============================================================================

def run_validation_tests():
    """
    Run validation tests for all knowledge models.
    """
    print("=" * 70)
    print("Knowledge Models - Validation Tests")
    print("=" * 70)
    print()

    # Test 1: CWEInfo
    print("[TEST 1] CWEInfo Model...")
    try:
        cwe = CWEInfo(
            cwe_id="79",
            name="Cross-site Scripting (XSS)",
            description="Improper neutralization of input during web page generation",
            severity=SeverityLevel.HIGH
        )
        assert cwe.cwe_id == "CWE-79"
        assert cwe.severity == SeverityLevel.HIGH
        assert cwe.to_dict() is not None
        assert cwe.to_json() is not None
        print("  ✓ CWEInfo creation successful")
        print(f"  ✓ CWE ID: {cwe.cwe_id}")
        print(f"  ✓ Severity: {cwe.severity.value}")
        print()
    except Exception as e:
        print(f"  ✗ CWEInfo test failed: {str(e)}")
        print()

    # Test 2: CVEInfo
    print("[TEST 2] CVEInfo Model...")
    try:
        cve = CVEInfo(
            cve_id="2021-1234",
            title="Example Vulnerability",
            description="Example CVE for testing",
            severity=SeverityLevel.CRITICAL,
            cvss_score=9.8,
            affected_products=["Product A 1.0", "Product B 2.0"]
        )
        assert cve.cve_id == "CVE-2021-1234"
        assert cve.cvss_score == 9.8
        assert cve.severity == SeverityLevel.CRITICAL
        print("  ✓ CVEInfo creation successful")
        print(f"  ✓ CVE ID: {cve.cve_id}")
        print(f"  ✓ CVSS Score: {cve.cvss_score}")
        print()
    except Exception as e:
        print(f"  ✗ CVEInfo test failed: {str(e)}")
        print()

    # Test 3: CWENode
    print("[TEST 3] CWENode Model...")
    try:
        cwe_info = CWEInfo(
            cwe_id="79",
            name="XSS",
            description="Cross-site Scripting"
        )
        node = CWENode(cwe_id="CWE-79", cwe_info=cwe_info)
        node.add_parent("CWE-93")
        node.add_child("CWE-80")
        node.add_related("CWE-95")
        assert len(node.parent_ids) == 1
        assert len(node.child_ids) == 1
        assert len(node.related_ids) == 1
        print("  ✓ CWENode creation successful")
        print(f"  ✓ Parents: {len(node.parent_ids)}")
        print(f"  ✓ Children: {len(node.child_ids)}")
        print(f"  ✓ Related: {len(node.related_ids)}")
        print()
    except Exception as e:
        print(f"  ✗ CWENode test failed: {str(e)}")
        print()

    # Test 4: CVENode
    print("[TEST 4] CVENode Model...")
    try:
        cve_info = CVEInfo(
            cve_id="2021-1234",
            title="Test CVE",
            description="Test"
        )
        node = CVENode(cve_id="CVE-2021-1234", cve_info=cve_info)
        node.add_cwe_node("CWE-79")
        node.add_connected_cve("CVE-2021-5678")
        assert len(node.cwe_nodes) == 1
        assert len(node.connected_cves) == 1
        print("  ✓ CVENode creation successful")
        print(f"  ✓ CWE Nodes: {len(node.cwe_nodes)}")
        print(f"  ✓ Connected CVEs: {len(node.connected_cves)}")
        print()
    except Exception as e:
        print(f"  ✗ CVENode test failed: {str(e)}")
        print()

    # Test 5: VulnerabilityData
    print("[TEST 5] VulnerabilityData Model...")
    try:
        cve = CVEInfo(
            cve_id="2021-1234",
            title="Test CVE",
            description="Test"
        )
        cwe = CWEInfo(
            cwe_id="79",
            name="XSS",
            description="Cross-site Scripting"
        )
        vuln = VulnerabilityData(
            vulnerability_id="VULN-001",
            cve_info=cve,
            cwe_infos=[cwe],
            overall_severity=SeverityLevel.HIGH,
            risk_score=75.0
        )
        vuln.add_tag("web-app")
        vuln.add_remediation_step("Apply security patch")
        assert len(vuln.tags) == 1
        assert len(vuln.remediation_steps) == 1
        print("  ✓ VulnerabilityData creation successful")
        print(f"  ✓ Tags: {len(vuln.tags)}")
        print(f"  ✓ Risk Score: {vuln.risk_score}")
        print()
    except Exception as e:
        print(f"  ✗ VulnerabilityData test failed: {str(e)}")
        print()

    # Test 6: KnowledgeGraph
    print("[TEST 6] KnowledgeGraph Model...")
    try:
        kg = KnowledgeGraph(name="Test Graph")
        cwe_node1 = CWENode(cwe_id="CWE-79")
        cwe_node2 = CWENode(cwe_id="CWE-93")
        cve_node = CVENode(cve_id="CVE-2021-1234")
        kg.add_cwe_node(cwe_node1)
        kg.add_cwe_node(cwe_node2)
        kg.add_cve_node(cve_node)
        kg.add_edge("CWE-79", "CWE-93", "parent")
        assert kg.total_nodes == 3
        assert kg.total_edges == 1
        assert kg.get_cwe_node("CWE-79") is not None
        print("  ✓ KnowledgeGraph creation successful")
        print(f"  ✓ Total nodes: {kg.total_nodes}")
        print(f"  ✓ Total edges: {kg.total_edges}")
        print()
    except Exception as e:
        print(f"  ✗ KnowledgeGraph test failed: {str(e)}")
        print()

    # Test 7: RiskAssessment
    print("[TEST 7] RiskAssessment Model...")
    try:
        assessment = RiskAssessment(
            assessment_id="RISK-001",
            vulnerability_id="VULN-001",
            likelihood_score=8.0,
            impact_score=9.0,
            exploitability_score=7.5,
            affected_count=150
        )
        risk_score = assessment.calculate_risk_score()
        assert risk_score > 0
        risk_level = assessment.get_risk_level()
        assert risk_level in SeverityLevel
        print("  ✓ RiskAssessment creation successful")
        print(f"  ✓ Risk Score: {risk_score}")
        print(f"  ✓ Risk Level: {risk_level.value}")
        print()
    except Exception as e:
        print(f"  ✗ RiskAssessment test failed: {str(e)}")
        print()

    # Summary
    print("=" * 70)
    print("✓ Knowledge Models Validation Complete")
    print("=" * 70)
    print()
    print("Available Models:")
    print("  • CWEInfo (Common Weakness Enumeration)")
    print("  • CVEInfo (Common Vulnerabilities and Exposures)")
    print("  • CWENode (Graph node for CWE relationships)")
    print("  • CVENode (Graph node for CVE relationships)")
    print("  • VulnerabilityData (Composite vulnerability data)")
    print("  • KnowledgeGraph (Knowledge graph structure)")
    print("  • RiskAssessment (Risk assessment results)")


if __name__ == "__main__":
    run_validation_tests()