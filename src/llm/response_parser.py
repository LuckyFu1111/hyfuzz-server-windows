"""
Response Parser Module for HyFuzz Windows MCP Server

This module provides sophisticated LLM response parsing capabilities:
- Multi-format response detection and parsing (JSON, text, structured)
- Security-specific information extraction (CVE, CWE, severity)
- Response validation and error handling
- Chain-of-Thought chain extraction
- Structured information extraction
- Response quality assessment
"""

import json
import re
import logging
from typing import Optional, Dict, List, Any, Tuple, Union
from dataclasses import dataclass, field, asdict
from enum import Enum
from abc import ABC, abstractmethod
from datetime import datetime
from enum import auto


# ============================================================================
# Enums and Data Structures
# ============================================================================

class ResponseFormat(Enum):
    """Detected response formats"""
    JSON = "json"
    STRUCTURED_TEXT = "structured_text"
    FREE_TEXT = "free_text"
    COT_CHAIN = "cot_chain"
    TECHNICAL_REPORT = "technical_report"
    ERROR = "error"
    UNKNOWN = "unknown"


class SeverityLevel(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class ResponseQuality(Enum):
    """Quality assessment of response"""
    EXCELLENT = "excellent"
    GOOD = "good"
    ACCEPTABLE = "acceptable"
    POOR = "poor"
    FAILED = "failed"


@dataclass
class SecurityIndicator:
    """Extracted security-related information"""
    cve_ids: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    severity_level: SeverityLevel = SeverityLevel.UNKNOWN
    affected_systems: List[str] = field(default_factory=list)
    attack_vectors: List[str] = field(default_factory=list)
    impact_description: str = ""
    remediation: List[str] = field(default_factory=list)
    confidence_score: float = 0.0


@dataclass
class CotStep:
    """Single step in Chain-of-Thought reasoning"""
    step_number: int
    title: str
    content: str
    reasoning: str = ""
    conclusion: str = ""


@dataclass
class ParsedResponse:
    """Structured parsed response"""
    original_content: str
    format_detected: ResponseFormat
    parsed_content: Dict[str, Any]
    security_indicators: Optional[SecurityIndicator] = None
    cot_chain: Optional[List[CotStep]] = None
    quality_score: float = 0.0
    is_valid: bool = True
    error_message: Optional[str] = None
    extraction_metadata: Dict[str, Any] = field(default_factory=dict)
    parsed_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data['format_detected'] = self.format_detected.value
        data['parsed_at'] = self.parsed_at.isoformat()
        if self.security_indicators:
            data['security_indicators']['severity_level'] = self.security_indicators.severity_level.value
        return data


@dataclass
class ExtractionPattern:
    """Pattern for extracting specific information"""
    name: str
    pattern: str
    description: str
    required: bool = False
    group_index: int = 1


# ============================================================================
# Extraction Patterns Registry
# ============================================================================

class PatternRegistry:
    """Manages extraction patterns"""

    def __init__(self):
        self.patterns: Dict[str, ExtractionPattern] = {}
        self.logger = logging.getLogger(__name__)
        self._initialize_security_patterns()

    def _initialize_security_patterns(self) -> None:
        """Initialize security-specific extraction patterns"""

        # CVE Pattern: CVE-YYYY-NNNNN
        self.register(ExtractionPattern(
            name="cve_id",
            pattern=r'CVE-\d{4}-\d{4,7}',
            description="Matches CVE identifiers"
        ))

        # CWE Pattern: CWE-NNN
        self.register(ExtractionPattern(
            name="cwe_id",
            pattern=r'CWE-\d{1,4}',
            description="Matches CWE identifiers"
        ))

        # Severity Pattern
        self.register(ExtractionPattern(
            name="severity",
            pattern=r'(?:severity|severity\s*level|cvss)\s*[:=]?\s*(critical|high|medium|low|info)',
            description="Matches severity levels",
            group_index=1
        ))

        # Impact Pattern
        self.register(ExtractionPattern(
            name="impact",
            pattern=r'(?:impact|consequence|effect)\s*[:=]?\s*([^.\n]+)',
            description="Matches impact statements",
            group_index=1
        ))

        # Remediation Pattern
        self.register(ExtractionPattern(
            name="remediation",
            pattern=r'(?:remediation|mitigation|fix|solution)\s*[:=]?\s*([^.\n]+)',
            description="Matches remediation steps",
            group_index=1
        ))

        # Attack Vector Pattern
        self.register(ExtractionPattern(
            name="attack_vector",
            pattern=r'(?:attack\s+vector|vector)\s*[:=]?\s*([^.\n]+)',
            description="Matches attack vectors",
            group_index=1
        ))

    def register(self, pattern: ExtractionPattern) -> None:
        """Register an extraction pattern"""
        self.patterns[pattern.name] = pattern
        self.logger.debug(f"Registered pattern: {pattern.name}")

    def get(self, name: str) -> Optional[ExtractionPattern]:
        """Get pattern by name"""
        return self.patterns.get(name)

    def extract_all(self, pattern_name: str, text: str) -> List[str]:
        """Extract all matches for a pattern"""
        pattern = self.get(pattern_name)
        if not pattern:
            return []
        matches = re.findall(pattern.pattern, text, re.IGNORECASE)
        return matches if matches else []

    def extract_first(self, pattern_name: str, text: str) -> Optional[str]:
        """Extract first match for a pattern"""
        matches = self.extract_all(pattern_name, text)
        return matches[0] if matches else None


# ============================================================================
# Base Response Parser
# ============================================================================

class BaseResponseParser(ABC):
    """Abstract base class for response parsers"""

    def __init__(self, pattern_registry: Optional[PatternRegistry] = None):
        self.pattern_registry = pattern_registry or PatternRegistry()
        self.logger = logging.getLogger(__name__)

    @abstractmethod
    def can_parse(self, response: str) -> bool:
        """Check if parser can handle this response"""
        pass

    @abstractmethod
    async def parse(self, response: str) -> ParsedResponse:
        """Parse response"""
        pass

    def _extract_security_indicators(self, content: str) -> SecurityIndicator:
        """Extract security indicators from content"""
        indicators = SecurityIndicator()

        # Extract CVE IDs
        indicators.cve_ids = self.pattern_registry.extract_all("cve_id", content)

        # Extract CWE IDs
        indicators.cwe_ids = self.pattern_registry.extract_all("cwe_id", content)

        # Extract severity
        severity_match = self.pattern_registry.extract_first("severity", content)
        if severity_match:
            try:
                indicators.severity_level = SeverityLevel[severity_match.upper()]
            except KeyError:
                indicators.severity_level = SeverityLevel.UNKNOWN

        # Extract impact
        impact_matches = self.pattern_registry.extract_all("impact", content)
        if impact_matches:
            indicators.impact_description = impact_matches[0]

        # Extract remediation
        indicators.remediation = self.pattern_registry.extract_all("remediation", content)

        # Extract attack vectors
        indicators.attack_vectors = self.pattern_registry.extract_all("attack_vector", content)

        # Calculate confidence score
        indicators.confidence_score = self._calculate_confidence(indicators)

        return indicators

    def _calculate_confidence(self, indicators: SecurityIndicator) -> float:
        """Calculate confidence score for extracted indicators"""
        score = 0.0

        # CVE/CWE presence
        if indicators.cve_ids or indicators.cwe_ids:
            score += 0.3

        # Severity level defined
        if indicators.severity_level != SeverityLevel.UNKNOWN:
            score += 0.2

        # Impact described
        if indicators.impact_description:
            score += 0.2

        # Remediation provided
        if indicators.remediation:
            score += 0.2

        # Attack vectors described
        if indicators.attack_vectors:
            score += 0.1

        return min(score, 1.0)

    def _calculate_quality_score(self, content: str, indicators: SecurityIndicator) -> float:
        """Calculate overall response quality"""
        score = 0.0

        # Length check
        if len(content) > 100:
            score += 0.2
        elif len(content) > 50:
            score += 0.1

        # Structure check
        if "\n" in content:
            score += 0.1

        # Indicator extraction
        score += indicators.confidence_score * 0.5

        # Specific content checks
        quality_keywords = ["analyze", "vulnerability", "security", "impact", "recommend"]
        for keyword in quality_keywords:
            if keyword in content.lower():
                score += 0.1

        return min(score, 1.0)


# ============================================================================
# JSON Response Parser
# ============================================================================

class JSONResponseParser(BaseResponseParser):
    """Parser for JSON-formatted responses"""

    def can_parse(self, response: str) -> bool:
        """Check if response is valid JSON"""
        try:
            json.loads(response.strip())
            return True
        except (json.JSONDecodeError, ValueError):
            return False

    async def parse(self, response: str) -> ParsedResponse:
        """Parse JSON response"""
        try:
            parsed_data = json.loads(response.strip())

            security_indicators = self._extract_security_indicators(json.dumps(parsed_data))

            parsed_response = ParsedResponse(
                original_content=response,
                format_detected=ResponseFormat.JSON,
                parsed_content=parsed_data,
                security_indicators=security_indicators,
                quality_score=self._calculate_quality_score(response, security_indicators),
                is_valid=True
            )

            self.logger.debug("Successfully parsed JSON response")
            return parsed_response

        except Exception as e:
            self.logger.error(f"JSON parsing error: {str(e)}")
            return ParsedResponse(
                original_content=response,
                format_detected=ResponseFormat.ERROR,
                parsed_content={},
                is_valid=False,
                error_message=f"JSON parsing failed: {str(e)}"
            )


# ============================================================================
# CoT Chain Response Parser
# ============================================================================

class CotChainResponseParser(BaseResponseParser):
    """Parser for Chain-of-Thought chain responses"""

    def can_parse(self, response: str) -> bool:
        """Check if response is CoT chain format"""
        cot_indicators = [
            "step 1", "step 2", "step 3",
            "first,", "second,", "third,",
            "analyze:", "reasoning:", "conclusion:"
        ]
        response_lower = response.lower()
        return sum(1 for indicator in cot_indicators if indicator in response_lower) >= 2

    async def parse(self, response: str) -> ParsedResponse:
        """Parse CoT chain response"""
        try:
            cot_chain = self._extract_cot_chain(response)
            security_indicators = self._extract_security_indicators(response)

            parsed_response = ParsedResponse(
                original_content=response,
                format_detected=ResponseFormat.COT_CHAIN,
                parsed_content={"reasoning_steps": len(cot_chain)},
                cot_chain=cot_chain,
                security_indicators=security_indicators,
                quality_score=self._calculate_quality_score(response, security_indicators),
                is_valid=True
            )

            self.logger.debug(f"Extracted {len(cot_chain)} CoT steps")
            return parsed_response

        except Exception as e:
            self.logger.error(f"CoT parsing error: {str(e)}")
            return ParsedResponse(
                original_content=response,
                format_detected=ResponseFormat.COT_CHAIN,
                parsed_content={},
                is_valid=False,
                error_message=f"CoT parsing failed: {str(e)}"
            )

    def _extract_cot_chain(self, response: str) -> List[CotStep]:
        """Extract CoT steps from response"""
        steps = []
        lines = response.split("\n")

        step_number = 0
        current_step = None
        current_content = []

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Check if this is a step header
            step_match = re.match(r'^(?:step\s*(\d+)|(\d+)\.)\s*[:]*\s*(.+)', line, re.IGNORECASE)
            if step_match:
                # Save previous step
                if current_step:
                    current_step.content = "\n".join(current_content)
                    steps.append(current_step)

                step_number = int(step_match.group(1) or step_match.group(2))
                title = step_match.group(3)

                current_step = CotStep(
                    step_number=step_number,
                    title=title,
                    content=""
                )
                current_content = []
            else:
                if current_step:
                    current_content.append(line)

        # Add final step
        if current_step:
            current_step.content = "\n".join(current_content)
            steps.append(current_step)

        return steps


# ============================================================================
# Technical Report Response Parser
# ============================================================================

class TechnicalReportParser(BaseResponseParser):
    """Parser for structured technical report responses"""

    def can_parse(self, response: str) -> bool:
        """Check if response is technical report format"""
        report_keywords = [
            "vulnerability", "analysis", "recommendations",
            "executive summary", "technical details",
            "severity", "impact", "mitigation"
        ]
        response_lower = response.lower()
        return sum(1 for keyword in report_keywords if keyword in response_lower) >= 3

    async def parse(self, response: str) -> ParsedResponse:
        """Parse technical report response"""
        try:
            security_indicators = self._extract_security_indicators(response)
            sections = self._extract_report_sections(response)

            parsed_response = ParsedResponse(
                original_content=response,
                format_detected=ResponseFormat.TECHNICAL_REPORT,
                parsed_content=sections,
                security_indicators=security_indicators,
                quality_score=self._calculate_quality_score(response, security_indicators),
                is_valid=True,
                extraction_metadata={"sections_found": len(sections)}
            )

            self.logger.debug(f"Parsed technical report with {len(sections)} sections")
            return parsed_response

        except Exception as e:
            self.logger.error(f"Report parsing error: {str(e)}")
            return ParsedResponse(
                original_content=response,
                format_detected=ResponseFormat.TECHNICAL_REPORT,
                parsed_content={},
                is_valid=False,
                error_message=f"Report parsing failed: {str(e)}"
            )

    def _extract_report_sections(self, response: str) -> Dict[str, str]:
        """Extract sections from technical report"""
        sections = {}
        section_keywords = [
            "summary", "analysis", "vulnerability", "severity",
            "impact", "recommendations", "conclusion", "details"
        ]

        for keyword in section_keywords:
            # Find section content
            pattern = rf'{keyword}[:\s]+(.*?)(?=(?:{"|".join(section_keywords)}|$))'
            match = re.search(pattern, response, re.IGNORECASE | re.DOTALL)
            if match:
                sections[keyword] = match.group(1).strip()[:500]

        return sections


# ============================================================================
# Free Text Response Parser
# ============================================================================

class FreeTextResponseParser(BaseResponseParser):
    """Parser for free-form text responses"""

    def can_parse(self, response: str) -> bool:
        """Free text parser accepts all non-error responses"""
        return len(response.strip()) > 0

    async def parse(self, response: str) -> ParsedResponse:
        """Parse free text response"""
        try:
            security_indicators = self._extract_security_indicators(response)

            # Extract sentences
            sentences = re.split(r'[.!?]+', response)
            sentences = [s.strip() for s in sentences if s.strip()]

            parsed_response = ParsedResponse(
                original_content=response,
                format_detected=ResponseFormat.FREE_TEXT,
                parsed_content={
                    "sentence_count": len(sentences),
                    "key_sentences": sentences[:3]
                },
                security_indicators=security_indicators,
                quality_score=self._calculate_quality_score(response, security_indicators),
                is_valid=True
            )

            self.logger.debug(f"Parsed free text response with {len(sentences)} sentences")
            return parsed_response

        except Exception as e:
            self.logger.error(f"Free text parsing error: {str(e)}")
            return ParsedResponse(
                original_content=response,
                format_detected=ResponseFormat.FREE_TEXT,
                parsed_content={},
                is_valid=False,
                error_message=f"Free text parsing failed: {str(e)}"
            )


# ============================================================================
# Main Response Parser Dispatcher
# ============================================================================

class ResponseParser:
    """
    Main response parser dispatcher that detects format and uses appropriate parser.

    Features:
    - Automatic format detection
    - Multi-parser support
    - Security information extraction
    - Response quality assessment
    - Error handling
    """

    def __init__(self, pattern_registry: Optional[PatternRegistry] = None):
        self.pattern_registry = pattern_registry or PatternRegistry()
        self.logger = logging.getLogger(__name__)

        # Initialize parsers
        self.parsers: List[BaseResponseParser] = [
            JSONResponseParser(self.pattern_registry),
            CotChainResponseParser(self.pattern_registry),
            TechnicalReportParser(self.pattern_registry),
            FreeTextResponseParser(self.pattern_registry),
        ]

        self.parse_history: List[ParsedResponse] = []
        self.stats = {
            "total_parsed": 0,
            "formats": {},
            "avg_quality": 0.0,
            "errors": 0
        }

    async def parse(self, response: str) -> ParsedResponse:
        """
        Parse LLM response with automatic format detection

        Args:
            response: Raw LLM response string

        Returns:
            ParsedResponse with detected format and extracted information
        """
        if not response or not response.strip():
            return ParsedResponse(
                original_content=response,
                format_detected=ResponseFormat.ERROR,
                parsed_content={},
                is_valid=False,
                error_message="Empty response"
            )

        # Try each parser in order
        for parser in self.parsers:
            if parser.can_parse(response):
                try:
                    parsed = await parser.parse(response)
                    self._update_stats(parsed)
                    self.parse_history.append(parsed)
                    self.logger.info(
                        f"Response parsed as {parsed.format_detected.value} "
                        f"with quality {parsed.quality_score:.2f}"
                    )
                    return parsed
                except Exception as e:
                    self.logger.warning(f"Parser failed: {str(e)}")
                    continue

        # Fallback: treat as free text
        self.logger.warning("No parser matched, using free text fallback")
        return await self.parsers[-1].parse(response)

    def _update_stats(self, parsed_response: ParsedResponse) -> None:
        """Update statistics"""
        self.stats["total_parsed"] += 1
        format_name = parsed_response.format_detected.value
        self.stats["formats"][format_name] = self.stats["formats"].get(format_name, 0) + 1

        if parsed_response.is_valid:
            # Update average quality
            old_avg = self.stats["avg_quality"]
            total = self.stats["total_parsed"]
            self.stats["avg_quality"] = (
                    (old_avg * (total - 1) + parsed_response.quality_score) / total
            )
        else:
            self.stats["errors"] += 1

    def get_statistics(self) -> Dict[str, Any]:
        """Get parsing statistics"""
        return {
            "total_parsed": self.stats["total_parsed"],
            "format_distribution": self.stats["formats"],
            "average_quality": self.stats["avg_quality"],
            "errors": self.stats["errors"],
            "success_rate": (
                (self.stats["total_parsed"] - self.stats["errors"]) /
                self.stats["total_parsed"] if self.stats["total_parsed"] > 0 else 0
            )
        }

    def get_history(self, limit: int = 10) -> List[ParsedResponse]:
        """Get recent parse history"""
        return self.parse_history[-limit:]

    def clear_history(self) -> None:
        """Clear parse history"""
        self.parse_history.clear()


# ============================================================================
# TESTING SECTION
# ============================================================================

async def run_tests():
    """Comprehensive test suite for response parser"""

    print("\n" + "=" * 80)
    print("RESPONSE PARSER COMPREHENSIVE TEST SUITE")
    print("=" * 80 + "\n")

    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    parser = ResponseParser()

    # Test 1: Pattern Registry
    print("[TEST 1] Pattern Registry")
    print("-" * 80)
    pattern_registry = PatternRegistry()
    cve_matches = pattern_registry.extract_all("cve_id", "Found CVE-2023-12345 and CVE-2024-67890")
    assert len(cve_matches) == 2, "CVE extraction failed"
    print(f"✓ Extracted {len(cve_matches)} CVE IDs: {cve_matches}")

    cwe_matches = pattern_registry.extract_all("cwe_id", "This affects CWE-78 and CWE-79")
    assert len(cwe_matches) == 2, "CWE extraction failed"
    print(f"✓ Extracted {len(cwe_matches)} CWE IDs: {cwe_matches}")
    print()

    # Test 2: JSON Response Parsing
    print("[TEST 2] JSON Response Parsing")
    print("-" * 80)
    json_response = """{
        "vulnerability": "Buffer Overflow",
        "severity": "critical",
        "cve": "CVE-2023-12345",
        "cwe": "CWE-131",
        "impact": "Remote Code Execution",
        "remediation": "Update to version 2.0"
    }"""
    parsed = await parser.parse(json_response)
    assert parsed.format_detected == ResponseFormat.JSON
    assert parsed.is_valid == True
    assert len(parsed.security_indicators.cve_ids) > 0
    print(f"✓ JSON parsed successfully")
    print(f"  Format: {parsed.format_detected.value}")
    print(f"  CVE IDs: {parsed.security_indicators.cve_ids}")
    print(f"  Quality: {parsed.quality_score:.2f}")
    print()

    # Test 3: CoT Chain Parsing
    print("[TEST 3] Chain-of-Thought Response Parsing")
    print("-" * 80)
    cot_response = """
    Step 1: Identify the vulnerability
    A buffer overflow occurs when more data is written to a buffer than it can hold.

    Step 2: Analyze the impact
    This can lead to arbitrary code execution. CVE-2023-12345 demonstrates this.

    Step 3: Determine remediation
    Apply security patches and use bounds checking.
    """
    parsed = await parser.parse(cot_response)
    assert parsed.format_detected == ResponseFormat.COT_CHAIN
    assert parsed.cot_chain is not None
    assert len(parsed.cot_chain) > 0
    print(f"✓ CoT chain parsed successfully")
    print(f"  Steps extracted: {len(parsed.cot_chain)}")
    for step in parsed.cot_chain:
        print(f"    - Step {step.step_number}: {step.title}")
    print()

    # Test 4: Technical Report Parsing
    print("[TEST 4] Technical Report Parsing")
    print("-" * 80)
    report_response = """
    Executive Summary:
    A critical vulnerability has been identified affecting multiple systems.

    Vulnerability Analysis:
    The vulnerability exists in the input validation routine, CWE-78.

    Severity Assessment:
    CVSS Score: 9.8 (Critical)

    Impact:
    Remote code execution on affected systems.

    Recommendations:
    Apply immediate security patches and implement input validation.
    """
    parsed = await parser.parse(report_response)
    assert parsed.format_detected == ResponseFormat.TECHNICAL_REPORT
    assert "analysis" in parsed.parsed_content or "assessment" in parsed.parsed_content
    print(f"✓ Technical report parsed successfully")
    print(f"  Sections found: {parsed.extraction_metadata.get('sections_found', 0)}")
    print(f"  CWE IDs: {parsed.security_indicators.cwe_ids}")
    print()

    # Test 5: Free Text Parsing
    print("[TEST 5] Free Text Response Parsing")
    print("-" * 80)
    free_text = "This is a vulnerability that affects systems running the affected software. It has high impact."
    parsed = await parser.parse(free_text)
    assert parsed.format_detected == ResponseFormat.FREE_TEXT
    print(f"✓ Free text parsed successfully")
    print(f"  Sentences: {parsed.parsed_content.get('sentence_count', 0)}")
    print()

    # Test 6: Security Indicator Extraction
    print("[TEST 6] Security Indicator Extraction")
    print("-" * 80)
    security_response = """
    Vulnerability: SQL Injection
    CVE ID: CVE-2023-99999
    CWE ID: CWE-89
    Severity: High
    Attack Vector: Network
    Impact: Database compromise and data theft
    Remediation: Use parameterized queries
    """
    parsed = await parser.parse(security_response)
    indicators = parsed.security_indicators
    assert len(indicators.cve_ids) > 0
    assert len(indicators.cwe_ids) > 0
    assert indicators.severity_level != SeverityLevel.UNKNOWN
    print(f"✓ Security indicators extracted:")
    print(f"  CVE IDs: {indicators.cve_ids}")
    print(f"  CWE IDs: {indicators.cwe_ids}")
    print(f"  Severity: {indicators.severity_level.value}")
    print(f"  Confidence: {indicators.confidence_score:.2f}")
    print()

    # Test 7: Response Quality Assessment
    print("[TEST 7] Response Quality Assessment")
    print("-" * 80)
    high_quality = """
    This vulnerability (CVE-2023-12345, CWE-78) requires immediate attention.

    Analysis:
    The command injection flaw allows attackers to execute arbitrary commands.

    Severity: Critical

    Mitigation:
    1. Implement input validation
    2. Use secure APIs
    3. Apply security patches
    """
    parsed = await parser.parse(high_quality)
    print(f"✓ Quality score: {parsed.quality_score:.2f}")
    assert parsed.quality_score > 0.5, "Quality should be good"
    print()

    # Test 8: Empty Response Handling
    print("[TEST 8] Empty Response Handling")
    print("-" * 80)
    empty_response = ""
    parsed = await parser.parse(empty_response)
    assert parsed.is_valid == False
    assert parsed.format_detected == ResponseFormat.ERROR
    print(f"✓ Empty response handled correctly")
    print(f"  Error: {parsed.error_message}")
    print()

    # Test 9: Parser Statistics
    print("[TEST 9] Parser Statistics")
    print("-" * 80)
    stats = parser.get_statistics()
    print(f"✓ Statistics:")
    print(f"  Total parsed: {stats['total_parsed']}")
    print(f"  Format distribution: {stats['format_distribution']}")
    print(f"  Average quality: {stats['average_quality']:.2f}")
    print(f"  Success rate: {stats['success_rate']:.2%}")
    print()

    # Test 10: Parse History
    print("[TEST 10] Parse History")
    print("-" * 80)
    history = parser.get_history(5)
    print(f"✓ Retrieved {len(history)} items from parse history")
    for i, item in enumerate(history[-3:]):
        print(f"  {i + 1}. Format: {item.format_detected.value}, Quality: {item.quality_score:.2f}")
    print()

    # Test 11: Multiple Format Detection
    print("[TEST 11] Multiple Format Detection")
    print("-" * 80)
    responses = [
        ('{"status": "ok"}', ResponseFormat.JSON),
        ('Step 1: Analyze\nStep 2: Conclude', ResponseFormat.COT_CHAIN),
        ('Executive Summary: Test\nVulnerability Analysis: Critical\nRecommendations: Patch immediately\nSeverity: High',
         ResponseFormat.TECHNICAL_REPORT),
        ('Just regular text here', ResponseFormat.FREE_TEXT),
    ]

    for response_text, expected_format in responses:
        parsed = await parser.parse(response_text)
        assert parsed.format_detected == expected_format, f"Format mismatch for {expected_format.value}"
        print(f"✓ {expected_format.value}: Correctly detected")
    print()

    # Test 12: Complex Security Extraction
    print("[TEST 12] Complex Security Extraction")
    print("-" * 80)
    complex_response = """
    Critical vulnerabilities discovered:
    - CVE-2023-11111: XSS vulnerability (CWE-79)
    - CVE-2023-22222: SQL Injection (CWE-89)
    - CVE-2023-33333: Command Injection (CWE-78)

    All have critical severity and network-based attack vectors.

    Remediation recommended immediately.
    """
    parsed = await parser.parse(complex_response)
    assert len(parsed.security_indicators.cve_ids) >= 3
    assert len(parsed.security_indicators.cwe_ids) >= 3
    print(f"✓ Complex extraction successful")
    print(f"  CVE IDs found: {len(parsed.security_indicators.cve_ids)}")
    print(f"  CWE IDs found: {len(parsed.security_indicators.cwe_ids)}")
    print(f"  CVEs: {parsed.security_indicators.cve_ids}")
    print(f"  CWEs: {parsed.security_indicators.cwe_ids}")
    print()

    print("=" * 80)
    print("ALL TESTS PASSED ✓")
    print("=" * 80 + "\n")

    return True


# ============================================================================
# Main Entry Point
# ============================================================================

if __name__ == "__main__":
    import asyncio

    success = asyncio.run(run_tests())
    if success:
        print("Response Parser is ready for integration!")