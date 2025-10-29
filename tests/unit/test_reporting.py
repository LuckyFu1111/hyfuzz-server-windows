import pytest

from src.reporting.report_generator import ReportGenerator


def test_report_generator_summary_includes_counts() -> None:
    generator = ReportGenerator()
    campaign = {"findings": [{"id": "CVE-1", "severity": "high"}]}

    html = generator.generate_summary(campaign)

    assert "Total findings: 1" in html
    assert "High severity findings: 1" in html


def test_report_generator_handles_findings_list() -> None:
    generator = ReportGenerator()
    findings = [{"id": "CVE-1", "severity": "medium"}]

    html = generator.generate_findings(findings)

    assert "CVE-1" in html


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__])
