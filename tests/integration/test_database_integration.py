import pytest

from src.knowledge.vulnerability_db import CVEEntry, SeverityLevel, VulnerabilityDB


@pytest.mark.asyncio
async def test_vulnerability_db_round_trip() -> None:
    db = VulnerabilityDB()
    entry = CVEEntry(
        cve_id="CVE-TEST-0001",
        description="Integration test vulnerability",
        severity=SeverityLevel.LOW,
        cvss_score=4.0,
        publish_date="2025-01-01",
        update_date="2025-01-01",
    )

    assert await db.add_cve(entry) is True
    fetched = await db.get_cve(entry.cve_id)
    assert fetched is not None
    assert fetched.cve_id == entry.cve_id


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__])
