import pytest

from src.knowledge.vulnerability_db import CVEEntry, SeverityLevel, VulnerabilityDB
from src.llm.llm_judge import LLMJudge


@pytest.mark.asyncio
async def test_real_world_like_workflow() -> None:
    db = VulnerabilityDB()
    await db.add_cve(
        CVEEntry(
            cve_id="CVE-REAL-0001",
            description="Demo overflow",
            severity=SeverityLevel.MEDIUM,
            cvss_score=5.0,
            publish_date="2025-01-01",
            update_date="2025-01-01",
        )
    )

    fetched = await db.get_cve("CVE-REAL-0001")
    judge = LLMJudge(model_name="mistral")
    judgment = judge.judge(fetched.cve_id if fetched else "")

    assert fetched is not None
    assert 0.0 <= judgment.score <= 1.0


if __name__ == "__main__":
    import asyncio

    asyncio.run(test_real_world_like_workflow())
