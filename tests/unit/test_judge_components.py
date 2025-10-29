import pytest

from src.llm.llm_judge import LLMJudge


def test_llm_judge_returns_judgment() -> None:
    judge = LLMJudge(model_name="mistral")
    result = judge.judge("test payload")

    assert 0.0 <= result.score <= 1.0
    assert isinstance(result.reasoning, str)


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__])
