import pytest

from src.llm.llm_judge import LLMJudge
from src.mcp_server.message_handler import MCPMessage


def test_mcp_message_round_trip_with_judge() -> None:
    judge = LLMJudge(model_name="mistral")
    request = MCPMessage(method="judgePayload", params={"payload": "attack"}, id="1")

    judgment = judge.judge(request.params["payload"])

    response = MCPMessage(result={"score": judgment.score, "reason": judgment.reasoning}, id=request.id)

    payload = response.to_dict()
    assert payload["result"]["score"] == pytest.approx(judgment.score)
    assert payload["result"]["reason"] == judgment.reasoning


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__])
