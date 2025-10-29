from src.models.judge_models import JudgeRequest, JudgeResponse

def test_judge_models_round_trip():
    request = JudgeRequest(payload="data")
    response = JudgeResponse(accepted=True, details="ok")
    assert request.payload == "data"
    assert response.accepted is True
