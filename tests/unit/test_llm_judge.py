from src.llm.llm_judge import LLMJudge

def test_llm_judge_outputs_judgment():
    judge = LLMJudge(model_name="ollama-test")
    judgment = judge.judge("payload")
    assert 0.0 <= judgment.score <= 1.0
