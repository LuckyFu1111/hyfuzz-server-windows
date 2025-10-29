from src.llm.llm_judge import LLMJudge

def test_judge_quick_benchmark():
    judge = LLMJudge(model_name="ollama-test")
    scores = [judge.judge(str(i)).score for i in range(5)]
    assert len(scores) == 5
