from src.learning.feedback_loop import FeedbackLoop

def test_feedback_loop_records_messages():
    loop = FeedbackLoop(history=[])
    loop.add_feedback("ok")
    assert loop.history == ["ok"]
