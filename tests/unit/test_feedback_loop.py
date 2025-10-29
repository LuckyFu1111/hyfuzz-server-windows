import pytest

from src.learning.feedback_loop import FeedbackLoop


def test_feedback_loop_records_messages() -> None:
    loop = FeedbackLoop(history=[])
    loop.add_feedback("payload improved")

    assert loop.history == ["payload improved"]


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__])
