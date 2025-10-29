import pytest

from src.notifications.notification_models import NotificationMessage
from src.notifications.notifier import NotificationService


def test_notification_service_console_channel(capsys: pytest.CaptureFixture[str]) -> None:
    service = NotificationService()
    message = NotificationMessage(channel="console", subject="Alert", body="Test message")

    service.send(message)

    captured = capsys.readouterr()
    assert "Alert" in captured.out


def test_notification_service_unknown_channel() -> None:
    service = NotificationService()
    message = NotificationMessage(channel="unknown", subject="Alert", body="Test")

    with pytest.raises(KeyError):
        service.send(message)


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__])
