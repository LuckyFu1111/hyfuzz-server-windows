from src.utils.metrics import Metric

def test_metric_dataclass():
    metric = Metric(name="requests", value=1.0)
    assert metric.value == 1.0
