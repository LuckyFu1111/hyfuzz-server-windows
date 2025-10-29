from src.models.execution_models import ExecutionContext

def test_execution_context_fields():
    context = ExecutionContext(target="device", timeout=30)
    assert context.timeout == 30
