from src.fuzzing.fuzz_engine import FuzzEngine, FuzzingTask

def test_fuzz_engine_execute_returns_targets():
    engine = FuzzEngine(tasks=[FuzzingTask(target="coap")])
    assert engine.execute() == ["coap"]
