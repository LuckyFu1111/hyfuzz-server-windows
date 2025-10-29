from src.fuzzing.fuzz_engine import FuzzEngine, FuzzingTask
from src.fuzzing.payload_handler import PayloadHandler

def test_fuzzing_pipeline_handles_payloads():
    engine = FuzzEngine(tasks=[FuzzingTask(target="coap")])
    handler = PayloadHandler(mutations=["-mut"])
    assert handler.prepare("seed") == ["seed-mut"]
    assert engine.execute() == ["coap"]
