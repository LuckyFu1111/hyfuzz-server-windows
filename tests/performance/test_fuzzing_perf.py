import time

from src.fuzzing.fuzz_engine import FuzzEngine, FuzzingTask


def test_fuzz_engine_execution_speed() -> None:
    engine = FuzzEngine(tasks=[FuzzingTask(target=f"target-{i}") for i in range(1000)])

    start = time.perf_counter()
    results = engine.execute()
    duration = time.perf_counter() - start

    assert len(results) == 1000
    assert duration < 0.5


if __name__ == "__main__":
    test_fuzz_engine_execution_speed()
