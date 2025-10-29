from src.llm.payload_generator import PayloadGenerationRequest, PayloadGenerator
from src.tasks.task_models import TaskDefinition
from src.tasks.task_queue import InMemoryTaskQueue
from src.tasks.worker_manager import WorkerManager


def test_distributed_campaign_assignment() -> None:
    generator = PayloadGenerator(model_name="mistral")
    queue = InMemoryTaskQueue()
    manager = WorkerManager()
    manager.register("worker-1")

    payload = generator.generate(PayloadGenerationRequest(prompt="run"))
    queue.enqueue(TaskDefinition(name="payload", payload={"payload": payload}))

    task = queue.dequeue()
    assert task is not None
    task.mark_completed({"ok": True})
    queue.mark_processed()
    manager.increment("worker-1")

    assert manager.workers["worker-1"].processed_tasks == 1


if __name__ == "__main__":
    test_distributed_campaign_assignment()
