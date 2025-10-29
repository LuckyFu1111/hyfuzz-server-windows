# Feedback Loop

The feedback loop is responsible for adapting fuzzing strategies using judge
outputs, defense analytics, and execution telemetry.

## Modules

- `src/learning/feedback_loop.py` – Orchestrates the loop and emits actionable
  strategy updates.
- `src/learning/strategy_optimizer.py` – Learns scoring weights for future
  payload generations.
- `src/fuzzing/fuzz_engine.py` – Consumes updated strategies to mutate payloads.

## Workflow

1. Collect execution results from `data/results/execution_results_samples.json`.
2. Obtain judge verdicts via `LLMJudge`.
3. Combine with defense risk reports from `src/defense/defense_integrator.py`.
4. Run the optimizer to adjust mutation priorities.

## Testing

Execute the following unit test to ensure the loop runs end-to-end:

```bash
pytest tests/unit/test_feedback_loop.py
```

This test validates that the loop can ingest mocked telemetry and produce a
strategy update without raising exceptions.
