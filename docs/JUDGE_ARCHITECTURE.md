# Judge Architecture

This document describes the logical architecture of the HyFuzz LLM-powered judge
subsystem. The judge operates as an expert reasoning layer that evaluates
payload execution outcomes and defense telemetry in order to guide the fuzzing
campaign.

## Components

1. **LLM Judge Core** – Wraps the Ollama-hosted model and exposes a minimal API
   via `src/llm/llm_judge.py`. The judge turns structured execution reports into
   scoring prompts and produces a `Judgment` dataclass with a normalized risk
   score.
2. **Prompt Builder** – Implemented in `src/llm/prompt_builder.py`, this module
   assembles chain-of-thought friendly prompts that combine context retrieved
   from the knowledge graph and vector database with execution telemetry.
3. **CoT Engine** – The reasoning helper in `src/llm/cot_engine.py` ensures that
   multi-step reasoning traces are persisted and can be audited or replayed.
4. **Feedback Loop** – `src/learning/feedback_loop.py` consumes judgments and
   defense analytics to adjust fuzzing strategies.
5. **Defense Integrator** – Located in `src/defense/defense_integrator.py`, this
   component enriches judge inputs with contextual threat intelligence.

## Data Flow

1. Execution telemetry is serialized via `src/execution/execution_result.py`.
2. Telemetry is enriched by the defense stack (`src/defense/*`).
3. Prompt Builder combines telemetry, context graph data, and prior judgments.
4. The LLM Judge reasons about the payload impact and emits a `Judgment`.
5. Judgments feed both reporting (`src/reporting/report_generator.py`) and the
   adaptive learning loop.

## Extensibility

- Custom prompt strategies can be registered through
  `src/llm/prompt_strategy.py`.
- Alternate defense sources can subscribe to the `DefenseIntegrator`.
- Additional scoring heuristics can be layered by extending
  `src/learning/strategy_optimizer.py`.

## Quick Smoke Test

```bash
python -m src.llm.llm_judge
```

Running the module ensures that the judge dataclasses import correctly.
