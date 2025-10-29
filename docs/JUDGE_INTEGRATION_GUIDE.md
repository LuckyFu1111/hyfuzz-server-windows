# Judge Integration Guide

This guide explains how to integrate the Phase 3 LLM-based judge with the rest
of the HyFuzz server stack.

## Prerequisites

- Ollama installed with the desired local model (for example `mistral:instruct`).
- Redis optional for caching, configured in `config/cache_config.yaml`.
- Knowledge base seeds located in `data/knowledge_cache/`.

## Configuration Steps

1. **Judge Settings** – Review `config/judge_config.yaml` for global runtime
   defaults. Per-environment overrides can be supplied through
   `config/example_configs/config_judge_balanced.yaml`.
2. **Environment Variables** – Copy `.env.example` to `.env` and set the
   `OLLAMA_BASE_URL` and `HYFUZZ_MODEL` values.
3. **Prompt Strategy** – Customize prompt behaviors via
   `src/llm/prompt_strategy.py`. Register additional strategies by extending the
   `PromptStrategyRegistry` class.
4. **Defense Signals** – Ensure `src/defense/defense_integrator.py` subscribers
   are registered from `src/defense/orchestrator.py` before judge execution.

## Execution Flow

1. Start the server: `python -m src`.
2. The MCP server (`src/mcp_server/server.py`) accepts execution reports from the
   Ubuntu client.
3. Reports are normalized into `ExecutionResult` objects.
4. The judge service (`src/llm/llm_service.py`) invokes `LLMJudge` with enriched
   prompts.
5. Judgments are persisted to `data/results/judgment_results.json` and published
   to monitoring and reporting subsystems.

## Verification

Run the integration test suite:

```bash
pytest tests/integration/test_judge_mcp_integration.py
```

This test ensures that MCP messages are accepted, normalized, and evaluated by
`LLMJudge` without raising errors.
