# Judge Quick Reference

A condensed checklist for operating the HyFuzz judge during Phase 3 campaigns.

## Key Commands

- Start server: `python -m src`
- Trigger full pipeline test: `pytest tests/integration/test_full_phase3_pipeline.py`
- Refresh knowledge cache: `python scripts/analyze_results.py --refresh-cache`

## Configuration Files

| File | Purpose |
|------|---------|
| `config/judge_config.yaml` | Global judge defaults |
| `config/example_configs/config_judge_balanced.yaml` | Balanced scoring profile |
| `src/config/judge_config.yaml` | Embedded defaults for packaging |

## Runtime Tips

- Monitor judge performance metrics via `logs/judge.log` and
  `logs/performance.log`.
- Defense signals arrive from `src/defense/defense_integrator.py`. Ensure the
  integrator has the WAF and IDS modules registered.
- To adjust chain-of-thought verbosity, tweak `cot_depth` inside
  `config/judge_config.yaml`.

## Health Check

```bash
python scripts/health_check.py --component judge
```

The script performs a smoke test by instantiating `LLMJudge` and executing a
sample payload evaluation.
