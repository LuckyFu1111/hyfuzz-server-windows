# HyFuzz Server Documentation Index

Welcome to the HyFuzz Server (Windows) knowledge base. This index surfaces the most relevant documents for configuring, operating, and extending the Phase 3 platform. Each guide is written in English and aligns with the repository tree described in the project specification.

## Getting Started

| Document | Purpose |
| -------- | ------- |
| [SETUP.md](SETUP.md) | Step-by-step provisioning for Windows 10/11 hosts, including VirtualBox networking tips and Ollama installation. |
| [INSTALLATION.md](../INSTALLATION.md) | Legacy quick installer for portable deployments – useful for lab experiments or demos. |
| [TESTING.md](TESTING.md) | Overview of unit, integration, performance, and e2e test suites with pytest commands. |

## Architecture & Design

| Document | Focus |
| -------- | ----- |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Service boundaries, sequence diagrams, and data-flow descriptions across MCP, LLM, knowledge, and defense layers. |
| [LLM_INTEGRATION.md](LLM_INTEGRATION.md) | Model selection, prompt templates, caching behaviour, and cost-control strategies for Ollama / OpenAI / Azure. |
| [JUDGE_ARCHITECTURE.md](JUDGE_ARCHITECTURE.md) | LLM judge decision tree, scoring rubric, and integration with defense telemetry. |
| [FEEDBACK_LOOP.md](FEEDBACK_LOOP.md) | Adaptive learning lifecycle, including how execution feedback modifies payload strategies. |

## Operations & Observability

| Document | Key Topics |
| -------- | ---------- |
| [MONITORING_GUIDE.md](MONITORING_GUIDE.md) | Prometheus exporters, Grafana dashboards, alert routing, and health probes. |
| [REPORTING_GUIDE.md](REPORTING_GUIDE.md) | Report templates, scheduled exports, and customization hooks for stakeholders. |
| [DEFENSE_INTEGRATION.md](DEFENSE_INTEGRATION.md) | WAF/IDS log ingestion, evasion detection heuristics, and defense feedback channels. |
| [DISTRIBUTED_FUZZING.md](DISTRIBUTED_FUZZING.md) | Task queue topology, Celery worker pools, recovery workflows, and scaling guidance. |
| [NOTIFICATION_SETUP.md](NOTIFICATION_SETUP.md) | Email/Slack/Discord/Teams notifier configuration and alert formatting. |

## Protocol & Knowledge Resources

| Document | Coverage |
| -------- | -------- |
| [PROTOCOL_GUIDE.md](PROTOCOL_GUIDE.md) | Detailed breakdown of CoAP, Modbus, MQTT, HTTP, gRPC, and JSON-RPC handlers and parsers. |
| [LLM_INTEGRATION.md](LLM_INTEGRATION.md) | Prompt engineering and payload reasoning best practices (duplicated here for convenience). |
| `data/` resources | *(If present)* data dictionary for CWE/CVE caches and embedding formats. |

## Security & Governance

| Document | Details |
| -------- | ------- |
| [SECURITY.md](../SECURITY.md) | Disclosure policy, threat model, and guidance for reporting vulnerabilities. |
| [AUTHENTICATION.md](AUTHENTICATION.md) | API keys, OAuth flows, RBAC roles, and session lifecycle. |
| [SECURITY.md](SECURITY.md) | Server hardening checklist, secrets management, and audit logging. |

## Contribution Workflow

| Document | Description |
| -------- | ----------- |
| [CONTRIBUTING.md](../CONTRIBUTING.md) | Development conventions, coding standards, and pull-request guidelines. |
| [CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md) | Community expectations and enforcement process. |
| [CHANGELOG_GUIDE.md](CHANGELOG_GUIDE.md) | How to draft release notes that align with Semantic Versioning and bumpversion automation. |

## Quick Reference Snippets

- **Launch server**: `python scripts/start_server.py`
- **Start distributed workers**: `python scripts/start_workers.py --concurrency 8`
- **Open dashboard**: `python scripts/start_dashboard.py --host 0.0.0.0 --port 8080`
- **Run end-to-end validation**: `pytest tests/e2e/test_complete_fuzzing_campaign.py -v`

If you create a new document, add it to the most relevant table above to keep the index accurate. For gaps or suggestions, open an issue in the repository or update this file directly.
