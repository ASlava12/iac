# iac documentation / документация iac

Two languages, four documents each. Pick by what you need.

Два языка, четыре документа в каждом. Выбирай по потребности.

## English

| Document | When to read it |
|---|---|
| [Tutorial](en/tutorial.md) | "I'm new — show me how to deploy something." Walks from install → first apply → fleet mode → GitOps → rollback. |
| [Reference](en/reference.md) | "I need to look up a specific flag / provider / config block." Provider catalog, RBAC, canary, observability, troubleshooting. |
| [Runbook](en/runbook.md) | "It's 2 AM, the page just landed." Triage decision tree, severity levels, rollback procedures, common failure modes, paging matrix. |
| [Architecture](en/architecture.md) | "I want to understand how it's built — control plane, agent, dispatcher, signing, layered apply." |

## Русский

| Документ | Когда читать |
|---|---|
| [Туториал](ru/tutorial.md) | "Я только начал — покажи на примере как деплоить." От установки до первого apply, fleet mode, GitOps, rollback. |
| [Справочник](ru/reference.md) | "Мне нужно найти конкретный флаг / провайдер / блок конфига." Каталог провайдеров, RBAC, canary, observability, troubleshooting. |
| [Runbook](ru/runbook.md) | "2 ночи, прилетел пейдж." Дерево решения для triage, severity-уровни, процедуры rollback, типовые failure modes, paging-матрица. |
| [Архитектура](ru/architecture.md) | "Хочу понять как инструмент устроен — control plane, агент, диспетчер, подпись, layered apply." |

## Quick links / быстрые ссылки

* `iac --help` and `iac <subcommand> --help` print full inline reference for any
  command. Comprehensive — start there for "what does this flag do?"
* `examples/` directory at the repo root has runnable manifests:
  [`hello-file.yaml`](../examples/hello-file.yaml) (minimal),
  [`web-service.yaml`](../examples/web-service.yaml) (single service with
  health gate), [`multi-host-cluster.yaml`](../examples/multi-host-cluster.yaml)
  (3-tier deploy across hosts), [`postgres-deploy.yaml`](../examples/postgres-deploy.yaml)
  (real-world dogfooded postgres).
* [`TASKS.md`](../TASKS.md) — phased roadmap with everything that's been
  shipped + open follow-ups.
