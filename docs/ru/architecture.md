# Архитектура

Как устроен `iac` внутри. Читай если хочешь контрибьютить, дебажить
странное поведение, или оценить инструмент против своих требований.

## Краткое описание

`iac` — single-binary, agent-based IaC инструмент на Rust. Оператор
описывает desired state в YAML манифестах; per-host агенты (или
SSH-pushed remote applier) приводят хост к нужному состоянию.
Центральный control plane хранит audit trail, гейтит рискованные
операции через approval + canary, диспатчит работу агентам.

Три режима деплоя сосуществуют:
* **Pull-mode agent** (как Puppet/Chef): агент на хосте сам пуллит
  изменения с сервера.
* **SSH push с центрального сервера** (как Ansible): control plane
  сам SSH'ится на хосты.
* **Direct CLI SSH**: одна команда оператора → SSH apply на конкретный
  хост, без сервера и агента.

Wire format одинаковый для всех трёх.

## Структура crates

Repo — Cargo workspace. Каждый crate имеет фокусную ответственность
и стабильный internal API.

```
crates/
├── iac-core         # примитивы: Resource, Diff, Executor, протокол
├── iac-providers    # per-kind lifecycle (file, systemd, docker, ...)
├── iac-agent        # daemon: poll, observe, apply, drift
├── iac-controlplane # центральный сервер: REST API, store, dispatcher
├── iac-cli          # операторский `iac` бинарь
```

Почему такой split:
* **iac-core** — protocol surface. Wire-типы здесь чтобы агент и
  control plane не могли разойтись в форме `AssignmentEnvelope` или
  `OperationView`.
* **iac-providers** — самый большой crate (~430 unit тестов). Каждый
  провайдер (`file`, `docker.container`, и т.д.) следует одному
  lifecycle: `observe → diff → apply → rollback`. Добавление нового
  провайдера не трогает core или controlplane. Phase 7di.1 объединил
  три JSON-envelope-based динамических runtime'а (shellout,
  external-process, wasm-core) на единый `PluginProvider<R:
  PluginRuntime>` impl в `iac-providers/src/plugin/`; типизированный
  WIT-based wasm-component runtime сохраняет собственный Provider
  impl by design.
* **iac-agent** и **iac-controlplane** зависят от core + providers,
  но никогда друг от друга напрямую — встречаются только на wire.
* **iac-cli** — операторский UX. Парсинг CLI (clap), рендер вывода,
  credential management. Никакой бизнес-логики — только вызовы в
  core / providers / HTTP.

## Three-state model

Всё в `iac` построено вокруг трёх состояний на ресурс:

| Состояние | Где живёт | Кто пишет |
|---|---|---|
| **Desired** | YAML манифест оператора | Оператор |
| **Observed** | Что `observe()` читает с хоста (running container, file contents, sysctl, ...) | `observe()` провайдера |
| **Applied** | То что мы последний раз записали (checkpoint для rollback) | `apply()` провайдера сохраняет checkpoint |

`diff(desired, observed)` выдаёт список `Change`'ей. `apply()`
применяет их. `rollback()` реверсит то что в checkpoint chain.

Каждый провайдер имплементирует этот lifecycle. Канонический пример —
`iac-providers/src/file/ops.rs`.

## Dispatch модель

Когда оператор submit'ит манифест:

```
┌────────────┐  POST /v1/operations           ┌──────────────────┐
│  iac CLI   │──────────────────────────────▶│  controlplane    │
└────────────┘  AssignmentEnvelope          ┌─└──────────────────┘
                                            │  ┌──────────────────┐
                                            │  │  store: SQLite/  │
                                            │  │  Postgres        │
                                            │  └──────────────────┘
                                            ▼
                            ┌─────────────────┴──────────────────┐
                            ▼                                    ▼
                    ┌───────────────┐                  ┌──────────────┐
                    │  agent (pull) │                  │  ssh push    │
                    │  poll-based   │                  │  worker      │
                    └───────┬───────┘                  └──────┬───────┘
                            │                                 │
                            ▼                                 ▼
                    ┌───────────────┐                  ┌──────────────┐
                    │   target      │                  │   target     │
                    │   host        │                  │   host       │
                    └───────────────┘                  └──────────────┘
```

Control plane:
1. Валидирует операцию (RBAC, policies, manifest schema).
2. Маршрутизирует ресурсы агентам по `metadata.spec.hostSelector.name`.
3. Считает layers по `dependsOn` (Phase 7by phased apply).
4. Если задан canary — разбивает каждый layer на batch 0 (canary) и
   batch 1 (baseline).
5. Сохраняет assignment строки в store, отсортированные по layer + batch.

Pull-mode агенты поллят `GET /v1/agents/{id}/assignments` периодически.
SSH push targets диспатчатся проактивно per-target Tokio worker
тасками. Оба зовут `complete_assignment` когда закончили; результат
прокидывается в operation status.

## Layered apply с canary

Две ортогональные оси гейтят dispatch:

* **Layers** (Phase 7by) приходят из `metadata.dependsOn`. Layer-N+1
  не может стартовать пока каждое layer-N задание не достигнет
  terminal state (succeeded). Failure в любом layer отменяет все
  последующие.
* **Canary batches** (Phase 7cg) внутри одного layer'а разбивают
  агентов на `batch=0` (диспатчится первым, canary) и `batch=1`
  (ждёт в `pending_canary`). Failure в canary отменяет остаток
  rollout'а.

Композиция: layer-N canary → layer-N baseline → layer-N+1 canary →
и так далее.

State machine — `iac-controlplane/src/store.rs::advance_phased_apply`
+ `advance_canary`.

## Подпись и верификация

Каждое задание, диспатченное агенту, подписывается Ed25519 со стороны
control plane. Агенты верифицируют перед apply. Phase 7ce ввёл
multi-key rotation: сервер хранит активный ключ + recently-rotated в
verification set; агенты пуллят bundle с `GET /v1/signing-keys` и
принимают подписи от любого пиннатого ключа.

Signing module — `iac-controlplane/src/signing.rs`; agent verification
— `iac-agent/src/remote.rs::verify_envelope`.

## Аутентификация и RBAC

Три identity-класса делят один bearer-token surface:

| Класс | Источник | Phase |
|---|---|---|
| `LegacyAdmin` | Static `admin_token` в server.toml | bootstrap |
| `User` | `iac users create`, Argon2id hash в DB | 6e |
| `Agent` | `POST /v1/agents/register`, sha256-хешированный токен | 2a |

Роли формируют lattice: `Viewer < Operator < Approver < Admin`.
RBAC checks — `iac-controlplane/src/identity.rs::require_role`.

Token TTL + rotation (Phase 7cc-7cd) — opt-in через
`agent_token_ttl_secs` в server.toml.

## Audit log

Каждый state-changing вызов append'ит строку в `audit_events`. Schema
— migration `20260429000004_audit.sql`. Events:
`operation.{submitted,approved,rejected,failed,succeeded}`,
`agent.{registered,token_rotated,heartbeat_lost}`,
`drift.{detected,accepted,reverted}`,
`signing.key_{rotated,retired}`,
`ssh.push_{succeeded,partial,failed}`,
`maintenance.window_{entered,exited}`.

Операторы запрашивают через `iac audit --server <url> --kind ... --limit ...`
(фильтры — точное совпадение по полю; серверного `since`-фильтра по
времени нет, при необходимости делайте сужение через `jq` на клиенте).

## Storage

Два бэкенда, идентичный wire format:
* **SQLite** — single binary, single file. Прогнан на Raspberry Pi 4
  (Phase 8.7) при 10 агентов × 1000 операций × 50 RPS с 0 ошибок.
  WAL mode + 30s `busy_timeout` (Phase 8.7 поднял с 5s после того,
  как bare-metal flash storage обнажил contention). Default для
  homelab. SQLITE_BUSY всплывает как HTTP 503 с `Retry-After: 1`,
  не 500, чтобы well-behaved клиенты делали back off.
* **Postgres** — production scale-out. Wire identical, меняется
  только `database_url`. Migrations в `migrations-postgres/`
  параллельно `migrations/` — поддерживаются вручную, чтобы не
  зависеть от sqlx-cli + SQLite/PG специфичных divergence.

## SIGHUP hot reload

Подмножество конфига (policies, modules, retention, maintenance
windows) перезагружается без рестарта на `SIGHUP`. Реализация — через
`arc_swap::ArcSwap` с `ReloadableState`. Hard-fields (bind, db_url,
tls, webhooks, rate_limit) владеют long-lived runtime state и
требуют рестарта by design.

## Соглашения в коде

* `forbid(unsafe_code)` workspace-wide.
* `edition = "2024"`, `rust-version = "1.95"`, `resolver = "3"`.
* sqlx 0.8 с `Any` driver — `?` placeholders runtime-translated для Postgres.
* No-comment-by-default policy: комментарии объясняют *почему*, не
  *что*. Provider lifecycle docs — module-level `//!` rustdoc.
* Тесты — канонические примеры. Чтение
  `crates/iac-controlplane/tests/e2e_*.rs` — fastest path к
  пониманию любой фичи.

## История фаз

История разработки записана в [`TASKS.md`](../../TASKS.md) (текущий
roadmap + последняя shipped фаза) и [`TASKS_ARCHIVE.md`](../../TASKS_ARCHIVE.md)
(закрытые фазы). Phase numbers (`7ck`, `7cj`, и т.д.) стабильны —
ссылаются из комментариев кода как anchor "почему это выглядит так?".

## Где смотреть код для X

| Если хочешь понять... | Читай |
|---|---|
| Wire format | `crates/iac-core/src/protocol.rs` |
| Как один ресурс flow'ится через apply | `crates/iac-core/src/executor.rs` + любой `iac-providers/src/<kind>/ops.rs` |
| Как операции диспатчатся | `crates/iac-controlplane/src/store.rs::create_operation` |
| Как layers + canary каскадятся при failure | `crates/iac-controlplane/src/store.rs::{advance_phased_apply, advance_canary}` |
| Как agent loop поллит и применяет | `crates/iac-agent/src/agent.rs` |
| Как SSH push диспатчит | `crates/iac-controlplane/src/ssh_push.rs` |
| Как RBAC + auth резолвится | `crates/iac-controlplane/src/identity.rs` |
| Как signing + rotation работает | `crates/iac-controlplane/src/signing.rs` |

E2e тест рядом с каждой фичей — обычно самый чистый способ понять
как она реально работает end-to-end:
`crates/iac-controlplane/tests/e2e_<feature>.rs`.
