# Архитектура

Как устроен `iac` внутри. Читай если хочешь контрибьютить, дебажить
странное поведение, или оценить инструмент против своих требований.

## Краткое описание

`iac` — single-binary (один исполняемый файл), agent-based
(построенный вокруг агентов на хостах) IaC-инструмент
(Infrastructure as Code, инфраструктура как код) на Rust. Оператор
описывает desired state (желаемое состояние) в YAML-манифестах;
per-host агенты (агент на каждом хосте) или SSH-pushed remote
applier (удалённый applier, которого центральный сервер запускает
по SSH) приводят хост к нужному состоянию. Центральный control
plane хранит audit trail (журнал аудита всех операций), гейтит
(допускает или блокирует) рискованные операции через approval
(согласование человеком) + canary (выкатывание на пробный
процент хостов), и диспатчит работу агентам.

Три режима деплоя сосуществуют:
* **Pull-mode agent** (как Puppet/Chef): агент на хосте сам
  забирает (pull) изменения с сервера.
* **SSH push с центрального сервера** (как Ansible): control plane
  сам SSH'ится на хосты.
* **Direct CLI SSH** (прямой SSH из CLI): одна команда оператора
  → SSH apply на конкретный хост, без сервера и агента.

Wire format (формат данных на проводе, при обмене по сети)
одинаковый для всех трёх режимов.

## Структура крейтов

Репозиторий — это Cargo workspace (общий проект из нескольких
крейтов). Каждый крейт (crate, в терминологии Rust — единица
компиляции, пакет) имеет фокусную ответственность и стабильный
внутренний API.

```
crates/
├── iac-core         # примитивы: Resource, Diff, Executor, протокол
├── iac-providers    # per-kind lifecycle (file, systemd, docker, ...)
├── iac-agent        # daemon: poll, observe, apply, drift
├── iac-controlplane # центральный сервер: REST API, store, dispatcher
├── iac-cli          # операторский `iac` бинарь
```

Почему такой раздел:
* **iac-core** — поверхность протокола. Wire-типы (типы данных,
  которые ходят по сети) живут здесь, чтобы агент и control plane
  не могли разойтись в форме `AssignmentEnvelope` или `OperationView`.
* **iac-providers** — самый большой крейт (~430 модульных тестов).
  Каждый провайдер (`file`, `docker.container`, и т.д.) следует
  одному жизненному циклу (lifecycle): `observe → diff → apply →
  rollback` (наблюдение → расчёт разницы → применение → откат).
  Добавление нового провайдера не трогает core или controlplane.
  Phase 7di.1 объединил три динамических runtime'а с JSON-envelope
  обменом (shellout, external-process, wasm-core) на единый
  `PluginProvider<R: PluginRuntime>` impl в `iac-providers/src/plugin/`;
  типизированный WIT-based wasm-component runtime сохраняет
  собственный Provider impl by design (специально, по дизайну).
* **iac-agent** и **iac-controlplane** зависят от core + providers,
  но никогда друг от друга напрямую — встречаются только на проводе
  (через wire-протокол).
* **iac-cli** — операторский UX (пользовательский опыт). Разбор
  аргументов CLI (через crate `clap`), рендер вывода, управление
  учётными данными (credential management). Никакой бизнес-логики —
  только вызовы в core / providers / HTTP.

## Модель трёх состояний (three-state model)

Всё в `iac` построено вокруг трёх состояний на ресурс:

| Состояние | Где живёт | Кто пишет |
|---|---|---|
| **Desired** (желаемое) | YAML-манифест оператора | Оператор |
| **Observed** (наблюдаемое) | Что `observe()` читает с хоста (запущенный контейнер, содержимое файла, sysctl, ...) | `observe()` провайдера |
| **Applied** (применённое) | То что мы последний раз записали (checkpoint — контрольная точка для отката) | `apply()` провайдера сохраняет checkpoint |

`diff(desired, observed)` выдаёт список изменений (`Change`'ей).
`apply()` применяет их. `rollback()` обращает то, что записано в
цепочке контрольных точек (checkpoint chain).

Каждый провайдер реализует этот жизненный цикл. Канонический пример —
`iac-providers/src/file/ops.rs`.

## Модель диспетчеризации (dispatch)

Когда оператор отправляет (submit) манифест:

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
1. Валидирует операцию (RBAC — управление правами, policies —
   политики, manifest schema — схема манифеста).
2. Маршрутизирует ресурсы агентам по `metadata.spec.hostSelector.name`.
3. Считает слои (layers) по `dependsOn` (Phase 7by — поэтапное
   применение, phased apply).
4. Если задан canary — разбивает каждый слой на batch 0 (canary,
   пробный) и batch 1 (baseline, основной).
5. Сохраняет строки заданий (assignments) в хранилище (store),
   отсортированные по слою и батчу.

Pull-mode агенты (агенты, забирающие задания) периодически опрашивают
`GET /v1/agents/{id}/assignments`. SSH push targets (хосты, к которым
сервер сам ходит по SSH) диспатчатся проактивно: один Tokio worker
(задача в асинхронном рантайме) на каждый target. Оба зовут
`complete_assignment` когда закончили; результат прокидывается в
статус операции.

## Послойное применение с canary (layered apply)

Две ортогональные оси гейтят диспетчеризацию:

* **Слои (layers)** (Phase 7by) приходят из `metadata.dependsOn`.
  Layer-N+1 не может стартовать, пока каждое задание layer-N не
  достигнет финального состояния (succeeded — успех). Сбой
  (failure) в любом слое отменяет все последующие.
* **Canary-батчи** (Phase 7cg) внутри одного слоя разбивают агентов
  на `batch=0` (диспатчится первым, canary) и `batch=1` (ждёт в
  `pending_canary` — отложенный канарейкой). Сбой в canary отменяет
  остаток выкатывания (rollout).

Композиция: canary слоя N → baseline слоя N → canary слоя N+1 →
и так далее.

Конечный автомат — `iac-controlplane/src/store.rs::advance_phased_apply`
+ `advance_canary`.

## Подпись и верификация

Каждое задание, отправленное агенту, подписывается алгоритмом Ed25519
со стороны control plane. Агенты верифицируют подпись перед apply.
Phase 7ce ввёл ротацию нескольких ключей (multi-key rotation): сервер
хранит активный ключ плюс недавно отозванные в наборе для верификации
(verification set); агенты забирают (pull) пакет (bundle) с
`GET /v1/signing-keys` и принимают подписи от любого закреплённого
(пиннатого) ключа.

Модуль подписи — `iac-controlplane/src/signing.rs`; проверка на
стороне агента — `iac-agent/src/remote.rs::verify_envelope`.

## Аутентификация и RBAC (управление ролями)

Три класса личностей (identity) делят один интерфейс bearer-токенов
(токен в HTTP-заголовке `Authorization: Bearer ...`):

| Класс | Источник | Phase |
|---|---|---|
| `LegacyAdmin` | Статичный `admin_token` в server.toml | bootstrap |
| `User` | `iac users create`, хеш Argon2id в БД | 6e |
| `Agent` | `POST /v1/agents/register`, sha256-хешированный токен | 2a |

Роли образуют решётку (lattice): `Viewer < Operator < Approver <
Admin`. Проверки RBAC — `iac-controlplane/src/identity.rs::require_role`.

TTL и ротация токенов (Phase 7cc-7cd) — включаются по желанию
(opt-in) через `agent_token_ttl_secs` в server.toml.

## Журнал аудита (audit log)

Каждый вызов, меняющий состояние, добавляет (append) строку в
`audit_events`. Схема — миграция `20260429000004_audit.sql`. Типы
событий:
`operation.{submitted,approved,rejected,failed,succeeded}`,
`agent.{registered,token_rotated,heartbeat_lost}`,
`drift.{detected,accepted,reverted}`,
`signing.key_{rotated,retired}`,
`ssh.push_{succeeded,partial,failed}`,
`maintenance.window_{entered,exited}`.

Операторы запрашивают через `iac audit --server <url> --kind ... --limit ...`
(фильтры — точное совпадение по полю; серверного фильтра `since` по
времени нет, при необходимости делайте сужение через `jq` на клиенте).

## Хранилище (storage)

Два бэкенда, идентичный wire-формат:
* **SQLite** — один бинарь, один файл. Прогнан на Raspberry Pi 4
  (Phase 8.7) при 10 агентов × 1000 операций × 50 RPS с 0 ошибок.
  Режим WAL (write-ahead log, журнал упреждающей записи) + 30 с
  `busy_timeout` (Phase 8.7 поднял с 5 с после того, как bare-metal
  flash-хранилище обнажило contention — конкурентную борьбу за
  блокировки). Дефолт для домашних лабораторий (homelab). SQLITE_BUSY
  всплывает как HTTP 503 с `Retry-After: 1` (не 500), чтобы
  well-behaved (вежливые) клиенты делали back off — отступали и
  повторяли запрос позже.
* **Postgres** — масштабирование под продакшен. Wire-формат
  идентичен, меняется только `database_url`. Миграции лежат в
  `migrations-postgres/` параллельно `migrations/` — поддерживаются
  вручную, чтобы не зависеть от `sqlx-cli` и SQLite/PG-специфичных
  расхождений (divergence).

## Горячая перезагрузка по SIGHUP (hot reload)

Подмножество конфига (policies — политики, modules — модули,
retention — настройки удержания данных, maintenance windows — окна
обслуживания) перезагружается без рестарта по сигналу `SIGHUP`.
Реализация — через `arc_swap::ArcSwap` с `ReloadableState`. Жёсткие
поля (bind, db_url, tls, webhooks, rate_limit) владеют долгоживущим
рантайм-состоянием и требуют рестарта by design (специально).

## Соглашения в коде

* `forbid(unsafe_code)` на весь workspace.
* `edition = "2024"`, `rust-version = "1.95"`, `resolver = "3"`.
* sqlx 0.8 с драйвером `Any` — placeholder'ы `?` переводятся в
  рантайме для Postgres.
* Политика "no-comment-by-default" (без лишних комментариев):
  комментарии объясняют *почему*, не *что*. Документация жизненного
  цикла провайдера — `//!` rustdoc на уровне модуля.
* Тесты — канонические примеры. Чтение
  `crates/iac-controlplane/tests/e2e_*.rs` — самый быстрый путь к
  пониманию любой фичи.

## История фаз

История разработки записана в [`TASKS.md`](../../TASKS.md) (текущий
roadmap — дорожная карта — и последняя выпущенная фаза) и
[`TASKS_ARCHIVE.md`](../../TASKS_ARCHIVE.md) (закрытые фазы).
Номера фаз (`7ck`, `7cj`, и т.д.) стабильны — на них ссылаются
комментарии в коде как на якорь "почему это выглядит так?".

## Где смотреть код для X

| Если хочешь понять... | Читай |
|---|---|
| Wire-формат (структуры обмена по сети) | `crates/iac-core/src/protocol.rs` |
| Как один ресурс проходит через apply | `crates/iac-core/src/executor.rs` + любой `iac-providers/src/<kind>/ops.rs` |
| Как операции диспатчатся | `crates/iac-controlplane/src/store.rs::create_operation` |
| Как слои и canary каскадятся при сбое | `crates/iac-controlplane/src/store.rs::{advance_phased_apply, advance_canary}` |
| Как главный цикл агента (agent loop) опрашивает и применяет | `crates/iac-agent/src/agent.rs` |
| Как SSH push диспатчит | `crates/iac-controlplane/src/ssh_push.rs` |
| Как RBAC и аутентификация резолвится | `crates/iac-controlplane/src/identity.rs` |
| Как подпись и ротация ключей работают | `crates/iac-controlplane/src/signing.rs` |

E2e-тест (end-to-end, сквозной) рядом с каждой фичей — обычно
самый чистый способ понять, как она реально работает от начала до
конца: `crates/iac-controlplane/tests/e2e_<feature>.rs`.
