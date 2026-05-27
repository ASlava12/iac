# Operations runbook

Полевой гайд по эксплуатации этого IaC-инструмента "по-боевому":
incident triage, rollback процедуры, on-call playbook для типичных
failure modes. В пару идут [`reference.md`](reference.md) (config
schema + feature surface) и [`architecture.md`](architecture.md)
(почему всё устроено именно так).

Runbook для v0 инструмента. По мере того как код взрослеет, item'ы
здесь должны устаревать (фикс в коде > фикс в runbook'е). Помечайте
такие записи на post-incident review.

---

## Содержание

1. [Базовый набор on-call](#базовый-набор-on-call)
2. [Уровни severity](#уровни-severity)
3. [Triage decision tree](#triage-decision-tree)
4. [Rollback процедуры](#rollback-процедуры)
5. [Типичные failure modes](#типичные-failure-modes)
6. [Cross-compile под MIPS / OpenWrt](#cross-compile-под-mips--openwrt)
7. [Diagnostic команды](#diagnostic-команды)
8. [Когда будить людей](#когда-будить-людей)
9. [Post-incident](#post-incident)

---

## Базовый набор on-call

**До первой смены:**

- У вас есть `ssh` на control-plane хост, читается `/var/lib/iac-controlplane/`.
- Ваш аккаунт имеет admin-token в RBAC-таблицах control-plane (см. [reference.md#RBAC](reference.md#rbac)).
- У вас read-доступ к hosts inventory флота.
- На ноуте установлен `iac` CLI той же версии что и флот.
- Знаете куда публикуется audit-chain anchor (out-of-band log: syslog, S3, signed-witness — что выбрала команда).

**Во время смены держите открытыми:**

- Prometheus-дэш control-plane (метрики `iac_*`).
- Audit feed. CLI сегодня не имеет follow-style tail; либо
  поллите интересующий kind через `watch -n 5 'iac audit --server <url>
  --kind drift.detected --limit 20'`, либо стримьте напрямую с API:
  `curl -sS -H "Authorization: Bearer $TOKEN" "$URL/v1/audit?limit=50&kind=drift.detected" | jq`.
- On-call канал для пейджинга.

**Правила большого пальца:**

- **Притормозите перед destructive action'ом.** Любой rollback path
  обратим; `iac apply --force` от спешки — нет. Если сомневаетесь —
  зовите вторую пару глаз.
- **Сначала audit-log, потом действие.** Перед `iac apply` прочитайте
  recent audit для затрагиваемых ресурсов. Кто-то может уже работать.
- **Maintenance windows не просто так.** Если вы вне окна, подумайте:
  может, изменение подождёт?

---

## Уровни severity

| Sev | Определение                                              | Время реакции | Примеры |
|-----|----------------------------------------------------------|--------------|----------|
| 1   | Production-affecting; видимая пользователю поломка       | Немедленно   | Cert протух, mass agent disconnect, control-plane HTTP 5xx |
| 2   | Production at-risk; redundancy compromised               | < 30 min     | Single-AZ control-plane down, signing-key rotation застряла |
| 3   | Degraded но не видно пользователю                        | В тот же рабочий день | Drift копится на N хостах, audit-chain probe отстаёт |
| 4   | Operator hygiene                                         | Best-effort  | Stale capability allowlist, log retention близко к лимиту |

Sev 1 и 2 требуют incident commander, даже если команда — один
человек. Документируйте таймстемпы, решения, выполненные команды —
post-incident review зависит от этого.

---

## Triage decision tree

Когда пейдж пришёл и вы не знаете в каком измерении сломалось —
проходите этот список сверху вниз. Каждый шаг исключает класс
проблем за < 60 секунд.

1. **Достижим ли control-plane?**
   `curl -sS https://control-plane.example/v1/health` — ждём HTTP
   200 с `{"status":"ok"}`. Не 200 → fault domain — control-plane;
   переходите к [Control-plane down](#control-plane-down).

2. **Агенты репортят?**
   ```sh
   curl -sS -H "Authorization: Bearer $TOKEN" "$URL/v1/agents" \
     | jq '.[] | {name, status, last_heartbeat_at}'
   ```
   Агенты с `last_heartbeat_at` старше 2× их observe-interval'а —
   молчат. > 5% молчат → fleet connectivity issue; переходите к
   [Fleet partition](#fleet-partition).

3. **Drift копится?**
   `iac drift --server $URL list` — резкий скачок открытых drift
   event'ов означает что-то на хосте либо не применилось, либо
   откатывает изменения. К [Drift surge](#drift-surge).

4. **Recent operation провалилась?**
   ```sh
   curl -sS -H "Authorization: Bearer $TOKEN" "$URL/v1/operations?status=failed&limit=50" | jq
   ```
   Failed apply мог оставить мир в half-changed состоянии. К
   [Failed apply](#failed-apply-half-applied-state).

5. **Audit-chain integrity probe?**
   `curl -sS -H "Authorization: Bearer $TOKEN" $URL/v1/audit/verify` —
   `{"ok": false}` означает что хеш одной из строк не сходится.
   **Это sev 1.** Прекратите triage других путей и идите в
   [Audit-chain mismatch](#audit-chain-mismatch).

Если ничего из вышеперечисленного — откройте audit feed, просканируйте
последние 30 минут на out-of-band действия, которые вы не ожидали.
Всё ещё ничего → эскалируйте.

---

## Rollback процедуры

### Откатить один ресурс

Агент хранит checkpoint на каждый applied step. Чтобы восстановить
pre-apply состояние одного ресурса:

```sh
# 1. Найдите operation, которая последней трогала ресурс.
#    Локальный `iac operations` перечисляет то, что применил ЭТОТ хост
#    (state-dir backed); серверная история — через API:
curl -sS -H "Authorization: Bearer $TOKEN" \
     "$URL/v1/audit?kind=operation.succeeded&limit=20" \
   | jq '.[] | select(.payload.resource_ids[]?=="file/prod/nginx-conf") | .operation_id'

# 2. Откатить. CLI ходит по checkpoint'у и пере-применяет prior
#    state. Идемпотентно — повторный запуск это no-op.
iac rollback <op-id> --server "$URL"
```

Rollback пишет audit-event с `kind=operation.rolled_back`. Проверьте
в audit feed перед declared done.

### Откатить целый apply

Если apply провалился на полпути (часть steps succeeded, часть
failed) — operation в статусе `partially_applied`. Control-plane
авто-откатывает успешные steps когда operation переходит в `failed`,
но можно forced manually:

```sh
iac rollback --operation <op-id> --include-succeeded
```

Это пройдёт по каждому step отрепорченному `succeeded` и запустит
provider's `rollback` для каждого. Steps без recorded checkpoint
скипаются с warning'ом.

### Откатить к known-good git commit

Когда манифесты в git ушли в плохое состояние и вы хотите быстро
вернуть флот, делается тем же путём, каким исходно катили вперёд —
повторным submit'ом из known-good ref:

```sh
# Apply манифестов на <good-sha>. Резолвленный SHA автоматически
# попадает в audit log как `source_commit`; --canary-pct ограждает
# раскат если уверенности не хватает.
iac apply --git-repo https://git.example.com/infra.git \
          --git-ref <good-sha> \
          --git-path manifests/ \
          --server "$URL" \
          --environment prod \
          --canary-pct 25 --yes
```

Агенты подхватывают новый desired state на следующем observe;
drift авто-резолвится по мере конвергенции мира. **Это НЕ то же
самое что per-resource rollback** — оно полагается на то что
новый манифест объявляет что вы хотите. Если ресурс удалён из git
между плохим и хорошим ref, агент его снесёт (см. семантику
удаления манифеста в [reference.md#GitOps](reference.md#gitops)).

### Восстановить из бэкапа

При corruption control-plane state — см.
[reference.md#Backups](reference.md#backups). Backup tarball
включает SQLite DB или Postgres dump + signing-key material.
Restore оффлайновый: остановить control-plane, swap state-dir,
restart.

Для SQLite-бэкендов валидированы два recovery-пути:

1. **Hot snapshot через `VACUUM INTO`** (Phase 9-F7,
   `trial/scenarios/fleet-f7-backup-restore.sh`). RPO ≈ wall-time
   снапшота (~45 с на 947 MB БД), RTO ≈ 1.6 с. Рестарт source CP
   не требуется. **Используй `VACUUM INTO`, не `.backup`** —
   `.backup` зависает в page-level SQLITE_BUSY retry-loop под
   активным writer'ом; `VACUUM INTO` — single-statement
   transactional snapshot за disk-write time.

2. **Continuous WAL replication через Litestream** (Phase 11 prep,
   `trial/scenarios/setup-litestream-replication.sh`). RPO < 1 с
   (default sync-interval 1 с), RTO ≈ 30 с. Zero impact на source
   — Litestream tail'ит WAL через shadow-WAL без блокировки
   writers. Реплицирует SFTP'ом на
   `cp-spare-02:/var/lib/iac-replica/`.

**Forensics caveat (урок F1 attempt #1).** Если CP умер от
disk-full, **НЕ** удалять WAL до checkpoint'а. В main DB могут
быть un-checkpointed frames в WAL; удалить WAL → main DB
malformed, `.dump` тоже упадёт. Правильная последовательность:

```sh
systemctl stop iac-controlplane
# В WAL ещё могут быть незафиксированные frames — checkpoint СНАЧАЛА.
sqlite3 /var/lib/iac-controlplane/server.db 'PRAGMA wal_checkpoint(TRUNCATE);'
# Только ТЕПЕРЬ безопасно перемещать файлы.
```

---

## Типичные failure modes

### Control-plane down

**Симптом:** `/v1/health` возвращает 5xx или connection-refused.
Агенты продолжают observe локально, но не могут запостить
результаты пока control-plane не встанет; локальный audit log на
каждом агенте закрывает gap.

**Quick check:**
```sh
ssh control-plane.example
sudo systemctl status iac-controlplane
sudo journalctl -u iac-controlplane -n 200 --no-pager
```

**Типичные причины:**

- **Disk full.** `/var/lib/iac-controlplane/server.db` вырос за
  пределы партиции. `df -h /var/lib/iac-controlplane` подтверждает.
  Лечение: ужесточить retention в `server.toml`
  (`[retention] audit_days = ...`) и SIGHUP'ить controlplane —
  prune-воркер на каждом цикле автоматически тримит audit / drift
  / per-resource caps. Admin-CLI `prune` команды нет. Disk full
  *также* убивает audit appends — агенты буферизуют локально.
- **Postgres connection storm.** Connection pool исчерпан; флот
  агентов вырос быстрее `max_connections`. Лечение: поднять
  `max_connections` на DB или снизить per-agent observe parallelism.
- **TLS cert истёк.** `openssl s_client -connect control-plane:443
  -servername control-plane.example` показывает expired cert.
  Обновить через собственный ACME-провайдер агента (мы едим свой
  собачий корм) — путь к cert'у в `server.toml`.
- **Migration failure on restart.** `journalctl` показывает SQL
  error во время `_iac_migrations` apply. Лечение: только
  roll-forward — пофиксить underlying migration, задеплоить новый
  binary; никогда не редактируйте уже shipped migration.

**Recovery path:**

1. Restore DB из последнего backup'а если disk corruption.
2. Перезапустить control-plane.
3. Смотреть как `iac_agent_seen_total` начинает тикать.
4. Когда ≥ 95% expected agents отчитались — флот реконвергировал.
5. Verify audit-chain integrity *перед* serving новых operations
   (corrupted tail может скрыть tampering): `GET /v1/audit/verify`.

### Fleet partition

**Симптом:** Много агентов с `last_seen` старше observe interval'а,
но каждый отдельный хост отвечает на TCP probe.

**Типичные причины:**

- Сетевой firewall change блокирует control-plane port.
- DNS на control-plane hostname поменялся, агенты закешировали
  старую резолюцию.
- mTLS cert rotation, который не доехал до всех агентов.

**Quick check с одного агента:**
```sh
ssh affected-agent
journalctl -u iac-agent -n 100 --no-pager
sudo -u iac-agent /usr/local/bin/iac-agent status     # local snapshot
```

**Recovery:** фикс почти всегда на network/credential границе, не в
самом агенте. Агенты авто-реконнектятся с exponential backoff —
рестартить их не надо после фикса underlying issue.

### Drift surge

**Симптом:** Open drift count резко вырос за последний observe cycle.

**Самые вероятные причины (по убыванию):**

1. **Кто-то ручками отредактировал config на хостах.** Сравните
   sample manifest с реальным on-disk состоянием.
2. **Package upgrade сбросил config-файл.** Типично на Debian/Ubuntu
   когда `dpkg` спрашивает и unattended-upgrade выбрал `keep-default`.
3. **Cron / scheduled task переписывает state.** Ищите cron entries
   управляемые *вне* IaC.
4. **Genuine policy drift** — spec поменялся в git; агенты честно
   догоняют. Cross-reference с recent operation audit'ом через
   `iac audit --server $URL --kind operation.succeeded --limit 30`.

**Лечение:** решите что прав — мир или spec. Если мир прав —
принимайте drift через `iac drift --server $URL accept <id> --reason
"<text>"` (записывает reason + actor в audit log). Если spec прав —
применяйте.

### Failed apply (half-applied state)

**Симптом:** GET `/v1/operations` возвращает строки со статусом
`failed`. (`iac operations` — лишь local-state-dir lister; серверная
история требует API или audit feed.)

**Шаги:**

```sh
# Что случилось?
curl -sS -H "Authorization: Bearer $TOKEN" "$URL/v1/operations/<op-id>" | jq

# Какие assignments застряли?
curl -sS -H "Authorization: Bearer $TOKEN" \
     "$URL/v1/operations/<op-id>/desired-state" \
   | jq '.items[] | select(.status != "succeeded") | {resource_id, status, message}'

# Откатить. С --server controlplane строит новую operation,
# которая пере-применяет prior desired-state каждого затронутого ресурса.
iac rollback <op-id> --server "$URL" --reason "<incident-id>"

# Investigate underlying failure (логи, audit, сам ресурс).
# Пофиксите root cause, переapply.
iac apply --server "$URL" --environment <env> manifests/
```

Если step помечен `Failed` но его `rollback` checkpoint отсутствует
(редко — обычно означает, что failure случился *до* того как
`pre_apply` записал checkpoint) — придётся откатывать руками,
применив prior spec из git.

### Audit-chain mismatch

**Симптом:** `GET /v1/audit/verify` возвращает `{"ok":false,
"broken_id":N}`.

**Это sev 1.** Означает либо:

- Database corruption (редко, ловится integrity check'ами SQLite/PG).
- Кто-то с DB write-доступом отредактировал audit-row out-of-band.
  *Это security incident.*
- Bug в audit chain implementation. Bug-shaped: исключить нельзя,
  но обращайтесь как с security case пока не доказано обратное.

**Шаги:**

1. **Прекратить принимать новые operations.** Maintenance windows —
   config-driven (`maintenance_windows` / `recurring_maintenance_windows`
   в `server.toml`); добавьте запись, покрывающую `now → now+2h`, и
   пошлите SIGHUP controlplane'у, чтобы загейтить non-admin submissions
   пока разбираетесь. Admin-CLI ярлыка для этого сегодня нет; правьте
   конфиг-файл.
2. **Достать broken row** и row сразу до неё:
   ```sh
   curl -sS -H "Authorization: Bearer $TOKEN" \
        "$URL/v1/audit?limit=1000" \
     | jq '.[] | select(.id == BROKEN_ID or .id == BROKEN_ID-1)'
   ```
   (Эндпоинт `/v1/audit` фильтрует только по `kind`/`actor`/`operation_id`/
   `agent_id`/`limit` — server-side `since`-фильтра нет; time-window
   narrow делайте client-side через `jq`, если нужно.)
3. **Сравнить с out-of-band trust anchor** (ваш syslog / S3 /
   signed-witness feed `chain-tip`, питающийся из
   `GET /v1/audit/chain-tip`). Та строка, чей `prev_hash` сходится с
   anchor — authentic; другая — forged.
4. **Ротейтить все credentials**, которые дали attacker'у DB
   write-доступ: admin tokens, DB passwords, control-plane signing
   key (`POST /v1/admin/signing-keys/rotate`).
5. Документируйте IRC для post-incident review.

### Capacity exhaustion под устойчивой нагрузкой

**Симптом:** держится 1+ час 5xx rate с `database is locked` /
`disk is full` / latency INSERT'а 4–6 с. SQLite write-path
saturates.

**Background — F1 trial findings.** Phase 9 fleet validation на
7-агентной фарме при 1 RPS submit-burst всплыли шесть отдельных
capacity ceiling'ов. Все шесть закрыты defaults; раздел существует
для операторов на бóльших флотах, где те же patterns могут
re-emerge.

| Симптом | Механизм | Default который ограничивает |
|---|---|---|
| `disk is full` через несколько часов | SQLite WAL растёт unbounded (autocheckpoint pages back, но не truncate'ит) | `journal_size_limit = 256 MiB` per-connection PRAGMA + periodic `wal_checkpoint(TRUNCATE)` task |
| INSERT latency 4–7 с под нагрузкой | Per-row INSERT-ы queue WAL frame allocation | Multi-row batched INSERT (chunk = 100) в `record_observations` |
| `observations` table 1 M+ строк | Нет per-resource cap; observations live до age-prune | `observation_max_per_resource = 50` + 5-min retention interval |
| Фризы 30 с каждую минуту | `wal_checkpoint(TRUNCATE)` blocking при contention | PASSIVE на большинстве tick'ов, TRUNCATE каждый 10-й (default cadence 60 с → TRUNCATE раз в 10 мин) |
| Agent local DB unbounded | `record_observation` INSERT'ит без cap | `AGENT_OBSERVATION_HISTORY_CAP = 10` per `resource_id`, inline DELETE после INSERT |
| Agent застрял в 413 retry-loop | Push body > CP `max_body_bytes`, agent retry'ит ту же oversized batch | Adaptive chunked push (chunk = 500 obs, halve on 413, drop singleton) |
| Каталог `executor/operations/` агента раздулся до 1.6 GB за 24 ч | Per-apply ULID-директория, GC не было | const `EXECUTOR_OPERATIONS_KEEP = 200` + GC после каждого apply |
| iac-trial unique-path observations bloat | `make_file_manifest` использовал `Ulid::new()` → неограниченный resource pool | Ограниченный `AtomicU64 % POOL` (default 200/host); fleet-wide cap N_hosts × POOL |
| Таблица `desired_states` пересекает 150 k строк, assignment-fetch SELECT slow | Per-(operation, resource) row без upsert, не было per-resource cap | `desired_state_max_per_resource = 10` retention (зеркалит observations cap shape, chunked DELETE) |

### Backend choice — SQLite knee при устойчивом ~3 RPS

**Phase 9 F1 stress matrix finding (gap-#11, 2026-05-16).**
24-часовой F1 baseline на 1 RPS проходит чисто на SQLite (попытка
#11: 0 failures на 86 400 ops). На 5 RPS sustained тот же стек
пересекает SQLite single-writer knee:

- Реальный throughput **3.6 ops/s** при цели 5 — server-side
  latency throttle'ит iac-trial token bucket.
- Cumulative failure rate **0.21 %** (всё ещё под 1 % cap'ом),
  но per-hour rate пиковал на **3.73 %** в h+18, sustained
  ≥ 1 % в течение 5 ч.
- `busy/5min` уперлось в **1846** (37× cap 50); slope-детектор
  фаерил оба триггера (deteriorating + sustained).
- p99 latency **> 2.5 с** на **0.67 %** запросов (длинный tail —
  глубина connection queue, не реальная работа).
- 0 CP / 0 agent unaccounted restarts. Audit chain intact.
  Per-resource cap держался (1400 distinct `resource_id`, 70 k
  observation-строк).

**Решение: принято как design knob.** Single-writer в SQLite
сериализует каждый INSERT — на 5 RPS sustained WAL frame queue
заполняется быстрее чем `wal_checkpoint(TRUNCATE)` успевает
дренировать. Tuning `synchronous=NORMAL` купил бы throughput
ценой durability, чего для audit-chain backend'а делать нельзя.
sqlx Any driver уже поддерживает Postgres end-to-end (схема в
`migrations-postgres/` идентична с заменой AUTOINCREMENT на
BIGSERIAL).

**Гайд оператору.** При sustained submit rate > 3 RPS — переведи
CP на Postgres:

```toml
# /etc/iac/server.toml
database_url = "postgres://iac:secret@db.internal:5432/iac"
```

…и накатывай миграции из
`crates/iac-controlplane/migrations-postgres/` (runtime применяет
их при старте так же как SQLite-миграции). Production-флоты
обычно держат submit-нагрузку гораздо ниже 1 RPS, так что SQLite
остаётся правильным default'ом — knee важен только при бёрсте
от CI или периодическом re-apply большого флота.

### Control-plane RSS scaling — page cache от размера таблиц

**Phase 9 finding (2026-05-27, fix-12 validation).** Долгое время
наблюдался рост CP resident-set-size (RSS, рабочая память
процесса в виде, который видит ОС) на длинных soak'ах: F1 #11
(24 ч, 1 RPS) дал 27 → 59 MiB (+116 %). Три расследования
последовательно подтвердили что это **не Rust heap leak** и
**не glibc arena fragmentation**:

1. **dhat heap profiler** (commit `3cfffbf`): cumulative
   295 MB allocations при peak alive 371 KB и end 63 KB — Rust
   сторона чистая, 99.996 % аллокаций освобождены.
2. **mimalloc validation** (commit `517498c`): swap allocator'а
   не уменьшил absolute growth (+40 MB vs +32 MB на стоке) —
   glibc арены тоже не источник.
3. **fix-12 validation** (commit `f570376`): cap'нули
   `desired_states` через retention (`desired_state_max_per_resource`,
   default 10) → таблица плато'ит на 14 k строк вместо
   неограниченного роста → **CP RSS growth упал с +116 % до
   +39.6 %** (3× меньше).

**Корень:** рост был реальным, но в **SQLite per-connection
page cache + sqlx prepared-statement cache** — оба масштабируются
с working-set size таблиц. Без cap'а `desired_states` росла на
1 row/submission (24 ч × 1 RPS ≈ 86 k строк); assignment-fetch
SELECT держал их pages hot. С cap'ом working set уменьшается в
~6 раз — кеши и буферы соответственно сжимаются.

**Что делать если RSS всё равно жмёт.** По убыванию ROI:

- **Принять как есть.** При 1 RPS × 24 ч с fix-12 рост +13 MB
  абсолютно; production-projection с 10 k resources × cap=10 =
  100 k DS-строк дала бы ~50-100 MB CP RSS bounded. Для
  большинства deployment'ов это норм.
- **Подкрутить per-resource caps.** Снижение
  `observation_max_per_resource` / `desired_state_max_per_resource`
  с 10 до 3-5 пропорционально уменьшает working set и page-cache
  footprint. Trade-off: меньше debug-истории.
- **Уменьшить sqlx connection pool.** Дефолт ~10 connection'ов
  × 2 MB page cache на каждое = до 20 MB только на pages. SQLite
  однопоточный по write'ам, так что больше 4-5 connection'ов
  редко даёт реальный read-concurrency.
- **`PRAGMA cache_size`.** По умолчанию `-2000` = 2 MB / conn.
  Можно опустить до `-1000` (1 MB) или `-256` (256 KB) для
  RSS-constrained deployment'ов. Trade-off: медленнее cold-page
  reads, hotter pages всё равно осядут.
- **Postgres backend.** Page cache в `shared_buffers` отдельного
  процесса — CP RSS перестаёт расти с размером БД. Стоимость:
  дополнительная инфраструктурная сложность (см. выше про
  3-RPS knee — тот же путь).

### Tuning beyond defaults

Если флот перерастает defaults (симптом: WAL hits cap + 5xx rate
растёт по часам без изменений config), tunables в
[`crates/iac-controlplane/src/config.rs`](../../crates/iac-controlplane/src/config.rs):

- `[retention] observation_max_per_resource` — снизить чтобы
  shrink steady-state DB. 10–20 ОК для большинства observability-needs.
- `[retention] desired_state_max_per_resource` — то же для
  desired_states (Phase 9-F1-fix-12 default = 10).
- `[retention] interval_secs` — снизить чтобы держать working
  set маленьким. 60 с агрессивно, но норм на SSD-class storage.
- `wal_checkpoint_interval_secs` — снизить чтобы reclaim WAL
  быстрее.
- `shutdown_timeout_secs` — поднять если service unit
  имеет высокий TimeoutStopSec и нужен дополнительный grace
  на drain.
- TODO post-Phase 11: `journal_size_limit` пока hard-coded в
  store.rs; вынести в config когда первый оператор упрётся в
  256 MiB на бóльшем флоте.

**Live triage.** При развёрнутом
[Phase 9 observability stack'е](../../trial/observability/README.md)
(Prometheus + Grafana на cp-spare-01) смотри **RSS by host** для
CP — устойчивый линейный рост за 200 MB на маленьком флоте — это
ранний сигнал (после fix-12 ожидаемо < +50 MB за 24 ч). Disk-free
panel ловит WAL-unbounded class до того как он становится
service-impacting.

Без Grafana — поллите напрямую:
```sh
ssh root@<cp> "ls -lh /var/lib/iac-controlplane/server.db*; df -h /"
journalctl -u iac-controlplane --since '5 minutes ago' \
    | grep -c 'database is locked'  # > 50/min ≈ saturation imminent
```

---

## Cross-compile под MIPS / OpenWrt

Репозиторий содержит готовую cross-compile конфигурацию для двух
Tier-3 MIPS-таргетов, используемых OpenWrt и MikroTik-железом:

- `mipsel-unknown-linux-musl` — 32-bit little-endian, рабочая
  лошадка OpenWrt (ar71xx, ramips, ath79).
- `mips64el-unknown-linux-musl` — 64-bit вариант для свежих
  MikroTik CCR/CHR.

Обе цели Tier-3, поэтому `rustc` не поставляет prebuilt `std` —
собираем из исходников через `-Z build-std` (cargo nightly).
`.cargo/config.toml` уже включает это для любого explicit
`--target mipsel-...` / `--target mips64el-...`.

### Prerequisites

- Docker (или podman) — `cross` запускает контейнер с C-toolchain
  внутри (`mipsel-linux-muslsf-gcc` и т. п.).
- Nightly Rust — нужен для `-Z build-std`. Поставь через
  `rustup install nightly && rustup default nightly` или передавай
  `+nightly` per-command.
- Crate `cross` — `cargo install cross --version 0.2.5`.
- `qemu-user-static` если хочешь смок-тестнуть бинарь на
  build-хосте: `apt install qemu-user-static`.

### Recipe сборки (iac-agent для OpenWrt mipsel)

```bash
# WASM на cranelift поддерживает только x86/aarch64 — на MIPS
# нет, так что у агента есть cargo-фича `wasm` (default-on), и
# для MIPS мы её отключаем.
CARGO_UNSTABLE_BUILD_STD=1 \
    cross +nightly build \
        --profile release-mini \
        --target mipsel-unknown-linux-musl \
        -p iac-agent \
        --no-default-features
```

Результат: `target/mipsel-unknown-linux-musl/release-mini/iac-agent`.

### Бюджет на размер бинаря

OpenWrt firmware-образы обычно выделяют 16 MiB rootfs, из которых
у `/usr/local/bin` свободно < 8 MiB. Наш бюджет — **< 10 MiB
stripped**.

```bash
ls -l target/mipsel-unknown-linux-musl/release-mini/iac-agent
# Текущее значение: ~7.0 MiB stripped (commit f3f0a21).
```

Если бинарь начинает выползать за 10 MiB:
- Убедись что `--no-default-features` (включённый WASM-фичей
  даёт +6 MiB).
- Проверь что профиль `release-mini` (`--release` оставляет
  `opt-level=3` + `lto=thin`; `release-mini` переключает на
  `opt-level=z` + `lto=fat` + `strip=true` + `panic=abort`).
- Аудит свежедобавленных зависимостей с прошлого зелёного билда.

### Smoke-тест через qemu-user-static

Sanity-check что бинарь хотя бы стартует на build-хосте:

```bash
qemu-mipsel-static target/mipsel-unknown-linux-musl/release-mini/iac-agent --help
```

Реальное упражнение провайдеров (`file` + `firewall.rule`)
требует настоящего MIPS-устройства; qemu-user ловит только
старт + clap-парсинг.

### Деплой на OpenWrt / MikroTik

`scp` бинарь в `/usr/local/bin/iac-agent` на железку, поставь
`+x`, напиши `/etc/iac/agent.toml`, и либо запускай через procd
init-скрипт (OpenWrt), либо через `/system scheduler` (RouterOS).
Capability-allowlist живёт в `/var/lib/iac-agent/capabilities.yaml`
(см. [справочник](reference.md#capabilities)).

Production-валидация Phase 10 на реальном железе hardware-gated
($30–80 single device, полдня cross-build setup, день на bring-up).
Пока это не сделано — относись к MIPS-поддержке как "компилируется
и smoke-тест проходит", а не "validated end-to-end".

---

## Diagnostic команды

В пару идёт `iac --help`. Сегодня controlplane CLI намеренно узкий
(apply / plan / rollback / drift / audit / users / approve / reject /
login / logout / version); read-side инспекция флота идёт через
`curl` + `jq` против API. Это by design — сервер источник истины,
API — контракт; более толстый admin CLI — это уже v2 ergonomics
pass поверх этих примитивов. `$URL` — base URL controlplane'а,
`$TOKEN` — admin/operator bearer.

```sh
# Recent operations на сервере.
curl -sS -H "Authorization: Bearer $TOKEN" "$URL/v1/operations?limit=20" | jq

# Drift очередь.
iac drift --server "$URL" list                     # все open
iac drift --server "$URL" list --agent-id <id>    # сузить до одного агента

# Audit feed (фильтр — exact-match per field; ни glob'а, ни `since`).
iac audit --server "$URL" --kind operation.submitted --limit 50
iac audit --server "$URL" --actor admin --limit 50
curl -sS -H "Authorization: Bearer $TOKEN" "$URL/v1/audit/chain-tip" | jq
curl -sS -H "Authorization: Bearer $TOKEN" "$URL/v1/audit/verify" | jq

# Agent inventory.
curl -sS -H "Authorization: Bearer $TOKEN" "$URL/v1/agents" \
  | jq '.[] | {name, environment, status, last_heartbeat_at, open_drifts}'
curl -sS -H "Authorization: Bearer $TOKEN" "$URL/v1/agents/<id>" | jq

# Local agent status (запускайте на хосте агента).
iac-agent --config /etc/iac/agent.toml status

# Force re-observe локально (без apply, без серверного взаимодействия).
iac-agent --config /etc/iac/agent.toml observe
```

Для control-plane хоста:

```sh
# Storage health.
sqlite3 /var/lib/iac-controlplane/server.db "PRAGMA integrity_check;"
# Или для Postgres:
psql -c "VACUUM (ANALYZE, VERBOSE) audit_events;"

# Latest log lines.
journalctl -u iac-controlplane -n 200 --no-pager

# Prometheus-shaped метрики, dump в stdout.
curl -sS http://localhost:9090/metrics | grep -E '^iac_'
```

---

## Когда будить людей

| Page если…                                      | Sev |
|--------------------------------------------------|-----|
| Audit-chain verify вернул `ok:false`             | 1   |
| Control-plane down > 5 min                       | 1   |
| Mass agent disconnect (> 50% флота)              | 1   |
| Cert expiry < 24h на production-facing service   | 1   |
| Failed apply, затронувший > 10 хостов            | 2   |
| Signing-key rotation застряла                    | 2   |
| Sustained drift surge (> 10× baseline)           | 2   |
| Backup job провалился дважды подряд              | 3   |

Для sev 1 будите **двух** человек: on-call primary И senior
engineer, знающего control-plane. Sev 2 — primary only. Sev 3
и 4 — заводите тикет; не пейджите.

---

## Post-incident

Пишите after-action report в течение 24h пока детали свежие.
Включайте:

- **Timeline.** Page time, time-to-detection, time-to-mitigation,
  time-to-resolution. UTC throughout.
- **Detection.** Кто/что заметил; могла ли метрика поймать раньше?
- **Root cause.** *Не* proximate trigger — underlying причина.
  Five-whys или предпочтительный фрейм команды.
- **Contributing factors.** Латентные issues, которые превратили
  small problem в big (e.g. устаревший runbook, отсутствующий alert).
- **Action items.** Каждый owned by named person, с deadline.
  Заводите тикеты сразу, не дайте им гнить в документе.

Обновляйте *этот runbook* если incident выявил triage path или
diagnostic команду, которой здесь не было. Future-you скажет
present-you спасибо.
