# Справочник оператора

Руководство по эксплуатации `iac` в продакшене. Предполагает, что
ты прочёл [туториал](tutorial.md).

## Архитектура одним абзацем

Control plane (управляющий узел, `iac-controlplane`) — один процесс
с бэкендом SQLite или Postgres. Принимает желаемое состояние
(desired state) от операторов (`iac` CLI), маршрутизирует задания
агентам в нужном окружении (per-environment), ведёт журнал аудита
(audit log), допускает или блокирует рискованные изменения через
RBAC (управление правами) + approval (согласование) + canary
(пробный выкат). Агент — долгоживущий демон (long-running daemon)
на каждом управляемом хосте, забирает задания (pulls assignments),
применяет их через каталог провайдеров (provider catalog) и
рапортует обратно. Весь трафик идёт по HTTP[S]; агент верифицирует
подпись Ed25519 на каждом задании (assignment), чтобы враждебная
(hostile) сеть не могла впрыснуть работу.

```
   оператор              control plane             агенты
  ┌────────┐    submit    ┌──────────────┐  pull   ┌────────┐
  │ iac    │─────────────▶│ controlplane │◀────────│ iac-   │
  │ (CLI)  │   approve    │ (один процесс)│ result │ agent  │
  └────────┘   rollback   │  + SQLite/PG │─────────└────────┘
                          └──────────────┘            (на каждом хосте)
```

## Конфиг сервера (`server.toml`)

Грузится `iac-controlplane --config <path>`. Перезагрузка мягких
полей по `SIGHUP` (Phase 7bx) — policies, modules, retention,
maintenance windows, retry-after format и `rate_limit` атомарно.
Жёсткие поля (`bind`, `database_url`, `tls`, `webhooks`) всё ещё
требуют рестарта.

```toml
bind          = "0.0.0.0:8443"
database_url  = "sqlite:///var/lib/iac/server/server.db?mode=rwc"
state_dir     = "/var/lib/iac/server"
admin_token   = "<длинная случайная строка — legacy bearer-token для первичного запуска>"
max_body_bytes = 8388608   # 8 MiB; увеличь для больших наборов манифестов

# Agent token TTL — None (опустить) = токены вечные (legacy).
# Рекомендация для prod: 86400 (24h) с auto-rotation.
agent_token_ttl_secs = 86400

# TLS. Поле `mode` обязательно, если присутствует [tls]:
#   "none"   — plain HTTP (только для dev/internal)
#   "server" — HTTPS с сертификатом сервера
#   "mutual" — mTLS; клиент обязан показать сертификат, подписанный client_ca_file
# Полностью убрать блок [tls] = эквивалент mode = "none".
[tls]
mode           = "server"
cert_file      = "/etc/iac/tls/server.crt"
key_file       = "/etc/iac/tls/server.key"
client_ca_file = "/etc/iac/tls/ca.crt"   # обязательно при mode = "mutual"

# Retention — сколько хранить terminal операции + audit события.
[retention]
operations_terminal_days = 90
audit_events_days        = 365

# Per-env, per-policy, per-agent rate limits.
[rate_limit]
operations_per_minute       = 30   # на environment
agent_requests_per_minute   = 600  # на агента (heartbeat/observ./drift)

# Webhook delivery для ops событий.
[[webhooks.sinks]]
name        = "slack-prod"
url         = "https://hooks.slack.example.com/..."
events      = ["operation.failed", "drift.detected"]

# Secret-резолверы — операторы ссылаются на зашифрованные/внешние секреты
# в манифестах через `${secret://<scheme>/<path>[#field]}`. Схема `env`
# доступна всегда (читает env переменные процесса сервера). Vault и SOPS —
# опт-ин.

# HashiCorp Vault — KV v2 запрос по HTTPS. Токен обязан идти по TLS
# (plain http:// отвергается; для тестов используй
# VaultResolver::new_allow_insecure).
[secrets.vault]
addr      = "https://vault.internal:8200"
token_env = "VAULT_TOKEN"   # рекомендуемо — токен берётся из env при старте
# token   = "..."           # inline (избегай в prod)

# Mozilla SOPS — расшифровка age/PGP-файлов в песочнице. Оператор кладёт
# `*.enc.yaml` под `base_dir`; пути резолвятся относительно него и
# отвергаются при попытке вылезти через `..` или симлинки. Без `#field`
# вернёт весь расшифрованный файл (TLS-сертификаты, SSH-ключи, .env-
# блобы пройдут как есть с сохранением внутренних переводов строк).
[secrets.sops]
base_dir = "/var/lib/iac/secrets"
# binary = "/usr/local/bin/sops"   # опционально; default — $IAC_SOPS_BIN или "sops"

# SSH push targets (Phase 7ck) — для хостов без агента.
[[ssh_targets]]
name           = "edge-router-01"
environment    = "edge"
host           = "10.0.0.1"
user           = "admin"
identity_file  = "/etc/iac/ssh/edge.key"
remote_iac_path = "/usr/local/bin/iac"
capabilities   = ["file", "sysctl.setting"]

# Проверка ключа хоста. По умолчанию policy = "strict" — known_hosts_file
# обязателен, незнакомые ключи отбрасываются. Для dev-спайка можно
# host_key_policy = "accept_new" (TOFU): первый фингерпринт пиннится,
# любое изменение позже = отказ.
host_key_policy  = "strict"
known_hosts_file = "/etc/iac/ssh/known_hosts"
```

### Синтаксис secret-ссылок

```yaml
# Где угодно в строковом поле spec'а:
spec:
  env_var:    "${secret://env/DATABASE_PASSWORD}"
  vault_kv:   "${secret://vault/secret/data/myapp/db#password}"
  sops_field: "${secret://sops/postgres.enc.yaml#password}"
  sops_file:  "${secret://sops/tls/server.key.enc}"   # whole-file decrypt
  composed:   "postgres://app:${secret://sops/db.enc.yaml#password}@db/app"
```

Ссылки на секреты лежат в хранилище control plane как есть и
резолвятся в момент выдачи задания агенту (agent-fetch time):
plaintext подставляется в подписанный envelope непосредственно
перед отправкой, поэтому агент видит только подставленное значение,
а в БД и манифестах хранится только ссылка.

Полная схема — в [crates/iac-controlplane/src/config.rs](../../crates/iac-controlplane/src/config.rs).

## Конфиг агента (`agent.toml`)

```toml
server_url    = "https://iac.example.com:8443"
state_dir     = "/var/lib/iac/agent"
environment   = "prod"
agent_name    = "vm-web-01"
observe_interval_secs = 30   # как часто пушить observations + drift

# Опциональный capabilities allowlist. Без него агент применяет любой
# kind, для которого есть провайдер. С ним — реджектит assignments
# с kinds НЕ в этом списке. Защита: "этот хост никогда не должен
# запускать docker."
capabilities_file = "/etc/iac/agent.capabilities.yaml"

# Опциональный TLS / mTLS. Зеркалит [tls] блок сервера.
[tls]
ca_file          = "/etc/iac/tls/ca.crt"
client_cert_file = "/etc/iac/tls/agent.crt"
client_key_file  = "/etc/iac/tls/agent.key"
```

`capabilities.yaml`:

```yaml
# Опционально. Default: `deny` (Phase 7cz.6 — fail-closed перевод) —
# kinds без явного rules-блока отбрасываются сразу. Поставьте
# `allow` для пермиссивной формы (kinds без блока не ограничены).
default_kind_policy: deny

# Per-kind секции. Каждый блок имеет `allow` (и `deny` для
# path-based kinds). Globs — flavour `globset` (`*`, `**`, `?`,
# `[…]`). Ресурсы матчатся против per-resource идентификатора,
# который провайдер возвращает из `capability_keys` (см. секции
# провайдеров ниже).
files:                       # управляет `file`
  allow: ["/etc/nginx/**"]
  deny: ["/etc/nginx/secrets/*"]
nginx_vhost:                 # управляет `nginx.vhost`
  allow: ["/etc/nginx/sites-available/*"]
systemd:                     # управляет `systemd.unit` (allow-only)
  allow: ["nginx", "myapp-*"]
docker:                      # управляет `docker.container` (allow-only)
  allow: ["web-*"]
packages:                    # управляет `package` (allow-only)
  allow: ["nginx"]
cron:                        # управляет `cron.job` (allow-only)
  allow: ["backup-*"]
```

Kinds без per-section блока (`acme.certificate`, `dns.record`,
`monitoring.check`, `sysctl.setting`, `docker.compose`,
`firewall.rule`, плюс любые operator-defined plugin kinds)
проваливаются в `default_kind_policy`.

## Каталог провайдеров

Каждый провайдер следует одному lifecycle: observe → diff → apply →
rollback. `state: present` — default; `state: absent` удаляет (где
поддерживается).

Для каждого провайдера ниже: **spec** (полная схема), **allowlist**
(секция в [`capabilities.yaml`](#конфиг-агента-agenttoml),
управляющая этим kind, и per-resource идентификатор, который
провайдер возвращает для матчинга против globs секции), **подводные
камни**, **пример манифеста**. Kinds, чья запись говорит *"нет
per-kind секции — проваливается в `default_kind_policy`"*, не имеют
выделенного блока в `capabilities.yaml`; их доступ контролируется
исключительно top-level default'ом.

### `file`

```yaml
kind: file
spec:
  path: /etc/foo.conf       # абсолютный path обязателен
  mode: "0644"              # опционально, octal string (в кавычках!)
  content: "..."            # inline-контент; опусти чтобы управлять только метаданными
  owner: root               # опционально; опущено = не трогать владельца
  group: root               # опционально; опущено = не трогать группу
  state: present            # present|absent
```

* **Allowlist:** секция `files:` (path globs); идентификатор = `spec.path`
* **Подводные камни:** `mode` — обязательно строка в кавычках (YAML
  иначе превратит `0644` в число). Если `owner` или `group` не задан,
  агент НЕ трогает владельца/группу — не подставляет текущего
  пользователя по умолчанию. Агенту нужен write на родительскую
  директорию; для `/etc/*` — обычно root или `sudo`. Атомарная запись
  использует `<path>.iac.tmp` + rename — на FS без поддержки rename
  на месте (некоторые FUSE-маунты) не сработает.
* **Пример:**

  ```yaml
  apiVersion: iac.example/v1
  kind: file
  metadata:
    name: nginx-default
    environment: prod
  spec:
    path: /etc/nginx/sites-available/default
    mode: "0644"
    owner: root
    content: |
      server { listen 80; root /var/www/html; }
  ```

### `systemd.unit`

Этот провайдер управляет только *состоянием* юнита (enabled / active);
доставка файла юнита — задача оператора: при необходимости объяви
отдельный `file`-ресурс для `/etc/systemd/system/<name>.service`.

```yaml
kind: systemd.unit
spec:
  name: nginx              # имя юнита; суффикс .service допустим (и добавится автоматически)
  type: service            # service|timer|socket|mount|… (по умолчанию: service)
  enabled: true            # systemctl enable / disable
  active: true             # systemctl start / stop
```

* **Allowlist:** секция `systemd:` (name globs, allow-only); идентификатор = unit name (например `nginx.service`)
* **Подводные камни:** `enabled` и `active` — независимы. `enabled:
  true` без `active: true` настроит autostart, но не запустит сервис
  сейчас. Чтобы изменить *файл* юнита, объяви рядом `file`-ресурс,
  пишущий `/etc/systemd/system/<name>.service`, и сделай
  `systemctl daemon-reload` отдельно (через `cron.job` или скрипт-обёртку);
  этот провайдер сознательно не трогает файловую систему.

### `package`

```yaml
kind: package
spec:
  name: nginx
  state: present           # present|absent — `latest` НЕ поддерживается
  version: "1.18.0-6.1"    # опциональный pin — только при state=present
  backend: apt             # сегодня реализован только `apt` (default)
```

* **Allowlist:** секция `packages:` (name globs, allow-only); идентификатор = `spec.name`
* **Подводные камни:** Сегодня реализован только бэкенд `apt`;
  dnf / pacman / apk в roadmap, но пока падают на validate-этапе.
  Для семантики "всегда последняя версия" фиксируйте `version`
  явно и обновляйте его через GitOps — катящегося `state: latest`
  больше нет. Pin-mismatch триггерит update step на следующем apply.
  `state: absent` вместе с `version` отвергается на validate-этапе.

### `docker.container`

```yaml
kind: docker.container
spec:
  name: web
  image: nginx:1.27
  ports: ["80:80"]                      # ["host:container", ...]
  env:
    NGINX_HOST: "example.com"
  volumes: ["/var/www:/usr/share/nginx/html:ro"]
  restart_policy: unless-stopped        # становится docker --restart=
  state: present
```

* **Allowlist:** секция `docker:` (name globs, allow-only); идентификатор = `spec.name`
* **Подводные камни:** Изменение image-тега → recreate, не rolling
  update. На время recreate сервис недоступен — для zero-downtime
  ставьте балансер впереди. Drift detection через `docker inspect`
  сравнивает image, env, port mappings; volumes сравниваются по source
  path, не по содержимому. Для multi-container стеков — `docker.compose`.

### `docker.compose`

```yaml
kind: docker.compose
spec:
  project: web-stack       # имя docker-compose проекта
  state: present           # present|absent
  source: |                # inline compose YAML
    services:
      app:
        image: nginx:1.27
        ports: ["8080:80"]
  env_file: /etc/iac/web.env  # опционально, --env-file
  workdir: /var/lib/iac/compose  # опционально, override
```

* **Allowlist:** нет per-kind секции — проваливается в `default_kind_policy`
* **Подводные камни:** Имя проекта ограничено `[a-z0-9_-]+` (как у
  docker'а). Source хешируется (sha256) для drift detection — даже
  whitespace-изменение пере-применит стек. Compose-файл материализуется
  в `<workdir>/<project>/docker-compose.yml` — операторы могут `cd`
  туда для ручной отладки `docker compose ps`. Healthchecks per-service
  живут внутри compose YAML (Docker сам ими управляет); IaC их не
  выводит как отдельный drift.
* **Пример:**

  ```yaml
  apiVersion: iac.example/v1
  kind: docker.compose
  metadata: { name: web-stack, environment: prod }
  spec:
    project: web-stack
    source: |
      services:
        web: { image: nginx:1.27, ports: ["80:80"] }
        cache: { image: redis:7, restart: unless-stopped }
  ```

### `nginx.vhost`

```yaml
kind: nginx.vhost
spec:
  config_path: /etc/nginx/conf.d/example.conf   # абсолютный путь записи
  server_names: ["example.com", "www.example.com"]
  upstream: "http://127.0.0.1:8080"             # полный scheme://host:port
  state: present
```

* **Allowlist:** секция `nginx_vhost:` (path globs); идентификатор = `spec.config_path`
* **Подводные камни:** Провайдер пишет ровно по `spec.config_path` —
  никакого танца sites-available/sites-enabled с симлинками. Выбирайте
  путь, который nginx уже инклюдит (`conf.d/*.conf` на большинстве
  дистрибутивов). `upstream` обязан содержать префикс схемы (`http://`
  или `https://`) и быть одним эндпоинтом. Бэкенд запускает `nginx -t`
  перед тем как объявить apply успешным, и делает reload через
  `systemctl reload nginx`. Для тонкой кастомизации (TLS, custom-headers)
  откажитесь от vhost-ресурса и используйте `file`-ресурс с полным
  конфигом — этот провайдер сознательно не выводит каждую опцию.

### `cron.job`

```yaml
kind: cron.job
spec:
  name: backup
  schedule: "0 3 * * *"    # 5-полевой crontab
  command: "/usr/local/bin/backup.sh"
  user: root
  state: present
```

* **Allowlist:** секция `cron:` (name globs, allow-only); идентификатор = `spec.name`
* **Подводные камни:** Пишет в `/etc/cron.d/iac-<name>` с tag-заголовком
  — ручная правка (или правка другим инструментом) безопасна. Schedule
  принимает классический 5-полевой синтаксис **или** Vixie-макросы
  (`@yearly`, `@annually`, `@monthly`, `@weekly`, `@daily`, `@midnight`,
  `@hourly`, `@reboot`); секунды не поддерживаются. Команда выполняется
  через `/bin/sh -c` — аккуратно с подстановкой env-vars (кавычки!).

### `firewall.rule`

```yaml
kind: firewall.rule
spec:
  name: allow-https        # тег comment в iptables / nft
  chain: INPUT
  action: ACCEPT
  protocol: tcp
  port: 443                # destination port
  state: present
```

* **Allowlist:** нет per-kind секции — проваливается в `default_kind_policy`
* **Подводные камни:** Бэкенд по умолчанию — iptables, идентифицирует
  свои правила через `-m comment --comment "iac:<name>"`. Бэкенд
  nftables (доработка Phase 9) включается через переменную
  `IAC_FIREWALL_BACKEND=nft` (или `nftables`) — для RHEL 9+, недавних
  Fedora и операторов, предпочитающих нативные nftables-семантики.
  Переживает `iptables -F` / `nft flush` (мы пере-применяем на observe),
  но не переживает reboot, если не персистите через средства
  дистрибутива (`iptables-persistent` на Debian, `nftables.service`
  save/restore — IaC этим пока не управляет).

### `monitoring.check`

```yaml
kind: monitoring.check
spec:
  name: app-health         # ОБЯЗАТЕЛЬНО — идентификатор проверки
  type: http               # http|tcp
  target: http://localhost:8080/healthz
  expected_status: 200     # http only
  timeout_secs: 5
  retries: 5               # Phase 7cj: retry on failure
  retry_interval_secs: 2
  state: present
```

* **Allowlist:** нет per-kind секции — проваливается в `default_kind_policy`
* **Подводные камни:** `apply` активно запускает probe (это шаг
  верификации, не просто запись конфига). Pure `std::net` HTTP/1.0 —
  HTTPS в v1 нет; для TLS-эндпоинтов держите локальный non-TLS
  liveness за TLS-терминатором. Failure после retries отменяет
  baseline (canary gating). Подбирайте `retries`/`retry_interval_secs`
  под warm-up upstream'а: слишком агрессивные значения вызывают
  ложные rollback'и при старте приложения.

### `sysctl.setting`

```yaml
kind: sysctl.setting
spec:
  key: net.ipv4.tcp_keepalive_time
  value: "120"
  state: present
```

* **Allowlist:** нет per-kind секции — проваливается в `default_kind_policy`
* **Подводные камни:** Пишет значение runtime прямо в
  `/proc/sys/<ключ-через-слэши>` — без shell-out, без `sysctl -p`,
  без сторонних зависимостей. **Изменение только runtime, теряется
  при ребуте.** Для сохранения между перезагрузками объяви рядом
  `file`-ресурс, пишущий в `/etc/sysctl.d/iac-<name>.conf`, чтобы
  ядро перезагрузило значение при следующем старте. Некоторые ключи
  (например `net.bridge.*`) требуют предварительной загрузки модуля
  ядра — IaC сам модуль не загрузит. Value — всегда строка в кавычках
  (даже для числа): YAML иначе превратит `0644` в число.

### `dns.record`

```yaml
kind: dns.record
spec:
  zone: example.com
  name: app                # относительно zone, FQDN, или '@' для apex
  type: A                  # A|AAAA|CNAME|TXT|MX
  value: "1.2.3.4"
  ttl: 300                 # секунды, ≥30
  state: present
  provider: cloudflare     # единственный backend в Phase 7cx
  cloudflare:
    api_token: "${secret://env/CF_API_TOKEN}"
```

* **Allowlist:** нет per-kind секции — проваливается в `default_kind_policy`
* **Подводные камни:** Идентификатор upsert — `(zone, name, type)`.
  Несколько записей с одинаковыми name+type (round-robin A,
  несколько TXT) — не моделируются: разносите их в отдельные
  манифесты с разными `metadata.name`, если backend сам дедуплицирует
  на серверной стороне. Тип-зависимая валидация на клиенте: `A`
  отбрасывает не-IPv4, `CNAME` требует hostname-вид. `ttl < 30`
  отбрасывается заранее — большинство провайдеров их и так отвергает.
* **Пример:**

  ```yaml
  apiVersion: iac.example/v1
  kind: dns.record
  metadata: { name: app-a, environment: prod }
  spec:
    zone: example.com
    name: app
    type: A
    value: "203.0.113.10"
    ttl: 300
    provider: cloudflare
    cloudflare: { api_token: "${secret://env/CF_API_TOKEN}" }
  ```

### `acme.certificate`

```yaml
kind: acme.certificate
spec:
  domains: ["example.com", "www.example.com"]
  email: ops@example.com
  cert_dir: /etc/iac/certs/example.com
  state: present
  renew_window_days: 30                # 1..=89
  staging: false                       # Let's Encrypt staging
  challenge: http-01                   # http-01 | dns-01-cloudflare
  webroot: /var/www/html               # требуется для http-01
  cloudflare_api_token: "${secret://env/CF_API_TOKEN}"  # для dns-01-cloudflare
```

* **Allowlist:** нет per-kind секции — проваливается в `default_kind_policy`
* **Подводные камни:** Первый домен — CN, остальные — SAN. Wildcard
  (`*.example.com`) требует `challenge: dns-01-cloudflare`: HTTP-01
  не умеет валидировать литеральный `*`. Cert/key пишутся в
  `<cert_dir>/<primary>.crt` и `<cert_dir>/<primary>.key` — из
  `nginx.vhost` (или вашего TLS-терминатора) ссылайтесь на эти
  пути. Auto-renew — когда expiry в `renew_window_days`. `staging:
  true` — обязательно при первой настройке зоны: Let's Encrypt prod
  rate-limits жёсткие.
* **Пример:**

  ```yaml
  apiVersion: iac.example/v1
  kind: acme.certificate
  metadata: { name: example-com-cert, environment: prod }
  spec:
    domains: ["example.com", "www.example.com"]
    email: ops@example.com
    cert_dir: /etc/iac/certs/example.com
    challenge: dns-01-cloudflare
    cloudflare_api_token: "${secret://env/CF_API_TOKEN}"
  ```

### Композитные ресурсы (composites)

`kind: service` раскрывается серверной стороной в `docker.container`
плюс `nginx.vhost`, если задан `domain`:

```yaml
kind: service
spec:
  name: web
  image: nginx:1.27
  port: 80                 # публикуемый host-порт (одно значение, не список)
  internal_port: 80        # опционально; порт прослушивания контейнера (default 80)
  domain: example.com      # опционально — при наличии генерируется nginx.vhost
```

Композит создаёт Docker-контейнер и, если задан `domain`,
соответствующий `nginx.vhost`. Никакой неявной `monitoring.check`
сегодня нет; объяви её отдельно рядом с `service`, если нужен
health-гейт.

Кастомные композиты объявляются как `[[modules]]` в server.toml
(Phase 7bv): TOML-шаблон с подстановкой скаляров через `{{ var }}`.

## Кастомные провайдеры

Агент позволяет добавлять новые resource kinds без пересборки бинарника.
Две точки расширения покрывают типовые случаи — выбирайте наиболее
простую, которая подходит.

### Trust model плагинов

> **Плагины работают с полными UID-привилегиями агента.**
> Вредоносный или buggy плагин может прочитать identity-файл
> агента (`<state_dir>/identity.json` — ваши control-plane
> creds), переписать БД агента, утащить любой ресурс, который
> когда-либо прошёл через `observe`, и exec'нуть произвольные
> бинарники. **Обращайтесь с plugin-бинарниками так же, как с
> бинарником агента.** Тот же provenance, sign-off, pinning.

Что runtime *обеспечивает*:

* **WASM-плагины** работают внутри wasmtime с hard CPU (fuel)
  и memory caps и без I/O imports пока оператор не opt-in'нул
  через `[wasi]`. Граница sandbox'а реальная — WASM-плагин
  не может из неё выскочить без wasmtime CVE.
* **External-process плагины** имеют call timeouts, NDJSON
  line caps (16 MiB), restart cool-off после серии crash'ей.
  В этих рамках плагин всё ещё работает с UID агента и
  наследует его filesystem access.
* **Shellout плагины** получают per-command timeouts и zombie
  reaping. Тот же UID-level trust что и external-process.

Что runtime **НЕ делает** (ответственность оператора):

* **Целостность plugin-бинарника.** Используйте поля
  `module_sha256` / `binary_sha256` в config'е чтобы прикрепить
  SHA-256 артефакта. Без pin'а атакующий, имеющий запись в
  путь плагина на хосте агента, может подменить бинарник и
  агент загрузит то, что там лежит. Pin'те через ваш
  config-management (Ansible, Chef, Salt, GitOps).
* **OS-level isolation.** Агент не спавнит плагины под
  отдельными UID / namespaces / cgroups. Если нужна
  per-plugin изоляция — запускайте агент внутри systemd
  user service со своим UID, или заверните весь агент в
  контейнер. Это платформенная интеграция, не то, что агент
  делает за вас.
* **Egress control плагина.** Runtime может ограничить WASI
  network/filesystem capabilities, но external-process и
  shellout плагины наследуют сеть агента. Если плагин НЕ
  должен ходить в публичный интернет — это работа network-
  policy / firewall на уровне OS / кластера.

### Рекомендуемая гигиена

1. **Pin'те SHA-256 каждого plugin-бинарника** в `agent.toml`.
   Обновляйте pin'ы через нормальный config-change-management.
2. **Запускайте агент под отдельным UID** (не root) если
   ресурсы, которыми он управляет, не требуют root. Большинство
   провайдеров работают под непривилегированным юзером с sudo
   на конкретные команды.
3. **Используйте WASM component-плагины** (с `[wasi]` opt-in)
   для всего, что вы не полностью контролируете — community
   plugins, vendor-shipped расширения, всё что вы не писали
   сами. Sandbox — реальная граница; другие runtime'ы — нет.
4. **Аудитьте `agent.toml`** так же, как бинарник агента — он
   контролирует, какой код агент будет загружать и запускать.

### Shell-out провайдеры (`[[shellout_providers]]`)

Оборачивают существующий CLI в три коротких shell-скрипта. Подходят
когда нижележащая операция уже доступна как одноразовая команда
(`iptables`, `ufw`, vendor-CLI, in-house Python-скрипт).

```toml
# agent.toml
[[shellout_providers]]
kind = "ufw.rule"                              # обязательно, уникально
observe = "/usr/local/bin/iac-ufw observe"     # обязательно
apply   = "/usr/local/bin/iac-ufw apply"       # обязательно
verify  = "/usr/local/bin/iac-ufw verify"      # опц.; fallback — re-observe
rollback = "/usr/local/bin/iac-ufw rollback"   # опц.; fallback — re-apply prior spec
capability_keys = ["{{ name }}"]               # `{{ field }}` берёт top-level скаляры из spec
env = ["UFW_DEBUG=1"]                          # additive — наследуемый env сохраняется
timeout_secs = 30                              # 1..=600
```

**Wire protocol** (stdin → stdout, по одному JSON-объекту):

* `observe` ← `{ kind, metadata, spec }` → `{ present: bool, spec? }`
* `apply` ← `{ kind, metadata, spec, phase: "create"|"update"|"delete" }` → `{ status: "ok"|"failed", message? }`
* `verify` ← как у observe → как у observe (post-apply проверка)
* `rollback` ← `{ kind, metadata, checkpoint }` → пустое тело, exit 0 = успех

`diff` агент вычисляет автоматически через побайтовое сравнение `spec`
против `observed.spec` (с `state: absent` → Delete) — ваш скрипт diff
никогда не видит. Capability-ключи получаются раскрытием шаблонов
выше относительно top-level скалярных полей resource.spec.

Tradeoff: spawn на каждом вызове (~1–5 мс на слабом CPU) и ограничения
по гранулярности diff (только top-level). Для chatty upstream'ов
или структурированного сравнения по полям — берите external-process.

### External-process plugin провайдеры (`[[external_providers]]`)

Долго живущий plugin-бинарник говорит NDJSON-RPC через stdin/stdout.
Подходит когда upstream требует persistent state — connection pools,
auth tokens, кеши — которые дорого пересоздавать на каждый вызов
(Kubernetes API, AWS SDK, gRPC сервисы).

```toml
# agent.toml
[[external_providers]]
kind = "k8s.deployment"
binary = "/usr/local/bin/iac-k8s-plugin"      # обязательно, абсолютный путь
args = ["--cluster", "prod"]                   # опц., препендится к argv
env = ["KUBECONFIG=/etc/iac/kc"]               # опц.
restart_on_crash = true                        # default: true
handshake_timeout_secs = 5                     # 1..=60
call_timeout_secs = 60                         # 1..=3600
```

**Lifecycle:**

1. Агент спавнит бинарник с piped stdin/stdout.
2. Плагин выводит одну JSON-строку на stdout — **hello-сообщение**:
   ```json
   {"hello":{"protocol_version":1,"kind":"k8s.deployment","capability_keys":["{{ name }}"],"methods":["observe","apply","diff","verify"]}}
   ```
   `kind` должен совпадать с конфигом агента (защита в глубину —
   ловит дрейф binary/config). `methods` перечисляет опциональные
   методы, в которые плагин opt-in'ится; для остальных агент
   подставляет fallback'и.
3. Дальше агент гоняет request/response цикл по stdin/stdout плагина:
   * Запрос: `{"id":<u64>, "method":"<name>", "params":{...}}`
   * Ответ: `{"id":<u64>, "result":{...}}` или `{"id":<u64>, "error":"..."}`

**Обязательные методы:** `observe`, `apply` (params такие же как у
shellout-протокола). Для `diff`, `verify`, `rollback`, `pre_apply`
агент использует fallback'и, если плагин не перечислил их в
`hello.methods`.

**Восстановление после краха:** если `restart_on_crash = true`
(default), агент прозрачно перезапускает бинарник при следующем
вызове после transport-ошибки. Плагины должны хранить durable
state на диске (не в памяти): runtime может рестартануть в любой
момент.

**Trust model:** плагин запускается под UID агента с полным доступом
к ФС. Операторы запускают плагины которым доверяют, ровно как и
сам бинарник агента. Пинуйте sha256 бинарников через distribution-
механизм, если нужна целостность.

### Sandboxed WASM плагины (`[[wasm_providers]]`)

Загружают `.wasm`-модуль внутрь wasmtime-песочницы. Подходит для
кода, которому доверяют меньше (community marketplace, third-party
вендоры, плагины от партнёра без доступа к ФС хоста), и для
воспроизводимой кросс-платформенной поставки (один `.wasm` —
идентичен на linux/macos/windows).

```toml
# agent.toml
[[wasm_providers]]
kind = "ufw.rule"
module = "/usr/local/share/iac/plugins/ufw.wasm"  # абсолютный путь
max_memory_bytes = 16777216                       # 16 MiB, default 16 MiB; range 64 KiB..=1 GiB
fuel_per_call = 100_000_000                       # ~100M инструкций, default 100M
```

**ABI v1.** Плагин обязан экспортировать:

* `memory: memory` — линейная память.
* `iac_alloc(size: i32) -> i32` — выделить scratch-буфер; хост туда пишет JSON envelope.
* `iac_dealloc(ptr: i32, size: i32)` — освободить буфер.
* `iac_kind() -> i64` — упакованный `(ptr<<32) | len` строки kind. Валидируется против config'а.
* `iac_observe(ptr: i32, len: i32) -> i64` — обязательно.
* `iac_apply(ptr: i32, len: i32) -> i64` — обязательно.

Опциональные методы плагин включает экспортом `iac_methods() -> i64`, возвращающим JSON-массив имён: `iac_diff`, `iac_verify`, `iac_rollback`, `iac_pre_apply`, `iac_capability_keys`. Всё остальное обрабатывает host fallback (то же поведение что у shellout / external-process).

**Sandbox model.**

* Без WASI. Плагин не видит ФС, env, сеть.
* `max_memory_bytes` лимитирует `memory.grow` — превышение трапает гостя.
* `fuel_per_call` декрементится примерно раз на инструкцию; runaway loop трапается до того, как съест CPU.
* Хост экспортирует ровно один import: `iac.log(ptr, len)` — operator-visible диагностика идёт через `tracing`-pipeline агента.

**Каждый top-level вызов получает свежий `Store`** с полным fuel-бюджетом — overrun предыдущего вызова не отравит следующий. Плагинам, которым нужно persistent state, хранить его снаружи модуля (host-managed файл, которым владеет агент).

**Писать плагин на Rust.** `cargo build --release --target wasm32-unknown-unknown`; экспортируйте ABI через `#[no_mangle] pub extern "C" fn iac_observe(...) -> i64 { ... }`. Минимальный scratchpad-аллокатор хватит — пример end-to-end WAT в тестах [`crates/iac-providers/src/wasm/runtime.rs`](../../crates/iac-providers/src/wasm/runtime.rs).

#### Component-model вариант (`runtime = "component"`)

Core-ABI выше работает для hand-written плагинов, но руками возиться
с ptr/len и JSON envelope быстро надоедает. Phase 7dd добавил
типизированный режим: ставите `runtime = "component"` — и плагин
работает против строго-типизированного WIT-интерфейса.

```toml
[[wasm_providers]]
kind = "ufw.rule"
module = "/usr/local/share/iac/plugins/ufw.component.wasm"
runtime = "component"                       # opt-in
max_memory_bytes = 16777216
fuel_per_call = 100_000_000
```

**WIT-интерфейс** (источник: [`crates/iac-providers/wit/plugin.wit`](../../crates/iac-providers/wit/plugin.wit)):

```wit
package iac:plugin@0.1.0;

interface provider {
    record metadata { name: string, environment: string,
                      labels: list<tuple<string, string>>,
                      annotations: list<tuple<string, string>> }
    record observed { present: bool, spec-json: string }
    record apply-outcome { ok: bool, message: string }
    enum phase { create, update, delete }

    kind: func() -> string;
    methods: func() -> list<string>;
    observe: func(metadata: metadata, spec-json: string) -> result<observed, string>;
    apply: func(metadata: metadata, spec-json: string, phase: phase) -> apply-outcome;
    capability-keys: func(metadata: metadata, spec-json: string) -> list<string>;
}

world plugin { export provider; }
```

**Поверхность автора (Rust).** Подключаете [`wit-bindgen`](https://crates.io/crates/wit-bindgen) и пишете:

```rust
wit_bindgen::generate!({ world: "plugin", path: "wit/plugin.wit", generate_all });

use exports::iac::plugin::provider::{
    ApplyOutcome, DiffKind, DiffResult, Guest, Metadata, Observed, Phase, VerifyOutcome,
};

struct MyPlugin;
impl Guest for MyPlugin {
    fn kind() -> String { "ufw.rule".into() }
    fn methods() -> Vec<String> { vec![] }  // или ["diff", "verify", "pre-apply", "rollback"]
    fn observe(m: Metadata, spec: String) -> Result<Observed, String> { /* ... */ }
    fn diff(m: Metadata, spec: String, observed: Observed) -> DiffResult { /* ... */ }
    fn pre_apply(m: Metadata, spec: String) -> Result<String, String> { /* checkpoint JSON */ }
    fn apply(m: Metadata, spec: String, phase: Phase) -> ApplyOutcome { /* ... */ }
    fn verify(m: Metadata, spec: String) -> VerifyOutcome { /* ... */ }
    fn rollback(m: Metadata, checkpoint: String) -> Result<(), String> { /* restore */ }
    fn capability_keys(m: Metadata, _: String) -> Vec<String> { vec![m.name] }
}
export!(MyPlugin);
```

Собирать через [`cargo-component`](https://github.com/bytecodealliance/cargo-component) (рекомендуется) или `cargo build --target wasm32-unknown-unknown` + `wasm-tools component new`. В любом случае результат — один `.component.wasm`.

**Опциональные методы.** Все методы trait'а обязательны на уровне *Rust* (`Guest` impl должен реализовать каждую сигнатуру, которую генерирует wit-bindgen), но *вызывает* host только те, которые перечислены в `methods()`. Распознаваемые имена opt-in: `"diff"`, `"verify"`, `"pre-apply"`, `"rollback"`. Каждый не-listed метод получает host fallback:

| Метод       | Host fallback (когда не opted in) |
|-------------|-----------------------------------|
| `diff`      | побайтовое spec-equality          |
| `verify`    | re-observe + diff                 |
| `pre-apply` | snapshot prior observed state     |
| `rollback`  | re-apply prior observed spec      |

**Зачем opt-in?** Host'овский spec-equality diff подходит для record-shaped ресурсов, но теряет точность когда observed state — *производное* (checksum vs. содержимое файла, нормализованное представление vs. ввод пользователя). Плагины, которым важны эти нюансы, возвращают структурированные `DiffResult` напрямую — host пробрасывает их verbatim, без JSON round-trip на проводе.

**Типизированные pre-apply / rollback.** При opt-in `pre-apply` возвращает JSON-encoded *checkpoint-строку*, которую host хранит непрозрачно. Host не заглядывает внутрь; на rollback она передаётся обратно плагинскому `rollback`. Шейп checkpoint'а полностью в руках плагина — операторам не нужно проектировать host-shaped schema для plugin state. WIT-сигнатура:

```wit
pre-apply: func(metadata: metadata, spec-json: string) -> result<string, string>;
rollback: func(metadata: metadata, checkpoint-json: string) -> result<_, string>;
```

Байты round-trip'ятся verbatim. Плагины которым нужна богатая rollback-семантика (multi-step, idempotent retries) владеют этой логикой — host работает byte-pipe'ом.

**Sandbox и lifecycle — те же.** Fuel limits, memory caps. По умолчанию без I/O — идентично core-варианту. Component-плагины могут opt-in'ом получить capability-driven I/O через `[wasi]` блок (следующая секция).

**Эталонный fixture.** [`crates/iac-providers/tests/fixtures/test-plugin/`](../../crates/iac-providers/tests/fixtures/test-plugin/) — готовый working компонент-плагин в ~50 строках Rust — копируйте как стартовую точку.

#### WASI preview2 capabilities

Component-model плагины (только component — core ABI не носит preview2 imports) могут opt-in'ом получить capability-driven I/O. Default — никакой WASI surface; всё ниже — opt-in.

```toml
[[wasm_providers]]
kind = "policy.engine"
module = "/srv/iac/policy.component.wasm"
runtime = "component"

[wasm_providers.wasi]
env = ["LOG_LEVEL=info"]
inherit_stdout = false       # default: false — guest stdout дропается
inherit_stderr = false
allow_network = false        # default: false — без sockets / dns

[[wasm_providers.wasi.preopens]]
host = "/var/lib/iac/policy/state"
guest = "/state"
writable = true              # default: false — read-only

[[wasm_providers.wasi.preopens]]
host = "/etc/iac/policy.d"
guest = "/policies"
# writable default = false → read-only mount
```

**Capability semantics.**

* **Preopens.** Каждая запись маппит host-директорию на guest-путь. Плагин видит `/state` (или какой guest-путь) как root и может `std::fs::read_dir`, `read_to_string` и т.д. под ним. *Никакие* host-пути не доступны — плагин не может `..` выскочить, не может открыть произвольные файлы, не видит другие preopen'ы пока они не объявлены.
* **Read-only по умолчанию.** Для записи нужен `writable = true`. Паттерн `read /etc/iac/<plugin>/config + write /var/lib/iac/<plugin>/state` — рекомендуемый.
* **Env.** Перечисляется явно; плагин НЕ наследует env агента. Передавайте только нужное.
* **Stdio.** Выключено по умолчанию. Plugin output никуда не идёт. Структурный путь — `tracing` через `iac.log` или wit-bindgen-generated логирование.
* **Network.** Выключено по умолчанию. При opt-in'е плагин видит wasi-sockets surface. **Плагины, которым нужен исходящий network, обычно лучше делать через external-process** — но для vendor-shipped компонент'ов это knob.

**Build target.** Плагины использующие WASI должны таргетиться на `wasm32-wasip2`:

```sh
rustup target add wasm32-wasip2
cargo build --release --target wasm32-wasip2
```

Output уже компонент (`wasm-tools component new` шаг не нужен). Плагины без WASI могут таргетиться на `wasm32-unknown-unknown` и componentise post-build через `cargo-component` или `wasm-tools`.

**Fail-closed.** Если плагин импортирует `wasi:filesystem`, но оператор забыл `[wasi]` блок (или поставил `preopens = []`) — instantiation падает на старте агента с ясным "missing import" error'ом. Loud signal, не silent malfunction.

**Эталонный fixture.** [`crates/iac-providers/tests/fixtures/wasi-plugin/`](../../crates/iac-providers/tests/fixtures/wasi-plugin/) — читает host-preopened файл через `std::fs` и возвращает контент через `observe`. Стартовая точка для плагинов, которым нужен filesystem state.

### Что выбирать

| Нужно                                            | shellout | external-process | wasm |
|--------------------------------------------------|:--------:|:----------------:|:----:|
| Обернуть existing CLI                            | ✅       |                  |      |
| Per-resource latency упирается в spawn           |          | ✅               | ✅   |
| Persistent in-memory state между вызовами        |          | ✅               |      |
| Кастомный diff / structured field-by-field       |          | ✅               | ✅   |
| Untrusted / third-party plugin code              |          |                  | ✅   |
| Hard CPU + memory limits на плагин               |          |                  | ✅   |
| Кросс-платформенный single artifact              |          |                  | ✅   |
| Автор не уверен с read/write loop'ом             | ✅       |                  |      |
| Быстро добавить 12 тривиальных kind'ов           | ✅       |                  |      |

Все три точки расширения переопределяют built-in'ы при коллизии
`kind` — агент логирует override и использует динамический.
Дубликаты `kind` между тремя источниками отклоняются на стадии
загрузки конфига.

## RBAC (управление правами по ролям)

Три класса личности (identity):

* **`LegacyAdmin`** — статичный `admin_token` из server.toml.
  Эквивалент роли Admin. Полезен для первичного запуска (bootstrap);
  в проде стоит ротировать на реальных пользователей.
* **`User`** — создаётся через `iac users create`, хранится хеш
  Argon2id. Роли прикреплены при создании.
* **`Agent`** — программная личность, регистрируется через
  `POST /v1/agents/register`. Не может выполнять действия уровня
  оператора.

Роли в решётке (lattice): `Viewer < Operator < Approver < Admin`.

```bash
iac users create --server <url> --user alice --roles operator
iac users create --server <url> --user bob   --roles approver
iac users create --server <url> --user root  --roles admin
# Несколько ролей: --roles operator,approver
```

## Политики и шлюзы согласования (policies + approval gates)

```toml
[[policies]]
name = "prod-requires-approval"
match.environment = "prod"
match.resource_count_min = 1
requires_approval = true
approvers = ["bob", "charlie"]

[[policies]]
name = "prod-rate-limit"
match.environment = "prod"
rate_limit_per_minute = 5
```

Операция с `requires_approval` садится в статус `pending_approval`.
Согласующий (approver) смотрит через `iac plan --server <url>
--operation <id>`, ревьюит разницу (diff), потом
`iac approve <op-id> --server <url>`.

## Canary-выкатывания (canary rollouts)

```bash
iac apply manifests/ --server <url> --environment prod \
                     --canary-pct 25 --yes
```

Внутри каждого layer'а 25% агентов идут в batch 0 (canary), остальные
— batch 1 (baseline). Любая ошибка в canary отменяет и остаток
canary, и весь baseline.

Для health-gate — добавь `monitoring.check` в canary resource list:

```yaml
- kind: file
  metadata: { name: app-config, dependsOn: [] }
- kind: docker.container
  metadata: { name: app, dependsOn: [file/prod/app-config] }
- kind: monitoring.check
  metadata: { name: app-health, dependsOn: [docker.container/prod/app] }
  spec:
    name: app-health
    type: http
    target: http://localhost:8080/health
    retries: 5
    retry_interval_secs: 2
```

## GitOps (управление инфраструктурой через Git)

```bash
# Проверка (gate) в CI на каждый pull request
iac plan --git-repo $REPO --git-ref $PR_SHA \
         --git-path manifests/ --server $URL

# После merge (слияния)
iac apply --git-repo $REPO --git-ref main \
          --git-path manifests/ --server $URL \
          --canary-pct 25 --yes
```

CLI клонирует репозиторий (`git fetch --depth=1`), разрешает ссылку
(ref) в 40-символьный SHA через `git rev-parse FETCH_HEAD`, делает
detached checkout (выгрузку коммита без ветки), записывает SHA как
`source_commit`. Per-repo cache (кеш по репозиторию) в
`$XDG_CACHE_HOME/iac-cli/git/`. Аутентификация — из системного
конфига `git`.

## SSH push (хосты без агента)

Для хостов, где нельзя поднять долгоживущий демон `iac-agent` —
встроенное сетевое железо, вендорские appliance'ы (готовые
аппаратно-программные коробки), контракторские окружения с
запретом демонов — объяви их как `[[ssh_targets]]` в `server.toml`.
Control plane относится к ним как к виртуальным агентам
(маршрутизация, canary, откат — всё работает так же), но вместо
ожидания их опроса (poll) — push-воркер сам идёт по SSH на каждый,
когда прилетают задания (assignments).

```toml
[[ssh_targets]]
name           = "edge-router-01"
environment    = "edge"
host           = "10.0.0.1"
user           = "admin"
identity_file  = "/etc/iac/ssh/edge.key"   # только SSH-ключ
remote_iac_path = "/usr/local/bin/iac"     # должен быть pre-installed
capabilities   = ["file", "sysctl.setting"] # allowlist; пустой = любое
connect_timeout_secs = 10

# Проверка ключа хоста. По умолчанию policy = "strict" — known_hosts_file
# обязателен, незнакомые ключи отбрасываются. Для dev-спайка можно
# host_key_policy = "accept_new" (TOFU): первый фингерпринт пиннится,
# любое изменение позже = отказ.
host_key_policy  = "strict"
known_hosts_file = "/etc/iac/ssh/known_hosts"
```

Предварительные требования (prerequisites) на каждом хосте:
1. SSH-ключ в `~admin/.ssh/authorized_keys` (публичная пара
   `identity_file`).
2. Бинарь `iac` лежит по `remote_iac_path`. На Ubuntu:
   `curl -L https://example.com/iac-aarch64 > /usr/local/bin/iac && chmod +x ...`
3. У пользователя есть нужные привилегии (root для записи `file`
   в `/etc` и т. п.). `sudo` не вызывается автоматически.

Использование со стороны оператора идентично pull-mode-агенту —
тот же `iac apply` с `hostSelector.name: edge-router-01`. SSH
worker pool (пул рабочих процессов) диспатчит прозрачно.

Записи в журнале аудита: `ssh.push_succeeded`, `ssh.push_partial`,
`ssh.push_failed`. Actor (актор события) — `ssh-push:<target_name>`.

Компромиссы по сравнению с pull-mode-агентами:
* Нет обхода NAT (NAT traversal) — control plane должен дотянуться
  до хоста.
* Учётные данные (SSH-ключ) в control plane — больше радиус
  поражения (blast radius) при компрометации.
* Нет ограничений на стороне агента (agent-side capability
  enforcement) — работает только серверный allowlist
  `capabilities = [...]`.

Используй pull-mode для основной массы флота; SSH push — для
хостов, где нет выбора.

## Прямой SSH-apply из CLI (direct CLI SSH apply, Phase 7cl)

Для одноразового (one-off) деплоя без сервера — `iac apply --ssh`:

```bash
iac apply manifest.yaml --ssh admin@host.example --ssh-key ~/.ssh/key
```

CLI открывает SSH, передаёт payload в удалённый `iac apply
--assignment-stdin`, разбирает результат. Требуется бинарь `iac` на
целевом хосте (инструмент подскажет команду `curl` для установки,
если его нет).

## Откат (rollback)

```bash
iac rollback <operation-id> --server <url> \
             --reason "incident-1234" \
             --canary-pct 50
```

Строит новую операцию из последних успешных спецификаций
(most-recent-prior-succeeded) для каждого ресурса. Идёт через
нормальный конвейер (policy + approval + canary). Ресурсы без
предыдущего состояния попадают в список `orphaned` (осиротевшие) —
их удаляют вручную.

## Наблюдаемость (observability)

### Метрики Prometheus

`GET /metrics` (без аутентификации). Счётчики операций (operation
counters), размер флота агентов, число событий drift, отказы по
rate-limit, информация о ключах подписи.

### Журнал аудита (audit log)

```bash
iac audit --server <url> --kind operation.submitted --limit 50
iac audit --server <url> --actor admin --limit 100
iac audit --server <url> --operation-id <id>
iac audit --server <url> --agent-id <id>
```

Фильтры — точное совпадение по полю; серверного сужения по
временному окну нет. Запрашивайте последний батч через `--limit`,
потом сужайте на стороне клиента через `jq`, если нужен фильтр в
стиле `since`; эндпоинт возвращает строки от свежих к старым
(newest-first).

## Окна обслуживания (maintenance windows)

Пауза non-emergency apply в change-freeze:

```toml
[[maintenance_windows]]
start    = "2026-12-24T00:00:00Z"
end      = "2027-01-02T00:00:00Z"
reason   = "holiday freeze"

[[recurring_maintenance_windows]]
days     = ["Sat", "Sun"]
start_time = "00:00"
end_time   = "23:59"
timezone   = "America/New_York"
reason     = "weekend freeze"
```

Submit в окне → 503 + `Retry-After`. Override через
`X-IAC-Maintenance-Bypass: yes` (admin only).

## Рабочие сценарии с дрифтом (drift workflows)

```bash
iac drift --server <url> list                          # открытые drifts (расхождения)
iac drift --server <url> accept <drift-id> --reason X  # принять как известный
iac drift --server <url> ignore <drift-id> --until 1h  # заглушить на N {s|m|h|d}
iac drift --server <url> revert <drift-id> --reason X  # переприменить предыдущее состояние
iac drift --server <url> accept-bulk --agent-id <id> --reason X
iac drift --server <url> ignore-bulk --agent-id <id> --until 24h --reason X
```

Агенты пушат события drift на каждом цикле наблюдения. Drift,
которого нет в свежем push'е, авто-закрывается (считается, что мир
сошёлся к описанному снаружи).

## Ротация ключа подписи сервера (signing-key rotation)

```bash
# Rotate (active меняется; старый остаётся в verification set)
curl -X POST https://iac.example.com:8443/v1/admin/signing-keys/rotate \
     -H "Authorization: Bearer $ADMIN_TOKEN"

# Подождать пока все агенты re-fetch'нут bundle (Phase 7cf), потом
# retire старый.
curl -X POST https://iac.example.com:8443/v1/admin/signing-keys/<old-id>/retire \
     -H "Authorization: Bearer $ADMIN_TOKEN"
```

## Производительность и ёмкость (performance + capacity)

Stress harness — [crates/iac-controlplane/tests/stress.rs](../../crates/iac-controlplane/tests/stress.rs):

```bash
IAC_STRESS=1 IAC_ASSIGNMENT_LEASE_SECS=5 \
  cargo test -p iac-controlplane --test stress -- --nocapture
```

Замеренный envelope (developer laptop, single-process SQLite):

| Fleet     | Ops × Resources | Submit p99 | Drain |
|-----------|-----------------|-----------:|------:|
| 3 агента  | 5 × 2           | 150 ms     | 2 s   |
| 10 агентов | 20 × 3          | 263 ms     | 24 s  |
| 30 агентов | 15 × 5          | 447 ms     | 40 s  |

SQLite ceiling — ~100 агентов или ~5 ops/sec sustained. Для бóльших
фитов — `database_url` на Postgres (wire identical).

### Real-fleet capacity envelope (Phase 9, 7-агентный VPS-trial)

24-часовой soak на 7-агентном flotе (1 RPS submit-burst, ~3 200
ресурсов на агента) показал шесть отдельных capacity ceiling'ов —
все закрыты defaults сегодня, всё стоит знать для fleet sizing:

| Механизм | Всплывает на | Bound default'ом |
|----------|--------------|------------------|
| SQLite WAL растёт unbounded | ~3 ч устойчивых writes | `journal_size_limit = 256 MiB` + periodic `wal_checkpoint(TRUNCATE)` |
| `observations` table unbounded | ~4 ч | `observation_max_per_resource = 50` + 5-min retention interval |
| `wal_checkpoint(TRUNCATE)` блокирует 30 с при contention | continuous | PASSIVE на большинстве tick'ов, TRUNCATE каждый 10-й |
| Local agent DB unbounded | ~6 ч | `AGENT_OBSERVATION_HISTORY_CAP = 10` per resource_id |
| Per-row INSERT-ы saturates WAL frame allocation | ~8 ч на 60 INSERT/с | Multi-row batched INSERT (chunk = 100) |
| Agent push body > CP `max_body_bytes` | после агентского backlog | Adaptive chunked push (chunk = 500 obs, halve on 413, drop singleton) |

**Tunables для outsized флитов** (10× размера trial и больше):

- `[retention] observation_max_per_resource` — снизить до 10–20 для
  observability-only deployments. 50 консервативно; trim'ит working
  set линейно с cap.
- `[retention] interval_secs` — снизить до 60 для флитов с
  > 1 K observations/s. SSD-class storage minute-cadence prune
  держит spокойно.
- `wal_checkpoint_interval_secs` — снизить до 30 если WAL size
  осциллирует возле `journal_size_limit`.

Когда defaults перестают хватать — switch на Postgres, и per-CP
ceiling двигается с "single-host SQLite write-throughput" на
"network round-trip" — обычно 5–10× headroom прыжок.

**Источники:** см. [TASKS_ARCHIVE.md](../../TASKS_ARCHIVE.md) разделы
`Phase 9-F1-fix-1` через `Phase 9-F1-fix-5` для полного forensic
write-up каждой находки.

## Развёртывание на Postgres

```toml
database_url = "postgres://iac:secret@db.internal:5432/iac?sslmode=require"
```

Миграции применяются автоматически на первом подключении
(`migrations-postgres/`). Пользователь БД должен сначала иметь
право `CREATE TABLE`; после первого старта можно урезать до
read/write.

## Резервные копии (backups)

* SQLite: `sqlite3 server.db .dump > backup.sql`. `state_dir` также
  держит ключи подписи (`signing-keys/`) — копируйте весь `state_dir`.
* Postgres: стандартный `pg_dump`. Ключи подписи в `state_dir` всё
  равно нужно бэкапить отдельно.

Восстановление = восстановить БД + `state_dir` на свежем сервере.
Агенты переподключатся автоматически; перерегистрация не требуется.

## Диагностика проблем (troubleshooting)

* **Агент застрял с "fetched" assignments после краша** — Phase 7cj
  добавил аренду (lease) на 60 секунд. Подожди минуту; следующий
  GET переклеймит. Переопределение через `IAC_ASSIGNMENT_LEASE_SECS`
  для более короткого recovery (восстановления).
* **"server signing bundle has no overlap with pinned keys"
  (нет пересечения с закреплёнными ключами)** — предохранитель из
  Phase 7cf. Набор ключей подписи сервера ушёл по ротации дальше,
  чем то, что агент запиннил. Очисти `server_pubkeys` в агентском
  `state_dir/identity.json`, перезапусти.
* **Операция застряла в `pending_canary`** — canary-батч не
  завершился. `iac plan --server <url> --operation <id>` покажет
  статус по каждому assignment.
* **`iac plan --git-repo` падает на аутентификации** — git CLI берёт твоё
  shell environment. Поставь `GIT_SSH_COMMAND` или
  `GH_TOKEN`/`GITHUB_TOKEN`.

## Где смотреть в коде

* `crates/iac-core/src/protocol.rs` — wire format.
* `crates/iac-controlplane/src/store.rs` — server state machine.
* `crates/iac-controlplane/src/api/` — HTTP handlers.
* `crates/iac-agent/src/{agent,remote}.rs` — agent loop + control
  plane client.
* `crates/iac-providers/src/<kind>/` — per-provider lifecycle.
* `crates/iac-controlplane/tests/` — каждая фича имеет e2e тест;
  читай как канонический пример любого flow.
