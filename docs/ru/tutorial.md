# Туториал

Этот гайд проводит нового оператора от "у меня есть хост" до "я
умею применять desired state, наблюдать drift и откатывать
изменения если что-то пошло не так". Сначала локальный режим (без
control plane), потом fleet-режим.

## Установка

### Из исходников (рекомендуется на текущей стадии)

```bash
git clone https://github.com/<your-fork>/iac
cd iac
cargo build --release --workspace
sudo install -m 0755 target/release/iac /usr/local/bin/
sudo install -m 0755 target/release/iac-agent /usr/local/bin/
sudo install -m 0755 target/release/iac-controlplane /usr/local/bin/
```

Билд требует Rust 1.95+. На Debian/Ubuntu:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
sudo apt install -y build-essential libsqlite3-dev pkg-config
```

`iac` — операторская CLI. `iac-agent` — daemon на каждом управляемом
хосте. `iac-controlplane` — центральный сервер.

### Проверка

```bash
iac --version
```

## "Hello, file" — минимальный пример

Самый короткий end-to-end сценарий — local mode без сервера и
агента, просто `iac apply` на текущий хост. Сохрани как `hello.yaml`:

```yaml
apiVersion: iac.example/v1
kind: file
metadata:
  name: hello
  environment: smoke
spec:
  path: /tmp/iac-hello.txt
  mode: "0644"
  content: "hello from iac\n"
```

Сначала plan — посмотреть что изменится:

```bash
iac plan hello.yaml
```

Apply:

```bash
iac apply hello.yaml --yes
cat /tmp/iac-hello.txt
# hello from iac
```

Повторный `iac plan` будет no-op — `iac` знает, что файл уже
сходится с desired state.

## Drift detection

Сломаем состояние вручную, чтобы посмотреть как detect drift:

```bash
echo "tampered" > /tmp/iac-hello.txt
iac plan hello.yaml
```

В выводе plan'а файл будет помечен как drifted. `iac apply`
вернёт его в нужное состояние.

## Локальный rollback

Каждый успешный apply записывается в `~/.local/share/iac/operations/`.
Откатить последний apply:

```bash
iac operations          # список последних op id
iac rollback <op-id>    # повторно применить предыдущий desired state
```

## Удалённый деплой одной командой (Ansible-style)

Если у тебя есть SSH-доступ к хосту и `iac` бинарь там установлен —
можешь применить манифест прямо с dev box без всяких серверов:

```bash
iac apply hello.yaml --ssh user@192.168.1.97 --yes
```

Внутри: `iac` SSH'ится туда, обнаруживает remote `iac` бинарь,
прокидывает payload через stdin → удалённый `iac apply
--assignment-stdin`. Никаких control plane, никаких агентов.

Если `iac` на удалённом хосте не установлен, инструмент напишет
готовую `curl | sh` команду для установки.

## Fleet-режим (control plane + agents)

Local mode хорош для одного хоста, но настоящая ценность инструмента
— fleet orchestration. Control plane — один бинарь, agent — другой.

### Поднимаем control plane

На контрольной машине (можно ту же что и dev box, пока учишься):

```bash
mkdir -p /var/lib/iac/server
cat >/etc/iac/server.toml <<'EOF'
bind = "0.0.0.0:8443"
database_url = "sqlite:///var/lib/iac/server/server.db?mode=rwc"
state_dir = "/var/lib/iac/server"
admin_token = "поменяй-меня-на-длинный-секрет"
[tls]
cert_file = "/etc/iac/tls/server.crt"
key_file  = "/etc/iac/tls/server.key"
EOF

iac-controlplane --config /etc/iac/server.toml
```

Для быстрого теста можно запустить на plain HTTP (убери `[tls]`
блок и поставь `bind = "127.0.0.1:8080"`).

### Регистрируем agent

На целевом хосте:

```bash
mkdir -p /var/lib/iac/agent
cat >/etc/iac/agent.toml <<'EOF'
server_url   = "https://iac.example.com:8443"
state_dir    = "/var/lib/iac/agent"
environment  = "prod"
agent_name   = "vm-web-01"
EOF

iac-agent --config /etc/iac/agent.toml
```

Первый запуск регистрирует агента и пинит публичный signing-ключ
сервера (TOFU — trust on first use). Последующие запуски используют
сохранённый identity из `state_dir/identity.json`.

### Submit с операторской стороны

```bash
iac login --server https://iac.example.com:8443 --user admin
# (вставить admin_token из server.toml)

iac apply manifests/ --server https://iac.example.com:8443 \
                     --environment prod --yes
```

Чтобы выкатывать постепенно — добавь `--canary-pct 25`:

```bash
iac apply manifests/ --server https://iac.example.com:8443 \
                     --environment prod --canary-pct 25 --yes
```

Control plane сначала отправит изменения на 25% агентов в
environment'е, дождётся их успешного завершения, и только потом —
остальным. Любая ошибка в canary отменяет дальнейший rollout.

### SSH push (вместо агентов на target'е)

Если на target нельзя поставить агента (сетевое железо, appliances) —
объяви хост как `[[ssh_targets]]` в server.toml:

```toml
[[ssh_targets]]
name = "edge-router-01"
environment = "edge"
host = "10.0.0.1"
user = "admin"
identity_file = "/etc/iac/ssh/edge.key"
```

Control plane сам ходит SSH к таким target'ам когда им нужно
выкатить изменения. Маршрутизация (`hostSelector.name`), canary,
rollback, audit log — всё работает прозрачно.

### GitOps

`iac apply` и `iac plan` оба умеют `--git-repo URL --git-ref REF`
для загрузки манифестов из Git revision вместо локального пути.
Resolved SHA автоматически записывается в `source_commit` audit log:

```bash
# CI gate (exit 0 если без изменений, 2 если есть, non-zero на ошибках)
iac plan --git-repo https://git.example.com/infra.git \
         --git-ref main --git-path manifests/ \
         --server https://iac.example.com:8443

# Merge gate (после approve PR'а)
iac apply --git-repo https://git.example.com/infra.git \
          --git-ref main --git-path manifests/ \
          --server https://iac.example.com:8443 \
          --canary-pct 25 --yes
```

### Серверный rollback

Когда apply оказался плохой идеей — откати **operation** (а не
просто файл):

```bash
iac rollback <operation-id> --server https://iac.example.com:8443 \
                            --reason "incident-1234" --canary-pct 50
```

Сервер построит новую operation из most-recent-prior-succeeded specs
для каждого ресурса и продиспатчит как обычную операцию. Ресурсы у
которых нет prior state (первичный deploy) попадут в `orphaned` —
их оператор удаляет вручную (семантика delete'а зависит от
провайдера).

## Что дальше

* [reference.md](reference.md) — полный provider catalog, config-
  схема, RBAC, audit log queries, drift workflows, maintenance
  windows, TLS/mTLS.
* [runbook.md](runbook.md) — on-call playbook (triage decision
  tree, rollback процедуры, типичные failure modes).
* [architecture.md](architecture.md) — как куски складываются
  внутри: control plane, агент, dispatcher, signing, layered apply.
* `examples/` — реальные манифесты (web-service, multi-host
  cluster, postgres deploy).
* `crates/iac-controlplane/tests/stress.rs` — stress harness для
  замера throughput на твоей инфраструктуре.
