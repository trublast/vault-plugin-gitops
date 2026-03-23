# Terraform Sandbox

Плагин запускает Terraform CLI в изолированной среде на базе Linux namespaces и `pivot_root`. Цель — ограничить влияние потенциально вредоносного кода в Terraform-провайдерах и манифестах на хостовую систему.

## Архитектура

```
Go plugin (Vault)
  │
  │  clone(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUTS)
  │  exec tmpDir/sandbox-init
  ▼
sandbox-init  (статический C-бинарник, ~65 KiB)
  │  mount --make-rprivate /
  │  bind-mount workspace, terraform, certs, DNS, /dev
  │  mount proc, tmpfs
  │  pivot_root → новый rootfs
  │  umount old root
  │  execve /usr/bin/terraform
  ▼
terraform  (видит только минимальный rootfs)
```

Процесс состоит из трёх звеньев:

1. **Go-плагин** (`sandbox.go`) — создаёт дочерний процесс в новых Linux namespaces, записывает встроенный C-хелпер в tmpfs-директорию (`tmpDir/sandbox-init`) и запускает его.
2. **sandbox-init** (`sandbox-init/main.c`) — доверенный C-бинарник, который готовит изолированный rootfs и делает `pivot_root` + `execve`.
3. **terraform** — запускается внутри sandbox, видит только разрешённые файлы.

Sandbox обязателен — без него terraform не запускается. Если среда не поддерживает sandbox (нет user namespaces, AppArmor блокирует), плагин возвращает ошибку.

## Изоляция

Бинарник `sandbox-init` встраивается в Go-плагин через `//go:embed`. При запуске плагин записывает его в tmpfs-директорию (тот же `tmpDir`, что используется для `.tf` файлов — обычно `/dev/shm`). Файл удаляется вместе с `tmpDir` после завершения terraform.

### Почему отдельный C-бинарник, а не чистый Go

Подготовка rootfs (`mount`, `pivot_root`) должна выполняться **внутри** дочернего процесса, уже находящегося в новых namespaces, но **до** запуска terraform. Go не позволяет реализовать это напрямую в одном `exec.Cmd`:

1. **`SysProcAttr` не поддерживает pre-exec хуки.** Go выполняет `clone()` → настройку fd/uid/gid → `execve()` в одном неразрывном цикле внутри `forkExec`. Вставить произвольный код (вызовы `mount`, `pivot_root`) между `clone()` и `execve()` невозможно без модификации runtime.

2. **Re-exec паттерн создаёт зависимость от `/proc/self/exe`.** Альтернатива — перезапуск самого Go-плагина с особым env-флагом, где `main()` определяет, что это «sandbox-режим», выполняет mount-операции через `syscall.Mount` и затем делает `syscall.Exec` в terraform. Но это добавляет сложность в `main()`, требует аккуратной изоляции логики sandbox от основного кода плагина, Go runtime при старте создаёт потоки (`runtime.GOMAXPROCS`), что конфликтует с однопоточными требованиями `unshare`/`setns`, и — главное — делает невозможным использование плагина в режиме embedded (встроенный в процесс Vault), поскольку перезапуск `/proc/self/exe` запустит Vault, а не sandbox-логику.

3. **CGo нежелателен.** Использование `syscall.Mount`/`syscall.PivotRoot` через CGo внесло бы зависимость от libc в основной бинарник плагина и усложнило бы кросс-компиляцию. Vault-плагины принято собирать как статические Go-бинарники.

4. **Distroless-совместимость.** В контейнере нет `/bin/sh` и утилиты `mount`, поэтому shell-скрипт невозможен. Статически скомпилированный C-бинарник (musl, ~65 KiB) не имеет внешних зависимостей.

Отдельный C-хелпер решает все эти проблемы: он запускается как первый процесс в новых namespaces, выполняет привилегированные mount-операции в однопоточном контексте, а затем заменяет себя на terraform через `execve`. При этом основной Go-плагин остаётся чистым Go без CGo.

| Механизм | Что даёт |
|---|---|
| `CLONE_NEWUSER` | Новое пространство пользователей; не требует `CAP_SYS_ADMIN` на хосте |
| `CLONE_NEWNS` | Собственная таблица монтирования; хостовая ФС изолирована через `pivot_root` |
| `CLONE_NEWPID` | Изолированное пространство PID; свежий `/proc` |
| `CLONE_NEWUTS` | Изолированное имя хоста |
| `pivot_root` | Полная замена корневой ФС; старый корень отмонтирован (`MNT_DETACH`) |
| Минимальный `PATH` | `/usr/bin` — только каталог с terraform |
| Чистое окружение | Allow-list переменных окружения; секреты хостового процесса не наследуются |
| `Pdeathsig: SIGKILL` | Дочерний процесс убивается при завершении родителя |

Сетевой namespace **не создаётся** (`CLONE_NEWNET` отсутствует) — terraform нужна сеть для скачивания провайдеров и обращения к Vault API.

## Rootfs внутри sandbox

После `pivot_root` terraform видит минимальную файловую систему:

```
/
├── workspace/          ← .tf файлы, state, провайдеры (read-write, bind-mount)
├── usr/bin/terraform   ← бинарник terraform (read-only, bind-mount)
├── etc/
│   ├── ssl/            ← CA-сертификаты (read-only, bind-mount)
│   ├── pki/            ← CA-сертификаты RHEL-style (read-only, если есть)
│   ├── resolv.conf     ← DNS-резолвер (read-only, bind-mount)
│   └── hosts           ← /etc/hosts (read-only, bind-mount)
├── proc/               ← свежий procfs для PID namespace
├── tmp/                ← tmpfs, 64 MiB, mode 1777
└── dev/
    ├── null            ← bind-mount с хоста
    ├── zero            ← bind-mount с хоста
    └── urandom         ← bind-mount с хоста
```

Всё остальное из хостовой ФС **недоступно**.

## Переменные окружения

Terraform получает минимальный набор переменных:

| Переменная | Значение |
|---|---|
| `HOME` | `/workspace` |
| `TMPDIR` | `/tmp` |
| `PATH` | `/usr/bin` |
| `TF_IN_AUTOMATION` | `true` |
| `TF_INPUT` | `false` |
| `CHECKPOINT_DISABLE` | `true` |
| `VAULT_ADDR` | из конфигурации бэкенда |
| `VAULT_TOKEN` | из конфигурации бэкенда |
| `VAULT_NAMESPACE` | из конфигурации бэкенда |
| `TF_CLI_CONFIG_FILE` | `.terraformrc` (относительный путь) |

Переменные хостового процесса (`os.Environ()`) **не наследуются**.

## sandbox-init: C-хелпер

Исходный код: `pkg/terraform/sandbox-init/main.c`

Статически скомпилированный бинарник (~65 KiB, musl-libc). Работает в distroless-контейнерах без `/bin/sh` и `mount`.

### Интерфейс

| Параметр | Источник | Описание |
|---|---|---|
| `SANDBOX_ROOTFS` | env | Каталог для нового корня (создаётся Go-плагином в `<tmpDir>/.rootfs`) |
| `argv[1]` | аргумент | Путь к terraform на хосте |
| `argv[2:]` | аргументы | Аргументы terraform (`init`, `plan`, `apply`, ...) |
| CWD | `cmd.Dir` | Рабочий каталог с .tf файлами (хостовой путь) |

### Последовательность действий

1. `mount("", "/", MS_PRIVATE | MS_REC)` — делает хостовое дерево монтирования приватным.
2. Создаёт каталоги внутри `SANDBOX_ROOTFS` (`/usr/bin`, `/etc/ssl`, `/proc`, `/tmp`, `/dev`, `/workspace`, `/.pivot`).
3. `bind_mount(CWD → rootfs/workspace)` — рабочий каталог (read-write).
4. `bind_mount(argv[1] → rootfs/usr/bin/terraform)` — бинарник (read-only).
5. Bind-mount `/etc/ssl`, `/etc/pki`, `/etc/resolv.conf`, `/etc/hosts` (read-only, пропускаются если не существуют).
6. Bind-mount путей из `SSL_CERT_FILE`, `SSL_CERT_DIR`, `CURL_CA_BUNDLE` (read-only, пропускаются если не заданы или не существуют).
7. `mount("tmpfs" → rootfs/dev)` + bind-mount `/dev/null`, `/dev/zero`, `/dev/urandom`.
8. `mount("proc" → rootfs/proc)` — свежий procfs.
9. `mount("tmpfs" → rootfs/tmp)` — 64 MiB tmpfs.
10. `mount(rootfs → rootfs, MS_BIND | MS_REC)` — рекурсивный bind rootfs как mount point (требование `pivot_root`; `MS_REC` необходим, чтобы дочерние bind-mount'ы были видны после `pivot_root`).
11. `pivot_root(rootfs, rootfs/.pivot)` — переключает корень.
12. `umount2("/.pivot", MNT_DETACH)` + `rmdir("/.pivot")` — отмонтирует старый корень.
13. `chdir("/workspace")`.
14. `unsetenv("SANDBOX_ROOTFS")` — убирает хостовой путь из окружения.
15. `execve("/usr/bin/terraform", ...)` — заменяет процесс на terraform.

## Порядок вызовов

```
ApplyTerraformFromFS()
  ├── os.MkdirTemp()           → tmpDir (на tmpfs, обычно /dev/shm)
  ├── extractTerraformFiles()  → tmpDir/workspace/*.tf
  ├── loadTerraformState()     → tmpDir/workspace/terraform.tfstate
  │
  ├── runTerraformInit()
  │     ├── newTerraformCommand()       ← returns error if sandbox unavailable
  │     │     ├── sandboxSupported()?        ← probe CLONE_NEWUSER
  │     │     ├── apparmorRestrictsUserns()? ← check sysctl
  │     │     ├── writeSandboxInit()         ← tmpDir/sandbox-init
  │     │     ├── os.MkdirAll(.rootfs)
  │     │     ├── exec.CommandContext(tmpDir/sandbox-init, terraform, init, ...)
  │     │     ├── buildSandboxEnv()
  │     │     └── SysProcAttr{Cloneflags: USER|NS|PID|UTS}
  │     ├── setupTerraformConfigFile()    ← TF_CLI_CONFIG_FILE=.terraformrc
  │     └── cmd.Run()
  │
  ├── runTerraformPlan()       (аналогично)
  ├── runTerraformApply()      (аналогично)
  │
  └── defer: saveTerraformState() + os.RemoveAll(tmpDir)
```

## Очистка

- Каждый вызов `runTerraformInit/Plan/Apply` создаёт свой дочерний процесс с собственным mount namespace.
- При завершении процесса namespace уничтожается, все bind-mount'ы автоматически размонтируются.
- Каталог `.rootfs` внутри `tmpDir` содержит только пустые директории после завершения — bind-mount'ы существовали только в namespace дочернего процесса.
- Файл `sandbox-init` в `tmpDir` удаляется вместе со всем `tmpDir`.
- `os.RemoveAll(tmpDir)` в `defer` удаляет всё, включая `.rootfs` и `sandbox-init`.

## Сборка

### Компиляция C-хелпера

```bash
# С помощью musl cross-compilers
make build-sandbox-init

# С помощью Docker (работает на любой ОС)
make build-sandbox-init-docker

# С помощью zig cc (macOS/Linux)
make -C pkg/terraform/sandbox-init zig
```

Результат: `pkg/terraform/sandbox-init/bin/sandbox-init-{amd64,arm64}`.

### Сборка плагина

```bash
# 1. Собрать C-хелпер
make build-sandbox-init-docker

# 2. Собрать плагин
make build
```

Сборка без предварительной компиляции sandbox-init завершится ошибкой `go:embed` — бинарник обязателен.

## Файлы

| Файл | Описание |
|---|---|
| `pkg/terraform/sandbox.go` | Оркестрация sandbox: probe namespaces, AppArmor-детекция, запись sandbox-init в tmpfs, создание команды, окружение |
| `pkg/terraform/sandbox-init/main.c` | C-хелпер: подготовка rootfs, bind-mount CA-путей, pivot_root, execve terraform |
| `pkg/terraform/sandbox-init/Makefile` | Кросс-компиляция C-хелпера (musl, docker, zig) |
| `pkg/terraform/sandbox_embed_amd64.go` | `//go:embed` sandbox-init для amd64 |
| `pkg/terraform/sandbox_embed_arm64.go` | `//go:embed` sandbox-init для arm64 |
| `pkg/terraform/cli.go` | Извлечение .tf файлов, запуск init/plan/apply |

## Ограничения

- **Сетевой доступ не ограничен.** Terraform нужна сеть для `init` (скачивание провайдеров) и для работы с Vault API. Для ограничения сети потребуется `CLONE_NEWNET` с настройкой veth/NAT.
- **Работает только на Linux.** Все файлы пакета `terraform` имеют build tag `//go:build linux`.
- **Требуются unprivileged user namespaces.** Ядро должно разрешать `CLONE_NEWUSER` без root (`sysctl kernel.unprivileged_userns_clone=1`). В большинстве современных дистрибутивов это включено по умолчанию.
- **AppArmor может блокировать sandbox.** Ubuntu 23.10+ по умолчанию включает `kernel.apparmor_restrict_unprivileged_userns=1`, что запрещает `mount`/`pivot_root` внутри user namespaces. Необходимо `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` или AppArmor-профиль с разрешением `userns` для бинарника плагина.
- **Distroless совместимость.** sandbox-init статически слинкован и не зависит от libc/shell в контейнере.
