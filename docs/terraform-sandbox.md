# Terraform Sandbox

Плагин запускает Terraform CLI в изолированной среде на базе Linux namespaces и `pivot_root`. Цель — ограничить влияние потенциально вредоносного кода в Terraform-провайдерах и манифестах на хостовую систему.

## Архитектура

```
Go plugin (Vault)
  │
  │  clone(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUTS)
  │  exec via /proc/self/fd/N (memfd)
  ▼
sandbox-init  (статический C-бинарник, ~10 KiB)
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

1. **Go-плагин** (`sandbox.go`) — создаёт дочерний процесс в новых Linux namespaces, загружает C-хелпер из памяти через `memfd_create`.
2. **sandbox-init** (`sandbox-init/main.c`) — доверенный C-бинарник, который готовит изолированный rootfs и делает `pivot_root` + `execve`.
3. **terraform** — запускается внутри sandbox, видит только разрешённые файлы.

## Уровни изоляции

### Полная изоляция (с sandbox-init)

Включается при сборке с тегом `sandbox_init`. Бинарник `sandbox-init` встраивается в Go-плагин через `//go:embed`.

#### Почему отдельный C-бинарник, а не чистый Go

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
| `memfd_create` | C-хелпер загружается в анонимную память, ничего не пишется на диск |
| Минимальный `PATH` | `/usr/bin` — только каталог с terraform |
| Чистое окружение | Allow-list переменных окружения; секреты хостового процесса не наследуются |
| `Pdeathsig: SIGKILL` | Дочерний процесс убивается при завершении родителя |

Сетевой namespace **не создаётся** (`CLONE_NEWNET` отсутствует) — terraform нужна сеть для скачивания провайдеров и обращения к Vault API.

### Namespace-only изоляция (без sandbox-init)

Если плагин собран без тега `sandbox_init`, переменная `sandboxInitBinary` равна `nil`. Namespaces (user/mount/PID/UTS) всё ещё создаются, но `pivot_root` и подготовка rootfs не выполняются. Terraform видит хостовую файловую систему.

### Без sandbox

Если ядро не поддерживает непривилегированные user namespaces (`kernel.unprivileged_userns_clone=0`), terraform запускается без изоляции с предупреждением в логе. Применяется только ограничение окружения и `Pdeathsig`.

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

| Переменная | Значение (sandbox) | Значение (без sandbox) |
|---|---|---|
| `HOME` | `/workspace` | `<workDir>` (хостовой путь) |
| `TMPDIR` | `/tmp` | `<workDir>` |
| `PATH` | `/usr/bin` | полный системный `PATH` |
| `TF_IN_AUTOMATION` | `true` | `true` |
| `TF_INPUT` | `false` | `false` |
| `CHECKPOINT_DISABLE` | `true` | `true` |
| `VAULT_ADDR` | из конфигурации бэкенда | из конфигурации бэкенда |
| `VAULT_TOKEN` | из конфигурации бэкенда | из конфигурации бэкенда |
| `VAULT_NAMESPACE` | из конфигурации бэкенда | из конфигурации бэкенда |
| `SSL_CERT_FILE` и др. | не передаются (certs в `/etc/ssl`) | из окружения хоста |
| `TF_CLI_CONFIG_FILE` | `.terraformrc` (относительный путь) | `.terraformrc` (относительный путь) |

Переменные хостового процесса (`os.Environ()`) **не наследуются**.

## memfd_create

Встроенный C-бинарник `sandbox-init` загружается в память без записи на диск:

1. `unix.MemfdCreate("sandbox-init", 0)` — создаёт анонимный файл в RAM.
2. `syscall.Write(fd, sandboxInitBinary)` — записывает содержимое из `//go:embed`.
3. Путь `/proc/self/fd/<N>` используется как `cmd.Path` для `exec.CommandContext`.
4. File descriptor остаётся открытым на всё время жизни плагина (однократная инициализация через `sync.OnceValues`).

При `clone()` дочерний процесс наследует fd, ядро загружает ELF из memfd при `execve`.

## sandbox-init: C-хелпер

Исходный код: `pkg/terraform/sandbox-init/main.c`

Статически скомпилированный бинарник (~65 KiB, musl-libc). Работает в distroless-контейнерах без `/bin/sh` и `mount`.

### Интерфейс

| Параметр | Источник | Описание |
|---|---|---|
| `SANDBOX_ROOTFS` | env | Каталог для нового корня (создаётся Go-плагином в `<workDir>/.rootfs`) |
| `argv[1]` | аргумент | Путь к terraform на хосте |
| `argv[2:]` | аргументы | Аргументы terraform (`init`, `plan`, `apply`, ...) |
| CWD | `cmd.Dir` | Рабочий каталог с .tf файлами (хостовой путь) |

### Последовательность действий

1. `mount("", "/", MS_PRIVATE | MS_REC)` — делает хостовое дерево монтирования приватным.
2. Создаёт каталоги внутри `SANDBOX_ROOTFS` (`/usr/bin`, `/etc/ssl`, `/proc`, `/tmp`, `/dev`, `/workspace`, `/.pivot`).
3. `bind_mount(CWD → rootfs/workspace)` — рабочий каталог (read-write).
4. `bind_mount(argv[1] → rootfs/usr/bin/terraform)` — бинарник (read-only).
5. Bind-mount `/etc/ssl`, `/etc/pki`, `/etc/resolv.conf`, `/etc/hosts` (read-only, пропускаются если не существуют).
6. `mount("tmpfs" → rootfs/dev)` + bind-mount `/dev/null`, `/dev/zero`, `/dev/urandom`.
7. `mount("proc" → rootfs/proc)` — свежий procfs.
8. `mount("tmpfs" → rootfs/tmp)` — 64 MiB tmpfs.
9. `mount(rootfs → rootfs, MS_BIND)` — делает rootfs mount point (требование `pivot_root`).
10. `pivot_root(rootfs, rootfs/.pivot)` — переключает корень.
11. `umount2("/.pivot", MNT_DETACH)` + `rmdir("/.pivot")` — отмонтирует старый корень.
12. `chdir("/workspace")`.
13. `unsetenv("SANDBOX_ROOTFS")` — убирает хостовой путь из окружения.
14. `execve("/usr/bin/terraform", ...)` — заменяет процесс на terraform.

## Порядок вызовов

```
ApplyTerraformFromFS()
  ├── os.MkdirTemp()           → tmpDir
  ├── extractTerraformFiles()  → tmpDir/<tfPath>/*.tf
  ├── loadTerraformState()     → tmpDir/<tfPath>/terraform.tfstate
  │
  ├── runTerraformInit()
  │     ├── newTerraformCommand()
  │     │     ├── sandboxSupported()?     ← probe CLONE_NEWUSER
  │     │     ├── sandboxInitFD()?        ← memfd с C-хелпером
  │     │     ├── os.MkdirAll(.rootfs)
  │     │     ├── exec.CommandContext(/proc/self/fd/N, terraform, init, ...)
  │     │     ├── buildCleanEnv(sandboxed=true)
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
- Каталог `.rootfs` внутри `workDir` содержит только пустые директории после завершения — bind-mount'ы существовали только в namespace дочернего процесса.
- `os.RemoveAll(tmpDir)` в `defer` удаляет всё, включая `.rootfs`.

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

### Сборка плагина с sandbox

```bash
# 1. Собрать C-хелпер
make build-sandbox-init-docker

# 2. Собрать плагин с тегом sandbox_init
make build-with-sandbox
```

### Сборка без sandbox (namespace-only)

```bash
make build
```

В этом случае `sandboxInitBinary = nil`, rootfs-изоляция отключена, но namespaces всё ещё применяются если ядро поддерживает.

## Файлы

| Файл | Описание |
|---|---|
| `pkg/terraform/sandbox.go` | Оркестрация sandbox: probe namespaces, memfd, создание команды, окружение |
| `pkg/terraform/sandbox-init/main.c` | C-хелпер: подготовка rootfs, pivot_root, execve terraform |
| `pkg/terraform/sandbox-init/Makefile` | Кросс-компиляция C-хелпера (musl, docker, zig) |
| `pkg/terraform/sandbox_embed_amd64.go` | `//go:embed` для amd64 (build tag: `sandbox_init`) |
| `pkg/terraform/sandbox_embed_arm64.go` | `//go:embed` для arm64 (build tag: `sandbox_init`) |
| `pkg/terraform/sandbox_noembed.go` | Заглушка `sandboxInitBinary = nil` (без тега `sandbox_init`) |
| `pkg/terraform/cli.go` | Извлечение .tf файлов, запуск init/plan/apply |

## Ограничения

- **Сетевой доступ не ограничен.** Terraform нужна сеть для `init` (скачивание провайдеров) и для работы с Vault API. Для ограничения сети потребуется `CLONE_NEWNET` с настройкой veth/NAT.
- **Работает только на Linux.** Все файлы пакета `terraform` имеют build tag `//go:build linux`.
- **Требуются unprivileged user namespaces.** Ядро должно разрешать `CLONE_NEWUSER` без root (`sysctl kernel.unprivileged_userns_clone=1`). В большинстве современных дистрибутивов это включено по умолчанию.
- **Distroless совместимость.** sandbox-init статически слинкован и не зависит от libc/shell в контейнере.
