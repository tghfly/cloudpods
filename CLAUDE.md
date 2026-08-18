# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 代码⽣成规范
当你⽣成代码时，必须遵循以下标记规范：
### 代码块标记
- 在每个⽣成的函数/类/代码块开头添加：`# [AI:START] tool=claude author=<⽤户名>`
- 在代码块结尾添加：`# [AI:END]`
### 整⽂件标记
- 如果⽣成整个⽂件，在⽂件第⼀⾏添加：`# [AI:FILE] tool=claude author=<⽤户名> date=YYYY-MM-DD`
### 示例
⽣成函数时：
```python
# [AI:START] tool=claude author=zhangsan
def calculate_total(items):
  """计算总⾦额"""
  return sum(item['price'] for item in items)
# [AI:END]
```

## 文档同步规范

项目开发过程中编写的**设计文档**和**规格文档**（位于 `docs/superpowers/specs/` 和 `docs/superpowers/plans/`）是代码的权威来源之一。后续开发或 bug 修复如果涉及已有文档覆盖的功能，**必须同步更新对应文档**，保持文档与代码一致。

### 适用场景

以下操作完成后，必须检查并更新相关设计文档：

1. **新增功能**：在已有设计文档覆盖的模块中新增功能（如给 AI 应用中心新增端点）
2. **修改行为**：改变了已有功能的接口、字段、流程或配置项
3. **Bug 修复**：修复 bug 时如果涉及接口、流程、数据结构的变更
4. **重构**：重构导致架构、模块划分或数据流发生变化

### 不适用场景

- 纯代码格式化、变量重命名等不影响行为的改动
- 新增功能但尚未编写对应设计文档（此时应新建设计文档而非跳过）

### 操作要求

- 改代码前先 `grep` 或搜索 `docs/superpowers/` 确认是否有相关设计文档
- 有则同步更新文档中对应的章节（接口定义、表结构、流程图等）
- 文档更新与代码变更在**同一次提交**中完成，commit message 中注明 `docs: sync ...`
## Overview

Cloudpods is a cloud-native multi/hybrid-cloud management platform written in Go ("a cloud on clouds"). Module path: `yunion.io/x/onecloud`, Go 1.24. It manages KVM/baremetal/on-premise resources plus public clouds (AWS, Azure, GCP, Alibaba, Huawei, etc.) behind one unified REST API.

Dependencies under `yunion.io/x/*` (jsonutils, sqlchemy, cloudmux, log, ...) are separate repos from github.com/yunionio, vendored into `vendor/`. Builds use `-mod vendor`.

## Build & Test Commands

```bash
make build                    # build all cmd/* binaries into _output/bin/
make cmd/host                 # build a single service (any cmd/* subdir name)
make test                     # go test all packages (excludes host-image/hostimage/torrent)
go test -mod vendor -run TestName ./pkg/compute/...   # run a single test
make fmt                      # gofmt all non-generated .go files
make check                    # fmt-check + gendocgo-check (CI gate)
make mod                      # refresh yunion.io/x deps + re-vendor
make docker-alpine-build F='-j4 cmd/host cmd/host-deployer'  # build in docker (recommended on non-Linux)
```

Notes:
- The Makefile sets `GOOS=linux` and `CGO_ENABLED=0` for builds by default; override `GOOS` when developing on Windows/macOS.
- License headers are managed by `make gencopyright`. Every .go file starts with the Apache 2.0 Yunion header.
- Generated files are marked `// Code generated ... DO NOT EDIT.` — do not hand-edit them (notably `pkg/apis/zz_generated.model.go` and `doc.go` files).

### Code generation

- `make gen-model-api` — regenerates model API structs in `pkg/apis` from model definitions (`scripts/codegen.py model-api`). Run after changing model struct tags.
- `make gen-swagger` — regenerates swagger specs (`docs/swagger/swagger_<svc>.yaml`).
- `make hostdeployer-grpc-gen` — regenerates gRPC code for `pkg/hostman/hostdeployer/apis/deploy.proto`.
- `make y18n-gen` — regenerates i18n message catalogs in `locales/` (source language en-US, also zh-CN).

## Services (cmd/ → pkg/)

Every `cmd/<svc>/main.go` is a thin stub; logic lives in the matching `pkg/` package. Key services:

| cmd/ | pkg/ | Purpose |
|---|---|---|
| region | pkg/compute | Core compute API: servers, hosts, networks, disks, all cloud resources. The largest service. |
| keystone | pkg/keystone | Identity/auth: domains, users, projects, tokens, RBAC policies |
| glance | pkg/image | Image service (qcow2 etc.) |
| monitor | pkg/monitor | Telemetry & alerting (Telegraf-based metrics) |
| scheduler | pkg/scheduler | Placement/scheduling service for VM creation requests |
| host | pkg/hostman | Per-host agent on KVM compute nodes (guests, storage, networks) |
| host-deployer | pkg/hostman/hostdeployer/deployserver | Guest disk deploy/mount helper (gRPC) |
| baremetal-agent | pkg/baremetal | Baremetal lifecycle: IPMI/Redfish, PXE, RAID |
| climc | cmd/climc | CLI client for all APIs |
| apigateway | pkg/apigateway | API gateway proxying to backend services |
| webconsole | pkg/webconsole | Web terminal (SSH/VNC) proxy for instances |
| notify | pkg/notify | Notifications (email/SMS/webhook) |

## Architecture

### Request flow

CLI (climc) / frontend → apigateway (optional) → service (region, keystone, ...). Services authenticate via keystone tokens and call each other using `pkg/mcclient` (see below).

### Core framework (`pkg/cloudcommon`)

Service bootstrap pattern (see `pkg/compute/service/service.go`): `common_options.ParseOptions` → `InitAuth` → `common_app.InitApp` (builds `appsrv.Application` HTTP server) → `cloudcommon.InitDB` → `InitHandlers` → `db.EnsureAppSyncDB` (auto-migrates all registered tables) → `ServeForever`. Master-only cron/worker code runs behind etcd leader election (`elect.Elect` / `IsSlaveNode`).

### ORM & CRUD (`pkg/cloudcommon/db`)

Not GORM — a custom ORM using vendored `yunion.io/x/sqlchemy` as query builder. Patterns:

- Each resource has a **model struct** (e.g. `SHost` in `pkg/compute/models/hosts.go`) and a **manager** (`SHostManager`) embedding mixin base pairs like `db.SEnabledStatusInfrasResourceBase` / `...ManagerBase`, constructed via `db.NewEnabledStatusInfrasResourceBaseManager(SHost{}, "hosts_tbl", "host", "hosts")` — args are table name, keyword singular, keyword plural. The plural keyword is the URL path segment (`/hosts`).
- Struct tags (`width`, `charset`, `nullable`, `index`, `list/get/update/create:"user|domain|admin|..."`) drive **both** the DB schema and RBAC/serialization behavior, validated at registration.
- Models register in the service's `InitHandlers` (e.g. `pkg/compute/service/handlers.go`): `db.RegisterModelManager(mgr)` + `db.NewModelHandler(mgr)` + `dispatcher.AddModelDispatcher(...)`. Generic REST verbs (list/get/create/update/delete) are auto-implemented by the dispatcher.
- Custom API actions are model methods named `PerformXxx` / `ValidateXxx` — no manual route registration needed.
- Many-to-many join tables use `db.SJointResourceBase` + `db.NewJointModelHandler` (e.g. `pkg/compute/models/hoststorages.go`).

### Async tasks (`pkg/cloudcommon/db/taskman`)

Long operations (VM create, disk deploy...) run as resumable async tasks:

- Task struct embeds `taskman.STask`, registered in `init()` via `taskman.RegisterTask(MyTask{})` (see `pkg/compute/tasks/` for hundreds of examples, organized by resource).
- Framework calls stage methods: `OnInit(ctx, obj, body)` starts; subsequent stages are `On<StageName>` methods named after the stage passed to `task.SetStage(...)`; `task.SetStageComplete` / `task.SetStageFailed` finish. Tasks persist state in DB and survive restarts.

### Compute service internals (`pkg/compute`)

- `models/` — DB models for every resource (guests.go, hosts.go, networks.go, ...)
- `tasks/` — taskman async tasks per resource subdirectory
- `guestdrivers/`, `hostdrivers/`, `regiondrivers/`, `storagedrivers/` — driver interfaces abstracting behavior per virtualization/cloud type (KVM vs ESXi vs managed public cloud, etc.)
- `usages/`, `specs/`, `capabilities/`, `policy/` — quota/usage, instance specs, capability queries

### Multicloud drivers

Cloud provider implementations (AWS, Azure, GCP, aliyun, huawei, esxi, ...) live **outside this repo** in the vendored module `vendor/yunion.io/x/cloudmux/pkg/multicloud/`. To change public-cloud/provider behavior, that means changing cloudmux itself (github.com/yunionio/cloudmux, typically vendored via `make mod`); the code in this repo consumes those drivers through `yunion.io/x/cloudmux/pkg/cloudprovider` interfaces, loaded in the region service via `multicloud/loader`.

### Client SDK (`pkg/mcclient`)

- `mcclient.ClientSession` is the core object (one per region/project, carries token). `pkg/mcclient/auth` provides `auth.GetAdminSession(ctx, region)` etc. for service-to-service calls.
- `pkg/mcclient/modules/<service>/mod_*.go` define one manager per resource embedding `modulebase.ResourceManager`, registered globally via `modules/register.go`.
- `pkg/mcclient/options/` holds CLI option structs shared with climc.

### climc CLI

Subcommands live in `cmd/climc/shell/<service>/`. Adding one = options struct (`pkg/mcclient/options/...`) + module manager (`pkg/mcclient/modules/...`) + `R(options, "name", "desc", callback)` registration in the shell package's init.

### Host management (`pkg/hostman`)

Agent running on each KVM host; reports host/guest status to region via mcclient, executes guest lifecycle operations locally, and calls `host-deployer` over gRPC for disk deployment.
