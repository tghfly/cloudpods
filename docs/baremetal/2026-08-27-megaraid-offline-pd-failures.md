# MegaRAID 盘状态转换配额耗尽导致装机失败（offline / JBOD / RAID0 全部失败）

- **日期**：2026-08-27
- **服务**：baremetal
- **代码主目录**：`pkg/baremetal/utils/raid/megactl/`
- **受影响组件**：MegaRAID（PERC）卡，包括 noRAID / JBOD 与 RAID0/RAID5 等所有建盘路径

---

## 1. 现象

在一台装有 PERC（型号 MegaRAID Linux PCIE，iDRAC9）控制器的物理机上安装 Ubuntu Server 24.04，无论选择 **不做 RAID** 还是 **RAID0**，均以 `deploy_fail` 结束：

- 不做 RAID（conf="none"）：
  - `megacliBuildJBOD` 报 `PDMakeJBOD` 失败；
  - 回退到 `storcli /c0/eall/sall show J` 又报 `syntax error, unexpected TOKEN_EALL`；
  - 最终 fallback 的 `MegaCli -CfgLdAdd -r0` 报 `0x26 The specified physical disk does not have the appropriate attributes`，`storcli /c0 add vd each type=raid0 drives=32:0,32:1,32:2 wt nora direct` 报 `resources already in use`。

- RAID0（conf="raid0"）：`MegaCli -CfgLdAdd -r0 [32:0]` 报 `0x26`；`storcli /c0 add vd type=r0 drives=32:0` 报 `resources already in use`。

detect 阶段三块盘全部 `status: offline`：

```
[info] RaidDiskInfo: [
  {"adapter":0,"enclousure":32,"slot":0,"model":"MTFDDAK1T9TDD","status":"offline",...},
  {"adapter":0,"enclousure":32,"slot":1,"model":"MG04SCA20ENY ","status":"offline",...},
  {"adapter":0,"enclousure":32,"slot":2,"model":"MG04SCA20ENY ","status":"offline",...}
]
```

---

## 2. 关键错误码

| 错误码 | 含义 |
| --- | --- |
| MegaCli `0x5f` | **Maximum allowed drive conversion has been reached** — 固件盘状态转换计数器耗尽 |
| MegaCli `0x26` | The specified physical disk does not have the appropriate attributes to complete the requested command — 盘不在 Unconfigured-Good 态 |
| storcli `Exit Code: 255, Operation not allowed` | 同样由转换配额耗尽导致的状态转换拒绝 |
| storcli `resources already in use` | 盘被 foreign config 或已有 VD 占用 |

---

## 3. 根因（两层叠加）

### 3.1 表层（代码 bug）：`storcliGetPDStates` 命令拼接错误

`pkg/baremetal/utils/raid/megactl/helper.go` 旧实现：

```go
cmd, err := getCmd("eall/sall", "show", "J")
```

`GetStorcliCommand("eall/sall", "show", "J")` 拼接出：

```
/opt/MegaRAID/storcli/storcli64 /c0 eall/sall show J
```

少了 `/`，storcli 报 `syntax error, unexpected TOKEN_EALL`（日志原文）。结果**整个状态 map 永远为空**，所有"已是目标态就跳过"的逻辑（`storcliClearJBODDisks` 跳过 UGood、`megacliBuildJBOD` 跳过 JBOD）实际上都是死代码，每次部署对全部盘做 UGood↔JBOD 往返转换。

### 3.2 深层（固件）：盘状态转换配额耗尽

MegaRAID 固件对单盘 UGood↔JBOD 状态转换次数有上限（`Maximum allowed drive conversion has been reached`）。`clearJBODDisks` 末尾的 `megacliEnableJBOD(true)/(false)` 双重开关、`storcliBuildJBOD` 开头的 on/off/on 切换，每次都会对**所有** JBOD 盘做批量转换；结合 3.1 的状态查询失效，反复部署把计数器烧光。一旦耗尽，所有状态转换（`PDMakeGood`、`set good force`、`set jbod`、`PDMakeJBOD`）都被固件拒绝（"Operation not allowed"），盘卡死在 offline 态。

RAID0 失败是同一个根因的下游症状：盘既不在 UGood 态（`-CfgLdAdd` 报 0x26），又被残留 foreign/旧配置占用（storcli 报 `resources already in use`）。

---

## 4. 修复

修改集中在 `pkg/baremetal/utils/raid/megactl/`：

| 文件 | 改动 | 作用 |
| --- | --- | --- |
| `helper.go::storcliGetPDStates` | `getCmd()` 取 `/c0` 前缀，再 `fmt.Sprintf("%s/eall/sall show J", base)` | 修正 storcli 语法；状态查询从"必然失败"变为"可用"，所有 skip 逻辑真正生效 |
| `helper.go::storcliClearJBODDisks` | 预查询 `storcliGetPDStates`，已是 UGood 的盘直接 `continue` | 避免对已 UGood 盘重复 `set good force`（每次都扣配额） |
| `megactl.go::megacliBuildJBOD` | 同上预查询，已是 JBOD 的盘跳过 | 避免对已 JBOD 盘执行 `PDMakeJBOD` 触发配额 |
| `megactl.go::clearJBODDisks` | 顺序改为：① 关 JBOD 模式（megacli + storcli）② 清 Foreign（megacli `-CfgForeign -Clear` + storcli `/c0/fall delete`）③ PDMakeGood / set good force；删掉末尾 `EnableJBOD true/false` 双重开关 | 释放 JBOD 锁、清理残留配置、移除每次烧配额的 on/off 抖动 |

### 关键代码位置

- `pkg/baremetal/utils/raid/megactl/helper.go:80` — `storcliGetPDStates` 命令修复
- `pkg/baremetal/utils/raid/megactl/helper.go:203` — `storcliClearJBODDisks` 跳过 UGood
- `pkg/baremetal/utils/raid/megactl/megactl.go:908` — `megacliBuildJBOD` 跳过 JBOD
- `pkg/baremetal/utils/raid/megactl/megactl.go:1012` — `clearJBODDisks` 顺序重构

---

## 5. 运维注意事项

**代码修复 ≠ 自动恢复已卡死的机器**。`0x5f Maximum allowed drive conversion has been reached` 计数器**只能通过完整断电冷重启复位**（关机、拔电源 30 秒以上放掉 Flea Power，或 iDRAC 冷启动周期）；普通 IPMI 软重启或 PXE 流程内的上下电**不会**复位。

### 已卡死机器的恢复步骤

1. **彻底断电冷重启**：graceful shutdown → 拔电源 / 关闭 PSU 30s+ → 上电
2. 重启后若盘仍 offline：
   - `storcli64 /c0/fall show` 检查 foreign config，必要时在 iDRAC 存储页面清理
   - 升级 PERC 固件（新版本对转换计数器行为有改善）
   - 极端情况下重新插拔磁盘
3. 再重新部署 —— 新代码路径会收敛：已是 UGood/JBOD 的盘直接跳过，转换配额不再被浪费

### 已部署代码路径的预期行为

- 反复重装同一台机器时，`storcliClearJBODDisks` 与 `megacliBuildJBOD` 的 skip 逻辑会让转换次数不再增长
- `clearJBODDisks` 末尾的双重开关已删除，配额消耗减少约一半
- 但**幂等性**：如果用户在外部工具（iDRAC、perccli）手动转过盘状态，重新部署时仍能恢复一致

---

## 6. 关联

- 触发机型：Dell PowerEdge，PERC MegaRAID Linux PCIE，iDRAC9
- 镜像：Ubuntu Server 24.04 (Noble) x86_64
- 相关代码域：`pkg/baremetal/utils/raid/megactl/`、`pkg/baremetal/utils/raid/drivers/`
- 上游 Broadcom 已知问题关键词：`megaraid_sas` firmware "drive conversion limit"、"Maximum allowed drive conversion has been reached"
