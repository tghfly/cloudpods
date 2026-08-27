# docs/baremetal

裸金属相关文档索引。代码主目录：`pkg/baremetal/`、`pkg/compute/models/hosts.go`、`pkg/compute/tasks/baremetal/`、`pkg/baremetal/utils/raid/`、`pkg/baremetal/utils/ipmitool/`。

## 索引

| 日期 | 类型 | 主题 | 文件 |
| --- | --- | --- | --- |
| 2026-08-27 | 修复 | MegaRAID 盘状态转换配额耗尽导致装机失败（offline / JBOD / RAID0 全部失败） | [2026-08-27-megaraid-offline-pd-failures.md](./2026-08-27-megaraid-offline-pd-failures.md) |
| — | 主题 | 裸金属纳管全链路指引（PXE/IPMI/RAID/部署） | [baremetal-onboarding-guide.md](./baremetal-onboarding-guide.md) |

## 本地约定

遵循 [docs/README.md](../README.md) 的总约定；本目录特有的注意点：

- 现场日志量通常很大，**只粘核心 5-20 行**（包含 firmware 错误码、命令、退出状态），其余走引用
- 涉及固件行为（PERC、HPE、LSI、Adaptec、MegaRAID）的根因，标注固件版本区间或厂家文档链接
- 修复必须给出"现场需要做什么操作"（如需冷重启、需 iDRAC 清理 foreign config），不能只写代码改动
