# LAB-004 全新受保护 Oracle 仪式

[English](../research/lab-004-protected-oracle-ceremony.md)

跟踪 Issue：[#89](https://github.com/jacklv-coder/OrchardProbe/issues/89)

状态：**提议完成检查点 2 无设备实现；外部动作保持关闭**

LAB-004 是针对 DemoLab `1.0 (4)` 的全新首方实验。它要回答：当每个外部输入与诊断都
遵守 LAB-003 角色边界时，现有固定区间自观测器能否闭合受保护 Oracle 证据链。它不会
重试、消费、修复或重新解释已经关闭的 DemoLab `1.0 (3)` LAB-002 仪式及其保留私有证据。

合并本激活只授权设计和下一项无设备集成检查点，不授权签名、访问 App Store Connect 或
TestFlight、上传、安装、启动、创建或消费授权信封、查询设备、设备观察、Backend 工作或
IPA 砸壳。

## 研究问题

对于唯一一个全新、项目自有的 DemoLab `1.0 (4)` Build 和一台后续选定的自有 iPhone，
主 App、DemoFramework 与 DemoShareExtension 的每个冻结 Slice 能否分别独立建立：

1. 已安装可执行文件属于精确冻结的 Build Lineage；
2. 预声明的 `__TEXT,__oprobe` 区间在磁盘上的初始状态受保护；
3. 同一映射区间已成为明文，并匹配唯一一次获准内部 TestFlight 上传前冻结的 Oracle。

两轮清理后的运行必须产生相同规范化证据，并绑定同一物理设备、安装、硬件型号及精确
iOS 版本/Build。任何缺失、额外、变化、不可观察、过期、重放或部分验证的项目都得到
No-Go；观察后绝不调整清单或区间。

## 固定范围与非目标

- 只允许仓库自有 DemoLab Marketing Version `1.0`、全新 Build `4`，以及自有且明确
  授权的 iPhone。
- 完整清单是主 App、DemoFramework、DemoShareExtension，以及签名前冻结的每个设备
  Slice。
- 后续最多可以提议一次内部 TestFlight 上传；外部测试员、公开链接、Beta App Review 与
  App Store 提交均不在范围内。
- 不得把第三方 App、用户 IPA、可执行字节、稳定设备标识符、凭据、Receipt/Export 内容、
  私有路径或原始私有日志提交或上传到 GitHub/CI。
- Go 只代表精确首方 Tuple 的受保护 Oracle 证据，不代表 Backend、提取或砸壳能力、用户
  流程、兼容性声明，也不允许在没有独立激活 PR 时开始 `DEVICE-001`。

## 闭合工件角色

每项未来 Host 操作都必须使用一个全新的、仅 Owner 可访问的 LAB-003 私有根：

```text
private-root/
├── experiments/<opaque-id>/  不可变控制工件与 Allow-list Phase
├── external-inputs/          仅当前操作员 Receipt 或 Export
└── diagnostics/              仅有界且操作员可见的诊断
```

Host 必须在创建或消费授权之前及关闭时，执行 LAB-003 的完整包含关系、类型、Owner、Mode、
大小、清单、无别名与稳定身份检查。外部输入经 `external-inputs` 打开，诊断经
`diagnostics` 创建；两者都不能出现在实验子目录，也不能通过重定向成为协议输入。失败只
保留有界的 Owner 私有证据，绝不扩大或重试动作。

## 顺序检查点

| 顺序 | 检查点 | 激活合并后的状态 | 门禁 |
|---:|---|---|---|
| 1 | 激活与后续设计 | `PR #90 合并后 done` | Issue #89、[PR #90](https://github.com/jacklv-coder/OrchardProbe/pull/90)、本双语契约与台账新增行进入 `main` |
| 2 | 无设备角色集成与合成回归 | `本实现 PR 合并后 done` | [检查点 2 台账](lab-004-device-free-integration.md)要求在现有受保护 Host 流程周围强制 LAB-003 Prepare/Preflight/Closure，同时全部外部与设备 Lane 保持关闭 |
| 3 | 精确签名 `1.0 (4)` 候选与冻结 Oracle | `下一提案 — 未授权` | 需要独立评审的检查点和全新明确授权；不含上传或设备动作 |
| 4 | 一次内部上传与安装 Enrollment | `planned` | 精确检查点 3 Tuple 必须已合并并独立复核；上传、安装与 Enrollment 分别需要其声明的全新授权 |
| 5 | 两轮干净观察 | `planned` | Enrollment 必须以精确已安装 Lineage 闭合；两个不同 Run 都需要全新信封和紧邻的明确授权 |
| 6 | 脱敏 Go/No-Go 结果 | `planned` | 只发布非秘密证据，更新双语技术/用户状态并关闭 Issue #89 |

同一时间只能有一个检查点处于 Active；前一完成 PR 进入 `main` 后才能开始后一项。失败或
不确定的外部动作必须保留并对账，不能静默重复。

## 证据与判定门禁

Go 要求冻结 Build/Oracle、已安装 Role/Slice 清单、授权身份绑定、映射坐标及两份干净
报告全部精确相等。初始保护要求已安装加密范围覆盖固定 Section，且磁盘 Digest 不同于
冻结明文 Digest；只有 `cryptid == 1` 不足以证明。明文要求同一映射区间 Digest 等于独立
冻结 Digest。三个角色与全部冻结 Slice 都必须通过。

安全 No-Go 是可接受结果：它让 `DEVICE-001` 保持阻塞，并记录哪项前提无法独立建立。
Go 也只允许另行提出 `DEVICE-001` 文档激活，不会启动 Backend 实现或操作其他 App。

## 紧邻下一门禁

检查点 2 实现 PR 合并后只能提议检查点 3；其独立激活通过评审并获得全新明确授权前不能
执行。检查点 2 不需要 Jack iPhone，也不得查询或操作它；当前不授权签名或访问 Apple。
