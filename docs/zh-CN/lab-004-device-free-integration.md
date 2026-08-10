# LAB-004 无设备 Host 集成

[English](../research/lab-004-device-free-integration.md)

跟踪 Issue：[#89](https://github.com/jacklv-coder/OrchardProbe/issues/89)

状态：**提议完成检查点 2 实现；设备与外部 Lane 保持关闭**

本文是 LAB-004 检查点 2 的实现台账。它把现有受保护 Host/Operator 流程接入 LAB-003
三角色布局，但不创建或消费授权、不签名 Build、不访问 Apple，也不查询设备。

## 固定操作 Profile

Adapter 只接受以下七个转换。操作名固定前置状态、后置状态与外部输入角色，调用方不能
独立指定 Lifecycle 或输入类型。

| 操作 | 必需前置状态 | 必需后置状态 | 外部输入 |
|---|---|---|---|
| `operator-start-enrollment` | 空 `experiments` 角色 | `base` | 无 |
| `operator-close-enrollment` | `base` | `enrollment-closed` | 一份有界 Receipt |
| `operator-start-run-1` | `enrollment-closed` | `run-1-control` | 无 |
| `operator-close-run-1` | `run-1-control` | `run-1-closed` | 一份有界 Export |
| `operator-start-run-2` | `run-1-closed` | `run-2-control` | 无 |
| `operator-close-run-2` | `run-2-control` | `complete` | 一份有界 Export |
| `operator-verify` | `complete` | `complete` | 无 |

Enrollment Publisher 现在使用已签名的随机 64 位小写十六进制 `experiment_id` 作为实验
子目录名。签名目录 Binding 与后续每次 Host 校验都要求同一名称、父目录身份、子目录身份
与实验 ID。因此历史固定名称 `lab002-experiment` 不再与受保护 Helper 兼容。

## 强制链

Callback 能到达受保护 Helper 之前，Adapter 会打开私有根和三个角色，校验精确选中
Lifecycle 清单，持有全部 Control/Phase 工件，只通过 `external-inputs` Descriptor 打开
Receipt 或 Export，并验证无别名、稳定身份和一个全新诊断名称。Helper 还会拒绝不匹配的
主目录 Descriptor：Enrollment Start 必须使用持有的 `experiments` 角色，后续操作必须使用
持有的不透明实验子目录。检查点 2 只允许这一个角色内 Binding，并拒绝所有额外 Descriptor；
三 Descriptor Helper 启动保持关闭，直到后续检查点审查每个额外来源 Binding 应归属的角色。
Receipt/Export 字节必须与持有外部输入 Descriptor 读取的字节完全相同。

紧邻 Helper 授权前，Host 会重新检查三个角色的精确清单，重新打开选中的 Lifecycle，并将
每个既有 Control/Phase 后代与其持有身份比较。Helper 返回后，Host 必须先捕获精确后置
Lifecycle，才能发布成功诊断：每个新发布的实验、Phase 目录和工件都会一直持有到 Closure。
Closure 重新打开完整后置状态，按角色相对名称、类型、Device 与 Inode 比较全部既有和新
捕获后代。因此同名替换或未捕获的转换都会 Fail-closed。

Helper 只通过持有的 `diagnostics` Descriptor 写入一条固定成功/失败语句。成功后，Closure
重新打开并比较根/角色身份，要求精确后置状态清单、未改变的外部输入身份与字节、指定的
有界只读诊断及完整无别名。Callback 失败时先精确移除本 Boundary 发布的诊断，再要求原
前置状态保持精确；部分 Lifecycle 发布则会变成通用 Fail-closed Closure 错误。公开结果
只含角色名称与操作状态，不含私有根、实验 ID、输入名称/内容或原始错误。

## 检查点 2 顺序台账

| 顺序 | 步骤 | 本 PR 进入 `main` 后的状态 | 证据 / 下一门禁 |
|---:|---|---|---|
| 2A | 让 Host 实验目录符合 LAB-003 | `done` | Rust 发布与签名 Binding 使用随机 64-hex 实验 ID；复制、改名或固定名称目录均失败 |
| 2B | 新增持有式 Preflight 与 Closure | `done` | 七个固定 Profile 校验精确前/后清单、角色身份、别名和失败 Closure |
| 2C | 约束 Helper 输入与诊断 | `done` | Helper 主 Binding 必须匹配 Active Boundary；启动前重新检查精确角色与持有后代；Receipt/Export 匹配持有外部输入；先捕获后置转换后代，再发布固定、有界、排他且仅 Owner 可访问的诊断 |
| 2D | 新增合成回归与 CI | `done` | Ruby 转换/对抗测试、既有 LAB-003 Suite、Rust 测试、语法、格式及 CI Wiring 覆盖本无设备边界 |
| 2E | 发布检查点 2 完成记录 | `active` | 本实现 PR 必须通过 Codex CR、GitHub Review 与全部必需 CI 后才能合并 |

## 范围结果

检查点 2 最多只能证明 Host 边界已为未来另行授权的首方仪式做好准备。它不创建 DemoLab
`1.0 (4)` Candidate、不冻结 Oracle、不上传 TestFlight、不安装或启动 App、不操作 Jack
iPhone、不观察受保护/明文字节、不解除 `DEVICE-001` 阻塞，也不提供 IPA 砸壳。

本完成 PR 合并后，检查点 3 仍是提案门禁。签名精确 Candidate 需要独立评审的激活与全新
明确授权，不能仅因为无设备代码已经合并就开始。
