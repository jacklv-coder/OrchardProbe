# LAB-004 无设备 Host 集成

[English](../research/lab-004-device-free-integration.md)

跟踪 Issue：[#89](https://github.com/jacklv-coder/OrchardProbe/issues/89)

状态：**PR #91 合并后检查点 2 完成；设备与外部 Lane 保持关闭**

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

检查点 2 中任何生产 Callback 都不能到达受保护 Helper。Adapter 会打开私有根和三个角色，校验精确选中
Lifecycle 清单，持有全部 Control/Phase 工件，只通过 `external-inputs` Descriptor 打开
Receipt 或 Export，并验证无别名、稳定身份和一个全新诊断名称。首次读取诊断清单前，Adapter
还会取得非阻塞排他 Diagnostics 角色锁，并一直持有到校验、发布、清理及 Descriptor 关闭全部
结束；所有受控诊断 Writer 都必须遵循这一锁协议。生产授权入口会重复完整前置状态校验，
随后对任何 Binding 请求返回终态 `helper_launch_closed`。真实 Helper 需要三个目录 Binding，
而本角色边界只能说明主 `experiments` 角色或不透明实验子目录的归属。后续检查点必须审查
另外两个来源 Binding，并把 Helper 实际消费的每个字节绑定到已接受快照，之后才能开放执行。
Receipt/Export 字节会通过持有的外部输入 Descriptor 保留，但检查点 2 不会把它们交给 Helper。
合成测试只设置内部授权状态来覆盖转换后捕获与 Closure；生产调用方无法从公开授权 API 获得
该状态。

紧邻返回关闭授权决定前，Host 会重新检查三个角色的精确清单，重新打开选中的 Lifecycle，并将
每个既有 Control/Phase 后代与其持有身份及打开时 SHA-256 比较。每个文件从捕获摘要到
Closure 都持有非阻塞共享读锁，使遵循协调协议的排他写入者无法进入；新转换工件也必须先
加入该加锁集合。合成 Callback 返回后，既有排他 Operator 目录锁仍会保持，直到测试捕获精确
后置 Lifecycle；之后合成 Closure 路径才能发布成功诊断。每个新发布的实验、Phase 目录和工件都会一直持有到
Closure。
Closure 重新打开完整后置状态，按角色相对名称、类型、Device、Inode 与文件内容摘要比较
全部既有和新捕获后代。因此同名替换、保留元数据的原位改写或未捕获的转换都会 Fail-closed。

Boundary 诊断 API 只通过持有的 `diagnostics` Descriptor 写入一条固定成功/失败语句。Preflight
同时预留一个文件位和较长固定语句所需的总字节容量，不会把已知的容量失败延迟到发布阶段。正常返回的操作
必须携带 `helper-success` 状态，持久化的 `helper-failure` 语句绝不能闭合为成功。成功后，Closure
重新打开并比较根/角色身份，要求精确后置状态清单、未改变的外部输入身份与字节、共享锁下
每个保留诊断的持有身份与打开时 SHA-256，以及在最终读取后再次确认单链接状态的新发布指定
有界只读诊断。新的单链接规则只适用于 Boundary 拥有的结果，不会重新分类先前保留的 Operator
证据。校验后，Host 会删除 Boundary 拥有的诊断、同步角色目录、要求已持有 Inode 的剩余链接数
为零，并重新校验原始诊断清单，之后才能返回 `closed`。经清理的返回状态是唯一成功指示；固定诊断
语句按设计仅临时存在。Closure 还要求完整无别名。Callback 失败时
先精确移除本 Boundary 发布的诊断，再要求原
前置状态保持精确；部分 Lifecycle 发布则会变成通用 Fail-closed Closure 错误。任何最终
Closure 失败也会在返回前按持有的 Device/Inode 身份扫描 `diagnostics` 角色并移除该 Boundary
精确拥有的诊断，因此同角色内的重命名或硬链接不能绕过清理，随后执行受检查的目录同步。
清理还要求已持有的 Inode 不再有任何链接，因此移出角色的重命名或硬链接会被判定为不确定，
而不会误报成功。若无法证明该身份已消失或删除已持久化，操作会返回独立终态
`diagnostic_cleanup_indeterminate`，而不是普通 Closure 失败；保留的私有证据不得视为成功。
Sink 身份会在任何可能失败的创建后写入或校验前保留，因此发布回滚也受同一清理证明保护。公开结果
只含角色名称与操作状态，不含私有根、实验 ID、输入名称/内容或原始错误。

## 检查点 2 顺序台账

| 顺序 | 步骤 | 本 PR 进入 `main` 后的状态 | 证据 / 下一门禁 |
|---:|---|---|---|
| 2A | 让 Host 实验目录符合 LAB-003 | `done` | Rust 发布与签名 Binding 使用随机 64-hex 实验 ID；复制、改名或固定名称目录均失败 |
| 2B | 新增持有式 Preflight 与 Closure | `done` | 七个固定 Profile 校验精确前/后清单、角色身份、别名和失败 Closure |
| 2C | 保持 Helper 启动关闭并测试诊断 | `done` | 生产授权 API 重新检查精确角色与持有后代后返回 `helper_launch_closed`；合成转换覆盖后置状态捕获及固定、有界、排他、仅 Owner 可访问的诊断清理，但不声称 Helper 已运行 |
| 2D | 新增合成回归与 CI | `done` | Ruby 转换/对抗测试、既有 LAB-003 Suite、Rust 测试、语法、格式及 CI Wiring 覆盖本无设备边界 |
| 2E | 发布检查点 2 完成记录 | `PR #91 合并后完成` | [PR #91](https://github.com/jacklv-coder/OrchardProbe/pull/91) 必须通过 Codex CR、GitHub Review 与全部必需 CI 后才能合并 |

## 范围结果

检查点 2 最多只能证明 Host 边界已为未来另行授权的首方仪式做好准备。它不创建 DemoLab
`1.0 (4)` Candidate、不冻结 Oracle、不上传 TestFlight、不安装或启动 App、不操作 Jack
iPhone、不观察受保护/明文字节、不解除 `DEVICE-001` 阻塞，也不提供 IPA 砸壳。

本完成 PR 合并后，检查点 3 仍是提案门禁。签名精确 Candidate 需要独立评审的激活与全新
明确授权，不能仅因为无设备代码已经合并就开始。
