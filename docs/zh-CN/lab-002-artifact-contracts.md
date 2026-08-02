# LAB-002 闭合工件契约

状态：**检查点 2B 已在 `main` 完成**

本文解释
[`schemas/lab002/lab-002-artifacts-v1.schema.json`](../../schemas/lab002/lab-002-artifacts-v1.schema.json)
中的 Schema Bundle。它从属于已评审的
[LAB-002 Oracle 设计](lab-002-oracle-design.md)，不会增加设备传输、通用目标选择、
路径、进程、地址或调用者选择的区间。

## 工件清单

Bundle 是自包含的 Draft 2020-12 JSON Schema。每个允许的顶层工件都有唯一固定的
`schema` 值。所有带 Profile 的工件都使用固定值
`orchardprobe.demolab.lab002.observation.v1`；刻意保持最小化的运行计数器状态不含
`profile` 字段。

| 工件 | 固定 `schema` 值 | 保留规则 |
|---|---|---|
| 私有授权目标清单 | `orchardprobe.lab002.authorized-targets.v1` | 每组精确身份一份私有构建前清单，绝不打进 IPA |
| 授权使用确认 | `orchardprobe.lab002.authorized-use-ack.v1` | 安装一份，每轮运行各一份 |
| 安装登记 Core | `orchardprobe.lab002.installation-enrollment-core.v1` | 以规范字符串嵌入签名授权信封 |
| 采集挑战 Core | `orchardprobe.lab002.collection-challenge-core.v1` | 以规范字符串嵌入签名授权信封 |
| 授权操作信封 | `orchardprobe.lab002.authorized-operation-envelope.v1` | 登记一份，每轮运行各一份 |
| 签名登记回执 | `orchardprobe.lab002.device-enrollment-receipt.v1` | 每个实验一份 |
| 设备选择确认 | `orchardprobe.lab002.device-selection-confirmation.v1` | 每个实验一份 |
| 设备登记绑定 | `orchardprobe.lab002.device-enrollment-binding.v1` | 每个实验一份 |
| 运行计数器状态 | `orchardprobe.lab002.run-counter-state.v1` | App Group 中一份状态文件，每轮被接受后原子替换 |
| 安装 Nonce 状态 | `orchardprobe.lab002.installation-nonce-state.v1` | 当前安装 Build 在设备 App Group 中的一份本地状态文件 |
| 冻结 Oracle | `orchardprobe.lab002.oracle.v1` | 上传前一份，并在外部保存其哈希 |
| 采集 Intent | `orchardprobe.lab002.collection-intent.v1` | 每轮运行一份 |
| 签名 Session Export | `orchardprobe.lab002.session-export.v1` | 每轮运行一份 |
| Session Report（`session.json`） | `orchardprobe.lab002.session-report.v1` | 每轮恰好一份，包含在签名 Export 中 |
| Role Report | `orchardprobe.lab002.role-report.v1` | 每轮恰好三份：主 App、Framework、Share Extension |
| Collection Binding | `orchardprobe.lab002.collection-binding.v1` | 每轮完成后各一份 |

签名登记回执和签名 Export 分别嵌入一个精确的规范化未签名 Core。这些内部 Core
是独立 `$defs`，不是额外保留文件。授权信封同样嵌入确认书和操作 Core 的精确规范
字节字符串，而不是解析后的副本。

## 闭合边界

- 每个对象都设置 `additionalProperties: false`。
- SHA-256、密钥、Nonce、ID、UUID、签名、源码 Commit 和运行计数器都使用精确长度的
  小写十六进制。
- Policy、Profile、Technique、Retention、Role、逻辑文件名、Operation、动作顺序、
  数据类别与运行计数器取值全部闭合。
- 安装确认必须带固定设备环境与安装动作序列；运行确认必须带登记绑定与固定的
  观察、导出、清理动作序列。
- Oracle 的 Role 顺序固定为主 App、Framework、Share Extension；每个 Role 会保留
  冻结的精确 `thin`、`fat32` 或 `fat64` 容器类型，并只能有 1 至 4 个按 Ordinal
  排序的 Slice。Host 关闭时必须精确匹配该容器表示，不能只凭 Slice 数量把一种 FAT
  编码替换为另一种。每个可执行文件区间最大 100 MiB，构建配置固定为 `Release`。
  签名 Export 条目顺序固定为 Session、主 App、Framework、Share Extension。
- 每个已观察 Slice 都显式记录固定 `__TEXT` Segment 与 `__oprobe` Section。
  `pass` Role 不得带原因；`fail` 与 `inconclusive` Role 至少需要一个闭合原因码。
- Schema 只允许安全范围整数和有界字符串。运行时字节限制更严格：确认书/操作 Core
  3 KiB、授权与 Host 控制工件 16 KiB、内部 Report 32 KiB、签名 Export 512 KiB。
- Run 1 必须使用计数器 `0000000000000001` 且 Prior Binding 为 null；Run 2 必须
  使用 `0000000000000002` 且 Prior Binding 非空。Challenge、Intent、未签名
  Export、Session Report、Role Report 与 Collection Binding 都闭合该
  Ordinal/Counter 关系。
- Host 以固定 Domain、`u32be` 长度和规范
  `{"roles": <精确 Oracle Role Array>}` 字节计算 `expected_inventory_sha256`。
  Intent 只保留在 Host，绝不会作为设备输入。
- Session Report 与 Role Report 都持久保存签名授权中的精确
  `authorization_not_after`。设备观察/完成动作与 Host Verifier 都拒绝晚于该绝对
  时间加固定 120 秒时钟偏差的 Phase 或完成时间，不能从 Session 创建时间推导
  相对截止时间。

JSON Schema 只负责形状、闭合词汇、顺序和标量边界。检查点 2B.2 仍必须验证跨工件
字段一致性、精确 900 秒窗口、规范字节相等、Digest 重算、Ed25519 域与签名、新鲜度、
一次性使用和重放/链式规则。仅通过 Schema 绝不代表完成授权、获得设备证据或得到
LAB-002 Go 结论。
