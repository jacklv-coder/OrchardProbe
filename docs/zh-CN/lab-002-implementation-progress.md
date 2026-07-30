# LAB-002 实现进度台账

状态：**检查点 2 正在本地实现分支开发**

本文用于跟踪 [LAB-002](lab-002-oracle-design.md) 检查点 2 的实现进度，不把尚未
合并的工作描述成 `main` 已具备的能力。只有一个完整实现 PR 通过 Codex CR、所需 CI
与合并复核后，[执行计划](execution-plan.md)中的权威检查点状态才能从 `planned`
更新为 `done`。

本台账任何一行都不会授权签名构建、TestFlight 上传、安装、设备观察或设备后端开发。

| 顺序 | 子步骤 | 分支本地状态 | 完成证据 / 下一门禁 |
|---:|---|---|---|
| 2A | 闭合协议基础与固定 Mach-O 区间 | `完成` | Build/目标/设备的域分离绑定、有界规范 JSON、Ed25519 授权信封、两次运行比较、三个 Role 专用 `__TEXT,__oprobe`、失败关闭解析器、仅 Fixture 的 CI 检查、对抗测试和 Codex CR 均已完成，当前没有 P1/P2 |
| 2B | 闭合 Schema 与完整 Host 工件链 | `完成` | 全部 18 种 Wire 形式、精确 Enrollment/Run/两轮验证链、对抗 Fixture、完整本地门禁和最终 Codex CR 均通过且没有剩余 P1/P2 |
| 2C | DemoLab 状态协调器与零参数观察器 | `进行中` | 按下文 2C.1–2C.5 顺序执行；不接受调用者选择的目标、区间、路径、PID 或地址 |
| 2D | 合成与 Simulator 验证 | `planned` | 覆盖三个 Role、全部生成 Slice、状态迁移、负向 Fixture、崩溃/重放边界，并明确 Simulator 只能得到 `inconclusive` |
| 2E | 文档、最终 CR、CI、PR 与合并 | `planned` | 更新中英双语架构/用户 Runbook 与兼容性模板；解决全部 P1/P2，通过所有门禁，复核 PR 后合并 |

## 当前已验证事实

- 仓库自有 DemoLab 的三个 Role 在每个 Simulator Slice 中各生成且只生成一个确定性的
  256 字节 `__TEXT,__oprobe` 区段。
- 设备无关 Rust 测试已覆盖绑定变化、非规范 JSON 拒绝、授权签名篡改、两次运行的
  重放/环境/清单漂移、保护/明文矛盾以及畸形 Mach-O 结构。
- Debug 与 Release Simulator 的精确产物均通过冻结清单检查：每种配置包含三个
  Role、每个 Role 两个 Slice，共六个互不相同的 Role/Slice 区间哈希，每个 Slice
  恰好一个 256 字节区段。
- 本地完整门禁通过：CLI 单元测试 5 项、CLI 集成测试 17 项、Core 测试 167 项、
  Fixture 集成测试 1 项、Schema 测试 9 项，以及格式化、Clippy 警告即错误和相对
  基线的 Diff 检查。
- 最终 2A 专项 Codex CR 已复核 Segment 重叠、经典/链式 Fixup、链式 Import 名称、
  动态重定位表、区段边界和非公开 CLI 边界，未发现可执行的 P1/P2。
- 设备无关成功状态明确命名为 `consistent_synthetic_evidence`；它不是 LAB-002 Go，
  也不证明观察过物理设备。
- 2B.1 已形成一份自包含 Draft 2020-12 Bundle，覆盖 16 类保留顶层工件和两个嵌入式
  未签名 Core。9 项 Schema 测试通过，覆盖两轮计数器替换、Binding 两个独立计数器、
  固定 Role/Slice 顺序、全部 100 MiB 可执行文件字段、固定 `__TEXT,__oprobe`、
  结果矛盾与未知字段。
- 最终 2B.1 专项 Codex CR 未发现剩余可执行 P1/P2。
- 2B.2 已为全部 18 种 Wire 形式提供精确的 `lab002::artifacts` Rust 类型，包括未知
  字段拒绝、必需 Null 字段与缺失字段区分、有界 JCS 生成/精确解码、标量与坐标校验，
  以及嵌入规范 Core 校验。正向往返与对抗用例覆盖非规范字节、字段缺失/显式 Null、
  负时间戳、字节上限、单字符嵌入 JSON、零加密区间和加密覆盖矛盾。
- 最终分片范围的 2B.2 Codex CR 已解决全部报告的 P1/P2，各专项复核均为 Clean。
- 2B.3b 已从私有目标 Manifest 开始，依次验证 Host 签名的安装信封、设备签名回执、
  物理设备选择确认和最终 Enrollment Binding，形成精确六工件链。专项测试会拒绝
  确认字节、回执签名、选择 Fingerprint、最终 Binding 以及时间顺序替换。
- 2B.3b 专项 Codex CR 已复核精确字节绑定、严格 Ed25519 Key 处理、重放/替换边界、
  跨工件相等关系，以及由所有者确认的物理 Fingerprint 信任输入，未发现剩余可执行
  P1/P2。
- 2B.3c 已从每轮确认和 Host 签名 Challenge 开始，依次闭合 Intent、Enrollment Key
  签名 Export、四份精确内嵌报告及最终 Collection Binding；会拒绝实验、Entry Digest、
  Role 文档、环境、时钟偏差、Role 顺序和最终 Binding 替换。
- 2B.3c Codex CR 发现并修复了 Enrollment 到 Run 及跨 Role 的时间连续性缺口。Run
  窗口及其允许偏差的 Session 必须晚于已验证的 Enrollment Binding 完成时间，
  Main App、Framework、Share Extension 的 Phase 也不能发生时钟倒退；最终专项复核
  为 Clean。
- 2B.3d 已闭合一套 Enrollment 加两轮互异有序 Run，会拒绝轮次调换/重放、Run 2
  Prior Binding 断裂、窗口重叠、Run 1 关闭前提前授权、Acknowledgement/Challenge/
  Collection/Session ID 重用、工件 Hash 共用、Counter 漂移，以及 Enrollment/设备/
  环境漂移。
- 2B.3d Codex CR 发现并修复了一次性 Acknowledgement ID、随机 Challenge ID 及
  Run 1 Binding 到 Run 2 授权的连续性缺口，最终专项复核为 Clean。
- 最终 2B.4 门禁重新构建了精确 Debug/Release Simulator 产物，并通过冻结的产物
  Fixture 测试。完整 Rust 门禁、格式化、Clippy 警告即错误、Schema 契约及相对基线
  Diff 检查均通过；最终全变更 Codex CR 未发现可执行问题。
- 2C.2 已加入一套仅 Main App 可见的固定存储实现：Owner-only 目录/文件、No-follow
  有界读取、排他 Coordinator Lock、Descriptor/目录项身份检查、Inbox 无替换发布、
  Quarantine/Restore/Consume 状态迁移、精确规范 Counter 记录、检查后的单调 Counter
  提交、Complete File Protection 与禁止备份。Extension 只编译固定名称和上限。
- App 与 Share Extension 的通用 Entitlement 在 Debug/Release 中展开为同一个通用
  App Group。6 项 Simulator 存储测试覆盖重复/超限/Symlink Import、当前/过期/畸形
  Discard、Quarantine 残留、Counter 跳号、消费和规范状态；最终 2C.2 专项 Codex CR
  没有剩余可执行 P1/P2。
- 早期四字段 Counter 形态只存在于未 Push、未安装的分支本地草稿中。实现明确拒绝而
  不迁移该格式，因为接受冻结三字段 Schema 之外的字节会把无效格式转成受信任的单调
  状态；没有已发布构建写入过该草稿。
- 2C.3 已实现精确五字段 Installation Nonce 状态与唯一固定的生产 Keychain Tuple。
  只有认证后的 Enrollment 可以创建 Ed25519 Key 和 32 字节 Nonce；生产 Key 不可同步，
  且使用 `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`。Keychain Entitlement 与
  Info.plist 读取同一个显式 Access Group 构建设置，受控签名 Lane 注入完整
  `Team ID + App Bundle ID`。每个 Run 只能加载并比对记录的 Build/Public Key，
  因此 Key 丢失、跨 Build 或不匹配都会失败，不能创建或修复。
  生产 Enrollment/Run/Discard 入口不接受调用方提供的时间或 Build 身份：时间来自系统
  时钟，精确 64 字符小写 Hex Build Binding 来自编译期注入的 App Info.plist；覆盖值
  只能通过 Debug 专用测试初始化器注入。签名 Archive 会拒绝缺失或格式错误的预计算
  Binding，并把校验后的值注入构建，不会用仓库内的空设置生成生产候选。首次专项
  CR 发现一个中断恢复缺口：Keychain Item 可能已落盘，而 Nonce/State 持久化失败。
  现在 Item 会记录并校验 Build Binding，只有同一 Build 再次通过认证的 Enrollment
  才能恢复该孤立 Key 并完成独占状态创建；Run 无法调用恢复路径，其他 Build 会被拒绝。
  下一次复审发现状态持久化成功、授权删除前崩溃的互补边界。现在只有 Enrollment 可以
  恢复那一个精确的隔离授权，重新验证后严格加载已持久化的 State/Key，再完成删除；
  新的重复 Enrollment 与所有 Run 仍会拒绝隔离/状态冲突。11 项合成 Simulator 测试与
  Debug/Release Build 已通过；最终专项 Codex 复审没有剩余可执行的 P1/P2。
- 2C.4a 已从验证后的 Run Envelope、编译期 Build/Observer/Source 事实、已认证
  Enrollment 连续性、重新计算的 Installation Binding、固定环境查询、精确 Run
  Counter、系统时间和 32 字节系统随机数闭合一份不可变规范 `session.json`。文件只会
  在固定 `reports/current` 下排他创建，使用有界 No-follow 读取、原子发布、完整保护及
  禁止备份。19 项合成 Simulator 测试覆盖精确规范解码、Session 排他性/大小上限、
  Counter 与授权消费、跳号、已有/暂存 Session、中断事务恢复、重放拒绝及无效 Source
  Provenance。专项 CR 发现并关闭了状态顺序与恢复缺口：所有可能失败的 Session 校验和
  冲突预检都先于新 Counter Commit；精确授权会一直保留在 Quarantine，直到 Counter
  与 Session 都持久化；只有原先已存在的那份 Quarantine 能恢复匹配的已提交/暂存事务，
  新导入的重放会被 Restore 并拒绝。CR 还关闭了 Source Provenance 不一致：Archive
  Lane 会在 Build Staging 前拒绝冻结的 LAB-002 40 位 Hex Wire Format 之外的 Git
  Object ID。

## 已完成的 2B 门禁

- 为确认、登记、Oracle、Intent、签名导出与 Collection Binding 定义精确闭合 Schema。
- 实现完整 Host 侧工件生成/验证链，不增加设备传输，也不增加公开的目标/区间选择命令。
- 落实已评审设计中的各 Surface 字节上限、精确规范编码、未知字段拒绝、签名绑定、
  新鲜度窗口和重放边界。
- 在进入 2C 前，为完整工件链加入正向与负向 Fixture。

### 2B 执行顺序

| 顺序 | 工作项 | 状态 | 退出门禁 |
|---:|---|---|---|
| 2B.1 | 冻结闭合 Schema 清单与字段契约 | `完成` | 全部保留工件和嵌入式未签名 Core 都已闭合、有界；9 项 Schema 门禁与专项 Codex CR 通过且没有 P1/P2 |
| 2B.2 | 实现对应 Rust 编解码与验证器 | `完成` | 全部 18 种 Wire 形式都有精确 Rust 编解码和验证器；142 项 Core 测试、9 项 Schema 测试、Clippy、Diff 检查及专项 Codex CR 均通过且没有剩余 P1/P2 |
| 2B.3 | 串起 Host 工件链与 Fixture | `完成` | 一套完整合成 Enrollment 加两轮链验证通过；大小、重放、签名、新鲜度、顺序、Digest 和未知字段 Fixture 全部失败关闭；分片 Codex CR 发现均已解决 |
| 2B.4 | 执行 2B 门禁与 Codex CR | `完成` | Debug/Release Simulator 产物、产物 Fixture、格式化、Clippy、5 项 CLI 单元 + 17 项 CLI 集成 + 167 项 Core + 1 项 Fixture 集成 + 9 项 Schema 测试、Diff 检查和最终全变更 Codex CR 均通过且没有剩余 P1/P2 |

#### 2B.3 执行顺序

| 顺序 | 工作项 | 状态 | 退出门禁 |
|---:|---|---|---|
| 2B.3a | 域分离签名与精确工件 Digest | `完成` | Host 授权、登记回执、Session Export 与设备选择 Fingerprint 使用冻结二进制 Domain；严格 Ed25519 拒绝弱 Key 及 Key/Domain/字节替换；5 项专项测试、Clippy 与专项 Codex CR 通过且无剩余 P1/P2 |
| 2B.3b | Enrollment 工件链 | `完成` | 精确六文件链验证全部 Digest、Host/设备签名、Challenge、环境、物理选择 Fingerprint、Key/Binding 元组和时间顺序；10 项 Host 专项测试、Clippy、Diff 检查与 Codex CR 均通过且无剩余 P1/P2 |
| 2B.3c | 单轮 Export 与 Collection Binding | `完成` | 一轮精确确认/Challenge/Intent/Export/四报告/Binding 链验证严格签名、Digest、Counter、Enrollment、环境和单调时间连续性；19 项 Host 专项测试、Clippy、Diff 检查和 Codex CR 均通过且无剩余 P1/P2 |
| 2B.3d | 完整两轮链与对抗 Fixture | `完成` | 一套合成 Enrollment 加 Run 1/Run 2 以精确 Ordinal/Counter、Prior Binding、单调窗口、互异 Acknowledgement/Challenge/Collection/Session ID 与工件，以及相同 Enrollment/设备/环境事实闭合；25 项 Host 专项测试、Clippy、Diff 检查和 Codex CR 均通过且无剩余 P1/P2 |

2B.3a 专项 CR 发现并关闭了新 Host 路径和既有授权验证器中的严格 Ed25519 缺口：
验证现使用 `verify_strict`、拒绝弱公钥，签名入口也拒绝派生出的弱 Key。

2B.3b 专项 CR 确认：只有 Host 签名的 Challenge/信封与所有者在物理设备上比对完整
Fingerprint 并记录于 Owner-only 选择工件后，自签名 Enrollment 回执才会被接受。
这个显式物理确认仪式是冻结的一方 Fixture 信任输入；验证器不会把它描述成硬件证明。

2B.3c 验证器返回密封的 Verified Token：调用者可以把它交给下一层验证器，但不能构造
或修改其中的闭合事实，从而避免 API 使用者在两轮门禁前替换已验证的 Key、Binding、
环境或时间。

2B.3d CR 还明确区分了签名 Core 内的随机 Challenge 值与完整 Challenge Envelope 的
SHA-256；两者在两轮之间都必须新鲜，一次性 Acknowledgement ID 也同样不能重用。

## 当前 2C 执行计划

2C 仍然只做设备无关实现：使用临时本地容器、合成 Key 与 Simulator 构建进行开发和
测试。它不授权签名 Archive、TestFlight 上传、App 安装或读取物理设备。

| 顺序 | 工作项 | 状态 | 退出门禁 |
|---:|---|---|---|
| 2C.1 | 冻结 Target 私有 API 与存储边界 | `完成` | 中英双语设备端实现契约已冻结固定相对名称、状态迁移、零参数 Observer 入口、仅测试依赖注入，以及 Host 禁止访问 App Group、调用者不得选择 Path/Target/Range 的边界 |
| 2C.2 | 实现固定 Inbox 与持久状态协调器 | `完成` | 仅 Main App 的 Import/Start/Discard、固定 App Group 生产定位、No-follow 有界读取、Lock/Quarantine 身份检查、精确 Counter 提交、原子写、Protection/Backup 策略、6 项 Simulator 测试、Debug/Release Build 和专项 Codex CR 均通过且没有剩余 P1/P2 |
| 2C.3 | 实现 Enrollment 状态与 Device-only Key 边界 | `完成` | 只有安装动作能创建合成/Keychain Key，精确绑定 Key/Nonce/Build；生产属性为 ThisDeviceOnly 且不可同步；支持同一已认证 Envelope 的中断恢复；丢失/重置/不匹配均拒绝，Run 路径不能创建或修复 Enrollment；11 项 Simulator 测试、Debug/Release Build 与专项 Codex CR 均通过 |
| 2C.4 | 实现 Session 生命周期与三个零参数 Observer | `进行中` | Main App、Framework、Share Extension 只观察各自编译固定的自身 Target/Range，按固定顺序只发布一次并绑定不可变 Session 事实；公开入口不接受 Path/Target/Range/PID/Address |
| 2C.5 | 实现签名 Export、Receipt 与 Cleanup 边界 | `planned` | 固定四文档 Export 与 Enrollment Receipt 使用登记 Key 签名且只能走系统 Share Sheet；Cleanup 必须匹配已完成 Export，不能重置固定状态/Key；专项门禁与 Codex CR 没有剩余 P1/P2 |

### 2C.4 执行顺序

| 顺序 | 工作项 | 状态 | 退出门禁 |
|---:|---|---|---|
| 2C.4a | 闭合并持久化不可变 Run Session | `完成` | 精确 Session Report 字段只来自已验证 Authorization、固定 Build/Runtime Facts、Enrollment 连续性、精确 Counter 与系统随机数/时间；Counter/Session 中断发布只可由原先精确 Quarantine 恢复，`session.json` 排他创建，19 项 Simulator 测试与专项 CR 通过 |
| 2C.4b | 实现 Target 私有 Mach-O Observer Core | `进行中` | 对安装文件做 No-follow 有界解析并解析已映射 Image，只推导编译固定的 `__TEXT,__oprobe` Range；返回闭合结构证据/原因，不接受调用方选择输入 |
| 2C.4c | 接入三个零参数 Role 入口 | `planned` | Main App、DemoFramework、Share Extension 只解析自身，按固定顺序各发布一次固定报告，并拒绝重复、过期或冲突 Session |
| 2C.4d | 完成 Session 并执行专项门禁 | `planned` | 精确顺序/完成迁移、负向 Simulator Fixture、Debug/Release Build、文档与专项 Codex CR 均通过且没有剩余 P1/P2 |
