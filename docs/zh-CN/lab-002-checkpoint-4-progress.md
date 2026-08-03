# LAB-002 检查点 4 进度台账

[English](../research/lab-002-checkpoint-4-progress.md)

跟踪 Issue：[#55](https://github.com/jacklv-coder/OrchardProbe/issues/55)

激活 PR：[#73](https://github.com/jacklv-coder/OrchardProbe/pull/73)

Host 流程 PR：[#74](https://github.com/jacklv-coder/OrchardProbe/pull/74)

发布管道修复 PR：[#76](https://github.com/jacklv-coder/OrchardProbe/pull/76)

冻结 Oracle 兼容 PR：[#78](https://github.com/jacklv-coder/OrchardProbe/pull/78)

当前分支状态：**检查点 4 active；4A 与 4B 已完成；失败关闭的发布管道诊断修复已合并；
不可变检查点 3 Oracle 的 4C 精确 Digest 兼容修复已通过 PR #78 合并；4C 现在要求在新的
Host 启动和任何真机操作前紧邻地取得另一份全新 RFC-0001 确认**

本台账控制已冻结首方 DemoLab `1.0 (3)` 候选的精确安装 Enrollment 与两轮执行。
它不授权其他源码、Build、Target、设备、分发渠道或 Device Backend。只有 `main`
中的版本具有权威性。

2026-08-01，操作员授权 Codex 对已冻结候选执行有界检查点 4 流程：恰好一次内部
TestFlight 上传、Apple 处理状态对账、协调操作员在所选自有 iPhone 上独立完成
TestFlight 安装、Enrollment 和两次干净观察。OrchardProbe 不安装、修改、重签名或
重新启动该工件；安装仍是独立 TestFlight Provisioning 操作，由操作员本人或 Codex
作为操作员明确授权的本地助手在任何 OrchardProbe 命令之外执行。该授权不包含外部测试、Beta App Review、App Store 提交、重签名、
再分发、任意目标选择或通用 Device Backend 工作。

## 治理偏差

恰好一次上传调用和只读 Apple 对账发生在操作员明确有界授权之后、但本激活 PR 进入
`main` 之前；该顺序违反执行台账的“先激活、后工作”规则。外部操作无法撤销，已处理
的不可变 Build 也不得再次上传。因此本台账明确保留该偏差，不能把它写成合规操作、
隐藏它或制造一次重试。此后没有安装、Enrollment 或观察；所有剩余检查点工作保持阻塞，
且必须在激活 PR 合并后才能开始 4B。这不是先例，也不是串行规则的例外。

上述工作流授权不能替代已评审设计要求的三次限时 RFC-0001 授权使用确认。Host
必须在安装 Enrollment 前紧邻地记录一次，并在每轮前各记录一次；每份确认都必须包含
一次明确确认、四项必需范围断言、精确设备/环境和闭合的操作、数据、保留范围。在对应的一次性签名信封
存在之前，不得开始安装或观察。

## 检查点 4 顺序计划

| 顺序 | 步骤 | 状态 | 完成门禁 |
|---:|---|---|---|
| 4A | 激活并关闭提前上传/对账治理偏差 | `完成 — PR #73` | 本台账与双语执行计划合并明确的不合规记录。Apple 已列出精确 DemoLab `1.0 (3)`，处理完成并进入现有内部组；不可变 Build 不重试，且没有创建外部测试或审核状态 |
| 4B | 闭合 Host 操作流程 | `完成 — PR #74` | 五个已评审 Fastlane 入口创建并原子保留安装/运行控制阶段，只接受有界且由设备创建的 Receipt/Export，要求每次明确确认、全部四项 RFC-0001 范围断言和完整 64 位十六进制 Fingerprint，派生仅 Host 的 Binding，并再次执行完整 Enrollment/Run/两轮验证。每次操作都会重新解析完整闭合的上传前 Evidence、重新 Hash 精确三个冻结 Archive 可执行文件，并依据原始 Prebuild/Candidate 元组重新验证保留的 Source；关闭时逐 Role/Slice 对照冻结 Oracle，最终链还要求两轮规范化观察完全一致。固定 Owner-only 目录均通过已持有描述符传入；命令不安装、不启动、不上传、不访问 App Group，也不选择 Target。安装前要求的无设备测试、Codex CR、CI、PR 与合并均已通过 |
| 4C | 精确安装与 Enrollment | `active — 等待全新确认` | 第一次获授权启动在发布前失败关闭：Helper 提前退出并关闭确认管道，Fastlane 又以 `EPIPE` 遮蔽了有界 Helper 错误；[PR #76](https://github.com/jacklv-coder/OrchardProbe/pull/76) 已合并该修复。下一次获全新确认启动也在发布前失败，因为不可变的检查点 3 Oracle 早于必需的 `container_kind` 字段；[PR #78](https://github.com/jacklv-coder/OrchardProbe/pull/78) 已合并仅限完整 Digest 的兼容修复。再次记录全新安装确认并签署一次性信封。在 OrchardProbe 之外独立 Provision 所选自有 iPhone 上唯一的 TestFlight `1.0 (3)`；导入信封，导出并验证设备签名 Receipt，对比全部 64 个 Fingerprint 十六进制字符，并在签名时间窗内关闭 Enrollment Binding |
| 4D | 干净运行 1 | `blocked on 4C` | 记录全新 Run-1 确认；创建并保留不同的 Host 侧 Intent，只导入签名 Challenge；全新启动三个固定 Role，再导出、验证、绑定并安全保留精确运行后清理报告 |
| 4E | 干净运行 2 | `blocked on 4D` | 使用更晚且不重叠的授权窗口和与 Run 1 链接的不同 Challenge；在不重装、不更换设备/OS、不重置状态的前提下重复全新三 Role 导出并关闭第二份 Binding |
| 4F | 检查点关闭 | `blocked on 4E` | 以冻结 Manifest、IPA 证据和外部 Oracle 验证完整 Enrollment 加两轮链；发布脱敏 Go/No-Go，不能通过重试掩盖失败或不完整运行 |

每行完成后才能开始下一行。Crash、过期、Share Extension 不可用、Fingerprint 对比失败、
Export 不完整、安装/设备/OS 改变或归一化结果不一致，都必须按已评审 No-Go 规则保留并
关闭，不能静默重试成通过结果。

## 上传对账记录

只从产生冻结候选的干净 Detached 源码 Commit 执行过一次已评审的
`ios demolab_upload_testflight`。由于终端 `altool` 响应不是有效 JSON，且既没有结构化
Product Error，也没有经验证的成功消息，本地 Lane 保留 `status: indeterminate`；该记录
保持不变作为证据。

随后只使用已登录的 App Store Connect 页面核对远端状态。页面显示 DemoLab `1.0 (3)`
处理完成、没有缺少出口合规信息，并属于现有内部组。因此 Apple 已接受该精确 Build，
不得重试上传。没有创建或修改 Tester Group、没有启用外部测试，也没有请求 Beta App
Review 或 App Store 提交。

## Host 工具门禁

检查点 2 已合并闭合工件 Schema、规范编码器、签名原语、完整 Enrollment/Run/两轮验证器、
设备 UI 与合成测试。步骤 4B 增加五个私有 Fastlane Lane：开始/关闭 Enrollment、开始/关闭
下一轮，以及验证完整保留链。每个发布动作使用随机 Owner-only Staging、排他 Rename、父目录
同步、固定文件名和精确阶段清单。授权 Seed 只留在冻结 Prebuild 目录；设备私钥只留在设备。
仍禁止手写 JSON、借用测试 Fixture 或操作后补填记录。

4B Codex CR 拒绝了初始实现，直到 Host 固定已评审签名验证器 ID、拒绝 Thin/多 Slice
矛盾、以安装文件大小约束每个观察 Slice，并由 Fastlane 通过排他工作流根锁串行化完整调用。
这四个 P2 必须具备回归覆盖，并重新通过完整本地门禁、全新无问题 CR、CI 与合并，之后才可
开始 4C。

随后完整 Diff CR 又发现两个 P2 来源缺口：Operator 会接受不完整的上传前 Evidence
对象，并把任意自有目录当作冻结 Archive。修复后的源码以禁止未知字段的方式反序列化完整
闭合 Evidence 树，验证 Package/出口合规、Lineage、Toolchain、Manifest、Oracle、IPA
以及全部六份二进制记录；再通过目录描述符枚举并重新 Hash 精确三个 Archive 可执行文件。
Archive 架构/UUID Evidence 也会规范化后与每个冻结 Oracle Slice 对齐。新增回归会拒绝
缺失的嵌套字段、未知字段和空的自有 Archive。一次临时且不提交的只读 Probe 已确认保留的
真实候选通过这套更严格的 Source-bundle 验证；该 Probe 没有上传、安装、Enrollment 或
触碰设备。

下一轮完整 Codex CR 又发现一个 P1 和两个 P2 闭合缺口：冻结来源加载器只建模了
`indeterminate` 上传审计形态，但已评审上传 Lane 可以原子替换为终态 `accepted` 形态；
两轮验证器没有在每轮结果中保留并比较冻结 Oracle 摘要；开始第 2 轮时也只计算了第 1 轮
Binding 的摘要，没有先完整验证保留的第 1 轮链。修复后会严格验证两种闭合上传结果（包括
终态时间戳），在 `VerifiedRun` 中保留并比较 Oracle 摘要，并在发布任何第 2 轮 Control
之前完成第 1 轮来源和完整链验证。回归覆盖两种上传形态、非法时间戳/状态组合，以及跨
Oracle 两轮拒绝。实现 PR 打开或合并前仍必须通过完整本地门禁与全新的无问题 CR。

该修复提交后，两次独立完整 Fastlane 门禁各自重新构建三份 Helper；Source Snapshot 为
`8f468ee4a076008520070110dcafc9dc76e43208adaf568a61cab91c13c90207`，工具链为
`1.85.0-aarch64-apple-darwin`。六份产物的 Size 均为 `3,179,024`，SHA-256 为
`5789f1726bec7aa1f7df93adc131ff103608fc625a06ecac13275bc0ffcb0413`，
CodeDirectory CDHash 为 `59bafcc5867af9864bbf1b10d17d8ea375b2607a`。临时测量分支随后被
完整删除，才把这一个精确 Tuple 加入已评审 Allowlist；正常非测量门禁再次重新构建并接受
该 Tuple，且无签名 Simulator Fixture 通过。

随后 Codex CR 发现一个 P2 兼容性回归：新的当前 Helper 验证位于既有 SHA-256 Git 仓库
跳过逻辑之前，但 LAB-002 v1 工件契约有意只接受 40 位 Source Commit。现在只有进入同一个
40 位检查点路径时才构建并验证当前 Helper；64 位仓库仍执行通用 DemoLab 检查，同时跳过
所有 LAB-002-v1 专属 Round Trip。该修复只改 Fastlane，不改变已测量的 Rust Source
Snapshot 或 Helper 产物 Tuple；仍需重新通过完整门禁与全新无问题 CR。

提交该修复后，两次独立完整 Fastlane 门禁各自产生三份完全一致的 Helper Build；Source
Snapshot 为 `0cab364ef4b3964bf6de1b864c459cd8b7b25e1e27d2e0d962ff20af6665d281`。
全部六份产物的 Size 均为 `3,179,072`，SHA-256 为
`0019b20af4d176fa62afe012fbf57cceac89009ffa2db47bdd1b54c2f3b4808f`，
CodeDirectory CDHash 为 `b0e3663ee3475784d787239f6ff9fdd7c3ff824c`。临时测量 Hook
已在把唯一该 Tuple 加入已评审 Allowlist 前删除；随后正常非测量门禁重新构建并接受了
该精确 Tuple，且无签名 Simulator Fixture 通过。

Rust 验证器修复提交后，两次独立完整 Fastlane 门禁以 Source Snapshot
`252af3147edadf200a090cc818c2fd4da231d5721befaaa7aa5c7b0f990aabd9`、固定工具链和
离线已验证依赖重新构建私有 Helper。所有构建都得到 Size `3,062,032`、SHA-256
`5d4e47c52967331af2ea7d066d6cd9c6c443d837fb88c0a94860c743f1a1d29e` 与 CodeDirectory
CDHash `42bd1c5f3d0e1c3841c5ef80216a21744529d37b`；Allowlist 只接受这个精确 Tuple。

下一轮完整 Diff Codex CR 又发现两个 P2 来源缺口。上传前 Evidence 虽记录 Manifest 与
Oracle 的 Device/Inode 身份，Operator 却只比较其格式、名称、Mode、Size 和摘要；可复用
Host Run 验证器也没有独立保留由已 Enrollment Manifest 推导的 Target Binding。修复后，
两份 Evidence 身份必须分别与实际持有的文件描述符一致；关闭 Enrollment 时会推导并保留
按固定三 Role 排序的 Target Binding 与集合摘要；每轮 Oracle 的全部 Role 和集合摘要必须
与这些 Manifest 派生值一致。新增回归会拒绝替换过的描述符身份，以及从另一 Target 派生、
内部仍自洽的 Oracle Target 集合。由于此次修改 Rust Helper，4B PR 打开前必须重新完成两次
独立可复现测量、只保留新 Tuple 的 Allowlist、正常门禁、完整本地测试和全新无问题 Codex CR。

提交该来源修复后，两次独立完整 Fastlane 门禁各自重新构建三份 Helper；Source Snapshot
为 `220f4cab162c91a9ae82fce85c534e09bf0f4f0c798695b369de99b40df24661`。
全部六份产物完全一致：工具链 `1.85.0-aarch64-apple-darwin`、Size `3,181,488`、
SHA-256 `b586c9629ba827d9c5f158276ffaa6994952ea7ba916e4de62854750dc98bc46`、
CodeDirectory CDHash `6777ec989e0c6ac034ea3905b3646f61fb1d1b98`。临时测量 Hook 已在
把该精确 Tuple 加入已评审 Allowlist 前完整移除。正常非测量门禁已重新构建并接受它，且
无签名 Simulator Fixture 通过；Format、锁定依赖且拒绝警告的 Clippy、全部 271 项
Workspace 测试、Ruby 语法和 Diff 检查也均通过。4B PR 前只剩全新无问题 Codex CR。

该 CR 又发现两个 P2 完整性缺口：Close-run 没有拒绝当前 Control 阶段目录中的额外条目；
可复用工件边界也没有要求 Oracle 的 Generator Revision 与 Source Commit 相等。修复后会
持有当前 Control 目录描述符，在读取任何 Control 工件前验证精确三文件清单，并把
Generator/Source Revision 相等纳入 `LabOracle` 验证，使 Control 创作与 Run 验证共享同一
约束。新增回归分别拒绝未计入的 Control 条目和由另一 Generator Revision 归因、格式仍合法
的 Oracle。由于该修复改变 Rust Helper，仍需新的两次独立可复现测量、Allowlist Tuple、
完整门禁和全新无问题 CR。

提交该修复后，两次独立完整 Fastlane 门禁各自重新构建三份 Helper；Source Snapshot 为
`87142c73a633b88df721cef1b008e53b76d455707870bc24a849da0debd93968`。
全部六份产物完全一致：工具链 `1.85.0-aarch64-apple-darwin`、Size `3,181,376`、
SHA-256 `df9e5f1bc60ee537930c51f6875e964660056040c78ee22ab73fb797a63abeab`、
CodeDirectory CDHash `c8206133f0885ab4e3b2d46179d71478f1e2912c`。临时测量 Hook 已在
把该精确 Tuple 加入已评审 Allowlist 前完整移除。正常非测量门禁已重新构建并接受它，且
无签名 Simulator Fixture 通过；Format、锁定依赖且拒绝警告的 Clippy、全部 273 项
Workspace 测试、Ruby 语法和 Diff 检查也均通过。4B PR 前只剩全新无问题 Codex CR。

该全新完整 Diff CR 随后又发现三个 P2 边界缺口：输出根可以与冻结 Prebuild 或 Candidate
目录别名；全部语义和 Archive 验证完成后没有再次读取来源工件；Receipt/Export Path 在确认
文件类型前会以阻塞模式打开。修复后会在启动 Helper 前拒绝重复的目录 Device/Inode 身份，
并在返回保留 Source Bundle 前再次验证 Prebuild/Candidate 精确清单、每个工件的全部字节与
身份，以及三个 Archive 可执行文件；Receipt/Export 则统一走现有的仓库外、仅 Owner 可访问
且非阻塞的快照边界。负向回归会拒绝别名 Binding、替换后的字节/身份、FIFO 与其他特殊外部
输入。由于来源重验证会改变 Rust Helper，4B PR 打开前仍需两次新的独立可复现测量、只保留
新 Tuple 的 Allowlist、正常门禁、全部本地门禁和全新无问题 CR。

提交该边界修复后，两次独立完整 Fastlane 门禁各自重新构建三份 Helper；Source Snapshot
为 `6dc02974b685a970d1e32b874142f6d26de92dab78605460a9ff82781a17502b`。全部六份产物
完全一致：工具链 `1.85.0-aarch64-apple-darwin`、Size `3,181,712`、SHA-256
`911ba178be1c0b20234ae72adeabe04c8c9ebbafe874c2cbdf9cdd5853e63c20`、CodeDirectory
CDHash `8285d08248480782cf362abb0136a1b37b1a8b91`。临时测量 Hook 已在把该精确 Tuple
加入已评审 Allowlist 前完整删除。正常非测量门禁已重新构建并接受它，且无签名 Simulator
Fixture 通过；Format、锁定依赖且拒绝警告的 Clippy、全部 274 项 Workspace 测试、Ruby
语法、Diff 检查和明确的无测量 Hook 检查也均通过。4B PR 前只剩全新无问题 Codex CR。

该完整 Diff CR 又发现两个 P2 完整性缺口。Run Control 创作只检查了 Oracle 顶层 Build
字段，没有在签名前拒绝与已关闭 Enrollment 不同的逐 Role Target Binding 或 Target Set
摘要；冻结来源加载器也会接受没有从绑定 IPA Entry 重新推导的 IPA Binary Size/Hash 声明。
修复后，任何 Run Control 签名前都会复用由 Manifest 派生的 Oracle Target Binding 验证器；
随后对已持有 IPA 进行有界检查与复制，要求精确三个可执行 Entry 的实际 Size 和 SHA-256
与 Evidence 一致。新增回归分别拒绝 Enrollment 范围外的 Oracle Binding 和伪造的 IPA
Entry Hash。由于该修复改变 Rust Helper，4B PR 打开前仍需两次新的独立可复现测量、只保留
新 Tuple 的 Allowlist、正常门禁、全部本地门禁和全新无问题 CR。

提交该完整性修复后，两次独立完整 Fastlane 门禁各自重新构建三份 Helper；Source Snapshot
为 `ff4bdb2c9674d3e63019104e69d96a83aee2e054f609f52227e9016232885b5b`。
全部六份产物完全一致：工具链 `1.85.0-aarch64-apple-darwin`、Size `3,270,256`、
SHA-256 `c840e1a92ddeabc18fc63376a5ec193c8f0710508cd2015085dcfba75af3f0b4`、
CodeDirectory CDHash `03450ddbd3e5096f7c948abdf2c8bc73245b2e8e`。临时测量 Hook 已在
把该精确 Tuple 加入已评审 Allowlist 前完整删除。正常非测量门禁已重新构建并接受它，且
无签名 Simulator Fixture 通过；Format、锁定依赖且拒绝警告的 Clippy、全部 276 项
Workspace 测试、Ruby 语法、Diff 检查和明确的无测量 Hook 检查也均通过。4B PR 前只剩
全新无问题 Codex CR。

该全新完整 Diff CR 发现两个 P1 执行阻断。Host 要求独立 `valid` 的
`security-framework` 签名 Tuple，但当前 iOS Observer 有意并如实输出有界 Parser 的
`not_checked` Tuple，导致任何真实设备 Export 都无法关闭；同时 Run 1 完成后可以立即创作
Run 2 Control，但最终验证器要求两个已签名 15 分钟窗口严格不重叠。修复后，Host 只接受
精确的 `not_checked`/`demolab-bounded-codesign-parser`/`1`、`inconclusive`、唯一
`signature_invalid_or_unchecked` Tuple 作为可复现的方法级 No-Go 证据，同时保留全部
Oracle 与保护态比较。Run 2 必须引用已经验证的 Run-1 对象，由 Core 自行派生前序 Binding，
且只有 Host 时间严格晚于 Run 1 已签名 `not_after` 才允许创作。新增回归覆盖伪造签名升级、
替换 Reason/Validator、精确时间边界和 Oracle 连续性。由于这些修改会改变 Rust Helper，
4B PR 前仍需新的可复现测量、替换 Allowlist Tuple、完整本地门禁和另一轮无问题 CR。

后续未提交 CR 又发现两个 P1 结果边界缺陷。Run 2 只晚于 Run 1 Deadline/完成时间仍可能
在设备用满允许的 120 秒时钟偏差时，让 `created_at` 与 Run 1 重叠；同时如实的 Unchecked
Tuple 仍会被最终 Lane 显示成普通验证成功。现在 Run 2 创作要求 Host 时间同时严格晚于
Run 1 已签名 `not_after`，以及保留的 Run 1 完成时间加 120 秒。已验证 Run 与双轮 Chain
还会携带封闭的 `go` 或 `no_go_signature_unchecked` Disposition；Helper 在第二轮关闭和
最终验证时返回该字段，Fastlane 会把后者明确显示为方法级 No-Go。端到端 Fixture 默认改为
当前 Observer 的精确 Unchecked Tuple，并由独立回归继续封闭 Valid 的 Go Tuple。由于这些
Rust 修改，4B PR 前仍需新的可复现测量、完整本地门禁和无问题 CR。

提交结果边界修复后，两次独立完整 Fastlane 门禁各自重新构建三份 Helper；Source Snapshot
为 `cbd037cd1b219dbeefeb994bce760cc9e3452a0657f0dc24d3eb0fca22089732`。
全部六份产物完全一致：工具链 `1.85.0-aarch64-apple-darwin`、Size `3,270,832`、
SHA-256 `48b8fc4736b828c05b889cb691cf7a324fd1fa5202469e0863e4c02bc06ed51a`、
CodeDirectory CDHash `f2be8b9daf358bbd866bade65f387454f6a44db6`。仅在 Tuple 缺失时生效的
临时测量 Hook 随后被完整删除，并把该 Source Snapshot 下唯一的精确产物 Tuple 加入已评审
Allowlist；两轮测量门禁的无签名 Simulator Fixture 也都通过。随后正常非测量门禁重新构建
并接受 Allowlist Helper，且无签名 Simulator Fixture 通过；
Format、锁定依赖且拒绝警告的 Clippy、全部 278 项 Workspace 测试、Ruby 语法、Diff 检查和
明确的无测量 Hook 检查也均通过。4B PR 前只剩一轮全新无问题 Codex CR。

该次最终完整 Diff CR 又发现一个 P2 源生命期缺口：完整 Operator 验证器在检查两轮保留结果前已加载并验证冻结 Prebuild/Candidate 元组，但链验证后未再次打开它们。并发替换源文件因此可能让结果继续基于过期的内存 Oracle 字节。修复在两轮链闭合后、返回处置结果前，重复完整的冻结源与保留源匹配。这一 Rust Helper 变更要求两次新的独立可复现性测量、替换唯一 Allowlist 元组、正常门禁、全部本地门禁和一次新的干净 CR，才能打开 4B PR。

提交该源生命期修复后，两次独立完整 Fastlane 门禁各自重新构建三份 Helper；Source Snapshot 为 `e7edd34197e5b4aade1c74431dbe632eb7e46470f2ec412046b45d42b47a5299`。全部六份产物完全一致：工具链 `1.85.0-aarch64-apple-darwin`、Size `3,270,944`、SHA-256 `1a173e6189cead86850e52332c6f6aadcddfc8f148698f4b7d8ca6777a91aa47`、CodeDirectory CDHash `71fb6ba2b6ed95c64d3d206d0913f9b0e4413347`。临时缺失 Tuple 测量 Hook 已完整删除，然后才把该 Source Snapshot 下唯一的精确产物 Tuple 加入已评审 Allowlist。两轮测量门禁的无签名 Simulator Fixture 也都通过。随后正常非测量门禁重新构建并接受 Allowlist Helper，无签名 Simulator Fixture 也通过。Format、锁定依赖且拒绝警告的 Clippy、全部 278 项 Workspace 测试、Ruby 语法、Diff 检查和明确的无测量 Hook 检查也均通过。4B PR 前只剩一轮全新无问题 Codex CR。

这轮全新完整 Diff CR 又发现两个 P2 关闭路径缺口：第二轮关闭重新验证第一轮时，没有单独把保留 Intent 重新绑定到冻结预上传证据；返回闭合处置前，也没有执行最终验证器使用的链后源复核。修复会在接受两轮链前重新核对第一轮保留 Intent，并在链闭合后、每次关闭返回前重新打开完整冻结 Prebuild/Candidate 元组。由于这会改变 Rust Helper，4B PR 前还需要两次新的独立可复现测量、替换唯一 Allowlist Tuple、正常门禁、全部本地门禁和一次新的干净 CR。

提交该关闭路径修复后，两次独立完整 Fastlane 门禁各自重新构建三份 Helper；Source Snapshot 为 `c454b2084ce5abbe2f677e91fbc4423fed9a852d0c167c7f82200543f427de3f`。全部六份产物完全一致：工具链 `1.85.0-aarch64-apple-darwin`、Size `3,270,944`、SHA-256 `fb57184babc4d7e6ba3bf2970ca2089ea345b0726c85b337f2c8d9ec4e405cf0`、CodeDirectory CDHash `5ffdb86cb678ac6ab670bccb811a28edbfb12a3e`。临时缺失 Tuple 测量 Hook 已完整删除，然后才把该 Source Snapshot 下唯一的精确产物 Tuple 加入已评审 Allowlist；两轮测量门禁的无签名 Simulator Fixture 也都通过。随后正常非测量门禁重新构建并接受 Allowlist Helper，无签名 Simulator Fixture 也通过。Format、锁定依赖且拒绝警告的 Clippy、全部 278 项 Workspace 测试、Ruby 语法、Diff 检查和明确的无测量 Hook 检查也均通过。4B PR 前只剩一次新的干净 Codex CR。

该次全新完整 Diff CR 又发现一个 P2 失败结果保留缺口：Host 关闭只识别全 Go Tuple 与当前
Observer 的精确签名未检查 Tuple；包含其他失败证据门禁、但结构有效且有设备签名的报告，
会在形成文档要求的方法级 No-Go 前被拒绝。修复增加封闭的通用 `no_go` Disposition，核对
有界 Observer 精确的签名/Outcome/Reason 语义，继续强制授权身份与坐标完整性，并把签名、
保护态、磁盘或映射明文比较失败保留为 No-Go，而不是丢失结果。混合 Role 处置不能被提升成
仅签名未检查的 No-Go。Fastlane 会接受并明确显示 `go`、`no_go_signature_unchecked` 与
`no_go` 三个封闭值。由于这会改变 Rust Helper，4B PR 前还需要两次新的独立可复现测量、
替换唯一 Allowlist Tuple、正常门禁、全部本地门禁和一次新的干净 CR。

后续未提交 CR 又发现该修复仍有一个 P2：已批准独立 Validator 明确给出的
`present` / `cms` / `invalid` 仍不属于两个已接受分支，会被拒绝而不是保留。现在只有这个
精确的已评审 Validator Tuple 会携带所需签名 Reason 关闭为通用 `no_go`；被修改的
Validator 身份、Revision、Outcome 或 Reasons 仍然无效。新增回归把 Invalid Tuple 与已评审
Go、有界 Unchecked、Ad-hoc、Absent、保护态和摘要失败情形一起固定。4B PR 前仍执行同一组
可复现性、Allowlist、正常门禁、本地门禁和干净 CR 要求。

提交该失败结果保留修复后，两次独立完整 Fastlane 门禁各自重新构建三份 Helper；Source
Snapshot 为 `c562abef73db2ef844582793a80883c1ee64b88087c4abd607f1ac72e32fffa1`。
全部六份产物完全一致：工具链 `1.85.0-aarch64-apple-darwin`、Size `3,271,056`、
SHA-256 `6ee4fd9ee2def07fad6dd512337a52d6a3ea30a3bbb9a3890dd743794f297a0f`、
CodeDirectory CDHash `5d6319d37d5bdc0852fbb8631cf7e7179e86ba6f`。临时缺失 Tuple
测量 Hook 已完整删除，然后才把该 Source Snapshot 下唯一的精确产物 Tuple 加入已评审
Allowlist；两轮测量门禁的无签名 Simulator Fixture 也都通过。随后正常非测量门禁重新构建
并接受 Allowlist Helper，无签名 Simulator Fixture 也通过。Format、锁定依赖且拒绝警告的
Clippy、全部 280 项 Workspace 测试、Ruby 语法、Diff 检查和明确的无测量 Hook 检查也均
通过。4B PR 前只剩一次新的干净 Codex CR。

该次全新完整 Diff CR 发现一个 P1 最终化缺口：第二轮结果先于完整双轮 Verifier 发布，
因此不同的规范化观察会先关闭阶段，随后验证失败，却不能保留任何最终 Disposition。修复会在
发布第二轮前先验证完整有序双轮链；结构有效的重复性不一致或不同单轮封闭 Disposition 现在
会成为通用 `no_go`，而重放、顺序、Enrollment、冻结 Oracle 与 Artifact 完整性错误仍会
拒绝发布。该 Rust Helper 变更再次要求两次独立可复现测量、替换唯一 Allowlist Tuple、正常
及本地门禁和一次新的干净 CR，才能打开 4B PR。

提交最终化修复后，两次独立完整 Fastlane 门禁各自重新构建三份 Helper；Source Snapshot
为 `775a15d6c019c39f99d110efb7dcc5bacc470fc0361e7d1061c6fff7468fa729`。
全部六份产物完全一致：工具链 `1.85.0-aarch64-apple-darwin`、Size `3,271,056`、
SHA-256 `203b22526f7664d942b55c5742ed3649a4f829f192211c85f82e08cae95582b6`、
CodeDirectory CDHash `66fc768edadb1f1a9e3b2a134d1fba8fdfe14927`。临时缺失 Tuple
测量 Hook 已完整删除，然后才把该 Source Snapshot 下唯一的精确产物 Tuple 加入已评审
Allowlist；两轮测量门禁的无签名 Simulator Fixture 也都通过。随后正常非测量门禁重新构建
并接受 Allowlist Helper，无签名 Simulator Fixture 也通过。Format、锁定依赖且拒绝警告的
Clippy、全部 281 项 Workspace 测试、Ruby 语法、Diff 检查和明确的无测量 Hook 检查也均
通过。4B PR 前只剩一次新的干净 Codex CR。

随后的合并前 CR 发现一个 P1 Oracle 来源缺口：Operator 会把保留 Archive/IPA 报告的
UUID 与 Oracle 对照，却没有从精确冻结二进制重新推导完整 Oracle Role/Slice Tuple。
修复后会解析并以密码学方式验证刚刚 Hash 的精确 Archive 内存快照和有界 IPA 内存快照中
持有的精确 Entry；验证两套 `Info.plist` 身份、CMS Trust、签名身份与 Entitlements；从
已签名 Manifest 重算每个 Target Binding；并要求完整重推导的 Oracle Role 与保留 Role
结构完全相等。每次加载或重新验证 Source Tuple 都执行同一检查。后续 CR 还要求身份值必须
从已签名报告重算，且 Parser 必须消费与 Hash 相同的内存字节；两个 P2 均已增加负向回归。
第二轮未提交 CR 未发现其他正确性问题。由于这会改变 Rust Helper，合并前仍需两次新的独立
可复现性测量、替换唯一 Allowlist Tuple、正常门禁、全部本地门禁和一次最终干净 CR。
4B 尚未合并期间，真机保持不操作。

提交该 Oracle 来源修复后，两次独立完整 Fastlane 门禁各自重新构建三份 Helper；Source
Snapshot 为 `690aa31e3d0da4d562b974b8e368fbb13c44c37c59a045e2a304c4ed8b7e25ec`。
全部六份产物完全一致：工具链 `1.85.0-aarch64-apple-darwin`、Size `3,283,408`、
SHA-256 `ba8bb79ac2f3bbf7ad3120b79f27e17c285aabcb3e784a5a1f2db818bce70246`、
CodeDirectory CDHash `25138be1efb9132acaa555d4bf561ce52b0ff8ea`。临时缺失 Tuple
测量 Hook 已完整删除，然后才把该 Source Snapshot 下唯一的精确产物 Tuple 加入已评审
Allowlist；两轮测量门禁的无签名 Simulator Fixture 也都通过。随后正常非测量门禁重新构建
并接受 Allowlist Helper，无签名 Simulator Fixture 也通过。
Format、锁定依赖且拒绝警告的 Clippy、全部 281 项 Workspace 测试、Ruby 语法、Diff 检查和
明确的无测量 Hook 检查也均通过。合并前只剩一次最终干净 CR；真机保持不操作。

该次最终完整 Diff CR 发现一个 P1 生命周期状态缺口：Enrollment 可以在复用的非空输出根
下再次发布随机命名的实验目录，使放弃或失败的实验被绕过而非按约束保留。修复后会在读取
请求之前，要求持有 Descriptor 的输出根具有精确空清单；使用唯一固定实验槽，并在原子
No-replace Rename 的前后分别核对只含 Staging/Final 的精确单项清单。回归测试固定拒绝
含保留实验子目录的根，并在发布边界出现其他子项时回滚。由于这会改变 Rust Helper，合并前仍需两次新的独立可复现性
测量、替换唯一 Allowlist Tuple、正常门禁、全部本地门禁和另一轮最终干净 CR。真机保持
不操作。

提交生命周期修复后，两次独立完整 Fastlane 门禁各自重新构建三份 Helper；Source
Snapshot 为 `87ae31a61d40199e20d3d9e50644660dbd6ebe6fe1ada9d0469e3d3174d27858`。
全部六份产物完全一致：工具链 `1.85.0-aarch64-apple-darwin`、Size `3,284,016`、
SHA-256 `c6050562a0e036bda25fb36e7e51a9e90b3a7df01202de2e30402261a77bde91`、
CodeDirectory CDHash `8b5f62771adf5fe02828201e41f13a90459e0f7f`。临时缺失 Tuple
测量 Hook 已完整删除，然后才把该 Source Snapshot 下唯一的精确产物 Tuple 加入已评审
Allowlist；两轮测量门禁的无签名 Simulator Fixture 也都通过。之后的正常非测量门禁已重新
构建并接纳该精确 Tuple，格式化、Clippy、Ruby 语法、Diff Hygiene、Fixture 与全部 283 项
本地测试均通过。Push 与合并前仅剩一次最终干净 CR；真机保持不操作。

该次完整 Diff CR 发现一个 P2 重试生命周期兼容缺口：一次有效的上传不确定结果对账会按
设计在下一份 Active 上传结果旁保留最多 32 份审计记录，但 Operator Source Loader 只允许
五个当前 Candidate 项。修复后仅接受既有封闭的对账文件名格式与数量上限，按封闭 Schema
解析每份保留记录，将其绑定到同一 Source Commit 与 IPA Digest，并验证时间戳、Destination、
Status、Note 和操作员对账决定；最终 Source 复核还会按身份重新打开每份记录。未知、畸形、
权限放宽、Tuple 不匹配、新增、删除或替换的记录仍会 Fail Closed。回归测试覆盖有效保留历史
流程、无效名称和错误 Tuple。由于这会改变 Rust Helper，Push 与合并前仍需两次新的独立可
复现测量、替换唯一 Allowlist Tuple、正常与完整本地门禁，以及另一轮最终干净 CR。真机保持
不操作。

提交对账历史兼容修复后，两次独立完整 Fastlane 门禁各自重新构建三份 Helper；Source
Snapshot 为 `8e94e44623985498c5b2f5873e1036bfc0979bca8fa3e3e326a0e659bec686fc`。
全部六份产物完全一致：工具链 `1.85.0-aarch64-apple-darwin`、Size `3,302,528`、
SHA-256 `c87b63b0d00cd46569215f8ed0064b10973a18012931be6101c425654a6bf1e5`、
CodeDirectory CDHash `31d712a0fa9ffa844603185d423e12b10157a7c8`。临时缺失 Tuple
测量 Hook 已完整删除，然后才把该 Source Snapshot 下唯一的精确产物 Tuple 加入已评审
Allowlist；两轮测量门禁的无签名 Simulator Fixture 均通过。随后正常非测量门禁重新构建并
接纳该精确 Helper，Fixture 也通过。Format、锁定依赖且拒绝警告的 Clippy、全部 284 项
Workspace 测试、Ruby 语法、Diff Hygiene 与明确的无测量 Hook 检查也均通过。Push 与合并
现在只剩一次最终的完整 Diff 干净 CR；真机保持不操作。

该次完整 Diff CR 又发现三个 P2 生命周期边界：冻结 Prebuild/Candidate Tuple 发生变化后，
Enrollment Close 仍可能发布闭合结果；保留的上传对账记录没有强制因果时间顺序；
Enrollment Result 及 Run Control/Result 发布使用通用 Publisher，Rename 边界没有阶段级精确
清单保护。修复后 Enrollment Close 会接收并持有 Prebuild/Candidate Descriptor，在闭合和
发布前完整复核 Source；对账时间必须满足
`attempt_started_at <= reconciled_at <=` 当前 Active 上传尝试时间；所有 Operator 阶段统一
通过感知既有阶段的 Rename 前后清单 Guard。回归覆盖两个方向的不可能时间顺序，以及
Staging 创建后、Rename 前由同一用户注入意外同级项的情形。由于 Rust Helper 再次变化，
Push 与合并前仍需两次新的独立可复现测量、替换唯一 Allowlist Tuple、正常与完整本地门禁，
以及一轮新的最终干净 CR。真机保持不操作。

后续未提交 CR 又发现一个剩余 P2 竞态：Enrollment Close 的最后一次 Source 检查仍早于
Publisher 等待确认的窗口。现在每个 Operator Control/Result 发布都会在 Rename 边界 Guard
的前后内部重新检查 Source；等待期间发生变化会回滚发布。可复现测量与最终门禁要求保持
不变；真机继续不操作。

第二轮后续未提交 CR 发现，Operator Loader 已强制执行对账因果时间顺序，但更早的上传门禁
和 Fastlane 记录校验仍会接受 `reconciled_at < attempt_started_at`。两处现在都会强制执行
可独立判断的时间下界；Operator Source Loader 还会针对后续 Active Retry 强制执行时间上界。
Rust 与 Fastlane 回归覆盖倒置时间线。可复现测量与最终门禁要求保持不变；真机继续不操作。

下一轮未提交 CR 又发现两个 P2 错误路径缺陷：Host 时钟回拨时，对账可能先发布终态记录，
然后才拒绝其时间顺序；关闭 Enrollment 也只在三个目录全部打开后才统一登记 Handle。现在会在
原子替换之前先验证待发布的终态记录，且回归证明拒绝后 Live Indeterminate 记录保持逐字节
不变；Enrollment Close 会在每次成功打开后立即登记 Handle，确保任意早期失败都关闭此前的
Descriptor。可复现测量与最终门禁要求保持不变；真机继续不操作。

随后的未提交 CR 又发现一个 P2 顺序竞态：同一用户可在 Source Guard 重新打开冻结 Tuple
期间插入意外阶段同级项，而该窗口位于边界唯一一次清单扫描之后。现在每个边界（包括
Enrollment Start）都会用两次清单检查夹住 Source 复核；回归从 Source Guard 内注入同级项，
确认发布回滚并删除自身 Staging。可复现测量与最终门禁仍然必需；真机继续不操作。

下一轮未提交 CR 发现一个 P2 Source 发布边界缺口：只在验证点重新打开冻结 Source，仍可能
漏掉第二个受控 Lane 在首个 Helper 调用期间进行的瞬时修改并恢复。现在 Fastlane 会按确定性
Device/Inode 顺序，为每个绑定目录获取非阻塞排他锁，并在完整 Helper 生命周期内持有全部锁。
共享任一冻结 Source 的冲突工作流会被拒绝；回归还证明多锁获取中途失败时，会先释放此前已
获取的锁，然后才允许重试。可复现测量与最终门禁仍然必需；真机继续不操作。

后续 CR 发现一个 P2 互操作缺口：Operator 锁可以排除其他 Operator 调用，但上传 Lane 在
最后门禁结束后、创建或替换上传结果记录前就释放了 Candidate 锁；对账也只持有结果文件锁。
现在最后一次上传门禁会在完整 Apple 请求和终态结果持久发布期间，持续持有 Output、Prebuild
与 Candidate 锁；对账会在原子替换和归档期间持续持有同一个 Candidate 目录锁。新增回归证明
既有受控 Writer 锁与新的 Operator Source 锁会相互排斥。可复现测量与最终门禁仍然必需；
真机继续不操作。

提交完整的 Operator 发布边界修复后，两次独立完整 Fastlane 门禁各自重新构建三份 Helper；
Source Snapshot 为
`e44ca6351bb9a9c69a0b5489e09faac97f90309dc5e2a0b9f90eae8cf3b93a21`。
全部六份产物完全一致：工具链 `1.85.0-aarch64-apple-darwin`、Size `3,303,744`、
SHA-256 `11c78291e0d733c7355b8411c28376ef08ec129e43685bc7a9eb5db946f38951`、
CodeDirectory CDHash `62aa4cabf5507bee36567b03d4766b8fa12e8c70`。随后已完整删除临时
缺失 Tuple 测量 Hook，并在精确的唯一产物 Tuple 加入已评审 Source Snapshot Allowlist 前，
通过明确的无 Hook 搜索；两轮测量门禁的无签名 Simulator Fixture 均通过。随后正常非测量
门禁重新构建并接纳该精确 Helper，Fixture 也通过。Format、锁定依赖且拒绝警告的 Clippy、
全部 287 项 Workspace 测试、Ruby 语法、Diff Hygiene 与明确的无测量 Hook 检查也均通过。
Push 与合并前仅剩 Allowlist 提交和最终完整 Diff CR；真机继续不操作。

该次最终完整 Diff CR 发现一个 P1 生命周期身份缺口：后续 Lane 会接受任何包含结构有效阶段
副本的 Owner-only 实验目录，因此复制目录可以被关闭，而最初固定生命周期仍保持打开。现在
Enrollment 发布会在原子 Rename 前，于同一个 Staging 目录中生成规范绑定，记录所持有输出根、
新实验目录的 Device/Inode 身份及 Enrollment Experiment ID，并由冻结 Host 授权密钥签名。
后续每个操作都会用独立重新打开的冻结 Source 验证该签名，要求固定子目录名，并在入口以及
每次发布边界的前后，重新核对持久化 Parent、所持有 Experiment 与当前路径身份。后续未提交
CR 拒绝了最初未签名的 Binding；回归现在证明原始目录可接受，而位于另一个 Parent 下的未改
副本和由 Owner 重写 Binding 的副本都会被拒绝。签名修复后的第二轮未提交 CR 未发现 Diff
范围内的正确性问题；全部 55 项 Helper 测试、锁定依赖且拒绝警告的 Clippy、Format、Ruby
语法和 Diff Hygiene 均通过。由于 Rust Helper 再次变化，Push 与合并前仍需两次新的独立
可复现性测量、替换唯一 Allowlist Tuple、正常及完整本地门禁，以及一轮新的最终干净 CR。
真机继续不操作。

随后已在本地提交通过认证的生命周期修复。第一次测量尝试证明临时缺失 Tuple 门禁范围过宽：
Fastlane 故意替换 SHA 的回归测试触发该入口，因此该次在构建当前 Helper 前失败，不计入测量。
入口收紧为仅允许尚无任何 Allowlist 项的 Source 后，两次独立完整 Fastlane 门禁分别重新构建
三份 Helper；Source Snapshot 为
`29bcf258ce3bb2a8ada0798ae65b6de1adaeed7c1c4c9cc97be38194eb645f67`。
全部六份产物完全一致：工具链 `1.85.0-aarch64-apple-darwin`、Size `3,360,384`、
SHA-256 `3d9a39ad38ace5856c662120d867491cf53d81aa57bdf437a498ca3d6f1241fb`、
CodeDirectory CDHash `95a4b27a75f08ac1337174dddac460aeb17ae028`；两轮无签名 Simulator
Fixture 均通过。临时门禁随后被完整删除，并在此精确唯一产物 Tuple 加入已评审 Source
Snapshot Allowlist 前通过明确的无 Hook 搜索。随后正常非测量门禁重新构建并接纳该精确
Helper，无签名 Simulator Fixture 通过。Format、锁定依赖且拒绝警告的全 Workspace Clippy、
全部 288 项 Workspace 测试、Ruby 语法、Diff Hygiene 及明确的无测量 Hook 搜索也均通过。
Push 与合并前仅剩 Allowlist 提交和一轮干净的最终完整 Diff CR。真机继续不操作。

该次最终完整 Diff CR 发现一个 P1 兼容性回归：把通用上传操作移入 LAB-002 Source Lock Block
后，合法的既有 DemoLab Evidence 会走非 Checkpoint 提前返回但不执行 Block，Lane 因而可能在
没有上传、也没有记录结果的情况下结束。现在该绕过路径会明确执行通用上传 Block，保留既有
行为；Checkpoint `1.0 (3)` 仍会在上传和终态结果发布期间持续持有三个 Source Lock。新增
Fastlane 回归要求非 Checkpoint Evidence 必须执行该 Block。此修复只改变 Fastlane 控制流，
已测量的 Rust Source Snapshot 与 Helper Tuple 不变。修复后的完整 Fastlane Gate、全部 288 项
Workspace 测试、锁定依赖且拒绝警告的全 Target Clippy、Rust Format、Ruby 语法、Diff Hygiene
及明确的无测量 Hook 搜索均通过。Push 与合并前仅剩修复提交和一轮新的干净最终 CR；真机继续
不操作。

下一轮完整 Diff CR 发现一个 P2 容器表示绑定缺口：冻结 Oracle 虽保留完整 Slice Tuple，
却没有保留来源 Mach-O 容器类型，因此 Host 只能推断 Thin 或多 Slice，可能把 `fat32`
证据接受为冻结 `fat64` 可执行文件，反之亦然。现在每个 Oracle Role 都会保留由彼此匹配的
冻结 Archive/IPA Report 派生出的精确 `thin`、`fat32` 或 `fat64` 类型，Host 关闭时会
精确比较该值。Schema 负向测试拒绝缺失或未知类型，Generator 回归把类型绑定到冻结
二进制，Host 回归则拒绝其他字段完全相同的多 Slice FAT 类型替换。由于这会改变 Rust
Helper，Push 与合并前必须重新完成两次独立完整可复现性测量、替换唯一 Allowlist Tuple、
正常及完整本地门禁，以及一轮新的最终干净 CR。真机继续不操作。

提交精确容器类型修复后，两次独立完整 Fastlane 门禁分别从 Source Snapshot
`5b17f8c1f0487364c896f9fe5e7d99ad9d0a78792644f6da1a5846c3b68d5fb6` 重新构建三份
Helper。全部六份产物完全一致：工具链 `1.85.0-aarch64-apple-darwin`、Size
`3,361,856`、SHA-256
`6839cda7e73f0877998efdf59783bba849fc85772e14318d8c977d5097484986`、CodeDirectory
CDHash `b1554d431c643b3232161e90abd500058012e0b7`；两轮无签名 Simulator Fixture
均通过。临时 Hook 仅在 Source Snapshot 完全没有既有 Allowlist 项时生效，因此已有 Source
的替换产物回归仍会失败关闭。随后已完整删除该 Hook，并在明确的无 Hook 搜索通过后，将这个
精确唯一产物 Tuple 加入已评审 Source Snapshot Allowlist。正常非测量门禁重新构建并接纳
Allowlist 中的 Helper，无签名 Simulator Fixture 通过。Rust Format、锁定依赖且拒绝警告的
全 Target Workspace Clippy、全部 288 项 Workspace 测试、
Ruby 语法、Diff Hygiene 及明确的无测量 Hook 搜索也均通过。Push 与合并前仅剩 Allowlist
提交，以及一轮新的最终干净完整 Diff CR。真机继续不操作。

随后该轮干净完整 Diff CR 发现一个 P2 发布内容竞态：Operator 阶段 Guard 虽关闭了目录清单
和冻结 Source，却没有在 Rename 前后立即重新绑定各 Staging 文件，因此同一 Owner 进程仍可能
在相同文件名下替换已验证字节。现在 Publisher 会记录每个新建 Artifact 的 Device/Inode 身份，
并在两个发布边界分别对精确文件名集合执行两轮有界复核；每轮都要求原始身份、Owner、`0400`
权限、长度和完整字节一致。目录枚举一旦超过固定预期数量就立即拒绝。确定性回归覆盖 Staging
改写、Rename 后改写、两轮之间同名替换，以及超过上限的目录清单。两轮后续未提交 CR 先发现
缺失的第二轮复核与上限，修复后未再发现 Diff 范围内的正确性问题。全部 59 项 Helper 测试、
锁定依赖且拒绝警告的 Helper Clippy、Rust Format 与 Diff Hygiene 均通过。由于 Rust Helper
再次变化，Push 与合并前仍需两次独立完整可复现性测量、替换唯一 Allowlist Tuple、正常及完整
本地门禁，以及一轮新的最终干净 CR。真机继续不操作。

发布修复后的第一次测量尝试虽产生两份完全一致的候选 Helper 身份，但完整门禁在 Simulator
Fixture 前停止，因此不计入测量。当前所选 Xcode 26.6 工具链报告 iPhoneOS SDK Build
`23F81a`；Artifact Schema 与 Artifact Validator 已允许 Apple 使用大写 Train 字母及
字母数字后缀，但独立实现的 Build Binding Validator 错误拒绝了全部小写后缀。现在 Binding
与 Device Environment Validator 统一采用关闭的 Schema 语法：数字前缀、一个大写 Train
字母及非空字母数字后缀。回归接受真实 SDK 拼写，同时继续拒绝小写 Train 字母。Core、Schema、
Fixture 与 Helper 测试、锁定依赖且拒绝警告的全 Target Workspace Clippy、Rust Format 与
Diff Hygiene 均通过。该 Rust 变化需要新的提交，并使两次独立可复现性测量从零重新开始。
真机继续不操作。

提交 Apple Build 语法修复后，两次独立完整 Fastlane 门禁分别从 Source Snapshot
`ba0cff84503f0ae35344420c3efdc60df6992fbf08336315d6948079a6457438` 重新构建三份
Helper。全部六份产物完全一致：工具链 `1.85.0-aarch64-apple-darwin`、Size
`3,381,712`、SHA-256
`e3c354cf9e4a15de0afd7a886802d09066d3c6c7496096f3379a0cb8279f1047`、CodeDirectory
CDHash `b114a781ed4799057138f237f8d334bf04aecbd7`；两轮无签名 Simulator Fixture
均通过。随后已完整删除临时缺失 Source 测量 Hook，并在明确的无 Hook 搜索通过后，才把这个
精确唯一产物 Tuple 加入已评审 Source Snapshot Allowlist。正常非测量门禁重新构建并接纳
Allowlist 中的 Helper，无签名 Simulator Fixture 通过。完整本地门禁也均通过：Rust Format、
锁定依赖且拒绝警告的全 Target Workspace Clippy、全部 292 项 Workspace 测试、Ruby 语法、
Diff Hygiene 及明确的无测量 Hook 搜索。Push 与合并前仍需 Allowlist/进度提交及一轮新的
干净完整 Diff CR。真机继续不操作。

最终完整 Diff Codex CR 已针对未变化的已评审 `origin/main` 完成，未发现可执行的正确性问题；
其聚焦测试、Clippy、Ruby 语法及 Diff 校验均通过，独立执行的正常本地门禁仍保持全部 292 项
Workspace 测试通过。检查点 4B 现在可以依次执行 SSH Push、远端 PR/CI 检查、合并前 CR 与
合并。真机继续不操作。

远端评审在合并前又发现一个 P2 跨时钟顺序问题。只要仍在授权窗口内，iPhone 签名的 Receipt
或已完成 Session 可以在有界时钟容差内领先 Mac 观测时间；Host 先前会把 Mac 的 `now()`
直接写入 Selection/Binding，导致完整验证器可能因为 Host 关闭时间早于手机签名事件而拒绝
合法链。现在两条关闭路径都会使用 Host 观测时间与已验证手机签名事件时间中的较晚值。既有
完整链验证器仍继续约束签名授权截止时间，因此该修复只恢复因果顺序，不会扩大任何授权窗口。
确定性回归覆盖 iPhone 事件领先 120 秒，并证明较晚的 Host 观测时间不会被向前回拨。

由于该修复改变 Rust Helper，两次独立完整 Fastlane 门禁分别从 Source Snapshot
`35af1682b7d2b7a98769ed64e5c4aa4bc7f227d60b5a7d4f2a2a745871a63d22` 重建三份产物。
全部六份产物完全一致：工具链 `1.85.0-aarch64-apple-darwin`、Size `3,381,696`、
SHA-256 `127f2821f48835dfd74aea409043dc0cb6abcd366d9fb29d3968e485438cecfc`、
CodeDirectory CDHash `9eee8288d796fa943a6e308f8d98268e846ecea8`；两轮无签名 Simulator Fixture
均通过。临时缺失 Source 测量 Hook 已在该精确唯一产物 Tuple 加入已评审 Source Snapshot
Allowlist 前完整删除，明确的无 Hook 搜索通过。正常非测量门禁重新构建并只接纳 Allowlist
中的 Helper，Fixture 通过。完整本地门禁也通过：Rust Format、锁定依赖且拒绝警告的全 Target
Workspace Clippy、全部 294 项 Workspace 测试、Ruby 语法、Diff Hygiene 及无 Hook 搜索。
后续仍严格依次执行 Allowlist/进度提交、干净完整 Diff Codex CR、SSH Push、远端 CI 与评审
检查、合并前 CR 及合并。真机继续不操作。

随后，针对未变化 `origin/main`
`9bb4ee86b051e7794fb2d63c57bc1cdd31b9cde4` 的必要完整 Diff Codex CR 已结束，未发现
可执行的正确性问题；其独立复跑的 Core 与 Operator 测试均通过。Workspace 复跑中唯一失败
是评审沙箱在进入 CLI 测试断言前禁止创建 Unix Socket；上述正常本地门禁中同一测试及全部
294 项 Workspace 测试均通过。剩余顺序现在是 SSH Push、关闭远端评审会话与 CI、重新执行
合并前 Codex CR，然后合并。真机继续不操作。

随后 PR #74 的三项远端 CI 全部通过，两个评审线程均已关闭，并以
`4c021cb1f6a01f26f904ce90769c88fbaf54a1f0` Squash Merge 进入 `main`。最终合并前
CR 曾提出把上传前与安装后 SuperBlob 摘要强制相等；单独的只读裁决认定该建议不成立：Apple
会重签名 TestFlight 工件，冻结设计因此有意绑定安装后的 Target Identity、UUID、Slice/区间
元组、签名状态和两轮安装后摘要稳定性。加入所建议的相等检查反而会拒绝合法首方 TestFlight
安装。因此 4B 无需 Production 改动即可完成。期间没有发生安装、Enrollment 或观察；4C
仍必须等紧邻操作前的新 RFC-0001 确认及一次性安装信封。

2026-08-03，操作员针对精确自有 `Jack iPhone` 与首方 DemoLab `1.0 (3)` Tuple 提供了
4C 所需的新确认。Host 把所选环境锁定为 `iPhone15,2`、iOS `26.6` Build `23G5065a`，
并验证了冻结 Candidate/Prebuild 的结构。第一次
`demolab_operator_start_enrollment` 调用随后在任何发布前失败关闭：Helper 在输出暂存目录
身份前退出，导致确认管道关闭，而 Fastlane 抛出未处理的 `Errno::EPIPE`，遮蔽了 Helper
的有界 Stderr。新的 Owner-only 输出根保持为空；没有创建信封、实验、TestFlight 安装、
App 导入、Enrollment Key、Receipt 或设备观察。该根作为失败证据保留。修复继续保持失败
关闭，记录单字节确认是否成功送达，在 `EPIPE` 后继续有界收集 Stdout/Stderr，并优先报告
Helper 失败，再报告次级管道诊断；回归同时覆盖正常送达与 Reader 提前关闭。原确认只绑定
失败的即时尝试，因此本修复通过 CR、CI、PR 并合并后，4C 必须重新取得一份新确认；不得从
未评审源码重试失败操作。

该修复的本地门禁已通过：Ruby 语法与 Diff Hygiene、Rust Format、锁定依赖且拒绝警告的
全 Target Clippy、全部 294 项 Workspace 测试，以及包含两种确认管道回归和无签名
Simulator Fixture 的完整无设备 `demolab_check`。Push 前与全新合并前 Codex CR 均未发现
可执行的正确性问题，三项远端 CI 全部通过，且没有遗留评审评论或线程。PR #76 随后以
`1d617d63fabd576765b28a8ba88fb02e117ecf5a` Squash Merge 进入 `main`。修复期间没有操作手机，
也没有发生 TestFlight 安装、App 导入、Enrollment 或观察。4C 唯一开放的下一门禁，是在创建
新的 Owner-only 输出根与安装信封前紧邻地重新取得一份全新 RFC-0001 确认。

2026-08-03 取得上述新确认后，Host 再次锁定相同的授权设备环境并重新验证精确冻结的
Prebuild/Candidate 结构。它创建了另一个完全独立且为空的 Owner-only 输出根，并从已合并
`main` 调用 `demolab_operator_start_enrollment`。管道修复按预期工作，暴露了有界 Helper
真实错误：冻结 Oracle 无法按当前 v1 类型解码。该尝试在发布前失败关闭，新根仍为空并作为
失败证据保留；没有发生手机操作、TestFlight 安装、App 导入、Enrollment Key、Receipt 或观察。

只读诊断没有发现工件变更。Oracle SHA-256 与检查点 3 台账中的
`326d7a3260600f13dd65c518fdbeafebbfb119deb31dced15eb4745ced5f9472` 完全一致，是没有重复键或
尾随字节的精确规范 JSON，并包含冻结的三个 Role/Slice Tuple。它生成于 PR #74 把每个 v1
Oracle Role 的 `container_kind` 设为必需字段之前；三份冻结 Archive 可执行文件均独立识别为
Thin arm64 Mach-O。修复因此继续严格解码当前 Oracle，只允许上述完整公开 Digest 的历史字节
进入兼容路径，仅在内存类型投影中补入 `container_kind = thin`，并且在任何发布前仍要求操作
Helper 从冻结 Archive 与 IPA 重新派生相同的完整 Role/Slice/Container Tuple。Digest 不同、
文档不规范、二进制不是 Thin 或任一 Tuple 变化都会继续失败关闭。回归验证当前严格解码、
Production Pin 拒绝任意历史文档、只有精确 Digest 才能正向适配，以及一字节变化后拒绝。
由于 Rust Helper 改变，必须先完成两轮独立完整可复现测量、替换其唯一 Allowlist Tuple，并依次
通过正常本地/CI/CR/PR 与合并门禁，之后才能再次请求新的全新确认。

随后两次独立完整 Fastlane 门禁分别从 Source Snapshot
`8718d9b88e496d4944e2c25a0186c9cd426f7aa3cdc7f69fa5555d7dd6d4c101` 重建三份产物。
全部六份产物完全一致：工具链 `1.85.0-aarch64-apple-darwin`、Size `3,382,320`、
SHA-256 `1b6b26a3d5a743c20d6836700b5ac42ff6d09262f0eae20b5ba4fda6252bf944`、
CodeDirectory CDHash `265eae5cecd0812c582c09b84211722d83bae6e4`；两轮无签名 Simulator Fixture
均通过。临时缺失 Source 测量 Hook 已在该精确唯一产物 Tuple 加入已评审 Source Snapshot
Allowlist 前完整删除，明确的无 Hook 搜索通过。正常非测量门禁重新构建并仅接纳 Allowlist
中的 Helper，无签名 Simulator Fixture 通过。完整本地门禁也均通过：Rust Format、锁定依赖
且拒绝警告的全 Target Workspace Clippy、全部 295 项 Workspace 测试、Ruby 语法、Diff
Hygiene 及无 Hook 搜索。下一项依次执行的门禁是 Allowlist/进度提交与完整 Diff Codex CR；
真机继续不操作。

该轮完整 Diff Codex CR 找到一个 P2 有界输入回归：严格解码拒绝超限 Oracle 后，兼容分支会在
有界解码器运行前先 Hash 整段输入。兼容分支现在会在计算兼容 Digest 前先拒绝超过 Oracle
固定 16-KiB 上限的字节；回归覆盖一份超限且所提供 Digest 原本匹配的输入。该 Rust Helper
变化使上一组产物测量不再适用于新的 Source Snapshot；必须从零重新完成两轮独立完整可复现
测量、新的唯一 Allowlist Tuple、正常及完整本地门禁和一轮新的干净完整 Diff CR。真机继续
不操作。

提交该上限修复后，两次全新独立完整 Fastlane 门禁分别从 Source Snapshot
`1c57b49686812fa59d7e4e76dd6b343150329153c565ff3ad6d99b05a2cf6706` 重建三份产物。
全部六份产物完全一致：工具链 `1.85.0-aarch64-apple-darwin`、Size `3,382,320`、
SHA-256 `9f6836b922b4b71961a59acf01d8701632f0b3ff8c971fe7be54d1d289c61d26`、
CodeDirectory CDHash `c447cb4b4f1e597f1f5ffc47fa4cac93753f9119`；两轮无签名 Simulator
Fixture 均通过。临时缺失 Source 测量 Hook 已在该精确唯一产物 Tuple 加入已评审 Source
Snapshot Allowlist 前完整删除，明确的无 Hook 搜索通过。正常非测量门禁重新构建并仅接纳
Allowlist 中的 Helper，无签名 Simulator Fixture 通过。完整本地门禁也均通过：Rust Format、
锁定依赖且拒绝警告的全 Target Workspace Clippy、全部 295 项 Workspace 测试、Ruby 语法、
Diff Hygiene 及无 Hook 搜索。下一项依次执行 Allowlist/进度提交和一轮新的干净完整 Diff
Codex CR；真机继续不操作。

新的完整 Diff Codex CR 已沿全部冻结 Host/Operator 调用方追踪有界且完整 Digest 固定的适配
路径，未发现可执行缺陷或 P1/P2。评审隔离环境运行 Workspace 测试时因系统策略拒绝创建 CLI
Unix Socket Fixture；相同测试及全部 295 项 Workspace 测试此前已在正常本地门禁通过。
Core 与 LAB-002 Tool 测试、锁定依赖且拒绝警告的全 Target Clippy、Rust Format、Ruby
语法、Diff Hygiene 和无 Hook 搜索均通过。下一项依次关闭 PR #78 的远端 CI/评审、在精确
Head 上重新运行合并前 Codex CR，然后合并。只有合并后 Host 才能请求新的全新 4C 确认；
失败尝试的旧确认不得复用，真机继续不操作。

PR #78 随后三项必需远端 CI 全部通过，没有评审线程或评论。精确 Head
`5830371288decd1c906c86aec8baee357b89f604` 上的全新合并前 Codex CR 追踪了完整兼容路径，
复现 Source Snapshot 选择，并重新运行聚焦 Core/Tool 测试、Clippy、Format、Ruby 语法及
Diff Hygiene，未发现可执行缺陷或 P1/P2。完整 Workspace 重跑唯一失败仍是评审沙箱在 CLI
断言前禁止创建 Unix Socket；相同测试已在正常本地及远端门禁通过。PR #78 随后以
`867c8983b9ea603a7bca2bbbd5f772923626b394` Squash Merge 进入 `main`。期间没有发生手机操作、
TestFlight 安装、App 导入、Enrollment 或观察。失败尝试的旧确认保持已消费；4C 下一项且
唯一开放门禁，是在创建新的 Owner-only 输出根和一次性安装信封前紧邻地取得另一份全新
RFC-0001 确认。
