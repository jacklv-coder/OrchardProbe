# LAB-002 检查点 4 进度台账

[English](../research/lab-002-checkpoint-4-progress.md)

跟踪 Issue：[#55](https://github.com/jacklv-coder/OrchardProbe/issues/55)

激活 PR：[#73](https://github.com/jacklv-coder/OrchardProbe/pull/73)

当前分支状态：**检查点 4 active；4A 完成；4B 实现正在进行 Codex CR 修复**

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
| 4A | 激活并关闭提前上传/对账治理偏差 | `激活 PR 进入 main 时完成` | 本台账与双语执行计划合并明确的不合规记录。Apple 已列出精确 DemoLab `1.0 (3)`，处理完成并进入现有内部组；不可变 Build 不重试，且没有创建外部测试或审核状态 |
| 4B | 闭合 Host 操作流程 | `实现 PR 进入 main 时完成` | 五个已评审 Fastlane 入口创建并原子保留安装/运行控制阶段，只接受有界且由设备创建的 Receipt/Export，要求每次明确确认、全部四项 RFC-0001 范围断言和完整 64 位十六进制 Fingerprint，派生仅 Host 的 Binding，并再次执行完整 Enrollment/Run/两轮验证。每次操作都会重新解析完整闭合的上传前 Evidence、重新 Hash 精确三个冻结 Archive 可执行文件，并依据原始 Prebuild/Candidate 元组重新验证保留的 Source；关闭时逐 Role/Slice 对照冻结 Oracle，最终链还要求两轮规范化观察完全一致。固定 Owner-only 目录均通过已持有描述符传入；命令不安装、不启动、不上传、不访问 App Group，也不选择 Target。安装前必须通过无设备测试、Codex CR、CI、PR 与合并 |
| 4C | 精确安装与 Enrollment | `blocked on 4B` | 记录全新安装确认并签署一次性信封；在 OrchardProbe 之外独立 Provision 所选自有 iPhone 上唯一的 TestFlight `1.0 (3)`；导入信封，导出并验证设备签名 Receipt，对比全部 64 个 Fingerprint 十六进制字符，并在签名时间窗内关闭 Enrollment Binding |
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
