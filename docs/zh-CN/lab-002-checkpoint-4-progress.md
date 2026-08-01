# LAB-002 检查点 4 进度台账

[English](../research/lab-002-checkpoint-4-progress.md)

跟踪 Issue：[#55](https://github.com/jacklv-coder/OrchardProbe/issues/55)

激活 PR 进入 `main` 后的状态：**检查点 4 active；4A 完成**

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
四项必需断言、精确设备/环境和闭合的操作、数据、保留范围。在对应的一次性签名信封
存在之前，不得开始安装或观察。

## 检查点 4 顺序计划

| 顺序 | 步骤 | 状态 | 完成门禁 |
|---:|---|---|---|
| 4A | 激活并关闭提前上传/对账治理偏差 | `激活 PR 进入 main 时完成` | 本台账与双语执行计划合并明确的不合规记录。Apple 已列出精确 DemoLab `1.0 (3)`，处理完成并进入现有内部组；不可变 Build 不重试，且没有创建外部测试或审核状态 |
| 4B | 闭合 Host 操作流程 | `planned` | 一个已评审、仅 Owner 可读写的 Host 命令创建并保留安装确认/信封，随后接收、保留并验证设备创建的签名 Receipt，再创建选择确认/Enrollment Binding。每轮由 Host 创建并保留确认/Challenge/Intent，接收并保留设备创建的签名 Export，创建 Binding，并验证最终两轮链。安装前必须通过无设备测试、Codex CR、CI、PR 与合并 |
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
设备 UI 与合成测试；但仓库尚未提供一个已评审的操作员命令，用于构造并持久保留真实操作
所需的完整 Host 工件集合。手写 JSON、借用测试 Fixture，或先安装再补记录都会违反冻结
方法。因此步骤 4B 必须在精确 TestFlight 安装前关闭这个操作缺口。
