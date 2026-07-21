# OrchardProbe 串行执行计划

[English source](../../EXECUTION_PLAN.md)

本文档是 OrchardProbe 存放在仓库中的权威执行台账。`PROJECT_PLAN.md` 说明产品
方向和版本里程碑；本文档决定实现工作可以按什么顺序启动。

只有 `main` 分支上的版本具有约束力。Feature Branch 上写入的状态，必须等对应
Pull Request 合并后才生效。英文版是字段和顺序的规范来源；中文版必须在同一个
PR 中同步更新。

## 串行门禁

项目刻意一次只推进一个台账步骤：

1. 为 `planned` 步骤建立 GitHub Issue，明确范围、依赖、安全限制、测试、文档和
   验收标准。
2. 先用一个只改计划文档的“激活 PR”，把唯一一个步骤从 `planned` 改为
   `active`，并记录 Issue 和激活 PR。该 PR 必须完成正常审查和合并门禁，实现
   才能开始。
3. 只要存在 `active` 或 `blocked` 步骤，就不得启动更后的台账步骤。
4. 实现 PR 把当前步骤从 `active` 改为 `done`，链接实现 PR，并同步受影响的技术
   文档和用户文档。由于只有 `main` 有效，`done` 只有在实现 PR 合并后才生效。
5. 当前步骤通过下方全部完成门禁、本地 `main` 与 `origin/main` 同步后，才能激活
   下一步。

`GOV-001` 是唯一例外：建立它的 Issue 和 PR 时台账尚不存在，所以无法先提交激活
PR。后续步骤不得复用这个例外。

## 状态定义

| 状态 | 含义 |
|---|---|
| `planned` | 已排序的未来工作，实现尚未开始。 |
| `active` | 当前唯一允许接受实现改动的步骤。 |
| `blocked` | 因已记录的外部依赖或 No-Go 条件停止；不得静默跳过并推进后续步骤。 |
| `done` | 对应实现 PR 已合并到 `main`，并满足全部完成门禁。 |

重新排序、拆分、合并、新增或删除步骤，都必须先通过独立且经过审查的计划 PR。
只存在于聊天、本地笔记或未合并分支中的计划不具有约束力。

## 完成门禁

只有同时满足全部适用条件，一个步骤才算完成：

- 验收标准和配套文档全部完成；
- 本地测试、格式化、Lint 和安全检查全部通过；
- 最终 Diff 已接受一次只读独立审查；可以调用本地 Claude CLI 进行咨询式 CR，
  但必须记录 CLI 实际报告的模型，且 Claude 不得写文件、Commit、PR、Review 或
  执行合并；
- 推送分支与本地已审查的 Commit 和精确 Diff 一致；
- 再从 GitHub 远端 Diff 进行一次自审；
- GitHub 全部必需检查成功，所有 Review Thread 已解决；
- PR 使用 Squash Merge，关联 Issue 已关闭，并且 Merge 已出现在
  `origin/main`；
- 本地 `main` 已 Fast-forward 到该 Merge，且工作区没有意外的已跟踪改动。

任何条件失败，都继续停留在当前步骤。只有 Issue 明确把 No-Go 定义为可接受且
需要记录的实验结果时，安全的 No-Go 才能完成实验步骤；它不能被宣传为设备支持
或砸壳能力已经可用。

## 当前门禁

`HOST-008` 是唯一正在进行的实现步骤，其私有工作目录范围、排除项、Host 文件
系统边界、资源上限、清理行为和验收标准由 Issue #37 固定。在 `HOST-008` 实现
PR 满足全部完成门禁并合并前，`HOST-009` 及以后步骤都不得启动。

## 执行台账

Issue 和 PR 链接是持久证据。PR 页面本身会展示 Merge Commit 和必需检查历史，
因此表格不重复保存容易漂移的 Commit SHA。

| 顺序 | ID | `main` 状态 | 交付物 / 验收摘要 | 依赖 | Issue | 激活 PR | 实现 PR |
|---:|---|---|---|---|---|---|---|
| 1 | `GOV-001` | `done` | 建立双语台账、串行门禁、完成定义和文档入口。 | — | [#29](https://github.com/jacklv-coder/OrchardProbe/issues/29) | Bootstrap 例外 | [#30](https://github.com/jacklv-coder/OrchardProbe/pull/30) |
| 2 | `HOST-001` | `done` | 不解压 Entry 即拒绝不安全或有歧义的 IPA Archive 结构。 | 基础能力 | [#19](https://github.com/jacklv-coder/OrchardProbe/issues/19) | 早于台账 | [#20](https://github.com/jacklv-coder/OrchardProbe/pull/20) |
| 3 | `HOST-002` | `done` | 在大小、压缩比、CRC 和 Inventory 一致性限制内读取或流式复制一个精确 Stored/Deflate Entry。 | `HOST-001` | [#21](https://github.com/jacklv-coder/OrchardProbe/issues/21) | 早于台账 | [#22](https://github.com/jacklv-coder/OrchardProbe/pull/22) |
| 4 | `HOST-003` | `done` | 解析有界 XML/Binary 根 `Info.plist` 身份和声明主程序元数据。 | `HOST-002` | [#23](https://github.com/jacklv-coder/OrchardProbe/issues/23) | 早于台账 | [#24](https://github.com/jacklv-coder/OrchardProbe/pull/24) |
| 5 | `HOST-004` | `done` | 流式读取并检查精确根主程序的 Mach-O 结构。 | `HOST-003` | [#25](https://github.com/jacklv-coder/OrchardProbe/issues/25) | 早于台账 | [#26](https://github.com/jacklv-coder/OrchardProbe/pull/26) |
| 6 | `HOST-005` | `done` | 只有在 Mach-O 解析通过后才清点有界的约定 Framework、dylib 和 Extension 候选，并把覆盖率标为不完整。 | `HOST-004` | [#27](https://github.com/jacklv-coder/OrchardProbe/issues/27) | 早于台账 | [#28](https://github.com/jacklv-coder/OrchardProbe/pull/28) |
| 7 | `HOST-006` | `done` | 解析约定嵌套 Bundle 的有界 `Info.plist` 和精确声明可执行文件；显式拒绝缺失、重复、越界、过大或畸形声明。 | `HOST-005` | [#31](https://github.com/jacklv-coder/OrchardProbe/issues/31) | [#32](https://github.com/jacklv-coder/OrchardProbe/pull/32) | [#33](https://github.com/jacklv-coder/OrchardProbe/pull/33) |
| 8 | `HOST-007` | `done` | 为全部受支持标准 Bundle 类型生成确定性的“声明可执行文件”清单，并明确覆盖率与歧义语义。 | `HOST-006` | [#34](https://github.com/jacklv-coder/OrchardProbe/issues/34) | [#35](https://github.com/jacklv-coder/OrchardProbe/pull/35) | [#36](https://github.com/jacklv-coder/OrchardProbe/pull/36) |
| 9 | `HOST-008` | `active` | 把不可变源 IPA 物化到私有、有界的工作目录，阻止 Symlink/Path Escape，排除 Receipt 和 `SC_Info`，不修改源文件。 | `HOST-007` | [#37](https://github.com/jacklv-coder/OrchardProbe/issues/37) | [#38](https://github.com/jacklv-coder/OrchardProbe/pull/38) | — |
| 10 | `HOST-009` | `planned` | 使用未改变的 Fixture 字节重建确定性、未签名、仅供分析的 IPA；保留必要元数据且绝不宣称已经解密。 | `HOST-008` | 激活时创建 | 激活时记录 | — |
| 11 | `HOST-010` | `planned` | 使用无设备 Fixture，把输入/输出 Hash、清单、逐二进制状态、排除项和打包证据写入带版本 Manifest。 | `HOST-009` | 激活时创建 | 激活时记录 | — |
| 12 | `LAB-001` | `planned` | 建立首方受保护 DemoLab Oracle，同时提供初始保护状态与预期明文的独立证据；否则记录有界 No-Go。 | `HOST-010` | [#9](https://github.com/jacklv-coder/OrchardProbe/issues/9) | 激活时记录 | — |
| 13 | `DEVICE-001` | `planned` | 在自有且获授权设备上评估一个边界狭窄的后端，记录可复现 Go/No-Go 证据，不扩大 Helper 边界。 | `LAB-001` | [#10](https://github.com/jacklv-coder/OrchardProbe/issues/10) | 激活时记录 | — |
| 14 | `DEVICE-002` | `planned` | 为唯一一个已验证后端和设备组合接受 ADR；没有必需真机记录时不得发布支持声明。 | `DEVICE-001` Go 结果 | 激活时创建 | 激活时记录 | — |
| 15 | `DEVICE-003` | `planned` | 在 RFC-0002 限制下实现最小 Helper 和 USB Transport，不提供 Shell、任意路径、PID 或内存 API。 | `DEVICE-002` | 激活时创建 | 激活时记录 | — |
| 16 | `EXPORT-001` | `planned` | 使用精确设备代码区间证据重建并验证根主程序，其他字节仍来自输入 IPA。 | `DEVICE-003` | 激活时创建 | 激活时记录 | — |
| 17 | `EXPORT-002` | `planned` | 把重建和逐二进制证据扩展到受支持的声明可执行文件清单；失败保持逐文件、显式可见。 | `EXPORT-001` | 激活时创建 | 激活时记录 | — |
| 18 | `UX-001` | `planned` | 实现 `oprobe decrypt <input.ipa>` 一条命令主路径：自动诊断、原子输出未签名 IPA，并生成独立 Manifest。 | `EXPORT-002` | 激活时创建 | 激活时记录 | — |
| 19 | `RELEASE-001` | `planned` | 发布可复现的窄范围 Alpha、安装说明、Checksum/SBOM、双语排错文档和有证据的兼容矩阵。 | `UX-001` | 激活时创建 | 激活时记录 | — |

## 本计划没有宣称什么

`HOST-007` 之后的条目都是计划，不是已实现能力。仓库目前尤其没有设备后端、
可用砸壳、设备/构建匹配、IPA 重建、`oprobe decrypt` 命令、可安装 Release 或正式
支持的设备组合。输出设计仍是未重签、仅供分析，并且只适用于用户有权分析的 App。
