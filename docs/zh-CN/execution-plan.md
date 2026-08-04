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
- 最终 Diff 已接受只读 Codex CR，覆盖正确性、并发/安全风险、测试缺口和文档
  一致性；全部 P1/P2 问题必须在 Push 或 Merge 前解决；
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

[PR #83](https://github.com/jacklv-coder/OrchardProbe/pull/83) 已进入
`main`；`LAB-002` 现为 `done — 保留证据的 No-Go`，Issue #55 已关闭。检查点 2
此前已通过合并的 PR #59 进入 `main`。2026-07-31，操作员明确接受了紧邻上一条的有界建议：只为首方
DemoLab `1.0 (3)` 创建签名候选与冻结上传前 Oracle，不上传 TestFlight、不安装、
不做设备观察。[PR #72](https://github.com/jacklv-coder/OrchardProbe/pull/72)
进入 `main` 后，检查点 3 为 `done`；其已完成顺序工作记录在
[检查点 3 进度台账](lab-002-checkpoint-3-progress.md)。[无设备设计](lab-002-oracle-design.md)已固定首方 DemoLab
自观测边界、三个
Role/全部 Slice 清单、每个 Role 的授权 Target 身份和固定代码区间、独立上传前
Oracle、有界报告、两次干净运行和 Fail-Closed Go/No-Go 规则。
安装前与每轮前还必须重新完成由 Host 签名、带策略版本的授权使用确认；设备本地
Enrollment Key/Receipt 会把两份签名 Run Export 绑定到同一台物理设备、同一 App
安装、硬件型号和 iOS Version/Build。任何后续实现只能在该设计内
进行。已完成的检查点 3 只建立精确本地签名 Candidate 与冻结上传前 Oracle，
不建立受保护 Oracle，也不授权 TestFlight 上传、安装、设备观察或设备 Backend 工作。
任何不同 Source、Version/Build、Manifest、签名 Tuple、上传、安装或观察都须另行
明确授权。2026-08-01，操作员已另行授权精确 Build 的有界检查点 4 流程；恰好一次内部
TestFlight 上传已对账为 Apple 接受并处理完成，未启用外部测试或提交审核。该外部操作
和对账发生在本激活 PR 进入 `main` 之前，违反上面的“先激活、后执行”串行门禁。这个
不可逆事实作为治理偏差保留，不能改写成合规操作或重试；此后没有安装或设备观察。
检查点 4 已通过激活 PR #73 变为 `active`，已评审 Host 操作工件链也已通过 PR #74
合并；其[顺序进度台账](lab-002-checkpoint-4-progress.md)保留此前每次失败关闭的 Host
尝试，以及通过 PR #76、#78、#80 与 #81 合并的修复。最后一次全新 4C 仪式已到达所选
自有 iPhone：TestFlight 显示并打开首方 DemoLab `1.0 (3)`，DemoLab 导入签名一次性
信封，设备创建并导出签名 Enrollment Receipt。由于 Host 随后在发布任何 Enrollment
Binding 前停止，已安装二进制 Lineage 仍未验证；外部 Receipt 与诊断日志被放入严格六项
实验目录。文件与
失败证据仍仅 Owner 可访问，授权已经过期，且已评审 No-Go 规则禁止把该仪式重建或重试成
通过。因此检查点 4 已以保留证据的 No-Go 关闭；两轮干净运行均未执行，没有受保护到明文
观察或 Go 结果，`DEVICE-001` 继续保持 `blocked`。
Issue #9 固定其首方 DemoLab 来源、独立的初始保护/预期明文 Oracle 证据、脱敏、
明确 Go/No-Go、文档和收窄声明标准。

Issue [#84](https://github.com/jacklv-coder/OrchardProbe/issues/84) 定义了
`LAB-003`：它是插入被阻塞 Backend 工作之前、独立评审且无设备的后续步骤。第一道门禁是
双语[外部工件布局契约](lab-003-external-artifact-layout.md)：实验子目录保留六个不可变基础
控制工件，并只允许当前生命周期状态对应的精确 Phase 目录；外部 Receipt/Export 输入与
有界诊断分别使用不同、互不重叠且仅 Owner 可访问的角色，完整路径和身份校验必须发生在
未来授权被创建或消费之前。本激活不会修改任何生命周期保护，
也不授权 Build、上传、安装、信封或设备操作。合并后只能开始 Issue #84 内的无设备实现与
合成测试；任何后续仪式仍需另一个已评审检查点和全新明确授权。

### LAB-002 检查点台账

与主台账相同，只有包含这些状态的 PR 进入 `main` 后才具有权威性。

| 顺序 | 检查点 | 本 PR 进入 `main` 后的状态 | 证据 / 下一门禁 |
|---:|---|---|---|
| 1 | 无设备 Oracle 设计 | `done` | [PR #58](https://github.com/jacklv-coder/OrchardProbe/pull/58)及已评审的[设计](lab-002-oracle-design.md) |
| 2 | 无设备实现与合成/Simulator 验证 | `done` | 已合并的 [PR #59](https://github.com/jacklv-coder/OrchardProbe/pull/59)实现闭合协议、Host 链、固定设备状态/Observer/Export 流程、生产授权验证及合成/Simulator 门禁；全部必需 CI、Review Thread 与合并前 Codex CR 均已清零 |
| 3 | 精确签名 DemoLab Build 与上传前 Oracle | `done` | 已从 PR #71 合并后的干净源码发布恰好一个通过验证的本地 DemoLab `1.0 (3)` 签名候选/冻结 Oracle Pair。[检查点 3 进度台账](lab-002-checkpoint-3-progress.md)与 [Issue #55](https://github.com/jacklv-coder/OrchardProbe/issues/55#issuecomment-5151749527)记录其非秘密证据；[PR #72](https://github.com/jacklv-coder/OrchardProbe/pull/72)是完成记录 Implementation PR，其合并使本行状态生效。授权仍不包含上传、安装或设备观察 |
| 4 | 安装 Enrollment 与两次干净真机观察 | `已关闭 — 保留证据的 No-Go` | TestFlight 显示并打开首方 DemoLab `1.0 (3)`；DemoLab 已导入全新信封并导出签名 Receipt。Host 在发布 Enrollment Binding 前停止，因此已安装二进制 Lineage 仍未验证；随后授权过期。Run 1 与 Run 2 均未执行，且本次仪式不重试。详见[检查点 4 进度台账](lab-002-checkpoint-4-progress.md) |
| 5 | 脱敏 LAB-002 Go/No-Go 结果 | `done — PR #83` | [PR #83](https://github.com/jacklv-coder/OrchardProbe/pull/83)在双语台账中保留流程性 4C No-Go 并关闭 Issue #55，不记录私有路径、标识符、Fingerprint、Receipt 内容或 Host 结果；不能据此声称 Go 或 Backend |

检查点 2 的完成证据保留在
[LAB-002 实现进度台账](lab-002-implementation-progress.md)。完整的检查点 2
实现现已进入 `main`。2A–2E
任一子步骤都不会单独授权签名构建、TestFlight 上传或设备观察。

激活 PR 与工作流准备 PR 均已合并，Issue #9 已记录无需账号的证据审计和首次签名候选
构建。已合并的可参数化、由操作员显式控制的 DemoLab Archive/证据/上传流程使用
带锁的随机构建暂存、排他发布和绑定证据的命名 `.ipa` Apple 上传；Gym 导出
Scratch 被限制在该暂存目录内并随之清理，同时
明确校验有界的 `altool` JSON 成功/错误响应；不保存 Apple 凭据，且为上传进程设置
固定截止时间。预上传记录绑定生成工程时实际使用的
XcodeGen 精确版本，并在执行前校验不可写文件及经过评审的版本/架构 SHA-256 白名单；
已验证字节会通过稳定的只读描述符复制到私有工作区内加锁、只读的快照，工程生成只执行
该快照；受控子进程会清除继承的动态加载器覆盖。上传状态使用已 fsync 的原子发布/替换，
避免中断把当前恢复记录留成半截 JSON。
Archive 二进制路径会逐级拒绝符号链接并保持在同一 Archive Root，Apple 上传进程启动
前会紧邻地重新测量三个二进制。归档和证据读取的
Apple 开发者工具也已固定为系统所选 Xcode 下的
root 所有绝对路径以及 `/usr/bin/xcrun`、`/usr/bin/plutil`，并在执行前后复核
身份、版本和 SDK，Check 与签名构建均清除继承的 Xcode 选择覆盖，并拒绝调用方 PATH
中的同名遮蔽工具。配置及解析后的临时根目录会在 Fastlane 组成导出命令前拒绝
Shell 不安全字符。该阶段也不把签名、分发或安装变成 `oprobe` 能力。API Key 使用
匿名只读描述符，IPA 则因 Apple 拒绝
无扩展名包路径而使用随机私有工作区内加锁的只读 `.ipa` 快照，并在使用前后复核
路径、Inode 与哈希；保留的 `altool` 身份同样在执行前后立即复核。

2026-07-29 已获得明确上传授权并在本机配置最小权限 API Key。首次上传在 Apple 接收
任何 IPA 字节前被拒绝，根因是 Xcode 26 `altool` 无法展开没有扩展名的匿名包路径。
通过 App Store Connect 页面与 API 对账确认 `1.0 (1)` 不存在 Build 和上传文件；
本地不确定记录已按“缺席”归档并恢复重试许可。

PR #49 已合并命名 `.ipa` 兼容修复。随后从干净的合并 Commit
`911db950cff8fc408294d56181477f7319442a36` 重新生成 DemoLab `1.0 (1)` 候选，
IPA SHA-256 为
`1bb541456d73d644e7c06a148c1e0c780f64f1eb622ae8af35ae482a75f4ec1b`。
唯一一次许可上传前，源码 Commit、证据、包元数据、版本/Build 和 Apple Distribution
签名均已独立复核。App Store Connect 先显示上传“正在处理”，随后在 TestFlight
构建列表中把版本 `1.0` 的 Build `1` 标为“准备提交”，因此 Apple 已接收并处理该
候选，禁止重试。本地 Lane 因 `altool` 最终 stdout 不是有效 JSON 而保留
`status: indeterminate`；这记录为工具可观测性缺口，不代表远端上传失败。本次没有
创建测试组、外部分发、Beta App Review 或 App Store 提交。

`1.0 (1)` 安装到自有且获授权的 iPhone 后暴露了独立的启动阻塞。受控 Mac 侧启动
捕获到 `dyld` 拒绝主程序的 DemoFramework 依赖和嵌入 Framework 自身的 Install
Name：二者使用
`/Library/Frameworks/DemoFramework.framework/DemoFramework`，而不是
`@rpath/DemoFramework.framework/DemoFramework`。Framework 字节实际存在于导出的
App Bundle，所以 Build `1` 保留为失败证据，不得重试，也不能用于明文 Oracle 观察。

PR #51 已合并 `@rpath` 修复及 Fail-closed Archive/IPA 链接检查。DemoLab
`1.0 (2)` 来自干净的合并 Commit
`5785c56e8bee8e30fdaefcb6e263852e9be874ab`，IPA SHA-256 为
`e383fcf0ee550effb68b183965208b1ef274688cc5233649b8e452135aafde40`。
唯一一次上传前已独立复核证据、签名、包元数据、Archive 链接和导出 IPA 链接。
本地 Lane 因 `altool` 最终响应不可解析而保留 `status: indeterminate`，但
App Store Connect API 已确认该精确 Build 为 `VALID`、内部状态为
`IN_BETA_TESTING`，且不缺少出口合规信息，因此禁止重试。现有内部组覆盖全部 Build；
没有修改测试组、启用公开链接、外部分发、Beta App Review 或 App Store 提交。

2026-07-29，只读设备查询已独立确认同一自有 iPhone 安装了 DemoLab `1.0 (2)`。
一次先终止旧进程的受控启动成功返回，精确启动的进程在 12 秒和 32 秒后仍存在。这只
通过了启动前置门禁，不证明已安装字节 Lineage、初始保护、明文或砸壳能力。

三个二进制仍分别标记为 `initial_protection_status: not_observed` 和
`expected_plaintext_status: candidate_pre_upload_archive_only`，因此这不是砸壳证据。
有界 Stage 3 观察确认：公开 CoreDevice 记录没有逐二进制已安装身份或哈希，文件服务
不提供已安装 App Bundle 域，分发签名 App 也不能通过公开 LLDB 暴露可执行映像；
Apple 分发处理还意味着上传前 IPA 哈希不能替代设备安装字节。因此无法在批准边界内
独立绑定精确已安装 Lineage、初始保护和明文范围。

已记录的[有界 No-Go](lab-001-protected-oracle.md)已完成 LAB-001，并阻塞
`DEVICE-001`。Issue #55 定义的有界替代 Oracle 研究现排序为 `LAB-002`。完整范围
固定为 DemoLab 主程序、DemoFramework 和 DemoShareExtension 三个可执行文件，
以及记录安装 Build 中它们包含的每个架构/Slice。任何设备观察前，已评审的设计/
构建清单必须冻结精确 DemoLab 源码 Commit 和记录 Build 身份、清单中每个 Slice
的一组非空固定精确映射代码区间，以及为每个区间独立生成的预期明文 Oracle 产物与
SHA-256，并把它们全部绑定到同一 Commit/Build。方法必须把每个已安装清单项和
Slice 独立绑定到该 Build，证明其初始已安装状态受保护，再证明同一预声明映射区间
已成为明文并匹配冻结 Oracle。观察后不得删减或重新分类清单项/区间；任何绑定或
受保护到明文转换无法证明都记录另一个有界 No-Go。本激活 PR 满足实现前的文档
门禁；任何新签名 Build 或 TestFlight 上传前还必须单独获得明确授权。在 LAB-002
取得 Go 结果前，不得开始设备 Backend 工作。

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
| 9 | `HOST-008` | `done` | 把不可变源 IPA 物化到私有、有界的工作目录，阻止 Symlink/Path Escape，排除 Receipt 和 `SC_Info`，不修改源文件。 | `HOST-007` | [#37](https://github.com/jacklv-coder/OrchardProbe/issues/37) | [#38](https://github.com/jacklv-coder/OrchardProbe/pull/38) | [#39](https://github.com/jacklv-coder/OrchardProbe/pull/39) |
| 10 | `HOST-009` | `done` | 使用未改变的 Fixture 字节重建确定性、未签名、仅供分析的 IPA；保留必要元数据且绝不宣称已经解密。 | `HOST-008` | [#40](https://github.com/jacklv-coder/OrchardProbe/issues/40) | [#41](https://github.com/jacklv-coder/OrchardProbe/pull/41) | [#42](https://github.com/jacklv-coder/OrchardProbe/pull/42) |
| 11 | `HOST-010` | `done` | 使用无设备 Fixture，把输入/输出 Hash、清单、逐二进制状态、排除项和打包证据写入带版本 Manifest。 | `HOST-009` | [#43](https://github.com/jacklv-coder/OrchardProbe/issues/43) | [#44](https://github.com/jacklv-coder/OrchardProbe/pull/44) | [#45](https://github.com/jacklv-coder/OrchardProbe/pull/45) |
| 12 | `LAB-001` | `done` | 记录当前内部 TestFlight 精确组合的有界 No-Go：无法在批准边界内独立观察精确已安装 Lineage、初始保护和明文范围。 | `HOST-010` | [#9](https://github.com/jacklv-coder/OrchardProbe/issues/9) | [#46](https://github.com/jacklv-coder/OrchardProbe/pull/46) | [#54](https://github.com/jacklv-coder/OrchardProbe/pull/54) |
| 13 | `LAB-002` | `done — 保留证据的 No-Go` | 评估仅限 DemoLab 的受保护到明文自观测 Oracle。无设备检查点 2、精确本地 DemoLab `1.0 (3)` 候选/冻结 Oracle 和 Host 操作链已分别通过 PR #59、#72 与 #74 完成；恰好一次内部 TestFlight 上传已对账为 Apple 接受。最后一次全新 4C 仪式中，TestFlight 显示并打开首方 DemoLab `1.0 (3)`，该 App 导入一次性信封并导出签名 Receipt；Host 在发布 Enrollment Binding 前停止，所以已安装二进制 Lineage 仍未验证，随后授权过期。[检查点 4 进度台账](lab-002-checkpoint-4-progress.md)保留该流程性 No-Go；两轮观察均未执行，不存在受保护到明文结果或 Go 结果，且本次仪式不重试。[PR #83](https://github.com/jacklv-coder/OrchardProbe/pull/83)发布脱敏关闭记录并关闭 Issue #55。 | `LAB-001` No-Go | [#55](https://github.com/jacklv-coder/OrchardProbe/issues/55) | 初始：[#57](https://github.com/jacklv-coder/OrchardProbe/pull/57)；检查点 3：[#61](https://github.com/jacklv-coder/OrchardProbe/pull/61)；检查点 4：[#73](https://github.com/jacklv-coder/OrchardProbe/pull/73) | 检查点 2：[#59](https://github.com/jacklv-coder/OrchardProbe/pull/59)；检查点 3：[#72](https://github.com/jacklv-coder/OrchardProbe/pull/72)；Host 流程：[#74](https://github.com/jacklv-coder/OrchardProbe/pull/74)；最终：[#83](https://github.com/jacklv-coder/OrchardProbe/pull/83) |
| 14 | `LAB-003` | `active — 检查点 3` | 闭合三角色布局、感知 Phase 的清单、无设备路径/身份预检、有界诊断及合成回归已通过 PR #86 合并。检查点 3 记录脱敏结论：仅布局 Go、设备仪式 No-Go。其结果 PR 可以关闭 LAB-003，但不能授权 Build、上传、安装、信封、设备动作、Backend 声明或可用 IPA 砸壳。 | `LAB-002` 保留证据的 No-Go | [#84](https://github.com/jacklv-coder/OrchardProbe/issues/84) | [#85](https://github.com/jacklv-coder/OrchardProbe/pull/85) | [#86](https://github.com/jacklv-coder/OrchardProbe/pull/86)；结果 PR 待记录 |
| 15 | `DEVICE-001` | `blocked` | 在自有且获授权设备上评估一个边界狭窄的后端，记录可复现 Go/No-Go 证据，不扩大 Helper 边界。 | 已评审的首方受保护 Oracle Go 结果；只有 `LAB-003` 不足以满足 | [#10](https://github.com/jacklv-coder/OrchardProbe/issues/10) | 激活时记录 | — |
| 16 | `DEVICE-002` | `planned` | 为唯一一个已验证后端和设备组合接受 ADR；没有必需真机记录时不得发布支持声明。 | `DEVICE-001` Go 结果 | 激活时创建 | 激活时记录 | — |
| 17 | `DEVICE-003` | `planned` | 在 RFC-0002 限制下实现最小 Helper 和 USB Transport，不提供 Shell、任意路径、PID 或内存 API。 | `DEVICE-002` | 激活时创建 | 激活时记录 | — |
| 18 | `EXPORT-001` | `planned` | 使用精确设备代码区间证据重建并验证根主程序，其他字节仍来自输入 IPA。 | `DEVICE-003` | 激活时创建 | 激活时记录 | — |
| 19 | `EXPORT-002` | `planned` | 把重建和逐二进制证据扩展到受支持的声明可执行文件清单；失败保持逐文件、显式可见。 | `EXPORT-001` | 激活时创建 | 激活时记录 | — |
| 20 | `UX-001` | `planned` | 实现 `oprobe decrypt <input.ipa>` 一条命令主路径：自动诊断、原子输出未签名 IPA，并生成独立 Manifest。 | `EXPORT-002` | 激活时创建 | 激活时记录 | — |
| 21 | `RELEASE-001` | `planned` | 发布可复现的窄范围 Alpha、安装说明、Checksum/SBOM、双语排错文档和有证据的兼容矩阵。 | `UX-001` | 激活时创建 | 激活时记录 | — |

## 本计划没有宣称什么

`LAB-002` 检查点 3 已针对精确本地 DemoLab `1.0 (3)` Candidate/冻结 Oracle Pair
完成，它的无设备检查点 2 实现也已完成。`LAB-003` 只激活无设备布局修复。这些步骤及
后续阻塞或计划条目都不建立产品能力。仓库目前尤其
没有受保护 Oracle、设备后端、可用砸壳、设备/构建匹配、Mach-O 重建、
调用方可见的 IPA 发布、
`oprobe decrypt` 命令、可安装 Release 或正式支持的设备组合。输出设计仍是未重签、
仅供分析，并且只适用于用户有权分析的 App。
