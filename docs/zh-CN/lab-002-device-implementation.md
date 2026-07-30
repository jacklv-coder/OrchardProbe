# LAB-002 设备端实现契约

状态：**检查点 2C 分支本地契约**

本文在加入设备端代码前冻结 DemoLab 内部边界，并从属于已评审的
[LAB-002 Oracle 设计](lab-002-oracle-design.md)。如有冲突，以该设计为准，且实现
门禁必须失败关闭。

本文不授权签名 Archive、TestFlight 上传、安装或物理设备观察。在设备无关门禁完成
之前，检查点 2C 的实现与测试必须只使用临时容器、合成 Key 与未签名 Simulator
Build。

## 对外能力边界

DemoLab 只提供以下用户动作：

| 动作 | 输入 | 效果 |
|---|---|---|
| Import LAB-002 authorization | 系统文档选择器提供的一个 URL | 最多复制一份闭合、规范的 Enrollment 或 Run Envelope 到固定 Inbox |
| Confirm installation enrollment | 无 | 消费一份有效安装 Envelope，只创建一次固定 Enrollment 状态 |
| Start clean LAB-002 run | 无 | 消费一份有效 Run Envelope，提交其精确下一 Counter，并启动固定三 Role Session |
| Discard stale LAB-002 authorization | 无 | 只删除已证明畸形、过期或 Build 不匹配的固定 Inbox 记录 |
| Export LAB-002 evidence | 无 | 构造一份固定的四文档签名 Export，并展示系统 Share Sheet |
| Confirm export received and clean reports | 一个明确的 Boolean UI 确认 | 重新计算已构造 Export，且只删除其匹配的已完成报告子树 |

文档选择 URL 只存在于 Import 边界。它不会写入报告、传给 Observer、由 Host/Core
接受，也不会在有界复制后复用。其他生产初始化器或方法都不得接受 URL、Path、
File Descriptor、Bundle、Image Header、Target、Role、Range、PID、Process、
Address 或逻辑文件名。

三个观察入口闭合且为零参数：

```text
Main App        observeCurrentMainExecutable()
DemoFramework   observeCurrentFrameworkImage()
Share Extension observeCurrentShareExecutable()
```

每个入口自行解析自身 Bundle、Executable、编译 Anchor、Role 与
`__TEXT,__oprobe` 区间。Framework 入口可以被嵌入 App 看见，但没有可选择输入。
Parser Helper 与 Report Builder 保持 Target 私有。

OrchardProbe CLI、Core、Host、Fastlane 或设备 Helper 都不存在解析、列出、读取、
写入、导入、导出或清理 App Group Container 的 API。

## Target 私有 Mach-O Observer Core

检查点 2C.4b 实现一份源代码级 Core，并由每个消费 Target 分别编译。生产构造器保持
私有，后续只有 2C.4c 的零参数 Role 入口可以提供其固定 Bundle Executable 与编译期
Anchor。URL 和 Mapped Header 注入只存在于 Debug 测试 Harness。

安装文件 Reader 使用 `O_NOFOLLOW` 只读打开固定 Executable，只接受仍有链接且不超过
100 MiB 的普通文件，使用 `pread` 精确读取，并在解析后重新核对 Descriptor 身份、
Mode、Link Count、Size、Modification Time 与 Change Time。Parser 随后：

1. 只接受一份 Thin、FAT32 或 FAT64 Container，最多四个不重叠且对齐的 Slice；
2. 限制 Load Command 数量/字节数和每份 Fixup Payload；
3. 绑定 FAT/Mach-O CPU 身份、File Type、UUID、Slice Ordinal 及经过检查的 File/VM
   坐标；
4. 要求恰好一个 64–1,024 字节、可执行、Regular、Pure-instruction 的
   `__TEXT,__oprobe` Section，且没有 Section Relocation；
5. 拒绝 Section/Segment 重叠，以及指向可执行 `__TEXT` 的 Classic 或 Chained
   Fixup；
6. 把唯一且与架构匹配的 Encryption Command 从 Slice 相对坐标规范为绝对文件坐标，
   并记录精确 Coverage；以及
7. 重新解析有界 Mapped Header，要求其 CPU 身份、UUID、固定坐标与编译 Anchor
   包含关系匹配安装 Slice，之后才返回 Mapped Range。

Core 只返回闭合证据结构与闭合 Reason Code，不执行 Oracle 比较、签名身份验证、
Mapped-memory Hash 或报告发布；这些仍按顺序留给 2C.4c。

### 零参数本地 Role 组装

检查点 2C.4c1 把同一份已评审 Core 分别编译进 App、Framework 与 Extension，并且
只暴露三个固定零参数入口。每个入口在内部提供自身固定 `Bundle` 与编译期 Assembly
Anchor。Disk Inspection 开始前，`dladdr` 必须把该 Anchor 绑定到固定 Bundle 解析
出的同一 Executable Path。

Active 64-bit Mapped Header 被限制为 4,096 个 Command 和 4 MiB，并通过 CPU
Type/Subtype、UUID、固定坐标及 Anchor 包含关系精确匹配一个安装 Slice。复制并 Hash
字节前，Mapped Header 与固定 Section 都必须完整落在同一个 Read+Execute VM Region
内。Disk Inspection 时间必须先于 Mapped Hash 时间。

安装 Slice 还会解析一份有界 Embedded Code-signature SuperBlob：Primary
CodeDirectory Layout、Identifier、Team Identifier、选定 XML Entitlement、
CMS/Ad-hoc/Unknown Kind，以及完整 SuperBlob SHA-256。编译期 32 字节 Identity Nonce
与固定 Role 会和这些选定身份值一起，使用与 Core 相同的 Target-identity Domain
进行长度分帧。iOS 没有公开 `SecStaticCode` 验证 Surface，因此 Parser 会明确记录
`not_checked`；成功启动、形似 CMS 的 Slot、Identifier 或 Digest 都不会变成
`valid`。所以除非以后有另行评审的 Validator 提供真实验证，最终报告必须为 No-Go。

报告编码与按固定顺序排他发布不属于本次本地组装，仍留给 2C.4c2。

## 固定生产 Container

生产代码只通过 `containerURL(forSecurityApplicationGroupIdentifier:)` 获取
Container。仓库中的 Simulator 标识符保持通用；受控签名 Build 在不提交真实值的
前提下提供已注册的一方标识符。

下列每个路径组件都是编译期固定字符串：

```text
lab-002-v1/
  coordinator.lock
  inbox/
    authorization-v1.json
    authorization-quarantine-v1.json
  state/
    installation-nonce-v1.json
    run-counter-v1.json
  reports/
    current/
      session.json
      main-app.json
      framework.json
      share-extension.json
```

生产代码不得接收或拼接调用者提供的路径组件。Export 的逻辑名称只能是四个固定
报告名，且不是文件系统路径。Enrollment Key 不是文件；它使用一个固定 Keychain
Service/Account/Access Group 元组。

`coordinator.lock`、`inbox` 和 `state` 在报告清理后继续存在。
`installation-nonce-v1.json`、`run-counter-v1.json` 和 Enrollment Key 只能随 App
删除，或由另行评审的实验拆除动作移除；普通 Start、Export、Discard、Cleanup
不能重置它们。

## 串行状态迁移

Main App 的 Import、Confirm Enrollment、Start、Discard、Export 与 Cleanup 全部
经过同一个串行协调器。所有修改 Inbox 的动作都必须持有排他 Coordinator Lock。

### Inbox

```text
absent --Import valid/exclusive--> imported
imported --identity-checked rename--> quarantined
quarantined --valid Confirm/Start--> consumed
quarantined --proven stale/malformed/build-mismatch--> discarded
```

意外 Quarantine、Lock 失败、非普通文件、Symlink、目录项/Descriptor 身份不匹配、
部分写、重复 Import 或崩溃残留都会阻塞，绝不自动修复。唯一的窄例外是下述显式、
已认证的 Enrollment Resume；它会重新验证同一份已隔离 Envelope，Run 无法调用。

### Enrollment

```text
uninitialized --valid installation envelope--> creating
creating --explicit same-envelope authenticated resume--> creating
creating --key + nonce + receipt committed--> enrolled
creating --unrecognized/conflicting partial failure--> experiment failed
enrolled --every run--> read-only continuity check
```

只有通过认证的安装动作可以创建设备专属 Key 和 Installation Nonce。Run 代码不能
创建、替换、修复、导入、导出或重置它们。Key 缺失/不可访问、Nonce 记录缺失/畸形、
Build 不匹配或公钥不匹配都必须在观察前失败。

中断的 Enrollment 只有在同一授权仍位于固定 Quarantine 时才能恢复。显式确认会重新
验证这些精确字节以及当前时间/Build。如果 Keychain Item 已存在而 Nonce State 不存在，
只有其记录的 Build Binding 匹配才能完成 State 创建；如果 Nonce State 已存在，则必须
严格匹配同一 Build 的 Key/Public Key Tuple，才能完成剩余 Enrollment 提交。新的授权
不能复用已有 State，普通 Cleanup、Run 与跨 Build 路径均不能进入这两个恢复分支。

### Run

```text
idle
  --valid envelope + exact counter commit-->
collecting_main
  --> collecting_framework
  --> awaiting_share_extension
  --> complete_unexported
  --> export_constructed
  --explicit receipt confirmation + exact rehash-->
idle
```

Counter 在创建 `session.json` 前持久提交。崩溃可以消耗 Counter，但不能重用它。
每个 Role Report 只能排他创建一次且不可覆盖。缺失、重复、顺序错误、过期或冲突
状态都会使精确实验失败；不完整/失败证据不能清理后重试成通过结果。

## 存储不变量

实现必须：

- 打开目录和文件时不跟随 Symlink，需要普通文件时必须验证普通文件；
- 每次 Inbox 迁移都持有 Owner-only 排他 Advisory Lock；
- Quarantine 前后比较打开 Descriptor 与目录项身份；
- 采取有界完整读取，并在动作前完成精确规范解码；
- 在同目录排他创建 Owner-only 临时文件，完整写入和 Flush，无替换发布，再 Fsync
  目录；
- 拒绝已存在的目标、临时文件、Quarantine 或意外目录项；
- 在锁定时使用 Complete File Protection，并将状态/报告排除备份；
- 永不覆盖 Role Report、静默重置 Counter、删除当前有效授权，或清理未 Export/
  不匹配 Session。

各 Surface 上限沿用已评审 Schema 契约：Control 文档 16 KiB、固定 State 记录
1 KiB、Role Report 128 KiB、Session Report 16 KiB、签名 Export 512 KiB。

## 生产与测试依赖

生产装配固定且保持 Internal：

- App Group Locator：唯一编译 Group 标识符；
- Wall Clock：系统 UTC 整秒；
- Random：系统密码学随机源，需要时精确 32 字节；
- Key Store：一个不可同步、`kSecAttrAccessibleWhenUnlockedThisDeviceOnly` 的
  Ed25519 Key；
- File Store：上述固定 Container 布局；
- Environment：脱敏 Hardware Model 与 iOS Product Version/Build；
- Target Observer：三个编译固定的零参数入口。

测试可以通过只对 Test Target 可见的 Internal Protocol 注入临时 Root、确定性
Clock、确定性 Random Source 和内存合成 Signing Key。生产 App/Extension
Initializer 不暴露这些依赖；Release 代码不存在 Environment Variable、Defaults、
URL Scheme、Pasteboard、Network、Command-line 或 IPC Override。

## 2C 实现门禁

1. 固定 Path/State 类型可供 Main App 与 Extension 编译。
2. Coordinator 对重复、超限、部分、Symlink、替换、Quarantine、Lock、过期和冲突
   记录失败关闭。
3. Enrollment 状态证明 Device-only Key/Nonce/Build 连续性，且不能从 Run 路径
   创建。
4. 三个 Observer 都没有可选择输入，且只发布一个固定 Role Report。
5. Receipt/Export 签名使用冻结 Domain，Cleanup 要求精确匹配已完成 Export。
6. Simulator/合成测试不声称物理设备或明文证据；其成功只表示结构 Plumbing。
