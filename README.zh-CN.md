# OrchardProbe

> 从明确支持的越狱 iOS 设备本地导出 App，并对有权分析的二进制执行可审计 Mach-O 解密与证据报告。

[English](README.md)

> [!IMPORTANT]
> **Pre-alpha：** OrchardProbe 目前只是工作名。仓库现已包含无需设备的 Rust Host 工具、首方模拟器 fixture、项目规划和基础治理政策，但仍没有设备后端、可用的导出工具、已验证的设备支持矩阵、正式版本或安装说明。

OrchardProbe 希望让经过授权的 iOS 二进制研究更透明、更可复现。计划中的工作流会探测设备能力、选择边界明确的导出后端、分别验证每个相关 Mach-O，并在机器可读的 manifest 中记录成功、失败和跳过的项目。

项目不会承诺支持所有 iOS 版本、设备、越狱环境或 App。首个可用里程碑会刻意收窄范围：先支持 Apple Silicon macOS，并只支持一种经过明确记录和真机验证的设备环境，再逐步扩展兼容性。

## 当前开发快照

当前代码刻意只实现 Host 端基础能力：报告本机 pre-alpha 状态、读取单个本地 Mach-O 的有界 Header 元数据、执行仅限库内的有界 IPA Archive 预检与 Entry 流式读取、解析有界的根 App 与约定嵌套 Bundle 身份元数据及精确声明可执行 Entry、检查根主程序的 Mach-O 结构，并仅在 Mach-O 解析通过后构建确定性的声明标准 Bundle 清单、把已验证 IPA App 树物化到自动清理的私有有界工作树、输出确定性的合成 manifest，以及检查 manifest 的 Schema 与路径安全约束。当前没有 CLI 命令接受 IPA。

```sh
cargo run --locked -p orchardprobe-cli -- doctor --json
cargo run --locked -p orchardprobe-cli -- inspect path/to/Mach-O --json
cargo run --locked -p orchardprobe-cli -- demo --json
cargo run --locked -p orchardprobe-cli -- verify path/to/manifest.json --json
```

这些命令不会连接设备、解密二进制、处理 IPA，也不能证明明文字节正确。`inspect` 只接受一个普通 Mach-O 文件，并仅读取有界的容器、Slice 与 Load Command 元数据；精确契约见 [Mach-O inspect 开发文档](docs/development/macho-inspect.md)。Capability、结构化错误和导出 manifest 现已有[带版本、边界明确的 pre-v1 契约](docs/development/schemas.md)，未来 transport 还必须先满足独立的[有界 Host/Helper 协议 RFC](docs/architecture/RFC-0002-bounded-host-helper-protocol.md)。两者都只是无设备契约；当前仍没有设备后端实现它们。仓库自有的 [DemoLab fixture](fixtures/DemoLab/README.md) 提供 Swift 主 App、Objective-C 动态 Framework 和 Share Extension，用于安全且可复现的模拟器构建。固定工具链和验证命令见 [Rust 开发指南](docs/development/getting-started.md)。

内部的[有界 IPA 输入基础（英文）](docs/development/ipa-preflight.md)先在不解压的
情况下验证 Archive 元数据，然后可以把一个精确的 Stored/Deflate Entry 读入有
上限且检查 CRC 的内存 Buffer，或流式复制到调用方 Sink。它尚未接入 CLI，因此
不改变上面对当前命令的描述。

独立的[有界 `Info.plist` 元数据解析器（英文）](docs/development/ipa-info-plist.md)
可以从 XML 或 Binary plist Event 中解析根 App 的 Bundle ID、版本和精确主程序
Entry。后续的[有界 IPA 主程序检查（英文）](docs/development/ipa-main-executable.md)
会把该精确 Entry 流式写入匿名临时文件并调用现有的仅元数据 Mach-O Parser。
它不证明已安装构建匹配、解密或明文字节正确。
[有界嵌套 Bundle 元数据层（英文）](docs/development/ipa-nested-bundles.md)可以解析
约定 Framework 和直接 Extension 的精确声明可执行 Entry，包括非标准名称。
[声明标准 Bundle Code 清单（英文）](docs/development/ipa-code-inventory.md)会消费这些
声明，让声明角色优先于 `.dylib` 后缀，并只增加同一封闭祖先范围内的小写 dylib。
其 Coverage 不包含任意嵌套 App、Watch/App Clip、未支持 Bundle 类型或仅仅看似
可执行的资源。仅限库内的[私有有界 IPA 工作树（英文）](docs/development/ipa-private-worktree.md)
随后会把已验证且未排除的字节复制到全新的 Owner-only 根目录，排除路径组件精确
等于 `_MASReceipt` 或 `SC_Info` 的内容，并在 Drop 或失败时清理整个工作树；它
不会修改 Mach-O，也不会生成输出 IPA。

## 文档

- [串行执行计划](docs/zh-CN/execution-plan.md)：权威步骤顺序、当前门禁、验收
  标准、Issue、PR 和完成规则。
- [用户指南](docs/zh-CN/user-guide.md)：计划中的
  `oprobe decrypt MyApp.ipa` 使用体验、运行条件、输出与失败行为。
- [技术总览](docs/zh-CN/technical-overview.md)：完整流水线、信任边界、重建模型、
  证据语义和源码学习顺序。
- [简体中文文档索引](docs/zh-CN/README.md)：架构、开发、兼容性和英文原始文档。
- [English documentation index](docs/README.md)。

一条命令处理 IPA 是首个可用 Alpha 的目标契约，当前 pre-alpha 代码尚未实现。

## 仅限授权用途

只能将 OrchardProbe 用于你本人或所在组织拥有的 App，或 App 所有者已经明确授权你开展相应测试的场景。你有责任遵守适用法律、平台条款、合同以及授权范围。

参与项目前请阅读：

- [法律与授权说明](LEGAL.md)
- [可接受使用政策](ACCEPTABLE_USE.md)
- [安全政策](SECURITY.md)
- [范围与威胁模型](docs/architecture/RFC-0001-scope-and-threat-model.md)
- [有界 Host/Helper 协议](docs/architecture/RFC-0002-bounded-host-helper-protocol.md)
- [兼容性证据政策](docs/compatibility/README.md)

## 项目愿景

目标不只是生成一个压缩包。一次成功的导出应当可解释、可独立验证：

- `doctor` 会说明 Host、设备、权限和依赖是否满足要求。
- 后端选择基于能力探测并被记录，而不是只根据 iOS 版本猜测。
- 主程序、Framework、动态库和 Extension 分别产生结果。
- 输入/输出哈希、Mach-O 元数据、签名状态、证据等级和失败原因写入带版本的 manifest。
- 不支持的组合应明确失败；ZIP 打包成功不会被当作所有二进制均已正确处理的证明。

## 计划范围

计划中的工具链将会：

- 接受一个授权本地 IPA 作为不可变重建输入，并自动匹配受支持设备上的同一
  已安装构建；
- 发现明确连接的设备，并只枚举政策范围内的用户 App；
- 优先使用 USB，仅将受约束的 SSH 通道作为备选方案；
- 使用短生命周期的设备 Helper，并只申请技术 Spike 证明必需的最小权限和 entitlements；
- 只传输重建所需的代码区间，以及所选 Bundle 根目录下经过路径和大小限制的文件，不提供任意 Shell、任意路径、任意 PID 或任意内存访问；
- 在 Host 端安全地重建和验证 Mach-O 二进制；
- 生成**未重签、仅供分析**的 App Bundle 或 IPA，并附带独立的 `manifest.json`；嵌入签名可能仍然存在但已经失效；
- 基于项目自行生成的 fixture 提供无需设备的 Demo。

初始兼容范围会刻意保持狭窄，且每项支持声明都必须有具体实测记录。当前 MVP 边界详见 [PROJECT_PLAN.md](PROJECT_PLAN.md)。

## 明确不做

OrchardProbe 不会提供或帮助实现：

- 搜索、下载、托管或分享未经授权的第三方解密 IPA；
- Apple ID 登录、自动购买或批量获取 App Store 内容；
- 绕过购买、订阅、许可证、反作弊、账号限制或 App 专用保护；
- 提供或执行越狱、内核漏洞利用、PAC/PPL 绕过或针对商业 App 的定向绕过；
- 重签、安装、功能修改或一键再分发；
- 导出 Keychain 项目，或 Documents、Cookie、数据库等 App 数据容器；
- 云端代导出服务。

增加上述能力的请求或贡献均不在项目范围内。

## 当前与计划中的 CLI

当前可以从源码运行的 Host-only 命令是：

```text
oprobe doctor [--json]
oprobe inspect <MACH-O> [--json]
oprobe demo [--json]
oprobe verify <manifest.json> [--json]
```

以下设备与产物命令仍只是未来设计占位，目前尚未实现：

```text
oprobe decrypt <input.ipa> [--output <output.ipa>] [--json]
oprobe devices [--json]
oprobe apps [--json]
oprobe verify <ipa-or-app> [--json]
```

目标成功路径只有 `oprobe decrypt MyApp.ipa`。输入 IPA 本身不能提供从加密到
明文的字节；同一构建必须已安装在一台受支持、已连接且明确授权的越狱设备上。
设备和 App 列表命令只用于诊断，不是正常流程必需步骤。详见
[用户指南](docs/zh-CN/user-guide.md)。

目前有意不提供 Release 安装命令。上面的 Cargo 命令只面向贡献者；只有在可复现的 alpha 版本发布后，项目才会添加正式安装文档。

## 架构概览

```mermaid
flowchart LR
  Input["授权输入 IPA"] --> Ingest["有界 Archive 接收与检查"]
  Ingest --> Inventory["Bundle 与 Mach-O 清单"]
  Inventory --> CLI
  CLI["Rust Host CLI"] --> Policy["授权与范围策略"]
  Policy --> Doctor["Doctor 与能力探测"]
  Doctor --> Router["后端路由"]
  Router --> Helper["最小必要权限设备 Helper"]
  Helper --> Stream["受限代码区间流"]
  Helper --> Bundle["受 Bundle 根目录限制的文件流"]
  Stream --> Rebuild["Mach-O 重建"]
  Bundle --> Package["未重签分析包"]
  Rebuild --> Package
  Package --> Verify["逐二进制证据报告与 Manifest"]
  Verify --> Output["*.decrypted.ipa + Manifest"]
```

Host 端计划采用 Rust workspace。小型 Objective-C/C Helper 只执行必要的设备端操作。Sprint 0 会先比较 suspended-spawn 和 mapped-file 两个候选，再决定 MVP 后端；当前尚不宣称其中任何一个可用。各后端 Adapter 会隔离在版本化 capability handshake 之后，使项目可以增加第二种实现，同时避免把 Helper 扩展为通用远程访问服务。

## 隐私与安全原则

- 本地优先运行：App Bundle、生成的报告、日志和原始设备详情留在用户自己的机器上。用户可以另行选择，只向公开兼容性表单提交其明确要求的脱敏环境信息，不包含稳定设备标识符。
- 无自动遥测：官方软件不会自动收集或传输使用信息、IPA、日志或设备数据。GitHub Issue 是用户主动、可选的提交，并受[兼容性证据政策](docs/compatibility/README.md)约束。
- 最小采集：只有 `.app` Bundle 在范围内；receipt、`SC_Info` 和数据容器按设计排除。
- 输出可审计：结构化报告说明后端选择、逐文件状态、哈希、签名状态和证据等级。`cryptid == 0` 等元数据本身不能证明明文字节正确；没有明文 oracle 时必须标记为 `inconclusive`。
- 兼容性诚实：公开宣称支持前必须由维护者复现，并按[兼容性证据政策](docs/compatibility/README.md)保存经过脱敏的真机记录。
- 安全 fixture：仓库测试只使用项目生成的 DemoLab 产物，不使用第三方专有二进制。

## 路线图

OrchardProbe 当前处于 **Sprint 0 / 项目基础建设**阶段。

1. **Sprint 0：** 固化范围与威胁模型，定义 Schema，构建 DemoLab fixture，并用自有测试 App 验证一个边界明确的技术 Spike。
2. **v0.1 alpha：** 加入 Rust CLI 骨架、能力诊断、USB 传输、一个实测后端、重建、打包和验证。
3. **v0.3：** 扩展逐二进制覆盖，加入第二后端或回退方案，并发布真实兼容矩阵。
4. **v0.6：** 加固断点恢复、结构化集成、Fuzz 和自托管真机测试。
5. **v1.0：** 只有在独立安全审查完成且可靠性指标达标后，才稳定协议与 manifest。

路线图表达方向，不代表日期或兼容性承诺。产品蓝图和发布门槛见
[PROJECT_PLAN.md](PROJECT_PLAN.md)；权威步骤顺序和当前门禁见
[串行执行计划](docs/zh-CN/execution-plan.md)。

## 参与贡献

项目仍在成形阶段，欢迎对威胁建模、Schema 设计、安全解析器、自生成 fixture、诊断、文档和可复现兼容性报告做出贡献。提交 Issue 或 Pull Request 前请阅读 [CONTRIBUTING.md](CONTRIBUTING.md)。

请勿在 Issue 或 Pull Request 中附加专有 IPA、商业 App 的解密二进制、receipt、凭据、原始设备标识符或客户机密材料。

安全敏感问题请按 [SECURITY.md](SECURITY.md) 私下报告，不要创建公开 Issue。

## 许可证与独立性

仓库源码采用 [Apache License 2.0](LICENSE)。该许可证不会授予对 OrchardProbe 所分析的任何 App、设备、平台或内容的权利。OrchardProbe 是独立项目，与 Apple Inc. 无关联，也未获其认可或背书。
