# 用户指南：输入一个 IPA，输出一个分析用已解密 IPA

[English version](../user-guide.md)

## 当前状态

> [!IMPORTANT]
> 本指南描述首个可用 Alpha 的目标体验，当前 pre-alpha 代码尚未实现它。
> 目前 OrchardProbe 只能读取单个 Mach-O 的有界元数据、验证无需设备的
> Schema，并运行仅限库内的 IPA Archive 预检。当前没有命令接受 IPA、连接
> iPhone、解密 App 或生成 IPA。

目标体验刻意保持简单：

```text
oprobe decrypt MyApp.ipa
```

在受支持的环境中，原始 IPA 保持不变，命令生成：

```text
MyApp.decrypted.ipa
MyApp.decrypted.manifest.json
```

设备发现、已安装 App 匹配、后端选择、Mach-O 枚举、重建和验证都应由
OrchardProbe 自动完成。普通用户不应填写 PID、内存地址、设备路径、SSH
命令或可执行文件清单。

## 用户需要准备什么

虽然命令行只出现一个文件，正常流程实际需要两个输入：

1. **一个你有权分析的本地 IPA。** OrchardProbe 不搜索、购买、下载 App，
   也不接收任何账号。
2. **一台已连接、明确授权且处于支持矩阵中的越狱测试设备。** 设备上必须已经
   安装与输入 IPA 完全相同的 App 构建。OrchardProbe 不负责越狱、安装 App
   或替换设备上的构建。

加密 IPA 是磁盘产物。计划中的后端必须从授权设备上匹配的已安装进程或映射
取得对应代码字节，再在 Mac 上重建本地 IPA。因此，只提供 IPA 而没有匹配的
授权设备是不够的。

## 计划中的最简使用流程

### 第一步：确认运行条件

未来 Alpha 运行前需要：

- 确认 App 和设备属于你/你的组织，或已经获得明确测试授权；
- 确认设备型号、iOS Build 和测试环境出现在正式兼容矩阵中；
- 通过 USB 连接并解锁设备；
- 确认设备上已安装与输入 IPA 相同的版本和 Build；
- Mac 有足够空间保存输入、工作副本、输出和验证数据；
- 不要向 OrchardProbe 提供 Apple ID、密码、Pairing Record、证书、Receipt
  或签名身份。

正常命令会自动运行预检。`oprobe doctor` 和 `oprobe devices` 用于排错，
不应成为成功路径中必须手动执行的步骤。

### 第二步：运行一条命令

```text
oprobe decrypt MyApp.ipa
```

也可以选择输出位置：

```text
oprobe decrypt MyApp.ipa --output Artifacts/MyApp.decrypted.ipa
```

自动化场景可以使用 `--json`。它会用一个机器可读的命令结果替代人类可读终端
摘要，其中包含 Outcome、输出与 Manifest 路径和二进制统计。独立 Manifest
文件仍是详细且权威的证据记录。

如果只发现一台兼容设备和一个匹配构建，工具自动选择。如果存在多台设备或
匹配不唯一，工具会停止并给出简短说明，不会猜测。未来非交互选择器只使用
临时设备别名，普通日志中不显示原始 UDID。

### 第三步：取得结果

所有必需的范围内 Mach-O 都处理完成后，OrchardProbe 会原子发布最终 IPA
和 Manifest。成功摘要应类似：

```text
Input:      MyApp.ipa
Device:     device-1 (supported configuration)
Binaries:   3 processed, 0 failed, 0 skipped
Output:     MyApp.decrypted.ipa
Manifest:   MyApp.decrypted.manifest.json
Signature:  embedded signature retained but not valid for installation
Evidence:   reconstruction complete; see manifest for per-binary level
```

Alpha 前具体文案可以调整，但退出状态、输入输出路径、二进制统计、签名警告和
证据摘要必须一眼可见。

## “已解密 IPA”在本项目中的含义

输出是一个**仅供分析的产物**：

- App Bundle 结构和非代码内容来自授权输入；
- 已验证匹配的设备构建只提供重建所需的身份依据和后端批准代码区间；
- 支持范围内的主程序、Framework、动态库和 Extension 分别处理；
- 加密代码区间只会被替换为所选后端针对该二进制、Slice 和本次 Session 返回
  的字节；
- 非代码内容按严格的 Archive 和路径规则复制；
- OrchardProbe 永远不对输出重签；
- 嵌入签名可能还存在，但通常已不再有效。

项目不会把输出宣传为可安装、可再分发、功能等价或适合直接执行，也不提供
签名和安装功能。

对普通授权 App，通常不存在独立的已知明文 Oracle。工具可以完成重建和结构
验证，但 Manifest 中的明文证据仍可能是 `inconclusive`。只有匹配的首方
Oracle 才能提高证据等级；`cryptid == 0`、ZIP 有效或传输 Hash 一致都不能
单独证明明文字节正确。

## 一条命令内部会做什么

计划中的 `decrypt` 会自动执行：

1. 把 IPA 当作不可信 Archive 验证，拒绝危险路径、链接、特殊文件和无界数据。
2. 枚举 App Bundle 中所有范围内 Mach-O 与 Slice。
3. 检查 Host 和设备能力。
4. 将 IPA 与同一已安装 App 构建匹配；任何歧义或不一致都停止。
5. 根据已观察能力选择一个明确支持的后端。
6. 只收集绑定本次 Session 的 Bundle Entry 和代码区间。
7. 在私有工作目录重建每个 Mach-O。
8. 验证字节数、Hash、结构、二进制覆盖和证据状态。
9. 打包到临时 Archive，验证后原子重命名为最终 `*.decrypted.ipa`。
10. 写出独立的版本化 Manifest，解释每个结果。

如果必需二进制失败、Target 变化、设备断开、超过资源上限或输出验证失败，
工具不应发布最终 IPA。原始 IPA 永远不原地修改。

## 常见失败

| 错误类别 | 含义 | 用户应该怎么做 |
|---|---|---|
| 没有受支持设备 | 当前连接环境没有经过验证的支持记录。 | 连接兼容矩阵中的测试设备。 |
| 多台设备 | 自动选择存在歧义。 | 断开不用的设备，或选择提示中的临时别名。 |
| 已安装构建不匹配 | 输入 IPA 与设备 App 不是同一验证构建。 | 在 OrchardProbe 外准备匹配构建后重试。 |
| 不支持的二进制或 Slice | 至少一个必需 Mach-O 超出能力范围。 | 阅读 Manifest，不要把部分产物当作完成的 IPA。 |
| Target 发生变化 | App、映射、设备或 Session 身份在过程中变化。 | 开始一次干净运行；工具不会静默切换 Target。 |
| 磁盘或配额不足 | 即将超过明确的安全上限。 | 释放空间或使用更小的授权 Fixture；工具不会自动放宽限制。 |
| 证据不足 | 重建完成，但没有独立明文 Oracle。 | 仅在授权分析中使用，并阅读逐二进制证据。 |

错误信息不能建议用户关闭 no-follow、扩大设备权限、改用通用 Shell，或静默切换
到未评审后端。

## 隐私与本地数据

OrchardProbe 本地优先且没有自动遥测。官方工具不得上传输入/输出 IPA、App
字节、原始日志、稳定设备标识符、凭据或 Session Material。公开 GitHub 报告
只能使用兼容性模板要求的脱敏字段。

临时工作文件保留在 Mac，并在正常结束时删除。失败清理必须确定性完成；未来
如果增加 `--keep-workdir`，必须由用户显式开启并警告其中可能包含敏感本地产物。

## 当前真正存在的命令

当前命令只是开发基础：

```text
oprobe doctor [--json]
oprobe inspect <MACH-O> [--json]
oprobe demo [--json]
oprobe verify <manifest.json> [--json]
```

它们不处理 IPA，也不连接设备。从源码运行方式见
[Rust workspace 指南（英文）](../development/getting-started.md)，整体原理见
[技术总览](technical-overview.md)。未来的 `oprobe verify <ipa-or-app>` 与当前
只验证 Manifest 的 `verify` 命令是两个接口；前者尚未实现。内部的
[IPA 预检（英文）](../development/ipa-preflight.md)是经过测试的库基础，不是新增
命令。

## 常见问题

### 只给 IPA、不连接设备可以吗？

加密 App 不可以。本地 IPA 是重建输入；授权设备上匹配的已安装构建提供设备端
代码证据。无需设备的模式只能读取元数据，或使用项目自有合成 Fixture 演示流程。

### OrchardProbe 会安装或运行我的 IPA 吗？

不会。安装、重签和执行输出不在项目范围内。经过评审的窄后端可能只触发完成
操作所必需的最小 Target 生命周期，但不能变成通用 App 启动器或修改器。

### 可以把 App Store 账号交给 OrchardProbe 吗？

不可以。OrchardProbe 不接收 Apple ID、不购买 App，也不下载账号内容。输入
IPA 和已安装构建必须由你通过自己的授权流程准备。

### 是否支持所有设备和 iOS 版本？

不支持。兼容性按一个个真机实测 Tuple 增加。相邻 iOS 版本或越狱环境在单独
记录前都属于未验证。

### 为什么 IPA 旁边还有 Manifest？

IPA 是分析产物，Manifest 是审计记录。它保存后端选择、逐二进制结果、Hash、
证据等级、签名状态、警告和失败原因，避免把“成功生成 ZIP”误当成完整成功。
