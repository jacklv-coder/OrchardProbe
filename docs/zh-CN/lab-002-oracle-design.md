# LAB-002 固定区间自观测 Oracle 设计状态

状态：**无设备设计，尚未实现或真机验证**

跟踪 Issue：[#55](https://github.com/jacklv-coder/OrchardProbe/issues/55)

完整规范见
[英文设计](../research/lab-002-oracle-design.md)。本页用于中文学习和进度定位。

合并本设计不授权签名 Build、TestFlight 上传、安装、真机观察、设备 Backend、
砸壳实现或 IPA 重建。精确的新版本/Build 仍须用户另行明确授权。

## 这一步解决什么

LAB-001 已证明：只靠 TestFlight、公开 CoreDevice 元数据和公开 LLDB，无法同时
证明精确已安装 Lineage、初始保护状态和对应明文区间。

LAB-002 设计一个仅用于项目自有 DemoLab 的证据机制：

1. Mac 在上传前，从干净 Commit 直接构建的 Archive 生成固定区间预期明文
   Oracle，再用绑定到同一精确 Build 的导出 IPA 独立复核同一区间；
2. DemoLab 主程序、DemoFramework、DemoShareExtension 各自只读自己的已安装
   Mach-O 文件和映射映像；
3. 每个组件只报告固定元数据、相对 Slice、可执行文件起点或未 Slide 映像的数值坐标
   和 SHA-256，不输出可执行字节、绝对路径、运行时地址或调用者选择的坐标；
4. Host 把两次干净 Session 的报告与上传前冻结 Oracle 严格比较，并要求两轮来自
   同一台物理设备、同一 App 安装、同一硬件型号和同一 iOS 版本/Build；
5. 安装前及每轮采集前都必须重新完成带策略版本的 RFC-0001 授权使用确认；设备
   所有权、安装状态、Build 上传授权或上一次确认都不能代替本次确认。

它不是通用读取器。入口不接收路径、PID、映像名、地址、Offset、Length 或架构，
调用者无法把它改成任意文件或任意内存访问。

这里的“精确 Build Lineage”只表示冻结的源码/Build、授权 Target、Mach-O UUID、
Slice、坐标和区间 Hash；Apple 会处理 TestFlight 包，因此 Go 也不能证明上传 IPA
与 Apple 安装的完整 Package 逐字节相同。

## 完整清单和固定区间

清单永远固定为：

- `DemoLab.app/DemoLab`
- `DemoLab.app/Frameworks/DemoFramework.framework/DemoFramework`
- `DemoLab.app/PlugIns/DemoShareExtension.appex/DemoShareExtension`

上传前清单冻结三个可执行文件的每个 Slice。运行时发现缺失、额外或变化的 Slice
都必须记录，不得在观察后删掉。

每个 Target 将包含唯一的 `__TEXT,__oprobe` 纯指令 Section。整个 Section 是该
Slice 唯一固定区间：

- 长度必须为 64–1,024 字节且非空；
- 不能包含 Relocation、Rebase、Bind、Chained Fixup、可变数据或内部 Padding；
- 不能依赖 Symbol 或调用者提供 Offset；
- 上传前冻结 File Offset、相对 VM Offset、Length 和预期明文 SHA-256；
- Apple 处理后任一字段变化都直接 No-Go，不重新选择“容易匹配”的区间。

这里的“变化”只指上传前 Archive/IPA 的身份、坐标、长度、明文字节不一致，以及
安装后的清单、UUID、坐标、长度或映射明文漂移。安装后磁盘区间变成与 Oracle
不同的密文是保护门禁要求的预期现象，不会被误判成区间漂移。

## 三方证据链

| 证据方 | 负责内容 | 单独不能证明 |
|---|---|---|
| Mac 上传前 Oracle 生成器 | 私有授权 Target 清单、同一源码构建 Archive、Commit/Build、IPA Hash、完整 Slice 清单、固定区间和预期明文 Hash | 已安装身份、初始保护或映射明文 |
| 三个组件的自观测器 | 自己的授权身份绑定、已安装 UUID/签名摘要、加密范围、磁盘 Hash、映射 Hash | 映射 Hash 就是预期明文 |
| Host Verifier | 验证私有授权清单/Key、预上传证据、本地 IPA、外部 Digest 绑定的 Oracle、签名 Enrollment/Selection 集，以及两轮签名 Intent/Challenge/Export/Binding 和 Session | 硬件 Attestation、完整安装包身份或新的设备、文件、进程、内存、Apple 签名能力 |

初始保护必须同时满足：

- 精确安装 Slice 与冻结 Slice 一致；
- 已安装签名必须分别报告 Presence/Kind/Validation，且精确为
  `present` / `cms` / `valid`；
- 有效加密命令为 `cryptid == 1`；
- 非空 `cryptoff/cryptsize` 完整覆盖固定区间；
- 磁盘区间可由组件自己的只读描述符读取；
- 磁盘 SHA-256 与预期明文 SHA-256 不同；并且
- 随后的同一区间映射 SHA-256 等于冻结预期明文 SHA-256。

所以 `cryptid`、UUID、签名、安装成功、单个不同 Hash 或单个匹配 Hash 都不能
独立构成通过证据。

签名字段复用 Export Manifest 的封闭值：Presence 为 `present/absent`，Kind 为
`cms/ad_hoc/unknown/not_applicable`，Validation 为
`valid/invalid/not_checked/not_applicable`。报告还写固定 Validator ID/Revision
和存在时的签名 Superblob SHA-256。只有显式、已评审 Validator 对各 Role 稳定
Descriptor/签名结构实际校验后才能写 `valid`；成功启动、Entitlement、Digest、
UUID 或 `cryptid` 不能推断验证成功。没有可用的公开平台 API 或有界且独立测试的
实现时必须写 `not_checked` 并得到 No-Go；Absent、Ad Hoc、Unknown、Invalid、
矛盾或 Unchecked 都不能通过。

预期明文 Hash 从干净 Commit 直接构建的 Archive 固定 Section 生成；随后独立
Hash 导出 IPA 的同一 Slice/区间，并要求身份、坐标、长度和 Hash 全部一致。
Archive 和 IPA 对应 Slice 都必须报告 `cryptid == 0`，但该字段只是与源码构建
来源配套的一致性检查，不能单独证明明文。缺少加密命令、非零 `cryptid` 或两份
区间不一致都会在上传前拒绝发布 Oracle。

编译前先在 Git 外 Owner-Only 目录建立
`lab-002-authorized-targets-v1.json`。它包含随机 256-bit Identity Nonce，
一套本实验专用 Ed25519 Host 授权公钥/Key ID，以及三个 Role 精确获授权的
`CFBundleIdentifier`、CodeDirectory Identifier、Team Identifier、
`application-identifier`、Team Entitlement 和 App Group Entitlement 的值或
“必须不存在”。生成器必须从 Archive 和导出 IPA 独立读取并匹配这些值。对应私钥
文件必须恰好包含 Raw 32-byte Ed25519 Private Seed，并以 `0400` 保存在 Git 外
Host 授权协调器中；打开时不得跟随符号链接，PEM、尾随字节或其他编码均拒绝。
私钥不能进入源码、IPA、设备或公开结果。
Key ID 精确等于 Raw 32-byte 公钥的 SHA-256；公钥/Key ID 编译进主程序并由 Build
Binding 绑定。
`0400` 只防止意外泄露，不代表不可导出或 HSM：Owner 进程/用户仍能复制私钥。
本实验因此信任未被攻陷的 Owner Account/协调器，在保留期后销毁 Key，且不对被
攻陷 Host 或恶意操作者提出授权安全声明。

授权清单 SHA-256 会与源码 Commit、版本/Build、Configuration、Observer Revision
和 Xcode/SDK/XcodeGen/Fastlane 身份一起规范化为 `build_binding_sha256`。同一
Build Binding 与 Identity Nonce 编译进三个 Target。每个组件只从自己的 Bundle
和嵌入签名元数据规范化实际身份，再以 Nonce、Role 和身份元组计算
`target_identity_binding_sha256`；报告只写该 Digest，不写 Bundle ID 或 Nonce。
任一 Bundle ID、签名 Identifier/Team、App Group、选定 Entitlement 或应缺失
状态变化都会 Fail-Closed。该机制用于防止误绑定，不宣称能对抗可修改并重签
Observer 的攻击者。

私有授权清单包含真实标识，只保留在 Git 外 `0400` 目录；该清单文件本身不进入
IPA、Oracle、报告或公开结果，其 SHA-256 被 Build、预上传证据、Oracle 和收集
Intent 绑定。只有 Identity Nonce 与 Host 授权公钥/Key ID 这几个清单值会按设计
编译进 Observer；真实目标标识与授权私钥绝不编译或导出。Oracle JSON 不包含自己
的 Hash；只有最终 Canonical Bytes 关闭后才计算 SHA-256，并把它存入独立预上传
证据，避免自引用。

四个跨组件 Binding 都不是拼接字符串或重序列化 JSON 后 Hash。英文规范定义了
唯一字节格式：Domain Tag 带结尾 NUL；字符串用 `u32` Big-Endian 字节长度加
Strict UTF-8；文本必须 NFC 且无 NUL/控制字符；Hash 和 Commit 使用定长小写
Hex。`build_binding_sha256` 按固定顺序包含源码、版本/Build、Release、
Observer Revision、授权清单 Hash、Xcode/SDK、XcodeGen 和 Fastlane/Gem Lock
身份。Target 身份格式依次包含 32-byte Nonce、单字节 Role、Bundle ID、
CodeDirectory Identifier/Team、带 Presence Byte 的两个标量 Entitlement，以及
去重并按 UTF-8 Byte 排序的 App Group 数组。Target 身份集合则按三个固定 Role
顺序 Hash 三个 Raw 32-byte Digest。字段缺失、额外、重排或非法编码都拒绝。

`device_installation_binding_sha256` 还按固定格式 Hash 私有 Identity Nonce、
设备 Enrollment 公钥、一次安装专用的随机 256-bit Nonce、只在设备内读取且不保存/导出的
Identifier-for-Vendor，以及固定平台查询得到的硬件型号标识、iOS Product Version
和 iOS Build。安装 Nonce 只保存在 App Group 内固定、禁止备份的状态记录中。
更换设备、重装/重置 App、更新 iOS、标识缺失或任一环境字段变化都会使 Binding
变化或无法生成，从而使实验失效；原始稳定设备标识和安装 Nonce 永远不离开设备。
固定查询为 `UIDevice.identifierForVendor`、`hw.machine`、
`kern.osproductversion` 和 `kern.osversion`；后三者生成报告中的脱敏硬件型号、
iOS Product Version 和 iOS Build。它们必须符合封闭语法、严格可打印 ASCII 且
不超过 32 Byte，查询缺失、非法字符或截断都 Fail-Closed。Verifier 通过已评审、
带版本的本地表把硬件型号映射到 SoC Family；表版本和派生 SoC 只进入私有测试
记录及脱敏兼容性行，不能选择或扩大 Observer 操作。

Host 对每份安装/Run 授权使用 Ed25519 签名。签名输入是固定 Domain Tag，加带
`u32be` 长度的精确 Canonical 授权确认 Bytes，再加带长度的精确 Enrollment 或
Run Challenge Core Bytes。导入信封内嵌这两个规范对象、Key ID 和 64-byte
Signature；App 在任何状态写入或观察前，必须用编译进 Build 的公钥复核规范 Bytes、
签名、策略、Scope、Build、Experiment/Run 与时间窗。只有 Hash/Boolean 而无有效
签名不能授权操作，且不允许算法协商或回退。

FAT Mach-O 的 `cryptoff/cryptsize` 是 Slice 内相对坐标。实现必须先用检查溢出的
加法把它们和固定 Section Offset 分别转换为整个文件绝对区间，再判断覆盖；不得
直接拿相对 `cryptoff` 比较绝对 File Offset。Section 还必须完全位于可执行
`__TEXT` 的 File-Backed 区域，并满足
`section.offset - segment.fileoff == section.addr - segment.vmaddr`；导出的
VM Offset 也必须等于 `section.addr - image_text_vmaddr`，否则 Hash 前直接拒绝。
报告会分别标注相对 Slice、可执行文件起点和未 Slide 映像的坐标。

## 报告和边界

每个 Session 固定四个文件：

```text
session.json
main-app.json
framework.json
share-extension.json
```

上述四个内部 Session/Report 文件各自最大 32 KiB；该上限不适用于另有
512 KiB 上限的 Session Export。清单必须正好三个 Role，每个 Slice 正好一个固定区间，
区间 64–1,024 字节。字段封闭，禁止重复 Key 和自由文本错误。所有 Canonical JSON
都严格采用 RFC 8785 JCS：无 BOM UTF-8、ECMAScript String Escape、按 UTF-16
Code Unit 排序 Key、无无意义空白；同时只允许 Schema 限定的整数，拒绝浮点和
Negative Zero，所有字符串输入必须已经是 NFC。Verifier 会在 Schema 校验后重新
编码并要求与原 Bytes 逐字节相同，因此替代 Escape、Key 顺序、空白、数字拼写、
Lone Surrogate、非 NFC 和非法控制字符都会拒绝。Export 内嵌报告也使用同一 JCS
String Escape；解码后的 UTF-8 Bytes 必须与独立报告完全相同且 Hash 一致。
通用 256 Scalar String 上限不适用于这个内嵌字段：每份内嵌报告最多 32 KiB
解码 UTF-8，JCS Escape 后最多 64 KiB。报告禁止控制字符，只有 Quote 和
Reverse Solidus 会扩为两个 Byte，因此四份报告和封闭 Envelope 仍严格小于
512 KiB。

报告只含：

- Session、Collection ID、Run Ordinal、Challenge Hash、Observer Revision、
  源码 Commit 和版本/Build；
- Role 与 Fixture 相对路径；
- `target_identity_binding_sha256`，但不包含原始私有身份或 Nonce；
- Thin/Fat 和完整 Slice 清单；
- CPU 类型、UUID、已安装签名 Presence/Kind/Validation、Validator ID/Revision
  和存在时的代码签名摘要；
- 固定 File Offset、相对 VM Offset 和 Length；
- `cryptoff`、`cryptsize`、`cryptid`、覆盖结果；
- 磁盘和映射 SHA-256；
- 固定 Outcome 和 Reason Code。

禁止绝对安装路径、运行时地址、原始字节、私有 Bundle ID、Identity Nonce、
设备标识、Receipt、凭据、任意日志或调用者文本。

Verifier 会先在各轮内部验证授权确认、Collection、Ordinal、Challenge、Session、
Counter 和时间字段，并要求两轮 Device/Installation Binding、硬件型号和 iOS
Version/Build 完全相同；再从观察投影中移除每轮必然不同的确认 Hash 与控制字段，
但保留授权策略版本。两轮剩余的源码/Build、环境、Target 身份、清单、坐标、Hash、
Outcome 和 Reason 必须逐字节相同。

## Session 和两次干净运行

主程序提供一个没有参数的“Start clean LAB-002 run”动作。它首先要求固定报告
目录不存在或为空，绝不会删除旧报告；之后才从固定 Inbox 校验并消费一个有效
Host Challenge，创建绑定 Collection ID、Run Ordinal 和 Challenge Hash 的随机
256-bit Session，写主程序报告，调用 Framework 的零参数自观测，然后提示维护者
显式打开 Share Extension。Challenge 缺失、格式错误、过期、已消费或 Build
Binding 不符时不得创建 Session，也不能影响已有报告。

单调 Counter 不保存在会被清理的报告目录，而来自 App Group 内固定的
`state/run-counter-v1.json`。该封闭记录最大 1 KiB，只含 Schema、同一 Build
Binding 和一个正好 16 位小写 Hex String 表示的 Big-Endian 无符号 64-bit
Counter。每个 Host 签名 Run Challenge 还必须绑定下一次精确 Counter：Run 1 为
`0000000000000001`，Run 2 为 `0000000000000002`。`session.json` 与 Role 报告使用
同一固定宽度格式；比较时先解码成整数，不能按 String 比较。主程序串行状态协调器
拒绝 Symlink 和非普通文件，完整有界读取并校验后执行带溢出检查的
`previous + 1`，且结果必须精确等于签名值。状态文件不存在时只允许 Run 1 初始化
为 `0000000000000001`；现有记录格式错误、Build Binding 不符、Ordinal/前值/
签名期望值不符时必须失败，不能重新初始化。随后在同目录排他创建临时文件、Flush，
并在创建 `session.json` 前原子替换固定状态文件。崩溃可以消耗
一个 Counter，但不能复用。报告清理永远不能删除或重置状态文件；两轮之间重装/
重置 App 或改变 Build Binding 会使实验无效。Extension 无权分配或更新 Counter；
`ffffffffffffffff` 表示已耗尽并拒绝新运行。

这个由 Host 签名并与持久 Counter 核对的下一值就是设备端已消费 Challenge 状态：
Run 1 完成 Counter 提交后，复制的 Run 1 信封仍期望值 1，但设备下一值只能为 2，
所以会在 Session/观察前拒绝；Run 2 同理。App 不允许跳号或任意更高值，也不会把
报告目录 Cleanup 当作 Challenge 状态 Cleanup。

同一固定状态目录还包含最大 1 KiB 的封闭
`state/installation-nonce-v1.json`，精确只写 Schema/Profile、Build Binding、
Raw Enrollment 公钥的 64 字符小写 Hex 和一个随机 64 字符小写 Hex Nonce。只有
通过 Host 签名验证的安装 Enrollment 动作能按
同一 No-Follow、排他创建、Flush 和目录 Fsync 规则建立；它同时在 Keychain 生成
固定 Service/Account/Access Group、`kSecAttrSynchronizable == false` 且
`kSecAttrAccessibleWhenUnlockedThisDeviceOnly` 的 Ed25519 Enrollment Key。两轮都只能读取既有状态，不能
新建、替换、修复或导出私钥/Nonce；每次加载必须从 Keychain 私钥派生公钥并与状态
文件逐字相同，再计算 Hash/Device Binding。缺失、畸形、被替换、从备份恢复、Key 不匹配
或 Build 不匹配都在观察前失败；Cleanup 永远不能删除固定状态或 Enrollment Key。

主程序和 Extension 使用已注册的 App Group 容器；路径只能通过 Apple 的
`containerURL(forSecurityApplicationGroupIdentifier:)` 获取，不能手工拼接。
每个 Role 只能排他创建一次报告，不允许覆盖。App Group 只供首方 App 与 Extension
内部协调；Host、CoreDevice File Service 和任何 Helper/Backend 永远不得读取、
写入、列举或解析该容器，所以没有修改 RFC-0001/0002 的共享容器禁令。

Import、Start 和 Discard 必须经过同一个主程序 Inbox 协调器：先通过 No-Follow
Descriptor 对固定 Owner-Only Lock File 取得排他 Advisory Lock；所有能发布、消费
或丢弃 Record 的入口都必须持锁，Extension 无 Inbox 操作。持锁期间以目录 Handle
相对方式打开 Record，要求 Directory Entry 与打开 Descriptor 身份一致，再使用
不覆盖 Rename 把该精确 Entry 原子隔离到固定操作专用 Quarantine 名称；目录 Fsync
并再次核对 Inode 后才能读取或删除。身份变化、已有 Quarantine、Lock 失败或崩溃
残留都阻塞全部 Inbox 操作并记录失败，禁止对未加锁或重新解析的路径执行 Unlink。

主程序另有显式“Import LAB-002 authorization”文档动作。iOS 提供用户选中的文档
URL；Handler 最多读取 16 KiB，只接受封闭且签名的 Enrollment/Run Challenge
Envelope，忽略来源文件名，并在持锁时把验证后的 Canonical Bytes 排他发布到固定
内部 Inbox。它不向 Observer 暴露通用文件浏览、路径、Target 或 Range。

另有零参数“Discard stale LAB-002 authorization”动作，只能在上述 Lock/原子隔离
流程下操作固定 Inbox Record。只有隔离后确认封闭 Record 已过期、格式错误或 Build
不匹配，才能删除该 Descriptor 对应 Quarantine Entry 并 Fsync Inbox。它不能删除
当前有效信封、接收路径或替换 Record。执行后对应 Enrollment/Run Intent 被放弃，
该 Experiment/Collection ID 与 Challenge 永远不能复用；Host 必须保留控制记录，
再建立全新签名信封，不能静默重试。

首次安装前，Host 必须交互式取得一次 RFC-0001 授权使用确认；每轮运行前还要取得
一次全新确认。每份最大 3 KiB 的 `authorized-use-ack-v1.json` 都包含受支持策略
版本、随机 Experiment ID、封闭操作类型、精确 Build Binding、私有授权 Target
清单 Hash、固定技术 Profile、适用 Run Ordinal、封闭数据类别/保留规则、确认时间/
有效窗和 `confirmed: true`。确认界面明确列出所选自有专用设备、首方 DemoLab、
固定区间磁盘/映射 Hash、导入/导出数据、保留规则和时间范围。安装与每轮完整
Import/Start/Extension/Export/Cleanup 是三个独立真机操作包，分别要求紧邻的确认；
静默、设备所有权、安装、Build 上传授权或旧确认都不是 Consent。
确认还必须包含四个精确为 `true` 的封闭断言：操作者拥有 Target 或取得 Owner
明确授权；只在批准的 App/设备/技术/数据/时间内行动；理解授权不自动使绕过行为在
所有法域合法；会保护本地输出且绝不用 OrchardProbe 对其重签、安装或再分发。
任一缺失/False 都不能签名，App 与 Verifier 也必须拒绝。流程不得索取或记录授权
信、客户合同、Apple ID 凭据、Receipt 或其他证明。
LAB-002 唯一接受的 `authorization_policy_version` 是精确 ASCII 值
`orchardprobe.authorized-use.v1`；未知值 Fail-Closed，未来版本必须先评审并修改
设计/Schema，不能协商或回退。

安装确认后，Host 生成随机 Enrollment Challenge 和封闭 Core，把确认与 Core 一起
签名为最大 16 KiB 的安装 Enrollment Envelope。操作者只在确认的设备安装精确
Build，再通过文档动作导入该信封。App 在创建任何状态前验证 Host 签名，随后生成
固定环境事实并要求等于签名的预期硬件/iOS 值，随后才生成
仅本设备 Enrollment Key 和安装 Nonce 并计算
Device/Installation Binding。它用 Enrollment Key 签名包含 Host Envelope/确认
Hash、Challenge Response、Experiment/Build、Enrollment 公钥、Device/Installation
Binding 和脱敏环境事实的 Receipt，再只通过 Share Sheet 导出。Host 验证 Receipt
自签名、Host Challenge、Build/环境后，Host 与 DemoLab 分别显示由 Envelope Hash、
Enrollment 公钥、Device/Installation Binding 和 Device-Selection Nonce 完整
SHA-256 派生的 64 字符小写 Hex Fingerprint（固定每 4 字符分组，不能截短）。操作者
必须在所选实体 iPhone 与 Host 间逐字比较并显式确认；Host 排他写入无自由文本的
`device-selection-confirmation-v1.json` 后，才可关闭
`device-enrollment-binding-v1.json`。其中绑定安装确认/Envelope/Receipt/Selection
Confirmation Hash、Enrollment 公钥、Device/Installation Binding、环境事实和
完成时间。这是实体设备选择仪式，不宣称硬件 Attestation；Run 1 在绑定完成前不得
建立。设备开始生成 Key/Nonce 后发生崩溃、半截 Receipt、签名错误或未导出都使
本实验 No-Go，不能删状态后重新 Enrollment 成 Pass。

完成每轮确认后，Host 建立独立 Owner-Only Run 目录，创建随机 Challenge、
Collection ID、Run Ordinal 和下一次精确 Counter 的封闭 Core；Core 已包含
Build/策略、非空 Enrollment
Binding Hash/公钥、已建立的 Device/Installation Binding 与时间窗。Host 把本轮
确认和 Core 签名为最大 16 KiB 的 `collection-challenge-v1.json` Envelope。
Intent 绑定该文件 Hash/签名、同一精确 Counter、安装确认与 Enrollment Binding
Hash、本轮确认、
授权清单/Target 身份集合、工具链、预上传证据、IPA、外部 Oracle 和预期清单。
Run 1 的 Prior Binding 为 `null`，但 Enrollment/Device Binding 已经非空；Run 2
还必须写入 Run 1 Binding Hash。维护者通过 AirDrop 或 Files 显式导入签名信封；
任何 OrchardProbe Host/Helper API 都不能访问 App Group，且自由路径/Target/Range
不能进入 Observer。

全部 Wall Clock 字段都是带符号 Unix UTC 整秒。Mac 关闭每份授权确认时只采样一次
`CLOCK_REALTIME`，令 `not_before` 等于该值、`not_after` 精确等于
`not_before + 900`，并拒绝溢出或同一操作内时钟倒退。每轮 Challenge/Intent 必须
复制对应确认的精确时间窗，安装也必须在安装确认时间窗内完成。iPhone 在 Import、
创建 Session 前、每个 Role Phase 前和完成前读取系统 Wall Clock，只接受
`not_before - 120 <= device_now <= not_after + 120`（全部 Checked）。120 秒是
Mac/iPhone 最大允许偏差，900 秒是授权/Challenge 最大名义有效期。Verifier 要求
每份确认精确 900 秒窗口、每轮确认与 Challenge/Intent 时间窗完全一致、两轮窗口
有序且不重叠、报告时间位于同一偏差扩展区间，且设备时间不倒退。偏差超过
120 秒、传输过期或时钟跳变都得到 `stale_or_conflicting_session`：观察前只能走
有界 Stale Purge 并建立全新 Collection；Session 创建后发生则方法级 No-Go。

主程序通过 Lock/Quarantine 流程打开固定 Challenge，检查 16 KiB 封闭 Envelope
及两个内嵌 Canonical 对象，验证编译公钥的 Ed25519 签名、Build、Ordinal、授权
策略/Scope、Enrollment Binding/公钥、时间窗和持久状态所要求的下一次精确 Counter。
它只加载既有 Device-Only Key 与
安装 Nonce，重新查询环境并计算 Device/Installation Binding；两轮都必须与
Enrollment 预期完全相同。持锁且 Record 仍在 Quarantine 时先原子提交该精确
Counter 增量，之后只删除 Descriptor 匹配的 Quarantine Entry、Fsync 并建立
Session。Session 和三个 Role 报告都绑定授权 Envelope、Enrollment 与
Device/Installation Binding、脱敏环境及 Challenge Hash。隔离或消费后崩溃即使
本轮失败，禁止复用或静默重建 Challenge。

四个内部报告完成后，主程序才提供显式“Export LAB-002 evidence”动作，生成最大
512 KiB 的 `lab-002-session-export-v1.json`。它按固定顺序包含四个固定逻辑文件名、
各自 SHA-256，以及作为 JSON String 编码的精确 Canonical Report UTF-8 Bytes；
同时由 Device-Only Enrollment Key 对固定 Domain 与未签名 Export Canonical Bytes
签名。禁止设备路径、可执行/映射字节、任意文件名和 Note。唯一出口是 iOS 系统
Share Sheet，维护者通过 AirDrop 或 Files 显式发送到 Mac。

Cleanup 与 Start 是分离动作；只有完整 Session Export 已构造，且操作者显式确认
Mac 已安全收到后才启用。它会先用该 Export 重新 Hash 精确四份报告，然后只删除
固定报告子树。Collecting、Failed、未 Export 或 Export 不匹配的 Session 都不能
清理；任何不完整/失败观察会直接终止该精确实验为 No-Go，不能靠清理重试成两轮
Pass。

每轮只接受用户在 Host 上选中的一个本地 Export。Host 用 No-Follow 私有打开，
验证外层封闭 Schema，提取并重新 Hash 正好四份报告，再排他保存并创建 Binding。
Host 还必须验证 Enrollment Key 对 Export 的签名。Binding 包含安装/本轮授权确认、
Host 授权 Envelope、Enrollment Binding、Intent/Challenge/签名 Session Export
Hash、Collection ID、Ordinal、签名及实际 Counter、Session ID、Enrollment 公钥、
Device/Installation Binding、四个报告 Hash 和结束时间。两轮 Collection、
Challenge、Session 都必须不同，Counter 必须精确为 1、2，且 Enrollment/Device
Binding、硬件型号和 iOS Version/Build 完全一致；任何产物不得跨 Run 复用、
覆盖或移动。

Verifier 必须要求一组完整安装确认/Host 签名 Envelope/Device 签名 Receipt/
Enrollment Binding、两组完整本轮确认/Host 签名 Challenge/Intent/Device 签名
Export/Binding 和两个完整 Session。它复核全部 Host 授权签名、Receipt 与两份
Export 的 Enrollment Key 签名、每份确认的策略/Scope/顺序/时间/操作/一次性使用、
Enrollment Challenge 与非空绑定，再验证私有来源、不同 ID、时间窗、Run 2 链、
同一 Enrollment/Device Binding 与环境以及全部 Hash，最后才比较 Build/Target/
UUID/清单/区间。缺失、重复、调换、复用、签名错误、无 Challenge、断链、Export
错误、混用设备/安装/OS 或不匹配都得到 `stale_or_conflicting_session`。

Intent 中的 IPA Hash 只证明本地预上传证据和 Oracle 来自该精确 IPA；它不会写进
设备报告，也不能证明 Apple 安装的完整 Package 与上传 IPA 逐字节相同。设备端只
绑定经 Apple 处理后仍稳定的授权 Target、UUID、Slice、固定坐标和固定区间证据。

Go 必须来自两次运行：

1. 在安装前完成带策略版本的安装确认并签名 Enrollment Envelope，把精确 Build
   安装到所选自有专用 iPhone，导入信封、生成并导出 Device 签名 Receipt，Host
   验证后逐字比较实体 iPhone/Host 的完整 Fingerprint，记录 Selection Confirmation
   并关闭 Enrollment Binding；之后不得换机、重装/重置 App 或更新 iOS；
2. 在 Run 1 前完成全新确认，确认报告目录为空，建立带非空 Enrollment Tuple 的
   签名 Run 1 Challenge/Intent，通过 iOS 文档 UI 显式导入，并终止旧进程；
3. 新启动主程序，产生 App/Framework 报告并从 Share Sheet 显式启动 Extension；
4. 通过系统 Share Sheet 显式导出完整 Session 到 Mac 并关闭 Run 1 Binding；
5. 完成上述受限清理并再次终止进程；在 Run 2 前完成另一份全新确认，建立并显式
   导入链到 Run 1 Binding 与 Enrollment/Device Binding 的签名 Run 2
   Challenge/Intent；
6. 重复完整观察、显式导出并关闭 Run 2 Binding；
7. Verifier 验证三份确认及 Host 签名、Enrollment Receipt/Selection/Binding 与
   Device 签名、全部私有来源产物、两组控制记录和两个 Session；
8. 分别验证并移除每轮 Collection/Ordinal/Challenge/Session/Counter/时间控制
   字段后，以同一 JCS 编码的剩余身份、坐标、Hash、Outcome 和 Reason 必须一致。

崩溃、Extension 未执行、报告缺失、重复、过期、重放、Slice 变化或两轮不一致，
都不能通过重试后静默忽略。

## 下一实现门禁

下一 PR 仍然完全无设备，必须完成：

- 三个 Target 的固定 Section 和零参数 Observer；
- 有界 Mach-O 解析与检查溢出的 File/VM 转换；
- Authorization/Oracle/Report/Challenge/Control/State Schema、Binding 编码和
  Host Verifier；
- Simulator 与合成 Fixture 的正常和恶意测试；
- Fat Mach-O、额外 Slice、UUID/区间不匹配、Fixup、溢出、`cryptid == 0`、
  Bundle ID/签名 Identifier/Team/App Group/Entitlement 不匹配、Nonce 不匹配、
  非零 FAT Slice Offset 的坐标归一化、Oracle 来源 `cryptid != 0`、
  Archive/IPA 区间不一致、加密范围未覆盖、磁盘 Hash 等于 Oracle、映射 Hash
  不匹配、Binding 编码歧义、授权确认缺失/过期/复用/策略版本不支持、任一 RFC-0001
  Consent 断言缺失/False、Host 授权
  签名无效/伪造/重放、Enrollment Receipt/公钥/Selection Confirmation/Binding
  缺失或不匹配、Fingerprint 无效/截短、预期/观察环境不一致、Receipt/Session
  Export 签名无效、Run 1 使用未 Enrollment 安装、混用物理设备/安装/OS、
  Identifier-for-Vendor 缺失/畸形、Enrollment Key 或安装 Nonce 丢失/重置、
  签名 Absent/Ad Hoc/Unknown/Invalid/Not Checked/矛盾或 Validator Revision 变化、
  时间窗格式错误/时钟偏差过大/时钟倒退、Challenge
  缺失/过期/复用、Cleanup 后复制 Challenge、签名期望 Counter 不符或跳号、
  Stale Inbox 清理或第二次放弃观察前尝试、Session Export 错误、
  重复/调换 Collection Set、Run 2 断链、File/VM Segment Delta 不一致、Counter
  溢出/回滚/重置或固定宽度编码错误、替代 JSON Escape/排序/数字拼写、非 NFC、
  Stale/Replay 等 Fail-Closed 测试；
- 内部 App Group Session 与文档 Import/Export 的原子写入、排他创建、大小/
  Escape、清理和重复报告测试；并发 Import/Start/Discard、Inode 替换、Quarantine
  残留和 Lock 失败测试；并证明不存在 Host/Helper 容器访问操作；
- 威胁模型、Runbook、兼容性模板和双语状态同步；以及
- 本地/远端 Codex CR、全部 CI 与 Review Thread 清零。

Simulator 没有受保护 TestFlight 二进制，只能验证结构和报告 Plumbing；它必须
得到 Inconclusive，不能被写成真机证据。

## Go / No-Go

Go 要求三个 Role 的每个冻结 Slice 在两次干净运行中全部满足：

- 精确 Commit/Build/IPA/Oracle/工具链绑定；
- 安装前和两轮前各有一份全新、受支持策略版本且 Scope/顺序/时间/一次性绑定全部
  通过的授权使用确认，四个 RFC-0001 Consent 断言都为 True，且每份 Host 签名
  信封都由编译公钥验证；
- Run 1 前已完成 Device 签名 Enrollment 和 Host/实体 iPhone 完整 Fingerprint
  对比，Receipt 和两份 Export 的签名均有效；
  两轮 Enrollment/Device Binding、硬件型号、iOS Version/Build 完全相同，期间
  没有换机、重装/重置 App、丢失 Enrollment 状态或更新 iOS；
- 私有授权清单 Hash 一致，三个 Role 的 Target 身份绑定全部匹配获授权的 Bundle
  ID、签名 Identifier/Team 和选定 Entitlement；
- 两个不同的一次性 Host Challenge 均正确响应，时间窗有序且 Run 2 正确链到
  Run 1 Binding；
- 安装清单没有缺失、额外、未映射或重新分类的 Slice；
- UUID、CPU、固定区间一致，且每个 Role 的签名状态精确为
  `present` / `cms` / `valid` 并记录 Validator Revision/摘要；
- `cryptid == 1` 的加密范围覆盖固定区间，磁盘 Hash 不同于 Oracle；
- 同一区间映射 Hash 等于冻结 Oracle；
- 磁盘身份/保护观察先于映射 Hash；
- 两轮规范化结果完全相同；以及
- 没有任意目标/区间、原始字节、宽权限原语或隐私泄露。

任一必需项失败就是该组合的 No-Go；缺证据得到 Inconclusive，也使方法级结果
No-Go。No-Go 可以完成 LAB-002，但不能降低 Oracle 标准或解除 DEVICE-001。

## 隐私和保留

Mac 只在 Git 外 Owner-Only 研究目录中，临时保留私有授权清单/Nonce/Host 私钥、
三份授权确认与签名信封、Enrollment Receipt/Selection/Binding、Oracle、Archive、
首方 IPA、
上传结果、原始报告和两轮控制记录，并在实验及
批准的加密备份周期结束后删除。设备仅保留一组报告和固定、禁止备份的安装/Counter
状态及 Device-Only Enrollment Key。原始 Identifier-for-Vendor、安装 Nonce 和
Enrollment 私钥永不离开设备；公开结果也不保留 Enrollment/Device Binding、
授权/Enrollment 公钥、签名、Device Selection Fingerprint/Confirmation 或确认
产物/Hash。证书、Profile、API Key、App Store
Receipt 和 Pairing Record 不能复制到
研究目录或公开记录；稳定设备 ID、私有 Bundle ID、绝对路径、运行时地址、受保护
可执行文件、IPA、Mapped Bytes 和原始私有日志都不能公开。首方 IPA 只允许在上述
有界私有周期内存在，期满后不能作为项目产物继续保留。

即使 LAB-002 最终 Go，也只证明精确首方 DemoLab 组合中的 Oracle 方法；项目
仍不能宣称已经能给任意 IPA 砸壳、已经有设备 Backend、已经支持第三方 App，
上传 IPA 与 Apple 安装包逐字节相同，或已经能输出可安装 IPA。
