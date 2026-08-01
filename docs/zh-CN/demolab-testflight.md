# DemoLab 受控 TestFlight 实验状态

本文是 `LAB-001` 的中文状态摘要。完整操作与证据边界以英文
[受控 TestFlight Runbook](../development/demolab-testflight.md) 为准。

## 目的

TestFlight 只用于准备一个由项目自己开发、自己签名、自己上传并安装到自有 iPhone
的 DemoLab 实验样本。它不是最终用户砸壳时需要执行的步骤，也不是
`oprobe decrypt` 的产品能力。

普通 Simulator DemoLab 没有 Apple 分发保护，只能验证工程构建、Mach-O 解析和
App/Framework/Extension 清点。受控 TestFlight 实验要进一步确认：Apple 处理并
安装后的同一 Build，能否同时提供独立的初始保护证据和精确明文 Oracle。

## 当前进度

- Apple Developer 团队、主 App ID、Share Extension App ID 和 App Store Connect
  App 记录已由维护者在仓库外准备。
- Fastlane 版本已锁定；无凭据 `demolab_check` 可构建 Simulator Fixture。
- `demolab_archive` 只从本机环境读取真实 Bundle ID/Team ID，把签名 Archive、IPA
  和预上传 SHA-256 证据写到 Git 仓库外；构建输入来自已记录 Commit 的不可变
  Git Snapshot，不从可能同时变化的工作区复制；签名与上传 Lane 都拒绝常见 CI
  环境，并要求明确确认当前是 CI 外的本机手工运行。输出根目录必须提前创建、由
  当前用户所有、权限已是 `0700` 且不是符号链接，路径不能含单引号或控制字符；
  Lane 不会创建它或修改其权限。Xcode 先写入输出根目录下随机生成的私有暂存目录；
  Lane 在整个构建期间持有输出根与暂存目录的描述符和排他咨询锁，并在构建前后比较
  Inode、权限和解析路径。证据生成完成后，再使用 Darwin 排他且拒绝符号链接的 Rename
  一次发布最终目录，已有目标不会被覆盖。Gym 的导出 Plist、中间 IPA 和其他 Scratch
  只能写入受锁暂存目录下另一个随机 `0700` 临时根；Lane 会确认 Gym 实际导出目录是
  该临时根的直接子目录，成功后删除临时根。私有 Oracle Helper 启动前的普通失败会
  清理未发布暂存产物；尝试启动 Helper 前则切换为失败安全保留，任何 Spawn、Helper、
  Evidence 或后续发布前失败都会保留 Owner-only 暂存现场，下一次 Archive 会在
  `.demolab-staging-*` 被显式协调前拒绝继续。签名产物不会遗留在系统临时目录。
- `demolab_upload_testflight` 只接受仓库外、权限受限的 App Store Connect API
  Key；上传前强制复核源码 Commit、证据类型、IPA 大小与 SHA-256、包内 Bundle
  ID、版本/Build 号、可执行文件路径及三个二进制哈希，再生成只读的私有临时副本、
  复核大小与 SHA-256，并以 `0400` 权限锁定在随机 `0700` 工作区中。Xcode 26
  `altool` 会拒绝没有 `.ipa` 扩展名的 `/dev/fd` 包路径，因此 Lane 传入这个受控的
  `DemoLab.ipa` 快照路径，并在 `altool --upload-package --wait` 前后复核同一
  Path、Inode、只读描述符、大小和哈希；Apple 工具不会收到或重新打开调用者原始
  IPA 路径。API Key 仍使用独立的匿名描述符。IPA 检查、
  大小和哈希来自同一份有界内存快照。证据 JSON 必须由当前用户所有且无组/其他用户权限，并从完成所有者、
  权限、路径和 Inode 校验的同一个有界、拒绝符号链接的文件描述符解析，避免校验后
  再按路径打开另一份文件；上传前还会要求完整的创建时间、源码、工具链、Release/
  App Store 构建、Archive 与 IPA 三个二进制的测量和状态，以及尚未建立的上传/安装
  Lineage。LAB-002 `1.0 (3)` 还必须包含精确 Manifest/Oracle 文件身份、外部 Oracle
  SHA-256、Build Binding、Target Identity Set 及相同 IPA Tuple；缺失或篡改任一部分
  都会在凭据或网络动作前拒绝。上传前必须保留证据旁的
  `DemoLab.xcarchive`；Lane 会重新测量其中三个二进制，并逐项比对大小、哈希、
  Architecture 和 UUID。Lane 还会复核包内
  `ITSAppUsesNonExemptEncryption=false`；该 Lane 不修改 TestFlight Beta 元数据，
  不使用 Fastlane Pilot，并禁止在 CI 运行。API Key 会经拒绝符号链接、非阻塞打开的文件描述符读取为有界
  内存快照，FIFO 等特殊文件会立即拒绝而不会等待写入方；在读取前复核所有者、权限、
  稳定路径和仓库边界，`altool` 只接收匿名描述符，不会再次打开调用者提供的路径。
  全部源码、构建、Plist、二进制和上传临时工作区都会以
  `0700` 新建；临时根目录必须解析到 Git 仓库外，并且只供当前用户访问或带 Sticky
  Bit。Lane 会直接解析当前配置的 `TMPDIR`，不依赖 Ruby 已缓存的 `Dir.tmpdir`；
  若自定义 `TMPDIR` 指向仓库内，或配置路径/解析后路径含单引号或控制字符，会在创建
  任何临时产物前拒绝，避免不安全路径进入 Fastlane Gym 的 Shell 导出参数。
- 受控真机观察已完成并得到有界 No-Go：当前精确组合无法在批准边界内独立绑定
  已安装 Lineage、初始保护和明文范围。`LAB-001` 已完成但不激活 `DEVICE-001`，
  更不能宣称已经具备砸壳能力。

## Fastlane 登录与本机安装

安装 Fastlane、安装 Ruby 依赖以及运行无签名的 `demolab_check` 都不需要登录
Apple 账号。签名 Archive 使用本机 Xcode 中的团队、证书和描述文件；上传则使用
仓库外的 App Store Connect API Key，不把 Apple ID 密码交给 Fastlane。上传时还要
设置 App Store Connect “App 信息”中现有 App 的数字 Apple ID
（`DEMO_LAB_APPLE_ID`）；它不是 Apple 登录邮箱。还必须把
`APP_STORE_CONNECT_KEY_TYPE` 明确设为 `team` 或 `individual`；个人 Key 会让
Lane 传入 `altool --api-key-subject user`，其他值会被拒绝。团队 Key 必须设置
真实的 `APP_STORE_CONNECT_ISSUER_ID`；个人 Key 没有 Issuer ID，因此必须取消
该变量。Xcode 26 的 `altool` 参数解析仍要求 `--api-issuer`，Lane 会自动用 Key ID
作为兼容占位值，用户不应编造 Issuer UUID。
DemoLab 不使用非豁免加密，主 App 明确声明
`ITSAppUsesNonExemptEncryption=false`，处理后的 Build 不需要额外手工回答出口合规
问题。

2026-07-29 的首次受控上传暴露了 `.ipa` 文件名要求：Apple 只创建空的
`AWAITING_UPLOAD` 占位记录，并在接收任何 IPA 文件字节前返回产品错误。同一包和
API Key 的普通路径验证通过，而描述符路径验证稳定复现
`Cannot expand files with extension ""`。通过 App Store Connect 页面和 API 对账
确认 `1.0 (1)` 不存在 Build 或上传文件后，本地不确定记录已归档为
`reconciled_absent`，才恢复重试许可。这只是传输兼容性证据，不是保护状态或明文证据。

PR #49 已合并兼容修复。新的 `1.0 (1)` 候选来自干净的合并 Commit
`911db950cff8fc408294d56181477f7319442a36`，IPA SHA-256 为
`1bb541456d73d644e7c06a148c1e0c780f64f1eb622ae8af35ae482a75f4ec1b`。
唯一一次许可上传后，App Store Connect 先显示“正在处理”，随后在 TestFlight 构建
列表中将版本 `1.0`、Build `1` 标为“准备提交”。这证明 Apple 已接收并处理该包，
因此禁止重试。本地结果因 `altool` 最终 stdout 不是有效 JSON 而保留
`status: indeterminate`；应保持这份仅所有者可访问的记录不变，它表示本地工具
可观测性缺口，不代表远端上传失败。本次没有创建测试组、外部分发、Beta App Review
或 App Store 提交。

Build `1` 随后安装到自有且获授权的 iPhone，但受控的 Mac 侧启动复现了立即退出。
`dyld` 显示主程序请求
`/Library/Frameworks/DemoFramework.framework/DemoFramework`，嵌入 Framework
自身也使用相同的错误绝对 Install Name。Framework 实际存在于 App Bundle 中，因此
这是链接配置缺陷，不是 IPA 缺少内容、TestFlight 拒绝或砸壳证据。Build `1` 必须
保持不变作为失败证据，不得重试。

修复会把 DemoFramework 的 Install Name Base 固定为 `@rpath`。回归 Lane 和签名
工作流使用固定到所选 Xcode 的 `otool`，要求 Framework ID 及主程序中所有匹配依赖
都精确等于 `@rpath/DemoFramework.framework/DemoFramework`。检查覆盖 Simulator
产物、签名 Archive、导出 IPA 和每次上传前的 Archive 复核；任何绝对路径或其他匹配
路径都会在发布或上传前失败。App Store Connect 的 Build 号不可变，因此将下一候选
预先确定为从合并修复生成的 `1.0 (2)`。

PR #51 已合并该修复。`1.0 (2)` 候选来自干净的合并 Commit
`5785c56e8bee8e30fdaefcb6e263852e9be874ab`，IPA SHA-256 为
`e383fcf0ee550effb68b183965208b1ef274688cc5233649b8e452135aafde40`。
上传前已独立复核证据、签名、包元数据、Archive 链接和导出 IPA 链接。唯一一次上传
调用后，本地因 `altool` 最终响应不是可解析 JSON 而保留
`status: indeterminate`，但不得重试：App Store Connect API 已把这个精确 Build
报告为 `VALID`，内部状态为 `IN_BETA_TESTING`，且不缺少出口合规信息。现有内部组
本身覆盖全部 Build；本次没有创建或修改测试组、启用公开链接、外部分发、
Beta App Review 或 App Store 提交。

## LAB-002 本机 Archive 配置

以下值只从仓库外的私有 Shell 配置加载，不得写入 Git、Issue、PR 或构建日志：

| 变量 | 用途 |
|---|---|
| `DEMO_LAB_CONFIRM_LOCAL_MANUAL_RUN` | 预构建、Archive、上传与对账都要求精确值 `I_AM_RUNNING_LOCALLY_OUTSIDE_CI`。 |
| `DEMO_LAB_APP_BUNDLE_ID` | 预构建、Archive 与上传使用的已注册首方主 App ID。 |
| `DEMO_LAB_SHARE_BUNDLE_ID` | 预构建、Archive 与上传使用的已注册 Share Extension App ID。 |
| `DEMO_LAB_APP_GROUP_ID` | 预构建与 Archive 使用的首方 App Group，须同时启用在主 App ID 与 Share Extension App ID。Archive Lane 拒绝仓库内 `group.com.example.*` 默认值，并把精确 Group 注入两者的 Entitlement 与 Info.plist。 |
| `DEMO_LAB_TEAM_ID` | 预构建与 Archive 使用的 10 字符 Apple Developer Team ID。 |
| `DEMO_LAB_MARKETING_VERSION` | 预构建与 Archive 使用的可选点分版本；默认 `1.0`。 |
| `DEMO_LAB_BUILD_NUMBER` | 预构建与 Archive 使用的正整数；检查点 3 当前只接受 `3`。 |
| `DEMO_LAB_OUTPUT_DIR` | 仓库外已存在的绝对私有目录，必须由当前用户所有、不是 Symlink、Mode `0700`。Archive Lane 会在该根目录下自动推导并锁定精确 3A 目录。 |

签名构建前先在仓库外创建私有输出根目录；Lane 会拒绝不存在的根目录：

```sh
mkdir -p /absolute/private/path/orchardprobe-demolab
chmod 700 /absolute/private/path/orchardprobe-demolab
export DEMO_LAB_OUTPUT_DIR=/absolute/private/path/orchardprobe-demolab
export DEMO_LAB_CONFIRM_LOCAL_MANUAL_RUN=I_AM_RUNNING_LOCALLY_OUTSIDE_CI
export DEMO_LAB_BUILD_NUMBER=3
bundle _4.0.16_ exec fastlane ios demolab_prepare_lab002
bundle _4.0.16_ exec fastlane ios demolab_archive
```

预构建 Lane 会先为经实时认证的 GitHub `main` Source 与 DemoLab `1.0 (3)` 发布唯一
三文件私有 3A Tuple。Archive Lane 从同一已锁定输出根推导该目录，只通过已持有
Directory Descriptor 读取，并重新推导/校验 Manifest、非弱 Authorization 公钥、
Identity Nonce、Build Binding、三个 Target Binding、Target-identity Set 与固定
Toolchain 后才注入构建。Shell 不再提供这些私有 Binding 值。

Archive 会在 Prebuild 目录仍被锁定时，把 Manifest 与冻结 Oracle 的 Owner-only
文件身份、外部 Oracle SHA-256、Build Binding、Target Identity Set 以及 IPA
Size/SHA-256 一并写入 Evidence。用户不需要手工复制或重命名任何单个文件；应完整保留
Lane 自动发布的同级 Prebuild 目录和 Run 目录。上传 Lane 会从 Evidence 的
Source/Version/Build 只推导这一对固定目录，把持有的 Directory Descriptor 交给受审
Helper，重新解析规范 Manifest、Prebuild 与 Oracle，重新推导授权 Key、Build Binding、
三个 Target Binding 和 Target Identity Set，并闭合三 Role Oracle/IPA Tuple。只读 IPA
快照就绪后、写入 Upload Attempt 或产生 Apple 网络动作前还会再次执行同一门禁。
合法重试可以保留最多 32 份已协调的上传审计记录；Helper 只接受固定的小写文件名，
并逐份重验 Owner-only Mode、Schema、Source Commit、IPA SHA-256、时间戳、目的地和
`reconciled_absent` 决策。除此以外的任何额外 Run 条目仍会拒绝。

LAB-002 v1 的 `source_commit` 固定为 40 位小写 Hex。SHA-256 Git 仓库中的
`demolab_check` 仍会执行全部通用 Fixture 检查，但会跳过无法表示 64 位 Commit 的
检查点私有输入往返与审阅源码快照回归；签名 `demolab_archive` 则会在构建前拒绝该
对象格式。

项目固定使用 Fastlane 2.237.0 和 Bundler 4.0.16。不要依赖 macOS 自带的旧 Ruby：

```sh
brew install ruby xcodegen
export PATH="$(brew --prefix ruby)/bin:$PATH"
gem install bundler -v 4.0.16
bundle _4.0.16_ config set --local path vendor/bundle
bundle _4.0.16_ install
bundle _4.0.16_ exec fastlane ios demolab_check
```

`demolab_check` 只把已被 Git 跟踪的 Fixture 源文件复制到临时目录，不会复制已忽略
的生成工程或 `DerivedData`；随后它解析 XcodeGen 可执行文件，要求文件不可写，并
在执行前把 SHA-256 与已评审的 arm64 XcodeGen 2.45.4/2.46.0 二进制白名单比对。
已验证的字节会通过稳定的只读源描述符复制到本次 0700 私有工作区内随机命名、仅所有
者可执行的快照。Lane 以只读方式重新打开快照、全程持有排他锁，只执行该快照，并在
生成前后复核其描述符、路径、Inode、大小、权限和 SHA-256；随后还会再次复核原始选中
的可执行文件。只会伪装版本输出的 PATH 包装器，或校验与执行之间发生的路径替换，都会
被拒绝。所有受控子进程还会清除 `DYLD_INSERT_LIBRARIES` 等动态加载器变量，防止借此
向已在白名单内的 XcodeGen 快照注入代码；回归检查会用恶意加载器变量启动子 Ruby，
并要求子进程观测不到该变量。其他架构必须先补充经过评审的二进制哈希，才能运行签名流程。随后 Lane 执行
无签名 Simulator 构建、核对产物并删除临时目录；签名 Lane 会把实际使用的 XcodeGen
精确版本写入预上传证据，便于审计工程生成工具链。Simulator 构建本身也在下述固定
Xcode 环境中执行，调用方继承的 Developer Directory、SDK、Toolchain 或 xcconfig
不能改变该检查。安装依赖和执行该 Lane 都不需要 Apple 登录。

Apple 开发者工具不会从调用方的 `PATH` 选择。Lane 只通过
`/usr/bin/xcode-select` 读取系统当前选中的 Xcode，且读取时先移除调用方继承的
`DEVELOPER_DIR`；它要求 Developer 目录及其中的 `xcodebuild`、`dwarfdump`、`lipo`、
`otool` 均为 root 所有且不可写，并同样固定 `/usr/bin/xcrun` 和 `/usr/bin/plutil`。
Archive 会把绝对 `xcodebuild` 路径交给 Gym，固定 `DEVELOPER_DIR`，移除继承的
SDK/Toolchain/xcconfig 选择，并为导出包装器使用以已验证 Xcode Toolchain 目录开头
的最小 PATH；因此 Gym 在可选 dSYM/BCSymbolMap 处理中调用的裸 `dwarfdump`/`lipo`
也固定到同一 Xcode。执行前记录可执行文件身份与哈希、Xcode 版本、iPhoneOS SDK
版本/Build，归档和证据生成后再次复核。回归 Lane 还会在 PATH 最前放置伪造的
`xcodebuild`/`xcrun`/`plutil`/`dwarfdump`/`lipo`/`otool`，确认它们均不会被选中。

Archive 进入上述仅含 Xcode 工具的最小环境前，会捕获生成工程时使用且已进入
Allowlist 的 XcodeGen 绝对路径、版本和文件身份。生成 Oracle 时直接重新验证这个
不可写的精确可执行文件，不会尝试从故意缩减的 `PATH` 再次发现 XcodeGen。调用方环境
恢复后，Lane 还必须重新执行一次基于 PATH 选择的常规 XcodeGen 校验，才允许发布最终
候选。回归 Lane 会确认缺失版本或文件身份不匹配在缩减环境中也必须被拒绝。

受控 App Store 导出会显式设置 `uploadSymbols=false`。当前 Xcode 默认把该选项设为
`true`，可能在 `Payload/` 旁增加顶层 `Symbols/`；LAB-002 不会为了这个仅供导出的
Sidecar 放宽 IPA Parser 的单一 App Root 边界，Gym 仍会单独保留 Archive dSYM。
Helper 正常返回错误后，已验证 Helper 会通过持有的目录描述符证明 Staging 精确只有
Archive 与 IPA、没有 Oracle 或临时 Oracle，再同步并复核目录；只有随后发出的精确
“发布前可清理”标记才会解除保留。崩溃、Signal、无标记失败、证明失败或“不确定发布”
标记都会继续保留私有 Staging 等待调和。

App Store 导出还会重新签名可执行文件。当前 Xcode 可能只改变末尾 Code Signature/
`__LINKEDIT` Extent，同时保持架构、CPU Subtype、Mach-O UUID、固定区间坐标与字节、
Fixup Layout、Encryption Command 及授权签名身份不变。只有单 Slice Thin Mach-O、
Archive/IPA Code Signature 起点相同，且两侧签名区都精确结束于各自 Slice EOF 时，
Oracle 才接受 Size 差异。它还会对共同签名起点之前的全部字节计算 Hash，且只把解析出的
`__LINKEDIT.filesize` 与 `LC_CODE_SIGNATURE.datasize` 字段归零；两个归一化前缀 Hash
必须一致。因此即使两份 Binary 都有独立有效签名，相邻字节或任何其他代码/Load-command
变化也会失败关闭。Fixup-layout 身份 Hash 只对同一个已解析的 `__LINKEDIT.filesize`
执行归一化；Segment/Fixup 边界校验仍使用它的实际值，其他所有 Segment Extent 与完整
Fixup Payload 继续被绑定。Oracle 会记录供已安装 Build Verifier 使用的 IPA Slice Size。
Fat 或多 Slice Size 变化、签名起点移动、闭合签名尾之外的增长，或任何既有身份/区间变化
仍会失败关闭。

## 安全边界

- 只能使用首方 DemoLab、自有 Apple 账号和自有且获授权的 iPhone。
- `.p8`、证书、描述文件、Archive、IPA、Receipt、UDID、Pairing Record、受保护
  二进制和原始私密日志不得提交或上传到 GitHub。
- 预上传证据 JSON 必须保持当前用户所有、权限 `0600`；不要把 `TMPDIR` 指向 Git
  仓库，也不要让其配置路径或解析后路径包含单引号/控制字符。
- Archive 前拒绝全部继承的 `GYM_*` 环境变量，避免 Fastlane 从 Shell 隐式改变
  构建选项或把 Result Bundle 重定向到受控运行目录之外。
- 签名和上传必须在专用、可信的本机 macOS 登录会话中手工执行。目录锁与身份复核
  可以拒绝遵守锁的并发 Lane 及可观察到的替换；已经能以同一 macOS 用户执行代码的
  恶意进程也能接触该用户的签名身份，不属于这个维护者实验 Lane 的防护边界。未来
  Device Collector 仍必须满足 RFC-0001 对恶意本机进程的更强要求。
- Fastlane 不保存 Apple ID 密码，不修改 Beta 测试元数据，不添加或通知外部测试
  员，也不自动安装 App；上传前拒绝所有继承的 `PILOT_*` 环境变量及
  `DEMO_ACCOUNT_REQUIRED`，并用最小显式环境、私有临时 Shell/Foundation Home
  和仅所有者创建掩码启动 Apple `altool`，命令结束即清理该工作区。IPA 与 API Key
  快照都会先关闭可写 Handle，再以 no-follow 方式重新打开同一 Inode 并复核描述符
  确为只读；IPA 保留受控的 `.ipa` 文件名并加锁，API Key 则 unlink 后仅通过匿名
  描述符传入。两份受控快照就绪后，Lane 会紧邻网络启动再次
  测量 Archive 的三个二进制，并要求大小、SHA-256、架构和 UUID 仍与证据完全一致；
  随后才复核 Xcode/`altool` 并启动上传。Lane 会先解析
  并验证当前 Xcode
  配置所选的 `altool` 入口；若它解析为 Xcode 26 的 `altoolShim`，则只允许启动
  同一 ContentDelivery 资源目录内真正的 `altool`，从而保留空的私有 Home，同时
  避免 Shim 对外部 `Defaults.properties` 的依赖。无账号检查会验证这个真实二进制
  能在该环境下提供所需上传参数；Lane 保留其路径、Inode 元数据和 SHA-256，在进程
  启动前立即复核，并在进程退出后再次复核。它还把 `--log-dir` 放在权限 `0700` 的
  私有工作区内，并限制单个日志及日志总量。ContentDelivery 可能自行放宽日志目录和
  文件 Mode，因此 Lane 要求这些 Entry 仍由当前用户所有且不可被 Group/Other 写入，
  外层私有目录负责保密，防止诊断落到用户持久日志目录或无限增长。
  上传结果先写入新的仅所有者可访问临时记录并 fsync，再以排他原子重命名发布，拒绝
  已有文件或符号链接；`altool` 开始网络动作前先持久化
  `status: indeterminate`，随后在任何网络动作前 fsync 父目录项。
  只有进程成功，且有界 JSON 响应能正常解析、没有
  `product-errors` 并包含明确的 `success-message`，才通过另一次已 fsync 的原子
  替换更新为
  `status: accepted`。此状态只表示上传已被接受，不表示 Build 已可在 TestFlight
  安装；仍须在 App Store Connect 确认 Build 就绪。`altool --wait` 有固定的
  30 分钟上限，到时 Lane 会终止其进程组并保留 `status: indeterminate`。若上传、
  等待或响应解析失败/超时，必须在 App Store Connect 按版本、Build 号和 IPA
  SHA-256 核对，因为远端可能已经接收 Build。不要手工删除结果文件：若 Build
  已存在则不得重试；只有确认不存在时，才能把结果中的 `attempt_started_at` 设为
  `DEMO_LAB_RECONCILED_ATTEMPT_STARTED_AT`，再设置
  `DEMO_LAB_CONFIRM_RETRY_AFTER_RECONCILIATION` 为
  `I_CONFIRMED_THIS_EXACT_BUILD_IS_ABSENT_IN_APP_STORE_CONNECT` 并运行
  `fastlane ios demolab_reconcile_indeterminate_upload`。该 Lane 会锁住并复核旧记录，
  通过已 fsync 的原子替换将其持久化为 `status: reconciled_absent` 后排他归档；
  归档成功后才允许新上传。
  恢复 Lane 只额外需要
  `DEMO_LAB_CONFIRM_LOCAL_MANUAL_RUN=I_AM_RUNNING_LOCALLY_OUTSIDE_CI` 和原来的
  `DEMO_LAB_EVIDENCE_PATH`，不需要两个 Bundle ID 或 API Key/上传凭据。
- TestFlight 上传成功只证明 Apple 接收了 Build；不能证明初始保护、已安装字节
  Lineage、正确明文或砸壳能力。

2026-07-29 已获得单独的明确上传授权并在仓库外配置最小权限 App Store Connect
API Key。`1.0 (1)` 已进入 TestFlight 并安装到自有设备，但其错误 Framework
Install Name 阻止启动，不能用于 LAB-001 观察。2026-07-29，只读设备查询已独立确认
同一自有 iPhone 安装的是修复后的 `1.0 (2)`；一次先终止旧进程的受控启动成功返回，
精确启动的进程在 12 秒和 32 秒后仍存在，之前的即时闪退没有复现。这只通过了启动
前置门禁，不证明已安装字节 Lineage、初始保护、明文或砸壳能力。

受控观察最终得到有界 No-Go。公开 CoreDevice App/Process 元数据没有逐二进制的
已安装 UUID、签名身份、Slice 或哈希，文件服务不提供已安装 App Bundle 域；
分发签名为 `get-task-allow=false`，LLDB 也无法获得可执行映像。上传前二进制虽为
`cryptid=0` 明文候选，但 Apple 分发还会增加 DRM 和重新处理二进制，所以上传
哈希不能替代精确的已安装 Lineage 或独立的保护/明文范围比较。完整结论见
[LAB-001 首方受保护 Oracle 结论](lab-001-protected-oracle.md)。LAB-001 以
No-Go 完成，不激活 DEVICE-001。

执行签名或上传 Lane 前还必须设置：

```sh
export DEMO_LAB_CONFIRM_LOCAL_MANUAL_RUN=I_AM_RUNNING_LOCALLY_OUTSIDE_CI
# 仅上传 Lane：App Store Connect 中该 App 的数字 Apple ID
export DEMO_LAB_APPLE_ID=1234567890 # 替换为真实数字 Apple ID
export APP_STORE_CONNECT_KEY_TYPE=team # 或 individual，必须与 Key 一致
# 仅 team：export APP_STORE_CONNECT_ISSUER_ID=<Issuer UUID>
# individual：unset APP_STORE_CONNECT_ISSUER_ID
```
