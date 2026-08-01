# LAB-002 检查点 3 进度台账

激活 [PR #61](https://github.com/jacklv-coder/OrchardProbe/pull/61)
进入 `main` 后的状态：**DemoLab `1.0 (3)` 为 `active`**

跟踪 Issue：[#55](https://github.com/jacklv-coder/OrchardProbe/issues/55)

2026-07-31，操作员明确接受了紧邻上一条的有界建议：创建首方 DemoLab `1.0 (3)`
签名候选与冻结上传前 Oracle。本授权不包含 TestFlight 上传、安装、物理设备观察或
设备 Backend 工作；这些操作仍须分别通过门禁。

只有本激活 PR 合并进 `main` 后，本台账才具有权威性。工作必须依次进行；前一行完成
前，后一行保持阻塞。

| 顺序 | 子步骤 | 状态 | 完成门禁 |
|---:|---|---|---|
| 3A | 私有预构建输入生成器 | `完成；PR #62 已合并` | 仅本机 `ios demolab_prepare_lab002` Lane 使用固定 Rust 工具链与通过 Checksum 认证的隔离 Cargo Source 构建仓库内部 `oprobe-lab002` Helper，只从已进入经 SSH 实时认证的 GitHub `main` 历史的干净 Commit 与固定构建工具链创建全新 Ed25519 原始 Seed、公钥/Key ID、Identity Nonce、规范 Authorized-target Manifest、Target-identity Set 和域分离 Build Binding，再把三个私有记录以 Owner-only 权限和持久化检查排他发布到 Git 外。纯设备无关单元/Workspace 测试、Codex CR 与 CI 已通过；[PR #62](https://github.com/jacklv-coder/OrchardProbe/pull/62) 已合并为 `0df9ee42fe5ac4de71ca9ae32a657b5f8f18deb6` |
| 3B | Archive/Oracle/证据闭合 | `完成；PR #63-#65 已合并` | 加固 Archive 流程消费并重新验证精确 3A 工件，只构建三个 Allowlist Role；比较 Archive/IPA Slice 身份与 `__TEXT,__oprobe`，发布规范冻结 Oracle，把其外部 SHA-256 绑定进上传前证据，并在闭合 Manifest/Oracle Tuple 缺失或不匹配时拒绝上传。[PR #65](https://github.com/jacklv-coder/OrchardProbe/pull/65) 以 `ca19db07a8badc5d7ce55cc556ab9205181056a5` 合并最终 Gate |
| 3C | 无设备测试、Codex CR、CI 与实现合并 | `完成；PR #66 已合并` | 临时合成 Key、未签名 Simulator 产物和仓库自有 Fixture 已覆盖弱 Key、畸形/私有路径、Symlink/Race/权限失败、Target 漂移、Slice/Range/Fixup 不匹配、规范化、原子发布与 Upload-gate 拒绝。全部 P1/P2 已解决，完整本地验证与必需 CI 已通过，评审后的实现已按 PR #62-#65 合并，且此前没有构建签名 `1.0 (3)` 候选。[PR #66](https://github.com/jacklv-coder/OrchardProbe/pull/66) 以 `e973f6057f5d03e3bab4f5857fdb47ed7699574a` 合并闭环和 3D 转换 |
| 3D | 精确签名 DemoLab `1.0 (3)` 候选 | `进行中；Xcode 导出策略修复实现中` | 首方 App ID 与专用 App Group 已在私有环境完成配置，独立临时签名预检通过。[PR #67](https://github.com/jacklv-coder/OrchardProbe/pull/67) 已修复第一次导出后 XcodeGen 失败，并以 `c6e9bd8d6620564017bcce2e81a8dfc3fc41e72f` 合并。随后全新 Source-bound Run 已完成签名 Archive/Export 并通过修复后的复核，但当前 Xcode 默认 `uploadSymbols=YES`，在严格关闭的 IPA App Root 外加入顶层 `Symbols/` Sidecar，流程再次安全失败关闭。没有发布 Candidate，也没有上传、安装或设备观察 |
| 3E | 脱敏完成记录 | `blocked` | 独立重新 Hash 并验证本地 Candidate、Manifest、Oracle 与 Evidence 绑定；只在 Issue #55 和中英文文档记录非秘密 Hash/工具链/Build 事实，执行最终 Codex CR/CI/Review 并合并检查点 3 结果 |

### 3D 顺序执行门禁

| 顺序 | 门禁 | 状态 | 完成标准 |
|---:|---|---|---|
| 3D.1 | 首方签名 Capability | `本机完成` | 专用 App Group 已同时关联现有首方主 App ID 与 Share Extension App ID；Xcode 已重新生成受影响 Profile，临时 Release 签名预检通过，且没有保留产物或公开私有标识 |
| 3D.2 | 导出后固定 XcodeGen 复核 | `完成；PR #67 已合并` | 进入固定 Xcode 环境前捕获 Allowlist 内 XcodeGen 的绝对 Path/Version/文件身份；生成 Oracle 时直接复核同一文件；恢复调用方 PATH 后，再以 PATH 选择复核一次才允许发布 |
| 3D.3 | 关闭的 Xcode 导出策略与已证明的发布前 Rollback | `实现中；已补 P1 修复` | 设置 `uploadSymbols=false`，使受控 IPA 保持单一 `Payload/*.app` Tree，同时单独保留 Archive dSYM。只有已验证 Helper 通过持有的目录描述符证明精确 Archive/IPA Pair 存在且没有 Oracle 状态，并发出显式 Cleanup-safe 标记时才解除保留；崩溃、Signal、无标记失败、证明失败与不确定发布均继续保留 |
| 3D.4 | 全新精确候选 | `被 3D.3 合并阻塞` | 从干净的已合并修复 Commit 创建新的 Source-bound 3A Tuple，发布唯一一个通过验证的 Owner-only `1.0 (3)` Archive/IPA/Oracle/Evidence Run；不得复用两次失败运行的 Tuple，不得上传、安装或观察设备 |

两次失败运行都不是候选：Archive/Export 均已完成，但均未发布闭合 Oracle/Evidence
Tuple。第一次未发布 Staging 已由 Rollback 清理；第二次确定性失败在保守的 Helper 前
门禁下保留了一个私有 Staging；经确认其中只有 Archive/IPA、没有 Oracle/Evidence 后，
已原子移动到非候选诊断名称。两份 Source-bound Prebuild Tuple 只作为私有历史诊断
保留，修复改变 `main` 后不得复用。

### 3B 顺序实现切片

| 顺序 | 切片 | 状态 | 完成门禁 |
|---:|---|---|---|
| 3B.1 | 安全消费 3A 工件 | `完成；PR #63 已合并` | Archive Lane 根据已锁定输出根及认证后的 `source/version/build` Tuple 推导唯一预构建目录。受评审 Helper 以 Descriptor-relative 方式读取精确三个 Mode `0400`、Owner-only 文件，重新推导非弱 Key、规范 Manifest、Build Binding、三个 Target Binding、Target-identity Set 与固定 Toolchain，并只返回有界私有 IPC Envelope。Fastlane 不再从调用方接收 Nonce、公钥或 Build Binding 变量。纯设备无关回归、Codex CR、GitHub Codex Review 与 CI 已通过；[PR #63](https://github.com/jacklv-coder/OrchardProbe/pull/63) 已合并为 `8d623d8e2391e4e110ff222c87fa3fc25aa2a23c` |
| 3B.2 | Archive/IPA Oracle 闭合 | `完成；PR #64 已合并` | Helper 与 Fastlane 在发布前后持有并重验最终 Archive App、IPA、六个 Archive Source、Oracle 与 Evidence；签名特殊槽、Zero-fill、逐 Entry IPA 变化、替换及不确定发布回归通过 Codex CR 和全部必需 CI。[PR #64](https://github.com/jacklv-coder/OrchardProbe/pull/64) 以 `5bf31bf305e30abb0121a0bcb76e5fcdf48eb3bc` 合并 |
| 3B.3 | Evidence 与 Upload Gate | `完成；PR #65 已合并` | Manifest/Oracle 身份及外部 Oracle SHA-256 已绑定进上传前 Evidence；精确闭合 Tuple 缺失、变化或不一致时 Upload Lane 会拒绝。[PR #65](https://github.com/jacklv-coder/OrchardProbe/pull/65) 以 `ca19db07a8badc5d7ce55cc556ab9205181056a5` 合并 |

### 3B.3 顺序执行门禁

| 顺序 | 门禁 | 状态 | 完成标准 |
|---:|---|---|---|
| 3B.3.1 | 闭合 Evidence 绑定 | `完成` | 在 Prebuild 目录仍被锁定时，把精确 Owner-only Manifest/Oracle 文件身份、外部 Oracle SHA-256、Build Binding、Target Identity Set 及 IPA Size/SHA-256 持久化进上传前记录 |
| 3B.3.2 | 上传时私有 Tuple 验证 | `完成` | 只从 Evidence 的 Source/Version/Build 推导固定同级 Prebuild/Run 目录，把持有的目录 Descriptor 交给受审 Helper，并在上传前重新解析规范 Manifest、Prebuild 与 Oracle |
| 3B.3.3 | Fail-closed 回归 | `完成` | 已覆盖缺失 LAB-002 Binding、Manifest/Oracle 身份或摘要变化、Build Binding/Target Set/IPA Tuple 不一致、非规范私有工件、不安全权限、目录替换、Run 条目增删，以及严格绑定的协调重试审计记录，且不产生网络操作 |
| 3B.3.4 | 文档、Codex CR、CI 与合并 | `完成；PR #65 已合并` | 中英文用户/技术文档、Workspace/Fastlane 检查、Helper 可复现验证、两轮最终 Codex CR 与全部必需 CI 均完成，合并前无未解决 P1/P2 |

3B.3 Helper 已从实现 Commit
`da758e963e8516cbb38f04e7c7786a041b6a4d9d` 的只读源码快照独立构建两次，
产物字节完全一致。登记 Tuple 为 Rust `1.85.0-aarch64-apple-darwin`，
Source Snapshot SHA-256
`4e59c359dcfa514ebfe1d22fcfa403f24b75fb2fb072aa46b12b339e2ea94116`，
Size `2019584`，SHA-256
`d150dd40834f0578024e7949d4a736eae3dbc9078264850714af49e70a3ccb55`，
CDHash `0382cc8dd78c61d6b0116f34f8ec81bb2002f7ed`。

### 3B.2 顺序执行门禁

| 顺序 | 门禁 | 状态 | 完成标准 |
|---:|---|---|---|
| 3B.2.1 | 闭合测量契约 | `完成` | 复用已接受的 LAB-002 规范 Oracle 模型和固定三 Role 顺序；所有可执行文件路径只能从已持有 Archive/IPA Root 推导，执行有界普通文件读取，并拒绝未知 Role、Slice、Range、Load Command 或 Fixup Layout |
| 3B.2.2 | Archive/IPA 一致性 | `完成` | 独立解析每个固定 Archive/IPA `Info.plist`；要求其 Bundle/Version/Executable Tuple，以及所有 Architecture、CPU Subtype、Mach-O UUID、受信 CMS/CodeDirectory 身份、Slice 范围、`__TEXT,__oprobe` 坐标/内容和已接受 Fixup Layout 精确一致；不得跳过任何 Role 或 Slice |
| 3B.2.3 | 规范私有发布 | `完成` | 编码唯一规范 Oracle，绑定认证后的 Source/Version/Build、3A Manifest 与 Build Binding，再以 Mode `0400` 在身份已持有的 Owner-only Run Directory 下排他、持久化发布且不打印内容 |
| 3B.2.4 | 纯设备无关闭环测试 | `完成；PR #64 已合并` | 合成 Fixture 测试覆盖一致性成功，以及 Target、Slice、UUID、Range、Fixup、签名特殊槽、Plaintext、规范化、权限、替换、逐 Entry IPA 变更与原子发布失败；文档、Codex CR 与全部必需 CI 均在 3B.3 开始前通过 |

最终完成 P1/P2 修复的 3B.2 Helper 已从 Commit
`7db46b22e409ec635b015091f1eff0b3e6f8287a` 的只读源码快照独立构建两次，
产物字节完全一致。登记 Tuple 为：
Rust `1.85.0-aarch64-apple-darwin`，Source Snapshot SHA-256
`ac687ac04a25cad4d57dc7de6f503081e4ee038cf55f7eb1a1924cf44bdeffbf`，
Size `1884528`，SHA-256
`d4f2b1c089371d91eda6363e9df9c9efcd0ed284305b948db4dca20a7883d971`，
CDHash `cadae3e5ba93f22c82aa811d7fb35c15dae16696`。该 Helper 在接受签名元数据前
会验证每个实际存在的 CodeDirectory 已签名特殊槽，并返回仍持有的
最终 Archive App Root 的 Device/Inode，使 Fastlane 能把最终 Evidence 与发布复核
绑定到 Helper 实际测量的精确目录，而不是可替换的 Pathname。

## 3C 闭环证据

- [PR #62](https://github.com/jacklv-coder/OrchardProbe/pull/62)、
  [PR #63](https://github.com/jacklv-coder/OrchardProbe/pull/63)、
  [PR #64](https://github.com/jacklv-coder/OrchardProbe/pull/64) 与
  [PR #65](https://github.com/jacklv-coder/OrchardProbe/pull/65) 按依赖顺序合并完整受评审实现，
  且此前没有构建签名 `1.0 (3)` 候选。
- 最终本地门禁通过 `cargo test --workspace --all-targets --locked`、Workspace
  Clippy 警告拒绝、全部 36 个 `oprobe-lab002` Helper 测试、Fastfile 语法、
  `fastlane ios demolab_check` 与 `git diff --check`。
- 先前 P1/P2 修复后，最终 Codex CR 未发现可操作缺陷；PR #65 随后通过仓库质量、
  Rust Test and lint 和完整 DemoLab Simulator Fixture 工作流，且没有 Review Thread。
- 所有 3C 执行均保持无设备，只使用仓库自有或合成输入；没有发生签名 Archive、
  TestFlight 上传、安装、连接设备观察或 Apple Upload 请求。

## 固定安全边界

- 范围仅限仓库自有 DemoLab 主 App、DemoFramework 与 DemoShareExtension。
- 授权私钥 Seed、Identity Nonce、私有 Target 标识、App Group、签名身份、Archive、
  IPA 与完整 Oracle 都必须留在 Git、Issue、PR、Chat 和 CI Log 之外。
- Generator 与 Archive Lane 不接受调用方选择的可执行路径、进程、地址、区间或清单扩展。
- 本检查点只授权 `1.0 (3)`。Source、Toolchain、Version、Build、Manifest 或签名
  Tuple 任一变化，都须重新授权并使用全新 Run 目录。
- 检查点 3 完成只证明存在独立冻结的本地 Candidate/Oracle 对，不证明已安装保护、
  映射明文、砸壳、IPA 重建或设备支持。

## 3A 实现边界

公共实现没有增加 `oprobe` 用户命令。内部 `oprobe-lab002` 可执行文件只在
私有临时目录构建并由 Fastlane 调用。Prepare 操作从标准输入接收固定三 Role
请求，只输出不含秘密的结果 Envelope；私有 Target Identifier 不会成为命令行
参数或结果字段。

发布的预构建目录精确包含：

- `lab-002-authorization-seed-v1.bin`：32 字节原始 Ed25519 Seed，Mode
  `0400`；
- `lab-002-authorized-targets-v1.json`：规范私有 Authorization Manifest，
  Mode `0400`；
- `lab-002-prebuild-v1.json`：规范 Build/Toolchain/Binding 记录，Mode
  `0400`。

目录只能创建在仓库外、已存在、Canonical、Mode `0700` 的输出根目录下。Lane
会拒绝尚未成为 GitHub 实时 `main` OID 祖先的干净本地 Commit，并在生成前再次核对
同一 Source。该 OID 由 `git ls-remote` 从写死的 SSH 仓库 URL 获取；命令在 Checkout
之外运行，排除本地、全局与系统 Git Configuration，禁用交互 Prompt 与 SSH Agent，
并使用受评审源码内固定的 GitHub Ed25519 Host Key 认证
`ssh.github.com:443`。SSH 不读取任何用户可控 Known-hosts Path：
`KnownHostsCommand` 只调用固定、Root-owned 的 `/bin/echo` 输出源码内 Key，使用后
还会重新验证 `/bin/echo` 与 `/usr/bin/ssh` 的内容和身份。可变的本地
Remote-tracking Ref 绝不作为评审证据。
同一受限通道还会执行 Quiet Fetch，只把所公布的 `main` 历史物化进本地 Object
Database，不写 `FETCH_HEAD`、不更新任何本地 Ref；随后第二次实时查询必须返回相同
OID，且该精确 Commit Object 必须已能在本地验证。祖先检查及后续 Git 操作都会显式
禁用 Git Replacement Ref。Helper 只从该精确 40-hex Commit 的只读 Git
Archive 快照构建；解包后的 Path/Blob OID 清单还必须与 `git ls-tree` 精确相等；外部 Attributes
造成的变换会被拒绝。Git Archive 的标准输出直接以无路径中间归档的 Pipe 交给
Extractor，且两个进程状态都必须成功。快照位于独立私有 Workspace，不读取
可变 Worktree，并在构建后
重新 Hash 完整源码树。Fastlane 会记录并持续持有受评审 Source Root 的
Device/Inode；Build 子进程在执行沙箱化 Cargo 前通过 Darwin `fchdir(2)` 进入
该已持有目录，并要求构建前后 Source Path 始终映射到同一身份。Build Binding
记录的 `gemfile_lock_sha256` 也只从同一
认证快照派生并随快照复核，Lane 不会 Hash 可变 Worktree 中的 `Gemfile.lock`。
Helper 构建绝不读取 Cargo `registry/src` 中可变的已解包源码；它会解析操作员
配置的 `CARGO_HOME`（仅在未设置时回退到账户默认目录），再按快照内
`Cargo.lock` 记录的 SHA-256 认证 Cargo Cache 中每个 `.crate` 原始
归档，对 Gzip/Tar 实际消费的压缩字节流同步 Hash，并只通过持有的 Directory
Descriptor 解包到构建可写 Workspace 之外的 Owner-private、只读临时目录，让
全新隔离的 `CARGO_HOME` 只使用该目录；随后再次 Hash 所持归档与完整依赖树。
Fastlane 还会持续持有已验证 Vendor Root 与 Rust Toolchain 的 Directory
Descriptor，并要求构建期间对应 Path 身份始终不变。由于同 UID 恶意进程仍可能在
前后检查之间短暂替换再恢复这些基于 Path 的输入，构建会固定 Archive 时间，并把
Source、Vendor 与 Toolchain Root 重映射到固定名称以获得可复现产物。在生成任何
Authorization Seed 之前，最终 Mach-O 必须精确命中按
`Source Snapshot SHA-256 + Rust Toolchain` 独立评审的白名单 Tuple；该 Tuple
同时固定文件大小、完整 SHA-256 与 SHA-256 CodeDirectory CDHash。因此瞬时替换
Toolchain 或 Vendor 不能生成任意 Helper 后再靠恢复受评审目录隐藏，任何不同产物
都会被拒绝。Helper Source 或受支持 Toolchain 改变时，必须重新评审并登记新的产物
Tuple。
构建结束后只为经过检查的清理恢复该临时 Source 的目录权限。Cargo、Build
Script 与 Procedural Macro 使用私有临时目录中的空隔离 `HOME`，并在 macOS
Sandbox 内运行：禁止网络，除受评审源码快照和固定 Rust Toolchain 外禁止读取操作员
Home，且禁止写入私有 Build Workspace 之外的位置。如果认证归档缺失，须先运行
`cargo fetch --locked`。
Build Binding 使用的 XcodeGen Path、Version、Device/Inode、Size、修改时间与
SHA-256 会作为同一 Selection 保留；生成完成后、Pre-build Result 返回前还会再次
选择并重新 Hash，要求与原 Selection 精确相等。

Generator 从开始就持有输出根与唯一 Staging 目录的 Directory Descriptor。
Fastlane 会把已经锁定的输出根 Descriptor 复制给 Helper，并传入预期的
Device/Inode；Helper 验证后直接使用该继承 Descriptor，发布过程不再重新打开可被
替换的输出根 Path。文件创建、目录同步、No-replace Rename、Rollback 与清理都以
Descriptor-relative 方式执行并禁止跟随链接；返回输出路径前还会重新核对其与所持
输出根身份一致。Fastlane 在 Helper 调用前后始终持有并锁定自己的输出根
Descriptor；如果后续 Result 或输出根复核失败，它会相对该 Descriptor 删除本次
发布的精确 Tuple。
Helper 会在写入任何私有字节前，通过已 Flush 的非秘密首行记录返回唯一 Staging
名称及其 Device/Inode 身份。Fastlane 会在检查进程状态或解析结果 JSON 前据此
启用 Rollback，再通过专用继承 Pipe 向 Helper 确认；Helper 收到确认前不能写入
私有字节。Fastlane 在发送请求前及确认 Rollback 前还会把运行中 PID 绑定到已验证
Helper：系统 `lsof` 必须返回预期可执行映像的 Device/Inode，Darwin `csops`
必须返回从完整 Hash 的 Mach-O CodeDirectory 解析出的 SHA-256 CDHash。因此即使
路径被替换后恢复，也无法冒充受评审 Helper。此后 Helper 中断、结果畸形或操作员
按 `Ctrl-C` 都会清理身份匹配的
Staging 或最终目录，并在 Rollback 后继续传播 `Interrupt`。Helper 报告成功前还会
相对 Parent Descriptor 重新打开最终入口，要求其 Device/Inode 仍等于 Staging
身份；Fastlane 解析 Helper Result 后也会从所持输出根 Descriptor 独立重开最终
入口，并在成功前再次执行同一身份检查。Helper Result 还会把三个固定私有 Artifact
名称分别绑定到发布后的 Device/Inode、Mode、Size 与 SHA-256。Fastlane 会验证这份
封闭清单，要求 Manifest 文件 Digest 与 Result 中的 Manifest Digest 相等，再以
Descriptor-relative 方式逐个重开、重新 Hash 并复核身份，最后再次重开最终目录。
在这些 Hash 之前、期间及之后，Fork 子进程会通过 `fchdir(2)` 进入已持有目录并
枚举目录项；集合必须精确等于三个固定 Artifact 名称，新增第四项也会 Fail-closed。
任一文件被原位修改或替换都会让最终检查失败，并触发已经启用、按身份限定的
Rollback。如果目录已被替换，Rollback 会拒绝接触
替代目录。如果已启用 Rollback 的身份同时从 Staging 与最终名称消失，Rollback
会把私有状态报告为不确定，不会声称已经清理。三个固定 Artifact 的每次 Unlink
都必须成功，目录删除也必须成功；随后还会通过已持有 Directory Descriptor 查询
路径，证明对应 Inode 没有被并发改名后继续可达。因此 Artifact 缺失或改名、目录
在打开后改名、Descriptor Path 仍存在或被替换，都会得到“不确定”而不是成功；
Lane 不会静默重试该 Tuple。
文件排他创建并 `fsync`，发布或清理后再 `fsync` Parent。相同
Source/Version/Build Tuple 再次使用会拒绝，不会覆盖私有输入。该 Lane 不执行
签名、Archive/Export、上传、安装或设备操作。

## 3B.1 实现边界

Archive Lane 不再从 Shell 接受 `DEMO_LAB_BUILD_BINDING_SHA256`、
`DEMO_LAB_IDENTITY_NONCE` 或 `DEMO_LAB_AUTHORIZATION_PUBLIC_KEY`。它会认证实时
GitHub `main` Source Commit，把检查点固定为 DemoLab `1.0 (3)`，并在已锁定私有
输出根下推导精确 3A 目录名称。私有 Helper 运行期间，输出根和推导出的预构建目录
都保持打开并持有排他锁。

Helper 的 `inspect-prebuild` 操作通过固定继承 Descriptor 接收已持有预构建目录及其
预期 Device/Inode。它只接受 Seed、Manifest 与 Pre-build Record 三个目录项。每个
Entry 都以 Descriptor-relative、No-follow、Nonblocking 方式打开，必须是非空、
当前用户所有、Mode `0400`、固定大小上限内的普通文件，并在每次读取前后核对身份与
时间戳。Helper 从 Seed 推导 Ed25519 公钥与 Key ID，拒绝弱 Key，把 Manifest 与
Record 解析为精确规范 Artifact，再根据 Archive Lane 预期的 Source、Version、
Build、Configuration、Observer、Toolchain 和固定三 Role Authorization Request
重新计算 Manifest Hash、Build Binding、三个 Role-specific Target Binding 与
Target-identity-set Hash。返回前还会再次执行精确目录清单、字节/身份读取及
Held-path 身份复核。

结果是只由 Fastlane 消费且不会打印的有界私有标准输出 IPC Envelope。Fastlane
要求精确 Schema/Field，并检查所持目录身份、Source/Version/Build/Toolchain、所有
64-hex Binding 和非弱公钥；随后再次验证受评审 Helper、所选 Xcode/XcodeGen 和所持
目录。只有这些闭合值才会注入仓库自有构建。PR #64 与 #65 随后闭合 Archive/IPA
Oracle 和上传时 Evidence Gate；单独的早期 3B.1 边界仍不作这两项声明。

## 3B.2 实现边界

同一个 `ios demolab_archive` Lane 现在会在 Export 后自动调用受评审私有 Helper；
操作员不需要手工复制 Archive、解包 IPA 或上传 Oracle。Fastlane 通过固定继承
Descriptor 传入已持有的 Archive 与 Run Directory；Helper 从已持有 Staging Root
打开导出的 IPA，验证精确且有界的 ZIP 清单，再复制到 Owner-only 私有工作区中测量。
Helper 会在测量前递归枚举已持有的 Archive App，只接受三个 Allowlist
可执行路径，并保留枚举过程中取得、参与测量的六个 Executable/Info.plist
Descriptor。最终闭合先执行一次精确 Executable 清单，再从已持有 App Root
重新打开并重新 Hash 每个保留路径，要求仍指向同一身份和摘要，随后再次执行
精确清单。因此无论替换发生在清单与路径复核之间，还是路径复核后新增可执行文件，
都会失败关闭。所有 IPA Entry 读取完成后还会重新 Hash 整个已持有 IPA，并要求与
解析前记录的摘要完全一致。

对于固定的主 App、Framework 与 Share Extension 三个 Role，Helper 要求 Archive 与
IPA 的精确可执行路径以及每个 Mach-O Slice 在 Architecture、CPU Subtype、UUID、
Slice 范围、签名身份、固定区间坐标与字节、加密状态，以及已接受 Classic 或
Chained Fixup Layout 的域分离摘要上全部一致。它会分别解析两份固定 Bundle
`Info.plist`，从 Artifact 本身绑定 Bundle Identifier、Version/Build 与 Executable
Name，而不借用授权请求里的值。闭合 CodeDirectory Parser 要求索引 Blob 精确消费
声明的完整 SuperBlob，拒绝 Scatter Table，只接受完整 SHA-256 Page 覆盖，并校验
已签名 Entitlements Special Slot。Xcode 的未签名 Simulator Fixture 可能带有精确的
`0x20400` Ad-hoc/Linker-signed CodeDirectory Profile，且没有 Team、Entitlements
或 CMS Slot；Parser 只接受这一精确缺省，并仍要求闭合的 Identifier Grammar。
该产物始终归类为 Ad-hoc，因此不能通过正式的签名 Archive/IPA Oracle 路径。
CMS 验证前，选定 Entitlement 只通过有明确
Event、Depth、Collection、Key 与累计 Scalar-byte 预算的 XML/Binary 流读取，
Binary 输入还会在库 Reader 构造引用向量前，预检 Trailer、Object Count、Offset、
Scalar Extent、Reference 与 Collection Length；重复 Root Key 或过大的未知结构
都会失败关闭；随后 Helper
验证精确 CodeDirectory 的 Detached CMS，要求 Signer 通过 macOS 本地 `codeSign`
信任策略（使用有界的 CMS 内嵌证书链与本地 Apple Trust Root），且 Signer
Certificate Team ID 必须等于已签名 CodeDirectory Team ID；验证只显式使用
Root-owned Apple System Root Keychain，并禁用默认/用户 Keychain 搜索列表。
未知 Load Command、Classic/Chained Fixup 混用、可执行文件缺失或多出、签名畸形或
不受信、区间漂移或任何字节不一致都会失败关闭。
Classic Rebase 与普通/Weak Bind Stream 必须包含终止 DONE，之后只允许 Linker
零填充；Lazy Bind Stream 则允许由多个分别以 DONE 终止的 Record 组成，但最后一个
Record 仍不得缺少 DONE。

发布前的最后一步，Helper 会从当前已持有的 Run Directory 路径重新打开固定 Archive
App 与 IPA，要求 Archive App Directory 保持原 Device/Inode，并从该重新打开的 Root
再次验证精确可执行清单以及六个保留文件的身份与完整摘要；同时两次重新打开当前 IPA，
要求其保持原身份、完整摘要和已验证 ZIP 清单。因此 Archive App 或 IPA 被改名/替换时，
Oracle 不会继续描述旧 Descriptor，而让紧随其后的 Evidence 步骤读取另一份当前路径。

Helper 还会返回最终 IPA 的 Size/Digest、Archive 六个保留文件按固定顺序排列的
Size/Digest Tuple，以及完成这些测量时仍持有的 Archive App Directory Device/Inode。
Fastlane 在写入 Pre-upload Evidence 前，会绑定该精确目录并独立 Snapshot 相同的三个
Mach-O 与三个 Info.plist，要求逐项完全相同。因此 Evidence 边界会同时拒绝 Helper
发布前后发生的 Source 或整个 Archive Root 替换，不再信任单纯的 Pathname 交接。

外层 Lane 会把 Gym Log、Result Bundle、dSYM ZIP 及其他 Export 辅助产物全部留在
一次性私有 Scratch Directory，只把返回的 IPA 移入最终 Staging。最终 Publisher
要求顶层清单精确只有 Archive、IPA、Oracle 与 Evidence，并持续持有 Oracle 绑定的
Archive App、IPA、六个 Archive Source、Oracle 和序列化 Evidence 的只读 Descriptor。
同一个函数会再次验证完整摘要与当前路径身份，执行排他的 Staging Directory Rename，
再从发布后的新路径逐个复核所有已持有 Descriptor，成功后才返回。纯设备无关回归会
发布一份合法 Fixture，并拒绝 IPA、Archive Source、整个 Archive App Root、Oracle、
Evidence 的替换以及额外顶层 Entry 注入。它还会在目录重命名后替换 IPA，并要求生成
一个仅所有者可读写的 `.demolab-staging-published-indeterminate-*.json` 同级 Gate，
其中绑定预期发布目录的 Device/Inode。该 Gate 必须在目录重命名前排他创建；创建失败
会阻止发布，只有全部重命名后 Descriptor 复核通过才会删除。现有 Retained-staging
扫描会识别遗留 Gate，因此最终复核失败会进入明确的人工核对路径，不会静默遗留未经
验证的最终 Run Directory。

只有三个 Role 全部通过后，Helper 才会编码规范
`orchardprobe.lab002.oracle.v1` 记录，将其绑定到已认证 Source、Version/Build、
Authorization-manifest 摘要、Target-identity Set 与 Build Binding，并以 Mode `0400`
在锁定的私有 Run Directory 下原子发布。完整 Oracle 与私有 Target 标识始终留在
Git 和日志之外。发布过程保持 Staging Descriptor，并使用验证文件的同一次 Metadata
读取返回精确 Device/Inode。由于 Darwin 没有按 Descriptor 身份绑定的 Unlink 原语，
Staging 创建后的任何失败都不再执行 Pathname 删除。Helper 会同步锁定目录，明确报告
发布状态不确定，并保留 Owner-only 的 Staging 或已发布现场，要求重试前显式协调。
Fastlane 在尝试启动 Oracle Helper 之前立即启用外层 Staging 保留，并贯穿 Result、
Oracle 身份、Helper、Toolchain、XcodeGen 与 Evidence 验证；只有 Staging Directory
原子发布为最终 Run 后才解除。Helper 的固定“不确定”标记只用于补充报告保留路径；
即使 Spawn 失败、无 Marker 的终止、Panic、断管、畸形结果或后续发布前失败，
Staging Tree 也会保留。此后的每次 Archive 尝试都会在创建新 Staging 前枚举已持有的
Output Directory；只要仍有 `.demolab-staging-*` 遗留项就拒绝继续，因此必须由操作者
显式协调现场，不能静默累积私有 Artifact。这会同时保留
预期字节及任何并发替代名称，避免误删同一用户放入的无关文件。本实现不会
上传 TestFlight、观察设备、重建 IPA，也尚未提供未来“只交给工具一个 IPA、输出砸壳后
IPA”的用户命令。PR #65 已把 Oracle 与 Authorization Manifest 身份持久绑定进
Pre-upload Evidence；Upload Lane 会在任何 Apple 网络访问前重新验证该精确闭合 Tuple，
并拒绝缺失或不匹配的绑定。
