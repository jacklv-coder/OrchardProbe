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
| 3A | 私有预构建输入生成器 | `已实现；PR #62 等待评审/合并` | 仅本机 `ios demolab_prepare_lab002` Lane 使用固定 Rust 工具链与通过 Checksum 认证的隔离 Cargo Source 构建仓库内部 `oprobe-lab002` Helper，只从已进入受评审 `origin/main` 历史的干净 Commit 与固定构建工具链创建全新 Ed25519 原始 Seed、公钥/Key ID、Identity Nonce、规范 Authorized-target Manifest、Target-identity Set 和域分离 Build Binding，再把三个私有记录以 Owner-only 权限和持久化检查排他发布到 Git 外。纯设备无关单元/Workspace 测试已通过；只有 [PR #62](https://github.com/jacklv-coder/OrchardProbe/pull/62) 通过 Codex CR/CI 并合并后，本行才完成 |
| 3B | Archive/Oracle/证据闭合 | `blocked` | 让加固 Archive 流程消费并重新验证精确 3A 工件，只构建三个 Allowlist Role；比较 Archive/IPA Slice 身份与 `__TEXT,__oprobe`，发布规范冻结 Oracle，并把其外部 SHA-256 绑定进上传前证据；Upload Lane 必须拒绝缺失或不匹配的 Manifest/Oracle 证据 |
| 3C | 无设备测试、Codex CR、CI 与实现合并 | `blocked` | 只使用临时合成 Key、未签名 Simulator 产物和仓库自有 Fixture；覆盖弱 Key、畸形/私有路径、Symlink/Race/权限失败、Target 漂移、Slice/Range/Fixup 不匹配、规范化、原子发布与 Upload-gate 拒绝；任何签名候选构建前必须先合并已评审实现 |
| 3D | 精确签名 DemoLab `1.0 (3)` 候选 | `blocked` | 从干净已合并的 3C Commit 出发，只从本机私有配置恢复已验证的首方签名标识，创建全新 3A 输入，Archive/Export `1.0 (3)`，并在新的 Owner-only Run 目录冻结 3B Oracle/证据；不得上传、安装或观察设备 |
| 3E | 脱敏完成记录 | `blocked` | 独立重新 Hash 并验证本地 Candidate、Manifest、Oracle 与 Evidence 绑定；只在 Issue #55 和中英文文档记录非秘密 Hash/工具链/Build 事实，执行最终 Codex CR/CI/Review 并合并检查点 3 结果 |

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
会拒绝尚未成为受评审 `origin/main` 祖先的干净本地 Commit，并在生成前再次核对
同一 Source。Helper 只从该精确 40-hex Commit 的只读 Git Archive 快照构建；
快照位于独立私有 Workspace，不读取可变 Worktree，并在构建后重新 Hash 完整源码
树。Build Binding 记录的 `gemfile_lock_sha256` 也只从同一认证快照派生并随快照
复核，Lane 不会 Hash 可变 Worktree 中的 `Gemfile.lock`。Helper 构建绝不读取
`~/.cargo/registry/src` 中可变的已解包源码；
它按快照内 `Cargo.lock` 记录的 SHA-256 认证 Cargo Cache 中每个 `.crate` 原始
归档，对 Gzip/Tar 实际消费的压缩字节流同步 Hash，并只通过持有的 Directory
Descriptor 解包到构建可写 Workspace 之外的 Owner-private、只读临时目录，让
全新隔离的 `CARGO_HOME` 只使用该目录；随后再次 Hash 所持归档与完整依赖树。
构建结束后只为经过检查的清理恢复该临时 Source 的目录权限。Cargo、Build
Script 与 Procedural Macro 使用私有临时目录中的空隔离 `HOME`，并在 macOS
Sandbox 内运行：禁止网络，除受评审源码快照和固定 Rust Toolchain 外禁止读取操作员
Home，且禁止写入私有 Build Workspace 之外的位置。如果认证归档缺失，须先运行
`cargo fetch --locked`。

Generator 从开始就持有输出根与唯一 Staging 目录的 Directory Descriptor。文件
创建、目录同步、No-replace Rename、Rollback 与清理都以 Descriptor-relative
方式执行并禁止跟随链接；返回输出路径前还会重新核对其与所持输出根身份一致。
Fastlane 在 Helper 调用前后始终持有并锁定自己的输出根 Descriptor；如果后续
Result 或输出根复核失败，它会相对该 Descriptor 删除本次发布的精确 Tuple。
Helper 会在写入任何私有字节前，通过已 Flush 的非秘密首行记录返回唯一 Staging
名称及其 Device/Inode 身份。Fastlane 会在检查进程状态或解析结果 JSON 前据此
启用 Rollback，再通过专用继承 Pipe 向 Helper 确认；Helper 收到确认前不能写入
私有字节。此后 Helper 中断、结果畸形或操作员按 `Ctrl-C` 都会清理身份匹配的
Staging 或最终目录，并在 Rollback 后继续传播 `Interrupt`。Helper 报告成功前还会
相对 Parent Descriptor 重新打开最终入口，要求其 Device/Inode 仍等于 Staging
身份；Fastlane 解析 Helper Result 后也会从所持输出根 Descriptor 独立重开最终
入口，并在成功前再次执行同一身份检查。如果目录已被替换，Rollback 会拒绝接触
替代目录。如果已启用 Rollback 的身份同时从 Staging 与最终名称消失，Rollback
会把私有状态报告为不确定，不会声称已经清理，也不会静默重试该 Tuple。
文件排他创建并 `fsync`，发布或清理后再 `fsync` Parent。相同
Source/Version/Build Tuple 再次使用会拒绝，不会覆盖私有输入。该 Lane 不执行
签名、Archive/Export、上传、安装或设备操作。
