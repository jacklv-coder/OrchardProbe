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
| 3A | 私有预构建输入生成器 | `planned` | 实现仅本机使用的操作 Lane：从干净已合并 Commit 与固定工具链，为精确 `1.0 (3)` 创建全新 Ed25519 原始 Seed、公钥/Key ID、Identity Nonce、规范 Authorized-target Manifest 和域分离 Build Binding；全部私有输出位于 Git 外，Owner-only、No-follow、Fsync 且原子发布 |
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
