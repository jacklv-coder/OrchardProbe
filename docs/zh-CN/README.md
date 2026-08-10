# OrchardProbe 简体中文文档

[English documentation index](../README.md)

OrchardProbe 把简单的用户体验和内部安全敏感实现分开。可以按目的阅读：

## 使用工具

- [用户指南](user-guide.md)：目标中的“一条命令输入 IPA、输出分析用已解密
  IPA”流程、运行前提、产物和失败行为。
- [兼容性证据政策（英文）](../compatibility/README.md)：什么条件下才能正式
  宣称支持某一设备环境。

## 学习系统

- [串行执行计划](execution-plan.md)：权威步骤顺序、当前门禁、Issue/PR 证据和
  完成定义。
- [技术总览](technical-overview.md)：端到端数据流、组件边界、Mach-O 重建、
  证据语义和源码阅读顺序。
- [LAB-001 首方受保护 Oracle 结论](lab-001-protected-oracle.md)：为什么当前
  内部 TestFlight 研究组合得到有界 No-Go。
- [LAB-002 固定区间 Oracle 设计状态](lab-002-oracle-design.md)：历史首方
  自观测方案的证据链、完整清单、固定区间、两轮流程和现已关闭的
  Go/No-Go 门禁。
- [LAB-002 检查点 3 进度](lab-002-checkpoint-3-progress.md)：精确 DemoLab
  `1.0 (3)` 候选/Oracle 授权、顺序实现门禁与脱敏本地候选记录。
- [LAB-002 检查点 4 进度](lab-002-checkpoint-4-progress.md)：已对账的内部上传、
  Host 工具门禁、终态 Enrollment 尝试及保留的流程性 No-Go。
- [LAB-003 外部工件布局](lab-003-external-artifact-layout.md)：已完成的无设备后续
  门禁，在未来授权前分离严格控制工件、操作员输入与诊断。
- [LAB-003 无设备实现结果](lab-003-implementation-result.md)：记录仅布局 Go 与继续
  有效的设备仪式 No-Go；不建立设备 Backend 或可用 IPA 砸壳。
- [LAB-004 全新受保护 Oracle 仪式](lab-004-protected-oracle-ceremony.md)：定义新的
  DemoLab `1.0 (4)` 六检查点实验；最初只授权无设备集成。
- [LAB-004 无设备 Host 集成](lab-004-device-free-integration.md)：记录七个闭合 Host 转换、
  持有式角色/输入/诊断边界、合成回归及检查点 3 门禁。
- [范围与威胁模型（英文）](../architecture/RFC-0001-scope-and-threat-model.md)
- [有界 Host/Helper 协议（英文）](../architecture/RFC-0002-bounded-host-helper-protocol.md)
- [Rust Host 架构决策（英文）](../architecture/ADR-0001-rust-host.md)

## 开发与验证

- [Rust workspace 指南（英文）](../development/getting-started.md)
- [Mach-O inspect 契约（英文）](../development/macho-inspect.md)
- [有界 IPA 预检与 Entry 读取（英文）](../development/ipa-preflight.md)
- [有界 IPA Info.plist 元数据（英文）](../development/ipa-info-plist.md)
- [有界 IPA 嵌套 Bundle 元数据（英文）](../development/ipa-nested-bundles.md)
- [有界 IPA 主程序 Mach-O 检查（英文）](../development/ipa-main-executable.md)
- [声明标准 Bundle IPA Code 清单（英文）](../development/ipa-code-inventory.md)
- [私有有界 IPA 工作树（英文）](../development/ipa-private-worktree.md)
- [确定性未签名分析 IPA 打包（英文）](../development/ipa-deterministic-package.md)
- [无设备 IPA 打包证据 Manifest（英文）](../development/ipa-package-manifest.md)
- [版本化 Schema 指南（英文）](../development/schemas.md)
- [DemoLab 开发指南（英文）](../development/demolab.md)
- [DemoLab 受控 TestFlight 实验状态](demolab-testflight.md)
- [兼容性测试记录模板（英文）](../compatibility/test-record-template.md)

> [!IMPORTANT]
> OrchardProbe 仍处于 pre-alpha。仓库目前没有实现 `oprobe decrypt`、设备后端
> 或 Mach-O 重建。描述该流程的文档是未来产品与技术契约，不代表当前代码已经能
> 对 IPA 砸壳。
