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
- [版本化 Schema 指南（英文）](../development/schemas.md)
- [DemoLab 开发指南（英文）](../development/demolab.md)
- [兼容性测试记录模板（英文）](../compatibility/test-record-template.md)

> [!IMPORTANT]
> OrchardProbe 仍处于 pre-alpha。仓库目前没有实现 `oprobe decrypt`、设备后端
> 或 IPA 重建。描述该流程的文档是未来产品与技术契约，不代表当前代码已经能
> 对 IPA 砸壳。
