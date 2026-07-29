# LAB-001 首方受保护 Oracle 结论

状态：**No-Go——当前精确研究组合不受支持**

2026-07-29，项目使用自有 DemoLab、自有 iPhone 和内部 TestFlight 完成了有界实验。
DemoLab `1.0 (2)` 已成功安装并稳定启动，但这只证明合法分发和启动前置条件。
该结论在结果 PR 合并后生效。

上传前 Archive 中三个 arm64 二进制均为 `cryptid=0` 的明文候选；Apple 官方说明
分发处理会对二进制增加 DRM 并重新压缩，因此上传 IPA 哈希不能当作设备安装字节
哈希。设备侧公开 CoreDevice App/Process 记录没有逐二进制 UUID、代码签名身份、
Slice 或范围哈希，也不提供已安装 App Bundle 文件域。导出 IPA 的分发签名为
`get-task-allow=false`；公开 LLDB 只能连接到进程，无法获得可执行映像、暂停进程或
列出映像。

Issue #9 同时禁止本阶段新增设备 Backend、Helper、Transport、进程选择、内存访问或
解密实现。因此不能在既定边界内同时建立：

1. 超越 Bundle ID、版本和 Build 号的精确已安装二进制 Lineage；
2. 同一二进制和 Slice 的独立初始保护证据；
3. 同一精确代码范围的独立明文 Oracle；以及
4. 可公开脱敏复现的范围哈希比较。

三个二进制的设备侧结论均为 `Inconclusive`，没有读取或伪造任何设备侧字节、范围或
哈希。完整证据、逐项标准和官方资料见
[英文研究说明](../research/lab-001-protected-oracle.md)。该记录也包含执行时
OrchardProbe 基线 Commit、一次受控运行的计数、维护者签署、UTC 日期、Issue/PR
链接和二次维护者复核状态；一次运行不满足也不宣称 `Go — Verified` 的两次运行门禁。

LAB-001 以这个有界 No-Go 完成，并阻塞 DEVICE-001。这不是“永远无法砸壳”的结论，
而是说明当前公开、非越狱 TestFlight 研究组合无法达到项目自己的严格证据标准。
本结果被接受时，后续要求是通过独立计划变更提出并排序替代 Oracle 步骤；该历史
要求现在由权威执行台账中的 `LAB-002` 计划步骤和 Issue #55 承接。LAB-002 尚未
激活或实现，仍须定义只面向首方 DemoLab、非通用、可独立验证保护和明文范围的新
方案：把每个已安装 Slice、区间和冻结 Oracle 产物绑定到同一精确 DemoLab 源码
Commit/Build，独立证明初始已安装状态受保护以及同一区间转换为匹配 Oracle 的映射
明文，并以 Go 结果完成，DEVICE-001 才能解除阻塞。规划 LAB-002 并不建立受保护
Oracle；项目仍没有设备 Backend、受保护 Oracle、Verified 兼容记录或可用的
`oprobe decrypt`。
