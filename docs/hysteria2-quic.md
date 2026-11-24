# Hysteria2 与 QUIC 可见性

## 结论

Hysteria2 建立在标准 QUIC 和 QUIC DATAGRAM 上。认证从 HTTP/3 的 `POST /auth` 开始，成功时返回 `233`；之后的代理请求使用加密的 QUIC 流及 DATAGRAM。服务端对未认证请求按普通 HTTP/3 服务器处理。客户端默认还会模仿 Chrome 的 QUIC 握手。因此，单凭 ALPN `h3`、端口、握手形状或 DATAGRAM 支持，不应给出确定的 Hysteria2 判定。[Hysteria2 协议](https://v2.hysteria.network/docs/developers/Protocol/)、[客户端配置](https://hy2.io/docs/advanced/Full-Client-Config/)。

| 输入来源 | 当前可做的事 | 判定边界 |
| --- | --- | --- |
| 标准 QUIC v1/v2 的客户端 Initial | 解开公开的 Initial 保护，读取可见 SNI、ALPN、ECH 扩展标记及客户端 DATAGRAM 接收上限 `quic.datagram_max_size`；用表达式组合条件 | `max_datagram_frame_size > 0` 只表示客户端愿意接收 DATAGRAM，HTTP/3 及其他 QUIC 应用也可使用它；缺少该字段也可能只是没捕获到完整 Initial |
| 握手后的被动逐包数据 | 观察方向、包长、时间和路径端点，用于后续经验证的统计候选模型 | 0-RTT、Handshake 和 1-RTT 载荷没有公开解密密钥；无法直接读 `/auth`、代理目标、DATAGRAM 载荷或 HTTP/3 头部 |
| 可信解密适配器提供的 QUIC 流 | 将已解密且按流有序的 HTTP/3 字节交给 `Inspect::feed_http3`，用表达式关联 `/auth`、`hysteria-auth` 头部名称与响应；代理流另需 Hysteria2 格式解析器 | 需要接入端持有应用流或会话密钥，并执行 QUIC 流重组及阻断；当前 NFQUEUE 路径没有该适配器 |
| Salamander / Gecko 模式 | 可做不依赖 QUIC 明文格式的外层 UDP 统计研究 | Salamander 用预共享密钥遮盖所有 QUIC 包；Gecko 再对长首部包分片、填充。没有密钥时，现有 QUIC Initial 分析器也无法看到原始包 |

Initial 的公开密钥派生与后续密钥的分界见 [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001.html)；DATAGRAM 参数 `0x20` 的含义见 [RFC 9221](https://www.rfc-editor.org/rfc/rfc9221.html)。[RFC 9312](https://www.rfc-editor.org/rfc/rfc9312.html) 提醒被动观察者不能可靠地仅凭通用线缆特征识别所有 QUIC 流，也不能把连接 ID 当作可靠的跨路径身份凭据。QUIC 迁移另见[连接迁移设计](quic-migration.md)。

## 论文与工程取舍

- [Exposing and Circumventing SNI-based QUIC Censorship of the Great Firewall of China](https://gfw.report/publications/usenixsecurity25/data/paper/quic-sni.pdf) 测量了大规模解开 QUIC Initial 后按 SNI 过滤的实践，也展示了规则的边界和滥用风险。这支持把 Initial 当作**可解析的握手声明**，不支持从中推断加密的 HTTP/3 请求。Initial 的保护密钥公开可导出，能解开包不等于认证客户端身份。
- [Is Custom Congestion Control a Bad Idea for Circumvention Tools?](https://ensa.fi/papers/congestion.pdf) 在受控网络中对 Hysteria 的 Brutal 拥塞控制做了速率与主动限速实验。它需要持续流量及可控链路条件；Hysteria2 也支持普通 BBR，不能把论文中的分类器直接当作通用 Hysteria2 规则。
- [The Discriminative Power of Cross-layer RTTs in Fingerprinting Proxy Traffic](https://www.ndss-symposium.org/wp-content/uploads/2025-966-paper.pdf) 研究代理的跨层 RTT 差异。适合研究未来的连接级候选模型，但需要计时数据及与实际部署相符的对照样本，尚不足以用在当前逐包阻断规则。
- [Website Fingerprinting in the Age of QUIC](https://petsymposium.org/popets/2021/popets-2021-0017.php) 说明包长、方向和时序仍可能泄露应用模式；其任务是网站指纹识别，不能把报告的准确率移植为 Hysteria2 的误报率。

## 后续路线

1. 先用 `quic.datagram_max_size` 与 `quic.alpn`、目标、协议版本等字段写**候选规则**，在普通 HTTP/3、WebTransport、MASQUE、Hysteria2 默认与混淆模式的真实样本上评估误报与漏报。示例：`fresh.quic.alpn == h3 && quic.datagram_max_size > 0`。它只表达客户端同时提出 `h3` 且允许接收 DATAGRAM。本地官方客户端默认模式的 16 次首轮握手全部满足该组合；与一份 Chrome QUIC 样本的去 GREASE 扩展及传输参数集合相同，而且客户端每次启动的顺序都变化，因此不能把该组合或单条顺序解释成 Hysteria2 身份。
2. 若能在受控终端或代理处接入已解密的 QUIC 流，可用 `fresh.http3.status == 233 && http3.method == POST && http3.path == /auth && http3.authority == hysteria && http3.request_header_name == hysteria-auth` 标记符合 Hysteria2 认证形状的请求与成功响应。这个条件不校验认证凭据；若需确认身份或解析内部目标，还要接入认证结果及 Hysteria2 代理帧解码。单靠路径上的 NFQUEUE 无法恢复 1-RTT 密钥。
3. 若测试显示连接级包形状有稳定价值，再设计可选统计分析器。先采集带标签样本，覆盖不同客户端、网络、拥塞算法、混淆模式和连接迁移；在独立样本上量化误报，避免把特定测试环境的阈值写进核心。
