# 线上协议识别覆盖盘点

2026-11-22 快照。范围取自 [Xray 出站协议与传输](https://xtls.github.io/en/config/transport.html)、[sing-box 入站协议](https://sing-box.sagernet.org/configuration/inbound/)和 [mihomo 代理类型](https://wiki.metacubex.one/en/config/proxies/)的公开支持清单。这些清单说明协议仍被维护或支持，**不是使用量排名**。这里的“识别”指引擎只看线上包、没有代理密钥、没有 TLS/QUIC 应用密钥时，能否把流量归于具体协议；识别 TLS、QUIC 等外层载体不算识别内层代理。

| 协议或部署方式 | 当前逐包路径能观察什么 | 具体协议识别状态 |
| --- | --- | --- |
| 明文 HTTP 代理、SOCKS4/5、SSH、普通 WireGuard、OpenVPN | HTTP 请求与 CONNECT 目标、SOCKS 请求、SSH banner；WireGuard 固定报文形状和双向索引；OpenVPN 双向 reset 顺序 | 已有对应分析器。WireGuard 和 OpenVPN 是结构/顺序识别，不验证加密身份；HTTP/SSH 不证明载荷是代理用途。见[架构说明](architecture.md)。 |
| 明文 h2c、sing-mux、Xray Mux.Cool | 能解析明文 HTTP/2 帧与子流，关联目标 | 已有解析器；承载在 TLS、VMess 等密文中时逐包路径看不到。见[多路复用](multiplexing.md)。 |
| VLESS `raw` 且未启用 TLS/REALITY/自身加密 | 可解析 v0 请求的命令、目标地址和端口；不记录 UUID | 已有结构候选分析器，不能验证服务端认证；Mux/Rvs 命令不带目标地址。Xray 对公开网络上的无保护 VLESS 有明确使用限制。[VLESS 配置](https://xtls.github.io/en/config/outbounds/vless.html)。 |
| 明文 WebSocket、HTTPUpgrade 传输 | 可见 HTTP/1.1 `Upgrade` 提议与 101 响应选择 | 已有载体协商观察字段；只说明升级协议，不能据此判定 VLESS、VMess 或其他内层代理。TLS 内的升级握手不可见。[RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.8)、[Xray HTTPUpgrade](https://xtls.github.io/en/config/transports/httpupgrade.html)。 |
| Trojan、VLESS/VMess 走 TLS 或 REALITY、AnyTLS、ShadowTLS、Naive、TrustTunnel H2、gRPC/WebSocket/XHTTP 走 TLS | TLS ClientHello 的可见 SNI、ALPN、版本与部分扩展；Trojan 首段方向/长度启发式 | 只能识别外层 TLS 或候选统计特征，不能确认内层是哪种代理。AnyTLS 的认证和帧在 TLS 握手后，REALITY 未认证连接会转发到伪装目标；ShadowTLS 也借用真实 TLS 握手。[AnyTLS 协议](https://github.com/anytls/anytls-go/blob/main/docs/protocol.md)、[REALITY 配置](https://xtls.github.io/en/config/transports/reality.html)、[ShadowTLS v3](https://github.com/ihciah/shadow-tls/blob/master/docs/protocol-v3-en.md)、[TrustTunnel 规范](https://github.com/TrustTunnel/TrustTunnel/blob/master/PROTOCOL.md)。 |
| Hysteria/Hysteria2、TUIC、ShadowQUIC、MASQUE H3、TrustTunnel H3、XHTTP H3 等 QUIC 载体 | 标准 v1/v2 Client Initial 中可见的 SNI、ALPN、ECH 扩展标记、DATAGRAM 接收上限；UDP 前 16 包的长度、方向、包间隔、首包统计及握手 CID 前缀匹配 | 能确认部分 QUIC 握手声明；随机碎片首轮有实验性候选，但不能从 `h3`、DATAGRAM 或该候选确认具体代理。认证、目标和 DATAGRAM 载荷受后续密钥保护。Hysteria2 的 Salamander/Gecko 会遮住标准 QUIC Initial。[Hysteria2 协议](https://www.hy2.io/docs/developers/Protocol/)、[TUIC 规范](https://github.com/tuic-protocol/tuic/blob/master/SPEC.md)、[RFC 9001](https://www.rfc-editor.org/rfc/rfc9001.html)、[外层指纹研究](outer-fingerprints.md)。 |
| Shadowsocks AEAD/2022、VMess 原生加密、VLESS Encryption 的随机外观、ShadowsocksR、Mieru、Sudoku 等加密/混淆载体 | TCP 可观察重组前前 16 包的方向、包长、间隔、同向突发和首包字节统计，并与 FET 组合；UDP 可观察前 16 包的方向、长度、间隔和首包字节统计 | 没有可靠的具体协议识别。Shadowsocks 2022 使用预共享密钥加密头部，随机 salt 不能当固定魔数；TCP/UDP 包形态按各自线缆边界采样。[SIP022](https://shadowsocks.org/doc/sip022.html)、[VLESS Encryption 配置](https://xtls.github.io/en/config/outbounds/vless.html)、[外层指纹研究](outer-fingerprints.md)。 |
| AmneziaWG 的混淆模式 | 可观察 UDP 包长和时序；固定 WireGuard 类型/长度可能已变 | 现有 WireGuard 分析器不能覆盖。AmneziaWG 可替换类型、添加随机前缀和垃圾包，新版本还可保护头部；没有配置参数时不能写出通用确定性签名。[AmneziaWG 文档](https://docs.amnezia.org/documentation/amnezia-wg/)。 |
| OpenConnect 的 TLS/DTLS 数据通道 | TCP 侧可见 TLS 握手；UDP 侧可见 DTLS 1.2/1.3 的明文 ClientHello、HelloVerifyRequest 和 ServerHello | 目前能识别 DTLS 外层，尚不能据此确认 OpenConnect 的隧道协议。它可使用 TLS 数据通道或 DTLS/ESP 次级通道，单靠 TLS/DTLS SNI 不能把它与普通加密业务区分。[sing-box OpenConnect 配置](https://sing-box.sagernet.org/configuration/endpoint/openconnect/)、[DTLS 1.3](https://www.rfc-editor.org/rfc/rfc9147.html)。 |

Xray 的代理协议、传输和安全层可自由组合；“支持 VLESS”不能推出“VLESS 有可见请求头”。同样，HTTP/2、HTTP/3 和 QUIC 的框架可用于普通业务、WebTransport、MASQUE 或代理。当前核心的 `feed_decoded` / `feed_http3` 只在调用方已经提供明文时工作，不计入逐包覆盖。

这些缺口一部分可由新解析器补上，另一部分来自协议主动隐藏或加密内层内容；后者需要带标签样本验证候选模型，不能把“没有专用签名”直接当成代码遗漏。

## 下一步

1. 对已补上的明文 VLESS 结构候选采集 Xray、sing-box、mihomo 客户端样本，验证不同实现与误报。HTTP/1 WebSocket/HTTPUpgrade 已有载体字段，后续可用实际客户端握手验证互通与误报；不能因为 `Upgrade: websocket` 就判定代理。
2. 对 QUIC 家族采集标注流量：普通 H3、WebTransport/MASQUE、TUIC、ShadowQUIC，并扩大 Hysteria2 默认与混淆模式样本。已有 Initial 字段、前 16 包形态、CID 前缀匹配和实验性随机碎片候选；官方 Gecko/Salamander 包装器及官方客户端各模式的本地首轮样本已用于检验候选边界，仍需正常 UDP 对照测量误报，再决定是否加入时序模型。不同客户端、拥塞控制和迁移路径要分开验证。
3. 保持“载体事实”和“具体代理候选”分层。Shadowsocks/VMess 等没有密钥时不承诺确定识别；FET 与 Trojan 长度模型在规则中保留候选含义。

## 主动探测的进入条件

目前未达到“主流协议都能可靠被动识别”的前提，因此先不实现 Reality 主动探测。Reality 对未认证请求会转发至伪装目标，普通 TLS 探针得到像正常站点的回答不能证明它不是 Reality，也不能证明它就是 Reality。[REALITY 服务端行为](https://xtls.github.io/en/config/transports/reality.html)。主动探测的研究需要明确授权的测试目标、同一目标站的直接连接对照、可重复差异与误报测量；[ShadowTLS 主动探测研究](https://www.petsymposium.org/foci/2023/foci-2023-0002.pdf)和[Shadowsocks 主动探测测量](https://gfw.report/publications/imc20/en/)可作为方法参考，但其结果不能直接移植到当前 Reality 实现。
