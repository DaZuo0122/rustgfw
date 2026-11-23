# 外层流量形态与内层分析器复用

## 研究依据与推论

- [IMC 2020 Shadowsocks 测量](https://gfw.report/publications/imc20/en/)报告首个客户端数据包的长度与随机性被用于挑选主动探测目标；这说明包首统计可以提供候选，不能单独认证具体协议。
- [USENIX Security 2023 全加密流量测量](https://gfw.report/publications/usenixsecurity23/en/)发现首包的平均置位数、可打印字符比例及明文前缀可用于筛除一部分正常流量。已有 `fet.*` 把这组启发式用于 TCP 首次载荷；UDP 不应复用 TCP 分段模型，因此单独按数据报边界采样。
- [USENIX Security 2024 嵌套 TLS 指纹](https://www.usenix.org/conference/usenixsecurity24/presentation/xue-fingerprinting)表明，加密代理的包长、方向和时序仍可泄露内层 TLS 握手。它支持保留早期双向序列供后续模型训练，但不意味着任何固定的两包规则就能识别代理。
- [Hysteria2 协议规范](https://www.hy2.io/docs/developers/Protocol/#gecko-obfuscation)说明 Gecko 会把 QUIC 长头包拆成 2–8 个随机填充的 UDP 数据报，再通过 Salamander 混淆；默认 Hysteria2 则是标准 QUIC。由此推论：同一方向先出现多个随机外观数据报、累计超过 QUIC Initial 的 1200 字节下限、又没有标准 v1/v2 Initial 形状，可以作为**实验性随机碎片首轮候选**。这也可能出现在其他私有 UDP 协议或截断抓包中，不能命名为 Hysteria2 命中。

## 已实现的外层字段

`TcpShape` 通过 `TcpPacketAnalyzer` 在 TCP 重组之前观察前 16 个带载荷数据包。它记录首包前 64 字节的统计量、原始包的有符号长度序列、相邻同向包累计长度，以及首次反向之前的包数和总字节数。正值属于建流方向，负值属于反方向。相同方向、序号和载荷长度的重传不重复计数。`tcp_shape.first_random_like` 使用前缀平均置位数 3.4–4.6、可打印比例低于 0.5、Shannon 熵至少 4.5 bit/byte 的组合，表示随机外观；可与 `tls.*`、`fet.*`、`trojan.*` 和端点字段组成表达式。

TCP 序列按照**包到达顺序**记录，不是 TCP 重组后的字节块大小。当前只跳过完全相同的重传；乱序、部分重叠和分段策略仍会改变序列。`tcp_shape.signed_bursts` 只合并相邻同向包，没有论文中的 RTT 和时间间隔约束，因此不能直接套用论文报告的识别准确率。解码流入口不运行 `TcpPacketAnalyzer`，因为已解码字节没有原始包边界。

`UdpShape` 在按需启用时观察同一 UDP 端点对的前 8 个数据报。它记录首包长度、前 64 字节的平均置位数、可打印字符比例与 Shannon 熵，以及相对首包方向的有符号包长序列、首次反向前的同向包数和累计字节数。`udp_shape.first_quic_initial_shape` 只检查 v1/v2 Initial 的可见头部形状，不进行 QUIC AEAD 验证；需要验证公开 Initial 时继续使用 `quic.*`。

`udp_shape.fragmented_random_candidate` 在首次反向之前至少两个同向数据报累计达到 1200 字节、每个被检查数据报前缀至少 32 字节、平均置位数位于 3.4–4.6、可打印比例低于 0.5、前缀熵至少 4.5 bit/byte，且没有标准 v1/v2 Initial 形状时置为 `true`。数值门槛是据论文和 Gecko 线缆格式提出的工程假设，尚未用带标签的 Hysteria2 Gecko、普通 H3、游戏及语音 UDP 样本校准；规则应结合端点、`quic.*` 和双向序列评估误报。

本地只读对照测试已检查 OpenGFW 提供的 Chrome、Firefox、curl、quiche、ngtcp2、aioquic 客户端 QUIC Initial 抓包；这些首包均被标为标准 Initial 形状，未触发随机碎片候选。这组对照只覆盖握手首包，不代表整个正常 UDP 背景流量。

每个字段的观察值属于外层数据报，不要求 MITM。包长序列只保留前 8 个数据报，并以首个看到的方向为正；在中途开始抓包时，正方向不一定是客户端。该分析器当前没有测量时序：内核或后端提供的包时间戳尚未进入核心输入，不能用用户态处理时间冒充线上间隔。

## 内层复用边界

`Inspect::feed_decoded` 用与逐包 TCP 路径相同的 `AnalyzerRule`、`BidirectionalAnalyzerRule` 和 `FlowRule`；单元测试已验证裸 VLESS 请求头经该入口分段输入后，原有 `vless.*` 表达式会阻断对应逻辑流。其他 HTTP/1、TLS、SOCKS、SSH 和复用协议分析器同样通过注册工厂复用。调用方必须先解密、解复用，并剥离代理封装头；当前 Linux NFQUEUE 与 Windows WinDivert 路径没有这些密钥，也不会自动得到内层明文。HTTP/3 的解码入口 `feed_http3` 单独接收 QUIC 请求流及 QPACK 状态。

下一轮需要用带标签抓包比较 Hysteria2 默认/Salamander/Gecko、普通 H3 与其他高熵 UDP，在不同分片、丢包和中途抓包条件下统计召回率与误报率，再决定是否固化更强的协议候选或加入时序特征。
