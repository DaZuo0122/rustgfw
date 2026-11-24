# 外层流量形态与内层分析器复用

## 研究依据与推论

- [IMC 2020 Shadowsocks 测量](https://gfw.report/publications/imc20/en/)报告首个客户端数据包的长度与随机性被用于挑选主动探测目标；这说明包首统计可以提供候选，不能单独认证具体协议。
- [USENIX Security 2023 全加密流量测量](https://gfw.report/publications/usenixsecurity23/en/)发现首包的平均置位数、可打印字符比例及明文前缀可用于筛除一部分正常流量。已有 `fet.*` 把这组启发式用于 TCP 首次载荷；UDP 不应复用 TCP 分段模型，因此单独按数据报边界采样。
- [USENIX Security 2024 嵌套 TLS 指纹](https://www.usenix.org/conference/usenixsecurity24/presentation/xue-fingerprinting)表明，加密代理的包长、方向和时序仍可泄露内层 TLS 握手。它支持保留早期双向序列供后续模型训练，但不意味着任何固定的两包规则就能识别代理。
- [NDSS 2025 跨层 RTT 差异](https://www.ndss-symposium.org/wp-content/uploads/2025-966-paper.pdf)用 TCP SEQ/ACK 配对估计传输 RTT，再对多组双向载荷包的时间序列做互相关以估计应用 RTT。代理转发到远端服务的额外往返时间可能使两者拉开；论文也指出，复用并发流、上下行分流和代理靠近目标服务器会削弱这种信号。
- [Hysteria2 协议规范](https://www.hy2.io/docs/developers/Protocol/#gecko-obfuscation)说明 Gecko 会把 QUIC 长头包拆成 2–8 个随机填充的 UDP 数据报，再通过 Salamander 混淆；默认 Hysteria2 则是标准 QUIC。由此推论：同一方向先出现多个随机外观数据报、累计超过 QUIC Initial 的 1200 字节下限、又没有标准 v1/v2 Initial 形状，可以作为**实验性随机碎片首轮候选**。这也可能出现在其他私有 UDP 协议或截断抓包中，不能命名为 Hysteria2 命中。

## 已实现的外层字段

`TcpShape` 通过 `TcpPacketAnalyzer` 在 TCP 重组之前观察前 16 个带载荷数据包。它记录首包前 64 字节的统计量、原始包的有符号长度序列、相邻同向包累计长度，以及首次反向之前的包数和总字节数。正值属于建流方向，负值属于反方向。相同方向、序号和载荷长度的重传不重复计数。`tcp_shape.first_random_like` 使用前缀平均置位数 3.4–4.6、可打印比例不超过 0.5、Shannon 熵至少 4.5 bit/byte 的组合，表示随机外观；可与 `tls.*`、`fet.*`、`trojan.*` 和端点字段组成表达式。

TCP 序列按照**包到达顺序**记录，不是 TCP 重组后的字节块大小。当前只跳过完全相同的重传；乱序、部分重叠和分段策略仍会改变序列。`tcp_shape.gaps_us` 逐项记录已计入包之间的微秒间隔，`last_gap_us` 报告当前包与前一包的间隔，`origin_first_span_us` 和 `first_reply_delay_us` 分别报告首方向首轮跨度及首次反向延迟。解码流入口不运行 `TcpPacketAnalyzer`，因为已解码字节没有原始包边界。

参考 [Xue 等人的特征提取方法](https://www.usenix.org/system/files/usenixsecurity24-xue-fingerprinting.pdf)，`tcp_shape.handshake_rtt_us` 取最初 SYN 到反向 SYN-ACK 后首个有效起始方向 ACK 的时间差；SYN-ACK 必须确认客户端初始序号加一，ACK 必须确认服务端初始序号加一，并按 TCP 的 32 位回绕计算。握手不完整、确认号不符、时间来源不一致或时间倒退时该字段缺失。`tcp_shape.timed_bursts` 仅在 RTT 与所有数据包间隔均可比较时生成：相邻同向包的间隔小于 3 倍握手 RTT 才合并，否则新建突发；无法计算时为 `?`。`signed_bursts` 继续只按方向合并，便于对照。`tcp_shape.size_trigram` 使用论文的 1–160、161–600、601–1210、1211+ 字节四档，正负号保留方向；每个新包报告迄今所有连续三包窗口，例如 `1,-4,-4`，表达式可匹配其中任一值。

论文还用 SEQ/ACK 对包建立总序，并在有标签数据上训练三元组与突发分类器。当前已核对握手确认号，但数据包仍只保留到达顺序和前 16 个载荷包，也没有移植论文的训练参数；这些字段是可组合的特征，不等于论文分类器或其报告的准确率。

`TcpRtt` 独立按需观察前 64 个载荷包，不依赖明文或 MITM。它把起始方向的数据包末序号与反向 ACK 精确对应，排除完全相同的重传，取最近三组出入方向载荷轮次内样本的 RTT 中位数作为 `tcp_rtt.transport_median_us`。应用 RTT 在 1–1000 毫秒范围按 1 毫秒步进寻找双向时间序列的最大相关分数；拉普拉斯权重的尺度取传输 RTT 的四分之一并限在 1–20 毫秒。只在至少三组出入轮次且窗口内有传输样本时报告应用 RTT、差值、轮次数、样本数和归一相关分数。时间缺失、来源变化或倒退会重置该分析器的时序窗口。

这是按论文方法做的**实验性特征提取**，没有移植其带标签的序贯假设检验及先验分布。实际相关峰也可能来自普通服务端处理、复用流的交错、重传、ACK 合并或 CDN 距离；`tcp_rtt.diff_us` 可在表达式中同 TCP 外层字段组合，不能单独作为代理身份判定。当前把建流时首先看到的方向当作请求方向，仅按到达顺序处理包；中途接入、部分重叠重传与重排仍需标注抓包验证。

`UdpShape` 在按需启用时观察同一 UDP 端点对的前 8 个数据报。它记录首包长度、前 64 字节的平均置位数、可打印字符比例与 Shannon 熵，以及相对首包方向的有符号包长序列、首次反向前的同向包数和累计字节数。`udp_shape.first_quic_initial_shape` 只检查 v1/v2 Initial 的可见头部形状，不进行 QUIC AEAD 验证；需要验证公开 Initial 时继续使用 `quic.*`。

DTLS 的 epoch 0 握手也有可见外层结构；需要区分它与随机外观 UDP 候选时使用 `dtls.*`。`DtlsHello` 可在分片跨多个数据报时重组 ClientHello，提取 SNI、ALPN、扩展序列及 cookie 交换事实；这些字段描述载体握手，不指认其内部隧道应用。

QUIC v1/v2 客户端 Initial 中，`quic.transport_parameter_ids` 保存 ClientHello transport parameters 的线缆顺序，`_no_grease` 版本删去 RFC 9000 的保留 ID。`disable_active_migration` 与 `active_connection_id_limit` 是客户端声明；它们可与 ALPN、TLS 扩展序列及 UDP 包形态组合，不代表后续迁移已经发生。

`udp_shape.fragmented_random_candidate` 在首次反向之前至少两个同向数据报累计达到 1200 字节、同向包长至少出现两种值、每个被检查数据报前缀至少 32 字节、平均置位数位于 3.4–4.6、可打印比例不超过 0.5、前缀熵至少 4.5 bit/byte，且没有标准 v1/v2 Initial 形状时置为 `true`。`udp_shape.origin_first_varied_lengths` 单独报告包长是否变化。数值门槛是据论文和 Gecko 线缆格式提出的工程假设；规则应结合端点、`quic.*` 和双向序列评估误报。

用 [Hysteria extras/v2 v2.14.0 官方包装器](https://github.com/HyNetworks/hysteria/tree/extras/v2.14.0/extras/obfs) 对 OpenGFW 只读 ngtcp2 QUIC Initial 分别运行 Gecko 和 Salamander 16 次，外层数据报样本保存在本地 Git 忽略目录，可用选择性测试复核。Gecko 每条轨迹有 2–8 个随机填充的分片；候选初测命中 15/16。漏掉的一条在第二包前 64 字节恰有 32 个可打印字节，整数千分比为 500；把 0.5 边界纳入后命中 16/16。Salamander 每条只有一个外层数据报，均未触发该分片候选。这组包装器样本只验证混淆层，没有模拟完整客户端的首轮发包。

又用 [Hysteria2 v2.14.0 官方客户端](https://hy2.io/docs/getting-started/Installation/) 分别以默认、Salamander、Gecko 配置连本机无响应 UDP 端口，每种模式独立启动 16 次，采集启动后约 0.25 秒的数据报；客户端配置与二进制样本均留在 Git 忽略目录。默认模式首轮发出两个 1250 字节的标准 QUIC v1 Initial；Salamander 首轮发出两个 1258 字节的随机外观包；Gecko 首轮发出多枚 512–1200 字节范围内、长度变化的随机外观包。原条件会把 Salamander 的两包首轮误判为碎片，因此加入首轮同向包长变化条件。选择性测试得到默认 0/16、Salamander 0/16、Gecko 16/16 的碎片候选结果。样本全部来自同一台机器的本机无响应目标，不能据此估计不同网络或普通高熵 UDP 背景下的误报率。

本地只读对照测试已检查 OpenGFW 提供的 Chrome、Firefox、curl、quiche、ngtcp2、aioquic 客户端 QUIC Initial 抓包；这些首包均被标为标准 Initial 形状，未触发随机碎片候选。这组对照只覆盖握手首包，不代表整个正常 UDP 背景流量。

每个字段的观察值属于外层数据报，不要求 MITM。包长序列只保留前 8 个数据报，并以首个看到的方向为正；在中途开始抓包时，正方向不一定是客户端。`udp_shape.gaps_us`、`last_gap_us`、`origin_first_span_us` 和 `first_reply_delay_us` 与 TCP 同义，可用于检验 Gecko 首轮分片的时间聚集性。

`Packet.capture_time` 保留来源：Linux NFQUEUE 有 `NFQA_TIMESTAMP` 时用内核包时间，否则用独立接收线程刚收到包时的单调时钟。`time_source` 为 `kernel`、`receive` 或 `none`。不同来源、缺失时间或时间倒退时，相应间隔记为 `?`，数值比较不会匹配。接收线程时间包含内核排队延迟，不能当作真实线上间隔；内核时间戳也受抓包点、时钟及转发路径影响。现阶段不把这些时间字段固化成协议判定阈值，先用带标签抓包校准。

## 内层复用边界

`Inspect::feed_decoded` 用与逐包 TCP 路径相同的 `AnalyzerRule`、`BidirectionalAnalyzerRule` 和 `FlowRule`；单元测试已验证裸 VLESS 请求头经该入口分段输入后，原有 `vless.*` 表达式会阻断对应逻辑流。其他 HTTP/1、TLS、SOCKS、SSH 和复用协议分析器同样通过注册工厂复用。调用方必须先解密、解复用，并剥离代理封装头；当前 Linux NFQUEUE 与 Windows WinDivert 路径没有这些密钥，也不会自动得到内层明文。HTTP/3 的解码入口 `feed_http3` 单独接收 QUIC 请求流及 QPACK 状态。

下一轮需要扩大完整客户端样本，并比较普通 H3 与其他高熵 UDP；在不同分片、丢包和中途抓包条件下统计召回率与误报率，再决定是否固化更强的协议候选或训练时序模型。
