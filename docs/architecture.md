# Linux-first implementation

当前支持 IPv4/IPv6 TCP/UDP 协议与端口规则、双向流决策缓存及 Linux NFQUEUE 逐包执行。Windows WinDivert 网络层适配器已可编译，本机连接的部分静态丢弃规则与动态 `DropFlow` 已接入 WFP，转发静态丢弃规则已接入 WinDivert 高优先级 DROP 句柄；真实驱动收发与 WFP 流量尚未验证。整体尚不是 OpenGFW 的功能替代品。

主流客户端协议与当前逐包识别能力的对照见[协议覆盖盘点](protocol-coverage.md)。

## 边界

- `rustgfw-core`：平台无关策略与执行接口。内核 packet ID、conntrack ID 和 WinDivert 地址只属于后端，不能作为跨平台流标识；后端通过 `FlowScope` 区分同端点的流量域。
- `rustgfw-linux`：NFQUEUE 收包和裁决。使用 nfq 的纯 Rust netlink 实现，并在本地依赖分支补充 conntrack zone 解析，暂不需要 C/C++ 桥接。
- `rustgfw-windows`：通过 WinDivert 2.2 DLL 捕获和重新注入网络层包，原样保留 WinDivert 地址；本机流量由 WFP 静态阻断开头连续的丢弃规则，转发流量由 WinDivert DROP 句柄执行同一静态前缀。本机 `DropFlow` 可对已观察到唯一端点 ID 的流安装按本机接口 LUID 限定、只匹配重新授权的 WFP 阻断规则，FLOW 删除事件负责撤销；动态规则到期也会撤销，以限制事件静默丢失时的残留时间，实际行为仍待真实驱动验证。
- 根二进制：按 `nfqueue` 或 `windivert` 选择 I/O 后端，共用默认动作、有序规则和应用层分析器；Linux 的 `nft=input|output|forward` 管理本实例 nft 表。

`PacketIo` 保持内核消息所有权直到裁决；错误上报调用者。`KernelPolicy` 独立描述安装和撤销，由 Linux 的 `NftPolicy` 实现。NFQUEUE 后端用独立线程持续读取 netlink socket，将消息放进容量 4096 的用户态队列；策略线程通过同一 socket 的复制描述符提交 verdict，避免策略与 nft 处理期间停止接收。后端默认用 `(ct zone, ct id)` 集合卸载已阻断的 TCP 流；集合项超时 120 秒，持续流量经过 115 秒后在一次 nft 事务中重建该项以续期。逐流 nft 写入和撤销由有序工作线程批量执行，用户态在写入完成前继续阻断该流；conntrack 销毁事件由独立线程持续接收、批量交给主循环，以免内核卸载让 NFQUEUE 空闲时丢失事件。退出或销毁事件丢失时先结束当前写入并取消排队批次，再删除或清空本实例的内核策略。已卸载流的 RST 在 nft 包路径删除集合项并放行，conntrack 销毁事件清理用户态卸载状态。可选 `ctmark=` 用预留 bit 在下一 nft hook 写入 conntrack mark，从而避免依赖近似唯一的 32 位 ID。只写入 packet mark 并不等于连接策略生效。Linux 从 NFQUEUE 的 conntrack 属性取得 zone 和有效 ID，把两者纳入用户态流作用域，并在销毁事件键中保留有方向的 zone；缺少有效 ID（包括零 ID）时以无序入出接口对及 packet mark 建立单独作用域，保留跨包检查。若不同 zone 共用这些接口与 mark，内核未提供 zone 元数据，用户态仍无法区分它们。Windows 本机和转发流量目前共用五元组作用域，以保留跨接口的双向流状态；WinDivert 的接口编号不能保证双向相同，跨网络域的重叠五元组仍需可靠身份来源才能隔离。规则版本与方向性 zone 的内核卸载碰撞风险仍待完善。

`Engine::replace_policy` 可在两次逐包处理之间替换整个用户态策略；新实例不会继承旧实例的流缓存。它没有自动修改内核规则。完整热更新需要先停止旧的异步卸载写入，再按后端语义切换内核静态规则并清理旧的动态裁决，最后替换用户态策略。Linux ID 集合可随 nft 表替换而清空；`ctmark=` 写在既存 conntrack 条目中，单个预留 bit 无法区分新旧规则版本，目前不能安全地沿用该位做无中断热更新。Windows WFP 和 WinDivert 的规则生命周期也需要单独编排。当前命令行没有热更新入口。

`Policy::decide` 可返回完整 IP 包替换裁决；Linux NFQUEUE 将替换包与 ACCEPT verdict 一起提交，Windows WinDivert 使用捕获时的地址重新注入替换包。`FlowAction::ReplaceUdpPayload` 让 UDP 流规则基于当前载荷生成新载荷，核心重建 IP/UDP 长度及校验和；过长或无法解析的替换结果丢弃当前包。TCP 流规则忽略此动作。多层 `Inspect` 策略按顺序检查前一层的替换包；后一层的丢弃或再次替换覆盖前一层结果。直接调用 `Policy::evaluate` 只得到放行或丢弃结果，包修改需要通过 `decide`/`PacketIo` 路径。有序表达式规则通过 `rules-file=path` 配置，语法见 [表达式规则](rules.md)。

Linux NFQUEUE 的 accept 表示恢复 netfilter 遍历，并不绕过其他链；Windows WinDivert 放行需要重新注入捕获的包，WFP 过滤规则的优先级与终止行为也不能映射成 Linux mark。用户提到的 wpf 在这里按 Windows Filtering Platform（WFP）理解。Windows 后端的当前边界见 [windows-backend.md](windows-backend.md)。

## 当前 Linux 路径

`cargo run --release -- nfqueue 100 accept`（或 `drop`）。外部规则模式需要已有 NFQUEUE 规则；指定 `nft=input|output|forward` 则由进程安装和撤销独占 nft 表。使用 `ctmark=0x80000000` 可启用需要预留 mark bit 的动态连接阻断路径。两种模式都需要 CAP_NET_ADMIN。默认队列拥塞不 fail-open；NFQUEUE 接收缓冲溢出时内核丢弃受影响的包，进程限频记录 `ENOBUFS` 后继续处理，避免撤销策略。ID 集合模式下 conntrack 销毁事件流的 `ENOBUFS`、netlink overrun、截断或损坏消息均表示生命周期信息丢失；后端先清空可能含过期 ID 的内核阻断集合，再关闭 ID 卸载并继续逐包裁决。若集合清空失败，则返回错误。关闭 GSO，截断或空载荷丢弃。进程不运行 sudo。

规则中的 queue bypass（无监听者）与 queue fail-open（队列满）是不同配置。托管模式收到 SIGINT/SIGTERM 时撤销表；崩溃和 SIGKILL 后仍可能留下表。没有无损排空保证。

## 协议与当前限制

DNS：`rustgfw nfqueue 100 accept dns-name=blocked.test` 在 UDP 上匹配标准查询的 IN 类问题；TCP 可匹配标准查询或响应中的 IN 类问题，域名大小写不敏感且配置可带尾点。UDP 目的端口 53 按数据报分析，不缓存域名裁决，因此同一 socket 的后续允许查询不受先前阻断影响。TCP 任一端口 53 启用长度前缀解析，支持连续消息、TCP 分段和压缩域名；每条消息的表达式字段独立替换，命中后阻断整个 TCP 流。表达式还可读取 DNS ID、查询/响应标记、操作码、单问题类型、响应码，以及答案段内 IN 类 A、AAAA 和 CNAME 值；IP 答案支持 CIDR 比较。目前解析 DNS 首部、问题段与答案段，暂不检查权威段和附加段；已解析部分畸形时 UDP 丢弃该包，TCP 结束分析并沿用传输层结果；TCP 超出 `dns-message-bytes` 也结束分析。尚不支持 DNS 修改、DoH/DoT、非 53 端口 DNS 自动识别。

TLS：`rustgfw nfqueue 100 accept tls-sni=blocked.test` 检查明文 ClientHello SNI，表达式还可匹配客户端提供的 ALPN、版本列表、ECH 扩展标记，以及反向 ServerHello 的版本、密码套件和可见 ALPN。支持 TCP 分段和 TLS handshake record 分段，可同时指定 `http-host=`。SNI 精确匹配且忽略 ASCII 大小写；不解密 ECH 内层域名或 TLS 1.3 的服务端 ALPN，QUIC 使用单独的 Initial 分析器。遇到 HelloRetryRequest 时继续读取最终 ServerHello，并跳过两者之间的兼容性 ChangeCipherSpec 记录。Hello 声明的正文长度上限 64 KiB，暂存字节预算由 `tls-buffer-bytes` 控制；超预算或无法识别时结束该分析器并沿用传输层裁决。

SSH：表达式可用 `ssh.protocol`、`ssh.software`、`ssh.banner` 匹配 TCP 任一方向的首次 SSH 标识行，例如 `ssh.software contains "OpenSSH"`。分析器支持分段标识行和此前的提示行，不限定端口；单方向默认读取最多 1024 字节，可用 `ssh-banner-bytes=N` 调整。无法识别或超预算时结束该方向的分析，不解析后续加密握手。

WireGuard：表达式引用 `wireguard.*` 字段时按需启用双向 UDP 分析器，不限定端口。它检查四种报文的头部类型、保留字节及长度，保留最近六个发送索引供反方向接收索引匹配；不验证密文和握手身份。新数据报原子替换该协议的观察字段，避免把旧报文的发送索引与新报文的数据类型错误串联。

OpenVPN：表达式引用 `openvpn.*` 字段时按需启用双向 TCP 或 UDP 分析器，不限定端口。客户端和服务端 hard reset 必须依次出现在相反方向；TCP 支持长度前缀与分段，确认握手后停止分析。UDP 随后跟踪控制或数据 opcode 与双向包数，新数据报替换本次协议字段。它是报文形状与握手顺序的启发式识别，不验证加密身份。

SOCKS：表达式引用 `socks.*` 字段时按需启用 TCP 首方向请求分析器，不限定端口。SOCKS4/4a/5 请求目标、命令与地址类型成为流观察值；SOCKS5 可跨分段跳过用户名密码认证帧，但凭据不进入观察值。服务器应答暂不分析。

VLESS：表达式引用 `vless.*` 字段时按需启用 TCP 首方向请求分析器，不限定端口。仅解析没有 TLS/REALITY 等保护层的 v0 首部，支持 TCP、UDP、Mux、Rvs 命令和目标地址；`vless.candidate` 仅表示线缆结构匹配，不验证 UUID。Mux/Rvs 没有目标地址字段。

FET：表达式引用 `fet.*` 字段时按需分析首方向首次交付的 TCP 数据，最多采样 8192 字节。分析器按 OpenGFW 的五组豁免条件报告 `fet.candidate` 与各项统计值；这是统计启发式，不是加密真实性验证或具体代理协议识别。首次采样受 TCP 分段影响，可在规则中约束 `fet.sample_len` 并与其他字段组合。

Trojan：表达式引用 `trojan.*` 字段时按需启用双向 TCP 长度序列分析器。它从客户端兼容性 ChangeCipherSpec 开始累计前四段交替方向的字节数，报告序列和统计候选标记；树模型移植自 OpenGFW，单独附带 MPL-2.0 许可。特征依赖交付分段及换向时机，不验证加密内层协议；规则可将候选标记与 TLS、FET 或端点信息组合。

QUIC：表达式引用 `quic.*` 字段时按需启用双向 UDP 流分析器，不限定端口。它用 v1/v2 Initial 公开密钥派生和 `ring` 的首部保护、AEAD 接口检查客户端 Initial，把 CRYPTO 帧按偏移重组后复用 TLS ClientHello 的 SNI、ALPN、版本列表、ECH 扩展标记和 DATAGRAM 接收上限解析。首个能解开的客户端连接 ID 决定流内分析对象，其他连接的 Initial 不会覆盖已收集片段；完整 ClientHello 后结束分析。Initial 的密钥公开，解密成功不认证客户端身份。RFC 密钥向量、自构造加密包及 OpenGFW 只读抓包样本已在本地测试；Linux 后端只需转交 UDP 数据报，无协议专用 I/O 逻辑。Hysteria2 的可见范围和论文见[研究记录](hysteria2-quic.md)。

HTTP 通过 `BidirectionalAnalyzerRule` 注册，TLS/DNS TCP/SSH 通过 `AnalyzerRule` 注册，共享流表及每方向 TCP 重组。UDP DNS 通过 `DatagramRule` 注册，逐个数据报分析，不占用 TCP 流表；数据报规则可限制源端口、目的端口或任一端口，畸形结果可要求丢弃该包。WireGuard 和表达式 DNS UDP 通过 `UdpStreamRule` 注册，保留跨数据报的双向状态。分析器报告带字段名的观察值，由规则回调匹配；新增同类分析器无需修改引擎中的协议匹配分支。TCP 观察结果区分完成与可继续分析，TLS/SSH 报告后释放分析器，DNS TCP 与 HTTP/1 可在同一流内报告后续消息。HTTP/1 同包多消息以分批观察结果逐条求值；响应批次恢复对应请求字段作为上下文，不将其计为新观察值。带端口限制的 TCP 分析器只为匹配端口的连接建立检查状态，其他 TCP 连接不占用检查流表。任一分析器匹配即阻断，其他分析器不能撤销这一决定。相同初始 SYN 重传保持状态，新的初始序号触发端点复用重建；这是被动流识别，不是内核 TCP 状态机的等价实现。

核心还支持 `AnalyzerRule::observing` 与 `FlowRule`：分析器只产出观察值，流级回调通过 `FlowContext` 读取同一双向 TCP 流的多个字段并组合判断，也可直接根据端点与作用域判断。`BidirectionalAnalyzerRule` 为整条 TCP 流创建一个分析器实例，两方向共用内部状态，但输入仍分别经过 TCP 重组；原有 `AnalyzerRule` 继续按方向创建实例。`FlowContext` 同时提供当前包的 `source`/`destination`、载荷 `payload` 和建流时固定的 `origin`/`target`，`reverse` 标示当前包相对建流方向是否反向。规则按注册顺序取第一个命中的 `Allow` 或 `Block`；`Allow` 结束该流的应用层检查，传输层规则仍逐包执行。`UdpStreamRule` 为双向 UDP 流创建独立分析器实例，保留跨数据报观察值并复用流级规则；`DropPacket` 只丢当前 UDP 数据报，对 TCP 则阻断整条流。原有 `DatagramRule` 继续按单个数据报执行，当前命令行的 UDP DNS 使用这一路径。每个字段保留最近一次观察批次的所有值；TCP 的新初始 SYN、空闲过期或显式清空会丢弃相关属性。平台后端提供的 `FlowScope` 参与流键，防止不同流量域复用属性。Linux 的动态内核卸载只处理 TCP `DropFlow`，UDP 阻断留在用户态逐包执行。

表达式规则在新建检查流前保守判断协议和端点是否可能匹配当前或后续反向包；无关流量不会占用检查流表，也不会因为检查流表满而被误丢。已建立的检查流仍按原状态继续处理；有流规则的检查状态不会仅因分析器结束或缺席就在容量清理时被移除，后续反向包仍能读取建流方向和观察值。自定义 `FlowRule` 默认视为可能匹配所有流；需要提前筛选时可提供覆盖两个方向及未来观察值的候选判断。

TCP 重组模块 `core::tcp` 已接入 `core::inspect` 的双向分析路径，支持连续字节交付、乱序缓存、重复数据裁剪和序号回绕。缓冲区冲突重叠会阻断流；已交付字节不保留副本。

已有解码结果的接入方可调用 `Inspect::feed_decoded(DecodedStream { scope, stream_id, origin, target, reverse, bytes })`。`scope` 标识外层连接，`stream_id` 区分其内部逻辑流；调用方按方向有序交付字节，并在结束时调用 `close_decoded`。这一路径跳过 IP/TCP 包解析与内核传输策略，复用相同的流分析器、观察批次和表达式规则，返回值只裁决该逻辑流，具体阻断由提供解码字节的接入方执行。普通逐包路径仍自行 TCP 重组。Linux NFQUEUE 不提供 TLS 或代理载荷解密，因此当前命令行没有解码字节的来源；此接口供后续代理或解密适配器使用。

HTTP/3 的解码流使用 `Inspect::feed_http3`：连接状态按 `FlowScope` 隔离，QPACK 编码器流与请求 HEADERS 共享动态表，请求和响应按 QUIC stream ID 关联。每条请求流独立运行 UDP 表达式规则；返回的 `DecodedVerdict` 携带被裁决的请求流 ID，以处理 QPACK 更新触发的延迟头部事件。同一流的 HEADERS 会等前面的 QPACK 阻塞头部解开后再依次交付。普通头部名称按方向进入 `http3.request_header_name` 或 `http3.response_header_name`，头部值不进入观察字段。服务端响应若先于客户端请求交付，响应字段先独立裁决，待请求字段到达后会按原顺序重新裁决带请求上下文的响应；提前出现的 `Block` 可立即执行，`Allow` 等到请求上下文确定后才终止检查。调用方需要验证协商的 HTTP/3 ALPN，并提供已解密、按流有序的 QUIC 字节。当前 Linux NFQUEUE 后端尚无这种适配器，因此逐包规则只能使用 QUIC Initial 的可见字段。

QUIC 迁移时，解码接入方保持同一连接 `FlowScope` 并提交当前路径端点；HTTP/3 规则的 `source`/`destination` 更新，首次端点 `origin`/`target` 与请求事实保留。逐包路径不会凭未认证的连接 ID 合并不同五元组。观察限制和 QUICstep 对照见 [QUIC 连接迁移](quic-migration.md)。

命令行的 `decoded-http3` 模式把已解密流事件接入这条核心路径，并按流输出裁决；输入格式见 [已解密流输入](decoded-streams.md)。它不接管 UDP socket 或 NFQUEUE，便于在 Linux 上独立验证规则与 QPACK 状态。

引擎核心通过 `tracing` 发布结构化裁决与诊断事件，输出由调用方配置。命令行默认写入标准错误，级别和格式见 [引擎日志](logging.md)。

`rustgfw nfqueue 100 accept http-host=blocked.test` 连续检查 HTTP/1 请求的所有 Host 头、绝对 URI 的 authority，以及 CONNECT 目标（大小写不敏感，含端口时需完整匹配）。表达式可读取请求方法、目标、版本及反向响应的状态码、版本；两方向观察值保存在同一流内。同包多条消息依次求值，上一条请求的字段不会与下一条请求的 Host 混用。流水线响应按请求顺序关联，临时 1xx 响应保留待决请求；HEAD 响应没有消息体，其声明的 `Content-Length` 不会挡住后续响应。任一 Host 值命中即阻断；无关头里的非 UTF-8 字节不妨碍 Host 识别。传输层规则先执行，Host 规则进一步阻断。识别前的包会放行；跨包分析不是代理式整请求缓冲。每方向乱序缓存及 HTTP 头默认各限 16 KiB，TCP 与可选的有状态 UDP 检查共用默认最多 16384 条流的容量，空闲 120 秒过期。双向 FIN 或未阻断流的 RST 会释放检查状态；单向 FIN 保留反向分析。容量满时只在有新完成流时扫描回收；仍满则丢弃新流的包。阻断流的 RST 不单凭包头清除用户态阻断状态。`Content-Length` 消息体按声明长度跳过；最终采用 chunked 传输编码时，解析块边界和 trailer 后继续检查下一条消息。无法定界的响应体、含糊的长度声明、超长或无法识别的 HTTP 头会结束该方向分析并沿用传输层结果；减小头预算可能让更长的阻断目标头无法被识别。成功 CONNECT 和 101 协议切换后的流不再按 HTTP 消息分析。HTTP/1 分析器不解析 HTTP/2；独立的明文 h2c 分析器按 stream ID 关联交错的请求和响应，详见 [表达式规则](rules.md)。

资源预算可由 `inspect-flows=N`、`transport-flows=N`、`flow-idle-seconds=N`、`reorder-bytes=N`、`http-header-bytes=N`、`tls-buffer-bytes=N`、`dns-message-bytes=N` 设置，Linux 和 Windows 命令使用同一组参数。例如 `rustgfw nfqueue 100 accept nft=forward inspect-flows=8192 transport-flows=131072 flow-idle-seconds=300 reorder-bytes=32768 http-header-bytes=32768 tls-buffer-bytes=131072 dns-message-bytes=65535 http-host=blocked.test`。`flow-idle-seconds` 同时作用于检查流表和传输层规则缓存；乱序预算按每方向计算。TLS 暂存预算默认 128 KiB，DNS TCP 单消息预算默认 65535 字节，UDP DNS 不受该预算影响。预算过低会使较大的匹配目标无法识别，此时使用传输层裁决。

SSH 标识行单方向读取预算另由 `ssh-banner-bytes=N` 设置，默认 1024 字节。

2026-11-13/14 验证：Windows 与 Debian workspace 单元测试及 Clippy `-D warnings` 通过。Debian 使用隔离网络命名空间验证 nftables → NFQUEUE → 引擎路径的 UDP、跨包 HTTP、TLS SNI、DNS、动态 TCP 阻断、RST 撤销及 conntrack 销毁事件。双 veth 转发拓扑中 IPv4/IPv6 UDP 的放行和内核丢弃、分段 HTTP Host 的放行和阻断均通过；UDP nft 计数器分别记录 2 个入队包和 2 个内核丢弃包。两种 IP 版本各连续发送 300 个有序 UDP 包，全部到达。额外通过 prerouting `notrack` 验证无 conntrack ID 的 IPv4/IPv6 HTTP 流仍在用户态阻断，且未写入 `blocked_ct`。20,000 包突发触发 NFQUEUE `ENOBUFS`，修复后进程保持运行且后续包正常交付；这不证明突发中的 UDP 包无损。故障注入移除动态集合但保留队列规则后，`nft` 卸载写入失败仍由用户态阻断且进程保持运行。单条转发 UDP 流以约 1,750 包/秒持续 34 秒，60,000 包全部按序到达，之后 HTTP Host 阻断仍生效；尚未覆盖多流长期高负载及 conntrack 事件流溢出。未使用 sudo，未改主机防火墙。测试辅助脚本放本地忽略目录 `target/`，不提交。

通用观察结果改造后，在隔离 IPv4/IPv6 本机拓扑实测 DNS TCP 同一连接先放行查询、后续查询命中后阻断整条流；HTTP 分段 Host 与 TLS 分段 ClientHello 的回归也通过。

2026-11-16 HTTP/1 连续消息回归：Debian 隔离网络命名空间的真实 NFQUEUE 路径中，同一 TCP 连接首个允许请求到达服务端、第二个阻断 Host 请求未到达；两条请求合并发送时整包被阻断；定长 POST 消息体中的伪 Host 请求未触发阻断。测试脚本只保留在忽略的 `target/` 目录。

同一隔离路径随后验证 chunked POST：块数据中的伪阻断 Host 和 trailer 未触发误判，trailer 后紧接的允许请求到达服务端，再后的阻断 Host 请求被拦截。测试脚本仍只保留在忽略的 `target/` 目录。

2026-11-16 DNS 答案规则回归：Debian 上使用无 `sudo` 的用户网络命名空间运行真实 nftables → NFQUEUE → 引擎路径。UDP 允许查询及其 A 响应到达对端；AAAA 查询按 `dns.qtype` 被丢弃；包含 `203.0.113.7` A 答案的响应按 `fresh.dns.answer_ipv4 in 203.0.113.0/24` 被丢弃；同一 UDP 流随后无答案的响应成功到达客户端，验证答案字段不会残留。测试脚本和规则文件只存放在忽略的 `target/` 目录。

2026-11-15 多流回归：Debian 隔离本机网络命名空间中，1000 条 TCP 流、64 个客户端并发交替发送允许与阻断 HTTP 请求。原逐流同步 nft 路径有 27 个客户端未收到允许响应并出现 NFQUEUE `ENOBUFS`；批量卸载与内核 RST 清理后，连续三轮均为 500 条允许流收到响应、500 条阻断流无泄漏，连接关闭后 `blocked_ct` 无残留项，进程无溢出日志。一次紧接编译和故障注入的运行出现 40 个客户端超时，未见溢出日志；随后独立三轮及故障注入后两轮均未复现，原因尚未定位。单流回归确认内核 RST 删除规则计数器递增，方向性 zone、重复阻断与事件丢失恢复仍通过。该结果只覆盖这一隔离拓扑与负载，尚不代表长期多流压力测试完成。测试脚本仅放在忽略目录 `target/`。

2026-11-15 多流故障定位与修复：在同一 1000 流、64 并发测试中复现 1～50 个客户端建连超时。诊断显示新连接的初始 SYN 可带旧连接的 `Established` conntrack ID，并命中用户态阻断缓存；内核 ID 集合和预留 mark 位也可能在连接元数据复用时拦截新 SYN。现在 ID 模式将命中阻断集合的 SYN/SYN-ACK 送回队列，用户态对初始 SYN 重新评估并撤销旧 ID；`ctmark=` 模式在新初始 SYN 上清除预留位。NFQUEUE 内核队列长度设为 4096，netlink 接收缓冲请求 4 MiB（实际值受系统 `rmem_max` 限制）。修复后 ID 模式和 `ctmark=` 模式各连续 20 轮、每轮 1000 流均有 500 条允许请求成功、500 条阻断请求无泄漏；单流动态阻断、RST 清理、销毁事件丢失恢复也通过。纯 TCP 基线 20 轮和无卸载 NFQUEUE 模式 30 轮均通过。偶见 SYN 重传，尚不能据此断言所有负载下零丢包。测试脚本仍只存放在本地忽略目录 `target/`。

多 zone 改造后，在隔离本机拓扑中设置 zone 7，与默认 zone 0 同时运行：两条 HTTP 阻断连接分别写入 `(7, id)` 和 `(0, id)` 集合项，后续包经内核丢弃，RST 撤销两个条目。又在隔离转发拓扑中以同一 IPv4/TCP 五元组分别建立 zone 7 与 zone 8 连接，完整握手后前者 HTTP 阻断并内核卸载，后者及后续包放行。缺少握手导致后续包无 conntrack 元数据时，按不同接口路径区分作用域，前者用户态阻断、后者放行。既有 IPv4/IPv6 FORWARD ID 模式和 `ctmark=` 模式回归通过；相同接口与 mark 下的无 conntrack 多 zone 流尚不可区分。

方向性 zone 另在隔离本机拓扑中以 `CT --zone-orig 7 --zone-reply 8` 验证：HTTP 命中后集合写入 `(8, id)`，原方向后续包及回复方向包都由内核丢弃，RST 随后撤销该集合项。用户态流作用域同时包含 conntrack ID，避免同五元组、同 zone 的不同连接共享分析状态；ID 仍是内核生成的近似唯一 32 位值，未证明所有碰撞场景均可隔离。

销毁事件丢失恢复在 Debian 隔离网络命名空间中分别注入 `NLMSG_OVERRUN`、损坏消息和超长数据报验证：已有内核阻断集合被清空，ID 卸载和销毁事件订阅被停用。IPv4/IPv6 转发及 HTTP 阻断回归通过。后续 10000 流测试真实复现了事件 socket 的 `ENOBUFS`；改为独立线程接收后，该负载下未再出现事件丢失。

2026-11-15 10000 流回归：Debian 隔离本机网络命名空间，64 个客户端并发，允许和阻断 HTTP 请求各 5000 条。纯 TCP 基线全部完成；无应用检查的 NFQUEUE 对照测试另以 5000 流全部完成。无内核卸载的 HTTP 检查、ID 集合卸载及 `ctmark=` 卸载均达到 5000 条允许请求成功、5000 条阻断请求无泄漏，约 36 秒完成。原默认容量 4096 时，大量阻断流尚未过期，检查流表满后按策略丢弃新流包，造成约 1600 个客户端超时；容量满时反复扫描整表又加重延迟。现默认容量为 16384，满表扫描只在出现完成流后执行。ID 与 `ctmark=` 的原 10000 流运行均在收尾记录一次 NFQUEUE `ENOBUFS`。随后 NFQUEUE 改为独立收包线程，在同样负载下分别运行 ID 集合、`ctmark=` 和外部 NFQUEUE 规则三种模式，各有 5000 条允许请求成功、5000 条阻断请求无泄漏，未见进程 `ENOBUFS` 日志；注入 conntrack 事件丢失的回归也通过。远端主机 `rmem_max` 为 212992，4 MiB 的 `SO_RCVBUF` 请求实际只得到 425984 字节，因此通过缩短 socket 积压时间改善该负载表现。TCP 统计仍有 SYN 重传，成功计数不代表突发中零丢包。测试脚本仍只存放在忽略的 `target/` 目录。

后续一次 20000 流、128 并发、检查流表容量 32768 的 ID 集合运行有 8 条连接在 6 秒内未完成建连；相同参数的纯 TCP 基线 20000 条均完成。引擎无 `ENOBUFS` 日志，这次失败尚未定位。

并发连接回归在隔离本机网络命名空间中以 ID 集合和 `ctmark=` 两种模式各运行 IPv4、IPv6 的 128 条 TCP 连接；每种组合均有 64 条 HTTP 命中被阻断、64 条允许并收到响应，进程保持运行。此测试没有覆盖长时间多流压力。绝对 URI、第二条 Host 和无关非 UTF-8 头的 HTTP 阻断也通过实际 NFQUEUE 路径验证。

`ctmark=` 模式另在隔离 IPv4/IPv6 本机与双 veth 转发拓扑验证：HTTP 命中后当前包进入后续 hook 写入 conntrack mark，后续同方向和反向包由内核丢弃；本机被阻断流的 RST 命中清标放行规则。本机每种 IP 版本并行测试 32 条 TCP 连接，16 条命中阻断、16 条允许且可收到反向响应，未见跨连接误阻断。未测试主机与其他防火墙规则共享 mark 位的场景，部署时须预留该位。

现有规则示例：`rustgfw nfqueue 100 accept udp:53:drop tcp:443:drop`。
规则按顺序首次匹配，端口匹配任一端点，支持 `any:any:drop`。未匹配使用默认动作。
IPv6 扩展头会跳过；原子分片可解析，其他 IP 分片暂时丢弃，需要在 Linux conntrack 重组后入队。非 TCP/UDP 使用默认动作。
传输层规则缓存默认上限 65536，空闲 120 秒过期；缓存只加速静态传输层规则，不代表 TCP 连接跟踪或重组。规则替换立即清空缓存。单个引擎实例处理一个网络命名空间；同一命名空间内的 conntrack zone 由 `FlowScope` 区分。

1. Linux 长时间压力与故障测试：裁决错误、真实 conntrack 事件丢失和 ID 复用；量化队列拥塞时的丢包率，并验证卸载故障后的恢复。
2. 方向性 zone 的卸载碰撞风险、同接口同 mark 的无 conntrack 多 zone 流隔离、规则版本与配置热更新；解析 IPv4 非首片及更复杂的 IPv6 扩展头组合。
3. TLS/DNS 等分析器的累计输入和时间预算、HTTP 流水线响应关联，以及未识别协议的处理策略。
4. 验证 Windows WFP 静态与动态规则、真实 WinDivert 收发；验证 FLOW 删除事件静默丢失后的规则回收和同五元组复用，再设计转发流量卸载。

参照本地 `references/opengfw` 的 io、engine、ruleset 和 analyzer 接口，以及 `references/gfw-rs` 的 NFQUEUE 尝试。参考项目保持只读；Trojan 决策树由 OpenGFW 模型移植，单独标注原始出处和 MPL-2.0 许可。API 核对：[nfq Queue](https://docs.rs/nfq/0.2.6/nfq/struct.Queue.html)、[nfq Message](https://docs.rs/nfq/0.2.6/nfq/struct.Message.html)。
