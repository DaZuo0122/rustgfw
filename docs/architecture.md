# Linux-first implementation

当前支持 IPv4/IPv6 TCP/UDP 协议与端口规则、双向流决策缓存及 Linux NFQUEUE 逐包执行。Windows WinDivert 网络层适配器已可编译，本机连接的部分静态丢弃规则已接入 WFP，转发静态丢弃规则已接入 WinDivert 高优先级 DROP 句柄；真实驱动收发与 WFP 流量尚未验证。整体尚不是 OpenGFW 的功能替代品。

## 边界

- `rustgfw-core`：平台无关策略与执行接口。内核 packet ID、conntrack ID 和 WinDivert 地址只属于后端，不能作为跨平台流标识；后端通过 `FlowScope` 区分同端点的流量域。
- `rustgfw-linux`：NFQUEUE 收包和裁决。使用 nfq 的纯 Rust netlink 实现，并在本地依赖分支补充 conntrack zone 解析，暂不需要 C/C++ 桥接。
- `rustgfw-windows`：通过 WinDivert 2.2 DLL 捕获和重新注入网络层包，原样保留 WinDivert 地址；本机流量由 WFP 静态阻断开头连续的丢弃规则，转发流量由 WinDivert DROP 句柄执行同一静态前缀。已具备 FLOW 事件读取和按 compartment 限定的精确流规则接口；WinDivert 事件缺少 compartment ID，运行时关联与卸载生命周期尚未接通。
- 根二进制：按 `nfqueue` 或 `windivert` 选择 I/O 后端，共用默认动作、有序规则和应用层分析器；Linux 的 `nft=input|output|forward` 管理本实例 nft 表。

`PacketIo` 保持内核消息所有权直到裁决；错误上报调用者。`KernelPolicy` 独立描述安装和撤销，由 Linux 的 `NftPolicy` 实现。NFQUEUE 后端默认用 `(ct zone, ct id)` 集合卸载已阻断的 TCP 流；集合项超时 120 秒，持续流量经过 115 秒后在一次 nft 事务中重建该项以续期。逐流 nft 写入和撤销由有序工作线程批量执行，用户态在写入完成前继续阻断该流；已卸载流的 RST 在 nft 包路径删除集合项并放行，conntrack 销毁事件清理用户态状态。可选 `ctmark=` 用预留 bit 在下一 nft hook 写入 conntrack mark，从而避免依赖近似唯一的 32 位 ID。只写入 packet mark 并不等于连接策略生效。Linux 从 NFQUEUE 的 conntrack 属性取得 zone 和 ID，把两者纳入用户态流作用域，并在销毁事件键中保留有方向的 zone；缺少 conntrack 元数据时以无序入出接口对及 packet mark 建立单独作用域，保留跨包检查。若不同 zone 共用这些接口与 mark，内核未提供 zone 元数据，用户态仍无法区分它们。Windows 本机网络层按 WinDivert 接口和子接口编号区分作用域；转发层仍使用实例默认作用域，以保留跨接口的双向流状态。规则版本与方向性 zone 的内核卸载碰撞风险仍待完善。

Linux NFQUEUE 的 accept 表示恢复 netfilter 遍历，并不绕过其他链；Windows WinDivert 放行需要重新注入捕获的包，WFP 过滤规则的优先级与终止行为也不能映射成 Linux mark。用户提到的 wpf 在这里按 Windows Filtering Platform（WFP）理解。Windows 后端的当前边界见 [windows-backend.md](windows-backend.md)。

## 当前 Linux 路径

`cargo run --release -- nfqueue 100 accept`（或 `drop`）。外部规则模式需要已有 NFQUEUE 规则；指定 `nft=input|output|forward` 则由进程安装和撤销独占 nft 表。使用 `ctmark=0x80000000` 可启用需要预留 mark bit 的动态连接阻断路径。两种模式都需要 CAP_NET_ADMIN。默认队列拥塞不 fail-open；NFQUEUE 接收缓冲溢出时内核丢弃受影响的包，进程限频记录 `ENOBUFS` 后继续处理，避免撤销策略。ID 集合模式下 conntrack 销毁事件流的 `ENOBUFS`、netlink overrun、截断或损坏消息均表示生命周期信息丢失；后端先清空可能含过期 ID 的内核阻断集合，再关闭 ID 卸载并继续逐包裁决。若集合清空失败，则返回错误。关闭 GSO，截断或空载荷丢弃。进程不运行 sudo。

规则中的 queue bypass（无监听者）与 queue fail-open（队列满）是不同配置。托管模式收到 SIGINT/SIGTERM 时撤销表；崩溃和 SIGKILL 后仍可能留下表。没有无损排空保证。

## 协议与当前限制

DNS：`rustgfw nfqueue 100 accept dns-name=blocked.test` 匹配标准查询的 IN 类问题，域名大小写不敏感且配置可带尾点。UDP 目的端口 53 按数据报分析，不缓存域名裁决，因此同一 socket 的后续允许查询不受先前阻断影响。TCP 任一端口 53 启用长度前缀解析，支持连续消息、TCP 分段和压缩域名；命中后阻断整个 TCP 流。UDP 畸形查询丢弃，TCP 畸形消息或超出 `dns-message-bytes` 的消息结束分析并沿用传输层结果。尚不支持 DNS 修改、DoH/DoT、非 53 端口 DNS 自动识别。

TLS：`rustgfw nfqueue 100 accept tls-sni=blocked.test` 检查明文 ClientHello SNI，支持 TCP 分段和 TLS handshake record 分段。可同时指定 `http-host=`。SNI 精确匹配且忽略 ASCII 大小写；不解密 ECH 内层域名，不涵盖 QUIC。ClientHello 声明的正文长度上限 64 KiB，暂存字节预算由 `tls-buffer-bytes` 控制；超预算、无 SNI 或无法识别时结束该分析器并沿用传输层裁决。

HTTP/TLS/DNS TCP 通过 `AnalyzerRule` 注册，共享流表及每方向 TCP 重组。UDP DNS 通过 `DatagramRule` 注册，逐个数据报分析，不占用 TCP 流表；数据报规则可限制源端口、目的端口或任一端口，畸形结果可要求丢弃该包。两类分析器都报告带字段名的观察值，由规则回调匹配；新增同类分析器无需修改引擎中的协议匹配分支。TCP 观察结果区分完成与可继续分析，HTTP/TLS 报告后释放分析器，DNS TCP 可在同一流中报告后续查询。带端口限制的 TCP 分析器只为匹配端口的连接建立检查状态，其他 TCP 连接不占用检查流表。任一分析器匹配即阻断，其他分析器不能撤销这一决定。相同初始 SYN 重传保持状态，新的初始序号触发端点复用重建；这是被动流识别，不是内核 TCP 状态机的等价实现。

TCP 重组模块 `core::tcp` 已接入 `core::inspect` 的双向分析路径，支持连续字节交付、乱序缓存、重复数据裁剪和序号回绕。缓冲区冲突重叠会阻断流；已交付字节不保留副本。

`rustgfw nfqueue 100 accept http-host=blocked.test` 检查首个 HTTP/1 请求的所有 Host 头、绝对 URI 的 authority，以及 CONNECT 目标（大小写不敏感，含端口时需完整匹配）。任一值命中即阻断；无关头里的非 UTF-8 字节不妨碍 Host 识别。传输层规则先执行，Host 规则进一步阻断。识别前的包会放行；跨包分析不是代理式整请求缓冲。每方向乱序缓存及 HTTP 头默认各限 16 KiB，检查流表默认最多 4096 条，空闲 120 秒过期。双向 FIN 或未阻断流的 RST 会释放检查状态；单向 FIN 保留反向分析。容量满时先回收已完成且未阻断的检查状态；如果该长连接之后继续发包，可能再次进入首请求分析。超长或无法识别的 HTTP 头结束该分析器并沿用传输层结果；减小头预算可能让更长的阻断目标头无法被识别。不支持 keep-alive 多请求检查和 HTTP/2。

资源预算可由 `inspect-flows=N`、`transport-flows=N`、`flow-idle-seconds=N`、`reorder-bytes=N`、`http-header-bytes=N`、`tls-buffer-bytes=N`、`dns-message-bytes=N` 设置，Linux 和 Windows 命令使用同一组参数。例如 `rustgfw nfqueue 100 accept nft=forward inspect-flows=8192 transport-flows=131072 flow-idle-seconds=300 reorder-bytes=32768 http-header-bytes=32768 tls-buffer-bytes=131072 dns-message-bytes=65535 http-host=blocked.test`。`flow-idle-seconds` 同时作用于检查流表和传输层规则缓存；乱序预算按每方向计算。TLS 暂存预算默认 128 KiB，DNS TCP 单消息预算默认 65535 字节，UDP DNS 不受该预算影响。预算过低会使较大的匹配目标无法识别，此时使用传输层裁决。

2026-11-13/14 验证：Windows 与 Debian workspace 单元测试及 Clippy `-D warnings` 通过。Debian 使用隔离网络命名空间验证 nftables → NFQUEUE → 引擎路径的 UDP、跨包 HTTP、TLS SNI、DNS、动态 TCP 阻断、RST 撤销及 conntrack 销毁事件。双 veth 转发拓扑中 IPv4/IPv6 UDP 的放行和内核丢弃、分段 HTTP Host 的放行和阻断均通过；UDP nft 计数器分别记录 2 个入队包和 2 个内核丢弃包。两种 IP 版本各连续发送 300 个有序 UDP 包，全部到达。额外通过 prerouting `notrack` 验证无 conntrack ID 的 IPv4/IPv6 HTTP 流仍在用户态阻断，且未写入 `blocked_ct`。20,000 包突发触发 NFQUEUE `ENOBUFS`，修复后进程保持运行且后续包正常交付；这不证明突发中的 UDP 包无损。故障注入移除动态集合但保留队列规则后，`nft` 卸载写入失败仍由用户态阻断且进程保持运行。单条转发 UDP 流以约 1,750 包/秒持续 34 秒，60,000 包全部按序到达，之后 HTTP Host 阻断仍生效；尚未覆盖多流长期高负载及 conntrack 事件流溢出。未使用 sudo，未改主机防火墙。测试辅助脚本放本地忽略目录 `target/`，不提交。

通用观察结果改造后，在隔离 IPv4/IPv6 本机拓扑实测 DNS TCP 同一连接先放行查询、后续查询命中后阻断整条流；HTTP 分段 Host 与 TLS 分段 ClientHello 的回归也通过。

2026-11-15 多流回归：Debian 隔离本机网络命名空间中，1000 条 TCP 流、64 个客户端并发交替发送允许与阻断 HTTP 请求。原逐流同步 nft 路径有 27 个客户端未收到允许响应并出现 NFQUEUE `ENOBUFS`；批量卸载与内核 RST 清理后，连续三轮均为 500 条允许流收到响应、500 条阻断流无泄漏，连接关闭后 `blocked_ct` 无残留项，进程无溢出日志。一次紧接编译和故障注入的运行出现 40 个客户端超时，未见溢出日志；随后独立三轮及故障注入后两轮均未复现，原因尚未定位。单流回归确认内核 RST 删除规则计数器递增，方向性 zone、重复阻断与事件丢失恢复仍通过。该结果只覆盖这一隔离拓扑与负载，尚不代表长期多流压力测试完成。测试脚本仅放在忽略目录 `target/`。

多 zone 改造后，在隔离本机拓扑中设置 zone 7，与默认 zone 0 同时运行：两条 HTTP 阻断连接分别写入 `(7, id)` 和 `(0, id)` 集合项，后续包经内核丢弃，RST 撤销两个条目。又在隔离转发拓扑中以同一 IPv4/TCP 五元组分别建立 zone 7 与 zone 8 连接，完整握手后前者 HTTP 阻断并内核卸载，后者及后续包放行。缺少握手导致后续包无 conntrack 元数据时，按不同接口路径区分作用域，前者用户态阻断、后者放行。既有 IPv4/IPv6 FORWARD ID 模式和 `ctmark=` 模式回归通过；相同接口与 mark 下的无 conntrack 多 zone 流尚不可区分。

方向性 zone 另在隔离本机拓扑中以 `CT --zone-orig 7 --zone-reply 8` 验证：HTTP 命中后集合写入 `(8, id)`，原方向后续包及回复方向包都由内核丢弃，RST 随后撤销该集合项。用户态流作用域同时包含 conntrack ID，避免同五元组、同 zone 的不同连接共享分析状态；ID 仍是内核生成的近似唯一 32 位值，未证明所有碰撞场景均可隔离。

销毁事件丢失恢复在 Debian 隔离网络命名空间中分别注入 `NLMSG_OVERRUN`、损坏消息和超长数据报验证：已有内核阻断集合被清空，ID 卸载和销毁事件订阅被停用。IPv4/IPv6 转发及 HTTP 阻断回归通过；真实高负载事件溢出仍未复现。

并发连接回归在隔离本机网络命名空间中以 ID 集合和 `ctmark=` 两种模式各运行 IPv4、IPv6 的 128 条 TCP 连接；每种组合均有 64 条 HTTP 命中被阻断、64 条允许并收到响应，进程保持运行。此测试没有覆盖长时间多流压力。绝对 URI、第二条 Host 和无关非 UTF-8 头的 HTTP 阻断也通过实际 NFQUEUE 路径验证。

`ctmark=` 模式另在隔离 IPv4/IPv6 本机与双 veth 转发拓扑验证：HTTP 命中后当前包进入后续 hook 写入 conntrack mark，后续同方向和反向包由内核丢弃；本机被阻断流的 RST 命中清标放行规则。本机每种 IP 版本并行测试 32 条 TCP 连接，16 条命中阻断、16 条允许且可收到反向响应，未见跨连接误阻断。未测试主机与其他防火墙规则共享 mark 位的场景，部署时须预留该位。

现有规则示例：`rustgfw nfqueue 100 accept udp:53:drop tcp:443:drop`。
规则按顺序首次匹配，端口匹配任一端点，支持 `any:any:drop`。未匹配使用默认动作。
IPv6 扩展头会跳过；原子分片可解析，其他 IP 分片暂时丢弃，需要在 Linux conntrack 重组后入队。非 TCP/UDP 使用默认动作。
传输层规则缓存默认上限 65536，空闲 120 秒过期；缓存只加速静态传输层规则，不代表 TCP 连接跟踪或重组。规则替换立即清空缓存。单个引擎实例处理一个网络命名空间；同一命名空间内的 conntrack zone 由 `FlowScope` 区分。

1. Linux 长时间压力与故障测试：裁决错误、真实 conntrack 事件丢失和 ID 复用；量化队列拥塞时的丢包率，并验证卸载故障后的恢复。
2. 方向性 zone 的卸载碰撞风险、同接口同 mark 的无 conntrack 多 zone 流隔离、规则版本与配置热更新；解析 IPv4 非首片及更复杂的 IPv6 扩展头组合。
3. TLS/DNS 等分析器的累计输入和时间预算、HTTP keep-alive 多请求检查，以及未识别协议的处理策略。
4. 验证 Windows WFP 静态规则和真实 WinDivert 收发；再设计精确流阻断的生命周期与转发流量卸载。

参照本地 `references/opengfw` 的 io、engine、ruleset 和 analyzer 接口，以及 `references/gfw-rs` 的 NFQUEUE 尝试。未修改或复制参考项目代码。API 核对：[nfq Queue](https://docs.rs/nfq/0.2.6/nfq/struct.Queue.html)、[nfq Message](https://docs.rs/nfq/0.2.6/nfq/struct.Message.html)。
