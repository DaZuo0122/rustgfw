# 表达式规则

Linux 和 Windows 命令都接受 `rules-file=path`。文件是 JSON；规则按数组顺序匹配，首个产生动作的规则生效。它不是 OpenGFW 配置格式的兼容实现。

```json
{
  "expressions": {
    "blocked_web": "http.host == \"blocked.test\" || tls.sni == \"blocked.test\"",
    "blocked_dns": "proto == udp && fresh.dns.qname == \"blocked.test\""
  },
  "rules": [
    {
      "name": "block web host",
      "expr": "proto == tcp && @blocked_web",
      "action": "block"
    },
    {
      "name": "drop one DNS query",
      "expr": "@blocked_dns",
      "action": "drop_packet"
    },
    {
      "name": "rewrite UDP payload",
      "expr": "proto == udp && dst.port == 5353 && payload == \"old\"",
      "action": "replace_udp_payload",
      "replacement": "new"
    },
    {
      "name": "drop correlated WireGuard data",
      "expr": "proto == udp && fresh.wireguard.type == data && wireguard.receiver_matched == true",
      "action": "drop_packet"
    },
    {
      "name": "drop OpenVPN after reverse reset",
      "expr": "proto == udp && openvpn.stage == handshake && openvpn.client_reset == 7 && openvpn.server_reset == 8",
      "action": "drop_packet"
    },
    {
      "name": "block SOCKS proxy target",
      "expr": "proto == tcp && socks.command == connect && socks.target_host == blocked.test",
      "action": "block"
    },
    {
      "name": "drop QUIC Initial by SNI",
      "expr": "proto == udp && fresh.quic.sni == blocked.test",
      "action": "drop_packet"
    }
  ]
}
```

例如 `rustgfw nfqueue 100 accept nft=forward rules-file=rules.json`。`rules-file` 可以和现有的传输层规则、资源预算参数一起使用；传输层规则先执行。当前没有规则文件热更新入口。

表达式使用 `!`、`&&`、`||` 和括号，优先级依次递减。比较值可用裸词或双引号字符串；字符串支持 `\"`、`\\`、`\n`、`\r`、`\t`。观察字段、`payload` 和 `payload_hex` 支持 `==`、`!=`、`contains`、`starts_with`、`ends_with`；域名等观察字段比较忽略 ASCII 大小写，`http.method`、`http.target`、`tls.alpn`、`tls.server_alpn`、`quic.alpn`、`dtls.alpn`、`dtls.server_alpn` 及载荷区分大小写。端口和 `payload.len` 支持 `==`、`!=`、`<`、`<=`、`>`、`>=`；`proto`、`reverse` 和 IP 地址支持 `==`、`!=`。可比较的内容：

可选的 `expressions` 对象定义命名条件，在规则或其他命名条件中以 `@名称` 引用。加载时递归展开引用，并检查未知名称和循环引用；展开后的规则按正常布尔逻辑求值。命名条件只组合匹配条件，动作仍由各条规则指定。

| 左侧 | 写法 | 含义 |
| --- | --- | --- |
| `proto` | `proto == tcp` / `udp` | 传输协议 |
| `src.port`、`dst.port`、`origin.port`、`target.port` | `dst.port >= 1024 && dst.port < 65535` | 当前包或建流时的端口 |
| 对应的 `.ip` | `src.ip in 10.0.0.0/8` 或 `src.ip == 10.0.0.1` | CIDR 或单个地址，支持 IPv4/IPv6 |
| `reverse` | `reverse == true` | 当前包是否与建流方向相反 |
| `payload` | `payload contains "old"` | 当前传输层载荷中的字节片段 |
| `payload.len` | `payload.len >= 32` | 当前包传输层载荷的字节数；TCP 按当前分段计算 |
| `payload_hex` | `payload_hex starts_with 0x00ff` | 当前传输层载荷中的二进制字节；十六进制数字须成对 |
| `http.host`、`http.method`、`http.target`、`http.request_version` | `http.method == CONNECT && http.target ends_with :443` | TCP HTTP/1 请求的请求行与可见 authority/Host |
| `http.status`、`http.response_version` | `http.status >= 400` | TCP HTTP/1 响应的状态码与版本；状态码是十进制观察值 |
| `http.upgrade_offer`、`http.upgrade_selected` | `http.upgrade_offer == websocket && fresh.http.upgrade_selected == websocket` | 明文 HTTP/1.1 的 Upgrade 提议及 101 响应选择；两侧均要求 `Connection: Upgrade`，只能说明可见的升级协商 |
| `http2.stream_id`、`http2.method`、`http2.path`、`http2.authority`、`http2.status` | `http2.path == /blocked && fresh.http2.status == 404` | 明文 HTTP/2 的流 ID、请求伪头部与响应状态；响应按 stream ID 恢复对应请求字段 |
| `http3.stream_id`、`http3.method`、`http3.path`、`http3.authority`、`http3.status`、`http3.request_header_name`、`http3.response_header_name` | `http3.path == /blocked && fresh.http3.status == 404` | 已解密 HTTP/3 流的请求和响应字段；请求与响应的普通头部名称分开报告，不保存头部值；需要调用 `Inspect::feed_http3`，普通 NFQUEUE 包路径不产生这些字段 |
| `mux_cool.session_id`、`mux_cool.status`、`mux_cool.network`、`mux_cool.host`、`mux_cool.port` | `mux_cool.host == blocked.test && fresh.mux_cool.status == keep` | 可见 Mux.Cool 载体内的子连接 ID、状态与目标；响应按 ID 恢复客户端 New 帧中的目标 |
| `sing_mux.version`、`sing_mux.protocol`、`sing_mux.padding` | `sing_mux.protocol == h2mux && fresh.http2.method == CONNECT` | 明文 sing-mux 版本、承载协议及 padding 标志；支持 `h2mux`、`smux`、`yamux` |
| `sing_mux.stream_id`、`sing_mux.frame`、`sing_mux.network`、`sing_mux.host`、`sing_mux.port` | `sing_mux.protocol == h2mux && fresh.sing_mux.host == example.org && http2.method == CONNECT` | 三种 sing-mux 承载的子流 ID 与目标网络、地址、端口；`sing_mux.frame` 目前只用于 `smux`/`yamux` 帧事件 |
| `tls.sni`、`tls.alpn` | `tls.alpn == h2` | 流内最近一次观察批次的任一值；`tls.alpn` 为客户端提供的协议列表 |
| `dns.id`、`dns.qr`、`dns.opcode`、`dns.qname`、`dns.qtype`、`dns.rcode` | `dns.qname == example.test && dns.qtype == 28` | DNS 消息 ID、查询或响应、操作码、IN 类问题域名与单问题类型；`rcode` 只在响应上报告首部低四位，数值字段为十进制字符串 |
| `dns.answer_ipv4`、`dns.answer_ipv6`、`dns.answer_cname` | `dns.qname == example.test && fresh.dns.answer_ipv4 in 203.0.113.0/24` | 响应答案段中的 IN 类 A、AAAA 地址与 CNAME 目标；一个字段可有多个值 |
| `tls.supported_version`、`tls.ech_extension` | `tls.supported_version == 0x0304 && tls.ech_extension == true` | ClientHello 的 `supported_versions` 提供列表及 ECH 扩展是否出现；列表中的版本各产生一个观察值 |
| `tls.client_legacy_version`、`tls.client_cipher_suite`、`tls.client_extension` | `tls.client_cipher_suite == 0x1301 && tls.client_extension == 0xfe0d` | ClientHello 的 legacy version，以及按线缆顺序分别报告的密码套件和扩展类型；单项字段可有多个值 |
| `tls.client_random`、`tls.client_session_id`、`tls.client_session_id_len`、`tls.client_compression_methods` | `tls.client_session_id_len == 32 && tls.client_compression_methods == 0x00` | ClientHello 的 random 和 session ID 为小写十六进制字节串，长度为十进制；压缩方法按线缆顺序用逗号连接。相同后缀也适用于 `quic.tls_client_*` 与 `dtls.client_*`；[RFC 9001 §8.4](https://www.rfc-editor.org/rfc/rfc9001.html#section-8.4) 禁止 QUIC 客户端使用非空 session ID 的兼容模式 |
| `tls.client_cipher_suites`、`tls.client_extensions`、对应的 `_no_grease` 字段 | `tls.client_cipher_suites_no_grease == "0x1301,0x1302"` | 逗号分隔的有序十六进制列表；原始字段保留 GREASE 值，`_no_grease` 只删除 RFC 8701 保留值，仍保留其余项顺序 |
| `tls.client_supported_group`、`tls.client_signature_algorithm`、`tls.client_key_share_group`，以及各自的有序复数和 `_no_grease` 字段 | `tls.client_supported_group == 0x001d && tls.client_key_share_groups_no_grease == 0x001d` | ClientHello 扩展 `supported_groups`、`signature_algorithms` 和 `key_share` 内的提议顺序；不存在的扩展不产生字段，值均为四位十六进制 |
| `tls.server_version`、`tls.server_cipher`、`tls.server_alpn` | `tls.alpn == h2 && fresh.tls.server_version == 0x0304` | TCP ServerHello 所选版本与密码套件以四位十六进制字符串表示；明文 ServerHello 中的 ALPN 单独报告 |
| `ssh.protocol`、`ssh.software`、`ssh.banner` | `fresh.ssh.software contains "OpenSSH"` | TCP 任一方向首次识别出的 SSH 标识行字段 |
| `wireguard.type`、`wireguard.sender_index`、`wireguard.receiver_index`、`wireguard.receiver_matched`、`wireguard.counter` | `wireguard.receiver_matched == true` | UDP WireGuard 报文形状与最近的反方向索引关联；索引和计数器按十进制字符串比较 |
| `openvpn.stage`、`openvpn.client_reset`、`openvpn.server_reset` | `openvpn.stage == handshake && openvpn.server_reset == 8` | TCP/UDP OpenVPN 双向重置握手；数值字段按十进制字符串比较 |
| `openvpn.opcode`、`openvpn.tx_packets`、`openvpn.rx_packets` | `openvpn.stage == data && fresh.openvpn.opcode == 6` | 仅 UDP：当前包的 opcode 与握手后的双向包数 |
| `socks.version`、`socks.command`、`socks.target_type`、`socks.target_host`、`socks.target_port`、`socks.auth` | `socks.target_host ends_with ".example.com"` | TCP SOCKS4/4a/5 客户端请求；命令为 `connect`、`bind` 或 `udp_associate`，认证类型为 `none` 或 `userpass` |
| `vless.candidate`、`vless.command`、`vless.target_type`、`vless.target_host`、`vless.target_port`、`vless.addons_length` | `proto == tcp && vless.candidate == true && vless.target_host == blocked.test` | 裸 VLESS v0 客户端请求头的结构匹配；不验证 UUID 或加密身份，`mux`/`rvs` 无目标地址 |
| `fet.candidate`、`fet.sample_len`、`fet.average_popcount_milli`、`fet.printable_per_mille`、`fet.first_six_printable`、`fet.longest_printable_run`、`fet.tls_http_prefix` | `proto == tcp && fet.candidate == true && fet.sample_len >= 32` | 首方向 TCP 载荷的 FET 启发式采样；`candidate` 只表示未命中豁免条件 |
| `tcp_shape.first_len`、`tcp_shape.first_prefix_len`、`tcp_shape.first_popcount_milli`、`tcp_shape.first_printable_per_mille`、`tcp_shape.first_entropy_milli`、`tcp_shape.first_random_like`、`tcp_shape.signed_lengths`、`tcp_shape.signed_bursts`、`tcp_shape.packet_count`、`tcp_shape.origin_first_run`、`tcp_shape.origin_first_bytes`、`tcp_shape.reply_seen` | `proto == tcp && tcp_shape.first_random_like == true && fresh.tcp_shape.packet_count >= 3` | TCP 重组前前 16 个带载荷包的包首统计、方向包长与连续同向突发；随机外观仅是候选，见[外层指纹研究](outer-fingerprints.md) |
| `tcp_shape.time_source`、`tcp_shape.last_gap_us`、`tcp_shape.gaps_us`、`tcp_shape.origin_first_span_us`、`tcp_shape.first_reply_delay_us` | `tcp_shape.time_source == kernel && fresh.tcp_shape.last_gap_us < 20000` | TCP 早期包的时间来源与微秒间隔；来源缺失或混合时为 `?`，不匹配数值比较 |
| `tcp_shape.handshake_rtt_us`、`tcp_shape.timed_bursts`、`tcp_shape.size_trigram` | `tcp_shape.handshake_rtt_us > 0 && tcp_shape.size_trigram == "1,-2,-2" && fresh.tcp_shape.timed_bursts == "100,-500"` | SYN 到首个确认号匹配的客户端 ACK 的 RTT 估计、按 3 倍 RTT 时间门槛切分的方向突发、四档包长三元组；`timed_bursts` 无法计算时为 `?`，见[外层指纹研究](outer-fingerprints.md) |
| `tcp_rtt.transport_median_us`、`tcp_rtt.application_estimate_us`、`tcp_rtt.diff_us`、`tcp_rtt.completed_pairs`、`tcp_rtt.transport_samples`、`tcp_rtt.correlation_peak_milli` | `proto == tcp && fresh.tcp_rtt.diff_us >= 20000 && tcp_rtt.completed_pairs >= 3` | 按需观察前 64 个 TCP 载荷包；反向 ACK 匹配的传输 RTT 中位数、三组出入方向对的时间相关峰及两者差值。数值单位为微秒，相关峰按全部跨方向包对归一到千分值；用于候选规则，见[外层指纹研究](outer-fingerprints.md) |
| `udp_shape.first_len`、`udp_shape.first_prefix_len`、`udp_shape.first_popcount_milli`、`udp_shape.first_printable_per_mille`、`udp_shape.first_entropy_milli`、`udp_shape.first_quic_initial_shape`、`udp_shape.signed_lengths`、`udp_shape.packet_count`、`udp_shape.short_header_form_packets`、`udp_shape.short_header_fixed_bit_packets`、`udp_shape.origin_first_run`、`udp_shape.origin_first_bytes`、`udp_shape.origin_first_varied_lengths`、`udp_shape.origin_first_random_like`、`udp_shape.origin_first_random_like_packets`、`udp_shape.reply_seen`、`udp_shape.fragmented_random_candidate` | `proto == udp && fresh.udp_shape.fragmented_random_candidate == true && udp_shape.origin_first_run >= 2` | 前 8 个双向 UDP 数据报的包首统计和方向包长；短首部首字节计数、随机外观包数可与首轮等长或变长组合，只表示外层形态，不等于具体协议命中。见[外层指纹研究](outer-fingerprints.md) |
| `udp_shape.time_source`、`udp_shape.last_gap_us`、`udp_shape.gaps_us`、`udp_shape.origin_first_span_us`、`udp_shape.first_reply_delay_us` | `proto == udp && fresh.udp_shape.origin_first_span_us < 20000` | UDP 早期数据报的时间来源与微秒间隔；接收线程时间受排队延迟影响 |
| `trojan.candidate`、`trojan.seq1`～`trojan.seq4` | `proto == tcp && trojan.candidate == true && trojan.seq1 >= 200` | 客户端 ChangeCipherSpec 后前四段交替方向的 TCP 字节数及长度模型的候选结果 |
| `quic.version`、`quic.sni`、`quic.alpn`、`quic.tls_supported_version`、`quic.ech_extension`、`quic.transport_parameters`、`quic.datagram_max_size` | `fresh.quic.alpn == h3 && quic.datagram_max_size > 0` | UDP QUIC v1/v2 客户端 Initial 中的 TLS ClientHello；ALPN 为客户端提供的列表，`transport_parameters` 表示扩展号 `0x0039` 是否出现；`datagram_max_size` 是客户端声明愿意接收的最大 DATAGRAM 帧长 |
| `quic.transport_parameter_id`、`quic.transport_parameter_ids`、`quic.transport_parameter_ids_no_grease` | `quic.transport_parameter_ids_no_grease contains "0xe,0xf"` | 客户端 transport parameters 的单项 ID 与按线缆顺序排列的十六进制 ID 列表；`_no_grease` 删除 [RFC 9000 §18.1](https://www.rfc-editor.org/rfc/rfc9000.html#section-18.1) 保留的 `31*N+27` ID，其余顺序不变。只有扩展存在时才报告列表 |
| `quic.disable_active_migration`、`quic.active_connection_id_limit` | `quic.disable_active_migration == true && quic.active_connection_id_limit >= 4` | 客户端在 Initial 中声明的迁移限制与愿意存储的连接 ID 数量；前者为布尔值，后者只在显式提供时报告。它们不证明后续路径或连接 ID 的身份，见[连接迁移设计](quic-migration.md) |
| `quic.tls_client_legacy_version`、`quic.tls_client_cipher_suite`、`quic.tls_client_extension`、有序复数字段及其 `_no_grease` 版本 | `quic.tls_client_extensions_no_grease contains "0x0039"` | QUIC Initial 解出的 ClientHello 使用与 TCP TLS 相同的套件/扩展及握手原始字段观察方式；不包含加密后的握手或 1-RTT 内容 |
| `quic.tls_client_supported_group`、`quic.tls_client_signature_algorithm`、`quic.tls_client_key_share_group`，以及各自的有序复数和 `_no_grease` 字段 | `quic.tls_client_supported_group == 0x001d` | QUIC Initial 中可见的 ClientHello 扩展内部列表；字段语义与 TCP TLS 相同 |
| `quic.server_version`、`quic.server_cipher` | `fresh.quic.server_cipher == 0x1301` | 反向 QUIC v1/v2 Initial 中 ServerHello 的 TLS 协商版本和密码套件；需先看到客户端 Initial 才能派生服务端密钥，TLS 1.3 的 ALPN 不在此阶段明文中 |
| `quic.retry_integrity_valid` | `fresh.quic.retry_integrity_valid == true` | 已先看到客户端 Initial，且反向 v1/v2 Retry 的连接 ID、非空 token 和完整性标签通过检查时报告；固定公开校验密钥不提供服务端身份认证 |
| `dtls.sni`、`dtls.alpn`、`dtls.supported_version`、`dtls.ech_extension`、`dtls.client_cookie_present` | `proto == udp && fresh.dtls.sni == blocked.test` | DTLS 1.2/1.3 明文 ClientHello；`client_cookie_present` 随 cookie 交换后的新 ClientHello 更新，ALPN 为客户端提供值 |
| `dtls.client_legacy_version`、`dtls.client_cipher_suite`、`dtls.client_extension`、有序复数字段及其 `_no_grease` 版本 | `dtls.client_extensions_no_grease contains "0x0010"` | 复用 TLS ClientHello 的套件、扩展、握手原始字段及 supported groups、signature algorithms 与 key share 列表解析；DTLS cookie 字段先从握手正文剥离 |
| `dtls.hello_verify`、`dtls.server_version`、`dtls.server_cipher`、`dtls.server_alpn` | `fresh.dtls.hello_verify == true || fresh.dtls.server_cipher == 0x1301` | 反向 DTLS 1.2 HelloVerifyRequest、DTLS 1.2/1.3 ServerHello；1.3 的服务端 ALPN 位于加密的 EncryptedExtensions，不产生 `server_alpn` |
| `fresh.` 加字段名 | `fresh.dns.qname == "blocked.test"` | 该字段必须由当前包更新 |
| 观察字段加 `exists` | `fresh.wireguard.type exists` | 字段至少有一个值；`fresh.` 还要求当前包更新 |
| 数值观察字段 | `fresh.openvpn.tx_packets > 10` | `>`、`>=`、`<`、`<=` 按无符号十进制整数比较；非数字值不匹配 |
| IP 观察字段 | `fresh.dns.answer_ipv6 in 2001:db8::/32` | 将观察值解析为 IP 地址并按 CIDR 匹配；非 IP 值不匹配 |

`origin`、`target` 是创建流时第一个包的端点；`src`、`dst` 随当前包方向变化。HTTP 按 TCP 方向连续分析 HTTP/1 消息；同包多条消息逐条求值，新请求会原子替换旧请求字段并清除旧响应字段，`http.target` 保留请求目标原文。HTTP 流水线响应按请求顺序关联，响应求值时恢复对应请求字段；这些请求字段不计入响应事件的 `fresh.`，例如 `http.target == /one && fresh.http.status == 404` 可命中对应响应。1xx 临时响应不消耗请求，101 协议切换会消耗请求。TLS 分析可见的 ClientHello SNI、ALPN 和反向 ServerHello；DNS 在 TCP/UDP 端口 53 分析。SSH 读取每个 TCP 方向的首条标识行，允许此前出现提示行，单方向最多读取 `ssh-banner-bytes` 字节。`fresh.` 适合逐包丢弃或修改，避免沿用较早数据报留下的观察值。

DNS 表达式逐个 UDP 数据报或 TCP 长度前缀消息求值；新消息替换前一条 DNS 字段。响应若带问题段，可同时匹配 `dns.qname` 与 `fresh.dns.rcode` 或答案字段；`dns.qtype` 仅在恰好一个 IN 类问题时报告，避免把多问题的域名和类型错配。答案字段汇集该响应答案段内相应类型的所有 IN 类记录，`dns.answer_cname` 报告规范名称的目标，支持压缩名称。`dns.qr` 的值为 `query` 或 `response`。目前不解析权威段、附加段以及其他答案类型。DNS 首部、问题和答案格式依据：[RFC 1035](https://www.rfc-editor.org/rfc/rfc1035.html)、[RFC 3596](https://www.rfc-editor.org/rfc/rfc3596.html)；TCP 可连续承载多条消息，响应顺序不作假定：[RFC 7766](https://www.rfc-editor.org/rfc/rfc7766.html)。

HTTP 分析器依据 `Content-Length` 跳过定长消息体，也能按最终 `Transfer-Encoding: chunked` 的块长度、扩展和 trailer 找到下一条消息；消息体中的文本不会被当成新请求。没有长度标记的请求视为无消息体。遇到同时出现 `Transfer-Encoding` 与 `Content-Length`、不一致的长度、无法识别的传输编码、`Connection: close` 或无法定界的响应体时，报告当前可见头部后停止该方向的后续解析。明文 HTTP/2 不在此分析器内。消息体长度判定依据：[RFC 9112](https://www.rfc-editor.org/rfc/rfc9112.html)。

`http.upgrade_offer` 与 `http.upgrade_selected` 分别报告 HTTP/1.1 请求和 101 响应中声明的 Upgrade 协议，大小写归一为小写，支持以逗号分隔的多个提议。两个字段都要求同条消息存在 `Connection: Upgrade`。响应规则可用请求上下文确认双方均声明 `websocket` 或其他协议；这些字段不验证 WebSocket 的 `Sec-WebSocket-Accept`，也不证明升级后的数据属于代理。TLS 内的握手不会进入逐包分析器。依据：[RFC 9110 Upgrade](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.8)、[RFC 6455](https://www.rfc-editor.org/rfc/rfc6455.html)。

HTTP/2 分析器识别直接发送连接前言的明文 h2c 连接，按 TCP 双向重组后的帧解析 HEADERS/CONTINUATION 和 HPACK 字段。请求以 stream ID 保存；同一连接内请求与响应交错时，响应规则可结合对应的 `http2.path` 与 `fresh.http2.status`。它不解析 HTTP/1.1 Upgrade 切换、TLS 加密后的 h2 载荷、服务端推送或 HTTP/2 DATA 内容；仅凭客户端 TLS ALPN 提供 `h2` 也不能确认服务端最终选择。帧和流语义依据：[RFC 9113](https://www.rfc-editor.org/rfc/rfc9113.html)，头部压缩使用 [httlib-hpack](https://docs.rs/httlib-hpack/latest/httlib_hpack/) 解码。

sing-mux 分析器先读取版本与承载协议选择头；版本 1 开启 padding 时，剥离后续每个方向前 16 次写入的长度和填充封装。`h2mux` 还会验证 HTTP/2 前言及 SETTINGS，只有验证成功才报告 `sing_mux.*`。其中的 `http2.method == CONNECT`、`http2.authority == localhost` 描述复用载体；客户端 DATA 开头的 sing-mux 子流请求才给出 `sing_mux.host`、`sing_mux.port` 和 `sing_mux.network`。目标按 HTTP/2 stream ID 保存，响应 HEADERS 恢复对应目标供规则组合。外层代理传输加密后，这些内部字段不可见。[sing-mux 协议头](https://github.com/SagerNet/sing-mux/blob/main/protocol.go)、[padding 格式](https://github.com/SagerNet/sing-mux/blob/main/padding.go)、[h2mux 客户端](https://github.com/SagerNet/sing-mux/blob/main/h2mux.go)。

`smux`/`yamux` 分析器先验证选择头和首帧，再根据各自的帧头重组子流请求，读取 sing-mux 的 SOCKS 地址格式。`fresh.sing_mux.host` 只在首次解析出子流目标的帧上成立；`sing_mux.host` 会在同一子流后续帧上恢复，不会沿用其他子流的目标。`sing_mux.frame` 表示当前帧类别。当前解析的是子流建立请求及帧关联，尚不解析子流内部应用层载荷；外层加密时也看不到这些字段。[smux 帧头](https://github.com/xtaci/smux/blob/master/frame.go)、[yamux 帧格式](https://github.com/hashicorp/yamux/blob/master/spec.md)、[sing-mux 子流请求](https://github.com/SagerNet/sing-mux/blob/main/protocol.go)。

`tls.server_version` 优先取 ServerHello 的 `supported_versions` 扩展，若无该扩展则取旧版版本字段。TLS 1.3 的服务端 ALPN 位于加密的 EncryptedExtensions，因而不会产生 `tls.server_alpn`；TLS 1.2 的明文 ServerHello 可报告该字段。分析器识别 HelloRetryRequest 后等待最终 ServerHello，允许两者间的兼容性 ChangeCipherSpec 记录；重试请求本身不产生最终选择字段。字段反映可见握手内容，不验证完整连接是否成功。依据：[RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html)、[RFC 7301](https://www.rfc-editor.org/rfc/rfc7301.html)。

`tls.supported_version` 和 `quic.tls_supported_version` 只来自客户端 `supported_versions` 扩展，按客户端提供的顺序报告为 `0x0304` 这样的四位十六进制字符串；缺少该扩展时不根据旧版版本字段补值。成功解析 ClientHello 时，`tls.ech_extension` 或 `quic.ech_extension` 总会报告 `true` 或 `false`。`true` 只说明外层 ClientHello 出现扩展号 `0xfe0d`；GREASE ECH 也使用这个扩展号，无法据此判断是否真的加密了内层 ClientHello。依据：[RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html)、[RFC 9849](https://www.rfc-editor.org/rfc/rfc9849.html)。

`field != value` 等价于 `!(field == value)`，因此字段缺失时也成立；需要字段实际存在时可写 `field exists && field != value`。观察字段的相等比较仍按文本处理；大小比较按无符号十进制整数处理，字段缺失时为假。

WireGuard 分析器按需处理任意 UDP 端口，识别握手发起、握手响应、cookie 回复和数据包的头部形状。`wireguard.receiver_matched` 表示接收索引在同一流反方向最近六个发送索引中出现过；这只是报文关联，不验证加密真实性。每个数据报先清除上一个数据报的 WireGuard 字段，再写入本次字段；不符合形状的数据报也会清除这些字段。

OpenVPN TCP/UDP 分析器按需处理任意端口。先看到首方向的客户端 hard reset，再看到反方向的服务端 hard reset，才报告 `openvpn.stage == handshake`。TCP 分析器读取双字节长度前缀，支持分段握手帧，确认后结束分析。UDP 后续合法控制或数据 opcode 报告 `stage == data` 并更新双向计数；`openvpn.opcode` 只描述当前数据报。分析器检查头部 opcode、首轮 key ID 与最短长度，不解密或验证会话。

SOCKS 分析器按需检查任意 TCP 端口的首方向请求，支持 SOCKS4、SOCKS4a 域名及 SOCKS5 的 IPv4、IPv6、域名目标和用户名密码认证帧。请求完成时发布目标字段，不解析服务器应答；不会把用户名或密码放入观察字段。SOCKS4a 的版本值为 `4a`，目标端口目前按十进制字符串比较。

VLESS 分析器按需检查首方向的明文 v0 请求头，支持 TCP、UDP、Mux 和 Rvs 命令，以及 IPv4、IPv6、域名目标。它按 TCP 分段累积到完整头部后发布字段，不记录 UUID，也不检查服务端是否接受该 UUID。`vless.candidate` 是结构候选，不能单独证明连接已通过认证；TLS、REALITY、VLESS Encryption 或其他外层加密时看不到这个头部。依据：[VLESS 格式](https://xtls.github.io/en/development/protocols/vless.html)、[Xray 编码实现](https://github.com/XTLS/Xray-core/blob/main/proxy/vless/encoding/encoding.go)。

FET 分析器仅在规则引用 `fet.*` 时启用，取首方向首次交付的 TCP 数据，最多检查 8192 字节。它复现 OpenGFW 的五组豁免条件：平均置位数不在 3.4～4.6、前六字节均可打印、可打印字节超过一半、最长连续可打印段超过 20 字节，或具有 TLS/HTTP 前缀。`fet.candidate == true` 表示这些豁免条件都不成立，并不证明流量已加密或属于某个代理协议；分段方式也会影响首次采样长度。`fet.average_popcount_milli` 和 `fet.printable_per_mille` 把比例乘以 1000 后截断为整数，便于用表达式与采样长度、端口及其他字段组合。依据：[OpenGFW FET 分析器](https://github.com/apernet/OpenGFW/blob/master/analyzer/tcp/fet.go)、[FET 测量论文](https://gfw.report/publications/usenixsecurity23/data/paper/paper.pdf)。

Trojan 分析器仅在规则引用 `trojan.*` 时启用，不限定 TCP 端口。它先检查首方向载荷是否有 TLS 记录前缀，再寻找客户端兼容性 ChangeCipherSpec 字节串；找到后累计前四段交替方向的重组 TCP 字节数，并在第四次换向（第五段开始）时报告一次。`trojan.seq1`～`trojan.seq4` 是十进制观察值，可与 TLS、FET、端口等条件组合。`trojan.candidate` 使用移植自 OpenGFW 的长度决策树，是统计候选结果，不验证 Trojan 协议本身。这里对分段 ChangeCipherSpec 的处理与 OpenGFW 原实现不同，原模型的误判率不能直接套用；实时准确率尚未实测。最多检查 512000 字节，届时若未凑齐序列便结束分析。决策树文件及其 MPL-2.0 许可见 [源码](../crates/core/src/trojan_tree.rs) 和 [许可文本](licenses/MPL-2.0.txt)；依据：[OpenGFW Trojan 分析器](https://github.com/apernet/OpenGFW/blob/master/analyzer/tcp/trojan.go)。

QUIC 分析器按需检查任意 UDP 端口的 v1/v2 Initial，解开公开的 Initial 密钥保护，按 CRYPTO 偏移重组分段 TLS 握手。客户端分析器提取 ClientHello 的 SNI、ALPN、版本列表、ECH 扩展标记和 DATAGRAM 传输参数，在完整消息到达后报告一次 `quic.version`；服务端分析器以最初客户端 Initial 的目标连接 ID 派生服务端密钥，并核对服务端包的目标连接 ID 是否等于客户端源连接 ID，再报告 ServerHello 的 TLS 版本和密码套件。收到通过完整性校验的 Retry 时，分析器改用 Retry 源连接 ID 派生后续 Initial 密钥，客户端分析器还核对重发 Initial 的 token 与源连接 ID；已完成的 ClientHello 观察值不会重复报告。两者均按规则引用独立启用，每个方向最多检查八个候选数据报。`quic.datagram_max_size` 对应客户端传输参数 `max_datagram_frame_size`（ID `0x20`），仅在参数出现时报告；值大于零表示客户端宣告可接收 DATAGRAM 帧，不代表该连接实际承载 DATAGRAM，也不标识具体应用。ALPN 列表表示客户端提供的协议，不表示服务端最终选择；目前只将可打印 ASCII 协议 ID 写入观察字段。Initial 密钥公开，解密成功不认证服务端身份；ECH 内层名称与非 v1/v2 版本仍不可见。`fresh.` 可让单包动作仅作用于报告观察值的那个包。实现依据：[RFC 7301](https://www.rfc-editor.org/rfc/rfc7301.html)、[RFC 9001](https://www.rfc-editor.org/rfc/rfc9001.html)、[RFC 9221](https://www.rfc-editor.org/rfc/rfc9221.html)、[RFC 9369](https://www.rfc-editor.org/rfc/rfc9369.html)。Hysteria2 的适用范围见[研究记录](hysteria2-quic.md)。

HTTP/3 的标准 ALPN 是 `h3`。表达式 `quic.alpn == h3 && quic.transport_parameters == true` 可标记客户端提出的 HTTP/3 连接候选；QUIC 的握手后应用数据与服务端选择的 ALPN 均受加密保护，因此当前被动引擎不能据此断言连接已经承载 HTTP/3 请求，更不能读取 HTTP/3 的 QPACK 头部。[HTTP/3 协议](https://www.rfc-editor.org/rfc/rfc9114.html)、[QUIC TLS 传输参数扩展](https://www.rfc-editor.org/rfc/rfc9001.html#section-8.2)。

UDP 分析器拒绝数据报时，该包直接丢弃，本次不再用流内旧观察值执行表达式规则；后续数据报仍可继续检查。

动作有 `allow`、`block`、`drop_packet`、`replace_udp_payload`。`allow` 和 `block` 结束该流的应用层检查；`drop_packet` 只丢当前 UDP 数据报，在 TCP 上阻断整个流。`replace_udp_payload` 只用于 UDP，在 TCP 上继续尝试后续规则。修改内容可用 `replacement` 指定 UTF-8 文本，或用 `replacement_hex` 指定十六进制字节，两者选一个。内核静态卸载仅处理传输层规则；表达式规则由用户态引擎执行。
