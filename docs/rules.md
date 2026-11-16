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

表达式使用 `!`、`&&`、`||` 和括号，优先级依次递减。比较值可用裸词或双引号字符串；字符串支持 `\"`、`\\`、`\n`、`\r`、`\t`。观察字段、`payload` 和 `payload_hex` 支持 `==`、`!=`、`contains`、`starts_with`、`ends_with`；域名等观察字段比较忽略 ASCII 大小写，`http.method`、`http.target`、`tls.alpn`、`tls.server_alpn`、`quic.alpn` 及载荷区分大小写。端口和 `payload.len` 支持 `==`、`!=`、`<`、`<=`、`>`、`>=`；`proto`、`reverse` 和 IP 地址支持 `==`、`!=`。可比较的内容：

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
| `http.host`、`http.method`、`http.target`、`http.request_version` | `http.method == CONNECT && http.target ends_with :443` | TCP 首个 HTTP/1 请求的请求行与可见 authority/Host |
| `http.status`、`http.response_version` | `http.status >= 400` | TCP 首个 HTTP/1 响应的状态码与版本；状态码是十进制观察值 |
| `tls.sni`、`tls.alpn`、`dns.qname` | `tls.alpn == h2` | 流内最近一次观察批次的任一值；`tls.alpn` 为客户端提供的协议列表 |
| `tls.server_version`、`tls.server_cipher`、`tls.server_alpn` | `tls.alpn == h2 && fresh.tls.server_version == 0x0304` | TCP ServerHello 所选版本与密码套件以四位十六进制字符串表示；明文 ServerHello 中的 ALPN 单独报告 |
| `ssh.protocol`、`ssh.software`、`ssh.banner` | `fresh.ssh.software contains "OpenSSH"` | TCP 任一方向首次识别出的 SSH 标识行字段 |
| `wireguard.type`、`wireguard.sender_index`、`wireguard.receiver_index`、`wireguard.receiver_matched`、`wireguard.counter` | `wireguard.receiver_matched == true` | UDP WireGuard 报文形状与最近的反方向索引关联；索引和计数器按十进制字符串比较 |
| `openvpn.stage`、`openvpn.client_reset`、`openvpn.server_reset` | `openvpn.stage == handshake && openvpn.server_reset == 8` | TCP/UDP OpenVPN 双向重置握手；数值字段按十进制字符串比较 |
| `openvpn.opcode`、`openvpn.tx_packets`、`openvpn.rx_packets` | `openvpn.stage == data && fresh.openvpn.opcode == 6` | 仅 UDP：当前包的 opcode 与握手后的双向包数 |
| `socks.version`、`socks.command`、`socks.target_type`、`socks.target_host`、`socks.target_port`、`socks.auth` | `socks.target_host ends_with ".example.com"` | TCP SOCKS4/4a/5 客户端请求；命令为 `connect`、`bind` 或 `udp_associate`，认证类型为 `none` 或 `userpass` |
| `fet.candidate`、`fet.sample_len`、`fet.average_popcount_milli`、`fet.printable_per_mille`、`fet.first_six_printable`、`fet.longest_printable_run`、`fet.tls_http_prefix` | `proto == tcp && fet.candidate == true && fet.sample_len >= 32` | 首方向 TCP 载荷的 FET 启发式采样；`candidate` 只表示未命中豁免条件 |
| `quic.version`、`quic.sni`、`quic.alpn` | `fresh.quic.alpn == h3` | UDP QUIC v1/v2 客户端 Initial 中的 TLS ClientHello；版本值为 `1` 或 `2`，ALPN 为客户端提供的协议列表 |
| `fresh.` 加字段名 | `fresh.dns.qname == "blocked.test"` | 该字段必须由当前包更新 |
| 观察字段加 `exists` | `fresh.wireguard.type exists` | 字段至少有一个值；`fresh.` 还要求当前包更新 |
| 数值观察字段 | `fresh.openvpn.tx_packets > 10` | `>`、`>=`、`<`、`<=` 按无符号十进制整数比较；非数字值不匹配 |

`origin`、`target` 是创建流时第一个包的端点；`src`、`dst` 随当前包方向变化。HTTP 在每个 TCP 方向只分析首个 HTTP/1 消息：请求字段和反向响应字段可在同一流的表达式中组合，`http.target` 保留请求目标原文。TLS 分析可见的 ClientHello SNI、ALPN 和反向 ServerHello；DNS 在 TCP/UDP 端口 53 分析。SSH 读取每个 TCP 方向的首条标识行，允许此前出现提示行，单方向最多读取 `ssh-banner-bytes` 字节。`fresh.` 适合逐包丢弃或修改，避免沿用较早数据报留下的观察值。

`tls.server_version` 优先取 ServerHello 的 `supported_versions` 扩展，若无该扩展则取旧版版本字段。TLS 1.3 的服务端 ALPN 位于加密的 EncryptedExtensions，因而不会产生 `tls.server_alpn`；TLS 1.2 的明文 ServerHello 可报告该字段。分析器识别 HelloRetryRequest 后等待最终 ServerHello，允许两者间的兼容性 ChangeCipherSpec 记录；重试请求本身不产生最终选择字段。字段反映可见握手内容，不验证完整连接是否成功。依据：[RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html)、[RFC 7301](https://www.rfc-editor.org/rfc/rfc7301.html)。

`field != value` 等价于 `!(field == value)`，因此字段缺失时也成立；需要字段实际存在时可写 `field exists && field != value`。观察字段的相等比较仍按文本处理；大小比较按无符号十进制整数处理，字段缺失时为假。

WireGuard 分析器按需处理任意 UDP 端口，识别握手发起、握手响应、cookie 回复和数据包的头部形状。`wireguard.receiver_matched` 表示接收索引在同一流反方向最近六个发送索引中出现过；这只是报文关联，不验证加密真实性。每个数据报先清除上一个数据报的 WireGuard 字段，再写入本次字段；不符合形状的数据报也会清除这些字段。

OpenVPN TCP/UDP 分析器按需处理任意端口。先看到首方向的客户端 hard reset，再看到反方向的服务端 hard reset，才报告 `openvpn.stage == handshake`。TCP 分析器读取双字节长度前缀，支持分段握手帧，确认后结束分析。UDP 后续合法控制或数据 opcode 报告 `stage == data` 并更新双向计数；`openvpn.opcode` 只描述当前数据报。分析器检查头部 opcode、首轮 key ID 与最短长度，不解密或验证会话。

SOCKS 分析器按需检查任意 TCP 端口的首方向请求，支持 SOCKS4、SOCKS4a 域名及 SOCKS5 的 IPv4、IPv6、域名目标和用户名密码认证帧。请求完成时发布目标字段，不解析服务器应答；不会把用户名或密码放入观察字段。SOCKS4a 的版本值为 `4a`，目标端口目前按十进制字符串比较。

FET 分析器仅在规则引用 `fet.*` 时启用，取首方向首次交付的 TCP 数据，最多检查 8192 字节。它复现 OpenGFW 的五组豁免条件：平均置位数不在 3.4～4.6、前六字节均可打印、可打印字节超过一半、最长连续可打印段超过 20 字节，或具有 TLS/HTTP 前缀。`fet.candidate == true` 表示这些豁免条件都不成立，并不证明流量已加密或属于某个代理协议；分段方式也会影响首次采样长度。`fet.average_popcount_milli` 和 `fet.printable_per_mille` 把比例乘以 1000 后截断为整数，便于用表达式与采样长度、端口及其他字段组合。依据：[OpenGFW FET 分析器](https://github.com/apernet/OpenGFW/blob/master/analyzer/tcp/fet.go)、[FET 测量论文](https://gfw.report/publications/usenixsecurity23/data/paper/paper.pdf)。

QUIC 分析器按需检查任意 UDP 端口的 v1/v2 客户端 Initial，解开公开的 Initial 密钥保护，按 CRYPTO 偏移重组分段 TLS ClientHello，再提取可见 SNI 和 ALPN。它在完整握手消息到达后报告一次 `quic.version`，有可见 SNI 或 ALPN 时同时报告对应字段；每条流最多检查八个候选数据报。ALPN 列表表示客户端提供的协议，不表示服务端最终选择；目前只将可打印 ASCII 协议 ID 写入观察字段。ECH 内层名称、非 v1/v2 版本及 Retry 后更换连接 ID 的握手暂不识别；`fresh.` 可让单包动作仅作用于报告观察值的那个包。实现依据：[RFC 7301](https://www.rfc-editor.org/rfc/rfc7301.html)、[RFC 9001](https://www.rfc-editor.org/rfc/rfc9001.html)、[RFC 9369](https://www.rfc-editor.org/rfc/rfc9369.html)。

UDP 分析器拒绝数据报时，该包直接丢弃，本次不再用流内旧观察值执行表达式规则；后续数据报仍可继续检查。

动作有 `allow`、`block`、`drop_packet`、`replace_udp_payload`。`allow` 和 `block` 结束该流的应用层检查；`drop_packet` 只丢当前 UDP 数据报，在 TCP 上阻断整个流。`replace_udp_payload` 只用于 UDP，在 TCP 上继续尝试后续规则。修改内容可用 `replacement` 指定 UTF-8 文本，或用 `replacement_hex` 指定十六进制字节，两者选一个。内核静态卸载仅处理传输层规则；表达式规则由用户态引擎执行。
