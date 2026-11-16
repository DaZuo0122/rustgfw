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
    }
  ]
}
```

例如 `rustgfw nfqueue 100 accept nft=forward rules-file=rules.json`。`rules-file` 可以和现有的传输层规则、资源预算参数一起使用；传输层规则先执行。当前没有规则文件热更新入口。

表达式使用 `!`、`&&`、`||` 和括号，优先级依次递减。比较值可用裸词或双引号字符串；字符串支持 `\"`、`\\`、`\n`、`\r`、`\t`。可比较的内容：

可选的 `expressions` 对象定义命名条件，在规则或其他命名条件中以 `@名称` 引用。加载时递归展开引用，并检查未知名称和循环引用；展开后的规则按正常布尔逻辑求值。命名条件只组合匹配条件，动作仍由各条规则指定。

| 左侧 | 写法 | 含义 |
| --- | --- | --- |
| `proto` | `proto == tcp` / `udp` | 传输协议 |
| `src.port`、`dst.port`、`origin.port`、`target.port` | `dst.port == 443` | 当前包或建流时的端口 |
| 对应的 `.ip` | `src.ip in 10.0.0.0/8` 或 `src.ip == 10.0.0.1` | CIDR 或单个地址，支持 IPv4/IPv6 |
| `reverse` | `reverse == true` | 当前包是否与建流方向相反 |
| `payload` | `payload == "old"` | 当前传输层载荷的 UTF-8 字节 |
| `http.host`、`tls.sni`、`dns.qname` | `http.host == "blocked.test"` | 流内最近一次观察批次的任一值 |
| `fresh.` 加字段名 | `fresh.dns.qname == "blocked.test"` | 该字段必须由当前包更新 |

`origin`、`target` 是创建流时第一个包的端点；`src`、`dst` 随当前包方向变化。HTTP 只分析首个 HTTP/1 请求，TLS 只分析可见的 ClientHello SNI；DNS 在 TCP/UDP 端口 53 分析。`fresh.` 适合逐包丢弃或修改，避免沿用较早数据报留下的观察值。

动作有 `allow`、`block`、`drop_packet`、`replace_udp_payload`。`allow` 和 `block` 结束该流的应用层检查；`drop_packet` 只丢当前 UDP 数据报，在 TCP 上阻断整个流。`replace_udp_payload` 只用于 UDP，在 TCP 上继续尝试后续规则。修改内容可用 `replacement` 指定 UTF-8 文本，或用 `replacement_hex` 指定十六进制字节，两者选一个。内核静态卸载仅处理传输层规则；表达式规则由用户态引擎执行。
