# 已解密 HTTP/3 流输入

`rustgfw decoded-http3 rules-file=path` 从标准输入逐行读取 JSON 事件，使用与逐包模式相同的表达式规则，并把请求流裁决逐行写到标准输出。这个入口用于验证已解密流的规则行为，也可供后续 QUIC 解密适配器使用。日志仍写到标准错误。

输入事件有三种：

```json
{"event":"data","scope":42,"stream_id":0,"origin":"192.0.2.1:12345","target":"198.51.100.2:443","reverse":false,"bytes":[1,3,0,0,209]}
{"event":"close_stream","scope":42,"stream_id":0}
{"event":"close_connection","scope":42}
```

`scope` 在同一运行中唯一标识一条 QUIC 连接，可用不超过 64 位的 JSON 整数，或用十进制字符串表示完整 128 位值。输出中的 `scope` 始终是十进制字符串。`stream_id` 是 QUIC stream ID；`reverse=false` 表示客户端发送，`true` 表示服务端发送。`origin` 与 `target` 是外层 UDP 端点。`bytes` 是该方向此流新增的有序明文字节，取值为 0 到 255 的整数数组；调用方负责 QUIC 解密、乱序重组、去重和 HTTP/3 ALPN 验证。

连接迁移后继续使用同一个 `scope`，并把每次输入的 `origin`、`target` 更新为当时路径的端点。规则里的 `source`、`destination` 使用当前路径；同一请求流的 `origin`、`target` 保留它首次输入时的端点。即使请求头要等迁移后的 QPACK 编码器流更新才能解码，首次端点也按原请求流记录。

核心按 QUIC 变长整数解析帧长度。HEADERS 的编码块限 64 KiB；DATA 与未知扩展帧的载荷会按长度逐段跳过，不要求一次提供完整帧。

输出示例：

```json
{"scope":"42","stream_id":0,"verdict":"drop_flow"}
```

每条输出裁决属于 `stream_id` 指向的请求流。QPACK 编码器流的输入可能使另一条等待中的请求流产生裁决，因此输出 ID 不一定等于当前输入 ID。没有完整可判定的头部时不会输出；`accept` 表示当前头部未触发阻断，`drop_flow` 表示该逻辑请求流应被阻断。这个模式不会回注或丢弃任何网络包。现有 Linux NFQUEUE 后端仍按外层 UDP 包运行，只能分析 QUIC Initial 中的可见信息。
