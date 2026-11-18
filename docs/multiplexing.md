# 多路复用协议调研与引擎边界

先按三个 Go 客户端实际使用的协议选择实现范围，而不是把所有复用流量当成普通 HTTP/2。

| 客户端 | 复用方式 | 代码或文档依据 |
| --- | --- | --- |
| xray-core | Mux.Cool 在一条已建立的可靠流里承载带子连接 ID 的帧；XHTTP 的 `xmux` 则管理 HTTP 连接复用，并可选择 HTTP/1.1、HTTP/2、HTTP/3。 | [Mux.Cool 格式](https://github.com/XTLS/Xray-docs-next/blob/main/docs/en/development/protocols/muxcool.md)、[Mux.Cool 客户端](https://github.com/XTLS/Xray-core/blob/main/common/mux/client.go)、[XHTTP dialer](https://github.com/XTLS/Xray-core/blob/main/transport/internet/splithttp/dialer.go) |
| sing-box | sing-mux 可选 `smux`、`yamux`、`h2mux`，默认 `h2mux`。先通过代理 dialer 建立主连接，再发送版本与协议选择；`h2mux` 以 HTTP/2 `CONNECT localhost` 打开子流。 | [复用配置](https://github.com/SagerNet/sing-box/blob/testing/docs/configuration/shared/multiplex.md)、[客户端建连](https://github.com/SagerNet/sing-mux/blob/main/client.go)、[协议头](https://github.com/SagerNet/sing-mux/blob/main/protocol.go)、[h2mux 实现](https://github.com/SagerNet/sing-mux/blob/main/h2mux.go) |
| mihomo | 使用 `metacubex/sing-mux` 分支，配置同样提供 `smux`、`yamux`、`h2mux`，默认 `h2mux`；其协议头与 sing-mux 对应。 | [官方配置](https://github.com/MetaCubeX/Meta-Docs/blob/main/docs/config/proxies/index.md)、[go.mod](https://github.com/MetaCubeX/mihomo/blob/Alpha/go.mod)、[协议头](https://github.com/MetaCubeX/sing-mux/blob/main/protocol.go) |

Mux.Cool 的 `v1.mux.cool` 和 sing-mux 的 `sp.mux.sing-box.arpa` 是内部目标标记，不能把它们当作通常可见的 DNS 或 TLS SNI。Mux.Cool 文档特别说明 VMess/VLESS 不会把这个目标名原样发送在数据包里。sing-mux 的选择头和后续 `smux`/`yamux`/`h2mux` 帧写在代理主连接内；外层经 TLS、QUIC 或代理协议加密后，当前被动包引擎只能分析外层可见的握手，不能从密文还原内层子流 ID 或目标地址。[Mux.Cool 格式](https://github.com/XTLS/Xray-docs-next/blob/main/docs/en/development/protocols/muxcool.md)、[sing-mux 客户端](https://github.com/SagerNet/sing-mux/blob/main/client.go)、[QUIC 加密](https://www.rfc-editor.org/rfc/rfc9001.html)。

引擎已能在明文 TCP 流中读取 sing-mux 选择头，并在版本 1 开启 padding 时剥离每个方向前 16 次写入的封装。`h2mux` 将 HTTP/2 帧交给现有分析器，目前识别 `CONNECT localhost` 载体，尚未读取其 DATA 内的代理目标。`smux` 和 `yamux` 已按帧边界及子流 ID 关联请求，读取子流的目标网络、地址与端口；不同子流的规则上下文分开恢复。下一步把“已解密的双向字节流”作为独立输入接入平台无关引擎，并继续分析子流内部的应用协议。Linux NFQUEUE 仍负责外层包的裁决；是否能提供内层字节取决于实际部署的代理或密钥来源。HTTP/3 当前只观察客户端 QUIC Initial 中的 ALPN 提议和 TLS 扩展，无法读取加密后的 HTTP/3 请求。[HTTP/2](https://www.rfc-editor.org/rfc/rfc9113.html)、[HTTP/3](https://www.rfc-editor.org/rfc/rfc9114.html)。
