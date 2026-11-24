# QUIC 连接迁移与规则状态

## 观察边界

QUIC 连接不等于 UDP 五元组。NAT 重新绑定或主动迁移会改变地址、端口；连接 ID 允许端点把新路径的数据报交给原连接。短首部没有连接 ID 长度字段，而迁移时端点通常切换连接 ID。新 ID 通过加密的 `NEW_CONNECTION_ID` 帧分发；仅看线上的包，无法可靠证明两个不同五元组、不同 ID 属于同一连接，也无法确认新路径通过了 `PATH_CHALLENGE`/`PATH_RESPONSE` 验证。

QUICstep 的实验实现正好覆盖这个场景：通过 WireGuard 隧道传送握手，再将短首部流量送到直连路径。它用首部首位区分长、短首部做路由，不依赖旁路观察者把直连包与隧道里的握手关联。因此，Linux NFQUEUE 只看到直连侧时，现有 Initial 分析器不会得到隧道里的 SNI；不能把未知的短首部流量默认为已通过 SNI 规则。即使观察到相同的连接 ID，未解密的短首部也不能作为可信的身份凭证。

`udp_shape.short_header_form_packets` 和 `short_header_fixed_bit_packets` 可在前 8 个数据报中计数短首部首字节形状，供表达式与包长、方向、时间组合。后者只覆盖 fixed bit 为 1 的包；[RFC 9287](https://www.rfc-editor.org/rfc/rfc9287.html) 允许协商后清除该位。计数不是 QUIC 身份验证，也不改变下面的五元组隔离和卸载行为。

本机官方 Hysteria2 客户端与服务端的一条正常连接在握手后出现连续 8 个符合普通短首部形状的双向数据报，已用本地可选测试验证。该样本没有执行 NAT 重新绑定或主动迁移；跨五元组关联仍需后续带连接事件的实验。

客户端 Initial 的 `quic.disable_active_migration` 表示它请求对端不要主动换本地地址，`quic.active_connection_id_limit` 表示它愿意存储的对端连接 ID 数量。它们来自明文可解析的 transport parameters；未出现的后者按 QUIC 协议默认值处理，但引擎只报告实际出现的值。这些声明不能证明任一后续数据报属于当前连接，也不改变逐包路径的五元组隔离。

## 引擎处理

- **逐包路径**：仍按 `FlowScope` 与 UDP 五元组隔离状态。迁移后首次出现的新五元组从新状态开始；不会仅凭可见连接 ID 继承旧路径的 `Allow`、`Block` 或解析事实。UDP 的 `DropFlow` 目前由用户态逐包执行，内核卸载不会跨五元组沿用旧判定。
- **已解密流路径**：QUIC 解码接入方必须在连接迁移后继续使用同一个 `FlowScope`，并保持 QUIC stream ID。每次 `DecodedStream` 的 `origin`、`target` 提供该次输入所属路径的端点；规则里的 `source`、`destination` 随路径变化，`origin`、`target` 保留该请求流首次输入时的端点，包括 HEADERS 因 QPACK 等待、迁移后才被解码的情况。HTTP/3 请求事实、QPACK 表和逐流裁决继续属于原连接。接入方负责认证包、关联连接 ID、处理路径验证和阻断执行。
- **没有解码接入方时**：可以用传输层目标或其他可见元数据做保守策略，但不能声称按 SNI/HTTP/3 内容准确识别 QUICstep 一类隐藏握手后的流量。短首部固定 bit 只能用作候选特征，不能用来证明连接身份或域名。

后续若接入能提供已认证的连接事件，应把连接身份、当前路径与连接 ID 的增退从解码器传给核心，再决定是否向逐包路径共享判定。连接身份必须由解码器保证稳定，不能直接用 conntrack ID、五元组或任意可见连接 ID 替代。Linux 与 Windows 后端分别处理本平台的路径和卸载语义，规则层只使用上述连接身份与当前端点。

参考：[RFC 9000 §5.1、§9](https://www.rfc-editor.org/rfc/rfc9000.html)、[QUICstep 实验论文](https://arxiv.org/html/2304.01073)、[QUICstep 的 WireGuard 路由配置](https://github.com/inspire-group/QUICstep-PETS/blob/main/quicstep-config/client/wg_qs.conf)。
