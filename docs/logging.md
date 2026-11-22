# 引擎日志

核心使用 `tracing` 发布结构化事件，不持有文件或控制台输出句柄。调用核心 API 的程序可以安装自己的 subscriber；仓库里的 `rustgfw` 命令行程序默认把日志写到标准错误，默认级别为 `info`。

用 `RUST_LOG` 调整级别，例如 `RUST_LOG=rustgfw_core=debug` 可查看规则序号与动作，`RUST_LOG=warn` 只显示警告与错误。设置 `RUSTGFW_LOG_FORMAT=json` 可得到每行一个 JSON 事件；默认 `text`。这些环境变量由命令行程序读取，不改变核心 API。

核心在应用规则命中时记录协议、`FlowScope`、规则序号、动作及可见的源和目的端点。首次阻断 TCP/UDP 流或 HTTP/3 请求流时记录 `info`；检查容量耗尽、TCP 重组失败及报文分析器判为畸形时记录 `warn`。传输策略的逐包裁决与协议解析停止事件使用 `debug`。日志不包含原始载荷、HTTP 头部值或 QPACK 字段值。

HTTP/3 的 QPACK 更新可能触发另一条请求流的裁决，日志中的 `stream_id` 与返回的 `DecodedVerdict.stream_id` 均指向实际被裁决的请求流。Linux NFQUEUE 和 Windows I/O 后端只负责包的接收、回注和内核策略；核心日志在两个平台上使用相同事件字段。
