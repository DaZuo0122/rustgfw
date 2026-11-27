# 引擎日志

核心使用 `tracing` 发布结构化事件，不持有文件或控制台输出句柄。调用核心 API 的程序可以安装自己的 subscriber；仓库里的 `rustgfw` 命令行程序默认把日志写到标准错误，默认级别为 `info`。

用 `RUST_LOG` 调整级别，例如 `RUST_LOG=rustgfw_core=debug` 可查看规则命中与最终裁决，`RUST_LOG=warn` 只显示警告与错误。设置 `RUSTGFW_LOG_FORMAT=json` 可得到每行一个 JSON 事件；默认 `text`。这些环境变量由命令行程序读取，不改变核心 API。

规则图在某条规则首次命中时发出 `debug` 事件 `rule hit recorded`，包含 `flow_id`、`event_seq`、`rule_id`、`scope` 及可用的 `stream_scope`；同一命中不会在后续包反复记录。选出动作后发出 `debug` 事件 `application rule matched`，其中 `priority`、`candidates` 和 `via` 分别表示生效优先级、当前候选动作数和满足依赖的规则 ID。`||` 依赖只记录实际采用的第一个成立分支。

首次阻断 TCP/UDP 流或 HTTP/3 请求流，以及 UDP 丢包或载荷替换时，核心发出 `info` 事件，包含最终裁决的 `rule_id`、`priority`、`via`、`flow_id`、`event_seq`、`stream_scope`、动作及可见端点。`flow_id` 是核心分配的会话标识；`event_seq` 是该会话内的观察批次序号，适合关联命中和裁决。其他通过 API 注入的旧式规则仍以 `rule_index` 记录 `debug` 日志。检查容量耗尽、TCP 重组失败及报文分析器判为畸形时记录 `warn`。传输策略的逐包裁决与协议解析停止事件使用 `debug`。日志不包含原始载荷、HTTP 头部值或 QPACK 字段值。

HTTP/3 的 QPACK 更新可能触发另一条请求流的裁决，日志中的 `stream_id` 与返回的 `DecodedVerdict.stream_id` 均指向实际被裁决的请求流。Linux NFQUEUE 和 Windows I/O 后端只负责包的接收、回注和内核策略；核心日志在两个平台上使用相同事件字段。
