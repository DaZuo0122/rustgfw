# Windows backend

`rustgfw windivert <WinDivert.dll 路径> <network|forward> <accept|drop> [规则...]` 使用与 Linux 相同的传输层规则、HTTP Host、TLS SNI 和 DNS 分析器。`network` 捕获本机收发，`forward` 捕获经过本机的包。WinDivert 2.2 负责抓包、裁决和原包重新注入；`DropFlow` 仍由用户态后续逐包执行。

WinDivert 的 `Recv` 把包从网络路径取出；接受必须调用 `Send` 重新注入。适配器保留完整的 80 字节 `WINDIVERT_ADDRESS`，使方向、接口和校验和标志随原包返回。丢弃不调用 `Send`。默认放行时，有效 ICMP/ICMPv6 直接走系统路径，分片仍进入引擎；这避免 WinDivert 对部分入站 ICMP 原包重注入失败而让引擎退出。默认丢弃仍捕获全部协议。在 `network` 与 `forward` 层使用同一决策接口。依据：[WinDivert 2.2 手册](https://reqrypt.org/windivert-doc.html)。

`network` 模式启动时，将有序规则开头连续的 `drop` 规则下沉到 WFP 本机连接授权层；遇到第一条 `accept` 就停止，避免改变优先顺序。协议与本机/对端端口分别匹配 IPv4/IPv6 的 `ALE_AUTH_CONNECT`、`ALE_AUTH_RECV_ACCEPT`，所有过滤器在一个事务中提交，动态会话结束即清除。WFP 初始化失败时记录原因并继续由 WinDivert 执行规则。此静态下沉尚未经过真实 WFP 流量测试。[各过滤层可用条件](https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-conditions-available-at-each-filtering-layer)、[过滤器仲裁](https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration)。

`forward` 模式没有本机 socket 的 ALE 身份，而且 WFP `IPFORWARD` 层没有 TCP/UDP 端口条件。因此转发模式用优先级 1 的 WinDivert `DROP` 句柄执行同一段开头的静态丢弃规则；优先级 0 的普通句柄继续捕获其余包作用户态检查。静态句柄安装失败时仍由普通句柄逐包执行。WinDivert 的转发层与 Windows NAT 存在已知限制，实际转发部署需要单独验证。[WinDivert 过滤器、优先级与 DROP 标志](https://reqrypt.org/windivert-doc.html)。

`wfp::WfpPolicy` 还提供精确本机五元组阻断规则的安装/撤销接口；每条流的两个方向同事务提交。IPv4 地址和端口按 WFP 要求使用主机字节序。此接口已编译并完成规则构造测试，但没有接入 WinDivert 的 `DropFlow` 路径，因为过滤器撤销必须与 Windows 流删除事件绑定，不能仅凭五元组或固定超时推断连接结束。ALE 授权层的策略变化会让已有连接在下一包重新授权；连接两个方向属于同一 ALE flow。转发包需要单独设计匹配范围。依据：[ALE 重新授权](https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization)、[WFP 对象生命周期](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management)、[WFP 条件字节序](https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-condition-identifiers-)。

Windows 编译、WinDivert 重注入模拟测试、完整 IPv4/TCP HTTP Host 阻断及双向 `DropFlow` 模拟测试、WFP 条件构造测试已通过。当前工作区没有可读取的 WinDivert DLL/驱动：官方 2.2.2-A 压缩包下载后被本机安全软件拒绝读取，因此尚无真实驱动收发结果。本机进程也未提升为管理员，未执行 WFP 规则安装。WinDivert 官方说明需要配套的 DLL/已签名驱动，并以管理员权限打开句柄。[官方发行页](https://reqrypt.org/windivert.html)。
