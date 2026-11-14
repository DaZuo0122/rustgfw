# Kernel policy contract

默认 ID 集合路径：HTTP/TLS/DNS over TCP 分析器确认阻断后返回 `DropFlow`，NFQUEUE 先丢当前包，再把 `(ct zone, ct id)` 写入本实例表的 `blocked_ct` 超时集合。规则位于静态规则和队列规则之前，匹配同一连接的两个方向；后续 TCP 包直接内核丢弃。没有有效 conntrack ID 时保留用户态阻断。集合条目 120 秒过期；用户态保留已卸载连接键，条目过期后下一包重新入队、丢弃并续装。UDP DNS 的单数据报阻断不会写入集合。

可选 `ctmark=0x80000000` 把动态阻断改为 conntrack mark。该参数必须与 `nft=` 一起使用，值须为单个由部署者预留的 bit；该 bit 同时占用 packet mark 和 conntrack mark。命中 `DropFlow` 时，NFQUEUE 把 bit 写到待裁决包的 packet mark 并放行到下一 nft hook；下一 hook 把 bit OR 到该包所属 conntrack mark，然后丢弃当前包。后续经过所选 hook 的 TCP 包按 conntrack mark 直接丢弃；RST 会清除 bit 并放行。没有 conntrack 信息时仍由用户态逐包阻断。此模式不依赖 32 位 conntrack ID、超时集合、销毁事件或逐流 `nft` 子进程。它只适用于本进程管理的 nft hook，并要求该 bit 在所属网络命名空间中没有被其他规则使用。隔离命名空间里的 IPv4/IPv6 OUTPUT 与 FORWARD HTTP 阻断、后续内核丢弃、转发连接反向包阻断和本机 RST 清标均已通过实测。

默认 ID 集合模式保留作无需预留 mark 的部署选项。用户态流表和销毁事件键包含 zone ID 及其方向；nft 集合匹配 `ct zone . ct id`，只包含 zone 数值与 32 位 ID。Linux 内核把 `nf_ct_get_id` 定义为近似唯一的伪 ID，不能保证并发连接绝无碰撞；同数值但不同方向的 zone 在 nft 键中也无法区分。需要避免这类碰撞的部署应优先使用预留 mark 的模式。[内核 ID 实现](https://github.com/torvalds/linux/blob/master/net/netfilter/nf_conntrack_core.c)。

每次首次阻断需要调用 `nft` 子进程，吞吐和延迟尚未优化；后续可改用 netlink 批量更新。已记录且尚未到续装时间的连接键不重复调用 `nft`；集合条目 120 秒过期后，下一个入队包会触发续装。集合写入失败时，后端记录错误并保留该连接的用户态阻断，每秒最多重试一次，不撤销整个策略表。被阻断流的 RST 回到 NFQUEUE；已卸载的流撤销内核条目，用户态阻断的流直接清理记录，然后放行关闭包。已排队包不能重装关闭的连接键。nft 规则启用 `ct event set destroy`，后端监听销毁事件并按 zone 与 ID 删除本实例记录。隔离命名空间中的真实 UDP 连接约 35 秒过期后收到了事件；高负载下的事件丢失和恢复仍需测试。事件接收缓冲 `ENOBUFS`、Netlink `NLMSG_OVERRUN` 或被截断的数据报会报错退出，避免把事件丢失误当作普通队列拥塞。conntrack ID 只在所属连接存活期间具备身份意义；事件丢失并发生 ID 复用时仍可能误伤新连接。生产级方案可写 conntrack mark 或强化事件丢失后的恢复。zone 0 和 zone 7 同时阻断、内核续包丢弃及 RST 撤销已在隔离命名空间实测；尚未验证同五元组跨 zone 的并发连接。

CLI 托管队列：`rustgfw nfqueue 100 accept nft=output dns-name=blocked.test`。`nft=` 可选 input/output/forward，一次选择一个 hook；不指定时维持外部规则模式。CLI 先绑定队列后安装表，收到 SIGINT/SIGTERM 或执行错误时撤销表。接收超时 200ms 用于空闲退出检查；不是包的用户态处理超时。SIGKILL/崩溃无法清理，已经排队而尚未裁决的包也没有无损排空保证。

托管 CLI 自动按顺序编译传输层规则：drop → 内核 Drop，accept → Inspect（入队继续检查）。默认动作仍由用户态执行。`any` 协议展开为 TCP/UDP，不覆盖 ICMP 等其他协议。Inspect 是当前规则链的终止匹配，不会继续命中后面的 drop；后续应用层规则仍可阻断。只有显式库调用可以指定 BypassInspection。

`core::offload::Rule` 描述静态 TCP/UDP 协议和任一端口匹配，动作包括 Drop、Inspect 和 BypassInspection。后者只跳过本引擎用户态检查，不承诺绕过系统其他防火墙。

Linux `nft::NftPolicy` 实现 `KernelPolicy`：创建独占 inet 表，安装指定 input/output/forward hook 的有序规则，最后将剩余流量交给 NFQUEUE。动态 TCP 阻断使用 nft 超时集合和 conntrack 销毁事件清理；不会把 packet mark 当成连接策略。

调用方先绑定队列，再安装 Plan；停止时先撤销 Plan，再关闭队列。安装、replace 和 revoke 的错误必须传播。revoke 借用句柄，因此失败可重试。没有隐式 Drop 清理；进程崩溃后表仍存在，恢复时须显式处理，不能按名字前缀批量删除别的实例。

replace 通过同一个 `nft -f -` 事务删除旧表并创建新表，不出现中间空规则窗口。安装用 create 而非 add，拒绝同名已有表。不修改其他表；可通过 handle.table_name() 获取运维标识。调用须在同一网络命名空间执行。

BypassInspection 只适用于无需后续 DPI 的规则。HTTP/TLS/DNS over TCP 阻断可写入动态集合；当前编译器没有把用户态放行映射为内核 accept，因此畸形包和 IP 分片仍需用户态检查；静态 drop 可以直接生效。尚未声明任意 IP 扩展头及畸形传输头下与纯用户态路径完全等价，需要进一步差分验证。

`bypass_without_listener` 只控制无队列监听者时的行为；拥塞策略由 NFQUEUE 配置控制。默认不应将两者混为一谈。

参考：[nftables 原子事务说明](https://wiki.nftables.org/wiki-nftables/index.php/Atomic_rule_replacement)。
