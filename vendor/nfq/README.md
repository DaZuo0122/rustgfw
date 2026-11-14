# nfq 0.2.6 local patch

This directory contains the `nfq` 0.2.6 crate by Gary Guo, originally published at
<https://crates.io/crates/nfq/0.2.6>. It remains licensed under MIT or
Apache-2.0; see `LICENSE-MIT` and `LICENSE-APACHE`.

The local change parses `CTA_ZONE` and directional `CTA_TUPLE_ZONE` attributes
from NFQUEUE conntrack metadata and exposes the result through
`Conntrack::get_zone()`. The Linux backend uses that scope for flow state and
conntrack destroy events.
