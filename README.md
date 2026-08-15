# zeytun-config

Parse proxy share links (`vmess://`, `vless://`, `trojan://`, `ss://`, …) into:

1. **`ShareProxy`** — structured node (app models / storage)
2. **sing-box outbound JSON** — via `convert` / `share_to_outbound`
3. **share-link emit** — `share_to_link(&ShareProxy) → String` (Copy / QR)

Rust counterpart of [ray2sing](https://github.com/hiddify/ray2sing) for Zeytun.

## Library

```rust
use zeytun_config::{convert, parse_share_proxy, share_to_link, share_to_outbound};

let node = parse_share_proxy("vless://...")?;
let outbound = share_to_outbound(&node);
let link = share_to_link(&node)?;
let json = convert("vless://...\nss://...")?;
```

## CLI

```bash
cargo run -p zeytun-config -- 'vless://uuid@host:443?security=tls&type=ws#tag'
```

## Schemes

`vmess` · `vless` · `trojan` · `ss` · `hy2`/`hysteria2` · `tuic` · `socks` · `http`/`https`/`phttp`  
Chains: `A -> B`. Transports: tcp/ws/grpc/http/httpupgrade/quic/xhttp (+ `extra` JSON).

## In Zeytun app

Path dep from `src-tauri`: `zeytun-config = { path = "../zeytun-config" }`.  
`link_parser` maps `ShareProxy` → `ProxyServer`.

→ skipped: warp/wg/ssh/naive/mieru/psiphon/dnstt — add when needed.
