//! zeytun-config — proxy share-link → structured node + sing-box outbound JSON.

mod error;
mod node;
mod outbound;
mod parse;
mod to_link;
mod to_outbound;
mod url_schema;
mod util;

pub use error::{Error, Result};
pub use node::{
    DownloadSettings, Http, Hysteria2, Shadowsocks, ShareProtocol, ShareProxy, Socks, Tls,
    Transport, Trojan, Tuic, Vless, Vmess,
};
pub use outbound::{Options, Outbound};
pub use parse::{parse_link, parse_share_proxy};
pub use to_link::share_to_link;
pub use to_outbound::{share_to_outbound, transport_to_json};

use util::expand_configs;

/// Convert one or more share links (and optional `A -> B` chains) into sing-box Options JSON bytes.
pub fn convert(input: &str) -> Result<Vec<u8>> {
    let opts = convert_options(input)?;
    Ok(serde_json::to_vec_pretty(&opts)?)
}

/// Same as [`convert`] but returns structured [`Options`].
pub fn convert_options(input: &str) -> Result<Options> {
    let nodes = parse_many(input)?;
    let outbounds: Vec<_> = nodes.iter().map(share_to_outbound).collect();
    if outbounds.is_empty() {
        return Err(Error::NoOutbounds);
    }
    Ok(Options { outbounds })
}

/// Parse multi-line / chained share text into structured nodes (detour set on chains).
pub fn parse_many(input: &str) -> Result<Vec<ShareProxy>> {
    let lines = expand_configs(input);
    let mut out = Vec::new();
    let mut counter = 0usize;

    for config in lines {
        if config.len() < 5 {
            continue;
        }
        let chains: Vec<&str> = config.split(" -> ").map(str::trim).collect();
        let mut detour: Option<String> = None;
        for chain in chains.iter().rev() {
            let chain = util::decode_base64_if_needed(chain);
            let mut node = match parse_share_proxy(&chain) {
                Ok(n) => n,
                Err(e) => {
                    eprintln!("skip `{chain}`: {e}");
                    continue;
                }
            };
            if node.name.is_empty() {
                node.name = node.protocol.type_name().to_string();
            }
            let tag = format!("{} § {}", node.name, counter);
            node.name = tag.clone();
            node.detour = detour.clone();
            detour = Some(tag);
            out.push(node);
            counter += 1;
        }
    }

    if out.is_empty() {
        return Err(Error::NoOutbounds);
    }
    Ok(out)
}

/// Parse a single link to one outbound (no tag suffix / no Options wrapper).
pub fn parse_outbound(link: &str) -> Result<Outbound> {
    Ok(share_to_outbound(&parse_share_proxy(link.trim())?))
}
