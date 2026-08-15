//! Structured share-link node (app-facing). Outbound JSON is derived from this.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareProxy {
    pub name: String,
    pub address: String,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detour: Option<String>,
    #[serde(flatten)]
    pub protocol: ShareProtocol,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum ShareProtocol {
    Socks(Socks),
    Http(Http),
    Shadowsocks(Shadowsocks),
    Trojan(Trojan),
    Hysteria2(Hysteria2),
    Tuic(Tuic),
    Vless(Vless),
    Vmess(Vmess),
}

impl ShareProtocol {
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Socks(_) => "socks",
            Self::Http(_) => "http",
            Self::Shadowsocks(_) => "shadowsocks",
            Self::Trojan(_) => "trojan",
            Self::Hysteria2(_) => "hysteria2",
            Self::Tuic(_) => "tuic",
            Self::Vless(_) => "vless",
            Self::Vmess(_) => "vmess",
        }
    }

    pub fn network(&self) -> Option<&str> {
        match self {
            Self::Vless(v) => Some(v.network.as_str()),
            Self::Vmess(v) => Some(v.network.as_str()),
            Self::Trojan(t) => Some(t.network.as_str()),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Socks {
    pub version: u8,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Http {
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<Tls>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Shadowsocks {
    pub method: String,
    pub password: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugin: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugin_opts: Option<String>,
    #[serde(default)]
    pub udp_over_tcp: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Trojan {
    pub password: String,
    pub network: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<Transport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<Tls>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hysteria2 {
    pub password: String,
    #[serde(default = "default_up")]
    pub up_mbps: u32,
    #[serde(default = "default_down")]
    pub down_mbps: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_ports: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hop_interval: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfs: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfs_password: Option<String>,
    pub tls: Tls,
}

fn default_up() -> u32 {
    50
}
fn default_down() -> u32 {
    100
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tuic {
    pub uuid: String,
    #[serde(default)]
    pub password: String,
    #[serde(default = "default_cc")]
    pub congestion_control: String,
    #[serde(default = "default_udp_relay")]
    pub udp_relay_mode: String,
    #[serde(default)]
    pub udp_over_stream: bool,
    #[serde(default)]
    pub zero_rtt_handshake: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub heartbeat: Option<String>,
    pub tls: Tls,
}

fn default_cc() -> String {
    "cubic".into()
}
fn default_udp_relay() -> String {
    "native".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vless {
    pub uuid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packet_encoding: Option<String>,
    pub network: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<Transport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<Tls>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vmess {
    pub uuid: String,
    #[serde(default)]
    pub alter_id: u32,
    #[serde(default = "default_security")]
    pub security: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packet_encoding: Option<String>,
    pub network: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<Transport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<Tls>,
}

fn default_security() -> String {
    "auto".into()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Tls {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub allow_insecure: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alpn: Option<Vec<String>>,
    #[serde(default)]
    pub disable_sni: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reality_pbk: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reality_sid: Option<String>,
}

/// Transport knobs shared by vless/vmess/trojan (incl. xhttp extras).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Transport {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers: Option<HashMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_early_data: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub early_data_header_name: Option<String>,

    // xhttp
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x_padding_bytes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_grpc_header: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_sse_header: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sc_max_each_post_bytes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sc_min_posts_interval_ms: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x_padding_obfs_mode: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x_padding_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x_padding_header: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x_padding_placement: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x_padding_method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uplink_http_method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id_placement: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq_placement: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uplink_data_placement: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uplink_data_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uplink_chunk_size: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id_table: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id_length: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xmux_max_concurrency: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xmux_max_connections: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xmux_c_max_reuse_times: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xmux_h_max_request_times: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xmux_h_max_reusable_secs: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xmux_h_keep_alive_period: Option<i64>,
    /// Separate download leg (xhttp `downloadSettings`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download: Option<DownloadSettings>,
}

/// XHTTP downloadSettings (split download dial).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DownloadSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detour: Option<String>,
    /// none | tls | reality
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    #[serde(default)]
    pub allow_insecure: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alpn: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reality_pbk: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reality_sid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x_padding_bytes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sc_max_each_post_bytes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sc_min_posts_interval_ms: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_grpc_header: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_sse_header: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xmux_max_concurrency: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xmux_max_connections: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xmux_c_max_reuse_times: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xmux_h_max_request_times: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xmux_h_max_reusable_secs: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xmux_h_keep_alive_period: Option<i64>,
}
