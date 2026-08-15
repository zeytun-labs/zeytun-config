//! ShareProxy → share-link URL (inverse of parse).

use crate::error::Result;
use crate::node::{
    DownloadSettings, Http, Hysteria2, Shadowsocks, ShareProtocol, ShareProxy, Socks, Tls,
    Transport, Trojan, Tuic, Vless, Vmess,
};
use base64::{engine::general_purpose, Engine as _};
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use serde_json::{json, Map, Value};
use std::fmt::Write as _;

/// Query/fragment encode set (RFC 3986 unreserved + safe punctuation kept bare).
const ENC: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'&')
    .add(b'+')
    .add(b',')
    .add(b'/')
    .add(b':')
    .add(b';')
    .add(b'<')
    .add(b'=')
    .add(b'>')
    .add(b'?')
    .add(b'@')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

fn enc(s: &str) -> String {
    utf8_percent_encode(s, ENC).to_string()
}

fn host_port(address: &str, port: u16) -> String {
    if address.contains(':') && !address.starts_with('[') {
        format!("[{address}]:{port}")
    } else {
        format!("{address}:{port}")
    }
}

fn push_q(q: &mut Vec<(String, String)>, k: &str, v: impl AsRef<str>) {
    let v = v.as_ref();
    if !v.is_empty() {
        q.push((k.to_string(), v.to_string()));
    }
}

fn push_q_opt(q: &mut Vec<(String, String)>, k: &str, v: &Option<String>) {
    if let Some(s) = v {
        push_q(q, k, s);
    }
}

fn finish_url(
    scheme: &str,
    userinfo: Option<&str>,
    address: &str,
    port: u16,
    q: &[(String, String)],
    name: &str,
) -> String {
    let mut out = String::new();
    let _ = write!(out, "{scheme}://");
    if let Some(ui) = userinfo {
        out.push_str(ui);
        out.push('@');
    }
    out.push_str(&host_port(address, port));
    if !q.is_empty() {
        out.push('?');
        for (i, (k, v)) in q.iter().enumerate() {
            if i > 0 {
                out.push('&');
            }
            let _ = write!(out, "{k}={}", enc(v));
        }
    }
    if !name.is_empty() {
        let _ = write!(out, "#{}", enc(name));
    }
    out
}

fn tls_query(q: &mut Vec<(String, String)>, tls: &Option<Tls>, _default_sni: &str) {
    let Some(t) = tls else { return };
    if !t.enabled && t.reality_pbk.is_none() {
        return;
    }
    if t.reality_pbk.is_some() {
        push_q(q, "security", "reality");
        push_q_opt(q, "pbk", &t.reality_pbk);
        push_q_opt(q, "sid", &t.reality_sid);
    } else {
        push_q(q, "security", "tls");
    }
    push_q_opt(q, "sni", &t.sni);
    push_q_opt(q, "fp", &t.fingerprint);
    if let Some(alpn) = &t.alpn {
        if !alpn.is_empty() {
            push_q(q, "alpn", alpn.join(","));
        }
    }
    if t.allow_insecure {
        push_q(q, "insecure", "1");
    }
}

fn transport_query(q: &mut Vec<(String, String)>, network: &str, transport: &Option<Transport>) {
    let net = if network.is_empty() { "tcp" } else { network };
    if net != "tcp" {
        push_q(q, "type", net);
    }
    let Some(t) = transport else { return };

    let mut path = t.path.clone();
    if net == "ws" {
        if let (Some(ed), Some(p)) = (t.max_early_data, path.as_ref()) {
            if ed > 0 {
                let join = if p.contains('?') { "&" } else { "?" };
                path = Some(format!("{p}{join}ed={ed}"));
            }
        }
    }
    push_q_opt(q, "path", &path);
    push_q_opt(q, "host", &t.host);
    if net == "grpc" {
        if let Some(sn) = t.service_name.as_ref().or(t.path.as_ref()) {
            push_q(q, "serviceName", sn);
        }
    }
    push_q_opt(q, "mode", &t.mode);
    push_q_opt(q, "method", &t.method);

    if net == "xhttp" {
        if let Some(extra) = xhttp_extra_json(t) {
            push_q(q, "extra", extra);
        }
    }
}

fn xhttp_extra_json(t: &Transport) -> Option<String> {
    let mut m = Map::new();
    let put = |m: &mut Map<String, Value>, k: &str, v: &Option<String>| {
        if let Some(s) = v {
            if !s.is_empty() {
                m.insert(k.to_string(), Value::String(s.clone()));
            }
        }
    };
    let put_b = |m: &mut Map<String, Value>, k: &str, v: &Option<bool>| {
        if let Some(b) = v {
            m.insert(k.to_string(), Value::Bool(*b));
        }
    };

    put(&mut m, "xPaddingBytes", &t.x_padding_bytes);
    put_b(&mut m, "noGRPCHeader", &t.no_grpc_header);
    put_b(&mut m, "noSSEHeader", &t.no_sse_header);
    put(&mut m, "scMaxEachPostBytes", &t.sc_max_each_post_bytes);
    put(&mut m, "scMinPostsIntervalMs", &t.sc_min_posts_interval_ms);
    put_b(&mut m, "xPaddingObfsMode", &t.x_padding_obfs_mode);
    put(&mut m, "xPaddingKey", &t.x_padding_key);
    put(&mut m, "xPaddingHeader", &t.x_padding_header);
    put(&mut m, "xPaddingPlacement", &t.x_padding_placement);
    put(&mut m, "xPaddingMethod", &t.x_padding_method);
    put(&mut m, "uplinkHTTPMethod", &t.uplink_http_method);
    put(&mut m, "sessionIDPlacement", &t.session_id_placement);
    put(&mut m, "sessionIDKey", &t.session_id_key);
    put(&mut m, "seqPlacement", &t.seq_placement);
    put(&mut m, "seqKey", &t.seq_key);
    put(&mut m, "uplinkDataPlacement", &t.uplink_data_placement);
    put(&mut m, "uplinkDataKey", &t.uplink_data_key);
    put(&mut m, "uplinkChunkSize", &t.uplink_chunk_size);
    put(&mut m, "sessionIDTable", &t.session_id_table);
    put(&mut m, "sessionIDLength", &t.session_id_length);

    let mut xmux = Map::new();
    put(&mut xmux, "maxConcurrency", &t.xmux_max_concurrency);
    put(&mut xmux, "maxConnections", &t.xmux_max_connections);
    put(&mut xmux, "cMaxReuseTimes", &t.xmux_c_max_reuse_times);
    put(&mut xmux, "hMaxRequestTimes", &t.xmux_h_max_request_times);
    put(&mut xmux, "hMaxReusableSecs", &t.xmux_h_max_reusable_secs);
    if let Some(p) = t.xmux_h_keep_alive_period {
        xmux.insert("hKeepAlivePeriod".into(), json!(p));
    }
    if !xmux.is_empty() {
        m.insert("xmux".into(), Value::Object(xmux));
    }

    if let Some(dl) = &t.download {
        m.insert("downloadSettings".into(), download_to_json(dl));
    }

    if m.is_empty() {
        None
    } else {
        Some(serde_json::to_string(&Value::Object(m)).unwrap_or_default())
    }
}

fn download_to_json(d: &DownloadSettings) -> Value {
    let mut m = Map::new();
    if let Some(a) = &d.address {
        m.insert("address".into(), json!(a));
    }
    if let Some(p) = d.port {
        m.insert("port".into(), json!(p));
    }
    if let Some(p) = &d.path {
        m.insert("path".into(), json!(p));
    }
    if let Some(h) = &d.host {
        m.insert("host".into(), json!(h));
    }
    if let Some(det) = &d.detour {
        m.insert("detour".into(), json!(det));
    }
    if let Some(s) = &d.security {
        m.insert("security".into(), json!(s));
    }
    if let Some(x) = &d.x_padding_bytes {
        m.insert("xPaddingBytes".into(), json!(x));
    }
    if let Some(x) = &d.sc_max_each_post_bytes {
        m.insert("scMaxEachPostBytes".into(), json!(x));
    }
    if let Some(x) = &d.sc_min_posts_interval_ms {
        m.insert("scMinPostsIntervalMs".into(), json!(x));
    }
    if let Some(b) = d.no_grpc_header {
        m.insert("noGRPCHeader".into(), json!(b));
    }
    if let Some(b) = d.no_sse_header {
        m.insert("noSSEHeader".into(), json!(b));
    }

    let mut xmux = Map::new();
    if let Some(x) = &d.xmux_max_concurrency {
        xmux.insert("maxConcurrency".into(), json!(x));
    }
    if let Some(x) = &d.xmux_max_connections {
        xmux.insert("maxConnections".into(), json!(x));
    }
    if let Some(x) = &d.xmux_c_max_reuse_times {
        xmux.insert("cMaxReuseTimes".into(), json!(x));
    }
    if let Some(x) = &d.xmux_h_max_request_times {
        xmux.insert("hMaxRequestTimes".into(), json!(x));
    }
    if let Some(x) = &d.xmux_h_max_reusable_secs {
        xmux.insert("hMaxReusableSecs".into(), json!(x));
    }
    if let Some(p) = d.xmux_h_keep_alive_period {
        xmux.insert("hKeepAlivePeriod".into(), json!(p));
    }
    if !xmux.is_empty() {
        m.insert("xmux".into(), Value::Object(xmux));
    }

    let sec = d.security.as_deref().unwrap_or("");
    let has_tls = sec.eq_ignore_ascii_case("tls")
        || sec.eq_ignore_ascii_case("reality")
        || d.sni.is_some()
        || d.fingerprint.is_some()
        || d.reality_pbk.is_some();
    if has_tls {
        let mut tls = Map::new();
        if let Some(sni) = &d.sni {
            tls.insert("serverName".into(), json!(sni));
        }
        if d.allow_insecure {
            tls.insert("allowInsecure".into(), json!(true));
        }
        if let Some(fp) = &d.fingerprint {
            tls.insert("fingerprint".into(), json!(fp));
        }
        if let Some(alpn) = &d.alpn {
            tls.insert("alpn".into(), json!(alpn));
        }
        if sec.eq_ignore_ascii_case("reality") || d.reality_pbk.is_some() {
            let mut reality = Map::new();
            reality.insert("enabled".into(), json!(true));
            if let Some(pbk) = &d.reality_pbk {
                reality.insert("publicKey".into(), json!(pbk));
            }
            if let Some(sid) = &d.reality_sid {
                reality.insert("shortId".into(), json!(sid));
            }
            tls.insert("reality".into(), Value::Object(reality));
        }
        m.insert("tlsSettings".into(), Value::Object(tls));
    }
    Value::Object(m)
}

fn vless_link(p: &ShareProxy, v: &Vless) -> String {
    let mut q = Vec::new();
    push_q(&mut q, "encryption", "none");
    transport_query(&mut q, &v.network, &v.transport);
    tls_query(&mut q, &v.tls, &p.address);
    push_q_opt(&mut q, "flow", &v.flow);
    if let Some(pe) = &v.packet_encoding {
        if pe != "xudp" {
            push_q(&mut q, "packetEncoding", pe);
        }
    }
    finish_url(
        "vless",
        Some(&enc(&v.uuid)),
        &p.address,
        p.port,
        &q,
        &p.name,
    )
}

fn trojan_link(p: &ShareProxy, t: &Trojan) -> String {
    let mut q = Vec::new();
    transport_query(&mut q, &t.network, &t.transport);
    tls_query(&mut q, &t.tls, &p.address);
    finish_url(
        "trojan",
        Some(&enc(&t.password)),
        &p.address,
        p.port,
        &q,
        &p.name,
    )
}

fn vmess_link(p: &ShareProxy, v: &Vmess) -> Result<String> {
    let mut obj = Map::new();
    obj.insert("v".into(), json!("2"));
    obj.insert("ps".into(), json!(&p.name));
    obj.insert("add".into(), json!(&p.address));
    obj.insert("port".into(), json!(p.port.to_string()));
    obj.insert("id".into(), json!(&v.uuid));
    obj.insert("aid".into(), json!(v.alter_id.to_string()));
    obj.insert("scy".into(), json!(&v.security));
    obj.insert("net".into(), json!(&v.network));
    obj.insert("type".into(), json!("none"));

    if let Some(t) = &v.transport {
        if let Some(path) = &t.path {
            let mut path = path.clone();
            if v.network == "ws" {
                if let Some(ed) = t.max_early_data {
                    if ed > 0 {
                        let join = if path.contains('?') { "&" } else { "?" };
                        path = format!("{path}{join}ed={ed}");
                    }
                }
            }
            obj.insert("path".into(), json!(path));
        }
        if let Some(host) = &t.host {
            obj.insert("host".into(), json!(host));
        }
        if let Some(mode) = &t.mode {
            obj.insert("type".into(), json!(mode));
        }
        if v.network == "xhttp" {
            if let Some(extra) = xhttp_extra_json(t) {
                obj.insert("extra".into(), json!(extra));
            }
        }
    }

    if let Some(tls) = &v.tls {
        if tls.enabled || tls.reality_pbk.is_some() {
            if tls.reality_pbk.is_some() {
                obj.insert("tls".into(), json!("reality"));
                if let Some(pbk) = &tls.reality_pbk {
                    obj.insert("pbk".into(), json!(pbk));
                }
                if let Some(sid) = &tls.reality_sid {
                    obj.insert("sid".into(), json!(sid));
                }
            } else {
                obj.insert("tls".into(), json!("tls"));
            }
            if let Some(sni) = &tls.sni {
                obj.insert("sni".into(), json!(sni));
            }
            if let Some(fp) = &tls.fingerprint {
                obj.insert("fp".into(), json!(fp));
            }
            if let Some(alpn) = &tls.alpn {
                if !alpn.is_empty() {
                    obj.insert("alpn".into(), json!(alpn.join(",")));
                }
            }
        }
    }

    if let Some(pe) = &v.packet_encoding {
        if pe != "xudp" {
            obj.insert("packetEncoding".into(), json!(pe));
        }
    }

    let raw = serde_json::to_vec(&Value::Object(obj))?;
    let b64 = general_purpose::STANDARD.encode(raw);
    Ok(format!("vmess://{b64}"))
}

fn ss_link(p: &ShareProxy, s: &Shadowsocks) -> String {
    let userinfo = format!("{}:{}", s.method, s.password);
    let b64 = general_purpose::STANDARD
        .encode(userinfo.as_bytes())
        .trim_end_matches('=')
        .to_string();
    let mut q = Vec::new();
    if let Some(plugin) = &s.plugin {
        let mut plugin_val = plugin.clone();
        if let Some(opts) = &s.plugin_opts {
            plugin_val = format!("{plugin};{opts}");
        }
        push_q(&mut q, "plugin", plugin_val);
    }
    finish_url("ss", Some(&b64), &p.address, p.port, &q, &p.name)
}

fn hy2_link(p: &ShareProxy, h: &Hysteria2) -> String {
    let mut q = Vec::new();
    if let Some(sni) = &h.tls.sni {
        push_q(&mut q, "sni", sni);
    }
    if h.tls.allow_insecure {
        push_q(&mut q, "insecure", "1");
    }
    if h.up_mbps != 50 {
        push_q(&mut q, "upmbps", h.up_mbps.to_string());
    }
    if h.down_mbps != 100 {
        push_q(&mut q, "downmbps", h.down_mbps.to_string());
    }
    push_q_opt(&mut q, "mport", &h.server_ports);
    push_q_opt(&mut q, "hopInterval", &h.hop_interval);
    push_q_opt(&mut q, "obfs", &h.obfs);
    push_q_opt(&mut q, "obfs-password", &h.obfs_password);
    finish_url(
        "hysteria2",
        Some(&enc(&h.password)),
        &p.address,
        p.port,
        &q,
        &p.name,
    )
}

fn tuic_link(p: &ShareProxy, t: &Tuic) -> String {
    let mut q = Vec::new();
    if let Some(sni) = &t.tls.sni {
        push_q(&mut q, "sni", sni);
    }
    if t.tls.allow_insecure {
        push_q(&mut q, "insecure", "1");
    }
    if t.congestion_control != "cubic" {
        push_q(&mut q, "congestion_control", &t.congestion_control);
    }
    if t.udp_relay_mode != "native" {
        push_q(&mut q, "udp_relay_mode", &t.udp_relay_mode);
    }
    if t.udp_over_stream {
        push_q(&mut q, "udp_over_stream", "1");
    }
    if t.zero_rtt_handshake {
        push_q(&mut q, "zero_rtt_handshake", "1");
    }
    push_q_opt(&mut q, "heartbeat", &t.heartbeat);
    let ui = if t.password.is_empty() {
        enc(&t.uuid)
    } else {
        format!("{}:{}", enc(&t.uuid), enc(&t.password))
    };
    finish_url("tuic", Some(&ui), &p.address, p.port, &q, &p.name)
}

fn socks_link(p: &ShareProxy, s: &Socks) -> String {
    let scheme = if s.version == 4 { "socks4" } else { "socks5" };
    let ui = if s.username.is_empty() && s.password.is_empty() {
        None
    } else {
        Some(format!("{}:{}", enc(&s.username), enc(&s.password)))
    };
    finish_url(scheme, ui.as_deref(), &p.address, p.port, &[], &p.name)
}

fn http_link(p: &ShareProxy, h: &Http) -> String {
    let https = h.tls.as_ref().map(|t| t.enabled).unwrap_or(false);
    let scheme = if https { "https" } else { "http" };
    let mut q = Vec::new();
    push_q_opt(&mut q, "path", &h.path);
    if let Some(tls) = &h.tls {
        if let Some(sni) = &tls.sni {
            push_q(&mut q, "sni", sni);
        }
        if tls.allow_insecure {
            push_q(&mut q, "insecure", "1");
        }
    }
    let ui = if h.username.is_empty() && h.password.is_empty() {
        None
    } else {
        Some(format!("{}:{}", enc(&h.username), enc(&h.password)))
    };
    finish_url(scheme, ui.as_deref(), &p.address, p.port, &q, &p.name)
}

/// Emit a standard share-link URL from a structured node.
///
/// → skipped: warp/wg/ssh/naive chain `A -> B` emit — add when product needs.
pub fn share_to_link(proxy: &ShareProxy) -> Result<String> {
    match &proxy.protocol {
        ShareProtocol::Vless(v) => Ok(vless_link(proxy, v)),
        ShareProtocol::Vmess(v) => vmess_link(proxy, v),
        ShareProtocol::Trojan(t) => Ok(trojan_link(proxy, t)),
        ShareProtocol::Shadowsocks(s) => Ok(ss_link(proxy, s)),
        ShareProtocol::Hysteria2(h) => Ok(hy2_link(proxy, h)),
        ShareProtocol::Tuic(t) => Ok(tuic_link(proxy, t)),
        ShareProtocol::Socks(s) => Ok(socks_link(proxy, s)),
        ShareProtocol::Http(h) => Ok(http_link(proxy, h)),
    }
}
